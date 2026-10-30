import Testing
@testable import SafeRoomCore

private func encode(_ name: String) -> [UInt8] {
    name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
}

private func query(_ name: String, type: UInt16 = 1) -> [UInt8] {
    [0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0] + encode(name) + DNSMessage.be(type) + [0, 1]
}

/// A response for `name` with an optional CNAME to `alias`, then one A record.
private func response(_ name: String, alias: String? = nil, a: [UInt8]) -> [UInt8] {
    var p: [UInt8] = [0, 9, 0x81, 0x80, 0, 1, 0, alias == nil ? 1 : 2, 0, 0, 0, 0] + encode(name) + [0, 1, 0, 1]
    var owner = encode(name)
    if let alias {
        let target = encode(alias)
        p += owner + [0, 5, 0, 1, 0, 0, 0, 60] + DNSMessage.be(UInt16(target.count)) + target
        owner = target
    }
    p += owner + [0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + a
    return p
}

private func makeFilter(ttl: Duration = .seconds(300)) -> DNSFilter {
    let store = BlocklistStore()
    store.replace(Blocklist(
        list: CompiledList(source: Array("evil.com\n198.51.100.0/24".utf8)),
        allow: [DomainRule(name: "partner.com", match: .subtree)],
        neverBlock: ["apple.com"]))
    return DNSFilter(store: store, learnedTTL: ttl)
}

private let list = makeFilter()

@Test func blockedQueryGetsNXDOMAIN() throws {
    guard case .block(let reply, let name, let type, let rule) = list.decide(query: query("a.EVIL.com", type: 65)) else {
        Issue.record("not blocked"); return
    }
    #expect(name == "a.evil.com" && type == 65 && rule == "evil.com")
    #expect(reply[3] & 0x0F == 3)
}

@Test func cleanQueryForwards() {
    #expect(list.decide(query: query("example.org")) == .forward)
}

@Test func garbageForwards() {
    #expect(list.decide(query: [1, 2, 3]) == .forward)
}

@Test func responseIsNotTreatedAsQuery() {
    #expect(list.decide(query: response("evil.com", a: [1, 2, 3, 4])) == .forward)
}

@Test func cleanResponsePasses() {
    #expect(list.decide(response: response("example.org", a: [192, 0, 2, 1])) == .pass)
}

@Test func blockedAddressInResponse() {
    guard case .block(_, let name, let reason) = list.decide(response: response("shady.org", a: [198, 51, 100, 7])) else {
        Issue.record("not blocked"); return
    }
    #expect(name == "shady.org")
    #expect(reason == .address(.v4(0xC633_6407)))
}

@Test func blockedCNAMETarget() {
    guard case .block(_, _, let reason) = list.decide(response: response("innocent.org", alias: "cdn.evil.com", a: [192, 0, 2, 1])) else {
        Issue.record("not blocked"); return
    }
    #expect(reason == .alias(target: "cdn.evil.com", rule: "evil.com"))
}

@Test func allowlistedNameSkipsAddressCheck() {
    #expect(list.decide(response: response("www.partner.com", a: [198, 51, 100, 7])) == .pass)
    #expect(list.decide(response: response("swscan.apple.com", a: [198, 51, 100, 7])) == .pass)
}

@Test func answerToABlockedQuestionIsBlocked() {
    // The query slipped past decide(query:); the answer still names it.
    guard case .block(_, let name, _) = list.decide(response: response("a.evil.com", a: [192, 0, 2, 1])) else {
        Issue.record("not blocked"); return
    }
    #expect(name == "a.evil.com")
}

@Test func allowlistedAliasTargetPasses() {
    #expect(list.decide(response: response("x.org", alias: "edge.apple.com", a: [192, 0, 2, 1])) == .pass)
}

@Test func addressBlockIsLearnedForOtherTypes() {
    let filter = makeFilter()
    #expect(filter.decide(query: query("shady.org", type: 28)) == .forward)
    _ = filter.decide(response: response("shady.org", a: [198, 51, 100, 7]))
    guard case .block(_, let name, let type, let rule) = filter.decide(query: query("shady.org", type: 28)) else {
        Issue.record("not learned"); return
    }
    #expect(name == "shady.org" && type == 28 && rule == "learned:198.51.100.7")
    #expect(filter.decide(query: query("other.org", type: 28)) == .forward)
}

@Test func learnedBlockExpires() async throws {
    let filter = makeFilter(ttl: .milliseconds(50))
    _ = filter.decide(response: response("shady.org", a: [198, 51, 100, 7]))
    try await Task.sleep(for: .milliseconds(120))
    #expect(filter.decide(query: query("shady.org")) == .forward)
}

@Test func allowlistedNameIsNeverLearned() {
    let filter = makeFilter()
    _ = filter.decide(response: response("www.partner.com", a: [198, 51, 100, 7]))
    #expect(filter.learned.count == 0)
    #expect(filter.decide(query: query("www.partner.com")) == .forward)
}

@Test func learnedCapacityIsBounded() {
    let store = BlocklistStore()
    store.replace(Blocklist(list: CompiledList(source: Array("198.51.100.0/24".utf8))))
    let filter = DNSFilter(store: store, learnedCapacity: 100)
    for i in 0..<250 { _ = filter.decide(response: response("n\(i).org", a: [198, 51, 100, 7])) }
    #expect(filter.learned.count <= 100)
}

/// The second review's bypass: one extra record whose owner name has a dot
/// inside a label used to make the whole answer unreadable, and it passed.
@Test func oddRecordDoesNotHideABlockedAddress() {
    var p = response("shady.org", a: [198, 51, 100, 7])
    p[7] = 2 // two answers
    // Owner name: one label "a.b" (a dot inside the label), type TXT, 1 byte.
    p += [3] + Array("a.b".utf8) + [0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 1, 0]
    guard case .block(_, _, let reason) = makeFilter().decide(response: p) else {
        Issue.record("passed"); return
    }
    #expect(reason == .address(.v4(0xC633_6407)))
}

@Test func oddRecordDoesNotHideABlockedAlias() {
    var p = response("innocent.org", alias: "cdn.evil.com", a: [192, 0, 2, 1])
    p[7] = 3
    p += [3] + Array("a.b".utf8) + [0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 1, 0]
    guard case .block = makeFilter().decide(response: p) else { Issue.record("passed"); return }
}

// MARK: - Monitor mode

@Test func monitorForwardsListedQueries() {
    let filter = makeFilter()
    filter.configure(monitorOnly: true, reportAllQueries: false)
    #expect(filter.decide(query: query("a.evil.com", type: 28)) == .forward)
    // The answer reports it once, as the query name with its type.
    guard case .monitor(let name, let type, let reason) = filter.decide(response: response("a.evil.com", a: [192, 0, 2, 1])) else {
        Issue.record("not monitored"); return
    }
    #expect(name == "a.evil.com")
    #expect(type == 1)
    let event = BlockEvent(wouldBlock: name, type: type, reason: reason, app: "app", transport: "udp")
    #expect(event.kind == .query)
    #expect(event.action == .wouldBlock)
    #expect(event.rule == "evil.com")
    #expect(filter.counters.values.wouldBlock == 1)
    #expect(filter.counters.values.blockedAnswers == 0)
}

@Test func monitorPassesListedAddressesWithoutLearning() {
    let filter = makeFilter()
    filter.configure(monitorOnly: true, reportAllQueries: false)
    guard case .monitor(_, _, .address(let address)) = filter.decide(response: response("shady.org", a: [198, 51, 100, 7])) else {
        Issue.record("not monitored"); return
    }
    #expect(address.description == "198.51.100.7")
    // Nothing learned, so the next query is not blocked either.
    #expect(filter.decide(query: query("shady.org", type: 28)) == .forward)
    let event = BlockEvent(wouldBlock: "shady.org", type: 1, reason: .address(address), app: "app", transport: "udp")
    #expect(event.kind == .answer)
    #expect(event.action == .wouldBlock)
}

@Test func monitorKeepsAllowList() {
    let filter = makeFilter()
    filter.configure(monitorOnly: true, reportAllQueries: false)
    #expect(filter.decide(response: response("www.partner.com", a: [198, 51, 100, 7])) == .pass)
}

@Test func blockingResumesWhenMonitorIsOff() {
    let filter = makeFilter()
    filter.configure(monitorOnly: true, reportAllQueries: false)
    filter.configure(monitorOnly: false, reportAllQueries: false)
    guard case .block = filter.decide(query: query("a.evil.com")) else { Issue.record("not blocked"); return }
}

// MARK: - All queries

@Test func allowedEventCarriesTheAnswer() throws {
    let event = try #require(BlockEvent(allowed: response("www.example.org", alias: "edge.example.net", a: [192, 0, 2, 1]),
                                        app: "com.example.app", transport: "tcp"))
    #expect(event.kind == .query)
    #expect(event.action == .allowed)
    #expect(event.name == "www.example.org")
    #expect(event.type == 1)
    #expect(event.addresses == ["192.0.2.1"])
    #expect(event.aliases == ["edge.example.net"])
    #expect(event.rule == nil)
    #expect(BlockEvent(allowed: query("www.example.org"), app: "a", transport: "udp") == nil)
}
