import Testing
@testable import SafeRoomCore

private func encode(_ name: String) -> [UInt8] {
    name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
}
private func query(_ name: String, id: UInt16, type: UInt16 = 1) -> [UInt8] {
    DNSMessage.be(id) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0] + encode(name) + DNSMessage.be(type) + [0, 1]
}
/// The upstream's answer to `sent`: same ID and question, one A record.
private func answer(to sent: [UInt8], name: String? = nil) -> [UInt8] {
    var p = Array(sent.prefix(2)) + [0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]
    let q = name.map { encode($0) + [0, 1, 0, 1] } ?? Array(sent[12...])
    p += q + [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]
    return p
}

@Test func roundTripRestoresTheClientID() throws {
    var mux = QueryMultiplexer<String>()
    let _v834 = mux.register(query("github.com", id: 0xBEEF), context: "flow A")
    let sent = try #require(_v834)
    #expect(sent[2...] == query("github.com", id: 0xBEEF)[2...])
    let _v993 = mux.resolve(answer(to: sent))
    let (packet, context) = try #require(_v993)
    #expect(context == "flow A")
    #expect(Array(packet[0..<2]) == [0xBE, 0xEF])
    #expect(mux.count == 0)
}

@Test func twoClientsWithTheSameIDDoNotCollide() throws {
    var mux = QueryMultiplexer<String>()
    let _v1278 = mux.register(query("a.com", id: 7), context: "A")
    let a = try #require(_v1278)
    let registeredB = mux.register(query("b.com", id: 7), context: "B")
    let b = try #require(registeredB)
    #expect(a[0..<2] != b[0..<2])
    let _c1532 = mux.resolve(answer(to: b))
    #expect(try #require(_c1532).context == "B")
    let _c1601 = mux.resolve(answer(to: a))
    #expect(try #require(_c1601).context == "A")
}

@Test func answerForAnotherQuestionIsRejected() throws {
    var mux = QueryMultiplexer<String>()
    let _v1703 = mux.register(query("github.com", id: 1), context: "A")
    let sent = try #require(_v1703)
    // Right ID, wrong name: a forged or misrouted answer.
    #expect(mux.resolve(answer(to: sent, name: "evil.com")) == nil)
    #expect(mux.count == 1) // the real answer can still arrive
    #expect(mux.resolve(answer(to: sent)) != nil)
}

@Test func caseOfTheEchoedNameIsIgnored() throws {
    var mux = QueryMultiplexer<String>()
    let _v2123 = mux.register(query("GitHub.com", id: 1), context: "A")
    let sent = try #require(_v2123)
    #expect(mux.resolve(answer(to: sent, name: "gItHuB.CoM")) != nil)
}

@Test func unknownIDAndQueriesAreRejected() throws {
    var mux = QueryMultiplexer<String>()
    let _v2374 = mux.register(query("github.com", id: 1), context: "A")
    let sent = try #require(_v2374)
    var wrongID = answer(to: sent)
    wrongID[0] ^= 0xFF
    #expect(mux.resolve(wrongID) == nil)
    #expect(mux.resolve(sent) == nil) // a query, not a response
    #expect(mux.resolve([1, 2, 3]) == nil)
}

@Test func answerIsDeliveredOnce() throws {
    var mux = QueryMultiplexer<String>()
    let _v2753 = mux.register(query("github.com", id: 1), context: "A")
    let sent = try #require(_v2753)
    #expect(mux.resolve(answer(to: sent)) != nil)
    #expect(mux.resolve(answer(to: sent)) == nil)
}

@Test func expiry() throws {
    var mux = QueryMultiplexer<String>(timeout: .seconds(10))
    let start = ContinuousClock.now
    let _v3067 = mux.register(query("github.com", id: 1), context: "A", now: start)
    let sent = try #require(_v3067)
    #expect(mux.expire(now: start + .seconds(5)) == 0)
    #expect(mux.expire(now: start + .seconds(11)) == 1)
    #expect(mux.resolve(answer(to: sent)) == nil)
}

@Test func capacityIsEnforced() {
    var mux = QueryMultiplexer<Int>(capacity: 100)
    for i in 0..<100 { #expect(mux.register(query("n\(i).com", id: UInt16(i)), context: i) != nil) }
    #expect(mux.register(query("x.com", id: 1), context: 0) == nil)
}

@Test func idsAreSpreadOut() throws {
    var mux = QueryMultiplexer<Int>()
    var ids = Set<UInt16>()
    for i in 0..<2000 {
        let _v3712 = mux.register(query("n\(i).com", id: 1), context: i)
        let sent = try #require(_v3712)
        ids.insert(UInt16(sent[0]) << 8 | UInt16(sent[1]))
    }
    #expect(ids.count == 2000)
}

@Test func unreadableQueryIsNotRegistered() {
    var mux = QueryMultiplexer<Int>()
    #expect(mux.register([0, 1, 2], context: 0) == nil)
}
