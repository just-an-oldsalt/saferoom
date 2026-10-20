import Foundation
import Testing
@testable import SafeRoomCore

private func blocklist(_ text: String, allow: [String] = [], neverBlock: [String] = []) -> Blocklist {
    let allowRules = allow.compactMap { try? ListParser.parseDomain(Substring($0)).get() }
    return Blocklist(list: CompiledList(source: Array(text.utf8)), allow: allowRules, neverBlock: neverBlock)
}

@Suite struct DomainMatching {
    let b = blocklist("""
    evil.com
    =exact.net
    *.wild.org
    *.zip
    """)

    @Test(arguments: ["evil.com", "a.evil.com", "a.b.c.evil.com", "EVIL.COM.", "Sub.Evil.Com"])
    func subtreeBlocks(_ name: String) {
        #expect(b.verdict(for: name) == .blocked(rule: "evil.com"))
    }

    @Test(arguments: ["notevil.com", "evil.co", "com", "evil.com.au", "xevil.com"])
    func subtreeDoesNotLeak(_ name: String) {
        #expect(b.verdict(for: name) == .pass)
    }

    @Test func exactMatchesOnlyItself() {
        #expect(b.verdict(for: "exact.net") == .blocked(rule: "exact.net"))
        #expect(b.verdict(for: "a.exact.net") == .pass)
    }

    @Test func subdomainsOnlySkipsApex() {
        #expect(b.verdict(for: "wild.org") == .pass)
        #expect(b.verdict(for: "a.wild.org") == .blocked(rule: "wild.org"))
        #expect(b.verdict(for: "a.b.wild.org") == .blocked(rule: "wild.org"))
    }

    @Test func wholeTLDNeedsPolicy() {
        #expect(b.verdict(for: "anything.zip") == .pass)
        let opted = Blocklist(list: b.list, neverBlock: [], allowTopLevelBlocks: true)
        #expect(opted.verdict(for: "anything.zip") == .blocked(rule: "zip"))
        #expect(opted.verdict(for: "zip") == .pass)
    }

    @Test func modesMergeForSameName() {
        let merged = blocklist("=both.com\n*.both.com")
        #expect(merged.verdict(for: "both.com") == .blocked(rule: "both.com"))
        #expect(merged.verdict(for: "a.both.com") == .blocked(rule: "both.com"))
        #expect(merged.list.domains.count == 1)
    }

    @Test func emptyListPassesEverything() {
        #expect(Blocklist.empty.verdict(for: "evil.com") == .pass)
    }
}

@Suite struct AllowWins {
    @Test func allowlistBeatsBroaderBlock() {
        let b = blocklist("evil.com", allow: ["good.evil.com"])
        #expect(b.verdict(for: "good.evil.com") == .allowed(rule: "good.evil.com"))
        #expect(b.verdict(for: "x.good.evil.com") == .allowed(rule: "good.evil.com"))
        #expect(b.verdict(for: "bad.evil.com") == .blocked(rule: "evil.com"))
    }

    @Test func allowlistBeatsNarrowerBlock() {
        let b = blocklist("=www.partner.com", allow: ["partner.com"])
        #expect(b.verdict(for: "www.partner.com") == .allowed(rule: "partner.com"))
    }

    @Test func builtInNeverBlockSurvivesABadFeed() {
        let b = Blocklist(list: CompiledList(source: Array("apple.com\n*.com\nevil.com".utf8)))
        #expect(b.verdict(for: "swscan.apple.com") == .allowed(rule: "apple.com"))
        #expect(b.verdict(for: "login.okta.com") == .allowed(rule: "okta.com"))
        // *.com is ignored without AllowTopLevelBlocks; evil.com still matches.
        #expect(b.verdict(for: "evil.com") == .blocked(rule: "evil.com"))
        #expect(b.verdict(for: "other.com") == .pass)
    }
}

@Suite struct AddressMatching {
    let b = blocklist("""
    198.51.100.0/24
    203.0.113.9
    10.0.0.0/25
    10.0.0.128/25
    2001:db8:bad::/48
    """)

    @Test func v4() {
        #expect(b.isBlocked(.v4(0xC633_6400)))  // 198.51.100.0
        #expect(b.isBlocked(.v4(0xC633_64FF)))  // 198.51.100.255
        #expect(!b.isBlocked(.v4(0xC633_6500)))  // 198.51.101.0
        #expect(!b.isBlocked(.v4(0xC633_63FF)))  // 198.51.99.255
        #expect(b.isBlocked(.v4(0xCB00_7109)))  // 203.0.113.9
        #expect(!b.isBlocked(.v4(0xCB00_710A)))
    }

    @Test func adjacentRangesMerge() {
        #expect(b.list.v4.count == 3)
        #expect(b.isBlocked(.v4(0x0A00_00FF)))
    }

    @Test func v6() {
        let base = (UInt128(0x2001_0db8) << 96) | (UInt128(0x0bad) << 80)
        #expect(b.isBlocked(.v6(base)))
        #expect(b.isBlocked(.v6(base | 0xFFFF)))
        #expect(!b.isBlocked(.v6(base + (UInt128(1) << 80))))
    }

    @Test func overBroadRangesAreRejected() {
        let all = blocklist("0.0.0.0/0\n::/0\n10.0.0.0/7\n2001::/15")
        #expect(!all.isBlocked(.v4(.max)))
        #expect(!all.isBlocked(.v6(.max)))
        #expect(all.list.stats.invalidCount == 4)
        #expect(blocklist("10.0.0.0/8").isBlocked(.v4(0x0A01_0203)))
    }
}

@Suite struct Cache {
    let list = CompiledList(source: Array("evil.com\n=x.net\n*.y.org\n198.51.100.0/24\n2001:db8::/32\nbad..line".utf8))

    @Test func roundTrip() throws {
        let restored = try CompiledList(cache: list.serialized())
        #expect(restored == list)
        #expect(restored.stats.invalidCount == 1)
        #expect(Blocklist(list: restored).verdict(for: "a.evil.com") == .blocked(rule: "evil.com"))
    }

    @Test func emptyRoundTrip() throws {
        #expect(try CompiledList(cache: CompiledList.empty.serialized()) == .empty)
    }

    @Test func flippedByteIsRejected() {
        var data = list.serialized()
        data[60] ^= 0x01
        #expect(throws: CompiledList.CacheError.checksumMismatch) { try CompiledList(cache: data) }
    }

    @Test func truncatedIsRejected() {
        let data = list.serialized().prefix(20)
        #expect(throws: CompiledList.CacheError.tooShort) { try CompiledList(cache: Data(data)) }
    }
}

@Test func scale250k() throws {
    let n = 250_000
    let text = (0..<n).map { "host\($0).bad\($0 % 997).example" }.joined(separator: "\n")
    let compileStart = ContinuousClock.now
    let list = CompiledList(source: Array(text.utf8))
    let compileTime = ContinuousClock.now - compileStart
    let b = Blocklist(list: list)
    #expect(list.domains.count == n)

    let queries = (0..<100_000).map { i -> [UInt8] in
        Array((i.isMultiple(of: 2) ? "a.host\(i).bad\(i % 997).example" : "clean\(i).example.org").utf8)
    }
    var blocked = 0
    let lookupStart = ContinuousClock.now
    for q in queries where b.verdict(normalized: q) != .pass { blocked += 1 }
    let lookupTime = ContinuousClock.now - lookupStart
    #expect(blocked == 50_000)

    let cache = list.serialized()
    let loadStart = ContinuousClock.now
    _ = try CompiledList(cache: cache)
    let loadTime = ContinuousClock.now - loadStart

    print("""
    250k: compile \(compileTime), in-memory \(list.byteSize / 1024) KiB, cache file \(cache.count / 1024) KiB, \
    cache load \(loadTime), lookup \(lookupTime / queries.count) each
    """)
}

@Test func allowlistIsExactNotHashed() {
    // The allowlist compares strings; a different name never matches it.
    let b = Blocklist(list: CompiledList(source: Array("evil.com".utf8)), allow: [DomainRule(name: "partner.com", match: .subtree)], neverBlock: [])
    #expect(b.allow.count == 1)
    #expect(b.verdict(for: "x.partner.com") == .allowed(rule: "partner.com"))
    #expect(b.verdict(for: "evil.com") == .blocked(rule: "evil.com"))
}

@Test func listHostIsProtectedExactlyNotItsSubtree() {
    let p = ProviderPolicy(["ListURL": "https://feeds.sharedhost.example/list.txt"])
    let b = p.blocklist(CompiledList(source: Array("sharedhost.example".utf8)))
    #expect(b.verdict(for: "feeds.sharedhost.example") == .allowed(rule: "feeds.sharedhost.example"))
    #expect(b.verdict(for: "evil.feeds.sharedhost.example") == .blocked(rule: "sharedhost.example"))
}
