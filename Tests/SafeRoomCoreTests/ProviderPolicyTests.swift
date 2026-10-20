import Testing
@testable import SafeRoomCore

@Test func defaults() {
    #expect(ProviderPolicy([:]) == ProviderPolicy())
}

@Test func readsKeys() {
    let p = ProviderPolicy([
        "ListPath": "/tmp/list.txt",
        "AllowList": ["partner.com", "=exact.org", "bad..name", 42],
        "NeverBlockHosts": ["mdm.example.com"],
        "Unknown": true,
    ])
    #expect(p.listPath == "/tmp/list.txt")
    #expect(p.allowList == [DomainRule(name: "partner.com", match: .subtree), DomainRule(name: "exact.org", match: .exact)])
    #expect(p.neverBlockHosts == ["mdm.example.com"])
}

@Test func relativePathIgnored() {
    #expect(ProviderPolicy(["ListPath": "list.txt"]).listPath == ProviderPolicy.defaultListPath)
}

@Test func neverBlockHostsJoinBuiltIn() {
    let p = ProviderPolicy(["NeverBlockHosts": ["mdm.example.com"]])
    let b = p.blocklist(CompiledList(source: Array("example.com\napple.com".utf8)))
    #expect(b.verdict(for: "mdm.example.com") == .allowed(rule: "mdm.example.com"))
    #expect(b.verdict(for: "www.example.com") == .blocked(rule: "example.com"))
    #expect(b.verdict(for: "apple.com") == .allowed(rule: "apple.com"))
}

@Test func storeSwaps() {
    let store = BlocklistStore()
    #expect(store.current.verdict(for: "evil.com") == .pass)
    store.replace(Blocklist(list: CompiledList(source: Array("evil.com".utf8))))
    #expect(store.current.verdict(for: "evil.com") == .blocked(rule: "evil.com"))
}
