import Foundation
import Testing
@testable import SafeRoomCore

@Test func defaults() {
    #expect(ProviderPolicy([:]) == ProviderPolicy())
    #expect(ProviderPolicy().listURL == nil)
    #expect(ProviderPolicy().auth == .none)
}

@Test func readsKeys() {
    let p = ProviderPolicy([
        "ListPath": "/tmp/list.txt",
        "ListURL": "https://intel.example.com/list.txt",
        "ListSHA256URL": "https://intel.example.com/list.txt.sha256",
        "AllowList": ["partner.com", "=exact.org", "bad..name", 42],
        "NeverBlockHosts": ["mdm.example.com"],
        "RefreshSeconds": 900,
        "MaxChangePercent": "20",
        "MaxListMegabytes": 8,
        "Auth": ["Type": "Bearer", "Token": "s3cret"],
        "Unknown": true,
    ])
    #expect(p.listPath == "/tmp/list.txt")
    #expect(p.listURL?.absoluteString == "https://intel.example.com/list.txt")
    #expect(p.listSHA256URL != nil)
    #expect(p.allowList == [DomainRule(name: "partner.com", match: .subtree), DomainRule(name: "exact.org", match: .exact)])
    #expect(p.neverBlockHosts == ["mdm.example.com"])
    #expect(p.refreshInterval == .seconds(900))
    #expect(p.maxChangePercent == 20)
    #expect(p.maxListBytes == 8 << 20)
    #expect(p.auth == .bearer(token: "s3cret"))
}

@Test func authDescriptionHidesToken() {
    #expect(!ProviderPolicy.Auth.bearer(token: "s3cret").description.contains("s3cret"))
}

@Test func clientCertificateAuth() {
    let p = ProviderPolicy(["Auth": ["Type": "clientCertificate", "IdentityIssuerContains": "Okta", "IdentitySubjectContains": ""]])
    #expect(p.auth == .clientCertificate(subjectContains: nil, issuerContains: "Okta"))
}

@Test func bearerWithoutTokenIsNone() {
    #expect(ProviderPolicy(["Auth": ["Type": "bearer"]]).auth == .none)
}

@Test(arguments: [
    ("http://intel.example.com/list", false), ("ftp://x.com/list", false), ("not a url", false),
    ("https://intel.example.com/list", true), ("http://localhost:8080/list", true), ("http://127.0.0.1/list", true),
])
func urlSchemes(_ text: String, _ accepted: Bool) {
    #expect((ProviderPolicy(["ListURL": text]).listURL != nil) == accepted)
}

@Test func refreshHasFloor() {
    #expect(ProviderPolicy(["RefreshSeconds": 5]).refreshInterval == ProviderPolicy.minimumRefresh)
}

@Test func relativePathIgnored() {
    #expect(ProviderPolicy(["ListPath": "list.txt"]).listPath == ProviderPolicy.defaultListPath)
}

@Test func neverBlockIncludesListHost() {
    let p = ProviderPolicy(["ListURL": "https://Intel.Example.com/list", "NeverBlockHosts": ["mdm.example.com"]])
    let b = p.blocklist(CompiledList(source: Array("example.com\napple.com".utf8)))
    #expect(b.verdict(for: "intel.example.com") == .allowed(rule: "intel.example.com"))
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
