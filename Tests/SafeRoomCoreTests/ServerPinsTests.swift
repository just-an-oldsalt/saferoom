import CryptoKit
import Foundation
import Testing
@testable import SafeRoomCore

/// The pin of a key is the SHA-256 of its DER SubjectPublicKeyInfo, which is
/// what openssl prints. CryptoKit's `derRepresentation` is that structure.
@Test func pinMatchesOpenSSLForm() throws {
    let key = P256.Signing.PrivateKey().publicKey
    let expected = Data(SHA256.hash(data: key.derRepresentation))
    #expect(ServerPins.pin(p256Point: key.x963Representation) == expected)
    #expect(ServerPins.check(pins: [expected], leaf: .p256(key.x963Representation)) == nil)
}

@Test func pinFailuresHaveReasons() {
    let key = P256.Signing.PrivateKey().publicKey
    let other = Data(SHA256.hash(data: P256.Signing.PrivateKey().publicKey.derRepresentation))
    #expect(ServerPins.check(pins: [other], leaf: .p256(key.x963Representation)) == .mismatch)
    #expect(ServerPins.check(pins: [], leaf: .p256(key.x963Representation)) == .noUsablePin)
    #expect(ServerPins.check(pins: [other], leaf: .none) == .noServerCertificate)
    #expect(ServerPins.check(pins: [other], leaf: .other) == .keyNotP256)
    #expect(ServerPins.check(pins: [other], leaf: .p256(Data(count: 33))) == .keyNotP256)
}

@Test func pinPolicyKey() {
    let dev = "LGXvyWdy35k1bIUgN9it9LsXkoCRvk5oLHh4CLbmGD0="
    let p = ProviderPolicy([
        "EventURL": "https://events.example.com/e",
        "EventServerPins": [dev, "not base64", "AAAA"],
    ])
    #expect(p.eventServerPins == [Data(base64Encoded: dev)!])
    #expect(p.ignored.filter { $0.hasPrefix("EventServerPins entry") }.count == 2)
    #expect(ExtensionStatus.PolicySummary(p).eventServerPins == 1)
}

/// A key that is present but unusable must refuse posts, not fall back to
/// the system trust check.
@Test func unusablePinsFailClosed() {
    let p = ProviderPolicy(["EventURL": "https://events.example.com/e", "EventServerPins": "abc"])
    #expect(p.eventServerPins == [])
    #expect(p.ignored.contains("EventServerPins: must be an array of strings"))
    #expect(ProviderPolicy(["EventURL": "https://events.example.com/e"]).eventServerPins == nil)
}
