import CryptoKit
import Foundation

/// Server key pins for the event URL (`EventServerPins`).
///
/// A pin is the SHA-256 of a server certificate's SubjectPublicKeyInfo, in
/// base64: the value of
/// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
/// A pin replaces the system trust check, so a self-signed server
/// certificate works. Only EC P-256 keys can be pinned.
public enum ServerPins {
    /// The DER header of a P-256 SubjectPublicKeyInfo. The 65-byte
    /// uncompressed point follows it.
    static let p256Header = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    /// The server's leaf key, as far as the pin check needs it.
    public enum LeafKey: Sendable, Equatable {
        /// The server sent no certificate.
        case none
        /// An EC P-256 key, as the 65-byte uncompressed point (X9.63).
        case p256(Data)
        /// Any other key type or size.
        case other
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case noUsablePin
        case noServerCertificate
        case keyNotP256
        case mismatch

        public var description: String {
            switch self {
            case .noUsablePin: "EventServerPins holds no usable pin, so every post is refused"
            case .noServerCertificate: "the event server sent no certificate"
            case .keyNotP256: "the event server's key is not EC P-256, so it cannot match a pin"
            case .mismatch: "server pin mismatch: the event server's key matches no entry in EventServerPins"
            }
        }
    }

    /// The pin of a P-256 key, or nil when the point is not 65 bytes in the
    /// uncompressed form.
    public static func pin(p256Point point: Data) -> Data? {
        guard point.count == 65, point.first == 0x04 else { return nil }
        return Data(SHA256.hash(data: p256Header + point))
    }

    /// Nil when the server's key matches a pin, else the reason. Fail
    /// closed: no pins means no match.
    public static func check(pins: [Data], leaf: LeafKey) -> Failure? {
        guard !pins.isEmpty else { return .noUsablePin }
        switch leaf {
        case .none: return .noServerCertificate
        case .other: return .keyNotP256
        case .p256(let point):
            guard let pin = pin(p256Point: point) else { return .keyNotP256 }
            return pins.contains(pin) ? nil : .mismatch
        }
    }

    /// Reads one policy entry: base64 of exactly 32 bytes.
    static func parse(_ text: String) -> Data? {
        guard let data = Data(base64Encoded: text.trimmingCharacters(in: .whitespaces)), data.count == 32 else {
            return nil
        }
        return data
    }
}
