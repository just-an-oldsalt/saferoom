import Foundation

/// The MDM policy, read from the DNS Proxy payload's `ProviderConfiguration`.
/// Unknown keys are ignored and bad values fall back to defaults, because a
/// typo in a profile must not stop the proxy from starting. docs/mdm.md lists
/// every key.
public struct ProviderPolicy: Sendable, Equatable {
    public static let defaultListPath = "/Library/Application Support/SafeRoom/blocklist.txt"

    /// HTTPS URL of the list. When set, it is the primary source.
    public var listURL: URL?
    /// Local list. The only source when `listURL` is nil; otherwise the
    /// fallback while nothing has loaded yet.
    public var listPath: String = defaultListPath
    /// Optional URL of the list's SHA-256, as hex. A download whose hash does
    /// not match is rejected.
    public var listSHA256URL: URL?
    public var auth: Auth = .none
    public var allowList: [DomainRule] = []
    public var neverBlockHosts: [String] = []
    public var refreshInterval: Duration = .seconds(3600)
    /// A new list whose entry count changes by more than this, compared with
    /// the current list, is rejected. 0 turns the check off.
    public var maxChangePercent: Int = 50
    public var maxListBytes: Int = 64 << 20

    public static let minimumRefresh: Duration = .seconds(300)

    public enum Auth: Sendable, Equatable {
        case none
        /// `Authorization: Bearer <token>`.
        case bearer(token: String)
        /// TLS client certificate from the keychain, chosen by substrings of
        /// its subject and issuer. docs/mtls-okta.md covers the open risks.
        case clientCertificate(subjectContains: String?, issuerContains: String?)
    }

    public init() {}

    public init(_ config: [String: Any]) {
        if let path = config["ListPath"] as? String, path.hasPrefix("/") { listPath = path }
        listURL = Self.url(config["ListURL"])
        listSHA256URL = Self.url(config["ListSHA256URL"])
        allowList = Self.rules(config["AllowList"])
        neverBlockHosts = Self.rules(config["NeverBlockHosts"]).map(\.name)
        if let seconds = Self.int(config["RefreshSeconds"]) {
            refreshInterval = max(.seconds(seconds), Self.minimumRefresh)
        }
        if let percent = Self.int(config["MaxChangePercent"]), percent >= 0 { maxChangePercent = percent }
        if let megabytes = Self.int(config["MaxListMegabytes"]), megabytes > 0 { maxListBytes = megabytes << 20 }
        auth = Self.auth(config["Auth"])
    }

    /// The list URL's host joins the never-block set: a feed that listed its
    /// own server could never be fixed by pushing a new list.
    public var effectiveNeverBlock: [String] {
        var hosts = NeverBlock.builtIn + neverBlockHosts
        for url in [listURL, listSHA256URL] {
            if let host = url?.host()?.lowercased(), IPAddress.parse(Substring(host)) == nil { hosts.append(host) }
        }
        return hosts
    }

    public func blocklist(_ list: CompiledList) -> Blocklist {
        Blocklist(list: list, allow: allowList, neverBlock: effectiveNeverBlock)
    }

    // MARK: - Value parsing

    /// HTTPS only, except loopback, so a list can be tested from a local server.
    static func url(_ value: Any?) -> URL? {
        guard let text = value as? String, let url = URL(string: text), let host = url.host() else { return nil }
        switch url.scheme?.lowercased() {
        case "https": return url
        case "http" where ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host.lowercased()): return url
        default: return nil
        }
    }

    /// Profiles carry numbers as integers, but a hand-edited one can carry a
    /// string. Accept both.
    static func int(_ value: Any?) -> Int? {
        switch value {
        case let n as Int: n
        case let n as NSNumber: n.intValue
        case let s as String: Int(s)
        default: nil
        }
    }

    static func rules(_ value: Any?) -> [DomainRule] {
        (value as? [Any] ?? []).compactMap { item in
            (item as? String).flatMap { try? ListParser.parseDomain(Substring($0)).get() }
        }
    }

    static func auth(_ value: Any?) -> Auth {
        guard let dict = value as? [String: Any] else { return .none }
        switch (dict["Type"] as? String)?.lowercased() {
        case "bearer":
            guard let token = dict["Token"] as? String, !token.isEmpty else { return .none }
            return .bearer(token: token)
        case "clientcertificate":
            let subject = (dict["IdentitySubjectContains"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            let issuer = (dict["IdentityIssuerContains"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            return .clientCertificate(subjectContains: subject, issuerContains: issuer)
        default:
            return .none
        }
    }
}

extension ProviderPolicy.Auth: CustomStringConvertible {
    /// For logs. Never prints the token.
    public var description: String {
        switch self {
        case .none: "none"
        case .bearer: "bearer"
        case .clientCertificate(let subject, let issuer):
            "clientCertificate(subject~\(subject ?? "*"), issuer~\(issuer ?? "*"))"
        }
    }
}
