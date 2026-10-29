import Foundation

/// The MDM policy, read from the DNS Proxy payload's `ProviderConfiguration`.
/// Unknown keys are ignored and bad values fall back to defaults, because a
/// typo in a profile must not stop the proxy from starting. docs/mdm.md lists
/// every key.
public struct ProviderPolicy: Sendable, Equatable {
    /// The local list must be inside this root-owned folder. The extension's
    /// sandbox can read nothing else, and a path elsewhere could point at a
    /// file a standard user can edit.
    public static let listFolder = "/Library/Application Support/SafeRoom/"
    public static let defaultListPath = listFolder + "blocklist.txt"

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
    /// the current list, is rejected. 0 (the default) turns the check off.
    ///
    /// Off by default because a rejection never clears on its own: when a
    /// feed legitimately grows or shrinks (a source added or dropped), every
    /// Mac would keep the old list until an admin changed the profile.
    public var maxChangePercent: Int = 0
    public var maxListBytes: Int = 64 << 20
    /// Lets list rules like `*.zip` block a whole top-level domain.
    public var allowTopLevelBlocks = false
    /// HTTPS URL that receives block events as JSON POSTs. Nil turns event
    /// posting off.
    public var eventURL: URL?
    /// How to authenticate to `eventURL`. Separate from `auth`, so the list
    /// token can stay read-only and the event token can only write events.
    public var eventAuth: Auth = .none
    /// Time between event posts. A post also goes out early when a full
    /// batch is waiting.
    public var eventInterval: Duration = .seconds(10)
    /// `EventServerPins`, decoded. Nil when the key is absent: the system
    /// trust check applies. Empty when the key is present but holds no
    /// usable pin: every post is refused (`ServerPins`).
    public var eventServerPins: [Data]?
    /// True when the SafeRoom app wrote this policy (`ConfiguredBy = app`),
    /// not an MDM profile. Only the app's window reads it, to decide whether
    /// the user may edit the policy (`ConfigurationAccess`).
    public var configuredByApp = false
    /// Policy values that were present but unusable, with the reason, for
    /// the log. Without this, a typo silently becomes a default.
    public var ignored: [String] = []

    public static let minimumRefresh: Duration = .seconds(300)
    public static let configuredByKey = "ConfiguredBy"
    public static let configuredByApp = "app"

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
        if let path = config["ListPath"] as? String {
            if path.hasPrefix(Self.listFolder), !path.split(separator: "/").contains("..") {
                listPath = path
            } else {
                ignored.append("ListPath \"\(path)\": must be inside \(Self.listFolder)")
            }
        }
        listURL = url("ListURL", config)
        listSHA256URL = url("ListSHA256URL", config)
        eventURL = url("EventURL", config)
        allowList = rules("AllowList", config)
        neverBlockHosts = rules("NeverBlockHosts", config).map(\.name)
        // Every number is clamped: an absurd profile value must not overflow
        // arithmetic and crash the extension on every refresh.
        if let seconds = Self.int(config["RefreshSeconds"]) {
            refreshInterval = .seconds(min(max(seconds, 300), 7 * 86_400))
        }
        if let percent = Self.int(config["MaxChangePercent"]) { maxChangePercent = min(max(percent, 0), 10_000) }
        if let megabytes = Self.int(config["MaxListMegabytes"]) { maxListBytes = min(max(megabytes, 1), 1024) << 20 }
        if let seconds = Self.int(config["EventIntervalSeconds"]) {
            eventInterval = .seconds(min(max(seconds, 1), 3600))
        }
        auth = Self.auth(config["Auth"])
        eventAuth = Self.auth(config["EventAuth"])
        if let value = config["EventServerPins"] { eventServerPins = pins("EventServerPins", value) }
        allowTopLevelBlocks = config["AllowTopLevelBlocks"] as? Bool ?? false
        configuredByApp = config[Self.configuredByKey] as? String == Self.configuredByApp
    }

    /// The never-block set: built-in names and NeverBlockHosts, each with
    /// everything under it.
    public var effectiveNeverBlock: [String] { NeverBlock.builtIn + neverBlockHosts }

    /// The list URL's host is never blocked, or a feed that listed its own
    /// server could never be fixed. The event URL's host neither, or a feed
    /// that listed it would silently stop every event. Exact name only: if
    /// a URL sits on a shared host, the names under it stay blockable.
    public var listHostRules: [DomainRule] {
        [listURL, listSHA256URL, eventURL].compactMap { url in
            guard let host = url?.host()?.lowercased(), IPAddress.parse(Substring(host)) == nil else { return nil }
            return DomainRule(name: host, match: .exact)
        }
    }

    public func blocklist(_ list: CompiledList) -> Blocklist {
        Blocklist(
            list: list, allow: allowList + listHostRules, neverBlock: effectiveNeverBlock,
            allowTopLevelBlocks: allowTopLevelBlocks)
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

    private mutating func url(_ key: String, _ config: [String: Any]) -> URL? {
        guard let value = config[key] else { return nil }
        if let url = Self.url(value) { return url }
        // The value is not logged: a URL can carry a credential.
        ignored.append("\(key): must be an https URL")
        return nil
    }

    private mutating func rules(_ key: String, _ config: [String: Any]) -> [DomainRule] {
        guard let value = config[key] else { return [] }
        guard let items = value as? [Any] else {
            ignored.append("\(key): must be an array of strings")
            return []
        }
        return items.compactMap { item in
            guard let text = item as? String else {
                ignored.append("\(key) entry \"\(item)\": not a string")
                return nil
            }
            switch ListParser.parseDomain(Substring(text)) {
            case .success(let rule): return rule
            case .failure(let error):
                ignored.append("\(key) entry \"\(text)\": \(error.reason)")
                return nil
            }
        }
    }

    /// Pins are public values, so the bad ones are logged in full.
    private mutating func pins(_ key: String, _ value: Any) -> [Data] {
        guard let items = value as? [Any] else {
            ignored.append("\(key): must be an array of strings")
            return []
        }
        return items.compactMap { item in
            guard let text = item as? String, let pin = ServerPins.parse(text) else {
                ignored.append("\(key) entry \"\(item)\": not the base64 of a SHA-256")
                return nil
            }
            return pin
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
