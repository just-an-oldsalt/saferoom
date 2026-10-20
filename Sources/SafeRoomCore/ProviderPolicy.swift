/// The MDM policy, read from the DNS Proxy payload's `ProviderConfiguration`.
/// Unknown keys are ignored and bad values fall back to defaults, because a
/// typo in a profile must not stop the proxy from starting.
///
/// Phase 4 reads the local-file keys. Phase 5 adds the URL fetch keys.
public struct ProviderPolicy: Sendable, Equatable {
    public static let defaultListPath = "/Library/Application Support/SafeRoom/blocklist.txt"

    public var listPath: String = defaultListPath
    public var allowList: [DomainRule] = []
    public var neverBlockHosts: [String] = []

    public init() {}

    public init(_ config: [String: Any]) {
        if let path = config["ListPath"] as? String, path.hasPrefix("/") { listPath = path }
        allowList = Self.rules(config["AllowList"])
        neverBlockHosts = Self.rules(config["NeverBlockHosts"]).map(\.name)
    }

    /// Domain strings in the same forms as the blocklist; bad ones are dropped.
    static func rules(_ value: Any?) -> [DomainRule] {
        (value as? [Any] ?? []).compactMap { item in
            (item as? String).flatMap { try? ListParser.parseDomain(Substring($0)).get() }
        }
    }

    public func blocklist(_ list: CompiledList) -> Blocklist {
        Blocklist(list: list, allow: allowList, neverBlock: NeverBlock.builtIn + neverBlockHosts)
    }
}
