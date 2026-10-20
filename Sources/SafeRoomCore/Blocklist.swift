/// What the proxy asks for every query: the compiled feed plus the allowlist.
///
/// Immutable and `Sendable`. A reload builds a new one and swaps it in, so a
/// lookup never sees a half-built list.
public struct Blocklist: Sendable {
    public let list: CompiledList
    /// Policy allowlist plus the built-in never-block set. Checked first, and
    /// a match here always wins over the blocklist, whatever is more specific.
    public let allow: DomainSet

    public init(list: CompiledList, allow: [DomainRule] = [], neverBlock: [String] = NeverBlock.builtIn) {
        self.list = list
        self.allow = DomainSet(allow + neverBlock.map { DomainRule(name: $0, match: .subtree) })
    }

    public static let empty = Blocklist(list: .empty)

    public enum Verdict: Sendable, Equatable {
        case pass
        /// An allow rule matched. `rule` is the matching suffix of the query.
        case allowed(rule: String)
        /// A block rule matched. `rule` is the matching suffix of the query.
        case blocked(rule: String)
    }

    /// `name` in any case, with or without a trailing dot.
    public func verdict(for name: String) -> Verdict {
        var bytes = Array(name.utf8)
        DomainKey.normalize(&bytes)
        return verdict(normalized: bytes)
    }

    /// `name` already lowercase with no trailing dot (from the DNS codec).
    public func verdict(normalized name: [UInt8]) -> Verdict {
        name.withUnsafeBufferPointer { buffer in
            func suffix(_ length: Int) -> String {
                String(decoding: buffer[(buffer.count - length)...], as: UTF8.self)
            }
            if let length = allow.matchedSuffixLength(buffer) { return .allowed(rule: suffix(length)) }
            if let length = list.domains.matchedSuffixLength(buffer) { return .blocked(rule: suffix(length)) }
            return .pass
        }
    }

    public func isBlocked(_ address: IPAddress) -> Bool {
        switch address {
        case .v4(let a): list.v4.contains(a)
        case .v6(let a): list.v6.contains(a)
        }
    }
}

/// Domains SafeRoom never blocks, whatever the list says. A bad feed that
/// lists one of these would cut Macs off from the services that are needed to
/// push a fixed list: Apple for system services, the MDM, the identity
/// provider. Policy adds its own hosts (the MDM server, the list URL host).
public enum NeverBlock {
    public static let builtIn: [String] = [
        "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "cdn-apple.com",
        "jamf.com", "jamfcloud.com",
        "okta.com", "oktacdn.com", "okta-emea.com", "oktapreview.com",
    ]
}
