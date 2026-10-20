import Darwin

/// How a domain entry matches names. The spelling of the line picks the mode;
/// docs/list-format.md is the reference.
public enum DomainMatch: UInt8, Sendable, Hashable {
    /// `evil.com`: the name and every name under it. What threat feeds mean.
    case subtree = 1
    /// `=evil.com`: that exact name only.
    case exact = 2
    /// `*.evil.com`: names under it, but not `evil.com` itself.
    case subdomainsOnly = 3
}

public struct DomainRule: Sendable, Hashable {
    /// Lowercase ASCII, no trailing dot.
    public let name: String
    public let match: DomainMatch

    public init(name: String, match: DomainMatch) {
        self.name = name
        self.match = match
    }
}

/// An address range. Host bits below the prefix are always zero.
public enum CIDRRule: Sendable, Hashable {
    case v4(UInt32, prefix: UInt8)
    case v6(UInt128, prefix: UInt8)
}

public struct InvalidLine: Sendable, Hashable {
    public let line: Int
    public let text: String
    public let reason: String
}

public struct ParsedList: Sendable {
    public var domains: [DomainRule] = []
    public var cidrs: [CIDRRule] = []
    /// Every bad line is counted, but only the first `sampleLimit` are kept,
    /// so a feed that is all garbage cannot cost unbounded memory.
    public var invalidCount = 0
    public var invalidSamples: [InvalidLine] = []
    public var lineCount = 0

    public static let sampleLimit = 50

    mutating func reject(line: Int, text: String, reason: String) {
        invalidCount += 1
        if invalidSamples.count < Self.sampleLimit {
            invalidSamples.append(InvalidLine(line: line, text: text, reason: reason))
        }
    }
}

/// Turns blocklist text into rules. Bad lines are recorded and skipped; they
/// never fail the whole list, because one typo in a 250k-line feed must not
/// leave a fleet unprotected.
public enum ListParser {
    /// Longer lines are rejected unread. No valid entry is near this long,
    /// and the cap bounds the work one line can cause.
    public static let maxLineBytes = 4096

    public static func parse(_ text: String) -> ParsedList {
        parse(Array(text.utf8))
    }

    /// Splits on the newline BYTE, one line at a time.
    ///
    /// Not `String.split(separator: "\n")`: Swift treats "\r\n" as one
    /// Character that never equals "\n", so a CRLF file became one line and
    /// parsed to nothing. Not a split into an array either: 64 MB of empty
    /// lines made 64 million substrings and gigabytes of memory.
    public static func parse(_ bytes: some Collection<UInt8>) -> ParsedList {
        let data = Array(bytes)
        var out = ParsedList()
        var lineNumber = 0
        var start = 0
        while start < data.count {
            let end = data[start...].firstIndex(of: UInt8(ascii: "\n")) ?? data.count
            lineNumber += 1
            if end - start > maxLineBytes {
                out.reject(line: lineNumber, text: "(line of \(end - start) bytes)", reason: "line longer than \(maxLineBytes) bytes")
            } else if end > start {
                // A trailing "\r" is removed by trimmingWhitespace.
                let line = String(decoding: data[start..<end], as: UTF8.self)
                parseLine(Substring(line), number: lineNumber, into: &out)
            }
            start = end + 1
        }
        out.lineCount = lineNumber
        return out
    }

    static func parseLine(_ raw: Substring, number: Int, into out: inout ParsedList) {
        var line = raw
        if let hash = line.firstIndex(of: "#") { line = line[..<hash] }
        line = line.trimmingWhitespace()
        if line.isEmpty || line.hasPrefix("!") { return }  // `!` is an Adblock comment

        func reject(_ reason: String) {
            out.reject(line: number, text: String(raw.prefix(200)), reason: reason)
        }

        let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" })

        // Hosts-file form: `0.0.0.0 evil.com [more.names ...]`.
        if tokens.count > 1 {
            guard parseAddress(tokens[0]) != nil else {
                return reject("more than one field, and the first is not an IP address")
            }
            for token in tokens.dropFirst() where !hostsFileNoise.contains(token.lowercased()) {
                switch parseDomain(token) {
                case .success(let rule): out.domains.append(rule)
                case .failure(let error): reject(error.reason)
                }
            }
            return
        }

        let token = tokens[0]
        if let cidr = parseCIDR(token) {
            out.cidrs.append(cidr)
            return
        }
        if token.contains("/"), !token.contains("://") {
            return reject("not a valid IP address or CIDR range")
        }
        switch parseDomain(token) {
        case .success(let rule): out.domains.append(rule)
        case .failure(let error): reject(error.reason)
        }
    }

    /// Names that hosts files list for the loopback address. Never rules.
    static let hostsFileNoise: Set<String> = [
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "0.0.0.0",
    ]

    struct DomainError: Error { let reason: String }

    static func parseDomain(_ token: Substring) -> Result<DomainRule, DomainError> {
        var s = token

        // Adblock form `||evil.com^`, common in feed exports. Same as subtree.
        if s.hasPrefix("||") {
            s = s.dropFirst(2)
            if s.hasSuffix("^") { s = s.dropLast() }
        }

        // A URL in a domain feed: keep only the host.
        if let scheme = s.firstRange(of: "://") {
            s = s[scheme.upperBound...]
            if let end = s.firstIndex(where: { $0 == "/" || $0 == "?" }) { s = s[..<end] }
            if let at = s.lastIndex(of: "@") { s = s[s.index(after: at)...] }
            if let colon = s.lastIndex(of: ":"), s[s.index(after: colon)...].allSatisfy(\.isNumber) {
                s = s[..<colon]
            }
        }

        var match = DomainMatch.subtree
        if s.hasPrefix("=") {
            match = .exact
            s = s.dropFirst()
        } else if s.hasPrefix("*.") {
            match = .subdomainsOnly
            s = s.dropFirst(2)
        } else if s.hasPrefix(".") {
            s = s.dropFirst()  // `.evil.com` is an older way to write subtree
        }
        if s.hasSuffix(".") { s = s.dropLast() }

        guard !s.isEmpty else { return .failure(DomainError(reason: "empty name")) }
        guard s.utf8.count <= 253 else { return .failure(DomainError(reason: "name longer than 253 bytes")) }
        guard s.allSatisfy(\.isASCII) else {
            return .failure(DomainError(reason: "non-ASCII name; write it as punycode (xn--...)"))
        }

        let name = s.lowercased()
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            if label.isEmpty { return .failure(DomainError(reason: "empty label (two dots in a row)")) }
            if label.utf8.count > 63 { return .failure(DomainError(reason: "label longer than 63 bytes")) }
            if label.contains("*") { return .failure(DomainError(reason: "wildcard is only supported as a leading *.")) }
            // Underscores are not legal in hostnames but are real in DNS
            // (`_dmarc`, and malware infrastructure that ignores the rules).
            guard label.utf8.allSatisfy({ isDomainByte($0) }) else {
                return .failure(DomainError(reason: "invalid character in name"))
            }
        }

        // A bare `com` would block every .com name. Blocking a whole TLD is a
        // real choice (.zip, .mov), so it is allowed, but only spelled `*.zip`,
        // where the intent cannot be an accident.
        if labels.count == 1, match != .subdomainsOnly {
            return .failure(DomainError(reason: "single-label name; write *.\(name) to block a whole TLD"))
        }
        if IPAddress.parse(Substring(name)) != nil {
            return .failure(DomainError(reason: "IP address where a name was expected"))
        }
        return .success(DomainRule(name: name, match: match))
    }

    static func isDomainByte(_ b: UInt8) -> Bool {
        (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F
    }

    static func parseAddress(_ token: Substring) -> IPAddress? { IPAddress.parse(token) }

    /// `198.51.100.0/24`, `2001:db8::/32`, or a bare address (a /32 or /128).
    public static func parseCIDR(_ token: Substring) -> CIDRRule? {
        let parts = token.split(separator: "/", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count <= 2, let address = IPAddress.parse(parts[0]) else { return nil }
        switch address {
        case .v4(let a):
            var prefix: UInt8 = 32
            if parts.count == 2 {
                guard let p = UInt8(parts[1]), p <= 32 else { return nil }
                prefix = p
            }
            let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
            return .v4(a & mask, prefix: prefix)
        case .v6(let a):
            var prefix: UInt8 = 128
            if parts.count == 2 {
                guard let p = UInt8(parts[1]), p <= 128 else { return nil }
                prefix = p
            }
            let mask: UInt128 = prefix == 0 ? 0 : ~UInt128(0) << (128 - prefix)
            return .v6(a & mask, prefix: prefix)
        }
    }
}

/// An IPv4 or IPv6 address as one integer, in network order (most
/// significant byte first), so ranges compare as plain numbers.
public enum IPAddress: Sendable, Hashable {
    case v4(UInt32)
    case v6(UInt128)

    public static func parse(_ token: Substring) -> IPAddress? {
        let s = String(token)
        var v4 = in_addr()
        if s.contains("."), !s.contains(":"), inet_pton(AF_INET, s, &v4) == 1 {
            return .v4(UInt32(bigEndian: v4.s_addr))
        }
        var v6 = in6_addr()
        if s.contains(":"), inet_pton(AF_INET6, s, &v6) == 1 {
            return .v6(fromBytes(v6))
        }
        return nil
    }

    public static func v6(bytes: some Collection<UInt8>) -> IPAddress {
        var value: UInt128 = 0
        for b in bytes { value = value << 8 | UInt128(b) }
        return .v6(value)
    }

    public static func v4(bytes: some Collection<UInt8>) -> IPAddress {
        var value: UInt32 = 0
        for b in bytes { value = value << 8 | UInt32(b) }
        return .v4(value)
    }

    private static func fromBytes(_ a: in6_addr) -> UInt128 {
        withUnsafeBytes(of: a) { raw in
            var value: UInt128 = 0
            for b in raw { value = value << 8 | UInt128(b) }
            return value
        }
    }
}

extension Substring {
    func trimmingWhitespace() -> Substring {
        let isSpace: (Character) -> Bool = { $0 == " " || $0 == "\t" || $0 == "\r" || $0 == "\u{FEFF}" }
        guard let start = firstIndex(where: { !isSpace($0) }) else { return self[endIndex...] }
        let end = lastIndex(where: { !isSpace($0) })!
        return self[start...end]
    }
}

extension IPAddress: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v4(let a):
            return "\(a >> 24).\(a >> 16 & 0xFF).\(a >> 8 & 0xFF).\(a & 0xFF)"
        case .v6(let a):
            var bytes = in6_addr()
            withUnsafeMutableBytes(of: &bytes) { raw in
                for i in 0..<16 { raw[i] = UInt8(truncatingIfNeeded: a >> (8 * (15 - i))) }
            }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &bytes, &text, socklen_t(text.count))
            return String(decoding: text.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
    }
}
