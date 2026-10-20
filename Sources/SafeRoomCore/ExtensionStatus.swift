import Foundation
import Synchronization

/// What the extension reports over XPC, to the app window and to `--status`.
/// JSON, so a Jamf extension attribute or a script can read it too.
public struct ExtensionStatus: Codable, Sendable, Equatable {
    public var version: String
    public var startedAt: Date
    public var policy: PolicySummary
    public var list: ListSummary?
    public var lastAttempt: Attempt?
    /// Time of the last download or file read that ended with a current list
    /// (accepted or unchanged). Health is measured from here.
    public var lastSuccessAt: Date?
    public var nextRefreshAt: Date?
    public var consecutiveFailures: Int
    public var counters: CounterValues

    public init(
        version: String, startedAt: Date, policy: PolicySummary, list: ListSummary?,
        lastAttempt: Attempt?, lastSuccessAt: Date?, nextRefreshAt: Date?,
        consecutiveFailures: Int, counters: CounterValues
    ) {
        self.version = version
        self.startedAt = startedAt
        self.policy = policy
        self.list = list
        self.lastAttempt = lastAttempt
        self.lastSuccessAt = lastSuccessAt
        self.nextRefreshAt = nextRefreshAt
        self.consecutiveFailures = consecutiveFailures
        self.counters = counters
    }

    public struct PolicySummary: Codable, Sendable, Equatable {
        /// With the query string and any user info removed, which can hold
        /// secrets.
        public var listURL: String?
        public var listPath: String
        public var sha256Check: Bool
        public var auth: String
        public var refreshSeconds: Int
        public var maxChangePercent: Int
        public var allowListCount: Int
        public var neverBlockHostCount: Int
    }

    public struct ListSummary: Codable, Sendable, Equatable {
        public var source: String
        public var loadedAt: Date
        public var domainRules: Int
        public var v4Ranges: Int
        public var v6Ranges: Int
        public var invalidLines: Int
        public var memoryBytes: Int
        /// First 16 hex characters of the source's SHA-256.
        public var sha256Prefix: String
    }

    public struct Attempt: Codable, Sendable, Equatable {
        public enum Result: String, Codable, Sendable {
            case accepted, unchanged, rejected, failed
        }

        public var at: Date
        public var source: String
        public var result: Result
        public var detail: String?

        public init(at: Date, source: String, result: Result, detail: String? = nil) {
            self.at = at
            self.source = source
            self.result = result
            self.detail = detail
        }
    }

    public struct CounterValues: Codable, Sendable, Equatable {
        public var queries = 0
        public var blockedQueries = 0
        public var blockedAnswers = 0
        public var learnedBlocks = 0

        public init() {}
    }
}

extension ExtensionStatus.PolicySummary {
    public init(_ policy: ProviderPolicy) {
        self.init(
            listURL: policy.listURL.map(Self.redacted),
            listPath: policy.listPath,
            sha256Check: policy.listSHA256URL != nil,
            auth: policy.auth.description,
            refreshSeconds: Int(policy.refreshInterval.components.seconds),
            maxChangePercent: policy.maxChangePercent,
            allowListCount: policy.allowList.count,
            neverBlockHostCount: policy.neverBlockHosts.count)
    }

    public static func redacted(_ url: URL) -> String {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return "?" }
        parts.query = nil
        parts.fragment = nil
        parts.user = nil
        parts.password = nil
        return parts.string ?? "?"
    }
}

extension ExtensionStatus {
    /// A source for display: URLs lose their query string and user info,
    /// which can hold secrets. Paths are returned as they are.
    public static func redact(_ source: String) -> String {
        guard source.contains("://"), let url = URL(string: source) else { return source }
        return PolicySummary.redacted(url)
    }
}

extension ExtensionStatus.ListSummary {
    public init(_ list: CompiledList, source: String, loadedAt: Date) {
        self.init(
            source: ExtensionStatus.redact(source), loadedAt: loadedAt,
            domainRules: list.stats.domainRules, v4Ranges: list.stats.v4Ranges, v6Ranges: list.stats.v6Ranges,
            invalidLines: list.stats.invalidCount, memoryBytes: list.byteSize,
            sha256Prefix: list.sourceSHA256.prefix(8).map { String(format: "%02x", $0) }.joined())
    }
}

// MARK: - Health

extension ExtensionStatus {
    public enum Health: String, Sendable {
        /// A list is loaded and the last check succeeded recently.
        case ok = "OK"
        /// The last attempts failed, but the list is not stale yet.
        case degraded = "DEGRADED"
        /// No successful check for three refresh intervals.
        case stale = "STALE"
        /// No list is loaded. Every query passes (fail-open).
        case noList = "NO LIST"
    }

    public func health(now: Date = Date()) -> Health {
        guard let list, list.domainRules + list.v4Ranges + list.v6Ranges > 0 else { return .noList }
        let staleAfter = TimeInterval(policy.refreshSeconds * 3)
        // Right after a start, the cached list is in use and the first check
        // is still running. Count the start as the reference until then.
        let reference = lastSuccessAt ?? startedAt
        if now.timeIntervalSince(reference) > staleAfter { return .stale }
        return consecutiveFailures > 0 ? .degraded : .ok
    }

    /// One line for a Jamf extension attribute or a monitoring check.
    public func healthLine(now: Date = Date()) -> String {
        let health = health(now: now)
        var parts: [String] = []
        if let list { parts.append("\(list.domainRules) domains, \(list.v4Ranges + list.v6Ranges) ranges") }
        if let lastSuccessAt { parts.append("list checked \(Self.stamp(lastSuccessAt))") }
        if consecutiveFailures > 0, let lastAttempt {
            parts.append("\(consecutiveFailures) failed: \(lastAttempt.detail ?? lastAttempt.result.rawValue)")
        }
        return parts.isEmpty ? health.rawValue : "\(health.rawValue): \(parts.joined(separator: ", "))"
    }

    static func stamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f.string(from: date)
    }

    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return e
    }()

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

/// Per-process counts, updated from every flow without a lock.
public final class FilterCounters: Sendable {
    let queries = Atomic<Int>(0)
    let blockedQueries = Atomic<Int>(0)
    let blockedAnswers = Atomic<Int>(0)
    let learnedBlocks = Atomic<Int>(0)

    public init() {}

    public var values: ExtensionStatus.CounterValues {
        var v = ExtensionStatus.CounterValues()
        v.queries = queries.load(ordering: .relaxed)
        v.blockedQueries = blockedQueries.load(ordering: .relaxed)
        v.blockedAnswers = blockedAnswers.load(ordering: .relaxed)
        v.learnedBlocks = learnedBlocks.load(ordering: .relaxed)
        return v
    }
}
