import Foundation
import Synchronization

/// One blocked query or answer, as the event URL receives it.
///
/// The fields are the ones the `block` log line carries, so a SIEM that
/// reads both sees the same data.
public struct BlockEvent: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        /// The query name was on the list. Nothing went upstream.
        case query
        /// The upstream answer named a listed alias or address.
        case answer
    }

    public var time: Date
    public var kind: Kind
    public var name: String
    /// The query's record type. Queries only.
    public var type: UInt16?
    /// The list rule that matched, when a domain rule did.
    public var rule: String?
    /// The listed CNAME or SVCB target. Answers only.
    public var alias: String?
    /// The listed address in the answer. Answers only.
    public var address: String?
    /// The signing identifier of the app that asked.
    public var app: String
    public var transport: String

    public init(
        time: Date = Date(), kind: Kind, name: String, type: UInt16? = nil, rule: String? = nil,
        alias: String? = nil, address: String? = nil, app: String, transport: String
    ) {
        self.time = time
        self.kind = kind
        self.name = name
        self.type = type
        self.rule = rule
        self.alias = alias
        self.address = address
        // An ad-hoc signed program chooses its own identifier, of any length.
        self.app = String(app.prefix(300))
        self.transport = transport
    }

    public init(query name: String, type: UInt16, rule: String, app: String, transport: String, time: Date = Date()) {
        self.init(time: time, kind: .query, name: name, type: type, rule: rule, app: app, transport: transport)
    }

    public init(answer name: String, reason: DNSFilter.Reason, app: String, transport: String, time: Date = Date()) {
        switch reason {
        case .alias(let target, let rule):
            self.init(time: time, kind: .answer, name: name, rule: rule, alias: target, app: app, transport: transport)
        case .address(let address):
            self.init(time: time, kind: .answer, name: name, address: address.description, app: app, transport: transport)
        }
    }
}

/// The body of one event POST.
public struct EventBatch: Codable, Sendable, Equatable {
    public struct Device: Codable, Sendable, Equatable {
        public var hostname: String?
        public var serialNumber: String?
        public var version: String

        public init(hostname: String?, serialNumber: String?, version: String) {
            self.hostname = hostname
            self.serialNumber = serialNumber
            self.version = version
        }
    }

    public var device: Device
    public var sentAt: Date
    /// Events lost since the previous batch because the buffer was full.
    public var dropped: Int
    public var events: [BlockEvent]

    public init(device: Device, sentAt: Date = Date(), dropped: Int, events: [BlockEvent]) {
        self.device = device
        self.sentAt = sentAt
        self.dropped = dropped
        self.events = events
    }

    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }()
}

/// Block events waiting to be posted. Every flow adds to it on its own
/// queue, so `add` only takes a lock and appends: a slow or dead event
/// server never delays a DNS answer.
///
/// The buffer is bounded. A flood of blocks, or a server that stays down,
/// drops the oldest events and counts them. The next batch reports the
/// count, so the server knows that events are missing.
public final class EventBuffer: Sendable {
    private struct State {
        var enabled = false
        var events: [BlockEvent] = []
        /// Dropped since the last `take`, for the next batch.
        var droppedPending = 0
        var droppedTotal = 0
    }

    private let state = Mutex(State())
    public let capacity: Int

    public init(capacity: Int = 10_000) {
        self.capacity = max(capacity, 1)
    }

    /// Off by default, so a policy with no event URL holds no events.
    /// Turning it off empties the buffer.
    public func setEnabled(_ enabled: Bool) {
        state.withLock { s in
            s.enabled = enabled
            if !enabled {
                s.events = []
                s.droppedPending = 0
            }
        }
    }

    public func add(_ event: BlockEvent) {
        state.withLock { s in
            guard s.enabled else { return }
            if s.events.count >= capacity { dropOldest(&s, keeping: capacity - 1) }
            s.events.append(event)
        }
    }

    /// Removes up to `limit` of the oldest events, with the drop count that
    /// goes with them.
    public func take(_ limit: Int) -> (events: [BlockEvent], dropped: Int) {
        state.withLock { s in
            let events = Array(s.events.prefix(limit))
            s.events.removeFirst(events.count)
            let dropped = s.droppedPending
            s.droppedPending = 0
            return (events, dropped)
        }
    }

    /// Returns a batch that could not be posted to the front of the buffer.
    /// Events added meanwhile stay behind it, and the oldest go first if the
    /// two together do not fit.
    public func putBack(_ events: [BlockEvent], dropped: Int) {
        state.withLock { s in
            guard s.enabled else { return }
            s.events = events + s.events
            s.droppedPending += dropped
            if s.events.count > capacity { dropOldest(&s, keeping: capacity) }
        }
    }

    public var count: Int { state.withLock { $0.events.count } }
    public var droppedTotal: Int { state.withLock { $0.droppedTotal } }

    /// Drops at least a tenth of the capacity at once, so a flood does not
    /// move the whole array on every add.
    private func dropOldest(_ s: inout State, keeping limit: Int) {
        let excess = s.events.count - limit
        guard excess > 0 else { return }
        let drop = min(s.events.count, max(excess, capacity / 10))
        s.events.removeFirst(drop)
        s.droppedPending += drop
        s.droppedTotal += drop
    }
}

extension ExtensionStatus {
    /// Event posting, when the policy sets an event URL.
    public struct EventSummary: Codable, Sendable, Equatable {
        /// Without the query string and user info.
        public var url: String
        public var auth: String
        public var intervalSeconds: Int
        public var queued: Int
        public var posted: Int
        public var dropped: Int
        public var consecutiveFailures: Int
        public var lastPostAt: Date?
        public var lastError: String?

        public init(
            url: String, auth: String, intervalSeconds: Int, queued: Int, posted: Int, dropped: Int,
            consecutiveFailures: Int, lastPostAt: Date?, lastError: String?
        ) {
            self.url = url
            self.auth = auth
            self.intervalSeconds = intervalSeconds
            self.queued = queued
            self.posted = posted
            self.dropped = dropped
            self.consecutiveFailures = consecutiveFailures
            self.lastPostAt = lastPostAt
            self.lastError = lastError
        }
    }
}
