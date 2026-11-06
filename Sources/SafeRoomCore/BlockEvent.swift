import Foundation
import Synchronization

/// One lookup, as the event URL receives it: a block, a block that monitor
/// mode let through, a name outside the permit list, or, with
/// `EventAllQueries`, an allowed lookup.
///
/// The fields of a block are the ones the `block` log line carries, so a
/// SIEM that reads both sees the same data.
public struct BlockEvent: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        /// About the query name: it was on the list, or, for `allowed`, the
        /// lookup itself.
        case query
        /// The upstream answer named a listed alias or address.
        case answer
    }

    public enum Action: String, Codable, Sendable {
        /// SafeRoom answered NXDOMAIN.
        case blocked
        /// Monitor mode: the answer went to the app unchanged, but would
        /// have been blocked.
        case wouldBlock
        /// `PermitOnly`: the name is not on the permit list. SafeRoom
        /// answered NXDOMAIN.
        case denied
        /// `PermitOnly` with `MonitorOnly`: the name is not on the permit
        /// list, but the answer went to the app unchanged.
        case wouldDeny
        /// `EventAllQueries`: a lookup that nothing on the list matched.
        case allowed
    }

    /// A threat-list match, blocked or not. These skip the post interval.
    public var isUrgent: Bool { action == .blocked || action == .wouldBlock }

    public var time: Date
    public var kind: Kind
    public var action: Action
    public var name: String
    /// The query's record type. Queries only.
    public var type: UInt16?
    /// The list rule that matched, when a domain rule did.
    public var rule: String?
    /// The listed CNAME or SVCB target. Answers only.
    public var alias: String?
    /// The listed address in the answer. Answers only.
    public var address: String?
    /// `allowed` only: every address in the answer.
    public var addresses: [String]?
    /// `allowed` only: every CNAME and SVCB target in the answer.
    public var aliases: [String]?
    /// The signing identifier of the app that asked.
    public var app: String
    public var transport: String

    public init(
        time: Date = Date(), kind: Kind, action: Action = .blocked, name: String, type: UInt16? = nil,
        rule: String? = nil, alias: String? = nil, address: String? = nil, addresses: [String]? = nil,
        aliases: [String]? = nil, app: String, transport: String
    ) {
        self.time = time
        self.kind = kind
        self.action = action
        self.addresses = addresses
        self.aliases = aliases
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

    /// Monitor mode. A listed query name reads as a `query` event, the
    /// same as when it is blocked; anything else as an `answer` event.
    public init(
        wouldBlock name: String, type: UInt16, reason: DNSFilter.Reason, app: String, transport: String,
        time: Date = Date()
    ) {
        if case .alias(let target, let rule) = reason, target == name {
            self.init(time: time, kind: .query, action: .wouldBlock, name: name, type: type, rule: rule,
                      app: app, transport: transport)
        } else {
            self.init(answer: name, reason: reason, app: app, transport: transport, time: time)
            action = .wouldBlock
        }
    }

    /// `PermitOnly`: a query name outside the permit list. `monitoring`
    /// means the lookup went through.
    public init(
        denied name: String, type: UInt16, monitoring: Bool = false, app: String, transport: String,
        time: Date = Date()
    ) {
        self.init(time: time, kind: .query, action: monitoring ? .wouldDeny : .denied, name: name, type: type,
                  app: app, transport: transport)
    }

    /// `EventAllQueries`: an upstream response that passed. Nil when the
    /// packet is not a readable response.
    public init?(allowed response: [UInt8], app: String, transport: String, time: Date = Date()) {
        guard let q = DNSMessage.question(response), q.isResponse else { return nil }
        let answer = DNSMessage.answer(response) ?? DNSMessage.Answer()
        let addresses = answer.addresses.map(\.description)
        let aliases = answer.names.map { String(decoding: $0, as: UTF8.self) }
        self.init(
            time: time, kind: .query, action: .allowed, name: q.nameString, type: q.type,
            addresses: addresses.isEmpty ? nil : addresses, aliases: aliases.isEmpty ? nil : aliases,
            app: app, transport: transport)
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
/// Two queues. Threat-list matches (`isUrgent`) go first: `take` empties
/// them before the rest, and the poster sends them without waiting for the
/// interval. Everything else (allowed lookups, permit-list denials) waits
/// for the next post.
///
/// The buffer is bounded. A flood, or a server that stays down, drops the
/// oldest events and counts them. The other events go first, so a flood of
/// allowed lookups cannot push out a block. The next batch reports the
/// count, so the server knows that events are missing.
public final class EventBuffer: Sendable {
    private struct State {
        var enabled = false
        var urgent: [BlockEvent] = []
        var routine: [BlockEvent] = []
        /// Dropped since the last `take`, for the next batch.
        var droppedPending = 0
        var droppedTotal = 0

        var count: Int { urgent.count + routine.count }
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
                s.urgent = []
                s.routine = []
                s.droppedPending = 0
            }
        }
    }

    public func add(_ event: BlockEvent) {
        state.withLock { s in
            guard s.enabled else { return }
            if s.count >= capacity { dropOldest(&s, keeping: capacity - 1) }
            if event.isUrgent { s.urgent.append(event) } else { s.routine.append(event) }
        }
    }

    /// Removes up to `limit` events, urgent ones first and the oldest first
    /// within each queue, with the drop count that goes with them.
    public func take(_ limit: Int) -> (events: [BlockEvent], dropped: Int) {
        state.withLock { s in
            var events = Array(s.urgent.prefix(limit))
            s.urgent.removeFirst(events.count)
            let more = s.routine.prefix(limit - events.count)
            s.routine.removeFirst(more.count)
            events += more
            let dropped = s.droppedPending
            s.droppedPending = 0
            return (events, dropped)
        }
    }

    /// Returns a batch that could not be posted to the front of its queues.
    /// Events added meanwhile stay behind it, and the oldest go first if the
    /// two together do not fit.
    public func putBack(_ events: [BlockEvent], dropped: Int) {
        state.withLock { s in
            guard s.enabled else { return }
            s.urgent = events.filter(\.isUrgent) + s.urgent
            s.routine = events.filter { !$0.isUrgent } + s.routine
            s.droppedPending += dropped
            if s.count > capacity { dropOldest(&s, keeping: capacity) }
        }
    }

    public var count: Int { state.withLock { $0.count } }
    /// Events that the poster sends without waiting for the interval.
    public var urgentCount: Int { state.withLock { $0.urgent.count } }
    public var droppedTotal: Int { state.withLock { $0.droppedTotal } }

    /// Drops at least a tenth of the capacity at once, so a flood does not
    /// move the whole array on every add. Routine events go first.
    private func dropOldest(_ s: inout State, keeping limit: Int) {
        let excess = s.count - limit
        guard excess > 0 else { return }
        var drop = min(s.count, max(excess, capacity / 10))
        s.droppedPending += drop
        s.droppedTotal += drop
        let routine = min(drop, s.routine.count)
        s.routine.removeFirst(routine)
        drop -= routine
        s.urgent.removeFirst(min(drop, s.urgent.count))
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
        /// New TLS connections to the event server since the start. Far
        /// fewer than the posts when the server keeps connections open.
        /// Optional, so a status from an older extension still decodes.
        public var connectionsOpened: Int?

        public init(
            url: String, auth: String, intervalSeconds: Int, queued: Int, posted: Int, dropped: Int,
            consecutiveFailures: Int, lastPostAt: Date?, lastError: String?, connectionsOpened: Int? = nil
        ) {
            self.connectionsOpened = connectionsOpened
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
