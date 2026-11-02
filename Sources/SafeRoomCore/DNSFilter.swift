import Synchronization

/// Every decision the proxy makes, in one place and without NetworkExtension,
/// so all of it is unit-tested. The relays only move bytes.
public final class DNSFilter: Sendable {
    public let store: BlocklistStore
    public let counters = FilterCounters()
    let learned: LearnedBlocks
    private let monitorOnly = Atomic<Bool>(false)
    private let reportAll = Atomic<Bool>(false)

    public init(store: BlocklistStore, learnedTTL: Duration = .seconds(300), learnedCapacity: Int = 10_000) {
        self.store = store
        self.learned = LearnedBlocks(ttl: learnedTTL, capacity: learnedCapacity)
    }

    /// Sets the policy's modes, at each proxy start.
    /// - monitorOnly: block nothing. A lookup that would have been blocked
    ///   comes back from `decide(response:)` as `.monitor`.
    /// - reportAllQueries: the relays report every answered lookup
    ///   (`BlockEvent(allowed:)`), not only blocks.
    public func configure(monitorOnly: Bool, reportAllQueries: Bool) {
        self.monitorOnly.store(monitorOnly, ordering: .relaxed)
        reportAll.store(reportAllQueries, ordering: .relaxed)
    }

    public var isMonitorOnly: Bool { monitorOnly.load(ordering: .relaxed) }
    public var reportsAllQueries: Bool { reportAll.load(ordering: .relaxed) }

    public enum QueryDecision: Sendable, Equatable {
        /// Send the packet upstream unchanged.
        case forward
        /// Answer the client with `reply` and do not send anything upstream.
        case block(reply: [UInt8], name: String, type: UInt16, rule: String)
        /// `PermitOnly`: the name is not on the permit list. Answer the
        /// client with `reply` (NXDOMAIN).
        case deny(reply: [UInt8], name: String, type: UInt16)
    }

    public enum ResponseDecision: Sendable, Equatable {
        /// Return the upstream response to the client unchanged.
        case pass
        /// Return `reply` (NXDOMAIN) to the client instead.
        case block(reply: [UInt8], name: String, reason: Reason)
        /// Monitor mode: return the upstream response unchanged, and report
        /// that it would have been blocked.
        case monitor(name: String, type: UInt16, reason: Reason)
        /// `PermitOnly`: the query name is not on the permit list. Return
        /// `reply` (NXDOMAIN).
        case deny(reply: [UInt8], name: String, type: UInt16)
        /// `PermitOnly` with monitor mode: return the upstream response
        /// unchanged, and report that the name is not on the permit list.
        case monitorDeny(name: String, type: UInt16)
    }

    public enum Reason: Sendable, Equatable {
        /// A CNAME or SVCB target is on the domain list.
        case alias(target: String, rule: String)
        /// An A, AAAA or SVCB hint address is in a listed range.
        case address(IPAddress)
    }

    /// Called for each query from a client. Every record type is blocked for a
    /// listed name, including HTTPS (65), so a browser cannot learn an
    /// address for it by asking a different way.
    ///
    /// A name whose answer was recently blocked for its address is blocked
    /// here too, for every record type (see `LearnedBlocks`).
    public func decide(query packet: [UInt8]) -> QueryDecision {
        guard let q = DNSMessage.question(packet), !q.isResponse else { return .forward }
        counters.queries.add(1, ordering: .relaxed)
        // Monitor mode decides on the answer only, so each lookup is
        // reported once. The answer check also sees a listed query name.
        if isMonitorOnly { return .forward }
        let rule: String
        switch store.current.verdict(normalized: q.name) {
        case .blocked(let r):
            rule = r
        case .allowed:
            return .forward
        case .notPermitted:
            guard let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .forward }
            counters.notPermitted.add(1, ordering: .relaxed)
            return .deny(reply: reply, name: q.nameString, type: q.type)
        case .pass:
            guard let address = learned.lookup(q.nameString) else { return .forward }
            rule = "learned:\(address)"
            counters.learnedBlocks.add(1, ordering: .relaxed)
        }
        guard let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .forward }
        counters.blockedQueries.add(1, ordering: .relaxed)
        return .block(reply: reply, name: q.nameString, type: q.type, rule: rule)
    }

    /// Called for each upstream response before it goes back to the client.
    ///
    /// With `PermitOnly`, only the query name must be on the permit list.
    /// CNAME and SVCB targets are checked against the threat list only:
    /// nearly every site answers through a CDN name that no admin would
    /// list. A threat match outranks a permit-list denial.
    ///
    /// An allowlisted query name passes without any check. The allowlist is
    /// how an admin fixes a false positive, and the likeliest false positive
    /// is a CDN or shared-hosting range in a feed. Without this, a listed
    /// Akamai range would break apple.com despite the never-block set.
    public func decide(response packet: [UInt8]) -> ResponseDecision {
        let blocklist = store.current
        guard let q = DNSMessage.question(packet) else { return .pass }
        var reason: Reason?
        var notPermitted = false
        switch blocklist.verdict(normalized: q.name) {
        case .allowed:
            return .pass
        case .notPermitted:
            // Monitor mode forwards every query, so this is where it sees
            // the name. Otherwise decide(query:) denied it already, unless
            // the client wrote the name in a form the parser read
            // differently.
            notPermitted = true
        case .blocked(let rule):
            // The query got past decide(query:), for example because the
            // client wrote its name in a form this parser read differently.
            // The resolver's answer names it plainly; block it here.
            reason = .alias(target: q.nameString, rule: rule)
        case .pass:
            break
        }
        let answer = DNSMessage.answer(packet) ?? DNSMessage.Answer()

        for target in answer.names where reason == nil {
            if case .blocked(let rule) = blocklist.verdict(normalized: target) {
                reason = .alias(target: String(decoding: target, as: UTF8.self), rule: rule)
                break
            }
        }
        let monitoring = isMonitorOnly
        if reason == nil, let address = answer.addresses.first(where: blocklist.isBlocked) {
            reason = .address(address)
            if !monitoring { learned.add(q.nameString, address: address) }
        }
        guard let reason else {
            guard notPermitted else { return .pass }
            counters.notPermitted.add(1, ordering: .relaxed)
            if monitoring { return .monitorDeny(name: q.nameString, type: q.type) }
            guard let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .pass }
            return .deny(reply: reply, name: q.nameString, type: q.type)
        }
        if monitoring {
            counters.wouldBlock.add(1, ordering: .relaxed)
            return .monitor(name: q.nameString, type: q.type, reason: reason)
        }
        guard let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .pass }
        counters.blockedAnswers.add(1, ordering: .relaxed)
        return .block(reply: reply, name: q.nameString, reason: reason)
    }
}

/// Names recently blocked because an answer held a listed address.
///
/// An address rule only sees the answer it is in. A host listed by its IPv4
/// address has its A answer blocked, but its AAAA answer has no listed
/// address and passes, so the app still connects over IPv6. Remembering the
/// name blocks its later queries of every type.
///
/// It cannot catch the first lookup reliably: the system sends A and AAAA at
/// the same time, and AAAA can come back first. To cut a host off at once,
/// list its domain or both its address families (docs/list-format.md).
final class LearnedBlocks: Sendable {
    private struct Entry {
        let expires: ContinuousClock.Instant
        let address: IPAddress
    }

    private let entries = Mutex<[String: Entry]>([:])
    private let ttl: Duration
    private let capacity: Int

    init(ttl: Duration, capacity: Int) {
        self.ttl = ttl
        self.capacity = capacity
    }

    func add(_ name: String, address: IPAddress) {
        let now = ContinuousClock.now
        entries.withLock { map in
            if map.count >= capacity {
                map = map.filter { $0.value.expires > now }
                // Still full means a flood of distinct names. Drop the tenth
                // that expires soonest, not everything: a flood must not
                // wipe the names learned before it.
                if map.count >= capacity {
                    for key in map.sorted(by: { $0.value.expires < $1.value.expires })
                        .prefix(max(capacity / 10, 1)).map(\.key) {
                        map[key] = nil
                    }
                }
            }
            map[name] = Entry(expires: now + ttl, address: address)
        }
    }

    /// The address that caused the block, if the entry is still live.
    func lookup(_ name: String) -> IPAddress? {
        let now = ContinuousClock.now
        return entries.withLock { map in
            guard let entry = map[name] else { return nil }
            guard entry.expires > now else {
                map[name] = nil
                return nil
            }
            return entry.address
        }
    }

    var count: Int { entries.withLock { $0.count } }
}
