import Synchronization

/// Every decision the proxy makes, in one place and without NetworkExtension,
/// so all of it is unit-tested. The relays only move bytes.
public final class DNSFilter: Sendable {
    public let store: BlocklistStore
    let learned: LearnedBlocks

    public init(store: BlocklistStore, learnedTTL: Duration = .seconds(300), learnedCapacity: Int = 10_000) {
        self.store = store
        self.learned = LearnedBlocks(ttl: learnedTTL, capacity: learnedCapacity)
    }

    public enum QueryDecision: Sendable, Equatable {
        /// Send the packet upstream unchanged.
        case forward
        /// Answer the client with `reply` and do not send anything upstream.
        case block(reply: [UInt8], name: String, type: UInt16, rule: String)
    }

    public enum ResponseDecision: Sendable, Equatable {
        /// Return the upstream response to the client unchanged.
        case pass
        /// Return `reply` (NXDOMAIN) to the client instead.
        case block(reply: [UInt8], name: String, reason: Reason)
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
        let rule: String
        switch store.current.verdict(normalized: q.name) {
        case .blocked(let r):
            rule = r
        case .allowed:
            return .forward
        case .pass:
            guard let address = learned.lookup(q.nameString) else { return .forward }
            rule = "learned:\(address)"
        }
        guard let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .forward }
        return .block(reply: reply, name: q.nameString, type: q.type, rule: rule)
    }

    /// Called for each upstream response before it goes back to the client.
    ///
    /// An allowlisted query name passes without any check. The allowlist is
    /// how an admin fixes a false positive, and the likeliest false positive
    /// is a CDN or shared-hosting range in a feed. Without this, a listed
    /// Akamai range would break apple.com despite the never-block set.
    public func decide(response packet: [UInt8]) -> ResponseDecision {
        let blocklist = store.current
        guard let q = DNSMessage.question(packet) else { return .pass }
        if case .allowed = blocklist.verdict(normalized: q.name) { return .pass }
        guard let answer = DNSMessage.answer(packet) else { return .pass }

        var reason: Reason?
        for target in answer.names {
            if case .blocked(let rule) = blocklist.verdict(normalized: target) {
                reason = .alias(target: String(decoding: target, as: UTF8.self), rule: rule)
                break
            }
        }
        if reason == nil, let address = answer.addresses.first(where: blocklist.isBlocked) {
            reason = .address(address)
            learned.add(q.nameString, address: address)
        }
        guard let reason, let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .pass }
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
                // Still full means a flood of distinct names. Starting over
                // costs only the memory; the list itself is unaffected.
                if map.count >= capacity { map.removeAll() }
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
