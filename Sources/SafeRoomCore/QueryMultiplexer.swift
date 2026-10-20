/// Lets many client flows share one upstream connection per resolver.
///
/// Each forwarded query gets a fresh random ID that no pending query uses.
/// The client's own ID and the question are remembered. An answer is
/// delivered only if its ID AND its question (name, type, class) match a
/// pending query; the client's ID is then restored. Random IDs plus the
/// question check are the standard defenses against forged answers.
///
/// Not thread-safe: the owner calls it from one serial queue.
public struct QueryMultiplexer<Context> {
    struct Pending {
        let originalID: UInt16
        let question: [UInt8]
        let deadline: ContinuousClock.Instant
        let context: Context
    }

    private var pending: [UInt16: Pending] = [:]
    private var rng = SystemRandomNumberGenerator()
    public let timeout: Duration
    /// Leaves most of the 16-bit ID space free, so a fresh ID is found fast
    /// and an off-path guess stays unlikely.
    public let capacity: Int

    public init(timeout: Duration = .seconds(10), capacity: Int = 8192) {
        self.timeout = timeout
        self.capacity = capacity
    }

    public var count: Int { pending.count }

    /// The query with its ID replaced, ready to send upstream. Nil if the
    /// packet has no readable question, or too many queries are pending.
    public mutating func register(
        _ query: [UInt8], context: Context, now: ContinuousClock.Instant = .now
    ) -> [UInt8]? {
        guard pending.count < capacity, let question = Self.questionKey(query) else { return nil }
        var id: UInt16
        repeat { id = UInt16.random(in: .min ... .max, using: &rng) } while pending[id] != nil
        pending[id] = Pending(
            originalID: UInt16(query[0]) << 8 | UInt16(query[1]),
            question: question, deadline: now + timeout, context: context)
        var out = query
        out[0] = UInt8(id >> 8)
        out[1] = UInt8(id & 0xFF)
        return out
    }

    /// The answer with the client's ID restored, and the context it belongs
    /// to. Nil for an answer that matches no pending query: late, forged, or
    /// for another question.
    public mutating func resolve(_ response: [UInt8]) -> (packet: [UInt8], context: Context)? {
        guard response.count >= DNSMessage.headerSize,
              response[2] & 0x80 != 0  // QR: it must be a response
        else { return nil }
        let id = UInt16(response[0]) << 8 | UInt16(response[1])
        guard let entry = pending[id], Self.questionKey(response) == entry.question else { return nil }
        pending[id] = nil
        var out = response
        out[0] = UInt8(entry.originalID >> 8)
        out[1] = UInt8(entry.originalID & 0xFF)
        return (out, entry.context)
    }

    /// Drops queries that got no answer in time. Returns how many.
    @discardableResult
    public mutating func expire(now: ContinuousClock.Instant = .now) -> Int {
        let before = pending.count
        pending = pending.filter { $0.value.deadline > now }
        return before - pending.count
    }

    public mutating func removeAll() { pending.removeAll() }

    /// Lowercased name, type, and class of the first question. Resolvers may
    /// echo the name in another case (0x20 encoding), so case is ignored.
    static func questionKey(_ packet: [UInt8]) -> [UInt8]? {
        guard let q = DNSMessage.question(packet), q.questionEnd <= packet.count else { return nil }
        return q.name + [0] + Array(packet[(q.questionEnd - 4)..<q.questionEnd])
    }
}
