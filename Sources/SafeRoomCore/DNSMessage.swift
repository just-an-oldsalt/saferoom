/// The small part of RFC 1035 that SafeRoom needs: read the question from a
/// query, build an NXDOMAIN reply, and read the names and addresses in an
/// upstream answer.
///
/// Every function returns nil on anything it cannot read. The proxy then
/// forwards the packet unchanged (fail-open). It never drops a packet because
/// the codec did not understand it.
public enum DNSMessage {
    public static let headerSize = 12

    public enum RecordType {
        public static let a: UInt16 = 1
        public static let cname: UInt16 = 5
        public static let aaaa: UInt16 = 28
        public static let svcb: UInt16 = 64
        public static let https: UInt16 = 65
    }

    public struct Question: Sendable, Equatable {
        public let id: UInt16
        /// Lowercase, dotted, no trailing dot. Ready for `Blocklist.verdict(normalized:)`.
        public let name: [UInt8]
        public let type: UInt16
        public let isResponse: Bool
        /// Byte offset just past the question section.
        public let questionEnd: Int

        public var nameString: String { String(decoding: name, as: UTF8.self) }
    }

    /// Reads the header and the one question. Works on queries and responses.
    public static func question(_ packet: [UInt8]) -> Question? {
        guard packet.count >= headerSize else { return nil }
        let flags = u16(packet, 2)
        let opcode = (flags >> 11) & 0xF
        // Standard queries with exactly one question. Anything else (NOTIFY,
        // UPDATE, multi-question packets) is forwarded unread.
        guard opcode == 0, u16(packet, 4) == 1 else { return nil }
        guard let (name, end) = readName(packet, at: headerSize), end + 4 <= packet.count else { return nil }
        return Question(
            id: u16(packet, 0), name: name, type: u16(packet, end),
            isResponse: flags & 0x8000 != 0, questionEnd: end + 4)
    }

    /// An NXDOMAIN reply to `packet`, which can be the query itself or an
    /// upstream response to it. Copies the ID, the question, and the RD and CD
    /// bits. Sets QR, RA and RCODE 3, with no records.
    public static func nxdomain(replyingTo packet: [UInt8]) -> [UInt8]? {
        guard let q = question(packet) else { return nil }
        let inFlags = u16(packet, 2)
        let rd: UInt16 = inFlags & 0x0100
        let cd: UInt16 = inFlags & 0x0010
        let flags: UInt16 = 0x8000 | rd | 0x0080 | cd | 3
        var out: [UInt8] = []
        out.reserveCapacity(q.questionEnd)
        out += be(q.id) + be(flags) + be(1) + be(0) + be(0) + be(0)
        out += packet[headerSize..<q.questionEnd]
        return out
    }

    /// What an upstream answer points at.
    public struct Answer: Sendable, Equatable {
        /// CNAME targets, and SVCB/HTTPS target names. Each one must pass the
        /// domain list too, or `evil-alias.com CNAME evil.com` gets through.
        public var names: [[UInt8]] = []
        /// A and AAAA records, plus SVCB/HTTPS ipv4hint and ipv6hint values.
        public var addresses: [IPAddress] = []
    }

    /// Reads the answer section of a response. Authority and additional
    /// sections are not read: a stub resolver connects to what is in answers.
    public static func answer(_ packet: [UInt8]) -> Answer? {
        guard let q = question(packet), q.isResponse else { return nil }
        let count = Int(u16(packet, 6))
        var offset = q.questionEnd
        var out = Answer()
        for _ in 0..<count {
            guard let (_, afterName) = readName(packet, at: offset), afterName + 10 <= packet.count else { return nil }
            let type = u16(packet, afterName)
            let length = Int(u16(packet, afterName + 8))
            let start = afterName + 10
            let end = start + length
            guard end <= packet.count else { return nil }
            switch type {
            case RecordType.a where length == 4:
                out.addresses.append(.v4(bytes: packet[start..<end]))
            case RecordType.aaaa where length == 16:
                out.addresses.append(.v6(bytes: packet[start..<end]))
            case RecordType.cname:
                guard let (target, _) = readName(packet, at: start) else { return nil }
                out.names.append(target)
            case RecordType.svcb, RecordType.https:
                guard readServiceBinding(packet, start..<end, into: &out) else { return nil }
            default:
                break
            }
            offset = end
        }
        return out
    }

    /// RFC 9460: priority, target name, then key/length/value parameters.
    /// Key 4 is ipv4hint and key 6 is ipv6hint.
    static func readServiceBinding(_ packet: [UInt8], _ range: Range<Int>, into out: inout Answer) -> Bool {
        guard range.count >= 3, let (target, afterTarget) = readName(packet, at: range.lowerBound + 2),
              afterTarget <= range.upperBound
        else { return false }
        if !target.isEmpty { out.names.append(target) }
        var offset = afterTarget
        while offset < range.upperBound {
            guard offset + 4 <= range.upperBound else { return false }
            let key = u16(packet, offset)
            let length = Int(u16(packet, offset + 2))
            let start = offset + 4
            let end = start + length
            guard end <= range.upperBound else { return false }
            switch key {
            case 4 where length % 4 == 0:
                for i in stride(from: start, to: end, by: 4) { out.addresses.append(.v4(bytes: packet[i..<i + 4])) }
            case 6 where length % 16 == 0:
                for i in stride(from: start, to: end, by: 16) { out.addresses.append(.v6(bytes: packet[i..<i + 16])) }
            default:
                break
            }
            offset = end
        }
        return true
    }

    /// Reads a possibly compressed name. Returns the dotted, lowercased name
    /// and the offset just past the name where it STARTED (not where a
    /// pointer led). The root name returns an empty array.
    ///
    /// Compression pointers must point backwards, which rules out loops; the
    /// jump count and the 255-byte limit are a second guard.
    static func readName(_ packet: [UInt8], at start: Int) -> ([UInt8], Int)? {
        var name: [UInt8] = []
        var offset = start
        var end: Int? = nil
        var jumps = 0
        var wireLength = 0
        while true {
            guard offset < packet.count else { return nil }
            let length = Int(packet[offset])
            switch length & 0xC0 {
            case 0xC0:
                guard offset + 1 < packet.count, jumps < 64 else { return nil }
                let target = (length & 0x3F) << 8 | Int(packet[offset + 1])
                guard target < offset else { return nil }
                if end == nil { end = offset + 2 }
                offset = target
                jumps += 1
            case 0x00:
                if length == 0 {
                    return (name, end ?? offset + 1)
                }
                let labelStart = offset + 1
                let labelEnd = labelStart + length
                wireLength += length + 1
                guard labelEnd <= packet.count, wireLength <= 255 else { return nil }
                if !name.isEmpty { name.append(UInt8(ascii: ".")) }
                for b in packet[labelStart..<labelEnd] {
                    // A dot inside a label cannot be written in dotted form.
                    // Such a name cannot be a listed domain, so give up and
                    // let it pass unread.
                    if b == UInt8(ascii: ".") { return nil }
                    name.append(b >= 0x41 && b <= 0x5A ? b | 0x20 : b)
                }
                offset = labelEnd
            default:
                return nil  // 0x40 and 0x80 label types are obsolete
            }
        }
    }

    @inline(__always)
    static func u16(_ p: [UInt8], _ i: Int) -> UInt16 { UInt16(p[i]) << 8 | UInt16(p[i + 1]) }

    @inline(__always)
    static func be(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
}

/// DNS over TCP prefixes each message with a 2-byte big-endian length.
/// Feed it bytes as they arrive; it returns each complete message.
public struct DNSTCPFramer: Sendable {
    private var buffer: [UInt8] = []

    public init() {}

    public mutating func push(_ bytes: some Collection<UInt8>) -> [[UInt8]] {
        buffer.append(contentsOf: bytes)
        var messages: [[UInt8]] = []
        var offset = 0
        while buffer.count - offset >= 2 {
            let length = Int(buffer[offset]) << 8 | Int(buffer[offset + 1])
            guard buffer.count - offset - 2 >= length else { break }
            messages.append(Array(buffer[(offset + 2)..<(offset + 2 + length)]))
            offset += 2 + length
        }
        if offset > 0 { buffer.removeFirst(offset) }
        return messages
    }

    /// Nil for a message over 65,535 bytes, which TCP DNS cannot carry.
    public static func frame(_ message: [UInt8]) -> [UInt8]? {
        guard message.count <= 0xFFFF else { return nil }
        return DNSMessage.be(UInt16(message.count)) + message
    }
}
