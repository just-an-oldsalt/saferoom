import Testing
@testable import SafeRoomCore

private func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

private func encode(_ name: String) -> [UInt8] {
    name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
}

/// A query as a stub resolver sends it: RD set, one question, class IN.
private func query(_ name: String, type: UInt16 = 1, id: UInt16 = 0xBEEF) -> [UInt8] {
    DNSMessage.be(id) + [0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0] + encode(name) + DNSMessage.be(type) + [0, 1]
}

private func names(_ answer: DNSMessage.Answer?) -> [String] {
    (answer?.names ?? []).map { String(decoding: $0, as: UTF8.self) }
}

// Real responses from 1.1.1.1, captured 2026-10-19.
private enum Captured {
    /// www.apple.com A: three CNAMEs, then one A record (184.26.202.199).
    static let appleA = hex("12348180000100040000000003777777056170706c6503636f6d000001000103777777056170706c6503636f6d000005000100000006001d0d7777772d6170706c652d636f6d0176076161706c696d6703636f6d000d7777772d6170706c652d636f6d0176076161706c696d6703636f6d000005000100000006001b03777777056170706c6503636f6d07656467656b6579036e65740003777777056170706c6503636f6d07656467656b6579036e6574000005000100000006001c0565363835380564736365390a616b616d616965646765036e6574000565363835380564736365390a616b616d616965646765036e65740000010001000000060004b81acac7")
    /// cloudflare.com HTTPS: ipv4hint and ipv6hint with two addresses each.
    static let cloudflareHTTPS = hex("1234818000010001000000000a636c6f7564666c61726503636f6d00004100010a636c6f7564666c61726503636f6d00004100010000012c003d0001000001000602683302683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5")
    /// www.apple.com AAAA: three CNAMEs, then two AAAA records.
    static let appleAAAA = hex("12348180000100050000000003777777056170706c6503636f6d00001c000103777777056170706c6503636f6d000005000100000010001d0d7777772d6170706c652d636f6d0176076161706c696d6703636f6d000d7777772d6170706c652d636f6d0176076161706c696d6703636f6d000005000100000010001b03777777056170706c6503636f6d07656467656b6579036e65740003777777056170706c6503636f6d07656467656b6579036e6574000005000100000010001c0565363835380564736365390a616b616d616965646765036e6574000565363835380564736365390a616b616d616965646765036e657400001c00010000001000102600140a500003810000000000001aca0565363835380564736365390a616b616d616965646765036e657400001c00010000001000102600140a500003840000000000001aca")
}

@Suite struct Questions {
    @Test func readsQuery() throws {
        let q = try #require(DNSMessage.question(query("Evil.COM", type: 65)))
        #expect(q.id == 0xBEEF)
        #expect(q.nameString == "evil.com")
        #expect(q.type == 65)
        #expect(!q.isResponse)
    }

    @Test func readsResponseQuestion() throws {
        let q = try #require(DNSMessage.question(Captured.appleA))
        #expect(q.nameString == "www.apple.com")
        #expect(q.isResponse)
    }

    @Test func rootName() throws {
        #expect(try #require(DNSMessage.question(query(""))).name.isEmpty)
    }

    @Test func rejectsTwoQuestions() {
        var p = query("evil.com")
        p[5] = 2
        #expect(DNSMessage.question(p) == nil)
    }

    @Test func rejectsNonQueryOpcode() {
        var p = query("evil.com")
        p[2] |= 0x28  // opcode 5, UPDATE
        #expect(DNSMessage.question(p) == nil)
    }

    @Test func rejectsDotInsideLabel() {
        let p = DNSMessage.be(1) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0] + [8] + Array("evil.com".utf8) + [0, 0, 1, 0, 1]
        #expect(DNSMessage.question(p) == nil)
    }
}

@Suite struct NXDomain {
    @Test func replyShape() throws {
        let q = query("evil.com", type: 28)
        let r = try #require(DNSMessage.nxdomain(replyingTo: q))
        #expect(Array(r[0..<2]) == [0xBE, 0xEF])
        #expect(r[2] == 0x81)  // QR, RD
        #expect(r[3] == 0x83)  // RA, RCODE 3
        #expect(Array(r[4..<12]) == [0, 1, 0, 0, 0, 0, 0, 0])
        #expect(Array(r[12...]) == Array(q[12...]))
        let parsed = try #require(DNSMessage.question(r))
        #expect(parsed.isResponse && parsed.nameString == "evil.com" && parsed.type == 28)
    }

    @Test func fromUpstreamResponseDropsAnswers() throws {
        let r = try #require(DNSMessage.nxdomain(replyingTo: Captured.appleA))
        #expect(r.count == 12 + encode("www.apple.com").count + 4)
        #expect(r[3] & 0x0F == 3)
        #expect(DNSMessage.answer(r) == DNSMessage.Answer())
    }

    @Test func copiesCheckingDisabled() throws {
        var q = query("evil.com")
        q[3] |= 0x10
        #expect(try #require(DNSMessage.nxdomain(replyingTo: q))[3] & 0x10 != 0)
    }
}

@Suite struct Answers {
    @Test func cnameChainAndA() throws {
        let a = try #require(DNSMessage.answer(Captured.appleA))
        #expect(names(a) == ["www-apple-com.v.aaplimg.com", "www.apple.com.edgekey.net", "e6858.dsce9.akamaiedge.net"])
        #expect(a.addresses == [.v4(0xB81A_CAC7)])
    }

    @Test func aaaa() throws {
        let a = try #require(DNSMessage.answer(Captured.appleAAAA))
        #expect(a.addresses.count == 2)
        guard case .v6(let first) = a.addresses[0] else { Issue.record("not v6"); return }
        #expect(first >> 64 == 0x2600_140A_5000_0381)
    }

    @Test func httpsHints() throws {
        let a = try #require(DNSMessage.answer(Captured.cloudflareHTTPS))
        #expect(a.names.isEmpty)  // target "." means "the owner name"
        #expect(a.addresses.prefix(2) == [.v4(0x6810_84E5), .v4(0x6810_85E5)])
        #expect(a.addresses.count == 4)
    }

    @Test func compressedNames() throws {
        // Question evil.com at offset 12. Answer 1: owner = pointer to 12,
        // CNAME target "cdn" + pointer to 12 ("cdn.evil.com"). Answer 2:
        // owner = pointer to the CNAME target, A 192.0.2.1.
        var p = DNSMessage.be(7) + [0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0] + encode("evil.com") + [0, 1, 0, 1]
        let targetOffset = p.count + 12
        p += [0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3] + Array("cdn".utf8) + [0xC0, 12]
        p += [0xC0, UInt8(targetOffset), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]
        let a = try #require(DNSMessage.answer(p))
        #expect(names(a) == ["cdn.evil.com"])
        #expect(a.addresses == [.v4(0xC000_0201)])
    }

    @Test func queryIsNotAnAnswer() {
        #expect(DNSMessage.answer(query("evil.com")) == nil)
    }
}

@Suite struct Malformed {
    @Test func pointerLoopIsRejected() {
        // Question name is a pointer to itself.
        let p = DNSMessage.be(1) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1]
        #expect(DNSMessage.question(p) == nil)
    }

    /// The review's bypass: a question name that is a forward pointer. It
    /// used to be refused unread, so the query went upstream unchecked.
    @Test func forwardPointerIsRead() throws {
        let p: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x12, 0, 1, 0, 1]
            + [4] + Array("evil".utf8) + [3] + Array("com".utf8) + [0]
        #expect(try #require(DNSMessage.question(p)).nameString == "evil.com")
    }

    @Test func overlongNameIsRejected() {
        let long = Array(repeating: String(repeating: "a", count: 63), count: 5).joined(separator: ".")
        #expect(DNSMessage.question(query(long)) == nil)
    }

    /// Every truncation and every single-byte corruption of real packets must
    /// return nil or a value. Never a crash: the extension parses untrusted
    /// bytes from every app on the Mac and from every upstream server.
    @Test func truncationAndCorruptionNeverCrash() {
        for packet in [Captured.appleA, Captured.appleAAAA, Captured.cloudflareHTTPS, query("evil.com")] {
            for n in 0...packet.count {
                let cut = Array(packet.prefix(n))
                _ = DNSMessage.question(cut)
                _ = DNSMessage.answer(cut)
                _ = DNSMessage.nxdomain(replyingTo: cut)
            }
            for i in packet.indices {
                for value: UInt8 in [0x00, 0x3F, 0x40, 0xC0, 0xFF] {
                    var bad = packet
                    bad[i] = value
                    _ = DNSMessage.question(bad)
                    _ = DNSMessage.answer(bad)
                }
            }
        }
    }

    @Test func randomBytesNeverCrash() {
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<20_000 {
            let bytes = (0..<Int.random(in: 0...80, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
            _ = DNSMessage.answer(bytes)
            _ = DNSMessage.nxdomain(replyingTo: bytes)
        }
    }
}

@Suite struct TCPFraming {
    @Test func splitsAndJoins() throws {
        let a = query("a.com")
        let b = query("b.com")
        let stream = try #require(DNSTCPFramer.frame(a)) + #require(DNSTCPFramer.frame(b))
        var framer = DNSTCPFramer()
        #expect(framer.push(stream.prefix(1)) == [])
        #expect(framer.push(stream[1..<(a.count + 3)]) == [a])
        #expect(framer.push(stream[(a.count + 3)...]) == [b])
    }

    @Test func tooLargeToFrame() {
        #expect(DNSTCPFramer.frame([UInt8](repeating: 0, count: 70_000)) == nil)
    }
}
