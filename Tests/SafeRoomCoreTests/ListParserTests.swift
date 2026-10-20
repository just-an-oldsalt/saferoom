import Testing
@testable import SafeRoomCore

private func domains(_ text: String) -> [DomainRule] { ListParser.parse(text).domains }
private func rule(_ name: String, _ match: DomainMatch = .subtree) -> DomainRule {
    DomainRule(name: name, match: match)
}

@Suite struct DomainForms {
    @Test func bareNameIsSubtree() {
        #expect(domains("evil.com") == [rule("evil.com")])
    }

    @Test func equalsIsExact() {
        #expect(domains("=evil.com") == [rule("evil.com", .exact)])
    }

    @Test func starDotIsSubdomainsOnly() {
        #expect(domains("*.evil.com") == [rule("evil.com", .subdomainsOnly)])
    }

    @Test func leadingDotIsSubtree() {
        #expect(domains(".evil.com") == [rule("evil.com")])
    }

    @Test func normalizesCaseAndTrailingDot() {
        #expect(domains("  EVIL.Example.COM.  \r") == [rule("evil.example.com")])
    }

    @Test func adblockForm() {
        #expect(domains("||evil.com^") == [rule("evil.com")])
    }

    @Test func urlKeepsOnlyHost() {
        #expect(domains("https://user@Evil.com:8443/path?q=1") == [rule("evil.com")])
    }

    @Test func underscoreAllowed() {
        #expect(domains("_dmarc.evil.com") == [rule("_dmarc.evil.com")])
    }

    @Test func wholeTLDOnlyWithStarDot() {
        #expect(domains("*.zip") == [rule("zip", .subdomainsOnly)])
        let parsed = ListParser.parse("com")
        #expect(parsed.domains.isEmpty)
        #expect(parsed.invalidCount == 1)
    }
}

@Suite struct HostsFile {
    @Test func hostsLines() {
        let text = """
        127.0.0.1 localhost
        0.0.0.0 evil.com
        0.0.0.0 a.bad.net b.bad.net # two on one line
        :: also.bad.org
        """
        #expect(domains(text) == [rule("evil.com"), rule("a.bad.net"), rule("b.bad.net"), rule("also.bad.org")])
    }

    @Test func twoFieldsWithoutAddressIsInvalid() {
        let parsed = ListParser.parse("evil.com other.com")
        #expect(parsed.domains.isEmpty)
        #expect(parsed.invalidCount == 1)
    }
}

@Suite struct CommentsAndJunk {
    @Test func commentsAndBlanks() {
        let text = """
        # header
        ! adblock comment

        evil.com # trailing comment
        """
        let parsed = ListParser.parse(text)
        #expect(parsed.domains == [rule("evil.com")])
        #expect(parsed.invalidCount == 0)
        #expect(parsed.lineCount == 4)
    }

    @Test(arguments: [
        "evil..com", "-", "ev!l.com", "évil.com", "mid.*.evil.com", "evil.*",
        String(repeating: "a", count: 64) + ".com", "10.0.0.0/33", "1.2.3/8",
    ])
    func rejected(_ line: String) {
        let parsed = ListParser.parse(line)
        #expect(parsed.domains.isEmpty && parsed.cidrs.isEmpty, "accepted: \(line)")
        #expect(parsed.invalidCount == 1, "not counted: \(line)")
    }

    @Test func badLinesDoNotStopTheList() {
        let parsed = ListParser.parse("good.com\nbad..com\nalso-good.com")
        #expect(parsed.domains.map(\.name) == ["good.com", "also-good.com"])
        #expect(parsed.invalidSamples.first?.line == 2)
    }

    @Test func samplesAreCapped() {
        let text = Array(repeating: "bad..com", count: 500).joined(separator: "\n")
        let parsed = ListParser.parse(text)
        #expect(parsed.invalidCount == 500)
        #expect(parsed.invalidSamples.count == ParsedList.sampleLimit)
    }
}

@Suite struct CIDRs {
    @Test func v4Range() {
        #expect(ListParser.parse("198.51.100.0/24").cidrs == [.v4(0xC633_6400, prefix: 24)])
    }

    @Test func hostBitsAreMasked() {
        #expect(ListParser.parse("198.51.100.77/24").cidrs == [.v4(0xC633_6400, prefix: 24)])
    }

    @Test func bareAddressIsHostRoute() {
        #expect(ListParser.parse("203.0.113.9").cidrs == [.v4(0xCB00_7109, prefix: 32)])
    }

    @Test func v6Range() {
        let expected = UInt128(0x2001_0db8) << 96
        #expect(ListParser.parse("2001:db8::/32").cidrs == [.v6(expected, prefix: 32)])
    }

    @Test func v6Bare() {
        #expect(ListParser.parse("::1").cidrs == [.v6(1, prefix: 128)])
    }

    @Test func zeroPrefix() {
        #expect(ListParser.parse("0.0.0.0/0").cidrs == [.v4(0, prefix: 0)])
    }
}

@Test func largeListParsesQuickly() {
    let text = (0..<250_000).map { "host\($0).bad\($0 % 997).example" }.joined(separator: "\n")
    let start = ContinuousClock.now
    let parsed = ListParser.parse(text)
    let elapsed = ContinuousClock.now - start
    #expect(parsed.domains.count == 250_000)
    print("parsed 250k lines in \(elapsed)")
}
