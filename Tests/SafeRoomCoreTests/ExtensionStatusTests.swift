import Foundation
import Testing
@testable import SafeRoomCore

private let start = Date(timeIntervalSince1970: 1_800_000_000)

private func status(
    entries: Int? = 1000, lastSuccess: TimeInterval? = 0, failures: Int = 0, refresh: Int = 3600
) -> ExtensionStatus {
    var policy = ProviderPolicy()
    policy.refreshInterval = .seconds(refresh)
    let list = entries.map {
        ExtensionStatus.ListSummary(
            CompiledList(source: Array((0..<$0).map { "d\($0).example" }.joined(separator: "\n").utf8)),
            source: "test", loadedAt: start)
    }
    return ExtensionStatus(
        version: "1", startedAt: start, policy: .init(policy), list: list,
        lastAttempt: failures > 0 ? .init(at: start, source: "x", result: .failed, detail: "HTTP status 503") : nil,
        lastSuccessAt: lastSuccess.map { start.addingTimeInterval($0) }, nextRefreshAt: nil,
        consecutiveFailures: failures, counters: .init())
}

@Test func healthStates() {
    #expect(status().health(now: start.addingTimeInterval(60)) == .ok)
    #expect(status(failures: 2).health(now: start.addingTimeInterval(60)) == .degraded)
    #expect(status().health(now: start.addingTimeInterval(3 * 3600 + 1)) == .stale)
    #expect(status(entries: nil).health(now: start) == .noList)
    #expect(status(entries: 0).health(now: start) == .noList)
}

@Test func justStartedFromCacheIsOK() {
    #expect(status(lastSuccess: nil).health(now: start.addingTimeInterval(5)) == .ok)
}

@Test func healthLine() {
    let line = status(failures: 1).healthLine(now: start.addingTimeInterval(60))
    #expect(line.hasPrefix("DEGRADED: 1000 domains, 0 ranges, list checked "))
    #expect(line.hasSuffix("1 failed: HTTP status 503, version 1"))
}

@Test func urlIsRedacted() {
    let p = ProviderPolicy(["ListURL": "https://user:pw@intel.example.com/list.txt?key=s3cret#x"])
    #expect(ExtensionStatus.PolicySummary(p).listURL == "https://intel.example.com/list.txt")
}

@Test func jsonRoundTrip() throws {
    let s = status()
    let data = try ExtensionStatus.encoder.encode(s)
    #expect(try ExtensionStatus.decoder.decode(ExtensionStatus.self, from: data) == s)
    #expect(!String(decoding: data, as: UTF8.self).contains("Token"))
}

@Test func filterCounts() {
    let store = BlocklistStore()
    store.replace(Blocklist(list: CompiledList(source: Array("evil.com".utf8))))
    let filter = DNSFilter(store: store)
    let q: [UInt8] = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4] + Array("evil".utf8) + [3] + Array("com".utf8) + [0, 0, 1, 0, 1]
    _ = filter.decide(query: q)
    _ = filter.decide(query: q)
    #expect(filter.counters.values.queries == 2)
    #expect(filter.counters.values.blockedQueries == 2)
}
