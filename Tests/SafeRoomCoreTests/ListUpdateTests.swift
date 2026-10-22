import CryptoKit
import Foundation
import Testing
@testable import SafeRoomCore

private func list(_ n: Int, prefix: String = "d") -> Data {
    Data((0..<n).map { "\(prefix)\($0).example" }.joined(separator: "\n").utf8)
}

private func sha(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func evaluate(
    _ body: Data, status: Int = 200, hash: String? = nil,
    current: CompiledList? = nil, policy: ProviderPolicy = ProviderPolicy()
) -> ListUpdate.Outcome {
    ListUpdate.evaluate(status: status, body: body, expectedSHA256: hash, current: current, policy: policy)
}

@Test func firstListIsAccepted() {
    guard case .accept(let l, _) = evaluate(list(1000)) else { Issue.record("not accepted"); return }
    #expect(l.entryCount == 1000)
}

@Test func notModified() {
    #expect(evaluate(Data(), status: 304, current: CompiledList(source: list(5))) == .unchanged)
}

@Test func notModifiedWithNoListIsAFailure() {
    #expect(evaluate(Data(), status: 304) == .reject(.httpStatus(304)))
}

@Test func identicalBodyIsUnchanged() {
    let body = list(500)
    #expect(evaluate(body, current: CompiledList(source: body)) == .unchanged)
}

@Test func httpErrorRejected() {
    #expect(evaluate(Data(), status: 403) == .reject(.httpStatus(403)))
}

@Test func sizeLimit() {
    var policy = ProviderPolicy()
    policy.maxListBytes = 10
    #expect(evaluate(list(10), policy: policy) == .reject(.tooLarge(bytes: list(10).count, limit: 10)))
}

@Test func hashChecked() {
    let body = list(10)
    guard case .accept = evaluate(body, hash: sha(body) + "  list.txt\n") else { Issue.record("good hash rejected"); return }
    guard case .reject(.hashMismatch) = evaluate(body, hash: sha(list(11))) else { Issue.record("bad hash accepted"); return }
    #expect(evaluate(body, hash: "<html>error</html>") == .reject(.badHashFile))
}

@Test func emptyReplacementRejected() {
    let current = CompiledList(source: list(5))
    #expect(evaluate(Data("# nothing here\nbad..line".utf8), current: current) == .reject(.empty))
}

@Test func emptyFirstListAccepted() {
    guard case .accept = evaluate(Data("# empty feed".utf8)) else { Issue.record("rejected"); return }
}

private let fiftyPercent: ProviderPolicy = {
    var p = ProviderPolicy()
    p.maxChangePercent = 50
    return p
}()

@Test func changeCheckIsOffByDefault() {
    guard case .accept = evaluate(list(10, prefix: "e"), current: CompiledList(source: list(1000))) else {
        Issue.record("rejected"); return
    }
}

@Test func largeShrinkRejected() {
    let current = CompiledList(source: list(1000))
    #expect(evaluate(list(400, prefix: "e"), current: current, policy: fiftyPercent)
        == .reject(.changeTooLarge(previous: 1000, new: 400, limitPercent: 50)))
}

@Test func largeGrowthRejected() {
    let current = CompiledList(source: list(1000))
    guard case .reject(.changeTooLarge) = evaluate(list(1600, prefix: "e"), current: current, policy: fiftyPercent) else {
        Issue.record("accepted"); return
    }
}

@Test func changeWithinLimitAccepted() {
    let current = CompiledList(source: list(1000))
    guard case .accept = evaluate(list(1400, prefix: "e"), current: current, policy: fiftyPercent) else { Issue.record("rejected"); return }
}


@Test func smallListsSkipPercentCheck() {
    guard case .accept = evaluate(list(50, prefix: "e"), current: CompiledList(source: list(5)), policy: fiftyPercent) else {
        Issue.record("rejected"); return
    }
}

@Test func retryBackoff() {
    let hour = Duration.seconds(3600)
    #expect(retryDelay(afterFailures: 1, refresh: hour) == .seconds(60))
    #expect(retryDelay(afterFailures: 3, refresh: hour) == .seconds(240))
    #expect(retryDelay(afterFailures: 20, refresh: hour) == hour)
}

@Test func fetchStateDecodesOlderFile() throws {
    let old = Data(#"{"url":"https://x.example/list","etag":"\"abc\""}"#.utf8)
    let state = try JSONDecoder().decode(FetchState.self, from: old)
    #expect(state.etag == "\"abc\"" && state.lastSuccessAt == nil)
}

@Test func retargetKeepsDates() {
    var state = FetchState(url: "https://a.example/list", etag: "e", lastModified: "m")
    state.lastSuccessAt = Date(timeIntervalSince1970: 1)
    state.retarget("https://b.example/list")
    #expect(state.etag == nil && state.lastModified == nil)
    #expect(state.lastSuccessAt == Date(timeIntervalSince1970: 1))
}

@Test func hashFileDecidesTheDownload() {
    let body = list(20)
    let current = CompiledList(source: body)
    #expect(ListUpdate.checkHash(sha(body) + "  list.txt\n", current: current) == .upToDate)
    #expect(ListUpdate.checkHash(sha(body).uppercased(), current: current) == .upToDate)
    #expect(ListUpdate.checkHash(sha(list(21)), current: current) == .download)
    #expect(ListUpdate.checkHash(sha(body), current: nil) == .download)
    #expect(ListUpdate.checkHash("<html>error</html>", current: current) == .badHashFile)
    #expect(ListUpdate.checkHash("", current: nil) == .badHashFile)
}
