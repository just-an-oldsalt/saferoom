import Foundation
import SafeRoomCore

/// Keeps the store's list current.
///
/// Start-up: the cached compiled list first, which takes under a millisecond,
/// so the proxy blocks from its first query. Then a refresh loop: download
/// (or read the local file), check with `ListUpdate`, install, write the
/// cache, sleep. Failures retry with backoff and keep the current list.
/// With no list at all, every query passes (fail-open).
actor ListLoader {
    let policy: ProviderPolicy
    let store: BlocklistStore
    private let fetcher: ListFetcher
    private var current: CompiledList?
    private var failures = 0
    private var loop: Task<Void, Never>?
    private var refreshing = false
    // Status, reported over XPC.
    private var listSummary: ExtensionStatus.ListSummary?
    private var lastAttempt: ExtensionStatus.Attempt?
    private var nextRefreshAt: Date?
    /// Validators and dates, kept on disk across restarts.
    private var state = ListLoader.loadFetchState()

    init(policy: ProviderPolicy, store: BlocklistStore) {
        self.policy = policy
        self.store = store
        self.fetcher = ListFetcher(policy: policy)
    }

    func start() {
        if let cached = Self.loadCache() {
            // The cached list is as old as its install, not as this start.
            install(cached, invalid: [], from: "cache", at: state.listInstalledAt)
        }
        loop = Task { await run() }
    }

    func stop() {
        loop?.cancel()
    }

    private func run() async {
        while !Task.isCancelled {
            let delay = await cycle()
            try? await Task.sleep(for: delay)
        }
    }

    /// One refresh with its bookkeeping. Returns the wait until the next one.
    private func cycle() async -> Duration {
        refreshing = true
        let ok = await refresh()
        refreshing = false
        failures = ok ? 0 : failures + 1
        if ok {
            state.lastSuccessAt = Date()
            Self.saveFetchState(state)
        }
        let delay = ok ? policy.refreshInterval : retryDelay(afterFailures: failures, refresh: policy.refreshInterval)
        if !ok { Log.list.notice("retrying in \(delay.components.seconds)s (failure \(self.failures))") }
        nextRefreshAt = Date().addingTimeInterval(TimeInterval(delay.components.seconds))
        return delay
    }

    /// Refreshes at once and restarts the timer from now. A refresh already
    /// running is not doubled; the caller gets the status when it is done.
    func refreshNow() async {
        guard !refreshing else { return }
        loop?.cancel()
        let delay = await cycle()
        loop = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await run()
        }
    }

    func status() -> (list: ExtensionStatus.ListSummary?, attempt: ExtensionStatus.Attempt?, lastSuccessAt: Date?, nextRefreshAt: Date?, failures: Int) {
        (listSummary, lastAttempt, state.lastSuccessAt, nextRefreshAt, failures)
    }

    /// True when the current list is the newest one available, even if that
    /// means nothing changed.
    private func refresh() async -> Bool {
        guard let url = policy.listURL else { return loadFile() }
        if await fetch(url) { return true }
        // The URL failed. With nothing loaded at all, the local file is better
        // than an empty list. With a list loaded, keep it: it is newer.
        if current == nil, FileManager.default.fileExists(atPath: policy.listPath) {
            Log.list.notice("falling back to \(self.policy.listPath, privacy: .public)")
            _ = loadFile()
        }
        return false
    }

    private func fetch(_ url: URL) async -> Bool {
        state.retarget(url.absoluteString)
        do {
            // Conditional headers only when a list is loaded. A 304 with no
            // list in memory would leave the proxy with nothing to install.
            let response = try await fetcher.fetch(url, state: current == nil ? nil : state)
            var expected: String?
            if response.status == 200, let hashURL = policy.listSHA256URL {
                let hash = try await fetcher.fetch(hashURL, state: nil)
                guard hash.status == 200 else {
                    Log.list.error("SHA-256 download failed: HTTP status \(hash.status)")
                    record(hashURL.absoluteString, .failed, "SHA-256 file: HTTP status \(hash.status)")
                    return false
                }
                expected = String(decoding: hash.body, as: UTF8.self)
            }
            let accepted = apply(
                ListUpdate.evaluate(
                    status: response.status, body: response.body, expectedSHA256: expected,
                    current: current, policy: policy),
                source: url.absoluteString)
            if accepted, response.status == 200 {
                state.etag = response.etag
                state.lastModified = response.lastModified
            }
            return accepted
        } catch {
            // URLError's full description is a page of nested user-info.
            let text = (error as? URLError).map { "\($0.localizedDescription) (URLError \($0.code.rawValue))" }
                ?? String(describing: error)
            Log.list.error("download failed: \(text, privacy: .public)")
            record(url.absoluteString, .failed, text)
            return false
        }
    }

    private func loadFile() -> Bool {
        let path = policy.listPath
        do {
            let body = try Data(contentsOf: URL(fileURLWithPath: path))
            return apply(
                ListUpdate.evaluate(status: 200, body: body, expectedSHA256: nil, current: current, policy: policy),
                source: path)
        } catch {
            Log.list.error("cannot read \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            record(path, .failed, error.localizedDescription)
            return false
        }
    }

    /// True unless the update was rejected.
    private func apply(_ outcome: ListUpdate.Outcome, source rawSource: String) -> Bool {
        let source = ExtensionStatus.redact(rawSource)
        switch outcome {
        case .unchanged:
            Log.list.info("\(source, privacy: .public) unchanged")
            record(source, .unchanged)
            return true
        case .accept(let list, let invalid):
            install(list, invalid: invalid, from: source)
            Self.writeCache(list)
            state.listInstalledAt = Date()
            Self.saveFetchState(state)
            record(source, .accepted)
            return true
        case .reject(let reason):
            record(source, .rejected, reason.description)
            Log.list.error("rejected \(source, privacy: .public): \(reason.description, privacy: .public); keeping the current list")
            return false
        }
    }

    private func record(_ source: String, _ result: ExtensionStatus.Attempt.Result, _ detail: String? = nil) {
        lastAttempt = .init(at: Date(), source: ExtensionStatus.redact(source), result: result, detail: detail)
    }

    private func install(_ list: CompiledList, invalid: [InvalidLine], from source: String, at installedAt: Date? = nil) {
        current = list
        listSummary = .init(list, source: source, loadedAt: installedAt ?? Date())
        store.replace(policy.blocklist(list))
        let s = list.stats
        Log.list.notice(
            "loaded from \(source, privacy: .public): \(s.domainRules) domains, \(s.v4Ranges) v4 ranges, \(s.v6Ranges) v6 ranges, \(s.invalidCount) invalid lines, \(list.byteSize / 1024) KiB")
        for sample in invalid.prefix(10) {
            Log.list.error("line \(sample.line): \(sample.reason, privacy: .public): \(sample.text, privacy: .public)")
        }
    }

    // MARK: - Files in the app group container

    private static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SafeRoom.appGroup)
    }

    private static func loadCache() -> CompiledList? {
        guard let url = container?.appendingPathComponent("blocklist.cache"),
              let data = try? Data(contentsOf: url)
        else { return nil }
        do {
            return try CompiledList(cache: data)
        } catch {
            Log.list.error("ignoring cache: \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    private static func writeCache(_ list: CompiledList) {
        write(list.serialized(), to: "blocklist.cache")
    }

    static func loadFetchState() -> FetchState {
        guard let url = container?.appendingPathComponent("fetch-state.json"),
              let data = try? Data(contentsOf: url),
              let state = try? JSONDecoder().decode(FetchState.self, from: data)
        else { return FetchState() }
        return state
    }

    static func saveFetchState(_ state: FetchState) {
        if let data = try? JSONEncoder().encode(state) { write(data, to: "fetch-state.json") }
    }

    private static func write(_ data: Data, to name: String) {
        guard let url = container?.appendingPathComponent(name) else { return }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url, options: .atomic)
        } catch {
            Log.list.error("cannot write \(name, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }
}
