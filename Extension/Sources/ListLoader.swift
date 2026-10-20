import CryptoKit
import Foundation
import SafeRoomCore

/// Puts a list into the store, and keeps a compiled copy on disk.
///
/// Start-up order: the cache first, which takes under a millisecond, so the
/// proxy blocks from its first query. Then the list file, compiled in the
/// background. Any failure leaves the current list in place; with no list at
/// all, every query passes (fail-open).
///
/// Phase 5 adds the URL fetch, the refresh timer, and the sanity checks.
final class ListLoader: Sendable {
    let policy: ProviderPolicy
    let store: BlocklistStore

    init(policy: ProviderPolicy, store: BlocklistStore) {
        self.policy = policy
        self.store = store
    }

    static var cacheURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: SafeRoom.appGroup)?
            .appendingPathComponent("blocklist.cache")
    }

    func start() {
        let cached = loadCache()
        if let cached {
            install(cached, from: "cache")
        }
        DispatchQueue.global(qos: .utility).async { [self] in
            loadFile(skipping: cached?.sourceSHA256)
        }
    }

    private func loadCache() -> CompiledList? {
        guard let url = Self.cacheURL, let data = try? Data(contentsOf: url) else { return nil }
        do {
            return try CompiledList(cache: data)
        } catch {
            Log.list.error("ignoring cache: \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    private func loadFile(skipping knownSHA: [UInt8]?) {
        let path = policy.listPath
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            Log.list.error("cannot read \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return
        }
        if Array(SHA256.hash(data: data)) == knownSHA {
            Log.list.info("\(path, privacy: .public) unchanged since the cache was written")
            return
        }
        let (list, invalid) = CompiledList.compile(data)
        install(list, from: path)
        for sample in invalid.prefix(10) {
            Log.list.error("line \(sample.line): \(sample.reason, privacy: .public): \(sample.text, privacy: .public)")
        }
        writeCache(list)
    }

    private func install(_ list: CompiledList, from source: String) {
        store.replace(policy.blocklist(list))
        let s = list.stats
        Log.list.notice(
            "loaded from \(source, privacy: .public): \(s.domainRules) domains, \(s.v4Ranges) v4 ranges, \(s.v6Ranges) v6 ranges, \(s.invalidCount) invalid lines, \(list.byteSize / 1024) KiB")
    }

    private func writeCache(_ list: CompiledList) {
        guard let url = Self.cacheURL else { return }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try list.serialized().write(to: url, options: .atomic)
        } catch {
            Log.list.error("cannot write cache: \(error.localizedDescription, privacy: .public)")
        }
    }
}
