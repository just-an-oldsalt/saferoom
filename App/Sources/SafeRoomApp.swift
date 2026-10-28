import SafeRoomCore
import SwiftUI

struct SafeRoomApp: App {
    @State private var activator = ExtensionActivator()
    @State private var proxy = ProxyConfigurator()
    @State private var monitor = StatusMonitor()

    var body: some Scene {
        WindowGroup {
            StatusView(activator: activator, proxy: proxy, monitor: monitor)
                .task {
                    activator.activate()
                    #if SAFEROOM_DEV_CONTROLS
                    proxy.applyTestPolicy()
                    #endif
                    proxy.refresh()
                }
                .task { await monitor.poll() }
        }
        .windowResizability(.contentSize)
        .windowToolbarStyle(.unifiedCompact(showsTitle: false))
    }
}

/// The extension's status, polled over XPC while the window is open.
@Observable
@MainActor
final class StatusMonitor {
    private(set) var status: ExtensionStatus?
    private(set) var problem: String? = "Connecting to the extension"
    private(set) var refreshing = false
    private(set) var updatedAt: Date?

    func poll() async {
        #if DEBUG
        // Debug builds: `-SampleStatus YES` shows made-up data, for
        // screenshots and UI work without a running extension.
        if UserDefaults.standard.bool(forKey: "SampleStatus") {
            status = Self.sample
            problem = nil
            updatedAt = Date()
            return
        }
        #endif
        while !Task.isCancelled {
            if !refreshing { apply(await ControlClient.fetch(refresh: false)) }
            try? await Task.sleep(for: .seconds(5))
        }
    }

    func refreshNow() async {
        refreshing = true
        apply(await ControlClient.fetch(refresh: true))
        refreshing = false
    }

    private func apply(_ outcome: ControlClient.Outcome) {
        switch outcome {
        case .success(let s?):
            status = s
            problem = nil
            updatedAt = Date()
        case .success(nil):
            status = nil
            problem = "The extension is running, but the DNS proxy is not started."
        case .failure(let error):
            status = nil
            problem = "The extension does not answer: \(error.localizedDescription)"
        }
    }

    #if DEBUG
    static var sample: ExtensionStatus? {
        let now = Date()
        func t(_ offset: TimeInterval) -> String { (now + offset).ISO8601Format() }
        let json = """
        {"version": "0.1.3 (18)", "startedAt": "\(t(-86_000))", "consecutiveFailures": 0,
         "lastSuccessAt": "\(t(-1_260))", "nextRefreshAt": "\(t(2_340))",
         "lastAttempt": {"at": "\(t(-1_260))", "source": "https://cookbook.oldsalt.zone/list.txt", "result": "unchanged"},
         "counters": {"queries": 48213, "blockedQueries": 312, "blockedAnswers": 9, "learnedBlocks": 4},
         "list": {"source": "https://cookbook.oldsalt.zone/list.txt", "loadedAt": "\(t(-86_000))",
                  "domainRules": 234910, "v4Ranges": 1451, "v6Ranges": 241, "invalidLines": 0,
                  "memoryBytes": 2252800, "sha256Prefix": "9f2c41d07ab3e815"},
         "policy": {"listURL": "https://cookbook.oldsalt.zone/list.txt", "listPath": "/Library/Application Support/SafeRoom/blocklist.txt",
                    "sha256Check": true, "auth": "bearer", "refreshSeconds": 3600, "maxChangePercent": 0,
                    "allowListCount": 3, "neverBlockHostCount": 2}}
        """
        return try? ExtensionStatus.decoder.decode(ExtensionStatus.self, from: Data(json.utf8))
    }
    #endif
}
