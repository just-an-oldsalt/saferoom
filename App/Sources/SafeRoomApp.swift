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
    }
}

/// The extension's status, polled over XPC while the window is open.
@Observable
@MainActor
final class StatusMonitor {
    private(set) var status: ExtensionStatus?
    private(set) var problem: String? = "Connecting to the extension"
    private(set) var refreshing = false

    func poll() async {
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
        case .success(nil):
            status = nil
            problem = "The extension is running, but the DNS proxy is not started."
        case .failure(let error):
            status = nil
            problem = "The extension does not answer: \(error.localizedDescription)"
        }
    }
}

struct StatusView: View {
    let activator: ExtensionActivator
    let proxy: ProxyConfigurator
    let monitor: StatusMonitor

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SafeRoom").font(.largeTitle.bold())

            GroupBox("Setup") {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Extension", value: activator.state)
                    LabeledContent("DNS proxy", value: proxy.state)
                    // Development builds only (make release DEV_CONTROLS=1).
                    // In a fleet build, MDM alone turns the proxy on and off;
                    // a user cannot disable it from this window.
                    #if SAFEROOM_DEV_CONTROLS
                    HStack {
                        Button("Activate extension") { activator.activate() }
                        Button("Enable DNS proxy") { proxy.setEnabled(true) }
                        Button("Disable") { proxy.setEnabled(false) }
                    }
                    Text("Development build. Under MDM, the profile enables the proxy.")
                        .font(.caption).foregroundStyle(.secondary)
                    #endif
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Status") {
                VStack(alignment: .leading, spacing: 6) {
                    if let s = monitor.status {
                        StatusDetails(status: s)
                    } else {
                        Text(monitor.problem ?? "").foregroundStyle(.secondary)
                    }
                    Button(monitor.refreshing ? "Refreshing..." : "Refresh list now") {
                        Task { await monitor.refreshNow() }
                    }
                    .disabled(monitor.refreshing || monitor.status == nil)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(24)
        .frame(minWidth: 520)
    }
}

struct StatusDetails: View {
    let status: ExtensionStatus

    var body: some View {
        let health = status.health()
        Text(health.rawValue)
            .font(.headline)
            .foregroundStyle(health == .ok ? .green : health == .degraded ? .orange : .red)
        if let list = status.list {
            LabeledContent("List", value: "\(list.domainRules) domains, \(list.v4Ranges + list.v6Ranges) ranges, \(list.memoryBytes / 1024) KiB")
            LabeledContent("Source", value: list.source)
            LabeledContent("Loaded", value: list.loadedAt.formatted(date: .abbreviated, time: .standard))
            if list.invalidLines > 0 { LabeledContent("Invalid lines", value: "\(list.invalidLines)") }
        }
        if let at = status.lastSuccessAt {
            LabeledContent("Last check", value: at.formatted(date: .abbreviated, time: .standard))
        }
        if let a = status.lastAttempt, a.result == .rejected || a.result == .failed {
            LabeledContent("Last problem", value: "\(a.result.rawValue): \(a.detail ?? "")")
                .foregroundStyle(.orange)
        }
        if let next = status.nextRefreshAt {
            LabeledContent("Next refresh", value: next.formatted(date: .omitted, time: .standard))
        }
        LabeledContent("Blocked", value: "\(status.counters.blockedQueries) queries, \(status.counters.blockedAnswers) answers of \(status.counters.queries)")
        LabeledContent("Policy", value: status.policy.listURL ?? status.policy.listPath)
        LabeledContent("Version", value: status.version)
    }
}
