import AppKit
import SafeRoomCore
import SwiftUI

/// The app window: the extension's health, the list in use, and the policy.
/// Read-only on a Mac that MDM manages: MDM alone sets the policy and turns
/// the proxy on and off. On any other Mac, the user picks the list here
/// (`ConfigurationAccess`).
struct StatusView: View {
    let activator: ExtensionActivator
    let proxy: ProxyConfigurator
    let monitor: StatusMonitor
    @State private var editing = false
    @State private var problem: String?

    private var access: ConfigurationAccess {
        #if DEBUG
        // Debug builds: `-SampleAccess firstRun|on|off` shows that mode, for
        // screenshots and UI work, with `-SampleStatus YES` for the last two.
        switch UserDefaults.standard.string(forKey: "SampleAccess") {
        case "firstRun": return .firstRun
        case "on": return .user(enabled: true)
        case "off": return .user(enabled: false)
        default: break
        }
        #endif
        // Until the extension answered once, its policy is unknown, and a
        // managed Mac could look like a first run.
        return ConfigurationAccess.decide(manager: monitor.answered ? proxy.manager : .unknown, running: monitor.status?.policy)
    }

    var body: some View {
        VStack(spacing: 0) {
            Header(status: monitor.status, problem: monitor.problem, note: note)
            Divider()
            Form {
                if access == .firstRun || access == .user(enabled: false) {
                    SetupSection(firstRun: access == .firstRun, busy: proxy.saving, problem: problem,
                                 turnOn: { turnOn() }, edit: { editing = true })
                }
                if let s = monitor.status {
                    Section { Metrics(status: s) }
                    ListSection(status: s)
                    PolicySection(
                        policy: s.policy, editable: access.canEdit, busy: proxy.saving, problem: problem,
                        edit: { editing = true }, turnOff: { turnOff() })
                }
                SystemSection(activator: activator, proxy: proxy, status: monitor.status)
                #if SAFEROOM_DEV_CONTROLS
                DevSection(activator: activator, proxy: proxy)
                #endif
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            Divider()
            Footer(monitor: monitor)
        }
        .frame(width: 620, height: 760)
        .background(.background)
        .sheet(isPresented: $editing) {
            SourceEditor(initial: proxy.settings ?? UserSettings(), proxy: proxy) { editing = false }
        }
    }

    private var note: String? {
        switch access {
        case .firstRun: "Choose a threat list below to turn on protection."
        case .user(enabled: false): "Protection is off. Turn it on below."
        case .user(enabled: true) where monitor.status == nil:
            "Protection is on, but the system extension does not answer. Allow SafeRoom in System Settings > General > Login Items & Extensions."
        default: nil
        }
    }

    private func turnOn() {
        Task { problem = await proxy.save(proxy.settings ?? UserSettings(), enabled: true) }
    }

    private func turnOff() {
        Task { problem = await proxy.setUserEnabled(false) }
    }
}

// MARK: - Header

private struct Header: View {
    let status: ExtensionStatus?
    let problem: String?
    /// Replaces the problem text while the user has not turned SafeRoom on.
    let note: String?

    var body: some View {
        VStack(spacing: 14) {
            HStack(alignment: .center, spacing: 16) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 72, height: 72)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("SafeRoom").font(.title.weight(.semibold))
                    Text("DNS threat protection")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                HealthBadge(state: state)
            }
            Banner(state: state, detail: detail)
        }
        .padding(.horizontal, 22)
        .padding(.top, 8)
        .padding(.bottom, 16)
    }

    private var state: DisplayState {
        guard let status else { return .offline }
        return DisplayState(status.health())
    }

    private var detail: String {
        guard let status else { return note ?? problem ?? "Connecting to the extension." }
        let list = status.list.map { "\($0.domainRules.formatted()) domains and \(($0.v4Ranges + $0.v6Ranges).formatted()) address ranges" }
        switch status.health() {
        case .ok:
            return "Blocking \(list ?? "the threat list"). The list is current."
        case .degraded:
            return "Blocking with the current list. The last \(status.consecutiveFailures) update checks failed: \(status.lastAttempt?.detail ?? "unknown error")."
        case .stale:
            return "Blocking with an old list. No update check succeeded for three refresh intervals."
        case .noList:
            return "No threat list is loaded. DNS works, but nothing is blocked."
        }
    }
}

/// The four health states plus "the extension does not answer".
private enum DisplayState {
    case protected, degraded, stale, unprotected, offline

    init(_ health: ExtensionStatus.Health) {
        switch health {
        case .ok: self = .protected
        case .degraded: self = .degraded
        case .stale: self = .stale
        case .noList: self = .unprotected
        }
    }

    var title: String {
        switch self {
        case .protected: "Protected"
        case .degraded: "Update problem"
        case .stale: "List out of date"
        case .unprotected: "Not blocking"
        case .offline: "Not running"
        }
    }

    var symbol: String {
        switch self {
        case .protected: "checkmark.shield.fill"
        case .degraded: "exclamationmark.shield.fill"
        case .stale: "clock.badge.exclamationmark.fill"
        case .unprotected: "xmark.shield.fill"
        case .offline: "bolt.horizontal.circle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .protected: .green
        case .degraded, .stale: .orange
        case .unprotected: .red
        case .offline: .secondary
        }
    }
}

private struct HealthBadge: View {
    let state: DisplayState

    var body: some View {
        Label(state.title, systemImage: state.symbol)
            .font(.callout.weight(.semibold))
            .foregroundStyle(state.tint)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(state.tint.opacity(0.14), in: Capsule())
            .overlay(Capsule().strokeBorder(state.tint.opacity(0.35)))
    }
}

private struct Banner: View {
    let state: DisplayState
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: state.symbol)
                .font(.title2)
                .foregroundStyle(state.tint)
                .frame(width: 28)
            Text(detail)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(state.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(state.tint.opacity(0.25)))
    }
}

// MARK: - Metrics

private struct Metrics: View {
    let status: ExtensionStatus

    var body: some View {
        let c = status.counters
        HStack(spacing: 10) {
            Metric(value: (status.list?.domainRules ?? 0).formatted(.number.notation(.compactName)),
                   label: "Domains", symbol: "globe")
            Metric(value: ((status.list?.v4Ranges ?? 0) + (status.list?.v6Ranges ?? 0)).formatted(.number.notation(.compactName)),
                   label: "IP ranges", symbol: "point.3.connected.trianglepath.dotted")
            Metric(value: (c.blockedQueries + c.blockedAnswers).formatted(.number.notation(.compactName)),
                   label: "Blocked", symbol: "hand.raised.fill", tint: .red)
            Metric(value: c.queries.formatted(.number.notation(.compactName)),
                   label: "Lookups checked", symbol: "magnifyingglass")
        }
        .padding(.vertical, 4)
    }
}

private struct Metric: View {
    let value: String
    let label: String
    let symbol: String
    var tint: Color = .accentColor

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: symbol).foregroundStyle(tint).font(.callout)
            Text(value).font(.title2.weight(.semibold).monospacedDigit())
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Sections

private struct ListSection: View {
    let status: ExtensionStatus

    var body: some View {
        Section("Threat list") {
            if let list = status.list {
                Row("Source", list.source, mono: true)
                Row("Loaded", list.loadedAt.formatted(date: .abbreviated, time: .shortened))
                Row("Fingerprint", "SHA-256 \(list.sha256Prefix)…", mono: true)
                Row("Memory", ByteCountFormatter.string(fromByteCount: Int64(list.memoryBytes), countStyle: .memory))
                if list.invalidLines > 0 { Row("Skipped lines", list.invalidLines.formatted()) }
            }
            if let at = status.lastSuccessAt {
                Row("Last check", at.formatted(.relative(presentation: .named)))
            }
            if let next = status.nextRefreshAt {
                Row("Next check", next.formatted(date: .omitted, time: .shortened))
            }
            if let a = status.lastAttempt, a.result == .rejected || a.result == .failed {
                LabeledContent("Last problem") {
                    Text("\(a.result.rawValue.capitalized): \(a.detail ?? "no detail")")
                        .foregroundStyle(.orange).textSelection(.enabled)
                }
            }
        }
    }
}

private struct PolicySection: View {
    let policy: ExtensionStatus.PolicySummary
    let editable: Bool
    let busy: Bool
    let problem: String?
    let edit: () -> Void
    let turnOff: () -> Void
    @State private var confirmingOff = false

    var body: some View {
        Section {
            Row("List location", policy.listURL ?? policy.listPath, mono: true)
            Row("Authentication", authText)
            Row("Integrity check", policy.sha256Check ? "SHA-256 file" : "TLS only")
            Row("Refresh interval", Duration.seconds(policy.refreshSeconds).formatted(.units(allowed: [.hours, .minutes], width: .wide)))
            Row("Allow list", "\(policy.allowListCount) entries")
            Row("Never-block hosts", "\(policy.neverBlockHostCount) entries")
            if let eventURL = policy.eventURL { Row("Block events", eventURL, mono: true) }
            if editable {
                HStack {
                    Button("Change list…", action: edit)
                    Spacer()
                    Button("Turn off protection", role: .destructive) { confirmingOff = true }
                }
                .disabled(busy)
                .confirmationDialog("Turn off protection?", isPresented: $confirmingOff) {
                    Button("Turn Off", role: .destructive, action: turnOff)
                } message: {
                    Text("SafeRoom stops blocking until you turn it on again.")
                }
                if let problem { Text(problem).font(.callout).foregroundStyle(.red) }
            }
        } header: {
            Text("Policy")
        } footer: {
            if editable {
                Label("Set on this Mac. No device management controls SafeRoom here.", systemImage: "person.crop.circle")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Set by your organization through device management.", systemImage: "building.2")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var authText: String {
        if policy.auth == "none" { return "None" }
        if policy.auth == "bearer" { return "Bearer token" }
        return "Client certificate"
    }
}

private struct SystemSection: View {
    let activator: ExtensionActivator
    let proxy: ProxyConfigurator
    let status: ExtensionStatus?

    var body: some View {
        Section("System") {
            Row("System extension", activator.state)
            Row("DNS proxy", status != nil ? "Running" : "Not answering")
            if let status {
                Row("Running since", status.startedAt.formatted(date: .abbreviated, time: .shortened))
                Row("Version", status.version)
            }
        }
    }
}

#if SAFEROOM_DEV_CONTROLS
private struct DevSection: View {
    let activator: ExtensionActivator
    let proxy: ProxyConfigurator

    var body: some View {
        Section {
            Row("Local configuration", proxy.state)
            HStack {
                Button("Activate extension") { activator.activate() }
                Button("Enable DNS proxy") { proxy.setEnabled(true) }
                Button("Disable") { proxy.setEnabled(false) }
                Button("Remove") { proxy.removeConfiguration() }
                    .help("Deletes the app's DNS proxy configuration, as on a new Mac.")
            }
        } header: {
            Label("Development build", systemImage: "hammer")
        } footer: {
            Text("Not in fleet builds. Under MDM, the profile turns the proxy on.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
#endif

private struct Row: View {
    let label: String
    let value: String
    let mono: Bool

    init(_ label: String, _ value: String, mono: Bool = false) {
        self.label = label
        self.value = value
        self.mono = mono
    }

    var body: some View {
        LabeledContent(label) {
            Text(value)
                .font(mono ? .callout.monospaced() : .callout)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .help(value)
        }
    }
}

// MARK: - Footer

private struct Footer: View {
    let monitor: StatusMonitor
    @State private var copied = false

    var body: some View {
        HStack(spacing: 12) {
            if let at = monitor.updatedAt {
                Text("Updated \(at.formatted(date: .omitted, time: .standard))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                copyDiagnostics()
            } label: {
                Label(copied ? "Copied" : "Copy diagnostics", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .disabled(monitor.status == nil)
            .help("Copies the status as JSON, for a support ticket. Holds no tokens.")
            Button {
                Task { await monitor.refreshNow() }
            } label: {
                if monitor.refreshing {
                    ProgressView().controlSize(.small).padding(.horizontal, 30)
                } else {
                    Label("Check for updates", systemImage: "arrow.clockwise")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(monitor.refreshing || monitor.status == nil)
            .help("Checks the list server now. At most once every 5 minutes.")
        }
        .controlSize(.large)
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private func copyDiagnostics() {
        guard let status = monitor.status,
              let data = try? ExtensionStatus.encoder.encode(status),
              let json = String(data: data, encoding: .utf8)
        else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(json, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }
}
