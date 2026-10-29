import Foundation
import Network
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import SafeRoomCore
import Synchronization

/// The system extension's entry point. It only routes: flows go to a relay,
/// decisions come from `Blocklist.decide` in SafeRoomCore.
///
/// Fail-open: until a list loads, the store holds an empty list and every
/// query is forwarded. A crash is not covered. While launchd restarts the
/// extension, queries in that gap fail (docs/threat-model.md).
final class DNSProxyProvider: NEDNSProxyProvider, NEAppProxyUDPFlowHandling, @unchecked Sendable {
    private let filter = DNSFilter(store: BlocklistStore())
    /// Block events for the event URL. Empty and off when the policy has none.
    private let events = EventBuffer()
    /// Written by startProxy and read by stopProxy, which can run on
    /// different threads.
    private let loader = Mutex<ListLoader?>(nil)
    private let poster = Mutex<EventPoster?>(nil)

    // Completion-handler forms, not the async overrides: the async ones pass a
    // non-Sendable [String: Any] across an isolation boundary, which Swift 6
    // strict concurrency rejects.
    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        Log.provider.notice("startProxy")
        // The payload's ProviderConfiguration arrives here, under VendorData.
        // NEDNSProxyManager.shared() does NOT return it in a system
        // extension: that manager belongs to the extension's own bundle ID,
        // and its configuration is empty. The policy is read once per start;
        // a changed configuration takes effect when the proxy restarts.
        let policy = ProviderPolicy(options?["VendorData"] as? [String: Any] ?? [:])
        Log.provider.notice(
            "policy: listURL=\(policy.listURL.map(ExtensionStatus.PolicySummary.redacted) ?? "none", privacy: .public) listPath=\(policy.listPath, privacy: .public) sha256URL=\(policy.listSHA256URL != nil) auth=\(policy.auth.description, privacy: .public) refresh=\(policy.refreshInterval.components.seconds)s maxChange=\(policy.maxChangePercent)% allow=\(policy.allowList.count) neverBlockHosts=\(policy.neverBlockHosts.count) eventURL=\(policy.eventURL.map(ExtensionStatus.PolicySummary.redacted) ?? "none", privacy: .public) eventAuth=\(policy.eventAuth.description, privacy: .public) eventServerPins=\(policy.eventServerPins.map { String($0.count) } ?? "none", privacy: .public)")
        for problem in policy.ignored {
            Log.provider.error("policy value ignored: \(Log.clean(problem), privacy: .public)")
        }
        let loader = ListLoader(policy: policy, store: filter.store)
        self.loader.withLock { $0 = loader }
        Task { await loader.start() }
        let poster = EventPoster(policy: policy, buffer: events, version: Self.version)
        events.setEnabled(poster != nil)
        self.poster.withLock { $0 = poster }
        if let poster { Task { await poster.start() } }
        let startedAt = Date()
        let summary = ExtensionStatus.PolicySummary(policy)
        let counters = filter.counters
        ControlServer.shared.register(.init(
            status: {
                let s = await loader.status()
                let eventSummary = await poster?.summary()
                return ExtensionStatus(
                    version: Self.version, startedAt: startedAt, policy: summary, list: s.list,
                    lastAttempt: s.attempt, lastSuccessAt: s.lastSuccessAt, nextRefreshAt: s.nextRefreshAt,
                    consecutiveFailures: s.failures, counters: counters.values, events: eventSummary)
            },
            refreshNow: { await loader.refreshNow() }))
        // Never fail the start because of the list: fail-open.
        completionHandler(nil)
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        Log.provider.notice("stopProxy reason=\(reason.rawValue, privacy: .public)")
        if let loader = loader.withLock({ $0 }) { Task { await loader.stop() } }
        ControlServer.shared.register(nil)
        guard let poster = poster.withLock({ $0 }) else {
            events.setEnabled(false)
            return completionHandler()
        }
        // The waiting events are in memory only. Give them one last post,
        // but never hold up the stop for longer than two seconds. Turning
        // the buffer off empties it, so that comes after the post.
        nonisolated(unsafe) let done = completionHandler
        Task { [events] in
            await poster.stop(flushWithin: .seconds(2))
            events.setEnabled(false)
            done()
        }
    }

    static let version: String = {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }()

    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        UDPRelay(flow: flow, filter: filter, events: events).start()
        return true
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow else { return false }
        TCPRelay(flow: tcp, filter: filter, events: events).start()
        return true
    }
}
