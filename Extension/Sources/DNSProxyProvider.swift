import Foundation
import Network
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import SafeRoomCore

/// The system extension's entry point. It only routes: flows go to a relay,
/// decisions come from `Blocklist.decide` in SafeRoomCore.
///
/// Fail-open: until a list loads, the store holds an empty list and every
/// query is forwarded. A crash is not covered. While launchd restarts the
/// extension, queries in that gap fail (docs/threat-model.md).
final class DNSProxyProvider: NEDNSProxyProvider, NEAppProxyUDPFlowHandling, @unchecked Sendable {
    private let filter = DNSFilter(store: BlocklistStore())
    private var loader: ListLoader?

    // Completion-handler forms, not the async overrides: the async ones pass a
    // non-Sendable [String: Any] across an isolation boundary, which Swift 6
    // strict concurrency rejects.
    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        Log.provider.notice("startProxy")
        // A DNS proxy provider has no protocolConfiguration property. The
        // configuration, MDM's included, is read through the shared manager.
        let manager = NEDNSProxyManager.shared()
        // NetworkExtension accepts this call from any thread.
        nonisolated(unsafe) let completionHandler = completionHandler
        manager.loadFromPreferences { [self] error in
            if let error {
                Log.provider.error("cannot load configuration, using defaults: \(error.localizedDescription, privacy: .public)")
            }
            let config = manager.providerProtocol?.providerConfiguration ?? [:]
            let policy = ProviderPolicy(config)
            Log.provider.notice("policy: listPath=\(policy.listPath, privacy: .public) allow=\(policy.allowList.count) neverBlockHosts=\(policy.neverBlockHosts.count)")
            let loader = ListLoader(policy: policy, store: filter.store)
            self.loader = loader
            loader.start()
            // Never fail the start because of the list: fail-open.
            completionHandler(nil)
        }
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        Log.provider.notice("stopProxy reason=\(reason.rawValue, privacy: .public)")
        completionHandler()
    }

    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        UDPRelay(flow: flow, filter: filter).start()
        return true
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow else { return false }
        TCPRelay(flow: tcp, filter: filter).start()
        return true
    }
}
