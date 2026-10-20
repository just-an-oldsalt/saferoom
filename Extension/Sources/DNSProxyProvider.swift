import NetworkExtension
import os
import SafeRoomCore

/// Phase 0 placeholder: starts, logs, and declines every flow. Declining a flow
/// (returning false) lets the system resolve it normally, which is fail-open.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let log = Logger(subsystem: SafeRoom.logSubsystem, category: "provider")

    // Completion-handler forms, not the async overrides: the async ones pass a
    // non-Sendable [String: Any] across an isolation boundary, which Swift 6
    // strict concurrency rejects.
    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        log.notice("startProxy")
        completionHandler(nil)
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.notice("stopProxy reason=\(reason.rawValue, privacy: .public)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        false
    }
}
