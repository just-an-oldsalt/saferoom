import Foundation
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import Observation

/// Turns the DNS proxy on from the app, for testing without MDM.
///
/// In production the MDM DNS Proxy payload does this, and a managed
/// configuration replaces this one. macOS asks the user to allow it the
/// first time ("SafeRoom would like to add proxy configurations").
@Observable
@MainActor
final class ProxyConfigurator {
    private(set) var state = "Unknown"

    func refresh() {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] error in
            let enabled = manager.isEnabled
            let configured = manager.providerProtocol != nil
            Task { @MainActor in
                if let error { state = "Error: \(error.localizedDescription)"; return }
                state = !configured ? "Not configured" : enabled ? "Enabled" : "Configured, disabled"
            }
        }
    }

    func setEnabled(_ enabled: Bool) {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] _ in
            if manager.providerProtocol == nil {
                let proto = NEDNSProxyProviderProtocol()
                proto.providerBundleIdentifier = ExtensionActivator.extensionID
                proto.providerConfiguration = [:]  // ProviderPolicy defaults
                manager.providerProtocol = proto
                manager.localizedDescription = "SafeRoom"
            }
            manager.isEnabled = enabled
            manager.saveToPreferences { [self] error in
                Task { @MainActor in
                    if let error { state = "Error: \(error.localizedDescription)" } else { refresh() }
                }
            }
        }
    }
}
