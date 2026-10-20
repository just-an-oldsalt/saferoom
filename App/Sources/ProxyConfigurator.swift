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

    // Writes to the configuration: development builds only. A fleet build
    // must not let a user change or disable the proxy from the app.
    #if SAFEROOM_DEV_CONTROLS
    /// Development hook. Launching the app with a `-TestPolicy` argument
    /// writes that dictionary into the proxy configuration. The value is
    /// old-style plist text, and nothing is saved in the app's preferences:
    ///
    ///     open /Applications/SafeRoom.app --args -TestPolicy \
    ///         '{ ListURL = "http://127.0.0.1:8765/list.txt"; Auth = { Type = bearer; Token = abc; }; }'
    ///     open /Applications/SafeRoom.app --args -TestPolicy '{}'   # back to defaults
    ///
    /// A normal launch changes nothing. A configuration installed by MDM
    /// replaces this one.
    func applyTestPolicy() {
        guard UserDefaults.standard.dictionary(forKey: "TestPolicy") != nil else { return }
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] _ in
            let policy = UserDefaults.standard.dictionary(forKey: "TestPolicy") ?? [:]
            guard let proto = manager.providerProtocol else { return }
            proto.providerConfiguration = policy
            // The provider reads its policy only when it starts, so turn the
            // proxy off and on again to restart it.
            // Two saves in quick succession get merged into one configuration
            // update with no restart, so wait between them.
            manager.isEnabled = false
            manager.saveToPreferences { _ in
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    manager.isEnabled = true
                    manager.saveToPreferences { [self] error in
                        Task { @MainActor in
                            if let error { state = "Error: \(error.localizedDescription)" } else { refresh() }
                        }
                    }
                }
            }
        }
    }

    func setEnabled(_ enabled: Bool) {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] _ in
            if manager.providerProtocol == nil {
                let proto = NEDNSProxyProviderProtocol()
                proto.providerBundleIdentifier = ExtensionActivator.extensionID
                proto.providerConfiguration = UserDefaults.standard.dictionary(forKey: "TestPolicy") ?? [:]
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
    #endif
}
