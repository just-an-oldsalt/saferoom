import Foundation
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import Observation
import SafeRoomCore

/// The app's view of the DNS proxy configuration, and the user's way to set
/// it on a Mac that no MDM manages.
///
/// Under MDM, the DNS Proxy payload sets the configuration and the window is
/// read-only (`ConfigurationAccess`). Without MDM, the user picks a list in
/// the app, and the app writes it here. macOS asks the user to allow it the
/// first time ("SafeRoom would like to add proxy configurations").
@Observable
@MainActor
final class ProxyConfigurator {
    private(set) var state = "Unknown"
    private(set) var manager: ConfigurationAccess.Manager = .unknown
    /// The settings in the app's configuration, when the app wrote it.
    private(set) var settings: UserSettings?
    private(set) var saving = false

    func refresh() {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] error in
            let found = Self.found(manager)
            let config = manager.providerProtocol?.providerConfiguration ?? [:]
            let settings = found == .configured(byApp: true, enabled: manager.isEnabled)
                ? UserSettings(configuration: config) : nil
            let detail = "protocol \(manager.providerProtocol == nil ? "none" : "present"), \(config.count) keys"
            Task { @MainActor in
                if let error {
                    state = "Error: \(error.localizedDescription)"
                    self.manager = .unknown
                    return
                }
                state = switch found {
                case .none, .unknown: "Not configured (\(detail))"
                case .configured(let byApp, let enabled):
                    "\(enabled ? "Enabled" : "Configured, disabled"), \(byApp ? "by the app" : "not by the app") (\(detail))"
                }
                self.manager = found
                self.settings = settings
            }
        }
    }

    /// Writes the user's settings and turns the proxy on or off. Returns an
    /// error message, or nil on success. The caller checks
    /// `ConfigurationAccess` first; this method checks again that the
    /// configuration it replaces is the app's own.
    func save(_ settings: UserSettings, enabled: Bool) async -> String? {
        saving = true
        defer { saving = false }
        let error = await write(settings.configuration, enabled: enabled)
        refresh()
        return error
    }

    /// Turns the proxy on or off and keeps the settings.
    func setUserEnabled(_ enabled: Bool) async -> String? {
        await save(settings ?? UserSettings(), enabled: enabled)
    }

    private func write(_ configuration: [String: Any], enabled: Bool) async -> String? {
        let manager = NEDNSProxyManager.shared()
        if let error = await load(manager) { return error }
        let found = Self.found(manager)
        guard found.writable else {
            return "This Mac's DNS proxy is set by device management. SafeRoom cannot change it."
        }
        let wasEnabled = manager.isEnabled
        let proto = found == .none ? NEDNSProxyProviderProtocol() : manager.providerProtocol ?? NEDNSProxyProviderProtocol()
        proto.providerBundleIdentifier = ExtensionActivator.extensionID
        proto.providerConfiguration = configuration
        manager.providerProtocol = proto
        manager.localizedDescription = "SafeRoom"
        // The provider reads its policy only when it starts. A running proxy
        // is turned off and on again to restart it. Two saves in quick
        // succession get merged into one update with no restart, so wait
        // between them.
        if wasEnabled, enabled {
            manager.isEnabled = false
            if let error = await save(manager) { return error }
            try? await Task.sleep(for: .seconds(2))
        }
        manager.isEnabled = enabled
        return await save(manager)
    }

    nonisolated private static func found(_ manager: NEDNSProxyManager) -> ConfigurationAccess.Manager {
        ConfigurationAccess.Manager(
            hasProtocol: manager.providerProtocol != nil,
            configuration: manager.providerProtocol?.providerConfiguration,
            enabled: manager.isEnabled)
    }

    private func load(_ manager: NEDNSProxyManager) async -> String? {
        await withCheckedContinuation { continuation in
            manager.loadFromPreferences { error in continuation.resume(returning: error?.localizedDescription) }
        }
    }

    private func save(_ manager: NEDNSProxyManager) async -> String? {
        await withCheckedContinuation { continuation in
            manager.saveToPreferences { error in continuation.resume(returning: error?.localizedDescription) }
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
            guard let proto = manager.providerProtocol else { return }
            proto.providerConfiguration = Self.testPolicy
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

    /// The `-TestPolicy` dictionary, marked as the app's own unless it says
    /// otherwise, so a development Mac stays editable in the window. Pass
    /// `ConfiguredBy = mdm;` to see the managed window.
    nonisolated private static var testPolicy: [String: Any] {
        var policy = UserDefaults.standard.dictionary(forKey: "TestPolicy") ?? [:]
        if policy[ProviderPolicy.configuredByKey] == nil {
            policy[ProviderPolicy.configuredByKey] = ProviderPolicy.configuredByApp
        }
        return policy
    }

    /// Development hook: back to the first run, with no System Settings trip.
    func removeConfiguration() {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] _ in
            manager.removeFromPreferences { [self] error in
                Task { @MainActor in
                    if let error { state = "Error: \(error.localizedDescription)" } else { refresh() }
                }
            }
        }
    }

    func setEnabled(_ enabled: Bool) {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [self] _ in
            if Self.found(manager) == .none {
                let proto = NEDNSProxyProviderProtocol()
                proto.providerBundleIdentifier = ExtensionActivator.extensionID
                proto.providerConfiguration = Self.testPolicy
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
