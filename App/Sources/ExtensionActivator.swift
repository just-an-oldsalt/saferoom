import Foundation
import Observation
import SystemExtensions

/// Asks macOS to install or update the DNS proxy system extension.
///
/// Under MDM the System Extensions payload pre-approves the team and bundle ID,
/// so this completes with no prompt. The DNS Proxy payload then turns the
/// proxy on. Without MDM, the user approves it in System Settings.
@Observable
@MainActor
final class ExtensionActivator: NSObject {
    static let extensionID = "com.oldsalt.saferoom.dnsproxy"

    private(set) var state = "Not requested"

    func activate() {
        state = "Requesting activation"
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

extension ExtensionActivator: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in state = "Waiting for approval in System Settings" }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        let text = result == .completed ? "Activated" : "Activated after reboot"
        Task { @MainActor in state = text }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let text = "Failed: \(error.localizedDescription)"
        Task { @MainActor in state = text }
    }
}
