import Foundation
import SafeRoomCore

/// Entry point. The command-line modes run and exit before any window or
/// app object exists, so a Jamf extension attribute (running as root, with
/// no user session) can call the app binary directly:
///
///     /Applications/SafeRoom.app/Contents/MacOS/SafeRoom --jamf
///
/// --status    the extension's status as JSON
/// --jamf      one line for a Jamf extension attribute: <result>OK: ...</result>
/// --refresh   download or read the list now, then print the status as JSON
/// --activate  submit the system extension and wait for the answer, for a
///             package post-install script
@main
enum Main {
    static func main() {
        let args = Set(CommandLine.arguments.dropFirst())
        if args.contains("--jamf") {
            exit(CommandLineTool.jamf())
        } else if args.contains("--status") {
            exit(CommandLineTool.status(refresh: false))
        } else if args.contains("--refresh") {
            exit(CommandLineTool.status(refresh: true))
        } else if args.contains("--activate") {
            exit(CommandLineTool.activate())
        }
        SafeRoomApp.main()
    }
}

enum CommandLineTool {
    static func status(refresh: Bool) -> Int32 {
        switch ControlClient.fetchBlocking(refresh: refresh) {
        case .success(let status?):
            print(String(decoding: (try? ExtensionStatus.encoder.encode(status)) ?? Data(), as: UTF8.self))
            return 0
        case .success(nil):
            printError("the extension is running, but the proxy is not started")
            return 2
        case .failure(let error):
            printError("cannot reach the SafeRoom extension: \(error.localizedDescription)")
            return 1
        }
    }

    /// Always exits 0: Jamf records the printed line, not the exit code.
    static func jamf() -> Int32 {
        let line: String
        switch ControlClient.fetchBlocking(refresh: false) {
        case .success(let status?): line = status.healthLine()
        case .success(nil): line = "NOT RUNNING: the proxy is not started"
        case .failure: line = "NOT RUNNING: the extension does not answer"
        }
        print("<result>\(line)</result>")
        return 0
    }

    /// Exit 0 when activated (now or after reboot), 3 when waiting for user
    /// approval (the MDM profile is missing), 1 on failure.
    static func activate() -> Int32 {
        let activator = CommandLineActivator()
        activator.submit()
        // OSSystemExtensionManager answers on the main queue.
        while activator.result == nil {
            RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        }
        print("saferoom: \(activator.message)")
        return activator.result ?? 1
    }

    private static func printError(_ text: String) {
        FileHandle.standardError.write(Data("saferoom: \(text)\n".utf8))
    }
}

import SystemExtensions

/// The same request as the window's activator, without a window.
///
/// `@unchecked Sendable`: the request, its delegate calls, and the timeout all
/// run on the main queue.
final class CommandLineActivator: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {
    private(set) var result: Int32?
    private(set) var message = ""

    func submit() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: ExtensionActivator.extensionID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [self] in
            finish(1, "no answer from macOS within 60 seconds")
        }
    }

    private func finish(_ code: Int32, _ text: String) {
        guard result == nil else { return }
        message = text
        result = code
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        finish(3, "waiting for approval: install the MDM profile, or approve in System Settings")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        finish(0, result == .completed ? "extension activated" : "extension activates after a reboot")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(1, "activation failed: \(error.localizedDescription)")
    }
}
