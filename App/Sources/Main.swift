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

    private static func printError(_ text: String) {
        FileHandle.standardError.write(Data("saferoom: \(text)\n".utf8))
    }
}
