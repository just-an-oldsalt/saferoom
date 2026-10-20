import Foundation
import SafeRoomCore
import Synchronization

/// Serves `SafeRoomControl` on the extension's Mach service, for the app
/// window and the app's `--status` and `--jamf` modes.
///
/// One listener per process, started in main.swift. Each proxy start
/// registers its provider as the source of status.
///
/// `@unchecked`: the listener is used only in `start()`, once, from main.
final class ControlServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    static let shared = ControlServer()

    /// What the server needs from the running proxy.
    struct Source: Sendable {
        let status: @Sendable () async -> ExtensionStatus
        let refreshNow: @Sendable () async -> Void
    }

    private let source = Mutex<Source?>(nil)
    private let listener = NSXPCListener(machServiceName: ControlChannel.machServiceName)

    func start() {
        // Only code signed by our team may connect. macOS checks this before
        // the delegate sees the connection.
        listener.setConnectionCodeSigningRequirement(ControlChannel.teamRequirement)
        listener.delegate = self
        listener.resume()
        Log.provider.notice("control listener on \(ControlChannel.machServiceName, privacy: .public)")
    }

    func register(_ source: Source?) {
        self.source.withLock { $0 = source }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: SafeRoomControl.self)
        connection.exportedObject = Handler(server: self)
        connection.resume()
        return true
    }

    fileprivate func current() -> Source? { source.withLock { $0 } }

    private final class Handler: NSObject, SafeRoomControl, Sendable {
        let server: ControlServer

        init(server: ControlServer) { self.server = server }

        func status(reply: @escaping (Data) -> Void) {
            nonisolated(unsafe) let reply = reply
            let source = server.current()
            Task {
                reply(await Self.encode(source?.status()))
            }
        }

        func refreshNow(reply: @escaping (Data) -> Void) {
            nonisolated(unsafe) let reply = reply
            let source = server.current()
            Task {
                await source?.refreshNow()
                reply(await Self.encode(source?.status()))
            }
        }

        /// Empty data means the proxy is not running in this process.
        private static func encode(_ status: ExtensionStatus?) -> Data {
            guard let status else { return Data() }
            return (try? ExtensionStatus.encoder.encode(status)) ?? Data()
        }
    }
}
