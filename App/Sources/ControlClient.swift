import Foundation
import SafeRoomCore
import Synchronization

/// Talks to the extension over XPC.
///
/// `.privileged` because the extension's Mach service lives in the system
/// domain (it runs as root). The connection checks that the server is signed
/// by our team, as the server checks us.
enum ControlClient {
    enum ClientError: LocalizedError {
        case timeout
        case badReply

        var errorDescription: String? {
            switch self {
            case .timeout: "no answer within the timeout"
            case .badReply: "the reply could not be read"
            }
        }
    }

    /// `.success(nil)` means the extension answered but no proxy is running.
    typealias Outcome = Result<ExtensionStatus?, Error>

    static func fetch(refresh: Bool, timeout: TimeInterval = 15, completion: @escaping @Sendable (Outcome) -> Void) {
        // NSXPCConnection is thread-safe; invalidate() may run on any thread.
        nonisolated(unsafe) let connection = NSXPCConnection(
            machServiceName: ControlChannel.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: SafeRoomControl.self)
        connection.setCodeSigningRequirement(ControlChannel.teamRequirement)
        connection.resume()

        // Error handler, reply, and timeout race; the first one wins.
        let done = Mutex(false)
        let finish: @Sendable (Outcome) -> Void = { outcome in
            guard done.withLock({ old in defer { old = true }; return !old }) else { return }
            connection.invalidate()
            completion(outcome)
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in finish(.failure(error)) }
        guard let control = proxy as? SafeRoomControl else { return finish(.failure(ClientError.badReply)) }
        let reply: (Data) -> Void = { data in
            if data.isEmpty { return finish(.success(nil)) }
            do {
                finish(.success(try ExtensionStatus.decoder.decode(ExtensionStatus.self, from: data)))
            } catch {
                finish(.failure(ClientError.badReply))
            }
        }
        if refresh { control.refreshNow(reply: reply) } else { control.status(reply: reply) }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(.failure(ClientError.timeout)) }
    }

    static func fetch(refresh: Bool) async -> Outcome {
        await withCheckedContinuation { continuation in
            fetch(refresh: refresh) { continuation.resume(returning: $0) }
        }
    }

    /// For the command line, which has no run loop to wait on.
    static func fetchBlocking(refresh: Bool) -> Outcome {
        let result = Mutex<Outcome?>(nil)
        let semaphore = DispatchSemaphore(value: 0)
        fetch(refresh: refresh) { outcome in
            result.withLock { $0 = outcome }
            semaphore.signal()
        }
        semaphore.wait()
        return result.withLock { $0 } ?? .failure(ClientError.timeout)
    }
}
