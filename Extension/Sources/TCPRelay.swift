import Foundation
import Network
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import SafeRoomCore

/// One client TCP connection's DNS traffic.
///
/// DNS over TCP carries each message after a 2-byte length. The relay frames
/// the byte stream into messages in both directions, so every query and every
/// answer gets the same checks as over UDP. Clients fall back to TCP for large
/// answers, and a TCP path that skipped the checks would be a bypass.
///
/// Same threading rule as `UDPRelay`: all state on `queue`.
final class TCPRelay: @unchecked Sendable {
    private let flow: NEAppProxyTCPFlow
    private let filter: DNSFilter
    private let app: String
    private let queue = DispatchQueue(label: "com.oldsalt.saferoom.tcp")
    private var upstream: NWConnection?
    private var fromClient = DNSTCPFramer()
    private var fromUpstream = DNSTCPFramer()
    private var closed = false

    init(flow: NEAppProxyTCPFlow, filter: DNSFilter) {
        self.flow = flow
        self.filter = filter
        self.app = flow.metaData.sourceAppSigningIdentifier
    }

    func start() {
        flow.open(withLocalFlowEndpoint: nil) { [self] error in
            queue.async { [self] in
                if let error {
                    Log.flow.error("tcp open failed: \(error.localizedDescription, privacy: .public)")
                    return close()
                }
                let connection = NWConnection(to: flow.remoteFlowEndpoint, using: .tcp)
                connection.stateUpdateHandler = { [self] state in
                    switch state {
                    case .failed(let error):
                        Log.flow.error("tcp upstream failed: \(error.localizedDescription, privacy: .public)")
                        close()
                    case .cancelled:
                        close()
                    default:
                        break
                    }
                }
                upstream = connection
                connection.start(queue: queue)
                readFromClient()
                readFromUpstream()
            }
        }
    }

    private func readFromClient() {
        flow.readData { [self] data, error in
            queue.async { [self] in
                guard !closed, error == nil, let data, !data.isEmpty else { return close() }
                for message in fromClient.push(data) {
                    switch filter.decide(query: message) {
                    case .block(let reply, let name, let type, let rule):
                        Log.blockedQuery(name: name, type: type, rule: rule, app: app, transport: "tcp")
                        writeToClient(reply)
                    case .forward:
                        guard let framed = DNSTCPFramer.frame(message) else { continue }
                        upstream?.send(content: Data(framed), completion: .contentProcessed { _ in })
                    }
                }
                readFromClient()
            }
        }
    }

    private func readFromUpstream() {
        upstream?.receive(minimumIncompleteLength: 1, maximumLength: 65_537) { [self] data, _, isComplete, error in
            guard !closed else { return }
            if let data, !data.isEmpty {
                for message in fromUpstream.push(data) {
                    switch filter.decide(response: message) {
                    case .pass:
                        writeToClient(message)
                    case .block(let reply, let name, let reason):
                        Log.blockedResponse(name: name, reason: reason, app: app, transport: "tcp")
                        writeToClient(reply)
                    }
                }
            }
            if isComplete || error != nil { return close() }
            readFromUpstream()
        }
    }

    private func writeToClient(_ message: [UInt8]) {
        guard let framed = DNSTCPFramer.frame(message) else { return }
        flow.write(Data(framed)) { error in
            if let error { Log.flow.error("tcp write failed: \(error.localizedDescription, privacy: .public)") }
        }
    }

    private func close() {
        guard !closed else { return }
        closed = true
        upstream?.cancel()
        upstream = nil
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }
}
