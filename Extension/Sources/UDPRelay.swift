import Foundation
import Network
// NetworkExtension predates Sendable; its callbacks are safe to capture here.
@preconcurrency import NetworkExtension
import SafeRoomCore

/// One client UDP socket's DNS traffic.
///
/// Each datagram arrives with the address the client sent it to (its
/// resolver). A blocked query is answered here. Anything else goes to that
/// same address over our own socket, and the answer is checked on the way
/// back. SafeRoom never picks a resolver: it uses the one the Mac already uses.
///
/// All state lives on `queue`. NetworkExtension calls back on its own
/// threads, so every callback hops onto the queue first. That is what makes
/// the `@unchecked Sendable` true.
final class UDPRelay: @unchecked Sendable {
    private let flow: NEAppProxyUDPFlow
    private let store: BlocklistStore
    private let app: String
    private let queue = DispatchQueue(label: "com.oldsalt.saferoom.udp")
    private var upstreams: [NWEndpoint: NWConnection] = [:]
    private var lastActivity = ContinuousClock.now
    private var idleTimer: DispatchSourceTimer?
    private var closed = false

    /// A client socket that stays quiet this long is closed. Its next query
    /// opens a new flow.
    static let idleTimeout: Duration = .seconds(30)

    init(flow: NEAppProxyUDPFlow, store: BlocklistStore) {
        self.flow = flow
        self.store = store
        self.app = flow.metaData.sourceAppSigningIdentifier
    }

    func start() {
        flow.open(withLocalFlowEndpoint: nil) { [self] error in
            queue.async { [self] in
                if let error {
                    Log.flow.error("udp open failed: \(error.localizedDescription, privacy: .public)")
                    return close()
                }
                startIdleTimer()
                readFromClient()
            }
        }
    }

    private func readFromClient() {
        flow.readDatagrams { [self] datagrams, error in
            queue.async { [self] in
                // An empty read with no error is the client closing its socket.
                guard !closed, error == nil, let datagrams, !datagrams.isEmpty else { return close() }
                lastActivity = .now
                for (data, endpoint) in datagrams {
                    handleQuery([UInt8](data), to: endpoint)
                }
                readFromClient()
            }
        }
    }

    private func handleQuery(_ packet: [UInt8], to endpoint: NWEndpoint) {
        switch store.current.decide(query: packet) {
        case .block(let reply, let name, let type, let rule):
            Log.blockedQuery(name: name, type: type, rule: rule, app: app, transport: "udp")
            writeToClient(reply, from: endpoint)
        case .forward:
            upstream(for: endpoint).send(content: Data(packet), completion: .contentProcessed { error in
                if let error { Log.flow.error("udp send failed: \(error.localizedDescription, privacy: .public)") }
            })
        }
    }

    private func upstream(for endpoint: NWEndpoint) -> NWConnection {
        if let existing = upstreams[endpoint] { return existing }
        let connection = NWConnection(to: endpoint, using: .udp)
        connection.stateUpdateHandler = { [self] state in
            if case .failed(let error) = state {
                Log.flow.error("udp upstream \(String(describing: endpoint), privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                upstreams[endpoint] = nil
                connection.cancel()
            }
        }
        upstreams[endpoint] = connection
        connection.start(queue: queue)
        readFromUpstream(connection, endpoint: endpoint)
        return connection
    }

    private func readFromUpstream(_ connection: NWConnection, endpoint: NWEndpoint) {
        connection.receiveMessage { [self] data, _, _, error in
            guard !closed else { return }
            if let data, !data.isEmpty {
                lastActivity = .now
                handleResponse([UInt8](data), from: endpoint)
            }
            if error == nil { readFromUpstream(connection, endpoint: endpoint) }
        }
    }

    private func handleResponse(_ packet: [UInt8], from endpoint: NWEndpoint) {
        switch store.current.decide(response: packet) {
        case .pass:
            writeToClient(packet, from: endpoint)
        case .block(let reply, let name, let reason):
            Log.blockedResponse(name: name, reason: reason, app: app, transport: "udp")
            writeToClient(reply, from: endpoint)
        }
    }

    /// `endpoint` is the resolver the client asked, so the reply appears to
    /// come from it.
    private func writeToClient(_ packet: [UInt8], from endpoint: NWEndpoint) {
        flow.writeDatagrams([(Data(packet), endpoint)]) { error in
            if let error { Log.flow.error("udp write failed: \(error.localizedDescription, privacy: .public)") }
        }
    }

    private func startIdleTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [self] in
            if ContinuousClock.now - lastActivity > Self.idleTimeout { close() }
        }
        timer.resume()
        idleTimer = timer
    }

    private func close() {
        guard !closed else { return }
        closed = true
        idleTimer?.cancel()
        idleTimer = nil
        for connection in upstreams.values { connection.cancel() }
        upstreams.removeAll()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }
}
