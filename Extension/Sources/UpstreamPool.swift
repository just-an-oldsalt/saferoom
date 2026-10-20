import Foundation
import Network
import SafeRoomCore

/// One UDP connection per resolver, shared by every client flow.
///
/// Opening a connection for each new client socket cost about 1.5 ms per
/// lookup (docs/performance.md). Sharing one per resolver removes that:
/// `QueryMultiplexer` gives each query a fresh random ID and matches the
/// answer back to its flow by ID and question.
///
/// All state lives on `queue`. That is what makes the `@unchecked Sendable`
/// true.
final class UpstreamPool: @unchecked Sendable {
    static let shared = UpstreamPool()

    /// Called with the answer, client ID restored, on the pool's queue.
    typealias Deliver = @Sendable ([UInt8]) -> Void

    /// Touched only on the pool's queue, like the pool itself.
    private final class Upstream: @unchecked Sendable {
        let connection: NWConnection
        var mux = QueryMultiplexer<Deliver>()
        var lastUsed = ContinuousClock.now

        init(connection: NWConnection) { self.connection = connection }
    }

    private let queue = DispatchQueue(label: "saferoom.upstream")
    private var upstreams: [NWEndpoint: Upstream] = [:]
    private var timer: DispatchSourceTimer?

    /// A Mac uses a handful of resolvers. The cap bounds sockets if a client
    /// sends to many addresses; the least recently used one is closed.
    static let maxUpstreams = 32
    /// A connection with nothing pending, unused this long, is closed.
    static let idleTimeout: Duration = .seconds(60)

    private init() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [self] in sweep() }
        timer.resume()
        self.timer = timer
    }

    func send(_ query: [UInt8], to endpoint: NWEndpoint, deliver: @escaping Deliver) {
        queue.async { [self] in
            let upstream = upstream(for: endpoint)
            guard let packet = upstream.mux.register(query, context: deliver) else {
                // Unreadable question, or 8,192 queries pending on this
                // resolver. Dropping it lets the client retry.
                Log.flow.error("upstream \(String(describing: endpoint), privacy: .public): query not sent (\(upstream.mux.count) pending)")
                return
            }
            upstream.lastUsed = .now
            upstream.connection.send(content: Data(packet), completion: .contentProcessed { error in
                if let error { Log.flow.error("udp send failed: \(error.localizedDescription, privacy: .public)") }
            })
        }
    }

    private func upstream(for endpoint: NWEndpoint) -> Upstream {
        if let existing = upstreams[endpoint] { return existing }
        if upstreams.count >= Self.maxUpstreams,
           let oldest = upstreams.min(by: { $0.value.lastUsed < $1.value.lastUsed })?.key {
            remove(oldest)
        }
        let connection = NWConnection(to: endpoint, using: .udp)
        let upstream = Upstream(connection: connection)
        connection.stateUpdateHandler = { [self] state in
            if case .failed(let error) = state {
                Log.flow.error("udp upstream \(String(describing: endpoint), privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                if upstreams[endpoint] === upstream { remove(endpoint) }
            }
        }
        upstreams[endpoint] = upstream
        connection.start(queue: queue)
        receive(upstream, from: endpoint)
        return upstream
    }

    private func receive(_ upstream: Upstream, from endpoint: NWEndpoint) {
        upstream.connection.receiveMessage { [self] data, _, _, error in
            if let data, !data.isEmpty, let (packet, deliver) = upstream.mux.resolve([UInt8](data)) {
                upstream.lastUsed = .now
                deliver(packet)
            }
            // An answer that matches nothing (late, duplicate, or forged) is
            // dropped silently.
            if error == nil, upstreams[endpoint] === upstream { receive(upstream, from: endpoint) }
        }
    }

    private func sweep() {
        let now = ContinuousClock.now
        for (endpoint, upstream) in upstreams {
            upstream.mux.expire(now: now)
            if upstream.mux.count == 0, now - upstream.lastUsed > Self.idleTimeout { remove(endpoint) }
        }
    }

    private func remove(_ endpoint: NWEndpoint) {
        guard let upstream = upstreams.removeValue(forKey: endpoint) else { return }
        upstream.mux.removeAll()
        upstream.connection.cancel()
    }
}
