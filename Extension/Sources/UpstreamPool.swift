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
/// A UDP connection keeps the interface it started on. `UpstreamLifecycle`
/// decides when to replace connections: on any network path change, when
/// the system reports a connection not viable or a better path, and at a
/// maximum age. Without this, a connection opened while a VPN reconnects
/// stays on the wrong interface.
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
        let endpoint: NWEndpoint
        var mux = QueryMultiplexer<Deliver>()
        let createdAt = ContinuousClock.now
        var lastUsed = ContinuousClock.now
        var viable = true
        var betterPathAvailable = false
        var waiting = false
        var closed = false

        init(connection: NWConnection, endpoint: NWEndpoint) {
            self.connection = connection
            self.endpoint = endpoint
        }

        var action: UpstreamLifecycle.Action {
            UpstreamLifecycle.action(
                age: .now - createdAt, viable: viable, betterPathAvailable: betterPathAvailable, waiting: waiting)
        }
    }

    private let queue = DispatchQueue(label: "saferoom.upstream")
    /// The connection that new queries to each resolver use.
    private var upstreams: [NWEndpoint: Upstream] = [:]
    /// Replaced connections that still wait for answers to their queries.
    private var retiring: [Upstream] = []
    private var timer: DispatchSourceTimer?
    private let pathMonitor = NWPathMonitor()
    private var lastPath: UpstreamLifecycle.PathFingerprint?

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

        pathMonitor.pathUpdateHandler = { [self] path in pathChanged(path) }
        pathMonitor.start(queue: queue)
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

    // MARK: - Connections

    private func upstream(for endpoint: NWEndpoint) -> Upstream {
        if let existing = upstreams[endpoint] {
            switch existing.action {
            case .keep: return existing
            case .retire: retire(existing)
            case .close: close(existing)
            }
        }
        if upstreams.count >= Self.maxUpstreams,
           let oldest = upstreams.values.min(by: { $0.lastUsed < $1.lastUsed }) {
            close(oldest)
        }
        let connection = NWConnection(to: endpoint, using: .udp)
        let upstream = Upstream(connection: connection, endpoint: endpoint)
        // Every handler runs on `queue`, and checks `closed`: a late callback
        // from a replaced connection must not touch its successor.
        connection.stateUpdateHandler = { [self] state in
            guard !upstream.closed else { return }
            switch state {
            case .failed(let error):
                Log.flow.error("udp upstream \(String(describing: endpoint), privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                close(upstream)
            case .waiting(let error):
                Log.flow.error("udp upstream \(String(describing: endpoint), privacy: .public) waiting: \(error.localizedDescription, privacy: .public)")
                upstream.waiting = true
                close(upstream)
            default:
                break
            }
        }
        connection.viabilityUpdateHandler = { [self] viable in
            guard !upstream.closed else { return }
            upstream.viable = viable
            if !viable { close(upstream) }
        }
        connection.betterPathUpdateHandler = { [self] better in
            guard !upstream.closed else { return }
            upstream.betterPathAvailable = better
            if better, upstreams[endpoint] === upstream { retire(upstream) }
        }
        upstreams[endpoint] = upstream
        connection.start(queue: queue)
        receive(upstream)
        return upstream
    }

    private func receive(_ upstream: Upstream) {
        upstream.connection.receiveMessage { [self] data, _, _, error in
            if let data, !data.isEmpty, let (packet, deliver) = upstream.mux.resolve([UInt8](data)) {
                upstream.lastUsed = .now
                deliver(packet)
            }
            // An answer that matches nothing (late, duplicate, or forged) is
            // dropped silently. A retiring connection keeps receiving until
            // it closes.
            if error == nil, !upstream.closed { receive(upstream) }
        }
    }

    /// New queries go to a new connection. This one stays open for the
    /// answers it still waits for, and `sweep` closes it.
    private func retire(_ upstream: Upstream) {
        if upstreams[upstream.endpoint] === upstream { upstreams[upstream.endpoint] = nil }
        if upstream.mux.count == 0 {
            close(upstream)
        } else {
            retiring.append(upstream)
        }
    }

    /// Closes now. Pending queries are dropped, and their clients retry.
    private func close(_ upstream: Upstream) {
        guard !upstream.closed else { return }
        upstream.closed = true
        if upstreams[upstream.endpoint] === upstream { upstreams[upstream.endpoint] = nil }
        retiring.removeAll { $0 === upstream }
        upstream.mux.removeAll()
        upstream.connection.cancel()
    }

    // MARK: - Network changes and housekeeping

    private func pathChanged(_ path: NWPath) {
        let current = UpstreamLifecycle.PathFingerprint(
            status: String(describing: path.status),
            interfaces: path.availableInterfaces.map(\.name),
            gateways: path.gateways.map { String(describing: $0) })
        defer { lastPath = current }
        guard let reason = UpstreamLifecycle.resetReason(previous: lastPath, current: current) else { return }
        let count = upstreams.count + retiring.count
        for upstream in Array(upstreams.values) + retiring { close(upstream) }
        Log.flow.notice("upstream pool reset: \(reason, privacy: .public) (\(current.description, privacy: .public)); closed \(count) connections")
    }

    private func sweep() {
        let now = ContinuousClock.now
        for upstream in Array(upstreams.values) {
            upstream.mux.expire(now: now)
            if upstream.mux.count == 0, now - upstream.lastUsed > Self.idleTimeout {
                close(upstream)
                continue
            }
            // Old or on a worse path, even if nobody sent a query since.
            switch upstream.action {
            case .keep: break
            case .retire: retire(upstream)
            case .close: close(upstream)
            }
        }
        for upstream in retiring {
            upstream.mux.expire(now: now)
            if upstream.mux.count == 0 { close(upstream) }
        }
    }
}
