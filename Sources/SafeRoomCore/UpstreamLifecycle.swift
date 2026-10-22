/// When the shared upstream UDP connections must be replaced.
///
/// A UDP connection picks its interface once, when it starts. If it starts
/// while a VPN is reconnecting, before the VPN client installs its route, it
/// stays on the physical interface and keeps asking the resolver over the
/// wrong path. So the pool drops every connection when the network path
/// changes, and replaces any connection older than `maxAge` in case the
/// route arrived after the last path change.
///
/// Pure rules, so they are tested without a network. The extension feeds
/// them values read from `NWPath` and `NWConnection`.
public enum UpstreamLifecycle {
    /// After this, new queries go to a new connection. The old one stays
    /// open until its pending queries are answered or time out.
    public static let maxAge: Duration = .seconds(30)

    /// The parts of a network path that decide which way packets go.
    public struct PathFingerprint: Equatable, Sendable, CustomStringConvertible {
        public var status: String
        /// Interface names in the system's order of preference.
        public var interfaces: [String]
        public var gateways: [String]

        public init(status: String, interfaces: [String], gateways: [String]) {
            self.status = status
            self.interfaces = interfaces
            self.gateways = gateways
        }

        /// For the log: interface names and counts, no addresses.
        public var description: String {
            "\(status), interfaces \(interfaces.joined(separator: ",")), \(gateways.count) gateways"
        }
    }

    /// Why the pool must drop every connection, or nil to keep them. The
    /// path monitor reports the current path once when it starts: that
    /// first report (`previous` nil) is not a change.
    public static func resetReason(previous: PathFingerprint?, current: PathFingerprint) -> String? {
        guard let previous, previous != current else { return nil }
        if previous.status != current.status { return "path status \(previous.status) -> \(current.status)" }
        if previous.interfaces != current.interfaces { return "interfaces changed" }
        return "gateways changed"
    }

    public enum Action: Equatable, Sendable {
        /// Keep using the connection.
        case keep
        /// Send new queries on a new connection. Let this one finish.
        case retire
        /// Close it now. Pending queries are dropped and clients retry.
        case close
    }

    /// What to do with one connection, from what the system reports about it.
    public static func action(age: Duration, viable: Bool, betterPathAvailable: Bool, waiting: Bool) -> Action {
        if !viable || waiting { return .close }
        if betterPathAvailable || age >= maxAge { return .retire }
        return .keep
    }
}
