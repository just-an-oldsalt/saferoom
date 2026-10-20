/// Every decision the proxy makes, in one place and without NetworkExtension,
/// so all of it is unit-tested. The provider only moves bytes.
extension Blocklist {
    public enum QueryDecision: Sendable, Equatable {
        /// Send the packet upstream unchanged.
        case forward
        /// Answer the client with `reply` and do not send anything upstream.
        case block(reply: [UInt8], name: String, type: UInt16, rule: String)
    }

    public enum ResponseDecision: Sendable, Equatable {
        /// Return the upstream response to the client unchanged.
        case pass
        /// Return `reply` (NXDOMAIN) to the client instead.
        case block(reply: [UInt8], name: String, reason: Reason)
    }

    public enum Reason: Sendable, Equatable {
        /// A CNAME or SVCB target is on the domain list.
        case alias(target: String, rule: String)
        /// An A, AAAA or SVCB hint address is in a listed range.
        case address(IPAddress)
    }

    /// Called for each query from a client. Every record type is blocked for a
    /// listed name, including HTTPS (65), so a browser cannot learn an
    /// address for it by asking a different way.
    public func decide(query packet: [UInt8]) -> QueryDecision {
        guard let q = DNSMessage.question(packet), !q.isResponse,
              case .blocked(let rule) = verdict(normalized: q.name),
              let reply = DNSMessage.nxdomain(replyingTo: packet)
        else { return .forward }
        return .block(reply: reply, name: q.nameString, type: q.type, rule: rule)
    }

    /// Called for each upstream response before it goes back to the client.
    ///
    /// An allowlisted query name passes without any check. The allowlist is
    /// how an admin fixes a false positive, and the likeliest false positive
    /// is a CDN or shared-hosting range in a feed. Without this, a listed
    /// Akamai range would break apple.com despite the never-block set.
    public func decide(response packet: [UInt8]) -> ResponseDecision {
        guard let q = DNSMessage.question(packet) else { return .pass }
        if case .allowed = verdict(normalized: q.name) { return .pass }
        guard let answer = DNSMessage.answer(packet) else { return .pass }

        var reason: Reason?
        for target in answer.names {
            if case .blocked(let rule) = verdict(normalized: target) {
                reason = .alias(target: String(decoding: target, as: UTF8.self), rule: rule)
                break
            }
        }
        if reason == nil, let address = answer.addresses.first(where: isBlocked) {
            reason = .address(address)
        }
        guard let reason, let reply = DNSMessage.nxdomain(replyingTo: packet) else { return .pass }
        return .block(reply: reply, name: q.nameString, reason: reason)
    }
}
