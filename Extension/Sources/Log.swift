import os
import SafeRoomCore

/// Unified-log categories. Block events are the SOC signal, so their fields are
/// `.public`: without that, the unified log redacts them as <private> and a
/// SIEM collecting the log sees nothing useful.
///
///     log stream --predicate 'subsystem == "com.oldsalt.saferoom"'
enum Log {
    static let provider = Logger(subsystem: SafeRoom.logSubsystem, category: "provider")
    static let list = Logger(subsystem: SafeRoom.logSubsystem, category: "list")
    static let flow = Logger(subsystem: SafeRoom.logSubsystem, category: "flow")
    static let block = Logger(subsystem: SafeRoom.logSubsystem, category: "block")

    static func blockedQuery(name: String, type: UInt16, rule: String, app: String, transport: String) {
        block.notice(
            "blocked query name=\(name, privacy: .public) type=\(type, privacy: .public) rule=\(rule, privacy: .public) app=\(app, privacy: .public) via=\(transport, privacy: .public)")
    }

    static func blockedResponse(name: String, reason: DNSFilter.Reason, app: String, transport: String) {
        let detail: String
        switch reason {
        case .alias(let target, let rule): detail = "alias=\(target) rule=\(rule)"
        case .address(let address): detail = "address=\(address.description)"
        }
        block.notice(
            "blocked answer name=\(name, privacy: .public) \(detail, privacy: .public) app=\(app, privacy: .public) via=\(transport, privacy: .public)")
    }
}
