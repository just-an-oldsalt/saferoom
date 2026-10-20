import os
import SafeRoomCore

/// Unified-log categories. Block events are the SOC signal, so their fields are
/// `.public`: without that, the unified log redacts them as <private> and a
/// SIEM collecting the log sees nothing useful.
///
///     log stream --predicate 'subsystem == "<app bundle ID>"'
enum Log {
    static let provider = Logger(subsystem: SafeRoom.logSubsystem, category: "provider")
    static let list = Logger(subsystem: SafeRoom.logSubsystem, category: "list")
    static let flow = Logger(subsystem: SafeRoom.logSubsystem, category: "flow")
    static let block = Logger(subsystem: SafeRoom.logSubsystem, category: "block")

    /// Text from the network or a list, made safe for a log line. A name
    /// with a newline in it could otherwise forge a second "blocked" line
    /// for a line-based SIEM. Bytes outside printable ASCII become \xNN.
    static func clean(_ text: String) -> String {
        var out = ""
        for byte in text.utf8.prefix(300) {
            if byte >= 0x20, byte < 0x7F, byte != UInt8(ascii: "\\") {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
                out += String(format: "\\x%02x", byte)
            }
        }
        return out
    }

    static func blockedQuery(name: String, type: UInt16, rule: String, app: String, transport: String) {
        // The app ID too: an ad-hoc signed program chooses its own.
        let name = clean(name), rule = clean(rule), app = clean(app)
        block.notice(
            "blocked query name=\(name, privacy: .public) type=\(type, privacy: .public) rule=\(rule, privacy: .public) app=\(app, privacy: .public) via=\(transport, privacy: .public)")
    }

    static func blockedResponse(name: String, reason: DNSFilter.Reason, app: String, transport: String) {
        let name = clean(name), app = clean(app)
        let detail: String
        switch reason {
        case .alias(let target, let rule): detail = "alias=\(clean(target)) rule=\(clean(rule))"
        case .address(let address): detail = "address=\(address.description)"
        }
        block.notice(
            "blocked answer name=\(name, privacy: .public) \(detail, privacy: .public) app=\(app, privacy: .public) via=\(transport, privacy: .public)")
    }
}
