import Foundation

/// The XPC interface the extension offers to the app and its command line.
///
/// Replies carry `ExtensionStatus` as JSON `Data`, so the interface stays a
/// plain Objective-C protocol and the status format can grow without
/// touching it.
@objc public protocol SafeRoomControl {
    func status(reply: @escaping (Data) -> Void)
    /// Downloads or reads the list now, then replies with the new status.
    func refreshNow(reply: @escaping (Data) -> Void)
}

public enum ControlChannel {
    /// The extension's `NEMachServiceName`. A sandboxed app may look up a
    /// Mach service only when its name starts with one of the app's groups,
    /// which is why it starts with the app group.
    public static let machServiceName = "346JJCHZP7.com.oldsalt.saferoom.dnsproxy"

    /// Both ends must be signed by this team. Without the check, any local
    /// process could read the status or trigger downloads.
    public static let teamRequirement =
        #"anchor apple generic and certificate leaf[subject.OU] = "346JJCHZP7""#
}
