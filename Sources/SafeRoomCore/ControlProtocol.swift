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

    /// Each end checks the other's code signature: a Developer ID
    /// certificate (the two field checks are Apple's Developer ID markers),
    /// our team, and the exact bundle identifier. Without it any local
    /// process could read the status or trigger downloads. With the team
    /// alone, any other app of the team could, and so could a development
    /// build, which can be signed by any team member's own certificate.
    static let developerID =
        #"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "346JJCHZP7""#
    public static let appRequirement = developerID + #" and identifier "com.oldsalt.saferoom""#
    public static let extensionRequirement = developerID + #" and identifier "com.oldsalt.saferoom.dnsproxy""#
}
