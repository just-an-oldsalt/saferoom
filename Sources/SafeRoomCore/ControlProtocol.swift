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

/// The XPC channel's names and signature checks, for the running build.
/// See `Identity` for how each is derived.
public enum ControlChannel {
    public static var machServiceName: String { Identity.current.machServiceName }
    public static var appRequirement: String { Identity.current.appRequirement }
    public static var extensionRequirement: String { Identity.current.extensionRequirement }

    /// The extension answers, but no proxy runs. Under MDM, the usual cause
    /// is a payload that macOS refuses, and only `nesessionmanager` logs why.
    public static let proxyNotStarted = """
        The extension is running, but the DNS proxy is not started. If MDM installs SafeRoom, \
        make sure that the DNS Proxy payload has ProviderDesignatedRequirement \
        (docs/mdm.md, "Deploy with Jamf Pro").
        """
}
