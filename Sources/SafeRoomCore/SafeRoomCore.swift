/// Shared names. Derived from the build's identity, so a build under another
/// organization needs no code change.
public enum SafeRoom {
    public static var logSubsystem: String { Identity.current.logSubsystem }
    public static var appGroup: String { Identity.current.appGroup }
}
