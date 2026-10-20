import Foundation
import Security

/// Who this build is: the signing team and the app's bundle ID. Every other
/// name (app group, XPC service, signature requirements, log subsystem) is
/// derived from these two, so a build under another organization changes
/// only Config/Identity.xcconfig and nothing in the code.
public struct Identity: Sendable, Equatable {
    public let teamID: String
    public let appID: String

    public init(teamID: String, appID: String) {
        self.teamID = teamID
        self.appID = appID
    }

    public var extensionID: String { appID + ".dnsproxy" }
    public var appGroup: String { "\(teamID).\(appID)" }
    /// The extension's NEMachServiceName. A sandboxed app may look up a Mach
    /// service only when its name starts with one of the app's groups.
    public var machServiceName: String { "\(teamID).\(extensionID)" }
    public var logSubsystem: String { appID }

    /// A Developer ID certificate (the two field checks are Apple's markers
    /// for it), this team, and one exact bundle ID. A development build, or
    /// another app of the same team, does not match.
    public func requirement(for identifier: String) -> String {
        #"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"#
            + #" and certificate leaf[subject.OU] = "\#(teamID)" and identifier "\#(identifier)""#
    }
    public var appRequirement: String { requirement(for: appID) }
    public var extensionRequirement: String { requirement(for: extensionID) }

    /// The identity of the running app or extension, read from its own code
    /// signature and bundle ID. The extension's bundle ID is the app's plus
    /// ".dnsproxy".
    public static let current: Identity = {
        let bundleID = Bundle.main.bundleIdentifier ?? "unknown"
        let appID = bundleID.hasSuffix(".dnsproxy") ? String(bundleID.dropLast(".dnsproxy".count)) : bundleID
        return Identity(teamID: runningTeamID() ?? "UNSIGNED", appID: appID)
    }()

    static func runningTeamID() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
        else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
