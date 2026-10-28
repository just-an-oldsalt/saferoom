import Foundation

/// The policy a user sets in the app, on a Mac that no MDM manages.
///
/// The app writes it into the DNS proxy configuration, the same place where
/// an MDM profile puts its policy, so the extension reads both the same way.
/// Only the keys a person needs are here. Everything else keeps the
/// extension's defaults.
public struct UserSettings: Sendable, Equatable {
    public enum Source: String, Sendable, CaseIterable {
        /// The free cookbook list. Needs no token.
        case cookbook
        /// A list URL that the user enters.
        case custom
    }

    public static let cookbookListURL = "https://cookbook.oldsalt.zone/list.txt"
    public static let cookbookHashURL = "https://cookbook.oldsalt.zone/list.txt.sha256"
    /// The refresh intervals the app offers, in seconds.
    public static let refreshChoices = [300, 900, 3600, 21_600, 86_400]

    public var source: Source = .cookbook
    public var listURL = ""
    /// Optional. The URL of the list's SHA-256 file.
    public var hashURL = ""
    /// Optional. Sent as a bearer token to the list URL.
    public var token = ""
    public var refreshSeconds = 3600
    /// Domains that are never blocked, in the list format.
    public var allowList: [String] = []
    /// Optional. Block events go here (docs/mdm.md, "Block events").
    public var eventURL = ""
    public var eventToken = ""

    /// The cookbook list, checked every hour.
    public init() {}

    /// Reads back a configuration that the app wrote. Keys it does not
    /// show are dropped at the next save.
    public init(configuration config: [String: Any]) {
        let list = config["ListURL"] as? String ?? ""
        if list.isEmpty || list == Self.cookbookListURL {
            source = .cookbook
        } else {
            source = .custom
            listURL = list
            hashURL = config["ListSHA256URL"] as? String ?? ""
            token = Self.bearerToken(config["Auth"])
        }
        if let seconds = ProviderPolicy.int(config["RefreshSeconds"]) { refreshSeconds = seconds }
        allowList = config["AllowList"] as? [String] ?? []
        eventURL = config["EventURL"] as? String ?? ""
        eventToken = Self.bearerToken(config["EventAuth"])
    }

    /// The `ProviderConfiguration` dictionary, marked as written by the app.
    public var configuration: [String: Any] {
        var config: [String: Any] = [
            ProviderPolicy.configuredByKey: ProviderPolicy.configuredByApp,
            "RefreshSeconds": refreshSeconds,
        ]
        switch source {
        case .cookbook:
            config["ListURL"] = Self.cookbookListURL
            config["ListSHA256URL"] = Self.cookbookHashURL
        case .custom:
            if !trimmed(listURL).isEmpty { config["ListURL"] = trimmed(listURL) }
            if !trimmed(hashURL).isEmpty { config["ListSHA256URL"] = trimmed(hashURL) }
            if !trimmed(token).isEmpty { config["Auth"] = ["Type": "bearer", "Token": trimmed(token)] }
        }
        let allow = allowList.map(trimmed).filter { !$0.isEmpty }
        if !allow.isEmpty { config["AllowList"] = allow }
        if !trimmed(eventURL).isEmpty {
            config["EventURL"] = trimmed(eventURL)
            if !trimmed(eventToken).isEmpty { config["EventAuth"] = ["Type": "bearer", "Token": trimmed(eventToken)] }
        }
        return config
    }

    /// What is wrong with the settings, in words for the user. Empty when
    /// they can be saved. The checks are the extension's own, so the app
    /// never saves a value that the extension would ignore.
    public var problems: [String] {
        var out: [String] = []
        if source == .custom, trimmed(listURL).isEmpty { out.append("Enter the address of your list.") }
        let policy = ProviderPolicy(configuration)
        for problem in policy.ignored {
            if problem.hasPrefix("ListURL") {
                out.append("The list address must start with https://.")
            } else if problem.hasPrefix("ListSHA256URL") {
                out.append("The hash file address must start with https://.")
            } else if problem.hasPrefix("EventURL") {
                out.append("The event address must start with https://.")
            } else if problem.hasPrefix("AllowList entry") {
                // `AllowList entry "x": reason`
                out.append("Allow list: \(problem.dropFirst("AllowList entry ".count))")
            } else {
                out.append(problem)
            }
        }
        return out
    }

    /// Splits text that the user typed (one domain per line, or separated
    /// by commas or spaces) into allow list entries.
    public static func parseAllowList(_ text: String) -> [String] {
        text.split { $0.isNewline || $0 == "," || $0 == " " || $0 == "\t" }.map(String.init)
    }

    private static func bearerToken(_ value: Any?) -> String {
        guard let dict = value as? [String: Any], (dict["Type"] as? String)?.lowercased() == "bearer" else { return "" }
        return dict["Token"] as? String ?? ""
    }

    private func trimmed(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// Whether the app may change the policy. Fail-closed: anything the app
/// cannot positively tell is unmanaged counts as managed, and a managed Mac
/// keeps the read-only window.
public enum ConfigurationAccess: Sendable, Equatable {
    /// No DNS proxy configuration exists. The user can set one up.
    case firstRun
    /// The app wrote the configuration. The user can change it.
    case user(enabled: Bool)
    /// An MDM profile, or something the app cannot identify, set it.
    case managed

    /// What the app's `NEDNSProxyManager` reported.
    public enum Manager: Sendable, Equatable {
        /// Not loaded yet, or the load failed.
        case unknown
        case none
        case configured(byApp: Bool, enabled: Bool)
    }

    /// - Parameters:
    ///   - manager: the app's own view of the configuration.
    ///   - running: the policy the extension reports, if it answers. It is
    ///     the policy really in force, so a running policy without the
    ///     app's marker makes the Mac managed whatever the manager says.
    public static func decide(manager: Manager, running: ExtensionStatus.PolicySummary?) -> ConfigurationAccess {
        if let running, running.configuredBy != ProviderPolicy.configuredByApp { return .managed }
        switch manager {
        case .unknown:
            return .managed
        case .none:
            return running == nil ? .firstRun : .managed
        case .configured(let byApp, let enabled):
            return byApp ? .user(enabled: enabled) : .managed
        }
    }

    public var canEdit: Bool { self != .managed }
}
