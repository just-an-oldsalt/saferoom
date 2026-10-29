import Foundation
import Testing
@testable import SafeRoomCore

@Test func defaultIsCookbook() {
    let config = UserSettings().configuration
    #expect(config["ListURL"] as? String == UserSettings.cookbookListURL)
    #expect(config["ListSHA256URL"] as? String == UserSettings.cookbookHashURL)
    #expect(config["Auth"] == nil)
    let policy = ProviderPolicy(config)
    #expect(policy.configuredByApp)
    #expect(policy.ignored.isEmpty)
    #expect(policy.refreshInterval == .seconds(3600))
    #expect(UserSettings().problems.isEmpty)
}

@Test func customRoundTrip() {
    var s = UserSettings()
    s.source = .custom
    s.listURL = " https://lists.example.com/list.txt "
    s.hashURL = "https://lists.example.com/list.txt.sha256"
    s.token = "abc"
    s.refreshSeconds = 900
    s.allowList = UserSettings.parseAllowList("partner.com\n=exact.org, other.net")
    s.eventURL = "https://events.example.com/e"
    s.eventToken = "def"
    let policy = ProviderPolicy(s.configuration)
    #expect(policy.listURL?.absoluteString == "https://lists.example.com/list.txt")
    #expect(policy.auth == .bearer(token: "abc"))
    #expect(policy.eventAuth == .bearer(token: "def"))
    #expect(policy.allowList.count == 3)
    #expect(policy.ignored.isEmpty)

    let back = UserSettings(configuration: s.configuration)
    #expect(back.source == .custom)
    #expect(back.listURL == "https://lists.example.com/list.txt")
    #expect(back.token == "abc")
    #expect(back.refreshSeconds == 900)
    #expect(back.allowList == ["partner.com", "=exact.org", "other.net"])
    #expect(back.eventToken == "def")
}

@Test func cookbookIgnoresCustomFields() {
    var s = UserSettings()
    s.listURL = "https://lists.example.com/list.txt"
    s.token = "abc"
    let config = s.configuration
    #expect(config["ListURL"] as? String == UserSettings.cookbookListURL)
    #expect(config["Auth"] == nil)
    #expect(UserSettings(configuration: config).source == .cookbook)
}

@Test func problemsInPlainWords() {
    var s = UserSettings()
    s.source = .custom
    #expect(s.problems == ["Enter the address of your list."])
    s.listURL = "http://lists.example.com/list.txt"
    #expect(s.problems == ["The list address must start with https://."])
    s.listURL = "https://lists.example.com/list.txt"
    s.allowList = ["bad..name"]
    #expect(s.problems.count == 1)
    #expect(s.problems[0].hasPrefix("Allow list: \"bad..name\""))
}

private func running(byApp: Bool) -> ExtensionStatus.PolicySummary {
    var config = UserSettings().configuration
    if !byApp { config[ProviderPolicy.configuredByKey] = nil }
    return .init(ProviderPolicy(config))
}

@Test func accessIsFailClosed() {
    typealias A = ConfigurationAccess
    #expect(A.decide(manager: .none, running: nil) == .firstRun)
    #expect(A.decide(manager: .configured(byApp: true, enabled: true), running: nil) == .user(enabled: true))
    #expect(A.decide(manager: .configured(byApp: true, enabled: false), running: nil) == .user(enabled: false))
    #expect(A.decide(manager: .configured(byApp: true, enabled: true), running: running(byApp: true)) == .user(enabled: true))
    // An MDM profile, as the manager or the extension reports it.
    #expect(A.decide(manager: .configured(byApp: false, enabled: true), running: nil) == .managed)
    #expect(A.decide(manager: .configured(byApp: true, enabled: true), running: running(byApp: false)) == .managed)
    #expect(A.decide(manager: .none, running: running(byApp: false)) == .managed)
    #expect(A.decide(manager: .none, running: running(byApp: true)) == .managed)
    #expect(A.decide(manager: .unknown, running: nil) == .managed)
    #expect(A.decide(manager: .unknown, running: running(byApp: true)) == .managed)
}

@Test func statusReportsWhoConfigured() {
    #expect(running(byApp: true).configuredBy == "app")
    #expect(running(byApp: false).configuredBy == nil)
}

@Test func emptyProtocolThatIsOffIsNoConfiguration() {
    typealias M = ConfigurationAccess.Manager
    // What loadFromPreferences leaves with nothing saved.
    #expect(M(hasProtocol: false, configuration: nil, enabled: false) == .none)
    #expect(M(hasProtocol: true, configuration: nil, enabled: false) == .none)
    #expect(M(hasProtocol: true, configuration: [:], enabled: false) == .none)
    // Turned on, or with content: a real configuration.
    #expect(M(hasProtocol: true, configuration: nil, enabled: true) == .configured(byApp: false, enabled: true))
    #expect(M(hasProtocol: true, configuration: ["ListURL": "https://a.test/l"], enabled: false)
        == .configured(byApp: false, enabled: false))
    #expect(M(hasProtocol: true, configuration: UserSettings().configuration, enabled: false)
        == .configured(byApp: true, enabled: false))
    #expect(M.none.writable && M.configured(byApp: true, enabled: true).writable)
    #expect(!M.unknown.writable && !M.configured(byApp: false, enabled: false).writable)
}
