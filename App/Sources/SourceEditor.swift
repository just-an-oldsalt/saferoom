import SafeRoomCore
import SwiftUI

/// Shown on a Mac with no MDM while protection is not on: the first run, or
/// after the user turned it off.
struct SetupSection: View {
    let firstRun: Bool
    let busy: Bool
    let problem: String?
    let turnOn: () -> Void
    let edit: () -> Void

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Label(firstRun ? "Choose a threat list" : "Protection is off",
                      systemImage: firstRun ? "list.bullet.rectangle.portrait" : "shield.slash")
                    .font(.headline)
                Text(firstRun
                     ? "SafeRoom blocks lookups for the domains on a threat list. The free cookbook list needs no account. You can change the list at any time."
                     : "SafeRoom does not check lookups now. Turn protection on to block the domains on your list again.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button(action: turnOn) {
                        if busy {
                            ProgressView().controlSize(.small).padding(.horizontal, 40)
                        } else {
                            Text(firstRun ? "Use the free cookbook list" : "Turn on protection")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    Button(firstRun ? "Choose another list…" : "Change list…", action: edit)
                }
                .disabled(busy)
                if let problem {
                    Text(problem).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                }
                if firstRun {
                    Text("macOS asks you to allow SafeRoom to add a proxy configuration. Click Allow.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
        }
    }
}

/// The sheet where the user picks the list and its options.
struct SourceEditor: View {
    let proxy: ProxyConfigurator
    let done: () -> Void
    @State private var settings: UserSettings
    @State private var allowText: String
    @State private var problem: String?

    init(initial: UserSettings, proxy: ProxyConfigurator, done: @escaping () -> Void) {
        self.proxy = proxy
        self.done = done
        _settings = State(initialValue: initial)
        _allowText = State(initialValue: initial.allowList.joined(separator: "\n"))
    }

    private var edited: UserSettings {
        var s = settings
        s.allowList = UserSettings.parseAllowList(allowText)
        return s
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("List", selection: $settings.source) {
                        Text("Free cookbook list").tag(UserSettings.Source.cookbook)
                        Text("My own list").tag(UserSettings.Source.custom)
                    }
                    .pickerStyle(.radioGroup)
                    if settings.source == .cookbook {
                        Text("Open threat intelligence feeds, merged into one list of about 235,000 domains. It comes with no warranty.")
                            .font(.caption).foregroundStyle(.secondary)
                        Link("Sources and licenses", destination: URL(string: "https://cookbook.oldsalt.zone/attribution.txt")!)
                            .font(.caption)
                    } else {
                        TextField("List address", text: $settings.listURL, prompt: Text("Required, starts with https://"))
                        TextField("Hash file address", text: $settings.hashURL, prompt: Text("Optional"))
                        SecureField("Bearer token", text: $settings.token, prompt: Text("Optional"))
                    }
                } header: {
                    Text("Threat list")
                }

                Section {
                    Picker("Check for updates", selection: $settings.refreshSeconds) {
                        ForEach(refreshChoices, id: \.self) { seconds in
                            Text(Self.refreshLabel(seconds)).tag(seconds)
                        }
                    }
                }

                Section {
                    TextEditor(text: $allowText)
                        .font(.callout.monospaced())
                        .frame(minHeight: 70)
                } header: {
                    Text("Never block")
                } footer: {
                    Text("One domain per line. Use this when the list blocks a site that you need.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section {
                    DisclosureGroup("Advanced: report blocks to a server") {
                        TextField("Event address", text: $settings.eventURL, prompt: Text("Starts with https://"))
                        SecureField("Event token", text: $settings.eventToken, prompt: Text("Optional"))
                        Text("SafeRoom sends each blocked lookup to this address: the name, the app that asked, and this Mac's name and serial number.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                let problems = edited.problems
                if !problems.isEmpty || problem != nil {
                    Section {
                        ForEach(problems, id: \.self) { Text($0).foregroundStyle(.red) }
                        if let problem { Text(problem).foregroundStyle(.red).textSelection(.enabled) }
                    }
                }
                if !settings.token.isEmpty || !settings.eventToken.isEmpty {
                    Text("Every user of this Mac can read a token saved here. Use a token that can do nothing else.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: done)
                    .keyboardShortcut(.cancelAction)
                Button {
                    save()
                } label: {
                    if proxy.saving {
                        ProgressView().controlSize(.small).padding(.horizontal, 30)
                    } else {
                        Text("Save and turn on")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(proxy.saving || !edited.problems.isEmpty)
            }
            .controlSize(.large)
            .padding(16)
        }
        .frame(width: 520, height: 620)
    }

    /// The offered intervals, plus the current one if a hand-edited
    /// configuration holds another.
    private var refreshChoices: [Int] {
        let choices = UserSettings.refreshChoices
        return choices.contains(settings.refreshSeconds) ? choices : (choices + [settings.refreshSeconds]).sorted()
    }

    static func refreshLabel(_ seconds: Int) -> String {
        switch seconds {
        case 3600: "Every hour"
        case 86_400: "Every day"
        default: "Every " + Duration.seconds(seconds).formatted(.units(allowed: [.days, .hours, .minutes], width: .wide))
        }
    }

    private func save() {
        let settings = edited
        Task {
            problem = await proxy.save(settings, enabled: true)
            if problem == nil { done() }
        }
    }
}
