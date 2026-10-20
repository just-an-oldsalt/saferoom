import SwiftUI

@main
struct SafeRoomApp: App {
    @State private var activator = ExtensionActivator()
    @State private var proxy = ProxyConfigurator()

    var body: some Scene {
        WindowGroup {
            StatusView(activator: activator, proxy: proxy)
                .task {
                    activator.activate()
                    proxy.applyTestPolicy()
                    proxy.refresh()
                }
        }
        .windowResizability(.contentSize)
    }
}

struct StatusView: View {
    let activator: ExtensionActivator
    let proxy: ProxyConfigurator

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SafeRoom").font(.largeTitle.bold())
            LabeledContent("Extension", value: activator.state)
            LabeledContent("DNS proxy", value: proxy.state)
            HStack {
                Button("Activate extension") { activator.activate() }
                Button("Enable DNS proxy") { proxy.setEnabled(true) }
                Button("Disable") { proxy.setEnabled(false) }
            }
            Text("Under MDM, the profile enables the proxy. These buttons are for testing.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(minWidth: 380)
    }
}
