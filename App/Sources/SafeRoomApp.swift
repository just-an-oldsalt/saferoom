import SwiftUI

@main
struct SafeRoomApp: App {
    @State private var activator = ExtensionActivator()

    var body: some Scene {
        WindowGroup {
            StatusView(activator: activator)
                .task { activator.activate() }
        }
        .windowResizability(.contentSize)
    }
}

struct StatusView: View {
    let activator: ExtensionActivator

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SafeRoom").font(.largeTitle.bold())
            Text(activator.state).font(.body.monospaced())
            Button("Activate extension") { activator.activate() }
        }
        .padding(24)
        .frame(minWidth: 380)
    }
}
