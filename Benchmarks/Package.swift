// swift-tools-version: 6.0
// The scale benchmark behind docs/performance.md. Run it with `make bench`.
import PackageDescription
let package = Package(
    name: "bench", platforms: [.macOS(.v15)],
    dependencies: [.package(name: "SafeRoom", path: "..")],
    targets: [.executableTarget(name: "bench", dependencies: [.product(name: "SafeRoomCore", package: "SafeRoom")],
                                swiftSettings: [.swiftLanguageMode(.v5)])]
)
