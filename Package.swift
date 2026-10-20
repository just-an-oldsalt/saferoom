// swift-tools-version: 6.0
//
// SafeRoomCore is every part of SafeRoom that does not need NetworkExtension:
// the list parser, the compiled matcher, the DNS wire codec and the policy
// model. Keeping it in a plain package means `swift test` runs it on any Mac,
// with no signing identity and no system extension installed.
import PackageDescription

let package = Package(
    name: "SafeRoom",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "SafeRoomCore", targets: ["SafeRoomCore"]),
    ],
    targets: [
        .target(name: "SafeRoomCore"),
        .testTarget(name: "SafeRoomCoreTests", dependencies: ["SafeRoomCore"]),
    ]
)
