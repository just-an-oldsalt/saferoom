import Foundation
import NetworkExtension

// A system extension has no run loop of its own. This hands the process to
// NetworkExtension, which instantiates the provider class named in Info.plist.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
