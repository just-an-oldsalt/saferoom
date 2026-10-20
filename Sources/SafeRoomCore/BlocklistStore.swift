import Synchronization

/// The live list. Every flow reads it per packet; a reload replaces it whole.
///
/// The lock is held only to copy or replace a struct whose arrays are
/// reference-counted, so a reader never waits on a compile and never sees a
/// half-built list.
public final class BlocklistStore: Sendable {
    private let state = Mutex(Blocklist.empty)

    public init() {}

    public var current: Blocklist { state.withLock { $0 } }

    public func replace(_ blocklist: Blocklist) {
        state.withLock { $0 = blocklist }
    }
}
