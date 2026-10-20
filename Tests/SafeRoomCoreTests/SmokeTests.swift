import Testing
@testable import SafeRoomCore

@Test func identifiersAreStable() {
    #expect(SafeRoom.logSubsystem == "com.oldsalt.saferoom")
}
