import Testing
@testable import SafeRoomCore

@Test func identityDerivesEveryName() {
    let id = Identity(teamID: "ABCDE12345", appID: "com.example.saferoom")
    #expect(id.extensionID == "com.example.saferoom.dnsproxy")
    #expect(id.appGroup == "ABCDE12345.com.example.saferoom")
    #expect(id.machServiceName == "ABCDE12345.com.example.saferoom.dnsproxy")
    #expect(id.logSubsystem == "com.example.saferoom")
    #expect(id.appRequirement.hasSuffix(#"leaf[subject.OU] = "ABCDE12345" and identifier "com.example.saferoom""#))
    #expect(id.extensionRequirement.contains(#"identifier "com.example.saferoom.dnsproxy""#))
    #expect(id.appRequirement.contains("1.2.840.113635.100.6.1.13")) // Developer ID only
}
