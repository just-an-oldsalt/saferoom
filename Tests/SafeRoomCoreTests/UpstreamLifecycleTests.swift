import Testing
@testable import SafeRoomCore

private typealias L = UpstreamLifecycle
private let wifi = L.PathFingerprint(status: "satisfied", interfaces: ["en0"], gateways: ["192.0.2.1"])

@Test func firstPathReportIsNotAChange() {
    #expect(L.resetReason(previous: nil, current: wifi) == nil)
}

@Test func samePathDoesNotReset() {
    #expect(L.resetReason(previous: wifi, current: wifi) == nil)
}

@Test func vpnTunnelAppearingResets() {
    var vpn = wifi
    vpn.interfaces = ["utun4", "en0"]
    #expect(L.resetReason(previous: wifi, current: vpn) == "interfaces changed")
    #expect(L.resetReason(previous: vpn, current: wifi) == "interfaces changed")
}

@Test func interfaceOrderChangeResets() {
    let a = L.PathFingerprint(status: "satisfied", interfaces: ["en0", "utun4"], gateways: [])
    let b = L.PathFingerprint(status: "satisfied", interfaces: ["utun4", "en0"], gateways: [])
    #expect(L.resetReason(previous: a, current: b) != nil)
}

@Test func statusAndGatewayChangesReset() {
    var down = wifi
    down.status = "unsatisfied"
    #expect(L.resetReason(previous: wifi, current: down) == "path status satisfied -> unsatisfied")
    var moved = wifi
    moved.gateways = ["198.51.100.1"]
    #expect(L.resetReason(previous: wifi, current: moved) == "gateways changed")
}

@Test func fingerprintDescriptionHasNoAddresses() {
    #expect(!wifi.description.contains("192.0.2.1"))
}

@Test func connectionActions() {
    let young = Duration.seconds(1)
    #expect(L.action(age: young, viable: true, betterPathAvailable: false, waiting: false) == .keep)
    #expect(L.action(age: young, viable: false, betterPathAvailable: false, waiting: false) == .close)
    #expect(L.action(age: young, viable: true, betterPathAvailable: false, waiting: true) == .close)
    #expect(L.action(age: young, viable: true, betterPathAvailable: true, waiting: false) == .retire)
    #expect(L.action(age: L.maxAge, viable: true, betterPathAvailable: false, waiting: false) == .retire)
    // Losing the path wins over age.
    #expect(L.action(age: L.maxAge, viable: false, betterPathAvailable: false, waiting: false) == .close)
}

@Test func resetClearsPendingQueries() throws {
    var mux = QueryMultiplexer<Int>()
    let q: [UInt8] = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 97, 0, 0, 1, 0, 1]
    #expect(mux.register(q, context: 1) != nil)
    mux.removeAll()
    #expect(mux.count == 0)
}
