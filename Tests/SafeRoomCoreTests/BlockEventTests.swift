import Foundation
import Testing
@testable import SafeRoomCore

private func event(_ name: String) -> BlockEvent {
    BlockEvent(query: name, type: 1, rule: name, app: "com.example.app", transport: "udp")
}

@Test func eventPolicyKeys() {
    let p = ProviderPolicy([
        "EventURL": "https://events.example.com/saferoom/events",
        "EventAuth": ["Type": "bearer", "Token": "write-only"],
        "EventIntervalSeconds": 30,
        "Auth": ["Type": "bearer", "Token": "read-only"],
    ])
    #expect(p.eventURL?.absoluteString == "https://events.example.com/saferoom/events")
    #expect(p.eventAuth == .bearer(token: "write-only"))
    #expect(p.auth == .bearer(token: "read-only"))
    #expect(p.eventInterval == .seconds(30))
    #expect(p.listHostRules.contains(DomainRule(name: "events.example.com", match: .exact)))
    #expect(ProviderPolicy().eventURL == nil)
    #expect(ProviderPolicy().eventAuth == .none)
}

@Test func eventPolicyRejectsPlainHTTPAndClamps() {
    let p = ProviderPolicy(["EventURL": "http://events.example.com/e", "EventIntervalSeconds": 0])
    #expect(p.eventURL == nil)
    #expect(p.ignored.contains { $0.hasPrefix("EventURL") })
    #expect(p.eventInterval == .seconds(1))
}

@Test func eventStatusHidesToken() throws {
    let p = ProviderPolicy([
        "EventURL": "https://events.example.com/e?key=secret",
        "EventAuth": ["Type": "bearer", "Token": "write-only"],
    ])
    let summary = ExtensionStatus.PolicySummary(p)
    #expect(summary.eventURL == "https://events.example.com/e")
    #expect(summary.eventAuth == "bearer")
    let json = String(decoding: try ExtensionStatus.encoder.encode(summary), as: UTF8.self)
    #expect(!json.contains("write-only"))
    #expect(!json.contains("secret"))
}

@Test func bufferIsOffUntilEnabled() {
    let buffer = EventBuffer()
    buffer.add(event("a.example"))
    #expect(buffer.count == 0)
    buffer.setEnabled(true)
    buffer.add(event("a.example"))
    #expect(buffer.count == 1)
    buffer.setEnabled(false)
    #expect(buffer.count == 0)
}

@Test func bufferTakesOldestFirst() {
    let buffer = EventBuffer()
    buffer.setEnabled(true)
    for i in 0..<5 { buffer.add(event("d\(i).example")) }
    let (first, dropped) = buffer.take(3)
    #expect(first.map(\.name) == ["d0.example", "d1.example", "d2.example"])
    #expect(dropped == 0)
    #expect(buffer.take(10).events.map(\.name) == ["d3.example", "d4.example"])
    #expect(buffer.take(10).events.isEmpty)
}

@Test func fullBufferDropsOldestAndCounts() {
    let buffer = EventBuffer(capacity: 100)
    buffer.setEnabled(true)
    for i in 0..<101 { buffer.add(event("d\(i).example")) }
    // A tenth of the capacity goes at once.
    #expect(buffer.count == 91)
    #expect(buffer.droppedTotal == 10)
    let (events, dropped) = buffer.take(1000)
    #expect(events.first?.name == "d10.example")
    #expect(events.last?.name == "d100.example")
    #expect(dropped == 10)
    // The pending count goes with one batch only.
    #expect(buffer.take(1000).dropped == 0)
    #expect(buffer.droppedTotal == 10)
}

@Test func putBackKeepsOrder() {
    let buffer = EventBuffer()
    buffer.setEnabled(true)
    buffer.add(event("a.example"))
    buffer.add(event("b.example"))
    let (batch, dropped) = buffer.take(1)
    buffer.add(event("c.example"))
    buffer.putBack(batch, dropped: dropped + 3)
    let (events, pending) = buffer.take(10)
    #expect(events.map(\.name) == ["a.example", "b.example", "c.example"])
    #expect(pending == 3)
}

@Test func putBackRespectsCapacity() {
    let buffer = EventBuffer(capacity: 10)
    buffer.setEnabled(true)
    for i in 0..<10 { buffer.add(event("d\(i).example")) }
    let (batch, _) = buffer.take(10)
    for i in 10..<15 { buffer.add(event("d\(i).example")) }
    buffer.putBack(batch, dropped: 0)
    #expect(buffer.count == 10)
    #expect(buffer.take(1).events.first?.name == "d5.example")
    #expect(buffer.droppedTotal == 5)
}

@Test func batchJSONShape() throws {
    let time = Date(timeIntervalSince1970: 1_800_000_000)
    let batch = EventBatch(
        device: .init(hostname: "mac-1", serialNumber: "C02XYZ", version: "0.1.4 (19)"),
        sentAt: time, dropped: 2,
        events: [
            BlockEvent(query: "bad.example", type: 28, rule: "bad.example", app: "com.apple.Safari", transport: "udp", time: time),
            BlockEvent(answer: "cdn.example", reason: .alias(target: "bad.example", rule: "bad.example"), app: "x", transport: "tcp", time: time),
            BlockEvent(answer: "ip.example", reason: .address(.v4(0x0A00_0001)), app: "x", transport: "udp", time: time),
        ])
    let data = try EventBatch.encoder.encode(batch)
    let json = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(json["dropped"] as? Int == 2)
    #expect(json["sentAt"] as? String == "2027-01-15T08:00:00Z")
    let device = try #require(json["device"] as? [String: Any])
    #expect(device["hostname"] as? String == "mac-1")
    let events = try #require(json["events"] as? [[String: Any]])
    #expect(events[0]["kind"] as? String == "query")
    #expect(events[0]["type"] as? Int == 28)
    #expect(events[1]["kind"] as? String == "answer")
    #expect(events[1]["alias"] as? String == "bad.example")
    #expect(events[2]["address"] as? String == "10.0.0.1")
    #expect(events[2]["rule"] == nil)
    #expect(try JSONDecoder.iso8601.decode(EventBatch.self, from: data) == batch)
}

private extension JSONDecoder {
    static var iso8601: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
