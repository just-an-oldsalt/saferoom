import Darwin
import Foundation
import SafeRoomCore

// bench <domains> <cidrs>: one size per process, so peak memory is clean.
let domainCount = Int(CommandLine.arguments[1])!
let cidrCount = Int(CommandLine.arguments[2])!

func rssMB() -> Double {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
    _ = withUnsafeMutablePointer(to: &info) { $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count) } }
    return Double(info.resident_size) / 1_048_576
}
func peakMB() -> Double { var u = rusage(); getrusage(RUSAGE_SELF, &u); return Double(u.ru_maxrss) / 1_048_576 }
func ms(_ d: Duration) -> Double { Double(d.components.seconds) * 1000 + Double(d.components.attoseconds) / 1e15 }

// Realistic shapes: feed domains average about 22 characters, 2-4 labels.
var rng = SystemRandomNumberGenerator()
let letters = Array("abcdefghijklmnopqrstuvwxyz0123456789")
let tlds = ["com", "net", "org", "xyz", "top", "ru", "info", "online", "site", "co.uk"]
func label(_ n: Int) -> String { String((0..<n).map { _ in letters[Int.random(in: 0..<letters.count, using: &rng)] }) }
var text = ""
text.reserveCapacity(domainCount * 24 + cidrCount * 18)
var names: [String] = []
names.reserveCapacity(min(domainCount, 200_000))
for i in 0..<domainCount {
    let name = (i % 3 == 0 ? label(4) + "." : "") + label(Int.random(in: 6...16, using: &rng)) + "." + tlds[i % tlds.count]
    text += name; text += "\n"
    if names.count < 200_000 { names.append(name) }
}
for i in 0..<cidrCount {
    let a = UInt32(truncatingIfNeeded: i &* 2654435761) | 0x0100_0000
    text += "\(a >> 24 & 0xFF).\(a >> 16 & 0xFF).\(a >> 8 & 0xFF).0/24\n"
}
let bytes = Array(text.utf8)
text = ""
let baseline = rssMB()

let t0 = ContinuousClock.now
let compiled = CompiledList.compile(bytes).list
let compileMS = ms(ContinuousClock.now - t0)
let peak = peakMB()
let blocklist = Blocklist(list: compiled)

let cache = compiled.serialized()
let t1 = ContinuousClock.now
let reloaded = try! CompiledList(cache: cache)
let loadMS = ms(ContinuousClock.now - t1)
precondition(reloaded.entryCount == compiled.entryCount)

// Lookups: half listed subdomains (hit after a suffix walk), half misses.
let queries: [[UInt8]] = (0..<400_000).map { i in
    i % 2 == 0 ? Array(("www." + names[i % names.count]).utf8) : Array("clean\(i).example.org".utf8)
}
var hits = 0
let t2 = ContinuousClock.now
for q in queries { if case .blocked = blocklist.verdict(normalized: q) { hits += 1 } }
let lookupNS = ms(ContinuousClock.now - t2) * 1e6 / Double(queries.count)

var ipHits = 0
let t3 = ContinuousClock.now
for i in 0..<400_000 { if blocklist.isBlocked(.v4(UInt32(truncatingIfNeeded: i &* 2654435761) | 0x0100_0000)) { ipHits += 1 } }
let ipNS = ms(ContinuousClock.now - t3) * 1e6 / 400_000

print(String(format: "%9d dom %8d cidr | list %6.1f MB | compile %7.0f ms | peak RSS %6.0f MB | after %5.0f MB | in-mem %6.1f MB | cache %6.1f MB load %5.1f ms | lookup %4.0f ns | ip %3.0f ns | hits %d",
    domainCount, cidrCount, Double(bytes.count) / 1_048_576, compileMS, peak, rssMB() - baseline + 0,
    Double(compiled.byteSize) / 1_048_576, Double(cache.count) / 1_048_576, loadMS, lookupNS, ipNS, hits))
