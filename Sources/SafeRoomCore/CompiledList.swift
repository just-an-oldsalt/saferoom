import CryptoKit
import Foundation

/// A blocklist after parsing: the part that comes from the feed, ready to
/// query, and cacheable on disk so the extension can start without a fetch.
///
/// The allowlist is NOT in here. It comes from MDM policy, which changes on
/// its own schedule, so `Blocklist` combines the two at load time.
public struct CompiledList: Sendable, Equatable {
    public let domains: DomainSet
    public let v4: AddressRanges<UInt32>
    public let v6: AddressRanges<UInt128>
    /// SHA-256 of the list text this was compiled from. The fetcher compares
    /// it to skip recompiling an unchanged list.
    public let sourceSHA256: [UInt8]
    public let stats: Stats

    public struct Stats: Sendable, Equatable {
        public var lineCount: Int
        public var invalidCount: Int
        public var domainRules: Int
        public var v4Ranges: Int
        public var v6Ranges: Int
    }

    public init(source: some Collection<UInt8>) {
        self = Self.compile(source).list
    }

    /// Compiles and also returns the first rejected lines, for the log.
    public static func compile(_ source: some Collection<UInt8>) -> (list: CompiledList, invalid: [InvalidLine]) {
        let parsed = ListParser.parse(source)
        let list = CompiledList(parsed: parsed, sourceSHA256: Array(SHA256.hash(data: Data(source))))
        return (list, parsed.invalidSamples)
    }

    public init(parsed: ParsedList, sourceSHA256: [UInt8]) {
        var v4: [(UInt32, UInt32)] = []
        var v6: [(UInt128, UInt128)] = []
        for cidr in parsed.cidrs {
            switch cidr {
            case .v4(let net, let prefix): v4.append(AddressRanges.range(network: net, prefix: prefix))
            case .v6(let net, let prefix): v6.append(AddressRanges.range(network: net, prefix: prefix))
            }
        }
        let domains = DomainSet(parsed.domains)
        let v4Ranges = AddressRanges(v4)
        let v6Ranges = AddressRanges(v6)
        self.init(
            domains: domains, v4: v4Ranges, v6: v6Ranges, sourceSHA256: sourceSHA256,
            stats: Stats(
                lineCount: parsed.lineCount, invalidCount: parsed.invalidCount,
                domainRules: domains.count, v4Ranges: v4Ranges.count, v6Ranges: v6Ranges.count))
    }

    init(
        domains: DomainSet, v4: AddressRanges<UInt32>, v6: AddressRanges<UInt128>,
        sourceSHA256: [UInt8], stats: Stats
    ) {
        self.domains = domains
        self.v4 = v4
        self.v6 = v6
        // Always 32 bytes, so the value survives the cache unchanged. All
        // zeros means "no source" (the empty list).
        self.sourceSHA256 = sourceSHA256.count == 32 ? sourceSHA256 : [UInt8](repeating: 0, count: 32)
        self.stats = stats
    }

    public static let empty = CompiledList(parsed: ParsedList(), sourceSHA256: [])

    public var byteSize: Int { domains.byteSize + v4.count * 8 + v6.count * 32 }
}

// MARK: - Cache file

/// The cache is a flat binary file: a fixed header, the raw arrays, and a
/// SHA-256 over everything before it. A file that fails any check is ignored
/// and the extension falls back to fetching, so a corrupt cache can cost a
/// fetch but can never install a wrong list.
///
/// Layout, all integers little-endian (every supported Mac is):
///
///     magic "SRCL" | version u32 | sourceSHA256 [32]
///     lineCount u64 | invalidCount u64
///     domainCount u64 | v4Count u64 | v6Count u64
///     keys [u64 * domainCount] | flags [u8 * domainCount]
///     v4 starts, v4 ends [u32 * v4Count each]
///     v6 starts, v6 ends [u128 * v6Count each]
///     checksum: SHA-256 of all bytes above [32]
extension CompiledList {
    static let magic: [UInt8] = Array("SRCL".utf8)
    /// Bump when the layout OR `DomainKey`'s hash changes.
    public static let formatVersion: UInt32 = 1

    public enum CacheError: Error, Equatable {
        case tooShort, badMagic, wrongVersion(UInt32), checksumMismatch, malformed
    }

    public func serialized() -> Data {
        var out = Data()
        out.append(contentsOf: Self.magic)
        out.appendLE(Self.formatVersion)
        out.append(contentsOf: sourceSHA256)
        for n in [stats.lineCount, stats.invalidCount, domains.count, v4.count, v6.count] {
            out.appendLE(UInt64(n))
        }
        out.appendArray(domains.keys)
        out.appendArray(domains.flags)
        out.appendArray(v4.starts)
        out.appendArray(v4.ends)
        out.appendArray(v6.starts)
        out.appendArray(v6.ends)
        out.append(contentsOf: SHA256.hash(data: out))
        return out
    }

    public init(cache data: Data) throws(CacheError) {
        let headerSize = 4 + 4 + 32 + 5 * 8
        guard data.count >= headerSize + 32 else { throw .tooShort }
        let body = data.prefix(data.count - 32)
        guard Data(SHA256.hash(data: body)) == data.suffix(32) else { throw .checksumMismatch }

        var reader = ByteReader(data: body)
        guard reader.bytes(4) == Self.magic else { throw .badMagic }
        let version: UInt32 = reader.le()
        guard version == Self.formatVersion else { throw .wrongVersion(version) }
        let sha = reader.bytes(32)
        let lineCount: UInt64 = reader.le()
        let invalidCount: UInt64 = reader.le()
        let domainCount: UInt64 = reader.le()
        let v4Count: UInt64 = reader.le()
        let v6Count: UInt64 = reader.le()

        // Bound the counts first, so the size arithmetic below cannot overflow.
        let limit: UInt64 = 1 << 32
        guard domainCount < limit, v4Count < limit, v6Count < limit,
              lineCount < limit, invalidCount < limit
        else { throw .malformed }
        let expected = UInt64(headerSize) + domainCount * 9 + v4Count * 8 + v6Count * 32
        guard expected == UInt64(body.count) else { throw .malformed }

        let keys: [UInt64] = reader.array(Int(domainCount))
        let flags: [UInt8] = reader.array(Int(domainCount))
        let v4Starts: [UInt32] = reader.array(Int(v4Count))
        let v4Ends: [UInt32] = reader.array(Int(v4Count))
        let v6Starts: [UInt128] = reader.array(Int(v6Count))
        let v6Ends: [UInt128] = reader.array(Int(v6Count))

        self.init(
            domains: DomainSet(sortedKeys: keys, flags: flags),
            v4: AddressRanges(sortedStarts: v4Starts, ends: v4Ends),
            v6: AddressRanges(sortedStarts: v6Starts, ends: v6Ends),
            sourceSHA256: sha,
            stats: Stats(
                lineCount: Int(lineCount), invalidCount: Int(invalidCount),
                domainRules: Int(domainCount), v4Ranges: Int(v4Count), v6Ranges: Int(v6Count)))
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendArray<T: FixedWidthInteger>(_ values: [T]) {
        values.withUnsafeBytes { append(contentsOf: $0) }
    }
}

private struct ByteReader {
    let data: Data
    var offset: Int

    init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    mutating func bytes(_ n: Int) -> [UInt8] {
        defer { offset += n }
        return Array(data[offset..<offset + n])
    }

    mutating func le<T: FixedWidthInteger>() -> T {
        let size = MemoryLayout<T>.size
        defer { offset += size }
        var value = T.zero
        _ = withUnsafeMutableBytes(of: &value) { data.copyBytes(to: $0, from: offset..<offset + size) }
        return T(littleEndian: value)
    }

    mutating func array<T: FixedWidthInteger>(_ count: Int) -> [T] {
        let size = count * MemoryLayout<T>.stride
        defer { offset += size }
        return [T](unsafeUninitializedCapacity: count) { buffer, initialized in
            _ = data.copyBytes(to: UnsafeMutableRawBufferPointer(buffer), from: offset..<offset + size)
            initialized = count
        }
    }
}
