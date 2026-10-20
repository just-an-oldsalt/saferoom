/// A set of domain rules, stored as sorted 64-bit hashes with a flag byte each.
///
/// ## Why hashes, and why reversed
///
/// 250k names as Swift strings cost 30-50 MB. As `UInt64` keys plus one flag
/// byte they cost 9 bytes each, about 2.25 MB, and a lookup is a binary search
/// over a flat array.
///
/// The hash runs over the name's bytes from RIGHT to LEFT. A query is then
/// hashed in one pass from its end, and at every dot the running value is
/// already the key of that suffix: `com`, then `evil.com`, then `a.evil.com`.
/// One walk checks every parent domain, which is what makes the subtree and
/// `*.` modes nearly free.
///
/// ## Collisions
///
/// A false match needs two different names with the same 64-bit FNV-1a value.
/// At 250k entries the chance that a given query collides is about 1 in 7e13.
/// A collision can only block a name; it can never unblock one.
public struct DomainSet: Sendable, Equatable {
    /// Flag bits. A rule's mode becomes a mask so that several rules for the
    /// same name merge with OR: `evil.com` plus `=evil.com` is still subtree.
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }
        /// Matches the name itself.
        public static let name = Flags(rawValue: 1)
        /// Matches every name below it.
        public static let descendants = Flags(rawValue: 2)

        init(_ match: DomainMatch) {
            switch match {
            case .subtree: self = [.name, .descendants]
            case .exact: self = .name
            case .subdomainsOnly: self = .descendants
            }
        }
    }

    public private(set) var keys: [UInt64]
    public private(set) var flags: [UInt8]

    public var count: Int { keys.count }
    public var byteSize: Int { keys.count * 8 + flags.count }

    public init(_ rules: some Sequence<DomainRule>) {
        var pairs = rules.map { (DomainKey.key($0.name), Flags($0.match).rawValue) }
        pairs.sort { $0.0 < $1.0 }
        var keys: [UInt64] = []
        var flags: [UInt8] = []
        keys.reserveCapacity(pairs.count)
        flags.reserveCapacity(pairs.count)
        for (key, flag) in pairs {
            if keys.last == key {
                flags[flags.count - 1] |= flag
            } else {
                keys.append(key)
                flags.append(flag)
            }
        }
        self.keys = keys
        self.flags = flags
    }

    /// Rebuilds a set from a cache file. The caller checked the contents.
    init(sortedKeys: [UInt64], flags: [UInt8]) {
        self.keys = sortedKeys
        self.flags = flags
    }

    public static let empty = DomainSet([])

    /// The length, in bytes from the END of `name`, of the shortest matching
    /// suffix, or nil. `evil.com` matching `a.evil.com` returns 8.
    ///
    /// `name` must already be lowercase ASCII with no trailing dot. The DNS
    /// codec and `DomainKey.normalize` produce that form.
    public func matchedSuffixLength(_ name: UnsafeBufferPointer<UInt8>) -> Int? {
        guard !keys.isEmpty, !name.isEmpty else { return nil }
        var hash = DomainKey.offset
        var i = name.count
        while i > 0 {
            i -= 1
            hash = DomainKey.step(hash, name[i])
            let atStart = i == 0
            guard atStart || name[i - 1] == UInt8(ascii: ".") else { continue }
            if let f = lookup(hash) {
                let flagsNeeded: Flags = atStart ? .name : .descendants
                if f.contains(flagsNeeded) { return name.count - i }
            }
        }
        return nil
    }

    func lookup(_ key: UInt64) -> Flags? {
        var low = 0
        var high = keys.count
        while low < high {
            let mid = (low + high) >> 1
            let k = keys[mid]
            if k == key { return Flags(rawValue: flags[mid]) }
            if k < key { low = mid + 1 } else { high = mid }
        }
        return nil
    }
}

/// The hash that keys a `DomainSet`. It is part of the cache file format, so
/// changing it means bumping `CompiledList.formatVersion`.
public enum DomainKey {
    static let offset: UInt64 = 0xCBF2_9CE4_8422_2325
    static let prime: UInt64 = 0x0000_0100_0000_01B3

    @inline(__always)
    static func step(_ hash: UInt64, _ byte: UInt8) -> UInt64 {
        (hash ^ UInt64(byte)) &* prime
    }

    /// FNV-1a over the name's bytes in reverse order.
    public static func key(_ name: String) -> UInt64 {
        var hash = offset
        for b in name.utf8.reversed() { hash = step(hash, b) }
        return hash
    }

    /// Lowercases ASCII letters and drops one trailing dot, in place. DNS
    /// names on the wire can arrive in any case (`EvIl.CoM`, 0x20 encoding).
    public static func normalize(_ bytes: inout [UInt8]) {
        if bytes.last == UInt8(ascii: ".") { bytes.removeLast() }
        for i in bytes.indices where bytes[i] >= 0x41 && bytes[i] <= 0x5A {
            bytes[i] |= 0x20
        }
    }
}
