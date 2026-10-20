/// Sorted, merged, non-overlapping address ranges with binary search.
///
/// CIDR rules become inclusive `[start, end]` ranges. Overlapping and adjacent
/// ranges merge, so `10.0.0.0/25` plus `10.0.0.128/25` is stored as one range
/// and a lookup is one binary search for the last range that starts at or
/// below the address.
public struct AddressRanges<Address: FixedWidthInteger & UnsignedInteger & Sendable>: Sendable, Equatable {
    public private(set) var starts: [Address]
    public private(set) var ends: [Address]

    public var count: Int { starts.count }

    public init(_ ranges: some Sequence<(Address, Address)>) {
        let sorted = ranges.sorted { $0.0 < $1.0 }
        var starts: [Address] = []
        var ends: [Address] = []
        for (start, end) in sorted {
            if let last = ends.last, last == .max || start <= last + 1 {
                ends[ends.count - 1] = Swift.max(last, end)
            } else {
                starts.append(start)
                ends.append(end)
            }
        }
        self.starts = starts
        self.ends = ends
    }

    init(sortedStarts: [Address], ends: [Address]) {
        self.starts = sortedStarts
        self.ends = ends
    }

    public func contains(_ address: Address) -> Bool {
        // Index of the first range that starts above the address.
        var low = 0
        var high = starts.count
        while low < high {
            let mid = (low + high) >> 1
            if starts[mid] <= address { low = mid + 1 } else { high = mid }
        }
        return low > 0 && address <= ends[low - 1]
    }

    /// The inclusive range a CIDR prefix covers.
    static func range(network: Address, prefix: UInt8) -> (Address, Address) {
        let hostBits = Address.bitWidth - Int(prefix)
        let hostMask: Address = hostBits == Address.bitWidth ? .max : (1 << hostBits) - 1
        return (network, network | hostMask)
    }
}
