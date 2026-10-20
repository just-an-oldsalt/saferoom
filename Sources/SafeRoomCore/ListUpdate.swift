import CryptoKit
import Foundation

/// Decides what to do with a download. Pure, so every rejection path has a
/// test. The fetcher only does the network part.
///
/// Every failure keeps the current list. A bad download can cost freshness,
/// never protection, and it can never install a list that cuts Macs off.
public enum ListUpdate {
    public enum Outcome: Sendable, Equatable {
        /// 304, or a body identical to the current list. Nothing to do.
        case unchanged
        case accept(CompiledList, invalid: [InvalidLine])
        case reject(Rejection)
    }

    public enum Rejection: Sendable, Equatable, CustomStringConvertible {
        case httpStatus(Int)
        case tooLarge(bytes: Int, limit: Int)
        case hashMismatch(expected: String, actual: String)
        case badHashFile
        /// A list with no valid entries, replacing one that had entries.
        case empty
        case changeTooLarge(previous: Int, new: Int, limitPercent: Int)

        public var description: String {
            switch self {
            case .httpStatus(let code): "HTTP status \(code)"
            case .tooLarge(let bytes, let limit): "list is \(bytes) bytes, over the \(limit)-byte limit"
            case .hashMismatch(let expected, let actual): "SHA-256 is \(actual), expected \(expected)"
            case .badHashFile: "the SHA-256 file does not start with 64 hex characters"
            case .empty: "the new list has no valid entries"
            case .changeTooLarge(let previous, let new, let limit):
                "entry count would change from \(previous) to \(new), more than \(limit)%"
            }
        }
    }

    /// - Parameters:
    ///   - status: HTTP status, or 200 for a local file.
    ///   - expectedSHA256: the hash file's content, when the policy has one.
    ///   - current: the list in use now, or nil when none has loaded.
    public static func evaluate(
        status: Int, body: Data, expectedSHA256: String?,
        current: CompiledList?, policy: ProviderPolicy
    ) -> Outcome {
        if status == 304 { return .unchanged }
        guard status == 200 else { return .reject(.httpStatus(status)) }
        guard body.count <= policy.maxListBytes else {
            return .reject(.tooLarge(bytes: body.count, limit: policy.maxListBytes))
        }

        let sha = Array(SHA256.hash(data: body))
        if let expectedSHA256 {
            guard let expected = parseHash(expectedSHA256) else { return .reject(.badHashFile) }
            guard expected == sha else {
                return .reject(.hashMismatch(expected: hex(expected), actual: hex(sha)))
            }
        }
        if let current, current.sourceSHA256 == sha { return .unchanged }

        let (list, invalid) = CompiledList.compile(body)
        if let rejection = sanityCheck(new: list, current: current, maxChangePercent: policy.maxChangePercent) {
            return .reject(rejection)
        }
        return .accept(list, invalid: invalid)
    }

    /// Lists under this size skip the percentage check: going from 10 entries
    /// to 20 is a 100% change and is normal for a small list.
    public static let percentCheckMinimum = 100

    static func sanityCheck(new: CompiledList, current: CompiledList?, maxChangePercent: Int) -> Rejection? {
        let newCount = new.entryCount
        let oldCount = current?.entryCount ?? 0
        if newCount == 0, oldCount > 0 { return .empty }
        guard maxChangePercent > 0, oldCount >= percentCheckMinimum else { return nil }
        let change = abs(newCount - oldCount) * 100
        guard change <= oldCount * maxChangePercent else {
            return .changeTooLarge(previous: oldCount, new: newCount, limitPercent: maxChangePercent)
        }
        return nil
    }

    /// The first 64 hex characters, so both a bare hash and the
    /// `<hash>  <filename>` output of `shasum -a 256` work.
    static func parseHash(_ text: String) -> [UInt8]? {
        let hexText = text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64)
        guard hexText.count == 64 else { return nil }
        var out: [UInt8] = []
        var index = hexText.startIndex
        while index < hexText.endIndex {
            let next = hexText.index(index, offsetBy: 2)
            guard let byte = UInt8(hexText[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

extension CompiledList {
    /// Domain rules plus address ranges, the number the sanity check compares.
    public var entryCount: Int { stats.domainRules + stats.v4Ranges + stats.v6Ranges }
}

/// What the fetcher remembers between runs, so an unchanged list costs a 304.
public struct FetchState: Codable, Sendable, Equatable {
    public var url: String?
    public var etag: String?
    public var lastModified: String?

    public init(url: String? = nil, etag: String? = nil, lastModified: String? = nil) {
        self.url = url
        self.etag = etag
        self.lastModified = lastModified
    }
}

/// Wait before retrying after a failure: 1, 2, 4, 8... minutes, never longer
/// than the normal refresh interval.
public func retryDelay(afterFailures failures: Int, refresh: Duration) -> Duration {
    let minutes = 1 << min(max(failures - 1, 0), 10)
    return min(.seconds(60 * minutes), refresh)
}
