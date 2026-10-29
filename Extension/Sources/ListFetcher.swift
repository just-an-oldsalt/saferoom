import Foundation
import Security
import SafeRoomCore

/// Downloads the list. Policy decides nothing here; `ListUpdate` does.
///
/// - The body is streamed and the download stops at the size limit, so a
///   huge, endless, or compressed-bomb response cannot fill memory or disk.
///   URLSession inflates gzip itself, so the count is of inflated bytes.
/// - Credentials (bearer token or client certificate) go only to the list
///   URL's host. Redirects are followed only to the same host and scheme.
/// - Client certificates come from the keychain, chosen by policy
///   (docs/mtls-okta.md).
final class ListFetcher: NSObject, URLSessionTaskDelegate, Sendable {
    struct Response: Sendable {
        let status: Int
        let body: Data
        let etag: String?
        let lastModified: String?
    }

    enum FetchError: Error, CustomStringConvertible {
        case notHTTP
        case tooLarge(Int)

        var description: String {
            switch self {
            case .notHTTP: "not an HTTP response"
            case .tooLarge(let bytes): "response is \(bytes) bytes, over the limit"
            }
        }
    }

    private let auth: ProviderPolicy.Auth
    private let maxBytes: Int
    /// The only host that gets credentials: the list URL's. A hash file on
    /// another host is fetched without them.
    private let credentialHost: String?
    private let credentialPort: Int?

    init(policy: ProviderPolicy) {
        self.auth = policy.auth
        self.maxBytes = policy.maxListBytes
        self.credentialHost = policy.listURL?.host()?.lowercased()
        self.credentialPort = policy.listURL.map(Self.port)
    }

    /// The URL's port, with the scheme's default filled in.
    static func port(_ url: URL) -> Int {
        url.port ?? (url.scheme?.lowercased() == "http" ? 80 : 443)
    }

    private func mayAuthenticate(_ url: URL?) -> Bool {
        guard let url, let host = url.host()?.lowercased() else { return false }
        return host == credentialHost && Self.port(url) == credentialPort
    }

    private var session: URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 300
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    /// `state` adds If-None-Match and If-Modified-Since. Pass nil to force a
    /// full download.
    func fetch(_ url: URL, state: FetchState?) async throws -> Response {
        var request = URLRequest(url: url)
        request.setValue("SafeRoom/\(Self.version)", forHTTPHeaderField: "User-Agent")
        if case .bearer(let token) = auth, mayAuthenticate(url) {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let etag = state?.etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        if let modified = state?.lastModified { request.setValue(modified, forHTTPHeaderField: "If-Modified-Since") }

        let session = self.session
        defer { session.finishTasksAndInvalidate() }
        let (stream, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw FetchError.notHTTP }
        if http.expectedContentLength > Int64(maxBytes) { throw FetchError.tooLarge(Int(http.expectedContentLength)) }

        var body = Data()
        body.reserveCapacity(Int(min(max(http.expectedContentLength, 0), Int64(maxBytes))))
        var chunk = [UInt8]()
        chunk.reserveCapacity(1 << 16)
        for try await byte in stream {
            chunk.append(byte)
            if chunk.count == 1 << 16 {
                body.append(contentsOf: chunk)
                chunk.removeAll(keepingCapacity: true)
                if body.count > maxBytes { throw FetchError.tooLarge(body.count) }
            }
        }
        body.append(contentsOf: chunk)
        guard body.count <= maxBytes else { throw FetchError.tooLarge(body.count) }
        return Response(
            status: http.statusCode,
            body: body,
            etag: http.value(forHTTPHeaderField: "ETag"),
            lastModified: http.value(forHTTPHeaderField: "Last-Modified"))
    }

    static let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"

    // MARK: - URLSessionTaskDelegate

    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest
    ) async -> URLRequest? {
        let from = task.originalRequest?.url
        guard let to = request.url, let from, to.scheme == from.scheme, to.host() == from.host(),
              Self.port(to) == Self.port(from)
        else {
            Log.list.error("refusing redirect to \(request.url.map(ExtensionStatus.PolicySummary.redacted) ?? "?", privacy: .public)")
            return nil
        }
        return request
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate else {
            return (.performDefaultHandling, nil)
        }
        guard mayAuthenticate(task.originalRequest?.url) else {
            Log.list.error("refusing a client certificate to a host other than the list URL's")
            return (.performDefaultHandling, nil)
        }
        guard case .clientCertificate(let subject, let issuer) = auth else {
            Log.list.error("server asked for a client certificate, but the policy Auth type is \(self.auth.description, privacy: .public)")
            return (.performDefaultHandling, nil)
        }
        guard let identity = Self.findIdentity(subjectContains: subject, issuerContains: issuer) else {
            Log.list.error("no keychain identity matches \(self.auth.description, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil)
        }
        return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
    }

    // MARK: - Keychain

    /// The first identity whose certificate subject and issuer contain the
    /// given text, ignoring case. Searches the keychains visible to this
    /// process, which runs as root: see docs/mtls-okta.md for why a user's
    /// login-keychain certificate may not be among them.
    static func findIdentity(subjectContains subject: String?, issuerContains issuer: String?) -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let identities = result as? [SecIdentity] else {
            Log.list.error("keychain identity search failed: OSStatus \(status, privacy: .public)")
            return nil
        }
        // A yearly renewal leaves the old certificate next to the new one
        // for a while. Skip the ones out of their validity dates, and take
        // the one that expires last.
        let now = Date()
        var best: (identity: SecIdentity, notAfter: Date, issuer: String)?
        var expired = 0
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { continue }
            let subjectText = SecCertificateCopySubjectSummary(certificate) as String? ?? ""
            let issuerText = issuerSummary(certificate)
            if let subject, !subjectText.localizedCaseInsensitiveContains(subject) { continue }
            if let issuer, !issuerText.localizedCaseInsensitiveContains(issuer) { continue }
            guard let (notBefore, notAfter) = validity(certificate), notBefore <= now, now < notAfter else {
                expired += 1
                continue
            }
            if best == nil || notAfter > best!.notAfter { best = (identity, notAfter, issuerText) }
        }
        if let best {
            // The issuer only: a subject can hold a person's name or email.
            Log.list.notice("using a client certificate issued by \(Log.clean(best.issuer), privacy: .public), valid until \(best.notAfter.ISO8601Format(), privacy: .public)")
            return best.identity
        }
        Log.list.error("searched \(identities.count) keychain identities, none matched (\(expired) matched but are expired or not yet valid)")
        return nil
    }

    /// The certificate's validity dates, or nil if they cannot be read.
    static func validity(_ certificate: SecCertificate) -> (Date, Date)? {
        let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any] else { return nil }
        func date(_ oid: CFString) -> Date? {
            guard let entry = values[oid as String] as? [String: Any],
                  let seconds = entry[kSecPropertyKeyValue as String] as? NSNumber
            else { return nil }
            return Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
        }
        guard let notBefore = date(kSecOIDX509V1ValidityNotBefore), let notAfter = date(kSecOIDX509V1ValidityNotAfter)
        else { return nil }
        return (notBefore, notAfter)
    }

    static func issuerSummary(_ certificate: SecCertificate) -> String {
        let keys = [kSecOIDX509V1IssuerName] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any],
              let issuer = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
              let parts = issuer[kSecPropertyKeyValue as String] as? [[String: Any]]
        else { return "" }
        return parts.compactMap { $0[kSecPropertyKeyValue as String] as? String }.joined(separator: ", ")
    }
}
