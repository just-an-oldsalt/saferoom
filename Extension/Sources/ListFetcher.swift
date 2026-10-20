import Foundation
import Security
import SafeRoomCore

/// Downloads the list. Policy decides nothing here; `ListUpdate` does.
///
/// - The body goes to a temporary file, and its size is checked before it is
///   read, so a huge response cannot exhaust the extension's memory.
/// - Redirects are followed only to the same host over HTTPS. The bearer
///   token is never sent anywhere the policy did not name.
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

    init(policy: ProviderPolicy) {
        self.auth = policy.auth
        self.maxBytes = policy.maxListBytes
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
        if case .bearer(let token) = auth {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let etag = state?.etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        if let modified = state?.lastModified { request.setValue(modified, forHTTPHeaderField: "If-Modified-Since") }

        let session = self.session
        defer { session.finishTasksAndInvalidate() }
        let (file, response) = try await session.download(for: request)
        defer { try? FileManager.default.removeItem(at: file) }
        guard let http = response as? HTTPURLResponse else { throw FetchError.notHTTP }

        let size = (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= maxBytes else { throw FetchError.tooLarge(size) }
        return Response(
            status: http.statusCode,
            body: try Data(contentsOf: file),
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
        guard let to = request.url, to.scheme == from?.scheme, to.host() == from?.host() else {
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
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { continue }
            let subjectText = SecCertificateCopySubjectSummary(certificate) as String? ?? ""
            let issuerText = issuerSummary(certificate)
            if let subject, !subjectText.localizedCaseInsensitiveContains(subject) { continue }
            if let issuer, !issuerText.localizedCaseInsensitiveContains(issuer) { continue }
            Log.list.notice("using client certificate subject=\(subjectText, privacy: .public) issuer=\(issuerText, privacy: .public)")
            return identity
        }
        Log.list.error("searched \(identities.count) keychain identities, none matched")
        return nil
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
