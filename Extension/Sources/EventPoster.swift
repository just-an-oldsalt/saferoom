import Foundation
import IOKit
import Security
import SafeRoomCore
import Synchronization

/// Posts block events to the policy's event URL.
///
/// The relays only add to the `EventBuffer`. This actor wakes every
/// `eventInterval`, empties the buffer in batches of `batchSize`, and posts
/// each batch as one JSON body. A failed post puts its batch back and waits
/// 1, 2, 4... minutes, up to 10, each spread by up to a quarter either way.
/// When the proxy stops, one last post gets two seconds, because the buffer
/// is in memory only. Nothing here can delay or change a DNS
/// answer: a dead event server only costs events, and the buffer bounds that
/// cost in memory.
///
/// - Credentials (bearer token or client certificate) go only to the event
///   URL's host. Every redirect is refused: URLSession would turn a
///   redirected POST into a GET without the body.
/// - With `EventServerPins`, the server's key must match a pin, and TLS 1.3
///   is the minimum. The pin replaces the system trust check, so a
///   self-signed certificate works. Without the key, the system check
///   applies.
/// - The response body is never read.
actor EventPoster {
    static let batchSize = 500
    static let maxRetryDelay: Duration = .seconds(600)

    private let url: URL
    private let auth: ProviderPolicy.Auth
    private let interval: Duration
    private let buffer: EventBuffer
    private let device: EventBatch.Device
    private let pins: [Data]?
    private var loop: Task<Void, Never>?
    private var posted = 0
    private var failures = 0
    private var lastPostAt: Date?
    private var lastError: String?

    init?(policy: ProviderPolicy, buffer: EventBuffer, version: String) {
        guard let url = policy.eventURL else { return nil }
        self.url = url
        self.auth = policy.eventAuth
        self.interval = policy.eventInterval
        self.buffer = buffer
        self.device = .init(hostname: Self.hostname(), serialNumber: Self.serialNumber(), version: version)
        self.pins = policy.eventServerPins
    }

    func start() {
        loop = Task { await run() }
    }

    func stop() {
        loop?.cancel()
        loop = nil
    }

    /// Stops, then makes one last try to post what is waiting. The buffer is
    /// in memory only, so an upgrade or a restart otherwise throws it away.
    /// Gives up after `limit`.
    func stop(flushWithin limit: Duration) async {
        stop()
        guard buffer.count > 0 else { return }
        let timeout = TimeInterval(limit.components.seconds)
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.flush(timeout: timeout) }
            group.addTask { try? await Task.sleep(for: limit) }
            await group.next()
            group.cancelAll()
        }
        if buffer.count > 0 { Log.event.notice("stopping with \(self.buffer.count) events not posted") }
    }

    func summary() -> ExtensionStatus.EventSummary {
        .init(
            url: ExtensionStatus.PolicySummary.redacted(url), auth: auth.description,
            intervalSeconds: Int(interval.components.seconds), queued: buffer.count, posted: posted,
            dropped: buffer.droppedTotal, consecutiveFailures: failures, lastPostAt: lastPostAt,
            lastError: lastError)
    }

    private func run() async {
        while !Task.isCancelled {
            let delay = failures == 0
                ? interval : jittered(retryDelay(afterFailures: failures, refresh: Self.maxRetryDelay))
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await flush()
        }
    }

    /// Posts until the buffer is empty or a post fails.
    private func flush(timeout: TimeInterval = 30) async {
        while !Task.isCancelled {
            let (events, dropped) = buffer.take(Self.batchSize)
            guard !events.isEmpty || dropped > 0 else { return }
            let batch = EventBatch(device: device, dropped: dropped, events: events)
            if let error = await post(batch, timeout: timeout) {
                buffer.putBack(events, dropped: dropped)
                failures += 1
                lastError = error
                Log.event.error("event post failed: \(error, privacy: .public); \(events.count) events kept, retrying (failure \(self.failures))")
                return
            }
            if failures > 0 { Log.event.notice("event post recovered after \(self.failures) failures") }
            failures = 0
            lastError = nil
            lastPostAt = Date()
            posted += events.count
            if events.count < Self.batchSize { return }
        }
    }

    /// Nil on a 2xx reply, else the reason.
    private func post(_ batch: EventBatch, timeout: TimeInterval) async -> String? {
        let body: Data
        do {
            body = try EventBatch.encoder.encode(batch)
        } catch {
            return "cannot encode the batch: \(error)"
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("SafeRoom/\(ListFetcher.version)", forHTTPHeaderField: "User-Agent")
        if case .bearer(let token) = auth {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = 2 * timeout
        if pins != nil { config.tlsMinimumSupportedProtocolVersion = .TLSv13 }
        // One delegate per post, so the failure it records belongs to this
        // post.
        let delegate = Delegate(auth: auth, url: url, pins: pins)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        // Cancels the response body instead of waiting for it.
        defer { session.invalidateAndCancel() }
        do {
            let (_, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { return "not an HTTP response" }
            return (200..<300).contains(http.statusCode) ? nil : "HTTP status \(http.statusCode)"
        } catch {
            // The delegate's reason is clearer than "cancelled".
            if let reason = delegate.failure { return reason }
            return (error as? URLError).map { "\($0.localizedDescription) (URLError \($0.code.rawValue))" }
                ?? String(describing: error)
        }
    }

    // MARK: - Device

    /// The local host name, from the kernel. ProcessInfo.hostName can make a
    /// DNS lookup, which would pass through this proxy.
    static func hostname() -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        guard gethostname(&buffer, buffer.count) == 0 else { return nil }
        let name = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return name.isEmpty ? nil : name
    }

    /// The hardware serial number, which the MDM inventory also holds.
    static func serialNumber() -> String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        let value = IORegistryEntryCreateCFProperty(service, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)
        return value?.takeRetainedValue() as? String
    }

    // MARK: - URLSessionTaskDelegate

    final class Delegate: NSObject, URLSessionTaskDelegate, Sendable {
        private let auth: ProviderPolicy.Auth
        private let host: String?
        private let port: Int
        private let pins: [Data]?
        private let failureText = Mutex<String?>(nil)

        /// Why the delegate refused the connection, for `lastError`.
        var failure: String? { failureText.withLock { $0 } }

        init(auth: ProviderPolicy.Auth, url: URL, pins: [Data]?) {
            self.auth = auth
            self.host = url.host()?.lowercased()
            self.port = ListFetcher.port(url)
            self.pins = pins
        }

        private func refuse(_ reason: String) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            failureText.withLock { $0 = reason }
            Log.event.error("\(reason, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil)
        }

        func urlSession(
            _ session: URLSession, task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest
        ) async -> URLRequest? {
            Log.event.error("refusing a redirect from the event URL (HTTP status \(response.statusCode))")
            return nil
        }

        func urlSession(
            _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge
        ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            let method = challenge.protectionSpace.authenticationMethod
            if method == NSURLAuthenticationMethodServerTrust {
                guard let pins else { return (.performDefaultHandling, nil) }
                guard let trust = challenge.protectionSpace.serverTrust else {
                    return refuse(ServerPins.Failure.noServerCertificate.description)
                }
                if let failure = ServerPins.check(pins: pins, leaf: Self.leafKey(trust)) {
                    return refuse(failure.description)
                }
                return (.useCredential, URLCredential(trust: trust))
            }
            guard method == NSURLAuthenticationMethodClientCertificate else {
                return (.performDefaultHandling, nil)
            }
            guard let url = task.originalRequest?.url, url.host()?.lowercased() == host, ListFetcher.port(url) == port,
                  case .clientCertificate(let subject, let issuer) = auth
            else {
                Log.event.error("event server asked for a client certificate, but EventAuth is \(self.auth.description, privacy: .public)")
                return (.performDefaultHandling, nil)
            }
            guard let identity = ListFetcher.findIdentity(subjectContains: subject, issuerContains: issuer) else {
                return refuse("no valid client certificate: no unexpired keychain identity matches \(auth.description)")
            }
            return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
        }

        /// The server's leaf key, in the form the pin check reads.
        static func leafKey(_ trust: SecTrust) -> ServerPins.LeafKey {
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
                  let key = SecCertificateCopyKey(leaf)
            else { return .none }
            let attributes = SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
            guard attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
                  attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
                  let point = SecKeyCopyExternalRepresentation(key, nil) as Data?
            else { return .other }
            return .p256(point)
        }
    }
}
