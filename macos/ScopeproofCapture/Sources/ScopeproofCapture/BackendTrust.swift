import Foundation

enum BackendTrust {
    private static var productionOrigins: Set<String> {
        let configured = Bundle.main.object(forInfoDictionaryKey: "ScopeproofHostedAPIOrigins") as? [String] ?? []
        return Set(configured.compactMap { value -> String? in
            guard value == value.trimmingCharacters(in: .whitespacesAndNewlines),
                  let url = URL(string: value),
                  url.scheme?.lowercased() == "https", url.port == nil,
                  url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
                  url.path.isEmpty || url.path == "/",
                  let host = url.host?.lowercased(), !host.isEmpty,
                  let canonical = URL(string: "https://\(host)") else { return nil }
            return canonical.absoluteString
        })
    }

    static func normalizedOrigin(_ candidate: URL?, approvedProductionOrigins: Set<String>? = nil) -> URL? {
        guard let candidate,
              candidate.user == nil, candidate.password == nil,
              candidate.query == nil, candidate.fragment == nil,
              candidate.path.isEmpty || candidate.path == "/" else { return nil }
        return origin(of: candidate, approvedProductionOrigins: approvedProductionOrigins ?? productionOrigins)
    }

    private static func origin(of candidate: URL?, approvedProductionOrigins: Set<String>) -> URL? {
        guard let candidate, candidate.user == nil, candidate.password == nil,
              let scheme = candidate.scheme?.lowercased(), let host = candidate.host?.lowercased() else { return nil }
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = candidate.port
        guard let origin = components.url else { return nil }
        if scheme == "https", approvedProductionOrigins.contains(origin.absoluteString) { return origin }
        #if DEBUG
        if scheme == "http", ["localhost", "127.0.0.1", "::1"].contains(host) { return origin }
        #endif
        return nil
    }

    static func sameOrigin(_ left: URL?, _ right: URL, approvedProductionOrigins: Set<String>? = nil) -> Bool {
        guard let trustedAudience = normalizedOrigin(right, approvedProductionOrigins: approvedProductionOrigins) else { return false }
        return origin(of: left, approvedProductionOrigins: [trustedAudience.absoluteString])?.absoluteString == trustedAudience.absoluteString
    }
}

private final class RejectRedirectDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let maximumBytes: Int64?

    init(maximumBytes: Int? = nil) { self.maximumBytes = maximumBytes.map(Int64.init) }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        if let maximumBytes, totalBytesWritten > maximumBytes { downloadTask.cancel() }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {}
}

enum BackendHTTP {
    static func data(for request: URLRequest, audience: URL) async throws -> (Data, URLResponse) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration, delegate: RejectRedirectDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let result = try await session.data(for: request)
        guard BackendTrust.sameOrigin(result.1.url, audience) else { throw UploadFailure.invalidServer }
        return result
    }

    static func download(_ url: URL, approvedOrigins: Set<String>, maximumBytes: Int) async throws -> (URL, HTTPURLResponse) {
        guard url.scheme == "https", url.user == nil, url.password == nil, url.fragment == nil,
              let origin = URL(string: "\(url.scheme!)://\(url.host!)\(url.port.map { ":\($0)" } ?? "")"),
              approvedOrigins.contains(origin.absoluteString) else { throw UpdateFailure.unapprovedDownload }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration, delegate: RejectRedirectDelegate(maximumBytes: maximumBytes), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.timeoutInterval = 120
        request.setValue("application/zip", forHTTPHeaderField: "Accept")
        let (temporaryURL, response) = try await session.download(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), http.url == url else { throw UpdateFailure.unapprovedDownload }
        if let declared = http.value(forHTTPHeaderField: "Content-Length"), Int(declared) ?? maximumBytes + 1 > maximumBytes { throw UpdateFailure.invalidArtifact("The release exceeds the download size limit.") }
        let retained = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-release-\(UUID().uuidString).zip")
        try FileManager.default.copyItem(at: temporaryURL, to: retained)
        return (retained, http)
    }
}
