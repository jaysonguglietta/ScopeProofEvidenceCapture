@preconcurrency import AppKit
import CryptoKit
import Foundation
import ImageIO
import Network

enum LocalConsoleFailure: LocalizedError {
    case startup(String)
    case invalidRequest
    case unauthorized
    case notFound
    case forbidden
    case invalidBody(String)

    var errorDescription: String? {
        switch self {
        case .startup(let detail): return "The local console could not start. \(detail)"
        case .invalidRequest: return "The local console received an invalid request."
        case .unauthorized: return "This local console session is no longer valid. Reopen it from the Scopeproof menu."
        case .notFound: return "The requested local evidence was not found."
        case .forbidden: return "The request was blocked by the local console security policy."
        case .invalidBody(let detail): return detail
        }
    }
}

@MainActor
final class LocalConsoleServer {
    struct Status: Codable {
        let localUser: String
        let evidenceRoot: String
        let indexState: String
        let hostedConnected: Bool
        let hostedServer: String
        let autoUpload: Bool
        let retentionDays: Int
        let summary: LocalEvidenceSummary
        let s3Configured: Bool
        let s3InventoryState: String
        let s3Bucket: String
        let s3Prefix: String
        let s3DownloadsAllowed: Bool
    }

    private let evidenceRoot: URL
    private let preferences: CapturePreferences
    private let s3Service: S3StorageService
    private let requestCapture: @MainActor () -> Void
    private let openS3Browser: @MainActor () -> Void
    private let queue = DispatchQueue(label: "com.scopeproof.capture.local-console", qos: .userInitiated)
    private var listener: NWListener?
    private var port: UInt16?
    private let sessionToken = LocalConsoleServer.randomToken(byteCount: 32)
    private var storedIndex: LocalEvidenceIndex?
    private var s3Cache: S3InventoryCache?

    init(
        evidenceRoot: URL, preferences: CapturePreferences, s3Service: S3StorageService,
        requestCapture: @escaping @MainActor () -> Void,
        openS3Browser: @escaping @MainActor () -> Void
    ) {
        self.evidenceRoot = evidenceRoot.standardizedFileURL
        self.preferences = preferences
        self.s3Service = s3Service
        self.requestCapture = requestCapture
        self.openS3Browser = openS3Browser
    }

    var isRunning: Bool { listener != nil && port != nil }
    var displayURL: URL? { port.flatMap { URL(string: "http://127.0.0.1:\($0)/") } }

    func open() async throws {
        if !isRunning { try await start() }
        try syncIndex(action: "console.opened")
        guard let port, let launchURL = URL(string: "http://127.0.0.1:\(port)/launch?token=\(sessionToken)") else { throw LocalConsoleFailure.startup("No local address was assigned.") }
        NSWorkspace.shared.open(launchURL)
    }

    func stop() {
        listener?.cancel()
        listener = nil
        port = nil
    }

    func syncIndex(action: String = "index.synchronized") throws {
        let entries = CaptureHistory.entries(in: evidenceRoot)
        let index = try evidenceIndex()
        try index.sync(entries: entries)
        try index.recordAudit(action: action, resourceID: "local-console", details: ["evidenceCount": String(entries.count)])
    }

    private func start() async throws {
        let listener: NWListener
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        do { listener = try NWListener(using: parameters) }
        catch { throw LocalConsoleFailure.startup(error.localizedDescription) }
        listener.newConnectionHandler = { [weak self] connection in self?.handle(connection) }
        self.listener = listener
        let gate = ListenerStartupGate()
        let assignedPort: UInt16 = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard let assignedPort = listener.port?.rawValue else {
                        gate.resume(continuation, with: .failure(LocalConsoleFailure.startup("No loopback port was assigned."))); return
                    }
                    gate.resume(continuation, with: .success(assignedPort))
                case .failed(let error):
                    gate.resume(continuation, with: .failure(LocalConsoleFailure.startup(error.localizedDescription)))
                case .cancelled:
                    gate.resume(continuation, with: .failure(LocalConsoleFailure.startup("The listener was cancelled.")))
                default: break
                }
            }
            listener.start(queue: queue)
        }
        port = assignedPort
    }

    nonisolated private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        receiveRequest(connection: connection, accumulated: Data())
    }

    nonisolated private func receiveRequest(connection: NWConnection, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] content, _, complete, error in
            guard let self else { connection.cancel(); return }
            var buffer = accumulated
            if let content { buffer.append(content) }
            if buffer.count > 2 * 1024 * 1024 {
                self.send(.json(status: 413, object: ["error": "Request body is too large."]), on: connection); return
            }
            if let request = HTTPRequest.parse(buffer) {
                if buffer.count < request.expectedLength {
                    self.receiveRequest(connection: connection, accumulated: buffer); return
                }
                Task { @MainActor in
                    let response = await self.route(request)
                    self.send(response, on: connection)
                }
            } else if complete || error != nil {
                self.send(.json(status: 400, object: ["error": LocalConsoleFailure.invalidRequest.localizedDescription]), on: connection)
            } else {
                self.receiveRequest(connection: connection, accumulated: buffer)
            }
        }
    }

    nonisolated private func send(_ response: HTTPResponse, on connection: NWConnection) {
        connection.send(content: response.encoded, completion: .contentProcessed { _ in connection.cancel() })
    }

    private func route(_ request: HTTPRequest) async -> HTTPResponse {
        do {
            guard ["127.0.0.1", "localhost"].contains(request.hostName), request.hostPort == port else { throw LocalConsoleFailure.forbidden }
            if request.path == "/launch", request.method == "GET" {
                guard request.query["token"] == sessionToken else { throw LocalConsoleFailure.unauthorized }
                return .redirect(location: "/", cookie: sessionCookie)
            }
            guard request.cookies["scopeproof_local"] == sessionToken else { throw LocalConsoleFailure.unauthorized }
            if request.method != "GET" {
                guard request.headers["origin"] == displayURL?.absoluteString.dropLast().description,
                      request.headers["sec-fetch-site"] == "same-origin",
                      request.headers["content-type"]?.lowercased().hasPrefix("application/json") == true else { throw LocalConsoleFailure.forbidden }
            }

            switch (request.method, request.path) {
            case ("GET", "/"):
                return .data(status: 200, contentType: "text/html; charset=utf-8", body: Data(LocalConsoleAssets.html.utf8))
            case ("GET", "/assets/app.css"):
                return .data(status: 200, contentType: "text/css; charset=utf-8", body: Data(LocalConsoleAssets.css.utf8), cache: "private, max-age=3600")
            case ("GET", "/assets/app.js"):
                return .data(status: 200, contentType: "text/javascript; charset=utf-8", body: Data(LocalConsoleAssets.javascript.utf8), cache: "private, max-age=3600")
            case ("GET", "/api/status"):
                let index = try evidenceIndex()
                try index.sync(entries: CaptureHistory.entries(in: evidenceRoot))
                let server = preferences.serverURL?.absoluteString ?? ""
                let hosted = BackendTrust.normalizedOrigin(preferences.serverURL).flatMap(KeychainStore.readToken(for:)) != nil
                let auditValid = try index.verifyAuditChain()
                let s3Settings = preferences.s3Storage
                return .codable(Status(
                    localUser: NSFullUserName(), evidenceRoot: evidenceRoot.path,
                    indexState: auditValid ? "Ready · loopback only · audit verified" : "Audit verification failed",
                    hostedConnected: hosted, hostedServer: server, autoUpload: preferences.autoUpload,
                    retentionDays: preferences.retentionDays, summary: try index.summary(),
                    s3Configured: s3Settings.isConfigured, s3InventoryState: s3InventoryState(settings: s3Settings),
                    s3Bucket: s3Settings.bucket, s3Prefix: s3Settings.prefix,
                    s3DownloadsAllowed: s3Settings.downloadsAllowed
                ))
            case ("GET", "/api/library"):
                return .codable(try await libraryPayload(forceS3Refresh: request.query["refreshS3"] == "1"))
            case ("GET", "/api/evidence"):
                let index = try evidenceIndex()
                try index.sync(entries: CaptureHistory.entries(in: evidenceRoot))
                let query = LocalEvidenceQuery(search: request.query["search"] ?? "", complianceArea: request.query["complianceArea"] ?? "", controlID: request.query["controlID"] ?? "", reviewStatus: request.query["reviewStatus"] ?? "")
                let evidence = try index.search(query)
                let all = try index.search(LocalEvidenceQuery(), limit: 1_000)
                return .codable(EvidencePayload(evidence: evidence, facets: .init(frameworks: Array(Set(all.map(\.complianceArea))).sorted(), controls: Array(Set(all.map(\.controlID))).sorted())))
            case ("POST", "/api/actions/open-folder"):
                try ensureEvidenceRoot()
                NSWorkspace.shared.open(evidenceRoot)
                try evidenceIndex().recordAudit(action: "folder.opened", resourceID: "evidence-root")
                return .json(status: 200, object: ["ok": true])
            case ("POST", "/api/actions/capture"):
                requestCapture()
                try evidenceIndex().recordAudit(action: "capture.requested", resourceID: "menu-bar-app")
                return .json(status: 202, object: ["ok": true])
            case ("POST", "/api/actions/open-s3-browser"):
                guard preferences.s3Storage.isConfigured else { throw S3StorageFailure.notConfigured }
                openS3Browser()
                try evidenceIndex().recordAudit(action: "s3.browser.opened", resourceID: "configured-prefix")
                return .json(status: 200, object: ["ok": true])
            default:
                if request.method == "GET", let evidenceID = routeEvidenceID(request.path, suffix: "/image") {
                    return try imageResponse(evidenceID: evidenceID)
                }
                if request.method == "GET", let evidenceID = routeEvidenceID(request.path, suffix: "/s3-image") {
                    return try await s3ImageResponse(evidenceID: evidenceID)
                }
                if request.method == "POST", let evidenceID = routeEvidenceID(request.path, suffix: "/review") {
                    return try reviewResponse(evidenceID: evidenceID, request: request)
                }
                if request.method == "POST", request.path == "/api/actions/reveal" {
                    let body = try decode(ActionBody.self, request.body)
                    let entry = try entry(for: body.evidenceID)
                    NSWorkspace.shared.activateFileViewerSelecting([entry.imageURL])
                    try evidenceIndex().recordAudit(action: "evidence.revealed", resourceID: body.evidenceID)
                    return .json(status: 200, object: ["ok": true])
                }
                throw LocalConsoleFailure.notFound
            }
        } catch {
            let status: Int
            switch error {
            case LocalConsoleFailure.unauthorized: status = 401
            case LocalConsoleFailure.forbidden: status = 403
            case LocalConsoleFailure.notFound: status = 404
            case LocalConsoleFailure.invalidBody: status = 400
            default: status = 500
            }
            return .json(status: status, object: ["error": error.localizedDescription])
        }
    }

    private func imageResponse(evidenceID: String) throws -> HTTPResponse {
        let entry = try entry(for: evidenceID)
        let data = try Data(contentsOf: entry.imageURL, options: [.mappedIfSafe])
        guard data.count <= 40 * 1024 * 1024, data.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), sha256(data) == entry.manifest.sha256 else {
            throw LocalConsoleFailure.invalidBody("The evidence image failed its integrity check.")
        }
        return .data(status: 200, contentType: "image/png", body: data, cache: "private, max-age=60")
    }

    private func s3ImageResponse(evidenceID: String) async throws -> HTTPResponse {
        guard evidenceID.count <= 80,
              evidenceID.range(of: #"^EV-[A-Z0-9]+$"#, options: .regularExpression) != nil,
              let cache = s3Cache else {
            throw LocalConsoleFailure.notFound
        }
        let settings = preferences.s3Storage
        guard settings == cache.settings, settings.downloadsAllowed,
              let credentials = KeychainStore.readS3Credentials(),
              let binding = KeychainStore.readS3VerifiedDestination(), binding.matches(settings) else {
            throw S3StorageFailure.verificationRequired
        }
        let entries = CaptureHistory.entries(in: evidenceRoot)
        let receiptBindings = EvidenceLibraryBuilder.verifiedReceiptBindings(
            entries: entries, settings: settings, destination: binding
        )
        let screenshots = EvidenceLibraryBuilder.s3Screenshots(
            objects: cache.objects, prefix: settings.prefix, receiptBindings: receiptBindings
        )
        guard let screenshot = screenshots.first(where: { $0.evidenceID == evidenceID }),
              screenshot.size >= 0, screenshot.size <= 40 * 1024 * 1024 else {
            throw LocalConsoleFailure.notFound
        }
        if let localEntry = entries.first(where: { $0.manifest.evidenceID == evidenceID }) {
            guard screenshot.receiptBinding?.imageSHA256 == localEntry.manifest.sha256 else {
                throw S3StorageFailure.invalidEvidence
            }
        }
        let previewDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("Scopeproof Console Preview-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: previewDirectory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: previewDirectory) }
        let previewURL = previewDirectory.appendingPathComponent("\(evidenceID).png", isDirectory: false)
        let manifestURL = previewDirectory.appendingPathComponent("\(evidenceID).json", isDirectory: false)
        let manifestDownload = try await s3Service.downloadObject(
            screenshot.manifestObject, settings: settings, credentials: credentials,
            binding: binding, to: manifestURL
        )
        let manifestData = try Data(contentsOf: manifestURL, options: [.mappedIfSafe])
        guard manifestData.count <= 2 * 1024 * 1024,
              manifestDownload.versionID == screenshot.manifestObject.versionID,
              let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: manifestData),
              manifest.schemaVersion == 6,
              manifest.evidenceID == screenshot.evidenceID,
              manifest.screenshotFilename == screenshot.filename,
              manifest.sha256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              manifest.safetyScanSha256 == manifest.sha256,
              screenshot.receiptBinding.map({
                  $0.manifestVersionID == manifestDownload.versionID &&
                  $0.manifestSHA256 == manifestDownload.sha256
              }) ?? true else {
            throw S3StorageFailure.invalidEvidence
        }
        let imageDownload = try await s3Service.downloadObject(
            screenshot.object, settings: settings, credentials: credentials,
            binding: binding, to: previewURL
        )
        let data = try Data(contentsOf: previewURL, options: [.mappedIfSafe])
        guard data.count <= 40 * 1024 * 1024,
              data.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
              imageDownload.versionID == screenshot.object.versionID,
              imageDownload.sha256 == manifest.sha256,
              validatedPNGDimensions(data, width: manifest.pixelWidth, height: manifest.pixelHeight),
              screenshot.receiptBinding.map({
                  $0.imageVersionID == imageDownload.versionID &&
                  $0.imageSHA256 == imageDownload.sha256
              }) ?? true else {
            throw S3StorageFailure.unsupportedDownloadedContent
        }
        return .data(status: 200, contentType: "image/png", body: data)
    }

    private func libraryPayload(forceS3Refresh: Bool) async throws -> EvidenceLibraryPayload {
        let index = try evidenceIndex()
        let entries = CaptureHistory.entries(in: evidenceRoot)
        try index.sync(entries: entries)
        let local = try index.search(LocalEvidenceQuery(), limit: 5_000)
        let settings = preferences.s3Storage
        var s3: [S3ScreenshotSummary] = []
        var state = s3InventoryState(settings: settings)
        var warning: String?

        if settings.isConfigured,
           let credentials = KeychainStore.readS3Credentials(),
            let binding = KeychainStore.readS3VerifiedDestination(), binding.matches(settings) {
            do {
                let objects: [S3StoredObject]
                if !forceS3Refresh, let cache = s3Cache,
                   cache.settings == settings, Date().timeIntervalSince(cache.loadedAt) < 60 {
                    objects = cache.objects
                } else {
                    objects = try await s3Service.listObjects(settings: settings, credentials: credentials, binding: binding)
                    s3Cache = S3InventoryCache(settings: settings, loadedAt: Date(), objects: objects)
                }
                let receiptBindings = EvidenceLibraryBuilder.verifiedReceiptBindings(
                    entries: entries, settings: settings, destination: binding
                )
                s3 = EvidenceLibraryBuilder.s3Screenshots(
                    objects: objects, prefix: settings.prefix, receiptBindings: receiptBindings
                )
                state = "Connected"
            } catch {
                state = "Unavailable"
                warning = "S3 inventory is temporarily unavailable. Local evidence is still shown. Verify the destination, permissions, network, and temporary AWS session, then refresh."
            }
        } else if settings.isConfigured {
            warning = "S3 is configured but not currently verified. Local evidence is shown; use S3 Evidence Storage in the menu-bar app to verify the destination."
        }

        let evidence = EvidenceLibraryBuilder.merge(local: local, s3: s3, s3PreviewsAllowed: settings.downloadsAllowed)
        return EvidenceLibraryPayload(
            evidence: evidence,
            facets: .init(
                frameworks: Array(Set(evidence.map(\.complianceArea))).sorted(),
                controls: Array(Set(evidence.map(\.controlID))).sorted(),
                assessmentPeriods: Array(Array(Set(evidence.map(\.assessmentPeriod).filter { !$0.isEmpty })).sorted().reversed()),
                storageLocations: EvidenceStorageLocation.allDisplayValues
            ),
            storage: .init(
                mode: state == "Connected" ? "Local + S3" : "Local", s3State: state,
                bucket: settings.isConfigured ? settings.bucket : "", prefix: settings.isConfigured ? settings.prefix : "",
                downloadsAllowed: settings.downloadsAllowed,
                warning: warning, refreshedAt: ISO8601DateFormatter().string(from: Date())
            )
        )
    }

    private func s3InventoryState(settings: S3StorageSettings) -> String {
        guard settings.isConfigured else { return "Not configured" }
        guard KeychainStore.readS3Credentials() != nil,
              KeychainStore.readS3VerifiedDestination()?.matches(settings) == true else { return "Verification required" }
        return "Ready"
    }

    private func reviewResponse(evidenceID: String, request: HTTPRequest) throws -> HTTPResponse {
        let body = try decode(ReviewBody.self, request.body)
        guard let status = EvidenceReviewStatus(rawValue: body.status) else { throw LocalConsoleFailure.invalidBody("Select a valid lifecycle status.") }
        let notes = body.notes.trimmingCharacters(in: .whitespacesAndNewlines)
        if [.approved, .rejected, .superseded].contains(status), notes.count < 20 { throw LocalConsoleFailure.invalidBody("Approval, rejection, and supersession require a rationale of at least 20 characters.") }
        guard !body.reviewer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw LocalConsoleFailure.invalidBody("A reviewer is required.") }
        let entry = try entry(for: evidenceID)
        guard EvidenceLifecycleStore.verify(entry.lifecycle, artifactSha256: entry.manifest.sha256) else { throw EvidenceLifecycleFailure.integrityFailure }
        _ = try EvidenceLifecycleStore.update(entry: entry, status: status, owner: body.owner, reviewer: body.reviewer, notes: notes, tags: body.tags)
        let index = try evidenceIndex()
        try index.sync(entries: CaptureHistory.entries(in: evidenceRoot))
        try index.recordAudit(action: "evidence.reviewed", resourceID: evidenceID, details: ["status": status.rawValue, "reviewer": String(body.reviewer.prefix(160))])
        return .json(status: 200, object: ["ok": true])
    }

    private func entry(for evidenceID: String) throws -> CaptureHistoryEntry {
        guard evidenceID.count <= 80, evidenceID.range(of: #"^EV-[A-Z0-9]+$"#, options: .regularExpression) != nil,
              let entry = CaptureHistory.entries(in: evidenceRoot).first(where: { $0.manifest.evidenceID == evidenceID }),
              CaptureHistory.isWithinReadableRoots(entry.imageURL, primaryDirectory: evidenceRoot),
              CaptureHistory.isWithinReadableRoots(entry.manifestURL, primaryDirectory: evidenceRoot) else { throw LocalConsoleFailure.notFound }
        return entry
    }

    private func ensureEvidenceRoot() throws {
        try FileManager.default.createDirectory(at: evidenceRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    private func evidenceIndex() throws -> LocalEvidenceIndex {
        if let storedIndex { return storedIndex }
        guard let supportRoot = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw LocalConsoleFailure.startup("The Application Support folder is unavailable.")
        }
        let support = supportRoot.appendingPathComponent("Scopeproof Capture", isDirectory: true)
        let index = try LocalEvidenceIndex(databaseURL: support.appendingPathComponent("local-console.sqlite3"), auditKeyData: KeychainStore.localAuditKey())
        storedIndex = index
        return index
    }

    private func routeEvidenceID(_ path: String, suffix: String) -> String? {
        let prefix = "/api/evidence/"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { return nil }
        return String(path.dropFirst(prefix.count).dropLast(suffix.count)).removingPercentEncoding
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        guard data.count <= 16 * 1024 else { throw LocalConsoleFailure.invalidBody("The request is too large.") }
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw LocalConsoleFailure.invalidBody("The request body is invalid.") }
    }

    private var sessionCookie: String { "scopeproof_local=\(sessionToken); Path=/; HttpOnly; SameSite=Strict; Max-Age=43200" }
    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    private func validatedPNGDimensions(_ data: Data, width: Int, height: Int) -> Bool {
        guard width > 0, height > 0, width <= 32_768, height <= 32_768,
              width.multipliedReportingOverflow(by: height).overflow == false,
              width * height <= 100_000_000,
              let source = CGImageSourceCreateWithData(data as CFData, nil),
              CGImageSourceGetCount(source) == 1,
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue == width,
              (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue == height else { return false }
        return true
    }
    private static func randomToken(byteCount: Int) -> String {
        Data((0..<byteCount).map { _ in UInt8.random(in: .min ... .max) }).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private struct ActionBody: Decodable { let evidenceID: String }
private struct ReviewBody: Decodable { let status: String; let owner: String; let reviewer: String; let notes: String; let tags: [String] }
private struct EvidencePayload: Encodable {
    struct Facets: Encodable { let frameworks: [String]; let controls: [String] }
    let evidence: [LocalEvidenceRecord]
    let facets: Facets
}

private struct EvidenceLibraryPayload: Encodable {
    struct Facets: Encodable {
        let frameworks: [String]
        let controls: [String]
        let assessmentPeriods: [String]
        let storageLocations: [String]
    }
    struct Storage: Encodable {
        let mode: String
        let s3State: String
        let bucket: String
        let prefix: String
        let downloadsAllowed: Bool
        let warning: String?
        let refreshedAt: String
    }
    let evidence: [EvidenceLibraryRecord]
    let facets: Facets
    let storage: Storage
}

private struct S3InventoryCache {
    let settings: S3StorageSettings
    let loadedAt: Date
    let objects: [S3StoredObject]
}

private extension EvidenceStorageLocation {
    static let allDisplayValues = [local.rawValue, s3.rawValue, localAndS3.rawValue]
}

private struct HTTPRequest {
    let method: String
    let path: String
    let query: [String: String]
    let headers: [String: String]
    let cookies: [String: String]
    let body: Data
    let expectedLength: Int

    var hostName: String {
        guard let host = headers["host"] else { return "" }
        if host.hasPrefix("[") { return String(host.dropFirst().prefix { $0 != "]" }) }
        return host.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
    }
    var hostPort: UInt16? {
        guard let host = headers["host"] else { return nil }
        if host.hasPrefix("[") { return host.split(separator: "]:").last.flatMap { UInt16($0) } }
        return host.split(separator: ":", maxSplits: 1).dropFirst().first.flatMap { UInt16($0) }
    }

    static func parse(_ data: Data) -> HTTPRequest? {
        let delimiter = Data("\r\n\r\n".utf8)
        guard let range = data.range(of: delimiter), range.lowerBound <= 32 * 1024,
              let headerText = String(data: data[..<range.lowerBound], encoding: .utf8) else { return nil }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ")
        guard parts.count == 3, parts[2] == "HTTP/1.1", ["GET", "POST"].contains(String(parts[0])) else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let separator = line.firstIndex(of: ":") else { return nil }
            let name = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, headers[name] == nil else { return nil }
            headers[name] = value
        }
        let contentLength = Int(headers["content-length"] ?? "0") ?? -1
        guard contentLength >= 0, contentLength <= 2 * 1024 * 1024 else { return nil }
        let bodyStart = range.upperBound
        let expected = bodyStart + contentLength
        guard data.count >= expected else {
            return HTTPRequest(method: String(parts[0]), path: "", query: [:], headers: headers, cookies: [:], body: Data(), expectedLength: expected)
        }
        guard var components = URLComponents(string: String(parts[1])), let path = components.percentEncodedPath.removingPercentEncoding, path.hasPrefix("/") else { return nil }
        guard headers["transfer-encoding"] == nil else { return nil }
        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard query[item.name] == nil, let value = item.value else { return nil }
            query[item.name] = String(value.prefix(500))
        }
        var cookies: [String: String] = [:]
        for item in (headers["cookie"] ?? "").split(separator: ";") {
            let pair = item.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard pair.count == 2, cookies[pair[0]] == nil else { return nil }
            cookies[pair[0]] = pair[1]
        }
        components.query = nil
        return HTTPRequest(method: String(parts[0]), path: path, query: query, headers: headers, cookies: cookies, body: data.subdata(in: bodyStart..<expected), expectedLength: expected)
    }
}

private final class ListenerStartupGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false

    func resume(_ continuation: CheckedContinuation<UInt16, Error>, with result: Result<UInt16, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        lock.unlock()
        continuation.resume(with: result)
    }
}

private struct HTTPResponse {
    let status: Int
    let headers: [String: String]
    let body: Data

    var encoded: Data {
        let reason = [200: "OK", 202: "Accepted", 302: "Found", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 413: "Payload Too Large", 500: "Internal Server Error"][status] ?? "Response"
        var merged = headers
        merged["Content-Length"] = String(body.count)
        merged["Connection"] = "close"
        merged["X-Content-Type-Options"] = "nosniff"
        merged["Referrer-Policy"] = "no-referrer"
        merged["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        merged["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
        let header = (["HTTP/1.1 \(status) \(reason)"] + merged.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" } + ["", ""]).joined(separator: "\r\n")
        return Data(header.utf8) + body
    }

    static func data(status: Int, contentType: String, body: Data, cache: String = "private, no-store") -> HTTPResponse {
        HTTPResponse(status: status, headers: ["Content-Type": contentType, "Cache-Control": cache], body: body)
    }
    static func codable<T: Encodable>(_ value: T) -> HTTPResponse {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return data(status: 200, contentType: "application/json; charset=utf-8", body: (try? encoder.encode(value)) ?? Data("{\"error\":\"Encoding failed\"}".utf8))
    }
    static func json(status: Int, object: [String: Any]) -> HTTPResponse {
        data(status: status, contentType: "application/json; charset=utf-8", body: (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8))
    }
    static func redirect(location: String, cookie: String) -> HTTPResponse {
        HTTPResponse(status: 302, headers: ["Location": location, "Set-Cookie": cookie, "Cache-Control": "no-store"], body: Data())
    }
}
