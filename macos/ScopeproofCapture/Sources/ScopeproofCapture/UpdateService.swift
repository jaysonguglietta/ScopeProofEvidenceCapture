import CryptoKit
import Foundation

struct ReleaseManifest: Codable, Sendable {
    let schemaVersion: Int
    let version: String
    let sequence: Int
    let downloadUrl: URL
    let sha256: String
    let byteSize: Int
    let publishedAt: String
    let expiresAt: String
    let minimumSystemVersion: String
    let teamIdentifier: String
    let designatedRequirement: String
    let keyId: String
    let notes: String

    var signingPayload: Data {
        let notesBase64 = Data(notes.utf8).base64EncodedString()
        return Data(["scopeproof-update-manifest-v1", String(schemaVersion), version, String(sequence), downloadUrl.absoluteString, sha256, String(byteSize), publishedAt, expiresAt, minimumSystemVersion, teamIdentifier, designatedRequirement, keyId, notesBase64].joined(separator: "\n").utf8)
    }
}

struct ReleaseEnvelope: Codable, Sendable {
    let manifest: ReleaseManifest
    let signatureDERBase64: String
}

struct TrustedUpdateKey: Sendable {
    let keyId: String
    let publicKeyX963Base64: String
    let notBefore: Date
    let notAfter: Date
}

enum UpdateFailure: LocalizedError {
    case invalidMetadata(String)
    case untrustedSignature
    case rollback
    case unapprovedDownload
    case invalidArtifact(String)

    var errorDescription: String? {
        switch self {
        case .invalidMetadata(let detail): return "Update metadata is invalid: \(detail)"
        case .untrustedSignature: return "The update was not signed by a currently trusted Scopeproof release key."
        case .rollback: return "The update was rejected because it is older than this Mac's installed or previously verified release."
        case .unapprovedDownload: return "The update download did not use an approved HTTPS origin or attempted a redirect."
        case .invalidArtifact(let detail): return "The downloaded update failed verification: \(detail)"
        }
    }
}

enum ReleaseVerifier {
    static func configuredIdentity(bundle: Bundle = .main) -> (teamIdentifier: String, designatedRequirement: String)? {
        guard let team = bundle.object(forInfoDictionaryKey: "ScopeproofUpdateTeamIdentifier") as? String,
              team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
              let requirement = bundle.object(forInfoDictionaryKey: "ScopeproofUpdateDesignatedRequirement") as? String,
              requirement.count >= 20, requirement.count <= 1_000 else { return nil }
        return (team, requirement)
    }

    static func trustedKeys(bundle: Bundle = .main) -> [TrustedUpdateKey] {
        guard let entries = bundle.object(forInfoDictionaryKey: "ScopeproofUpdatePublicKeys") as? [[String: String]] else { return [] }
        let formatter = ISO8601DateFormatter()
        return entries.compactMap { entry in
            guard let id = entry["keyId"], let key = entry["publicKeyX963Base64"], let start = entry["notBefore"].flatMap(formatter.date), let end = entry["notAfter"].flatMap(formatter.date) else { return nil }
            return TrustedUpdateKey(keyId: id, publicKeyX963Base64: key, notBefore: start, notAfter: end)
        }
    }

    static func verify(_ envelope: ReleaseEnvelope, keys: [TrustedUpdateKey], expectedTeamIdentifier: String, expectedDesignatedRequirement: String, installedVersion: String, highestSequence: Int, now: Date = Date()) throws -> ReleaseManifest {
        let manifest = envelope.manifest
        let formatter = ISO8601DateFormatter()
        guard manifest.schemaVersion == 1, manifest.version.range(of: "^\\d+\\.\\d+\\.\\d+$", options: .regularExpression) != nil, manifest.sequence > 0, manifest.byteSize > 0, manifest.byteSize <= 500 * 1024 * 1024,
              manifest.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              manifest.teamIdentifier == expectedTeamIdentifier, manifest.designatedRequirement == expectedDesignatedRequirement,
              let published = formatter.date(from: manifest.publishedAt), let expires = formatter.date(from: manifest.expiresAt),
              published <= now.addingTimeInterval(300), expires > now, expires.timeIntervalSince(published) <= 45 * 86_400,
              compareVersions(currentSystemVersion(), manifest.minimumSystemVersion) != .orderedAscending else {
            throw UpdateFailure.invalidMetadata("version, sequence, digest, platform, or validity constraints failed")
        }
        guard let trusted = keys.first(where: { $0.keyId == manifest.keyId && $0.notBefore <= published && $0.notAfter >= expires }),
              let keyData = Data(base64Encoded: trusted.publicKeyX963Base64),
              let signatureData = Data(base64Encoded: envelope.signatureDERBase64),
              let publicKey = try? P256.Signing.PublicKey(x963Representation: keyData),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureData),
              publicKey.isValidSignature(signature, for: manifest.signingPayload) else { throw UpdateFailure.untrustedSignature }
        if manifest.sequence < highestSequence || compareVersions(manifest.version, installedVersion) == .orderedAscending { throw UpdateFailure.rollback }
        return manifest
    }

    static func compareVersions(_ left: String, _ right: String) -> ComparisonResult {
        let a = left.split(separator: ".").prefix(3).map { Int($0.split(separator: "-")[0]) ?? 0 }
        let b = right.split(separator: ".").prefix(3).map { Int($0.split(separator: "-")[0]) ?? 0 }
        for index in 0..<3 { let l = index < a.count ? a[index] : 0; let r = index < b.count ? b[index] : 0; if l != r { return l < r ? .orderedAscending : .orderedDescending } }
        return .orderedSame
    }

    private static func currentSystemVersion() -> String {
        let value = ProcessInfo.processInfo.operatingSystemVersion
        return "\(value.majorVersion).\(value.minorVersion).\(value.patchVersion)"
    }
}

actor UpdateService {
    private let approvedDownloadOrigins: Set<String> = ["https://scopeproof-pci.jayson-guglietta.chatgpt.site", "https://github.com"]
    private var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.5.1" }

    func check(serverURL: URL?) async throws -> ReleaseManifest? {
        guard let server = BackendTrust.normalizedOrigin(serverURL) else { throw UploadFailure.invalidServer }
        guard let token = KeychainStore.readToken(for: server), !token.isEmpty else { throw UploadFailure.notConfigured }
        var request = URLRequest(url: server.appendingPathComponent("api/native/releases/latest"))
        request.timeoutInterval = 20
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(appVersion, forHTTPHeaderField: "X-Scopeproof-Version")
        let (data, response) = try await BackendHTTP.data(for: request, audience: server)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), data.count <= 32 * 1024,
              let envelope = try? JSONDecoder().decode(ReleaseEnvelope.self, from: data) else { throw UploadFailure.invalidResponse }
        guard let identity = ReleaseVerifier.configuredIdentity() else { throw UpdateFailure.invalidMetadata("the compiled update identity is not configured") }
        let release = try ReleaseVerifier.verify(envelope, keys: ReleaseVerifier.trustedKeys(), expectedTeamIdentifier: identity.teamIdentifier, expectedDesignatedRequirement: identity.designatedRequirement, installedVersion: appVersion, highestSequence: KeychainStore.highestUpdateSequence())
        return ReleaseVerifier.compareVersions(release.version, appVersion) == .orderedSame ? nil : release
    }

    func downloadAndVerify(_ manifest: ReleaseManifest) async throws -> URL {
        guard manifest.downloadUrl.pathExtension.lowercased() == "zip" else { throw UpdateFailure.invalidArtifact("Only signed ZIP releases are accepted.") }
        let (download, _) = try await BackendHTTP.download(manifest.downloadUrl, approvedOrigins: approvedDownloadOrigins, maximumBytes: manifest.byteSize)
        defer { try? FileManager.default.removeItem(at: download) }
        let data = try Data(contentsOf: download, options: [.mappedIfSafe])
        guard data.count == manifest.byteSize, SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == manifest.sha256 else { throw UpdateFailure.invalidArtifact("SHA-256 or byte size does not match the signed manifest.") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-update-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let entries = try run("/usr/bin/zipinfo", ["-1", download.path]).split(separator: "\n").map(String.init)
        guard !entries.isEmpty, entries.count <= 10_000, entries.allSatisfy({ !$0.hasPrefix("/") && !$0.split(separator: "/").contains("..") && !$0.contains("\0") }) else { throw UpdateFailure.invalidArtifact("The archive contains an unsafe path.") }
        _ = try run("/usr/bin/ditto", ["-x", "-k", download.path, root.path])
        let extracted = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isSymbolicLinkKey])?.allObjects as? [URL] ?? []
        guard try extracted.allSatisfy({ try $0.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true }) else { throw UpdateFailure.invalidArtifact("The archive contains a symbolic link.") }
        let apps = extracted.filter { $0.lastPathComponent == "Scopeproof Capture.app" }
        guard apps.count == 1, (try apps[0].resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true else { throw UpdateFailure.invalidArtifact("The archive must contain exactly one non-symlink Scopeproof Capture.app.") }
        let app = apps[0]
        _ = try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", "-R", manifest.designatedRequirement, app.path])
        let signing = try run("/usr/bin/codesign", ["-dv", "--verbose=4", app.path], includeStandardError: true)
        guard signing.contains("TeamIdentifier=\(manifest.teamIdentifier)") else { throw UpdateFailure.invalidArtifact("Developer ID team does not match the signed manifest.") }
        _ = try run("/usr/sbin/spctl", ["-a", "-t", "exec", "-vv", app.path], includeStandardError: true)
        _ = try run("/usr/bin/xcrun", ["stapler", "validate", app.path], includeStandardError: true)
        let updates = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Scopeproof Capture/Verified Updates", isDirectory: true)
        try FileManager.default.createDirectory(at: updates, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let destination = updates.appendingPathComponent("Scopeproof-Capture-\(manifest.version).zip")
        if FileManager.default.fileExists(atPath: destination.path) { try FileManager.default.removeItem(at: destination) }
        try FileManager.default.copyItem(at: download, to: destination)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        try KeychainStore.saveHighestUpdateSequence(manifest.sequence)
        return destination
    }

    private func run(_ executable: String, _ arguments: [String], includeStandardError: Bool = false) throws -> String {
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        let output = Pipe(); process.standardOutput = output; let error = Pipe(); process.standardError = error
        try process.run(); process.waitUntilExit()
        let stdout = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let stderr = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else { throw UpdateFailure.invalidArtifact(String(stderr.prefix(500))) }
        return includeStandardError ? stdout + stderr : stdout
    }
}
