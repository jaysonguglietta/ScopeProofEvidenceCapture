import CryptoKit
import Foundation

enum AWSCollectorUploadFailure: LocalizedError {
    case reconcile, intent, scope, noMapping
    var errorDescription: String? {
        switch self {
        case .reconcile: return "A previous upload may have committed. This Mac will check server status, not silently create another object version. If processing remains quarantined, ask your administrator to reconcile the displayed cloud evidence ID."
        case .intent: return "The upload capability did not preserve the expected tenant, checksum, headers, expiry, encryption, and AWS destination. No bytes were sent."
        case .scope: return "The capture or saved assessment scope no longer matches your current membership and assessment. Re-select scope; existing evidence is never relabeled."
        case .noMapping: return "No submitted AWS mapping exists for this exact local artifact."
        }
    }
}

struct AWSCollectorUploadIntent: Codable, Sendable {
    struct Upload: Codable, Sendable { let method: String; let url: String; let requiredHeaders: [String: String] }
    let uploadIntentId: String
    let evidenceId: String
    let expiresAt: String
    let upload: Upload
}

struct AWSCollectorEvidenceStatus: Codable, Sendable {
    let tenantId: String
    let evidenceId: String
    let assessmentId: String
    let controlId: String
    let systemName: String
    let title: String
    let status: String
    let revision: Int
    let createdBy: String
    let approvedBy: String?
    let expiresAt: String
    let capturedAt: String
    let checksumSha256: String
    let byteSize: Int
    var presentation: String {
        switch status {
        case "QUARANTINED": return "Quarantined — not yet validated; no review approval implied."
        case "VALIDATING": return "Server validation / scanning in progress."
        case "NEEDS_REVIEW": return "Validation completed; awaiting an independent reviewer."
        case "APPROVED": return "Approved by the server-recorded reviewer."
        case "REJECTED": return "Rejected by validation or review."
        case "EXPIRED": return "Expired under server retention policy."
        case "PURGED": return "Purged by server retention processing."
        default: return "Unknown server state — no success claim."
        }
    }
}

/// Protected local transaction journal. A presigned URL is a capability and is
/// retained only in device-only Keychain, never in a receipt sidecar or UI log.
struct AWSCollectorUploadRecord: Codable, Sendable {
    let schemaVersion: Int
    let scope: String
    let selection: AWSCollectorSelection
    let localEvidenceId: String
    let manifestSHA256: String
    let imageSHA256: String
    let byteSize: Int
    let cloudEvidenceId: String
    let idempotencyKey: String
    let sequence: Int
    let requestData: Data
    var intent: AWSCollectorUploadIntent?
    var putAttempted: Bool
    var putCompleted: Bool
    var serverStatus: AWSCollectorEvidenceStatus?
}

extension AWSCollectorService {
    func submit(entry: CaptureHistoryEntry, selection: AWSCollectorSelection, configuration: AWSCollectorConfiguration,
        put: @Sendable (URLRequest, String) async throws -> Void = AWSCollectorUploadHTTP.put) async throws -> AWSCollectorEvidenceStatus {
        let profile = try currentProfile(configuration)
        let workspace = TenantWorkspaceBinding(tenantID: selection.tenantId, workspaceID: selection.assessmentId)
        guard selection.userId == profile.userId, selection.tenantId == profile.tenantId,
              selection.apiOrigin == configuration.apiOrigin.absoluteString, entry.manifest.belongs(to: workspace),
              entry.manifest.controlID == selection.controlId, entry.manifest.system == selection.systemName else { throw AWSCollectorUploadFailure.scope }
        let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: workspace)
        guard artifact.imageData.count <= 26_214_400, artifact.manifest.safetyStatus == "passed" || artifact.manifest.safetyStatus == "redacted" else { throw AWSCollectorUploadFailure.scope }
        let manifestSHA = LocalEvidenceArchive.digest(artifact.manifestData)
        let device = try KeychainStore.awsCollectorIdentity(scope: configuration.keyScope, userId: profile.userId)
        guard device.deviceId == selection.deviceId else { throw AWSCollectorFailure.enrollmentRejected }
        var record: AWSCollectorUploadRecord
        if let previous = try KeychainStore.awsCollectorUpload(scope: configuration.keyScope, userId: profile.userId, manifestSHA: manifestSHA) {
            guard previous.schemaVersion == 1, previous.scope == configuration.keyScope,
                  previous.selection.userId == selection.userId, previous.selection.assessmentId == selection.assessmentId,
                  previous.selection.controlId == selection.controlId, previous.selection.systemName == selection.systemName,
                  previous.selection.deviceId == device.deviceId, previous.localEvidenceId == entry.manifest.evidenceID,
                  previous.manifestSHA256 == manifestSHA, previous.imageSHA256 == artifact.manifest.sha256,
                  previous.byteSize == artifact.imageData.count else { throw AWSCollectorUploadFailure.scope }
            record = previous
            // A submitted/ambiguous PUT is never repeated automatically. Query
            // the authoritative server state without allocating another nonce.
            if record.putAttempted || record.serverStatus != nil { return try await refreshStatus(record: record, configuration: configuration) }
        } else {
            try await verifyCurrentScope(selection, configuration: configuration)
            let sequence = try KeychainStore.nextAWSCollectorUploadSequence(scope: configuration.keyScope, userId: profile.userId)
            record = try Self.prepareUpload(artifact: artifact, selection: selection, profile: profile,
                device: device, scope: configuration.keyScope, sequence: sequence)
            try KeychainStore.saveAWSCollectorUpload(record)
        }
        if record.intent == nil {
            guard let body = try JSONSerialization.jsonObject(with: record.requestData) as? [String: Any],
                  let proof = body["deviceManifest"] as? [String: Any], proof["challenge"] as? String == profile.uploadProofChallenge,
                  let signedAt = (proof["signedAt"] as? String).flatMap(Self.instant), abs(signedAt.timeIntervalSinceNow) < 300 else { throw AWSCollectorUploadFailure.reconcile }
            let response = try await api(path: "v1/upload-intents", body: body, configuration: configuration)
            record.intent = try JSONDecoder().decode(AWSCollectorUploadIntent.self, from: response)
            _ = try Self.putRequest(record: record, imageData: artifact.imageData)
            try KeychainStore.saveAWSCollectorUpload(record)
        }
        let request = try Self.putRequest(record: record, imageData: artifact.imageData)
        // Reload/re-hash the original bytes just before crossing the disclosure
        // boundary. A review, workspace change, or replaced file cannot relabel it.
        let current = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: workspace)
        guard current.manifestData == artifact.manifestData, current.imageData == artifact.imageData else { throw AWSCollectorUploadFailure.scope }
        try Task.checkCancellation()
        record.putAttempted = true
        try KeychainStore.saveAWSCollectorUpload(record)
        try await put(request, artifact.manifest.sha256)
        record.putCompleted = true
        try KeychainStore.saveAWSCollectorUpload(record)
        return try await refreshStatus(record: record, configuration: configuration)
    }

    func refreshStatus(record: AWSCollectorUploadRecord, configuration: AWSCollectorConfiguration) async throws -> AWSCollectorEvidenceStatus {
        let profile = try currentProfile(configuration)
        guard record.scope == configuration.keyScope, record.selection.tenantId == profile.tenantId, record.selection.userId == profile.userId else { throw AWSCollectorUploadFailure.scope }
        let response = try await api(path: "v1/customer/collector-evidence/status", body: ["evidenceId": record.cloudEvidenceId], configuration: configuration)
        let status = try JSONDecoder().decode(AWSCollectorEvidenceStatus.self, from: response)
        guard status.tenantId == profile.tenantId, status.evidenceId == record.cloudEvidenceId,
              status.assessmentId == record.selection.assessmentId, status.controlId == record.selection.controlId,
              status.systemName == record.selection.systemName, status.createdBy == profile.userId,
              status.checksumSha256 == record.imageSHA256, status.byteSize == record.byteSize, status.revision >= 0,
              ["QUARANTINED", "VALIDATING", "NEEDS_REVIEW", "APPROVED", "REJECTED", "EXPIRED", "PURGED"].contains(status.status),
              status.status != "APPROVED" || (status.approvedBy != nil && status.approvedBy != status.createdBy) else { throw AWSCollectorFailure.invalidResponse }
        var updated = record; updated.serverStatus = status
        try KeychainStore.saveAWSCollectorUpload(updated)
        return status
    }

    private func verifyCurrentScope(_ selection: AWSCollectorSelection, configuration: AWSCollectorConfiguration) async throws {
        var cursor: String?
        for _ in 0..<20 {
            let page = try await assessments(configuration: configuration, cursor: cursor)
            if let assessment = page.items.first(where: { $0.id == selection.assessmentId }) {
                guard assessment.status == "ACTIVE", assessment.revision == selection.assessmentRevision,
                      assessment.controls.contains(selection.controlId), assessment.systems.contains(selection.systemName),
                      assessment.catalogId == selection.catalogId,
                      page.catalogs.contains(where: { $0.id == selection.catalogId && $0.digestSha256 == selection.catalogDigest && $0.controls.contains(where: { $0.id == selection.controlId }) }) else { throw AWSCollectorUploadFailure.scope }
                return
            }
            guard let next = page.nextCursor, next != cursor else { throw AWSCollectorUploadFailure.scope }
            cursor = next
        }
        throw AWSCollectorUploadFailure.scope
    }

    static func prepareUpload(artifact: ValidatedEvidenceArtifact, selection: AWSCollectorSelection, profile: AWSCollectorProfile,
        device: AWSCollectorDeviceIdentity, scope: String, sequence: Int, now: Date = Date()) throws -> AWSCollectorUploadRecord {
        guard sequence > 0, sequence <= 9_007_199_254_740_991, let challenge = profile.uploadProofChallenge,
              let captured = instant(artifact.manifest.capturedAt) else { throw AWSCollectorUploadFailure.scope }
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let manifestSHA = LocalEvidenceArchive.digest(artifact.manifestData)
        let evidenceID = "evd_" + LocalEvidenceArchive.digest(Data(("scopeproof-local-cloud-map-v1\n" + scope + "\n" + profile.userId + "\n" + device.deviceId + "\n" + manifestSHA).utf8)).prefix(32)
        let nonce = UUID().uuidString.lowercased()
        let proof: [String: Any] = ["schemaVersion": 1, "tenantId": profile.tenantId, "userId": profile.userId,
            "deviceId": device.deviceId, "assessmentId": selection.assessmentId, "controlId": selection.controlId,
            "evidenceId": evidenceID, "expectedSha256": artifact.manifest.sha256, "expectedSize": artifact.imageData.count,
            "contentType": "image/png", "capturedAt": formatter.string(from: captured), "challenge": challenge,
            "nonce": nonce, "sequence": sequence, "signedAt": formatter.string(from: now)]
        let canonical = try JSONSerialization.data(withJSONObject: proof, options: [.sortedKeys, .withoutEscapingSlashes])
        let signature = try P256.Signing.PrivateKey(rawRepresentation: device.privateKey).signature(for: Data("scopeproof-device-upload-manifest-v1\n".utf8) + canonical).rawRepresentation
        let body: [String: Any] = ["idempotencyKey": nonce, "controlId": selection.controlId, "evidenceId": evidenceID,
            "expectedSha256": artifact.manifest.sha256, "expectedSize": artifact.imageData.count, "contentType": "image/png",
            "deviceManifest": proof, "devicePublicKeySpki": try device.publicKey.base64EncodedString(), "deviceSignature": base64URL(signature),
            "assessmentId": selection.assessmentId, "capturedAt": formatter.string(from: captured), "description": artifact.manifest.description,
            "deviceId": device.deviceId, "evidenceType": "SCREENSHOT", "source": "scopeproof-native-capture",
            "systemName": selection.systemName, "title": artifact.manifest.title,
            "metadata": ["localEvidenceId": artifact.manifest.evidenceID, "localManifestSHA256": manifestSHA,
                "localCaptureChainEventHash": artifact.manifest.chainEventHash, "localProvenanceKeyId": artifact.manifest.provenance?.keyID ?? ""]]
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 65_536 else { throw AWSCollectorUploadFailure.scope }
        return AWSCollectorUploadRecord(schemaVersion: 1, scope: scope, selection: selection,
            localEvidenceId: artifact.manifest.evidenceID, manifestSHA256: manifestSHA, imageSHA256: artifact.manifest.sha256,
            byteSize: artifact.imageData.count, cloudEvidenceId: String(evidenceID), idempotencyKey: nonce, sequence: sequence,
            requestData: data, intent: nil, putAttempted: false, putCompleted: false, serverStatus: nil)
    }

    static func putRequest(record: AWSCollectorUploadRecord, imageData: Data, now: Date = Date()) throws -> URLRequest {
        guard let intent = record.intent, intent.evidenceId == record.cloudEvidenceId, resourceID(intent.uploadIntentId, prefix: "upl"),
              intent.upload.method == "PUT", let expires = instant(intent.expiresAt), expires > now, expires <= now.addingTimeInterval(601),
              let url = URL(string: intent.upload.url), intent.upload.url.utf8.count <= 8192,
              url.scheme == "https", url.port == nil, url.user == nil, url.password == nil, url.fragment == nil,
              let host = url.host, host.range(of: #"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"#, options: .regularExpression) != nil,
              url.path == "/tenants/\(record.selection.tenantId)/controls/\(record.selection.controlId)/quarantine/\(intent.uploadIntentId).upload",
              record.byteSize == imageData.count, LocalEvidenceArchive.digest(imageData) == record.imageSHA256 else { throw AWSCollectorUploadFailure.intent }
        let headers = intent.upload.requiredHeaders
        let names: Set<String> = ["content-length", "content-type", "x-amz-checksum-sha256", "x-amz-meta-control-id", "x-amz-meta-evidence-id", "x-amz-meta-expected-sha256", "x-amz-meta-upload-nonce-digest", "x-amz-meta-tenant-id", "x-amz-meta-upload-intent-id", "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context"]
        guard Set(headers.keys) == names, headers.values.allSatisfy({ $0.utf8.count <= 8192 && !$0.contains("\r") && !$0.contains("\n") }),
              headers["content-length"] == String(record.byteSize), headers["content-type"] == "image/png",
              headers["x-amz-checksum-sha256"] == Data(SHA256.hash(data: imageData)).base64EncodedString(),
              headers["x-amz-meta-control-id"] == record.selection.controlId, headers["x-amz-meta-evidence-id"] == record.cloudEvidenceId,
              headers["x-amz-meta-expected-sha256"] == record.imageSHA256, headers["x-amz-meta-tenant-id"] == record.selection.tenantId,
              headers["x-amz-meta-upload-intent-id"] == intent.uploadIntentId,
              // The upload nonce is derived with a server secret, not the
              // device-proof nonce. Preserve its authenticated opaque digest.
              headers["x-amz-meta-upload-nonce-digest"]?.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              headers["x-amz-server-side-encryption"] == "aws:kms", let kms = headers["x-amz-server-side-encryption-aws-kms-key-id"],
              kms.range(of: #"^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$"#, options: .regularExpression) != nil,
              let encodedContext = headers["x-amz-server-side-encryption-context"], let contextData = Data(base64Encoded: encodedContext),
              let context = try JSONSerialization.jsonObject(with: contextData) as? [String: String],
              context == ["scopeproofPurpose": "quarantine", "scopeproofTenantId": record.selection.tenantId] else { throw AWSCollectorUploadFailure.intent }
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let singleton = ["X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-Security-Token", "X-Amz-Signature", "X-Amz-SignedHeaders"]
        let kmsParts = kms.split(separator: ":").map(String.init)
        let dateFormatter = DateFormatter(); dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0); dateFormatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        guard singleton.allSatisfy({ name in query.filter { $0.name == name }.count == 1 }),
              query.first(where: { $0.name == "X-Amz-Algorithm" })?.value == "AWS4-HMAC-SHA256",
              let signed = query.first(where: { $0.name == "X-Amz-SignedHeaders" })?.value,
              Set(signed.split(separator: ";").map(String.init)) == names.union(["host"]),
              let seconds = query.first(where: { $0.name == "X-Amz-Expires" })?.value.flatMap(Int.init), (1...600).contains(seconds),
              let credential = query.first(where: { $0.name == "X-Amz-Credential" })?.value,
              credential.range(of: #"^[A-Z0-9]{8,128}/[0-9]{8}/[a-z0-9-]+/s3/aws4_request$"#, options: .regularExpression) != nil,
              kmsParts.count >= 6, credential.split(separator: "/")[2] == kmsParts[3],
              host.hasSuffix(".s3.\(kmsParts[3]).amazonaws.com" + (kmsParts[1] == "aws-cn" ? ".cn" : "")),
              let securityToken = query.first(where: { $0.name == "X-Amz-Security-Token" })?.value, (16...4096).contains(securityToken.utf8.count),
              query.first(where: { $0.name == "X-Amz-Signature" })?.value?.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              let signedTime = query.first(where: { $0.name == "X-Amz-Date" })?.value.flatMap({ dateFormatter.date(from: $0) }),
              signedTime <= now.addingTimeInterval(5), signedTime.addingTimeInterval(Double(seconds)) > now,
              signedTime.addingTimeInterval(Double(seconds)) <= expires.addingTimeInterval(1) else { throw AWSCollectorUploadFailure.intent }
        var request = URLRequest(url: url); request.httpMethod = "PUT"; request.httpBody = imageData
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        return request
    }
}

private final class AWSCollectorPutRedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}
enum AWSCollectorUploadHTTP {
    static func put(_ request: URLRequest, expectedSHA256: String) async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false; configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData; configuration.timeoutIntervalForResource = 120
        let session = URLSession(configuration: configuration, delegate: AWSCollectorPutRedirectBlocker(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, response.url == request.url, http.statusCode == 200,
              let checksum = http.value(forHTTPHeaderField: "x-amz-checksum-sha256").flatMap({ Data(base64Encoded: $0) }),
              checksum.map({ String(format: "%02x", $0) }).joined() == expectedSHA256,
              let version = http.value(forHTTPHeaderField: "x-amz-version-id"), !version.isEmpty, version != "null" else { throw AWSCollectorUploadFailure.reconcile }
        _ = try await BackendHTTP.collect(bytes, maximumBytes: 64 * 1024)
    }
}
