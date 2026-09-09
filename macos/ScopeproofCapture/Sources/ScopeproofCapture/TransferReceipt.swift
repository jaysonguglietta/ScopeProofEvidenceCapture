import CryptoKit
import Foundation

enum TransferReceiptKind: String, Codable, CaseIterable, Sendable { case hosted, jira, s3 }

enum TransferReceiptFailure: LocalizedError {
    case unverified
    var errorDescription: String? {
        "A transfer receipt is missing, malformed, altered, or belongs to another artifact or destination. Verify the remote outcome before retrying. For Jira, reconcile existing attachments first; a filename alone is not proof of delivery."
    }
}

/// A device-sealed record of an authenticated network response, not a claim that
/// the provider's embedded signing key/HMAC has an independently trusted identity.
struct TransferReceipt: Codable, Sendable {
    static let domain = "scopeproof-authenticated-transfer-response-v1"
    static let method = "authenticated-response-and-device-seal-v1"
    let schemaVersion: Int
    let verificationMethod: String
    let kind: TransferReceiptKind
    let evidenceID: String
    let tenantID: String
    let workspaceID: String
    let screenshotSHA256: String
    let manifestSHA256: String
    let destination: [String: String]
    let recordedAt: String
    let payload: Data
    let payloadSHA256: String
    var provenance: LocalProvenanceSignature?

    static func url(for entry: CaptureHistoryEntry, kind: TransferReceiptKind) -> URL {
        switch kind { case .hosted: return entry.receiptURL; case .jira: return entry.jiraReceiptURL; case .s3: return entry.s3ReceiptURL }
    }

    static func s3Destination(_ settings: S3StorageSettings, accountID: String) -> [String: String] {
        ["bucket": settings.bucket, "region": settings.region, "accountID": accountID,
         "prefix": settings.tenantScopedPrefix, "securityProfile": settings.securityProfile.rawValue,
         "encryption": settings.encryptionMode.rawValue, "kmsKeyARN": settings.kmsKeyARN,
         "retentionMode": settings.retentionMode.rawValue, "retentionDays": String(settings.retentionDays)]
    }

    /// Call only after the upload service validates a successful response from
    /// its expected authenticated destination. Never migrate an old disk receipt.
    static func record(
        payload: Data, kind: TransferReceiptKind, artifact: ValidatedEvidenceArtifact,
        manifestURL: URL, destination: [String: String], receiptURL: URL
    ) throws {
        guard let binding = artifact.manifest.tenantBinding, payload.count <= 1024 * 1024 else {
            throw TransferReceiptFailure.unverified
        }
        var receipt = TransferReceipt(
            schemaVersion: 1, verificationMethod: method, kind: kind,
            evidenceID: artifact.manifest.evidenceID, tenantID: binding.tenantID,
            workspaceID: binding.workspaceID, screenshotSHA256: artifact.manifest.sha256,
            manifestSHA256: digest(artifact.manifestData), destination: destination,
            recordedAt: ISO8601DateFormatter().string(from: Date()), payload: payload,
            payloadSHA256: digest(payload), provenance: nil
        )
        guard receipt.validProviderPayload(artifact: artifact, manifestURL: manifestURL) else {
            throw TransferReceiptFailure.unverified
        }
        receipt.provenance = try LocalProvenance.sign(
            payload: LocalProvenance.canonicalJSON(receipt, removingTopLevelKeys: ["provenance"]),
            domain: domain, privateKeyData: KeychainStore.localTransferReceiptPrivateKey()
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(receipt).write(to: receiptURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
    }

    static func verified(
        for entry: CaptureHistoryEntry, kind: TransferReceiptKind,
        artifact suppliedArtifact: ValidatedEvidenceArtifact? = nil,
        expectedDestination: [String: String]? = nil
    ) throws -> (receipt: TransferReceipt, data: Data) {
        let artifact = try suppliedArtifact ?? ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
        let data = try ValidatedEvidenceArtifact.readBoundedRegularFile(
            at: url(for: entry, kind: kind), within: entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent(),
            maximumBytes: 2 * 1024 * 1024
        )
        let receipt = try JSONDecoder().decode(Self.self, from: data)
        let originalObject = try JSONSerialization.jsonObject(with: data) as? NSDictionary
        let typedObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? NSDictionary
        guard let binding = artifact.manifest.tenantBinding,
              originalObject == typedObject,
              receipt.schemaVersion == 1, receipt.verificationMethod == method,
              receipt.kind == kind, receipt.evidenceID == artifact.manifest.evidenceID,
              receipt.tenantID == binding.tenantID, receipt.workspaceID == binding.workspaceID,
              receipt.screenshotSHA256 == artifact.manifest.sha256,
              receipt.manifestSHA256 == digest(artifact.manifestData),
              receipt.payload.count <= 1024 * 1024, receipt.payloadSHA256 == digest(receipt.payload),
              expectedDestination.map({ $0 == receipt.destination }) ?? true,
              ISO8601DateFormatter().date(from: receipt.recordedAt) != nil,
              let signature = receipt.provenance,
              signature.keyID == KeychainStore.localTransferReceiptSigningKeyID(),
              LocalProvenance.verify(signature, payload: try LocalProvenance.canonicalJSON(receipt, removingTopLevelKeys: ["provenance"]), domain: domain),
              receipt.validProviderPayload(artifact: artifact, manifestURL: entry.manifestURL) else {
            throw TransferReceiptFailure.unverified
        }
        return (receipt, data)
    }

    static func isVerified(for entry: CaptureHistoryEntry, kind: TransferReceiptKind, expectedDestination: [String: String]? = nil) -> Bool {
        (try? verified(for: entry, kind: kind, expectedDestination: expectedDestination)) != nil
    }

    static func status(for entry: CaptureHistoryEntry, kind: TransferReceiptKind) -> String {
        guard FileManager.default.fileExists(atPath: url(for: entry, kind: kind).path) else { return "Pending" }
        return isVerified(for: entry, kind: kind) ? "Verified response (device seal)"
            : (kind == .jira ? "Unverified receipt — reconcile Jira" : "Unverified receipt — verify remote outcome")
    }

    private func validProviderPayload(artifact: ValidatedEvidenceArtifact, manifestURL: URL) -> Bool {
        switch kind {
        case .s3:
            guard let value = try? JSONDecoder().decode(S3UploadReceipt.self, from: payload),
                  value.schemaVersion == 3, value.evidenceID == evidenceID,
                  value.screenshotSHA256 == screenshotSHA256, value.manifestSHA256 == manifestSHA256,
                  destination.count == 9,
                  destination["bucket"] == value.bucket, destination["region"] == value.region,
                  destination["accountID"] == value.awsAccountID,
                  destination["securityProfile"] == value.securityProfile,
                  destination["encryption"] == value.encryption, destination["kmsKeyARN"] == value.kmsKeyARN,
                  destination["retentionMode"] == value.retentionMode,
                  destination["retentionDays"] == String(value.retentionDays),
                  let prefix = destination["prefix"], !prefix.isEmpty,
                  value.awsAccountID.range(of: #"^\d{12}$"#, options: .regularExpression) != nil,
                  ISO8601DateFormatter().date(from: value.uploadedAt) != nil,
                  value.objectKeys.count == 2, Set(value.objectKeys).count == 2 else { return false }
            let expected = [artifact.manifest.screenshotFilename: screenshotSHA256, manifestURL.lastPathComponent: manifestSHA256]
            var seen = Set<String>()
            var parents = Set<String>()
            for key in value.objectKeys {
                let name = (key as NSString).lastPathComponent
                guard key.hasPrefix(prefix + "/"), key.hasSuffix("/\(evidenceID)/\(name)"),
                      let hash = expected[name], seen.insert(name).inserted,
                      let version = value.versionIDs[key], !version.isEmpty, version != "null",
                      let etag = value.etags[key], !etag.isEmpty,
                      let checksum = value.s3ChecksumsSHA256[key], let bytes = Data(base64Encoded: checksum),
                      bytes.count == 32, bytes.map({ String(format: "%02x", $0) }).joined() == hash else { return false }
                parents.insert((key as NSString).deletingLastPathComponent)
            }
            return seen.count == 2 && parents.count == 1
        case .hosted:
            guard destination.count == 1, let origin = destination["origin"], Self.isOrigin(origin),
                  let body = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
                  let receipt = body["receipt"] as? [String: Any],
                  let attestation = receipt["attestation"] as? [String: Any],
                  attestation["version"] as? Int == 3,
                  attestation["manifestSchemaVersion"] as? Int == artifact.manifest.schemaVersion,
                  attestation["evidenceId"] as? String == evidenceID,
                  attestation["imageSha256"] as? String == screenshotSHA256,
                  attestation["manifestSha256"] as? String == manifestSHA256,
                  attestation["chainEventHash"] as? String == artifact.manifest.chainEventHash,
                  attestation["chainSequence"] as? Int == artifact.manifest.chainSequence,
                  attestation["provenanceKeyId"] as? String == artifact.manifest.provenance?.keyID,
                  let signature = attestation["signature"] as? String, !signature.isEmpty else { return false }
            return true
        case .jira:
            struct Envelope: Decodable { let receipt: JiraCloudUploadReceipt }
            guard destination.count == 3, let origin = destination["origin"], Self.isOrigin(origin),
                  let value = try? JSONDecoder().decode(Envelope.self, from: payload).receipt,
                  value.evidenceID == evidenceID, value.issueKey == artifact.manifest.jiraIssueKey,
                  destination["issueKey"] == value.issueKey, destination["siteURL"] == value.siteURL,
                  Self.isOrigin(value.siteURL), !value.receiptID.isEmpty,
                  ISO8601DateFormatter().date(from: value.uploadedAt) != nil,
                  value.receiptSHA256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
                  !value.signature.isEmpty,
                  let attachments = value.attachments else { return false }
            let expected = [artifact.manifest.screenshotFilename: artifact.imageData.count, manifestURL.lastPathComponent: artifact.manifestData.count]
            return expected.allSatisfy { name, size in attachments.filter { $0.filename == name && $0.size == size && !$0.id.isEmpty }.count == 1 }
        }
    }

    private static func isOrigin(_ value: String) -> Bool {
        guard let url = URL(string: value), url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/" else { return false }
        if url.scheme == "https", url.host != nil { return true }
        #if DEBUG
        return url.scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(url.host ?? "")
        #else
        return false
        #endif
    }

    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
