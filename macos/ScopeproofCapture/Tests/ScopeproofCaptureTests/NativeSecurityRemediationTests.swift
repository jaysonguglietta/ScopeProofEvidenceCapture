import CryptoKit
import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Native evidence security remediations", .serialized)
struct NativeSecurityRemediationTests {
    @Test("Legacy artifacts are browsing-only and the central loader rejects unsafe files")
    func validatesEvidenceFilesWithoutFollowingLinks() throws {
        let root = temporaryDirectory("artifact-loader")
        defer { try? FileManager.default.removeItem(at: root) }
        let valid = try makeEvidence(in: root, baseName: "valid")

        let artifact = try ValidatedEvidenceArtifact.loadForLegacyBrowsing(valid, requireLifecycle: false)
        #expect(artifact.manifest.sha256 == valid.manifest.sha256)
        #expect(!artifact.provenanceVerified)
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.load(valid, requireLifecycle: false)
        }
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.exportFiles(for: valid)
        }
        #expect(throws: EvidenceArtifactFailure.self) {
            try EvidenceLifecycleStore.update(
                entry: valid, status: .approved, owner: "Owner", reviewer: "Reviewer",
                notes: "An attacker-controlled legacy approval must not be accepted.", tags: []
            )
        }
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.validateDownloaded(
                manifestData: Data(contentsOf: valid.manifestURL), imageData: validPNG,
                manifestURL: valid.manifestURL, imageURL: valid.imageURL,
                requireLocalAnchor: false
            )
        }

        let external = root.deletingLastPathComponent().appendingPathComponent("outside-\(UUID().uuidString).png")
        defer { try? FileManager.default.removeItem(at: external) }
        try validPNG.write(to: external)
        let symlinkURL = root.appendingPathComponent("symlink.png")
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: external)
        let symlinkEntry = try makeEvidence(in: root, baseName: "symlink", existingImageURL: symlinkURL)
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.loadForLegacyBrowsing(symlinkEntry, requireLifecycle: false)
        }

        let hardLinkURL = root.appendingPathComponent("hardlink.png")
        try FileManager.default.linkItem(at: valid.imageURL, to: hardLinkURL)
        let hardLinkEntry = try makeEvidence(in: root, baseName: "hardlink", existingImageURL: hardLinkURL)
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.loadForLegacyBrowsing(hardLinkEntry, requireLifecycle: false)
        }
        #expect(throws: EvidenceArtifactFailure.self) {
            try ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: valid.manifestURL, within: root, maximumBytes: 8
            )
        }
    }

    @Test("Capture and lifecycle provenance signatures fail after field tampering")
    func verifiesSignedProvenance() throws {
        let privateKey = P256.Signing.PrivateKey().rawRepresentation
        var manifest = makeManifest(baseName: "signed", schemaVersion: 7, chainSequence: 1)
        manifest.provenance = try LocalProvenance.signManifest(manifest, privateKeyData: privateKey)
        #expect(LocalProvenance.verifyManifest(manifest))
        let encodedManifest = try JSONEncoder().encode(manifest)
        let encodedObject = try #require(
            JSONSerialization.jsonObject(with: encodedManifest) as? [String: Any]
        )
        #expect(encodedObject["schemaVersion"] as? Int == 7)
        #expect(encodedObject["chainSequence"] as? Int == 1)
        #expect(encodedObject["provenance"] as? [String: Any] != nil)
        var downgradedObject = encodedObject
        downgradedObject["schemaVersion"] = 6
        downgradedObject.removeValue(forKey: "chainSequence")
        downgradedObject.removeValue(forKey: "provenance")
        let downgradedBytes = try JSONSerialization.data(
            withJSONObject: downgradedObject, options: [.sortedKeys]
        )
        #expect(UploadService.uploadSignature(
            token: "test-token", manifest: encodedManifest, image: validPNG
        ) != UploadService.uploadSignature(
            token: "test-token", manifest: downgradedBytes, image: validPNG
        ))
        let entry = CaptureHistoryEntry(
            manifest: manifest, manifestURL: URL(fileURLWithPath: "/tmp/signed.json"),
            imageURL: URL(fileURLWithPath: "/tmp/signed.png"),
            receiptURL: URL(fileURLWithPath: "/tmp/signed.receipt.json")
        )
        let anchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 1, eventHash: manifest.chainEventHash,
            signingKeyID: try #require(manifest.provenance?.keyID),
            anchoredAt: "2026-08-28T12:00:00Z"
        )
        #expect(CaptureHistory.captureChainIntegrity([entry], anchor: anchor))
        #expect(!CaptureHistory.captureChainIntegrity([], anchor: anchor))

        var manifestObject = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(manifest)) as? [String: Any])
        manifestObject["title"] = "attacker changed title"
        let tamperedManifest = try JSONDecoder().decode(
            CaptureManifest.self, from: JSONSerialization.data(withJSONObject: manifestObject)
        )
        #expect(!LocalProvenance.verifyManifest(tamperedManifest))

        var event = EvidenceLifecycleEvent(
            sequence: 1, occurredAt: "2026-08-28T12:00:00Z", actor: "Reviewer",
            action: "status.approved", status: .approved, owner: "Owner", reviewer: "Reviewer",
            reviewNotes: "Verified exact production settings.", tags: ["production"],
            supersedesEvidenceID: nil, artifactSha256: manifest.sha256,
            policyVersion: EvidenceLifecycleStore.policyVersion,
            safetyScanPolicy: SensitiveDataScanner.policyVersion,
            previousHash: "GENESIS", eventHash: String(repeating: "a", count: 64),
            provenance: nil
        )
        event.provenance = try LocalProvenance.signLifecycleEvent(
            event, evidenceID: manifest.evidenceID, privateKeyData: privateKey
        )
        #expect(LocalProvenance.verifyLifecycleEvent(event, evidenceID: manifest.evidenceID))
        var eventObject = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as? [String: Any])
        eventObject["reviewNotes"] = "tampered"
        let tamperedEvent = try JSONDecoder().decode(
            EvidenceLifecycleEvent.self, from: JSONSerialization.data(withJSONObject: eventObject)
        )
        #expect(!LocalProvenance.verifyLifecycleEvent(tamperedEvent, evidenceID: manifest.evidenceID))
    }

    @Test("Capture chain rejects gaps, repeated or reordered sequences, and invalid genesis")
    func rejectsNonContiguousCaptureHistory() throws {
        let privateKey = P256.Signing.PrivateKey().rawRepresentation
        let first = try makeSignedChainEntry(
            sequence: 1, previousHash: "GENESIS", capturedAt: "2026-08-28T12:00:00Z",
            privateKey: privateKey
        )
        let second = try makeSignedChainEntry(
            sequence: 2, previousHash: first.manifest.chainEventHash,
            capturedAt: "2026-08-28T12:01:00Z", privateKey: privateKey
        )
        let third = try makeSignedChainEntry(
            sequence: 3, previousHash: second.manifest.chainEventHash,
            capturedAt: "2026-08-28T12:02:00Z", privateKey: privateKey
        )
        let anchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 3, eventHash: third.manifest.chainEventHash,
            signingKeyID: try #require(third.manifest.provenance?.keyID),
            anchoredAt: "2026-08-28T12:02:00Z"
        )

        // CaptureHistory order is newest-first.
        #expect(CaptureHistory.captureChainIntegrity([third, second, first], anchor: anchor))
        #expect(!CaptureHistory.captureChainIntegrity([third, first], anchor: anchor))
        #expect(!CaptureHistory.captureChainIntegrity([third, second, second, first], anchor: anchor))
        #expect(!CaptureHistory.captureChainIntegrity([second, third, first], anchor: anchor))

        let wrongLink = try makeSignedChainEntry(
            sequence: 2, previousHash: String(repeating: "b", count: 64),
            capturedAt: "2026-08-28T12:01:00Z", privateKey: privateKey
        )
        let wrongLinkAnchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 2, eventHash: wrongLink.manifest.chainEventHash,
            signingKeyID: try #require(wrongLink.manifest.provenance?.keyID),
            anchoredAt: "2026-08-28T12:01:00Z"
        )
        #expect(!CaptureHistory.captureChainIntegrity([wrongLink, first], anchor: wrongLinkAnchor))

        let badGenesis = try makeSignedChainEntry(
            sequence: 1, previousHash: String(repeating: "c", count: 64),
            capturedAt: "2026-08-28T12:00:00Z", privateKey: privateKey
        )
        let badGenesisAnchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 1, eventHash: badGenesis.manifest.chainEventHash,
            signingKeyID: try #require(badGenesis.manifest.provenance?.keyID),
            anchoredAt: "2026-08-28T12:00:00Z"
        )
        #expect(!CaptureHistory.captureChainIntegrity([badGenesis], anchor: badGenesisAnchor))
        #expect(!CaptureHistory.captureChainIntegrity([second], anchor: wrongLinkAnchor))

        let invalidPackageRoot = temporaryDirectory("invalid-chain-package")
        defer { try? FileManager.default.removeItem(at: invalidPackageRoot) }
        let destination = invalidPackageRoot.appendingPathComponent("assessor.zip")
        #expect(throws: AssessorPackageFailure.self) {
            try AssessorPackageExporter.export(
                entries: [third], completeHistory: [third, first], to: destination,
                preparedBy: "Reviewer", packageName: "Invalid chain",
                signingKeyOverride: P256.Signing.PrivateKey(),
                captureAnchorOverride: anchor
            )
        }
    }

    @Test("Local retention requires an unexpired exact-version locked S3 receipt and fails closed on holds")
    func requiresDurableLockedCopyForRetention() throws {
        let root = temporaryDirectory("durable-copy")
        defer { try? FileManager.default.removeItem(at: root) }
        let (entry, anchor) = try makeSignedEvidence(in: root, baseName: "retained")
        let now = try #require(ISO8601DateFormatter().date(from: "2026-08-28T12:00:00Z"))
        let imageKey = "scopeproof/8.3.1/2026-Q3/\(entry.manifest.evidenceID)/retained.png"
        let manifestKey = "scopeproof/8.3.1/2026-Q3/\(entry.manifest.evidenceID)/retained.json"
        let manifestData = try Data(contentsOf: entry.manifestURL)
        let retainedThrough = "2027-08-28T12:00:00Z"
        let receipt = S3UploadReceipt(
            schemaVersion: 3, evidenceID: entry.manifest.evidenceID,
            bucket: "company-evidence", region: "us-east-1", awsAccountID: "123456789012",
            principalARN: "arn:aws:sts::123456789012:assumed-role/scopeproof/operator",
            securityProfile: S3SecurityProfile.production.rawValue,
            objectKeys: [imageKey, manifestKey],
            etags: [imageKey: "image-etag", manifestKey: "manifest-etag"],
            versionIDs: [imageKey: "image-version", manifestKey: "manifest-version"],
            s3ChecksumsSHA256: [
                imageKey: Data(SHA256.hash(data: validPNG)).base64EncodedString(),
                manifestKey: Data(SHA256.hash(data: manifestData)).base64EncodedString(),
            ],
            requestIDs: [imageKey: "request-image", manifestKey: "request-manifest"],
            uploadedAt: "2026-08-28T11:59:00Z", encryption: "aws:kms",
            kmsKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            retentionMode: S3RetentionMode.compliance.rawValue, retentionDays: 365,
            retainUntilByObjectKey: [imageKey: retainedThrough, manifestKey: retainedThrough],
            screenshotSHA256: entry.manifest.sha256,
            manifestSHA256: sha256(manifestData)
        )
        try JSONEncoder().encode(receipt).write(to: entry.s3ReceiptURL)
        #expect(CaptureHistory.hasDurableLockedCopy(for: entry, now: now, trustedAnchor: anchor))
        #expect(!CaptureHistory.hasDurableLockedCopy(
            for: entry,
            now: try #require(ISO8601DateFormatter().date(from: "2027-08-28T12:00:01Z")),
            trustedAnchor: anchor
        ))

        try Data("{}".utf8).write(to: LocalEvidenceHoldStore.url(for: entry.manifestURL))
        #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
    }

    private func makeEvidence(
        in root: URL, baseName: String, existingImageURL: URL? = nil
    ) throws -> CaptureHistoryEntry {
        let imageURL = existingImageURL ?? root.appendingPathComponent("\(baseName).png")
        if existingImageURL == nil { try validPNG.write(to: imageURL) }
        let manifest = makeManifest(baseName: baseName)
        let manifestURL = root.appendingPathComponent("\(baseName).json")
        try JSONEncoder().encode(manifest).write(to: manifestURL)
        return CaptureHistoryEntry(
            manifest: manifest, manifestURL: manifestURL, imageURL: imageURL,
            receiptURL: root.appendingPathComponent("\(baseName).receipt.json"), evidenceRoot: root
        )
    }

    private func makeSignedEvidence(
        in root: URL, baseName: String
    ) throws -> (CaptureHistoryEntry, LocalCaptureChainAnchor) {
        let imageURL = root.appendingPathComponent("\(baseName).png")
        try validPNG.write(to: imageURL)
        let privateKey = P256.Signing.PrivateKey().rawRepresentation
        var manifest = makeManifest(baseName: baseName, schemaVersion: 7, chainSequence: 1)
        manifest.provenance = try LocalProvenance.signManifest(
            manifest, privateKeyData: privateKey
        )
        let manifestURL = root.appendingPathComponent("\(baseName).json")
        try JSONEncoder().encode(manifest).write(to: manifestURL)
        let entry = CaptureHistoryEntry(
            manifest: manifest, manifestURL: manifestURL, imageURL: imageURL,
            receiptURL: root.appendingPathComponent("\(baseName).receipt.json"),
            evidenceRoot: root
        )
        let anchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 1, eventHash: manifest.chainEventHash,
            signingKeyID: try #require(manifest.provenance?.keyID),
            anchoredAt: "2026-08-28T12:00:00Z"
        )
        return (entry, anchor)
    }

    private func makeSignedChainEntry(
        sequence: Int, previousHash: String, capturedAt: String, privateKey: Data
    ) throws -> CaptureHistoryEntry {
        let baseName = "chain\(sequence)"
        var manifest = makeManifest(
            baseName: baseName, schemaVersion: 7, chainSequence: sequence,
            chainPreviousHash: previousHash, capturedAt: capturedAt
        )
        manifest.provenance = try LocalProvenance.signManifest(
            manifest, privateKeyData: privateKey
        )
        return CaptureHistoryEntry(
            manifest: manifest,
            manifestURL: URL(fileURLWithPath: "/tmp/\(baseName).json"),
            imageURL: URL(fileURLWithPath: "/tmp/\(baseName).png"),
            receiptURL: URL(fileURLWithPath: "/tmp/\(baseName).receipt.json")
        )
    }

    private func makeManifest(
        baseName: String, schemaVersion: Int = 6, chainSequence: Int? = nil,
        chainPreviousHash: String = "GENESIS",
        capturedAt: String = "2026-08-11T12:00:00Z"
    ) -> CaptureManifest {
        let digest = sha256(validPNG)
        let evidenceID = "EV-\(baseName.uppercased().filter { $0.isLetter || $0.isNumber }.prefix(20))"
        let sessionID = "session_test"
        let chainHash = sha256(Data("\(chainPreviousHash)|\(digest)|\(evidenceID)|\(capturedAt)|\(sessionID)".utf8))
        return CaptureManifest(
            schemaVersion: schemaVersion, evidenceID: evidenceID, capturedAt: capturedAt,
            localTimestamp: "2026-08-11 08:00:00 EDT", timezone: "America/New_York",
            sourceURL: "https://admin.example.com", sourceHost: "admin.example.com",
            browser: "Safari", windowTitle: "Settings", screenshotFilename: "\(baseName).png",
            sha256: digest, pixelWidth: 1, pixelHeight: 1, captureMethod: "test",
            timestampAuthority: "local", safetyStatus: "passed", redactionFindings: [],
            redactedRegions: 0, safetyScanSha256: digest,
            safetyScanPolicy: SensitiveDataScanner.policyVersion, safetyScanCompletedAt: capturedAt,
            sessionID: sessionID, sessionName: "Audit", controlID: "8.3.1", title: "MFA",
            system: "Okta", environment: "Production", assessmentPeriod: "2026 Q3",
            description: "MFA enabled", complianceArea: "PCI DSS 4.0.1",
            controlTitle: "Strong authentication", customFileName: "MFA",
            catalogVersion: ComplianceCatalog.catalogVersion, evidenceOwner: "Owner",
            tags: ["identity"], expectedEvidence: "MFA status",
            mappedControls: ComplianceCatalog.mappings(
                frameworkName: "PCI DSS 4.0.1", controlID: "8.3.1"
            ),
            manualRedactions: 0, reviewerNote: nil, jiraIssueKey: nil, jiraIssueURL: nil,
            chainPreviousHash: chainPreviousHash, chainEventHash: chainHash,
            chainSequence: chainSequence, provenance: nil
        )
    }

    private var validPNG: Data {
        Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")!
    }

    private func temporaryDirectory(_ name: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scopeproof-\(name)-\(UUID().uuidString)", isDirectory: true)
        try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
