import CryptoKit
import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Native evidence security remediations", .serialized)
struct NativeSecurityRemediationTests {
    @Test("Capture-chain rollback heads are isolated across tenant workspaces")
    func isolatesCaptureChainHeadsByTenantWorkspace() throws {
        let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let first = try #require(TenantWorkspaceBinding.validated(
            tenantID: "tenant-a-\(suffix.prefix(12))", workspaceID: "audit"
        ))
        let second = try #require(TenantWorkspaceBinding.validated(
            tenantID: "tenant-b-\(suffix.prefix(12))", workspaceID: "audit"
        ))
        let firstScope = KeychainStore.captureChainScopeIdentifier(binding: first)
        let secondScope = KeychainStore.captureChainScopeIdentifier(binding: second)
        #expect(firstScope != secondScope)
        #expect(firstScope == KeychainStore.captureChainScopeIdentifier(binding: first))
        #expect(firstScope.range(of: #"^local-capture-chain-anchor-v2-[a-f0-9]{64}$"#, options: .regularExpression) != nil)
    }

    @Test("Pending capture journals require complete tenant-bound chain metadata")
    func validatesCaptureCommitJournal() throws {
        let root = "/Users/tester/Documents/Scopeproof Evidence/tenants/customer/workspaces/audit"
        var journal = LocalCaptureCommitJournal(
            schemaVersion: LocalCaptureCommitJournal.currentSchemaVersion,
            evidenceID: "EV-ABC123", tenantID: "customer", workspaceID: "audit",
            evidenceRootPath: root,
            imagePath: "\(root)/PCI/8.3/2026-Q3/evidence.png",
            manifestPath: "\(root)/PCI/8.3/2026-Q3/evidence.json",
            lifecyclePath: "\(root)/PCI/8.3/2026-Q3/evidence.review.json",
            startedAt: "2026-09-01T12:00:00Z"
        )
        #expect(journal.isValid)
        #expect(journal.prospectiveAnchor == nil)
        journal.chainPreviousHash = "GENESIS"
        journal.chainSequence = 1
        journal.chainEventHash = String(repeating: "b", count: 64)
        journal.signingKeyID = String(repeating: "c", count: 64)
        #expect(journal.prospectiveAnchor?.sequence == 1)
    }

    @Test("Lifecycle and hold signatures use distinct trust domains and keys")
    func separatesTrustSigningDomains() throws {
        var event = EvidenceLifecycleEvent(
            sequence: 1, occurredAt: "2026-09-01T12:00:00Z", actor: "Reviewer",
            action: "status.approved", status: .approved, owner: "Owner", reviewer: "Reviewer",
            actorSubjectID: "test-reviewer", authenticationMethod: "test-override",
            authenticatedAt: "2026-09-01T12:00:00Z", reviewNotes: "Reviewed evidence",
            tags: [], supersedesEvidenceID: nil, artifactSha256: String(repeating: "d", count: 64),
            policyVersion: EvidenceLifecycleStore.policyVersion, safetyScanPolicy: "test",
            previousHash: "GENESIS", eventHash: String(repeating: "e", count: 64), provenance: nil
        )
        let lifecycleKey = P256.Signing.PrivateKey().rawRepresentation
        let holdKey = P256.Signing.PrivateKey().rawRepresentation
        let lifecycle = try LocalProvenance.signLifecycleEvent(
            event, evidenceID: "EV-ABC123", privateKeyData: lifecycleKey
        )
        event.provenance = lifecycle
        var hold = LocalEvidenceHoldRecord(
            schemaVersion: 2, evidenceID: "EV-ABC123",
            artifactSha256: String(repeating: "d", count: 64), active: true,
            updatedAt: "2026-09-01T12:00:00Z", actor: "Reviewer", reason: "Matter 12345",
            sequence: 1, previousHash: "GENESIS", eventHash: String(repeating: "f", count: 64),
            actorSubjectID: "test-reviewer", authenticationMethod: "test-override",
            authenticatedAt: "2026-09-01T12:00:00Z", provenance: nil
        )
        hold.provenance = try LocalProvenance.signHold(hold, privateKeyData: holdKey)
        #expect(lifecycle.keyID != hold.provenance?.keyID)
        #expect(LocalProvenance.verifyLifecycleEvent(event, evidenceID: "EV-ABC123"))
        #expect(LocalProvenance.verifyHold(hold))
    }
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

    @Test("Schema-8 captures create signed schema-4 lifecycle records")
    func signsCurrentLifecycleSchema() throws {
        let root = temporaryDirectory("schema-4-lifecycle")
        defer { try? FileManager.default.removeItem(at: root) }
        let imageURL = root.appendingPathComponent("current.png")
        try validPNG.write(to: imageURL)
        let privateKey = P256.Signing.PrivateKey().rawRepresentation
        var manifest = makeManifest(baseName: "current", schemaVersion: 8, chainSequence: 1)
        manifest.provenance = try LocalProvenance.signManifest(manifest, privateKeyData: privateKey)
        let manifestURL = root.appendingPathComponent("current.json")
        try JSONEncoder().encode(manifest).write(to: manifestURL)
        let entry = CaptureHistoryEntry(
            manifest: manifest, manifestURL: manifestURL, imageURL: imageURL,
            receiptURL: root.appendingPathComponent("current.receipt.json"), evidenceRoot: root
        )
        let anchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: 1, eventHash: manifest.chainEventHash,
            signingKeyID: try #require(manifest.provenance?.keyID),
            anchoredAt: manifest.capturedAt
        )

        let lifecycle = try EvidenceLifecycleStore.update(
            entry: entry, status: .draft, owner: "Control Owner", reviewer: "Capture workflow",
            notes: "Capture created and bound to the current lifecycle schema.", tags: ["current"],
            privateKeyDataOverride: privateKey, trustedAnchor: anchor
        )

        #expect(lifecycle.schemaVersion == 4)
        #expect(lifecycle.events.count == 1)
        #expect(lifecycle.events[0].provenance != nil)
        #expect(EvidenceLifecycleStore.verify(
            lifecycle, artifactSha256: manifest.sha256,
            provenanceKeyID: manifest.provenance?.keyID
        ))
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

    @Test("Deleting a legal-hold marker fails closed when the trust head remains")
    func rejectsDeletedLegalHoldMarker() throws {
        let root = temporaryDirectory("deleted-hold")
        defer { try? FileManager.default.removeItem(at: root) }
        let entry = try makeEvidence(in: root, baseName: UUID().uuidString)
        _ = try installHold(for: entry)
        let markerURL = LocalEvidenceHoldStore.url(for: entry.manifestURL)

        #expect({
            guard case .active = LocalEvidenceHoldStore.state(for: entry) else { return false }
            return true
        }())
        try FileManager.default.removeItem(at: markerURL)

        #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
    }

    @Test("Legacy signed holds migrate to an immutable trust head")
    func anchorsLegacyLegalHoldBeforeDeletion() throws {
        let root = temporaryDirectory("legacy-hold")
        defer { try? FileManager.default.removeItem(at: root) }
        let entry = try makeEvidence(in: root, baseName: UUID().uuidString)
        var record = LocalEvidenceHoldRecord(
            schemaVersion: 1, evidenceID: entry.manifest.evidenceID,
            artifactSha256: entry.manifest.sha256, active: true,
            updatedAt: "2026-08-28T11:00:00Z", actor: "Security Reviewer",
            reason: "Preserve legacy evidence for matter 12345", provenance: nil
        )
        record.provenance = try LocalProvenance.signHold(
            record, privateKeyData: P256.Signing.PrivateKey().rawRepresentation
        )
        let markerURL = LocalEvidenceHoldStore.url(for: entry.manifestURL)
        try JSONEncoder().encode(record).write(to: markerURL, options: .atomic)

        #expect({
            guard case .active = LocalEvidenceHoldStore.state(for: entry) else { return false }
            return true
        }())
        let scope = LocalEvidenceHoldStore.trustScope(for: entry)
        let storedHead = try KeychainStore.localTrustHead(domain: .legalHold, scope: scope)
        let migratedHead = try #require(storedHead)
        let currentHoldKey = try P256.Signing.PrivateKey(
            rawRepresentation: KeychainStore.localHoldPrivateKey()
        )
        let currentHoldKeyID = SHA256.hash(data: currentHoldKey.publicKey.x963Representation)
            .map { String(format: "%02x", $0) }.joined()
        #expect(migratedHead.signingKeyID == currentHoldKeyID)
        try FileManager.default.removeItem(at: markerURL)
        #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
    }

    @Test("Moving held evidence preserves its immutable legal-hold trust scope")
    func preservesLegalHoldAcrossMove() throws {
        let root = temporaryDirectory("moved-hold")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source", isDirectory: true)
        let destination = root.appendingPathComponent("destination", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        let entry = try makeEvidence(in: source, baseName: UUID().uuidString)
        _ = try installHold(for: entry)
        let originalScope = LocalEvidenceHoldStore.trustScope(for: entry)

        try FileManager.default.moveItem(at: source, to: destination)
        let movedEntry = CaptureHistoryEntry(
            manifest: entry.manifest,
            manifestURL: destination.appendingPathComponent(entry.manifestURL.lastPathComponent),
            imageURL: destination.appendingPathComponent(entry.imageURL.lastPathComponent),
            receiptURL: destination.appendingPathComponent(entry.receiptURL.lastPathComponent),
            evidenceRoot: destination
        )

        #expect(LocalEvidenceHoldStore.trustScope(for: movedEntry) == originalScope)
        #expect({
            guard case .active = LocalEvidenceHoldStore.state(for: movedEntry) else { return false }
            return true
        }())
    }

    @Test("Retention preserves evidence when a hold marker is missing during a pending trust advance")
    @MainActor
    func retentionRejectsMissingPendingHoldMarker() async throws {
        let root = temporaryDirectory("pending-hold-retention")
        defer { try? FileManager.default.removeItem(at: root) }
        let entry = try makeEvidence(in: root, baseName: UUID().uuidString)
        let (_, advance) = try installHold(for: entry, writeMarker: false, commit: false)
        defer {
            KeychainStore.cancelLocalTrustAdvance(
                advance, scope: LocalEvidenceHoldStore.trustScope(for: entry)
            )
        }

        #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
        let report = try await CaptureHistory.removeExpired(
            in: root, retentionDays: 1,
            now: try #require(ISO8601DateFormatter().date(from: "2026-08-28T12:00:00Z"))
        ) { _ in true }

        #expect(report.movedToTrash == 0)
        #expect(report.skippedLegalHold == 1)
        #expect(FileManager.default.fileExists(atPath: entry.manifestURL.path))
        #expect(FileManager.default.fileExists(atPath: entry.imageURL.path))
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

    private func installHold(
        for entry: CaptureHistoryEntry, writeMarker: Bool = true, commit: Bool = true
    ) throws -> (LocalEvidenceHoldRecord, LocalTrustAdvance) {
        let privateKey = P256.Signing.PrivateKey().rawRepresentation
        let updatedAt = "2026-08-28T11:00:00Z"
        let actor = "Security Reviewer"
        let reason = "Preserve evidence for matter 12345"
        let subjectID = "reviewer-(UUID().uuidString.lowercased())"
        let previousHash = "GENESIS"
        let sequence = 1
        let eventHash = holdDigest([
            previousHash, entry.manifest.evidenceID, String(sequence), String(true),
            updatedAt, subjectID, actor, reason,
        ])
        var record = LocalEvidenceHoldRecord(
            schemaVersion: LocalEvidenceHoldRecord.currentSchemaVersion,
            evidenceID: entry.manifest.evidenceID, artifactSha256: entry.manifest.sha256,
            active: true, updatedAt: updatedAt, actor: actor, reason: reason,
            sequence: sequence, previousHash: previousHash, eventHash: eventHash,
            actorSubjectID: subjectID, authenticationMethod: "test-override",
            authenticatedAt: updatedAt, provenance: nil
        )
        record.provenance = try LocalProvenance.signHold(record, privateKeyData: privateKey)
        let scope = LocalEvidenceHoldStore.trustScope(for: entry)
        let advance = try KeychainStore.prepareLocalTrustAdvance(
            domain: .legalHold, scope: scope, previousHash: previousHash,
            sequence: sequence, eventHash: eventHash,
            signingKeyID: try #require(record.provenance?.keyID)
        )
        if writeMarker {
            try JSONEncoder().encode(record).write(
                to: LocalEvidenceHoldStore.url(for: entry.manifestURL), options: .atomic
            )
        }
        if commit {
            try KeychainStore.commitLocalTrustAdvance(advance, scope: scope)
        }
        return (record, advance)
    }

    private func holdDigest(_ fields: [String]) -> String {
        let payload = fields.map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
        return sha256(Data(payload.utf8))
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
            tenantID: schemaVersion >= 8 ? "tenant-test" : nil,
            workspaceID: schemaVersion >= 8 ? "workspace-test" : nil,
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
