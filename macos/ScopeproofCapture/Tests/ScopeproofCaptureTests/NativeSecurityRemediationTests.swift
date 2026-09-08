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
                entries: [third], completeHistory: [third, first], expectedBinding: .localDefault, to: destination,
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
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
        let root = temporaryDirectory("durable-copy")
        defer { try? FileManager.default.removeItem(at: root) }
        let entry = try makeBoundEvidence(in: root, name: "retained", binding: .localDefault)
        let anchor = try #require(try KeychainStore.captureChainAnchor(binding: .localDefault))
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
        let rawReceipt = try JSONEncoder().encode(receipt)
        try rawReceipt.write(to: entry.s3ReceiptURL)
        #expect(!CaptureHistory.hasDurableLockedCopy(for: entry, now: now, trustedAnchor: anchor))
        let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false, trustedAnchor: anchor)
        try TransferReceipt.record(payload: rawReceipt, kind: .s3, artifact: artifact,
            manifestURL: entry.manifestURL,
            destination: ["bucket": receipt.bucket, "region": receipt.region, "accountID": receipt.awsAccountID,
                "prefix": "scopeproof", "securityProfile": receipt.securityProfile, "encryption": receipt.encryption,
                "kmsKeyARN": receipt.kmsKeyARN, "retentionMode": receipt.retentionMode, "retentionDays": "365"],
            receiptURL: entry.s3ReceiptURL)
        #expect(CaptureHistory.hasDurableLockedCopy(for: entry, now: now, trustedAnchor: anchor))
        #expect(!CaptureHistory.hasDurableLockedCopy(
            for: entry,
            now: try #require(ISO8601DateFormatter().date(from: "2027-08-28T12:00:01Z")),
            trustedAnchor: anchor
        ))

        try Data("{}".utf8).write(to: LocalEvidenceHoldStore.url(for: entry.manifestURL))
        #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
        }
    }

    @Test("Transfer receipt trust rejects raw, tampered, foreign-destination and self-signed files")
    func verifiesTransferReceiptsAgainstDeviceTrustAndExactArtifact() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("transfer-receipts")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "receipt", binding: .localDefault)
            let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
            let origin = "https://scopeproof.example"
            _ = try EvidenceLifecycleStore.update(entry: entry, status: .draft, owner: "Owner", reviewer: "Capture workflow",
                notes: "Captured synthetic test evidence for transfer integrity validation.", tags: [])
            let payload = try JSONSerialization.data(withJSONObject: ["receipt": ["attestation": [
                "version": 3, "manifestSchemaVersion": 8, "evidenceId": entry.manifest.evidenceID,
                "imageSha256": entry.manifest.sha256, "manifestSha256": sha256(artifact.manifestData),
                "chainEventHash": entry.manifest.chainEventHash, "chainSequence": 1,
                "provenanceKeyId": try #require(entry.manifest.provenance?.keyID), "signature": "provider-signature"
            ]]])
            #expect(!entry.isUploaded)
            try payload.write(to: entry.receiptURL)
            #expect(!entry.isUploaded)
            #expect(TransferReceipt.status(for: entry, kind: .hosted).contains("Unverified"))
            #expect(throws: (any Error).self) { try ValidatedEvidenceArtifact.exportFiles(for: entry) }
            try TransferReceipt.record(payload: payload, kind: .hosted, artifact: artifact,
                manifestURL: entry.manifestURL, destination: ["origin": origin], receiptURL: entry.receiptURL)
            #expect(entry.isUploaded)
            #expect(try ValidatedEvidenceArtifact.exportFiles(for: entry).contains { $0.sourceURL == entry.receiptURL })
            #expect(TransferReceipt.isVerified(for: entry, kind: .hosted, expectedDestination: ["origin": origin]))
            #expect(!TransferReceipt.isVerified(for: entry, kind: .hosted, expectedDestination: ["origin": "https://another.example"]))
            let valid = try Data(contentsOf: entry.receiptURL)
            var object = try #require(JSONSerialization.jsonObject(with: valid) as? [String: Any])
            object["destination"] = ["origin": "https://another.example"]
            try JSONSerialization.data(withJSONObject: object).write(to: entry.receiptURL)
            #expect(!entry.isUploaded)
            object = try #require(JSONSerialization.jsonObject(with: valid) as? [String: Any])
            object["unexpectedAuthority"] = "trusted"
            try JSONSerialization.data(withJSONObject: object).write(to: entry.receiptURL)
            #expect(!entry.isUploaded)
            var forged = try JSONDecoder().decode(TransferReceipt.self, from: valid)
            forged.provenance = try LocalProvenance.sign(
                payload: LocalProvenance.canonicalJSON(forged, removingTopLevelKeys: ["provenance"]),
                domain: TransferReceipt.domain, privateKeyData: P256.Signing.PrivateKey().rawRepresentation)
            try JSONEncoder().encode(forged).write(to: entry.receiptURL)
            #expect(!entry.isUploaded)
            try valid.write(to: entry.receiptURL)
            #expect(entry.isUploaded)
            KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
                #expect(!entry.isUploaded)
                #expect(KeychainStore.localTransferReceiptSigningKeyID() == nil)
            }
        }
    }

    @Test("Receipt schema and digest validation runs before a response is sealed")
    func rejectsUnboundProviderReceiptBeforeRecording() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("unbound-transfer")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "unbound", binding: .localDefault)
            let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
            #expect(throws: TransferReceiptFailure.self) {
                try TransferReceipt.record(payload: Data("{\"receipt\":{}}".utf8), kind: .hosted,
                    artifact: artifact, manifestURL: entry.manifestURL,
                    destination: ["origin": "https://scopeproof.example"], receiptURL: entry.receiptURL)
            }
            #expect(!FileManager.default.fileExists(atPath: entry.receiptURL.path))
            #expect(KeychainStore.localTransferReceiptSigningKeyID() == nil)
        }
    }

    @Test("Jira response binds the confirmed site, issue and exact attachment sizes")
    func validatesJiraTransferDestinationAndAttachments() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("jira-receipt")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "jira", binding: .localDefault, jiraIssueKey: "SEC-12")
            let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
            let destination = ["origin": "https://scopeproof.example", "siteURL": "https://team.atlassian.net", "issueKey": "SEC-12"]
            let value: [String: Any] = ["receiptId": "receipt-1", "evidenceId": entry.manifest.evidenceID,
                "issueKey": "SEC-12", "siteUrl": "https://team.atlassian.net", "uploadedAt": "2026-09-08T12:00:00Z",
                "receiptSha256": String(repeating: "a", count: 64), "signature": "server-only-hmac",
                "attachments": [["id": "1", "filename": entry.imageURL.lastPathComponent, "size": artifact.imageData.count],
                    ["id": "2", "filename": entry.manifestURL.lastPathComponent, "size": artifact.manifestData.count]]]
            let payload = try JSONSerialization.data(withJSONObject: ["receipt": value])
            try TransferReceipt.record(payload: payload, kind: .jira, artifact: artifact,
                manifestURL: entry.manifestURL, destination: destination, receiptURL: entry.jiraReceiptURL)
            #expect(TransferReceipt.isVerified(for: entry, kind: .jira, expectedDestination: destination))
            var wrongSite = destination
            wrongSite["siteURL"] = "https://another.atlassian.net"
            #expect(throws: TransferReceiptFailure.self) {
                try TransferReceipt.record(payload: payload, kind: .jira, artifact: artifact,
                    manifestURL: entry.manifestURL, destination: wrongSite, receiptURL: entry.jiraReceiptURL)
            }
            var wrongSize = value
            wrongSize["attachments"] = [["id": "1", "filename": entry.imageURL.lastPathComponent, "size": artifact.imageData.count + 1]]
            #expect(throws: TransferReceiptFailure.self) {
                try TransferReceipt.record(payload: JSONSerialization.data(withJSONObject: ["receipt": wrongSize]), kind: .jira,
                    artifact: artifact, manifestURL: entry.manifestURL, destination: destination, receiptURL: entry.jiraReceiptURL)
            }
        }
    }

    @Test("Executed hosted and Jira response constructors match the native receipt contract")
    func acceptsActualProviderResponseConstructorFixtures() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("provider-constructor")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "contract", binding: .localDefault, jiraIssueKey: "SEC-12")
            let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
            let replacements = ["__EVIDENCE_ID__": entry.manifest.evidenceID,
                "__IMAGE_HASH__": entry.manifest.sha256, "__MANIFEST_HASH__": sha256(artifact.manifestData),
                "__CHAIN_HASH__": entry.manifest.chainEventHash, "__KEY_ID__": try #require(entry.manifest.provenance?.keyID),
                "__IMAGE_FILENAME__": entry.imageURL.lastPathComponent,
                "__MANIFEST_FILENAME__": entry.manifestURL.lastPathComponent,
                "__LIFECYCLE_FILENAME__": EvidenceLifecycleStore.url(for: entry.manifestURL).lastPathComponent,
                "__IMAGE_SIZE__": String(artifact.imageData.count), "__MANIFEST_SIZE__": String(artifact.manifestData.count)]
            func resolve(_ fixture: String) -> Data {
                Data(replacements.reduce(fixture) { $0.replacingOccurrences(of: $1.key, with: $1.value) }.utf8)
            }
            try TransferReceipt.record(payload: resolve(ProviderContractFixture.hosted), kind: .hosted,
                artifact: artifact, manifestURL: entry.manifestURL,
                destination: ["origin": "https://scopeproof.example"], receiptURL: entry.receiptURL)
            #expect(entry.isUploaded)
            // The outer hosted artifact ID differs deliberately from the local
            // EV ID. Only the inner attestation binds the local artifact.
            try TransferReceipt.record(payload: resolve(ProviderContractFixture.jira), kind: .jira,
                artifact: artifact, manifestURL: entry.manifestURL,
                destination: ["origin": "https://scopeproof.example", "siteURL": "https://team.atlassian.net", "issueKey": "SEC-12"],
                receiptURL: entry.jiraReceiptURL)
            #expect(TransferReceipt.isVerified(for: entry, kind: .jira))
        }
    }

    @Test("Deleting a legal-hold marker fails closed when the trust head remains")
    func rejectsDeletedLegalHoldMarker() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
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
    }

    @Test("Hold changes preserve independently signed complete history in one atomic marker")
    func preservesCompleteHoldDecisionLedger() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("hold-ledger")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "ledger", binding: .localDefault)
            let key = P256.Signing.PrivateKey().rawRepresentation
            #expect(LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
            for active in [true, false, true] {
                _ = try LocalEvidenceHoldStore.set(entry: entry, active: active, actor: "Reviewer",
                    reason: active ? "Preserve audit matter evidence" : "Matter owner authorized release",
                    privateKeyDataOverride: key, expectedBinding: .localDefault)
            }
            let url = LocalEvidenceHoldStore.url(for: entry.manifestURL)
            let original = try Data(contentsOf: url)
            let current = try JSONDecoder().decode(LocalEvidenceHoldRecord.self, from: original)
            #expect(current.sequence == 3 && current.history?.count == 2)
            #expect(LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
            for data in current.history ?? [] {
                let prior = try JSONDecoder().decode(LocalEvidenceHoldRecord.self, from: data)
                #expect(LocalProvenance.verifyHold(prior) && prior.history == nil)
            }
            var truncated = current
            truncated.history?.removeFirst()
            try JSONEncoder().encode(truncated).write(to: url)
            #expect(!LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
            var tampered = current
            tampered.history?[0] = Data("{}".utf8)
            try JSONEncoder().encode(tampered).write(to: url)
            #expect(LocalEvidenceHoldStore.state(for: entry) == .invalid)
            try original.write(to: url)
            #expect(LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
        }
    }

    @Test("Legacy lost hold prefixes cannot be declared complete by a subsequent decision")
    func keepsMissingLegacyHoldHistoryExplicitlyIncomplete() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("legacy-hold-ledger")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "legacyledger", binding: .localDefault)
            let key = P256.Signing.PrivateKey().rawRepresentation
            var last: LocalEvidenceHoldRecord?
            for active in [true, false] {
                last = try LocalEvidenceHoldStore.set(entry: entry, active: active, actor: "Reviewer",
                    reason: "Synthetic legal matter decision", privateKeyDataOverride: key)
            }
            var legacy = try #require(last)
            legacy.history = nil
            try JSONEncoder().encode(legacy).write(to: LocalEvidenceHoldStore.url(for: entry.manifestURL))
            #expect(!LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
            _ = try LocalEvidenceHoldStore.set(entry: entry, active: true, actor: "Reviewer",
                reason: "Preserve new matter despite legacy history gap", privateKeyDataOverride: key)
            #expect(!LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
            if case .active = LocalEvidenceHoldStore.state(for: entry) {} else { Issue.record("New preservation hold must remain active") }
        }
    }

    @Test("Legacy signed holds migrate to an immutable trust head")
    func anchorsLegacyLegalHoldBeforeDeletion() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
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
    }

    @Test("Moving held evidence preserves its immutable legal-hold trust scope")
    func preservesLegalHoldAcrossMove() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
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
    }

    @Test("Retention preserves evidence when a hold marker is missing during a pending trust advance")
    @MainActor
    func retentionRejectsMissingPendingHoldMarker() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
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
            do {
                _ = try await CaptureHistory.removeExpired(
                    in: root, expectedBinding: .localDefault, retentionDays: 1,
                    now: try #require(ISO8601DateFormatter().date(from: "2026-08-28T12:00:00Z"))
                ) { _ in Issue.record("Paused retention must not contact the remote store"); return true }
                Issue.record("Retention must remain blocked until complete history is durable")
            } catch LocalRetentionFailure.durableHistoryRequired {
                // Expected containment: retain every local record.
            }
            #expect(FileManager.default.fileExists(atPath: entry.manifestURL.path))
            #expect(FileManager.default.fileExists(atPath: entry.imageURL.path))
        }
    }


    @Test("Default and named workspaces reject foreign records at discovery, load, index and export")
    func enforcesExpectedWorkspaceAtEveryReadBoundary() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("workspace-boundaries")
            defer { try? FileManager.default.removeItem(at: root) }
            let tenantA = TenantWorkspaceBinding(tenantID: "customer-a", workspaceID: "audit")
            let tenantB = TenantWorkspaceBinding(tenantID: "customer-b", workspaceID: "audit")
            let local = try makeBoundEvidence(in: root, name: "LOCAL", binding: .localDefault)
            let a = try makeBoundEvidence(in: tenantA.scopedEvidenceRoot(base: root), name: "CUSTOMERA", binding: tenantA)
            let b = try makeBoundEvidence(in: tenantB.scopedEvidenceRoot(base: root), name: "CUSTOMERB", binding: tenantB)
            let legacyA = try makeEvidence(in: tenantA.scopedEvidenceRoot(base: root), baseName: "LEGACYUNDERA")

            #expect(CaptureHistory.entries(in: root, expectedBinding: .localDefault).map(\.manifest.evidenceID) == [local.manifest.evidenceID])
            #expect(CaptureHistory.entries(in: tenantA.scopedEvidenceRoot(base: root), expectedBinding: tenantA).map(\.manifest.evidenceID) == [a.manifest.evidenceID])
            #expect(CaptureHistory.entries(in: tenantB.scopedEvidenceRoot(base: root), expectedBinding: tenantB).map(\.manifest.evidenceID) == [b.manifest.evidenceID])
            #expect(!CaptureHistory.isWithinReadableRoots(a.imageURL, primaryDirectory: root, expectedBinding: .localDefault))
            #expect(throws: EvidenceArtifactFailure.self) {
                try ValidatedEvidenceArtifact.load(a, expectedBinding: .localDefault)
            }
            #expect(throws: EvidenceArtifactFailure.self) {
                try ValidatedEvidenceArtifact.loadForLegacyBrowsing(legacyA, expectedBinding: tenantA)
            }
            #expect(try ValidatedEvidenceArtifact.load(a, expectedBinding: tenantA).provenanceVerified)
            #expect(throws: EvidenceArtifactFailure.self) {
                try EvidenceLifecycleStore.update(
                    entry: a, status: .draft, owner: "Test", reviewer: "Test",
                    notes: "Wrong workspace", tags: [], expectedBinding: .localDefault
                )
            }
            #expect(throws: EvidenceArtifactFailure.self) {
                try LocalEvidenceHoldStore.set(
                    entry: a, active: true, reason: "Wrong workspace",
                    expectedBinding: .localDefault
                )
            }

            let index = try LocalEvidenceIndex(
                databaseURL: root.appendingPathComponent("test-index.sqlite3"),
                expectedBinding: .localDefault, auditKeyData: Data(repeating: 0xA5, count: 32)
            )
            try index.sync(entries: [local, a, b])
            #expect(try index.search(LocalEvidenceQuery()).map(\.evidenceID) == [local.manifest.evidenceID])
            #expect(throws: EvidenceArtifactFailure.self) {
                try AssessorPackageExporter.export(
                    entries: [a], completeHistory: [a], expectedBinding: .localDefault,
                    to: root.appendingPathComponent("must-not-exist.zip"),
                    preparedBy: "Test", packageName: "Wrong workspace",
                    signingKeyOverride: P256.Signing.PrivateKey()
                )
            }
            #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("must-not-exist.zip").path))

            // Moving a correctly signed foreign pair outside the reserved tenant
            // subtree must not make it part of local/default.
            let moved = root.appendingPathComponent("moved", isDirectory: true)
            try FileManager.default.createDirectory(at: moved, withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: a.manifestURL, to: moved.appendingPathComponent(a.manifestURL.lastPathComponent))
            try FileManager.default.copyItem(at: a.imageURL, to: moved.appendingPathComponent(a.imageURL.lastPathComponent))
            #expect(CaptureHistory.entries(in: root, expectedBinding: .localDefault).map(\.manifest.evidenceID) == [local.manifest.evidenceID])
            #expect(CaptureHistory.captureChainIntegrity([local], expectedBinding: .localDefault))
            #expect(!CaptureHistory.captureChainIntegrity([local, a], expectedBinding: .localDefault))

            // Even duplicate IDs within the right workspace are not addressable.
            try FileManager.default.copyItem(at: local.manifestURL, to: moved.appendingPathComponent(local.manifestURL.lastPathComponent))
            try FileManager.default.copyItem(at: local.imageURL, to: moved.appendingPathComponent(local.imageURL.lastPathComponent))
            #expect(CaptureHistory.entries(in: root, expectedBinding: .localDefault).isEmpty)
        }
    }

    @Test("Paused retention preserves every file and chain anchor without invoking remote durability")
    @MainActor
    func retentionContainmentPreservesCompleteHistory() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("retention-containment")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeBoundEvidence(in: root, name: "RETAIN", binding: .localDefault)
            let files = [
                entry.imageURL, entry.manifestURL,
                EvidenceLifecycleStore.url(for: entry.manifestURL),
                LocalEvidenceHoldStore.url(for: entry.manifestURL),
                entry.receiptURL, entry.jiraReceiptURL, entry.s3ReceiptURL
            ]
            for file in files.dropFirst(2) {
                try Data("synthetic preserved decision".utf8).write(to: file)
            }
            let original = try files.map { try Data(contentsOf: $0) }
            let anchor = try KeychainStore.captureChainAnchor(binding: .localDefault)
            do {
                _ = try await CaptureHistory.removeExpired(
                    in: root, expectedBinding: .localDefault, retentionDays: 1,
                    now: Date(timeIntervalSince1970: 2_000_000_000)
                ) { _ in
                    Issue.record("Paused retention must not use a PNG-only remote durability result")
                    return true
                }
                Issue.record("Cleanup must fail closed")
            } catch LocalRetentionFailure.durableHistoryRequired {}
            #expect(try files.map { try Data(contentsOf: $0) } == original)
            #expect(try KeychainStore.captureChainAnchor(binding: .localDefault) == anchor)
            #expect(CaptureHistory.captureChainIntegrity([entry], expectedBinding: .localDefault))
        }
    }

    @Test("Exact-version archive expires only PNG and restores full signed history without changing trust")
    @MainActor
    func preservesAndRestoresArchivedHistory() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("archive-roundtrip")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeArchiveReadyEvidence(in: root)
            let snapshot = try LocalEvidenceArchive.snapshot(entry, expectedBinding: .localDefault)
            let record = try makeArchiveRecord(snapshot)
            try LocalEvidenceArchive.persist(record, for: entry, expectedBinding: .localDefault)
            let anchor = try #require(try KeychainStore.captureChainAnchor(binding: .localDefault))
            let trash = temporaryDirectory("isolated-test-trash")
            defer { try? FileManager.default.removeItem(at: trash) }
            try await LocalEvidenceArchive.expirePayload(for: entry, expectedBinding: .localDefault,
                remoteRevalidator: { _ in true }, trashPayload: { try FileManager.default.moveItem(at: $0, to: trash.appendingPathComponent($0.lastPathComponent)) })
            #expect(entry.isPayloadArchived)
            for file in snapshot.files where file.sourceURL != entry.imageURL { #expect(try Data(contentsOf: file.sourceURL) == file.data) }
            let history = CaptureHistory.entries(in: root, expectedBinding: .localDefault)
            #expect(history.count == 1 && history[0].manifest.evidenceID == entry.manifest.evidenceID)
            #expect(CaptureHistory.captureChainIntegrity(history, expectedBinding: .localDefault))
            #expect(try KeychainStore.captureChainAnchor(binding: .localDefault) == anchor)
            #expect(throws: EvidenceArchiveFailure.self) { try ValidatedEvidenceArtifact.exportFiles(for: entry, expectedBinding: .localDefault) }
            let index = try LocalEvidenceIndex(databaseURL: root.appendingPathComponent("index.sqlite3"), expectedBinding: .localDefault, auditKeyData: Data(repeating: 4, count: 32))
            try index.sync(entries: history)
            #expect(try index.search(LocalEvidenceQuery()).first?.payloadArchived == true)
            // Recover missing metadata from the archive too, never by regenerating it.
            try FileManager.default.removeItem(at: EvidenceLifecycleStore.url(for: entry.manifestURL))
            let staged = try stageArchiveFiles(snapshot.files, in: root)
            try LocalEvidenceArchive.restoreStagedFiles(staged, record: record, evidenceRoot: root, expectedBinding: .localDefault)
            #expect(!entry.isPayloadArchived)
            #expect(try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: .localDefault).imageData == validPNG)
            for file in snapshot.files { #expect(try Data(contentsOf: file.sourceURL) == file.data) }
            #expect(try KeychainStore.captureChainAnchor(binding: .localDefault) == anchor)
            #expect(LocalEvidenceHoldStore.hasCompleteHistory(for: entry))
        }
    }

    @Test("Remote archive verification failure and a concurrent hold always preserve PNG")
    @MainActor
    func refusesUnsafeArchiveExpiry() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("archive-failclosed")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeArchiveReadyEvidence(in: root)
            let record = try makeArchiveRecord(LocalEvidenceArchive.snapshot(entry, expectedBinding: .localDefault))
            try LocalEvidenceArchive.persist(record, for: entry, expectedBinding: .localDefault)
            var trashCalls = 0
            await #expect(throws: EvidenceArchiveFailure.self) {
                try await LocalEvidenceArchive.expirePayload(for: entry, expectedBinding: .localDefault,
                    remoteRevalidator: { _ in false }, trashPayload: { _ in trashCalls += 1 })
            }
            let key = try KeychainStore.localHoldPrivateKey()
            await #expect(throws: EvidenceArchiveFailure.self) {
                try await LocalEvidenceArchive.expirePayload(for: entry, expectedBinding: .localDefault,
                    remoteRevalidator: { _ in
                        _ = try LocalEvidenceHoldStore.set(entry: entry, active: true, actor: "Reviewer", reason: "New preservation matter",
                            privateKeyDataOverride: key, expectedBinding: .localDefault)
                        return true
                    }, trashPayload: { _ in trashCalls += 1 })
            }
            #expect(trashCalls == 0 && FileManager.default.fileExists(atPath: entry.imageURL.path))
        }
    }

    @Test("Archive recovery rejects wrong workspace, altered descriptors, and conflicting existing files")
    func refusesArchiveTrustSubstitution() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("archive-adversarial")
            defer { try? FileManager.default.removeItem(at: root) }
            let entry = try makeArchiveReadyEvidence(in: root)
            let snapshot = try LocalEvidenceArchive.snapshot(entry, expectedBinding: .localDefault)
            let record = try makeArchiveRecord(snapshot)
            try LocalEvidenceArchive.persist(record, for: entry, expectedBinding: .localDefault)
            let other = try #require(TenantWorkspaceBinding.validated(tenantID: "other", workspaceID: "audit"))
            #expect(throws: EvidenceArchiveFailure.self) { try LocalEvidenceArchive.validate(record, evidenceRoot: root, expectedBinding: other) }
            var altered = record; altered.provenance = nil
            #expect(throws: EvidenceArchiveFailure.self) { try LocalEvidenceArchive.validate(altered, evidenceRoot: root, expectedBinding: .localDefault) }
            let descriptor = LocalEvidenceArchive.url(for: entry.manifestURL)
            var unknown = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: descriptor)) as? [String: Any])
            unknown["unexpected"] = "must not be ignored"
            try JSONSerialization.data(withJSONObject: unknown).write(to: descriptor)
            #expect(throws: EvidenceArchiveFailure.self) { try LocalEvidenceArchive.load(for: entry, expectedBinding: .localDefault) }
            try LocalEvidenceArchive.encoded(record).write(to: descriptor)
            let staged = try stageArchiveFiles(snapshot.files, in: root)
            try Data("conflict".utf8).write(to: entry.imageURL)
            #expect(throws: EvidenceArchiveFailure.self) { try LocalEvidenceArchive.restoreStagedFiles(staged, record: record, evidenceRoot: root, expectedBinding: .localDefault) }
            #expect(try Data(contentsOf: entry.imageURL) == Data("conflict".utf8))
            try snapshot.files.first(where: { $0.sourceURL == entry.imageURL })!.data.write(to: entry.imageURL)
            try Data("tampered staged bytes".utf8).write(to: staged[0].sourceURL)
            #expect(throws: EvidenceArchiveFailure.self) { try LocalEvidenceArchive.restoreStagedFiles(staged, record: record, evidenceRoot: root, expectedBinding: .localDefault) }
        }
    }

    @Test("New capture chain continues through archived history and rejects loss of its descriptor")
    @MainActor
    func continuesChainAfterArchival() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("archive-chain")
            defer { try? FileManager.default.removeItem(at: root) }
            let captureKey = P256.Signing.PrivateKey().rawRepresentation
            let first = try makeArchiveReadyEvidence(in: root, captureKey: captureKey)
            let record = try makeArchiveRecord(LocalEvidenceArchive.snapshot(first, expectedBinding: .localDefault))
            try LocalEvidenceArchive.persist(record, for: first, expectedBinding: .localDefault)
            try await LocalEvidenceArchive.expirePayload(for: first, expectedBinding: .localDefault,
                remoteRevalidator: { _ in true }, trashPayload: { try FileManager.default.moveItem(at: $0, to: root.appendingPathComponent(".test-trash.png")) })
            let second = try makeBoundEvidence(in: root, name: "nextcapture", binding: .localDefault,
                captureKey: captureKey, sequence: 2, previousHash: first.manifest.chainEventHash,
                capturedAt: "2026-09-01T12:00:00Z")
            let history = CaptureHistory.entries(in: root, expectedBinding: .localDefault)
            #expect(history.count == 2 && history.first?.manifest.evidenceID == second.manifest.evidenceID)
            #expect(CaptureHistory.captureChainIntegrity(history, expectedBinding: .localDefault))
            #expect(first.isPayloadArchived)
            try FileManager.default.removeItem(at: LocalEvidenceArchive.url(for: first.manifestURL))
            #expect(!CaptureHistory.captureChainIntegrity(CaptureHistory.entries(in: root, expectedBinding: .localDefault), expectedBinding: .localDefault))
            #expect(try KeychainStore.captureChainAnchor(binding: .localDefault)?.sequence == 2)
        }
    }

    @Test("AWS submission preserves local identity, binds the exact PUT, and reconciles processing without duplicate upload")
    func submitsAndReconcilesAWSEvidence() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let root = temporaryDirectory("aws-submission")
            defer { try? FileManager.default.removeItem(at: root) }
            let tenant = "ten_" + String(repeating: "a", count: 32)
            let user = "usr_" + String(repeating: "b", count: 32)
            let assessmentID = "asm_" + String(repeating: "d", count: 32)
            let configuration = try AWSCollectorConfiguration(fields: ["apiOrigin": "http://localhost:8787", "tenantId": tenant, "displayName": "Synthetic Customer",
                "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Test", "authorizationEndpoint": "https://synthetic.auth.us-east-1.amazoncognito.com/oauth2/authorize",
                "tokenEndpoint": "https://synthetic.auth.us-east-1.amazoncognito.com/oauth2/token", "clientId": "publicClient123", "portalOrigin": "https://customer.example"])
            #expect(configuration.oauth.scopes.contains("scopeproof/evidence.collect"))
            #expect(configuration.portalOrigin?.host == "customer.example")
            let binding = TenantWorkspaceBinding(tenantID: tenant, workspaceID: assessmentID)
            let entry = try makeBoundEvidence(in: root, name: "AWSCAPTURE", binding: binding)
            _ = try EvidenceLifecycleStore.update(entry: entry, status: .draft, owner: "Owner", reviewer: "Reviewer", notes: "Local review", tags: [], privateKeyDataOverride: KeychainStore.localLifecyclePrivateKey(), expectedBinding: binding)
            let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: binding)
            let profile = AWSCollectorProfile(tenantId: tenant, tenantHostname: "localhost", userId: user, membershipId: "mem_" + String(repeating: "c", count: 32), role: "collector", tokenExpiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(3600)), uploadProofChallenge: "verified-jti-synthetic")
            let device = try KeychainStore.awsCollectorIdentity(scope: configuration.keyScope, userId: user)
            let catalog = AWSCollectorCatalog(id: "pci-test", title: "Synthetic catalog", framework: "PCI DSS", version: "4.0.1", controls: [.init(id: "8.3.1", requirement: "Requirement 8", title: "MFA", defaultEvidence: "Reviewed configuration")], digestSha256: String(repeating: "f", count: 64))
            let assessment = AWSCollectorAssessment(id: assessmentID, name: "Synthetic Assessment", status: "ACTIVE", revision: 0, framework: "PCI DSS 4.0.1", catalogId: catalog.id, systems: ["Okta"], controls: ["8.3.1"], periodStart: "2026-01-01", periodEnd: "2026-12-31", scopeLocked: true)
            let page = AWSCollectorAssessmentPage(tenantId: tenant, items: [assessment], nextCursor: nil, catalogs: [catalog])
            let selection = AWSCollectorSelection(tenantId: tenant, apiOrigin: configuration.apiOrigin.absoluteString, userId: user, deviceId: device.deviceId, assessmentId: assessmentID, assessmentRevision: 0, catalogId: catalog.id, catalogDigest: catalog.digestSha256, controlId: "8.3.1", systemName: "Okta")
            let fixture = NativeAWSUploadFixture(profile: profile, page: page, image: artifact.imageData)
            let service = AWSCollectorService(transport: { request, url, maximum in try await fixture.response(request: request, expectedURL: url, maximum: maximum) })
            _ = try await service.resume(configuration: configuration, store: NativeAWSUploadTestRefreshStore())
            let first = try await service.submit(entry: entry, selection: selection, configuration: configuration, put: { request, digest in try await fixture.put(request: request, digest: digest) })
            #expect(first.status == "QUARANTINED" && !first.presentation.contains("completed"))
            #expect(first.evidenceId.hasPrefix("evd_") && entry.manifest.evidenceID.hasPrefix("EV-"))
            await fixture.setStatus("NEEDS_REVIEW")
            let second = try await service.submit(entry: entry, selection: selection, configuration: configuration, put: { request, digest in try await fixture.put(request: request, digest: digest) })
            #expect(second.status == "NEEDS_REVIEW")
            let putCount = await fixture.putCount
            let intentCount = await fixture.intentCount
            #expect(putCount == 1 && intentCount == 1)
            #expect(try Data(contentsOf: entry.manifestURL) == artifact.manifestData)
            var journal = try #require(try KeychainStore.awsCollectorUpload(scope: configuration.keyScope, userId: user, manifestSHA: LocalEvidenceArchive.digest(artifact.manifestData)))
            #expect(journal.putCompleted && journal.serverStatus?.status == "NEEDS_REVIEW")
            journal.putCompleted = false; journal.serverStatus = nil
            try KeychainStore.saveAWSCollectorUpload(journal)
            await fixture.setStatus("QUARANTINED")
            let uncertain = try await service.submit(entry: entry, selection: selection, configuration: configuration, put: { request, digest in try await fixture.put(request: request, digest: digest) })
            #expect(uncertain.status == "QUARANTINED")
            #expect(await fixture.putCount == 1)
            await fixture.setStatus("APPROVED", approvedBy: "usr_" + String(repeating: "e", count: 32))
            let reviewed = try await service.submit(entry: entry, selection: selection, configuration: configuration, put: { request, digest in try await fixture.put(request: request, digest: digest) })
            #expect(reviewed.status == "APPROVED")
            await fixture.setStatus("APPROVED", approvedBy: user)
            await #expect(throws: AWSCollectorFailure.self) { try await service.submit(entry: entry, selection: selection, configuration: configuration, put: { request, digest in try await fixture.put(request: request, digest: digest) }) }
            let originalIntent = try #require(journal.intent)
            journal.intent = AWSCollectorUploadIntent(uploadIntentId: originalIntent.uploadIntentId, evidenceId: originalIntent.evidenceId, expiresAt: originalIntent.expiresAt,
                upload: .init(method: "PUT", url: originalIntent.upload.url.replacingOccurrences(of: "synthetic-bucket.s3.us-east-1.amazonaws.com", with: "attacker.example"), requiredHeaders: originalIntent.upload.requiredHeaders))
            #expect(throws: AWSCollectorUploadFailure.self) { try AWSCollectorService.putRequest(record: journal, imageData: artifact.imageData) }
            var badHeaders = originalIntent.upload.requiredHeaders; badHeaders["authorization"] = "must-never-forward"
            journal.intent = AWSCollectorUploadIntent(uploadIntentId: originalIntent.uploadIntentId, evidenceId: originalIntent.evidenceId, expiresAt: originalIntent.expiresAt, upload: .init(method: "PUT", url: originalIntent.upload.url, requiredHeaders: badHeaders))
            #expect(throws: AWSCollectorUploadFailure.self) { try AWSCollectorService.putRequest(record: journal, imageData: artifact.imageData) }
            if let path = ProcessInfo.processInfo.environment["SCOPEPROOF_NATIVE_UPLOAD_FIXTURE_PATH"] {
                let request = try #require(await fixture.requestData)
                let body = try JSONSerialization.jsonObject(with: request)
                let now = ISO8601DateFormatter().string(from: Date())
                try JSONSerialization.data(withJSONObject: ["body": body, "actor": ["tenantId": tenant, "userId": user], "identity": ["jwtId": profile.uploadProofChallenge!, "authenticatedAt": now], "now": now], options: [.sortedKeys]).write(to: URL(fileURLWithPath: path))
            }
        }
    }

    private func makeArchiveReadyEvidence(in root: URL, captureKey: Data? = nil) throws -> CaptureHistoryEntry {
        let entry = try makeBoundEvidence(in: root, name: "archivable", binding: .localDefault, captureKey: captureKey)
        _ = try EvidenceLifecycleStore.update(entry: entry, status: .approved, owner: "Owner", reviewer: "Reviewer",
            notes: "Reviewed original evidence", tags: [], privateKeyDataOverride: KeychainStore.localLifecyclePrivateKey(), expectedBinding: .localDefault)
        let key = try KeychainStore.localHoldPrivateKey()
        for active in [true, false] {
            _ = try LocalEvidenceHoldStore.set(entry: entry, active: active, actor: "Reviewer", reason: "Signed matter decision",
                privateKeyDataOverride: key, expectedBinding: .localDefault)
        }
        return entry
    }

    private func makeArchiveRecord(_ snapshot: EvidenceArchiveSnapshot) throws -> EvidenceArchiveRecord {
        let prefix = "scopeproof/tenant/workspace"
        let objects = snapshot.files.map { file in
            EvidenceArchiveObject(filename: file.sourceURL.lastPathComponent,
                objectKey: "\(prefix)/PCI/\(snapshot.entry.manifest.evidenceID)/\(file.sourceURL.lastPathComponent)",
                versionID: "synthetic-version-\(file.sourceURL.lastPathComponent)", eTag: "synthetic-etag",
                sha256: sha256(file.data), checksumSHA256: Data(SHA256.hash(data: file.data)).base64EncodedString(),
                byteCount: file.data.count, retainUntil: "2036-09-01T12:00:00Z")
        }
        return try LocalEvidenceArchive.makeRecord(snapshot: snapshot, objects: objects,
            destination: ["prefix": prefix, "securityProfile": S3SecurityProfile.production.rawValue, "retentionMode": S3RetentionMode.compliance.rawValue])
    }

    private func stageArchiveFiles(_ files: [ValidatedEvidenceFile], in root: URL) throws -> [ValidatedEvidenceFile] {
        let stage = root.appendingPathComponent(".synthetic-stage-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
        return try files.map { file in
            let url = stage.appendingPathComponent(file.sourceURL.lastPathComponent)
            try file.data.write(to: url)
            return ValidatedEvidenceFile(sourceURL: url, data: file.data)
        }
    }

    private func makeBoundEvidence(
        in root: URL, name: String, binding: TenantWorkspaceBinding, jiraIssueKey: String? = nil,
        captureKey: Data? = nil, sequence: Int = 1, previousHash: String = "GENESIS", capturedAt: String = "2026-08-11T12:00:00Z"
    ) throws -> CaptureHistoryEntry {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var manifest = makeManifest(baseName: name, schemaVersion: 8, chainSequence: sequence, chainPreviousHash: previousHash, capturedAt: capturedAt, jiraIssueKey: jiraIssueKey)
        manifest.tenantID = binding.tenantID
        manifest.workspaceID = binding.workspaceID
        manifest.provenance = try LocalProvenance.signManifest(
            manifest, privateKeyData: captureKey ?? P256.Signing.PrivateKey().rawRepresentation
        )
        _ = try KeychainStore.advanceCaptureChain(
            previousHash: previousHash, sequence: sequence, eventHash: manifest.chainEventHash,
            signingKeyID: try #require(manifest.provenance?.keyID), binding: binding
        )
        let imageURL = root.appendingPathComponent(manifest.screenshotFilename)
        let manifestURL = root.appendingPathComponent(name + ".json")
        try validPNG.write(to: imageURL)
        try JSONEncoder().encode(manifest).write(to: manifestURL)
        return CaptureHistoryEntry(
            manifest: manifest, manifestURL: manifestURL, imageURL: imageURL,
            receiptURL: root.appendingPathComponent(name + ".receipt.json"), evidenceRoot: root
        )
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
        capturedAt: String = "2026-08-11T12:00:00Z", jiraIssueKey: String? = nil
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
            manualRedactions: 0, reviewerNote: nil, jiraIssueKey: jiraIssueKey, jiraIssueURL: nil,
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
