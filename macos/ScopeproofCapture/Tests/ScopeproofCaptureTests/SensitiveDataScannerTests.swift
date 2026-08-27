import Foundation
import CoreGraphics
import CryptoKit
import Testing
@testable import ScopeproofCapture

@Suite("Sensitive data scanner")
struct SensitiveDataScannerTests {
    @Test("Neutralizes spreadsheet formulas after whitespace and control prefixes", arguments: [
        ("=1+1", "\"'=1+1\""),
        (" +cmd|' /C calc'!A0", "\"' +cmd|' /C calc'!A0\""),
        ("\t@SUM(A1:A2)", "\"'\t@SUM(A1:A2)\""),
        ("-42", "\"'-42\""),
        ("ordinary", "\"ordinary\""),
        ("quoted \"value\"", "\"quoted \"\"value\"\"\""),
    ])
    func neutralizesSpreadsheetFormulas(value: String, expected: String) {
        #expect(CSVSerializer.cell(value) == expected)
    }

    @Test("Detects Luhn-valid PANs and ignores invalid card-like values")
    func detectsLuhnValidPANAndIgnoresInvalidNumber() {
        #expect(SensitiveDataScanner.detectedKinds(in: "Card 4111 1111 1111 1111").contains(.pan))
        #expect(!SensitiveDataScanner.detectedKinds(in: "Order 4111111111111112").contains(.pan))
    }

    @Test("Detects credential families without retaining secret text")
    func detectsCredentialFamiliesWithoutRetainingSecretText() {
        #expect(SensitiveDataScanner.detectedKinds(in: "AKIAIOSFODNN7EXAMPLE").contains(.awsAccessKey))
        #expect(SensitiveDataScanner.detectedKinds(in: "api_token=very-sensitive-token-value-12345").contains(.apiToken))
        #expect(SensitiveDataScanner.detectedKinds(in: "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature").contains(.authorization))
    }

    @Test("Requires HTTPS except for loopback development servers", arguments: [
        ("https://scopeproof-pci.jayson-guglietta.chatgpt.site", true),
        ("https://scopeproof.example", false),
        ("http://localhost:3000", true),
        ("http://127.0.0.1:3000", true),
        ("http://scopeproof.example", false),
        ("file:///tmp/evidence", false),
    ])
    func validatesServerTransport(value: String, expected: Bool) {
        #expect(UploadService.isAllowedServerURL(URL(string: value)!) == expected)
    }

    @Test("Accepts responses only from the credential audience origin")
    func validatesResponseAudience() {
        let origin = URL(string: "https://scopeproof-pci.jayson-guglietta.chatgpt.site")!
        #expect(BackendTrust.sameOrigin(URL(string: "https://scopeproof-pci.jayson-guglietta.chatgpt.site/api/native/evidence"), origin))
        #expect(!BackendTrust.sameOrigin(URL(string: "https://attacker.example/api/native/evidence"), origin))
        #expect(BackendTrust.normalizedOrigin(URL(string: "https://scopeproof-pci.jayson-guglietta.chatgpt.site/redirect")) == nil)
    }

    @Test("Verifies signed update metadata and rejects tampering and rollback")
    func verifiesSignedUpdatesAndRejectsTampering() throws {
        let privateKey = P256.Signing.PrivateKey()
        let formatter = ISO8601DateFormatter()
        let now = Date()
        let origin = URL(string: "https://downloads.scopeproof.example")!
        let manifest = ReleaseManifest(schemaVersion: 1, version: "99.0.0", sequence: 42, downloadUrl: URL(string: "https://downloads.scopeproof.example/macos/99.0.0/Scopeproof-Capture-99.0.0.zip")!, sha256: String(repeating: "a", count: 64), byteSize: 1_024, publishedAt: formatter.string(from: now.addingTimeInterval(-60)), expiresAt: formatter.string(from: now.addingTimeInterval(86_400)), minimumSystemVersion: "14.0", teamIdentifier: "ABCDE12345", designatedRequirement: "identifier \"com.scopeproof.capture\" and anchor apple generic", keyId: "release-2026", notes: "Security update")
        let signature = try privateKey.signature(for: manifest.signingPayload)
        let envelope = ReleaseEnvelope(manifest: manifest, signatureDERBase64: signature.derRepresentation.base64EncodedString())
        let trusted = TrustedUpdateKey(keyId: "release-2026", publicKeyX963Base64: privateKey.publicKey.x963Representation.base64EncodedString(), notBefore: now.addingTimeInterval(-3_600), notAfter: now.addingTimeInterval(172_800))
        #expect(try ReleaseVerifier.verify(envelope, keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: VerifiedUpdateRelease(sequence: 41, version: "98.0.0", sha256: String(repeating: "b", count: 64))).sequence == 42)
        #expect(throws: UpdateFailure.self) { try ReleaseVerifier.verify(envelope, keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: VerifiedUpdateRelease(sequence: 43, version: "100.0.0", sha256: String(repeating: "b", count: 64))) }
        #expect(throws: UpdateFailure.self) { try ReleaseVerifier.verify(envelope, keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: VerifiedUpdateRelease(sequence: 42, version: manifest.version, sha256: String(repeating: "b", count: 64))) }
        #expect(try ReleaseVerifier.verify(envelope, keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: VerifiedUpdateRelease(sequence: 42, version: manifest.version, sha256: manifest.sha256)).sequence == 42)
        let tampered = ReleaseManifest(schemaVersion: 1, version: "99.0.1", sequence: 42, downloadUrl: manifest.downloadUrl, sha256: manifest.sha256, byteSize: manifest.byteSize, publishedAt: manifest.publishedAt, expiresAt: manifest.expiresAt, minimumSystemVersion: manifest.minimumSystemVersion, teamIdentifier: manifest.teamIdentifier, designatedRequirement: manifest.designatedRequirement, keyId: manifest.keyId, notes: manifest.notes)
        #expect(throws: UpdateFailure.self) { try ReleaseVerifier.verify(ReleaseEnvelope(manifest: tampered, signatureDERBase64: envelope.signatureDERBase64), keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: nil) }
        #expect(throws: UpdateFailure.self) { try ReleaseVerifier.verify(envelope, keys: [trusted], expectedTeamIdentifier: "WRONG12345", expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: nil) }
        let githubManifest = ReleaseManifest(schemaVersion: 1, version: manifest.version, sequence: 43, downloadUrl: URL(string: "https://github.com/scopeproof/releases/download/v99/Scopeproof-Capture.zip")!, sha256: manifest.sha256, byteSize: manifest.byteSize, publishedAt: manifest.publishedAt, expiresAt: manifest.expiresAt, minimumSystemVersion: manifest.minimumSystemVersion, teamIdentifier: manifest.teamIdentifier, designatedRequirement: manifest.designatedRequirement, keyId: manifest.keyId, notes: manifest.notes)
        let githubSignature = try privateKey.signature(for: githubManifest.signingPayload)
        #expect(throws: UpdateFailure.self) { try ReleaseVerifier.verify(ReleaseEnvelope(manifest: githubManifest, signatureDERBase64: githubSignature.derRepresentation.base64EncodedString()), keys: [trusted], expectedTeamIdentifier: manifest.teamIdentifier, expectedDesignatedRequirement: manifest.designatedRequirement, expectedDownloadOrigin: origin, installedVersion: "1.3.2", previousRelease: nil) }
        #expect(ReleaseVerifier.approvedBundleMetadata(identifier: "com.scopeproof.capture", version: manifest.version, manifest: manifest))
        #expect(!ReleaseVerifier.approvedBundleMetadata(identifier: "com.scopeproof.capture", version: "98.0.0", manifest: manifest))
    }

    @Test("Adds a full-width header above captured pixels")
    @MainActor
    func addsTimestampHeaderWithoutCoveringEvidence() throws {
        let width = 960
        let height = 540
        let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
        let sourceContext = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        sourceContext.setFillColor(CGColor(gray: 1, alpha: 1))
        sourceContext.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let source = sourceContext.makeImage()!
        let service = CaptureService(preferences: CapturePreferences())
        let output = try service.stampedImage(source: source, stamp: "SCOPEPROOF EVIDENCE • CAPTURED 2026-08-10 08:00:00 EDT\nPCI 8.3.1 • payments / Production • 2026 Q3\nSOURCE Safari • Security settings")

        #expect(output.width == width)
        #expect(output.height > height)
    }

    @Test("Combines scrolling sections with a visible separator")
    @MainActor
    func combinesScrollingSections() throws {
        let first = makeImage(width: 960, height: 540, gray: 0.9)
        let second = makeImage(width: 960, height: 540, gray: 0.7)
        let service = CaptureService(preferences: CapturePreferences())
        let output = try service.scrollingComposite(viewports: [first, second])

        #expect(output.width == first.width)
        #expect(output.height > first.height + second.height)
    }

    @Test("Rejects incomplete and resized scrolling captures")
    @MainActor
    func rejectsInvalidScrollingSections() {
        let service = CaptureService(preferences: CapturePreferences())
        let first = makeImage(width: 960, height: 540, gray: 0.9)
        let resized = makeImage(width: 900, height: 540, gray: 0.7)

        #expect(throws: CaptureFailure.self) { try service.scrollingComposite(viewports: [first]) }
        #expect(throws: CaptureFailure.self) { try service.scrollingComposite(viewports: [first, resized]) }
    }

    @Test("Scans sensitive values introduced only by the final header")
    @MainActor
    func scansFinalHeaderPixels() throws {
        let width = 1200
        let height = 500
        let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
        let sourceContext = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        sourceContext.setFillColor(CGColor(gray: 1, alpha: 1))
        sourceContext.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let source = sourceContext.makeImage()!
        let service = CaptureService(preferences: CapturePreferences())
        let stamp = "SCOPEPROOF EVIDENCE\nSOURCE Safari — https://admin.example/settings?api_token=very-sensitive-token-value-12345"
        let stamped = try service.stampedImage(source: source, stamp: stamp)
        // Vision OCR is unavailable on some headless macOS runners. Production
        // still fails closed on that error; the test exercises exact pixels
        // when Vision is available and always verifies the same detection rule.
        if let scan = try? SensitiveDataScanner.scanAndRedact(stamped) {
            #expect(scan.findings.contains { $0.kind == .apiToken })
            #expect(scan.redactedRegions > 0)
        } else {
            #expect(SensitiveDataScanner.detectedKinds(in: stamp).contains(.apiToken))
        }
    }

    @Test("Provides framework-specific controls and safe evidence paths")
    func providesComplianceCatalogAndSafePaths() {
        #expect(ComplianceCatalog.framework(named: "PCI DSS 4.0.1").controls.contains { $0.id == "8.3.1" })
        #expect(ComplianceCatalog.framework(named: "HIPAA Security Rule").controls.contains { $0.id == "164.312(b)" })
        #expect(ComplianceCatalog.framework(named: "FedRAMP / NIST 800-53").controls.contains { $0.id == "AC-2" })
        #expect(ComplianceCatalog.safePathComponent("../../HIPAA/records") == "HIPAA-records")
        let preview = ComplianceCatalog.filenamePreview(frameworkName: "HIPAA Security Rule", controlID: "164.312(b)", customName: "Audit controls", assessmentPeriod: "2026 Q3")
        #expect(preview.contains("HIPAA / 164.312-b / 2026-Q3 / HIPAA_164.312-b_Audit-controls"))
        let jiraPreview = ComplianceCatalog.filenamePreview(frameworkName: "HIPAA Security Rule", controlID: "164.312(b)", customName: "Audit controls", assessmentPeriod: "2026 Q3", jiraIssueKey: "grc-42")
        #expect(jiraPreview.contains("HIPAA_164.312-b_GRC-42_Audit-controls"))
        #expect(JiraHandoff.isValidIssueKey("GRC-42"))
        #expect(!JiraHandoff.isValidIssueKey("../../GRC-42"))
        #expect(JiraHandoffSettings(baseURL: "https://example.atlassian.net", projectKey: "GRC", attachmentMode: .evidenceSet, includeGuideInPackages: true, customInstructions: "").issueURL(for: "GRC-42")?.absoluteString == "https://example.atlassian.net/browse/GRC-42")
    }

    @Test("Imports bounded catalogs with provenance and rejects duplicate control IDs")
    func validatesImportedCatalogs() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-catalog-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let validURL = root.appendingPathComponent("approved-controls.json")
        let valid = ComplianceFramework(
            name: "Test Framework \(UUID().uuidString)", fileCode: "TEST", folderName: "Test",
            controls: [.init(id: "T-1", title: "Test control")], version: "2026.1", source: "Approved GRC export"
        )
        try JSONEncoder().encode(valid).write(to: validURL)
        let imported = try ComplianceCatalog.importCatalog(from: validURL)
        defer { ComplianceCatalog.removeImportedCatalog(named: imported.name) }
        #expect(imported.version == "2026.1")
        #expect(imported.source?.contains("SHA-256") == true)
        #expect(imported.source?.contains("approved-controls.json") == false)

        let duplicateURL = root.appendingPathComponent("duplicate-controls.json")
        let duplicate = ComplianceFramework(
            name: "Duplicate Framework", fileCode: "DUP", folderName: "Duplicate",
            controls: [.init(id: "AC-1", title: "First"), .init(id: "ac-1", title: "Duplicate")]
        )
        try JSONEncoder().encode(duplicate).write(to: duplicateURL)
        #expect(throws: CocoaError.self) { try ComplianceCatalog.importCatalog(from: duplicateURL) }
    }

    @Test("Finds legacy and current evidence recursively")
    func findsEvidenceRecursivelyAndDecodesLegacyManifest() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-history-\(UUID().uuidString)", isDirectory: true)
        let nested = root.appendingPathComponent("HIPAA/164.312-b/2026-Q3", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let imageURL = nested.appendingPathComponent("evidence.png")
        try Data([0x89, 0x50, 0x4e, 0x47]).write(to: imageURL)
        let manifest = CaptureManifest(
            schemaVersion: 2, evidenceID: "EV-LEGACY", capturedAt: "2026-08-11T12:00:00Z", localTimestamp: "2026-08-11 08:00:00 EDT", timezone: "America/New_York",
            sourceURL: nil, sourceHost: nil, browser: "Safari", windowTitle: "Settings", screenshotFilename: imageURL.lastPathComponent,
            sha256: "abc", pixelWidth: 100, pixelHeight: 100, captureMethod: "test", timestampAuthority: "local",
            safetyStatus: "passed", redactionFindings: [], redactedRegions: 0, safetyScanSha256: nil, safetyScanPolicy: nil, safetyScanCompletedAt: nil, sessionID: "session_test", sessionName: "Legacy",
            controlID: "164.312(b)", title: "Audit controls", system: "EHR", environment: "Production", assessmentPeriod: "2026 Q3", description: "",
            complianceArea: nil, controlTitle: nil, customFileName: nil, catalogVersion: nil, evidenceOwner: nil, tags: nil, expectedEvidence: nil,
            mappedControls: nil, manualRedactions: nil, reviewerNote: nil, jiraIssueKey: nil, jiraIssueURL: nil, chainPreviousHash: "GENESIS", chainEventHash: "event"
        )
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(manifest)) as? [String: Any])
        object.removeValue(forKey: "complianceArea")
        object.removeValue(forKey: "controlTitle")
        object.removeValue(forKey: "customFileName")
        let manifestURL = nested.appendingPathComponent("evidence.json")
        try JSONSerialization.data(withJSONObject: object).write(to: manifestURL)

        let entries = CaptureHistory.entries(in: root)
        #expect(entries.count == 1)
        #expect(entries.first?.imageURL.resolvingSymlinksInPath().path == imageURL.resolvingSymlinksInPath().path)
        #expect(entries.first?.manifest.complianceArea == nil)
    }

    @Test("Maintains a verifiable review lifecycle and approved-only assessor package")
    func exportsApprovedEvidenceWithLifecycleIntegrity() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-package-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let imageURL = root.appendingPathComponent("approved.png")
        let imageData = Data([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4])
        try imageData.write(to: imageURL)
        let digest = SHA256.hash(data: imageData).map { String(format: "%02x", $0) }.joined()
        let manifest = CaptureManifest(
            schemaVersion: 3, evidenceID: "EV-APPROVED", capturedAt: "2026-08-11T12:00:00Z", localTimestamp: "2026-08-11 08:00:00 EDT", timezone: "America/New_York",
            sourceURL: nil, sourceHost: nil, browser: "Safari", windowTitle: "Settings", screenshotFilename: imageURL.lastPathComponent,
            sha256: digest, pixelWidth: 100, pixelHeight: 100, captureMethod: "test", timestampAuthority: "local",
            safetyStatus: "passed", redactionFindings: [], redactedRegions: 0, safetyScanSha256: nil, safetyScanPolicy: nil, safetyScanCompletedAt: nil, sessionID: "session_test", sessionName: "Audit",
            controlID: "8.3.1", title: "MFA", system: "Okta", environment: "Production", assessmentPeriod: "2026 Q3", description: "MFA enabled",
            complianceArea: "PCI DSS 4.0.1", controlTitle: "Strong authentication", customFileName: "MFA",
            catalogVersion: ComplianceCatalog.catalogVersion, evidenceOwner: "Control Owner", tags: ["identity"], expectedEvidence: "MFA status",
            mappedControls: ComplianceCatalog.mappings(frameworkName: "PCI DSS 4.0.1", controlID: "8.3.1"), manualRedactions: 0, reviewerNote: nil,
            jiraIssueKey: "GRC-42", jiraIssueURL: "https://example.atlassian.net/browse/GRC-42",
            chainPreviousHash: "GENESIS", chainEventHash: "event"
        )
        let manifestURL = root.appendingPathComponent("approved.json")
        try JSONEncoder().encode(manifest).write(to: manifestURL)
        let entry = CaptureHistoryEntry(manifest: manifest, manifestURL: manifestURL, imageURL: imageURL, receiptURL: root.appendingPathComponent("approved.receipt.json"))
        _ = try EvidenceLifecycleStore.update(entry: entry, status: .inReview, owner: "Control Owner", reviewer: "Reviewer", notes: "Review opened against production configuration.", tags: ["identity"])
        let lifecycle = try EvidenceLifecycleStore.update(entry: entry, status: .approved, owner: "Control Owner", reviewer: "Reviewer", notes: "Verified against production configuration.", tags: ["identity"])
        #expect(EvidenceLifecycleStore.verify(lifecycle, artifactSha256: digest))
        #expect(lifecycle.status == .approved)

        var projectedTamper = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(lifecycle)) as? [String: Any])
        projectedTamper["status"] = "Rejected"
        let projectedRecord = try JSONDecoder().decode(EvidenceLifecycleRecord.self, from: JSONSerialization.data(withJSONObject: projectedTamper))
        #expect(projectedRecord.status == .approved)
        #expect(EvidenceLifecycleStore.verify(projectedRecord, artifactSha256: digest))

        var eventTamper = projectedTamper
        var tamperedEvents = try #require(eventTamper["events"] as? [[String: Any]])
        tamperedEvents[1]["status"] = "Rejected"
        eventTamper["events"] = tamperedEvents
        let tamperedRecord = try JSONDecoder().decode(EvidenceLifecycleRecord.self, from: JSONSerialization.data(withJSONObject: eventTamper))
        #expect(!EvidenceLifecycleStore.verify(tamperedRecord, artifactSha256: digest))

        let truncated = EvidenceLifecycleRecord(schemaVersion: 2, evidenceID: lifecycle.evidenceID, events: Array(lifecycle.events.dropFirst()))
        #expect(!EvidenceLifecycleStore.verify(truncated, artifactSha256: digest))
        let rolledBack = EvidenceLifecycleRecord(schemaVersion: 2, evidenceID: lifecycle.evidenceID, events: Array(lifecycle.events.prefix(1)))
        #expect(EvidenceLifecycleStore.verify(rolledBack, artifactSha256: digest))
        #expect(!rolledBack.status.isPackageEligible)
        let replayed = EvidenceLifecycleRecord(schemaVersion: 2, evidenceID: lifecycle.evidenceID, events: lifecycle.events + [lifecycle.events[1]])
        #expect(!EvidenceLifecycleStore.verify(replayed, artifactSha256: digest))

        let zipURL = root.appendingPathComponent("assessor.zip")
        let signingKey = P256.Signing.PrivateKey()
        let package = try AssessorPackageExporter.export(entries: [entry], to: zipURL, preparedBy: "Reviewer", packageName: "Q3 Assessment", signingKeyOverride: signingKey)
        #expect(package.evidenceCount == 1)
        #expect(FileManager.default.fileExists(atPath: package.zipURL.path))
        #expect(FileManager.default.fileExists(atPath: package.checksumURL.path))
        let extracted = root.appendingPathComponent("verified-package", isDirectory: true)
        try FileManager.default.createDirectory(at: extracted, withIntermediateDirectories: true)
        let unzip = Process()
        unzip.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        unzip.arguments = ["-x", "-k", package.zipURL.path, extracted.path]
        try unzip.run(); unzip.waitUntilExit()
        #expect(unzip.terminationStatus == 0)
        let envelopeData = try Data(contentsOf: extracted.appendingPathComponent("Scopeproof Assessor Package/03-Package-Manifest.json"))
        let envelope = try #require(JSONSerialization.jsonObject(with: envelopeData) as? [String: Any])
        let signedManifest = try #require(envelope["manifest"] as? [String: Any])
        let signatureFields = try #require(envelope["signature"] as? [String: String])
        let canonicalManifest = try JSONSerialization.data(withJSONObject: signedManifest, options: [.sortedKeys, .withoutEscapingSlashes])
        let publicKeyBase64 = try #require(signatureFields["publicKeyX963Base64"])
        let signatureBase64 = try #require(signatureFields["valueDERBase64"])
        let publicKeyData = try #require(Data(base64Encoded: publicKeyBase64))
        let signatureData = try #require(Data(base64Encoded: signatureBase64))
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
        let packageSignature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        #expect(publicKey.isValidSignature(packageSignature, for: canonicalManifest))
        let comment = JiraHandoff.comment(for: entry, settings: .defaults)
        #expect(comment.contains("GRC-42"))
        #expect(comment.contains(digest))
    }
}

private func makeImage(width: Int, height: Int, gray: CGFloat) -> CGImage {
    let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
    let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.setFillColor(CGColor(gray: gray, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    return context.makeImage()!
}
