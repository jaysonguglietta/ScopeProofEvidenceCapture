import Foundation
import CoreGraphics
import CryptoKit
import Testing
@testable import ScopeproofCapture

@Suite("Sensitive data scanner")
struct SensitiveDataScannerTests {
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
        ("https://scopeproof.example", true),
        ("http://localhost:3000", true),
        ("http://127.0.0.1:3000", true),
        ("http://scopeproof.example", false),
        ("file:///tmp/evidence", false),
    ])
    func validatesServerTransport(value: String, expected: Bool) {
        #expect(UploadService.isAllowedServerURL(URL(string: value)!) == expected)
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
        let stamped = try service.stampedImage(source: source, stamp: "SCOPEPROOF EVIDENCE\nSOURCE Safari — https://admin.example/settings?api_token=very-sensitive-token-value-12345")
        let scan = try SensitiveDataScanner.scanAndRedact(stamped)

        #expect(scan.findings.contains { $0.kind == .apiToken })
        #expect(scan.redactedRegions > 0)
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
        let lifecycle = try EvidenceLifecycleStore.update(entry: entry, status: .approved, owner: "Control Owner", reviewer: "Reviewer", notes: "Verified against production configuration.", tags: ["identity"])
        #expect(EvidenceLifecycleStore.verify(lifecycle))

        let zipURL = root.appendingPathComponent("assessor.zip")
        let package = try AssessorPackageExporter.export(entries: [entry], to: zipURL, preparedBy: "Reviewer", packageName: "Q3 Assessment")
        #expect(package.evidenceCount == 1)
        #expect(FileManager.default.fileExists(atPath: package.zipURL.path))
        #expect(FileManager.default.fileExists(atPath: package.checksumURL.path))
        let comment = JiraHandoff.comment(for: entry, settings: .defaults)
        #expect(comment.contains("GRC-42"))
        #expect(comment.contains(digest))
    }
}
