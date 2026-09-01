import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Unified evidence library")
struct EvidenceLibraryTests {
    @Test("Indexes only current screenshot objects under the configured S3 layout")
    func indexesS3Screenshots() {
        let key = "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.png"
        let objects = [
            S3StoredObject(key: key, size: 900, lastModified: "2026-08-20T10:00:00Z", eTag: "old", versionID: "v1", isLatest: false),
            S3StoredObject(key: key, size: 1_024, lastModified: "2026-08-21T10:00:00Z", eTag: "new", versionID: "v2", isLatest: true),
            S3StoredObject(key: key.replacingOccurrences(of: ".png", with: ".json"), size: 200, lastModified: "2026-08-21T10:00:00Z", eTag: "manifest"),
            S3StoredObject(key: "scopeproof-evidence/10.2-Logging/2026-Q3/EV-DELETED/deleted.png", size: 500, lastModified: "2026-08-19T10:00:00Z", eTag: "deleted-old", versionID: "old", isLatest: false),
            S3StoredObject(key: "scopeproof-evidence/10.2-Logging/2026-Q3/EV-DELETED/deleted.json", size: 200, lastModified: "2026-08-19T10:00:00Z", eTag: "deleted-manifest"),
            S3StoredObject(key: "scopeproof-evidence/unexpected/EV-BAD.png", size: 100, lastModified: "2026-08-21T10:00:00Z", eTag: "invalid"),
        ]

        let screenshots = EvidenceLibraryBuilder.s3Screenshots(objects: objects, prefix: "scopeproof-evidence")
        #expect(screenshots.count == 1)
        #expect(screenshots.first?.evidenceID == "EV-ABC123")
        #expect(screenshots.first?.size == 1_024)
        #expect(screenshots.first?.versionCount == 2)
        #expect(screenshots.first?.controlFolder == "8.3.1-MFA")
    }

    @Test("Omits an evidence ID claimed by more than one S3 object key")
    func rejectsAmbiguousS3EvidenceIdentifiers() {
        let first = "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/first.png"
        let second = "scopeproof-evidence/10.2-Logging/2026-Q3/EV-ABC123/second.png"
        let objects = [
            S3StoredObject(key: first, size: 900, lastModified: "2026-08-20T10:00:00Z", eTag: "one", versionID: "v1"),
            S3StoredObject(key: second, size: 901, lastModified: "2026-08-21T10:00:00Z", eTag: "two", versionID: "v2"),
            S3StoredObject(key: first.replacingOccurrences(of: ".png", with: ".json"), size: 200, lastModified: "2026-08-20T10:00:01Z", eTag: "manifest-one", versionID: "m1"),
            S3StoredObject(key: second.replacingOccurrences(of: ".png", with: ".json"), size: 201, lastModified: "2026-08-21T10:00:01Z", eTag: "manifest-two", versionID: "m2"),
        ]

        #expect(EvidenceLibraryBuilder.s3Screenshots(objects: objects, prefix: "scopeproof-evidence").isEmpty)
    }

    @Test("Merges local and S3 screenshots by evidence ID without exposing object keys")
    func mergesStorageLocations() throws {
        let local = LocalEvidenceRecord(
            evidenceID: "EV-ABC123", capturedAt: "2026-08-21T10:00:00Z", localTimestamp: "Aug 21, 2026",
            complianceArea: "PCI DSS 4.0.1", controlID: "8.3.1", controlTitle: "MFA", title: "MFA settings",
            system: "Identity", environment: "Production", assessmentPeriod: "2026 Q3", owner: "Owner",
            reviewer: "", reviewStatus: "Draft", reviewNotes: "", tags: ["identity"], jiraIssueKey: nil,
            sourceURL: nil, safetyStatus: "Passed", sha256: String(repeating: "a", count: 64), uploaded: false,
            lifecycleValid: true
        )
        let stored = S3ScreenshotSummary(
            evidenceID: "EV-ABC123", controlFolder: "8.3.1-MFA", assessmentPeriod: "2026-Q3",
            filename: "PCI_8_3_EV-ABC123.png", size: 1_024, lastModified: "2026-08-21T10:00:00Z",
            versionCount: 1,
            object: S3StoredObject(key: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.png", size: 1_024, lastModified: "2026-08-21T10:00:00Z", eTag: "one", versionID: "image-v1"),
            manifestObject: S3StoredObject(key: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.json", size: 300, lastModified: "2026-08-21T10:00:01Z", eTag: "manifest-one", versionID: "manifest-v1"),
            receiptBinding: S3EvidenceReceiptBinding(
                evidenceID: "EV-ABC123",
                imageKey: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.png",
                imageVersionID: "image-v1", imageETag: "one", imageSHA256: String(repeating: "a", count: 64),
                manifestKey: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.json",
                manifestVersionID: "manifest-v1", manifestETag: "manifest-one", manifestSHA256: String(repeating: "b", count: 64)
            )
        )
        let s3Only = S3ScreenshotSummary(
            evidenceID: "EV-DEF456", controlFolder: "10.2-Audit-logging", assessmentPeriod: "2026-Q2",
            filename: "PCI_10_2_EV-DEF456.png", size: 2_048, lastModified: "2026-06-30T10:00:00Z",
            versionCount: 3,
            object: S3StoredObject(key: "scopeproof-evidence/10.2-Audit-logging/2026-Q2/EV-DEF456/PCI_10_2_EV-DEF456.png", size: 2_048, lastModified: "2026-06-30T10:00:00Z", eTag: "two"),
            manifestObject: S3StoredObject(key: "scopeproof-evidence/10.2-Audit-logging/2026-Q2/EV-DEF456/PCI_10_2_EV-DEF456.json", size: 300, lastModified: "2026-06-30T10:00:01Z", eTag: "manifest-two"),
            receiptBinding: nil
        )

        let records = EvidenceLibraryBuilder.merge(local: [local], s3: [stored, s3Only])
        #expect(records.count == 2)
        #expect(records.first(where: { $0.evidenceID == "EV-ABC123" })?.storageLocation == .localAndS3)
        #expect(records.first(where: { $0.evidenceID == "EV-ABC123" })?.reviewAvailable == true)
        #expect(records.first(where: { $0.evidenceID == "EV-DEF456" })?.storageLocation == .s3)
        #expect(records.first(where: { $0.evidenceID == "EV-DEF456" })?.reviewAvailable == false)
        #expect(records.first(where: { $0.evidenceID == "EV-DEF456" })?.s3PreviewAvailable == false)
        #expect(records.first(where: { $0.evidenceID == "EV-DEF456" })?.lifecycleValid == false)
        #expect(records.first(where: { $0.evidenceID == "EV-DEF456" })?.s3IntegrityVerified == false)

        let encoded = String(decoding: try JSONEncoder().encode(records), as: UTF8.self)
        #expect(!encoded.contains("scopeproof-evidence/"))
        #expect(!encoded.contains("accessKey"))
        #expect(!encoded.contains("secret"))
    }

    @Test("Does not merge an unverified newer S3 version into a local artifact")
    func rejectsUnboundS3Poisoning() {
        let local = LocalEvidenceRecord(
            evidenceID: "EV-ABC123", capturedAt: "2026-08-21T10:00:00Z", localTimestamp: "Aug 21, 2026",
            complianceArea: "PCI DSS 4.0.1", controlID: "8.3.1", controlTitle: "MFA", title: "MFA settings",
            system: "Identity", environment: "Production", assessmentPeriod: "2026 Q3", owner: "Owner",
            reviewer: "", reviewStatus: "Draft", reviewNotes: "", tags: [], jiraIssueKey: nil,
            sourceURL: nil, safetyStatus: "Passed", sha256: String(repeating: "a", count: 64), uploaded: false,
            lifecycleValid: true
        )
        let poisoned = S3ScreenshotSummary(
            evidenceID: "EV-ABC123", controlFolder: "8.3.1-MFA", assessmentPeriod: "2026-Q3",
            filename: "PCI_8_3_EV-ABC123.png", size: 999, lastModified: "2026-08-22T10:00:00Z",
            versionCount: 2,
            object: S3StoredObject(key: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.png", size: 999, lastModified: "2026-08-22T10:00:00Z", eTag: "attacker", versionID: "new-version"),
            manifestObject: S3StoredObject(key: "scopeproof-evidence/8.3.1-MFA/2026-Q3/EV-ABC123/PCI_8_3_EV-ABC123.json", size: 300, lastModified: "2026-08-22T10:00:01Z", eTag: "attacker-manifest", versionID: "new-manifest"),
            receiptBinding: nil
        )

        let record = EvidenceLibraryBuilder.merge(local: [local], s3: [poisoned], s3PreviewsAllowed: true)[0]
        #expect(record.storageLocation == .local)
        #expect(!record.s3Available)
        #expect(!record.s3PreviewAvailable)
        #expect(!record.s3IntegrityVerified)
        #expect(record.s3IntegrityStatus.contains("not bound"))
    }
}
