import CryptoKit
import Foundation

struct AssessorPackageResult: Sendable {
    let zipURL: URL
    let checksumURL: URL
    let evidenceCount: Int
    let sha256: String
}

enum AssessorPackageFailure: LocalizedError {
    case noApprovedEvidence
    case integrityMismatch(String)
    case packageToolFailed(String)

    var errorDescription: String? {
        switch self {
        case .noApprovedEvidence: return "No approved evidence matches the selected package scope. Approve evidence in Search Evidence before exporting."
        case .integrityMismatch(let evidenceID): return "Evidence \(evidenceID) failed integrity validation and was not exported. Restore the original artifact or recapture it."
        case .packageToolFailed(let detail): return "The assessor package could not be created. \(detail)"
        }
    }
}

enum AssessorPackageExporter {
    static func export(entries: [CaptureHistoryEntry], to destination: URL, preparedBy: String, packageName: String, jiraSettings: JiraHandoffSettings = .defaults) throws -> AssessorPackageResult {
        let approved = entries.filter { $0.lifecycle.status.isPackageEligible }
        guard !approved.isEmpty else { throw AssessorPackageFailure.noApprovedEvidence }
        let fileManager = FileManager.default
        let packageID = "PKG-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).uppercased())"
        let generatedAt = ISO8601DateFormatter().string(from: Date())
        let safePreparedBy = cleanLine(preparedBy, maximum: 160)
        let safePackageName = cleanLine(packageName, maximum: 180)
        let temporaryRoot = fileManager.temporaryDirectory.appendingPathComponent("scopeproof-assessor-\(UUID().uuidString)", isDirectory: true)
        let packageRoot = temporaryRoot.appendingPathComponent("Scopeproof Assessor Package", isDirectory: true)
        try fileManager.createDirectory(at: packageRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? fileManager.removeItem(at: temporaryRoot) }

        var artifactIndex: [[String: Any]] = []
        var csvRows = ["Evidence ID,Framework,Control,Control title,Jira issue,Jira URL,Evidence title,System,Environment,Assessment period,Captured at,Owner,Status,Tags,Redactions,SHA-256,File"]
        for entry in approved {
            let imageData = try Data(contentsOf: entry.imageURL, options: [.mappedIfSafe])
            guard sha256(imageData) == entry.manifest.sha256, EvidenceLifecycleStore.verify(entry.lifecycle) else { throw AssessorPackageFailure.integrityMismatch(entry.manifest.evidenceID) }
            let framework = ComplianceCatalog.framework(named: entry.manifest.complianceArea)
            let evidenceFolder = packageRoot.appendingPathComponent("Evidence", isDirectory: true)
                .appendingPathComponent(framework.folderName, isDirectory: true)
                .appendingPathComponent(ComplianceCatalog.safePathComponent(entry.manifest.controlID), isDirectory: true)
            try fileManager.createDirectory(at: evidenceFolder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let files = [entry.imageURL, entry.manifestURL, EvidenceLifecycleStore.url(for: entry.manifestURL), entry.receiptURL, entry.jiraReceiptURL]
                .filter { fileManager.fileExists(atPath: $0.path) }
            var packagedFiles: [[String: String]] = []
            for source in files {
                let target = evidenceFolder.appendingPathComponent(source.lastPathComponent)
                try fileManager.copyItem(at: source, to: target)
                let relative = target.path.replacingOccurrences(of: packageRoot.path + "/", with: "")
                packagedFiles.append(["path": relative, "sha256": sha256(try Data(contentsOf: target, options: [.mappedIfSafe]))])
            }
            let lifecycle = entry.lifecycle
            let frameworkName = entry.manifest.complianceArea ?? "PCI DSS 4.0.1"
            artifactIndex.append([
                "evidenceId": entry.manifest.evidenceID, "framework": frameworkName, "catalogVersion": entry.manifest.catalogVersion ?? "legacy",
                "controlId": entry.manifest.controlID, "controlTitle": entry.manifest.controlTitle ?? "", "title": entry.manifest.title,
                "jiraIssueKey": entry.manifest.jiraIssueKey ?? "", "jiraIssueURL": entry.manifest.jiraIssueURL ?? "",
                "system": entry.manifest.system, "environment": entry.manifest.environment, "assessmentPeriod": entry.manifest.assessmentPeriod,
                "capturedAt": entry.manifest.capturedAt, "owner": lifecycle.owner, "reviewer": lifecycle.reviewer, "status": lifecycle.status.rawValue,
                "tags": lifecycle.tags, "redactions": entry.manifest.redactedRegions + (entry.manifest.manualRedactions ?? 0),
                "screenshotSha256": entry.manifest.sha256, "captureChainEventHash": entry.manifest.chainEventHash,
                "lifecycleChainValid": true, "mappedControls": entry.manifest.mappedControls?.map { ["framework": $0.framework, "controlId": $0.controlID, "relationship": $0.relationship] } ?? [],
                "files": packagedFiles,
            ])
            let relativeImage = "Evidence/\(framework.folderName)/\(ComplianceCatalog.safePathComponent(entry.manifest.controlID))/\(entry.imageURL.lastPathComponent)"
            csvRows.append([
                entry.manifest.evidenceID, frameworkName, entry.manifest.controlID, entry.manifest.controlTitle ?? "", entry.manifest.jiraIssueKey ?? "", entry.manifest.jiraIssueURL ?? "", entry.manifest.title,
                entry.manifest.system, entry.manifest.environment, entry.manifest.assessmentPeriod, entry.manifest.capturedAt, lifecycle.owner,
                lifecycle.status.rawValue, lifecycle.tags.joined(separator: "; "), String(entry.manifest.redactedRegions + (entry.manifest.manualRedactions ?? 0)), entry.manifest.sha256, relativeImage,
            ].map(csv).joined(separator: ","))
        }

        let frameworks = Array(Set(approved.map { $0.manifest.complianceArea ?? "PCI DSS 4.0.1" })).sorted()
        let periods = Array(Set(approved.map { $0.manifest.assessmentPeriod })).sorted()
        var coverageRows = ["Framework,Catalog version,Control,Control title,Approved evidence,Coverage"]
        for frameworkName in frameworks {
            let framework = ComplianceCatalog.framework(named: frameworkName)
            let capturedControlIDs = Set(approved.filter { ($0.manifest.complianceArea ?? "PCI DSS 4.0.1") == frameworkName }.map { $0.manifest.controlID })
            var controls = framework.controls
            for customID in capturedControlIDs where !controls.contains(where: { $0.id == customID }) { controls.append(ComplianceControl(id: customID, title: "Custom or imported control")) }
            for control in controls {
                let count = approved.filter { ($0.manifest.complianceArea ?? "PCI DSS 4.0.1") == frameworkName && $0.manifest.controlID == control.id }.count
                coverageRows.append([frameworkName, framework.version ?? ComplianceCatalog.catalogVersion, control.id, control.title, String(count), count > 0 ? "Covered by package" : "No approved evidence in package"].map(csv).joined(separator: ","))
            }
        }
        let readme = """
        SCOPEPROOF ASSESSOR EVIDENCE PACKAGE

        Package: \(safePackageName)
        Package ID: \(packageID)
        Generated: \(generatedAt)
        Prepared by: \(safePreparedBy)
        Frameworks: \(frameworks.joined(separator: ", "))
        Assessment periods: \(periods.joined(separator: ", "))
        Approved evidence items: \(approved.count)

        START HERE
        1. Open 01-Control-Coverage.csv to identify covered controls and visible evidence gaps.
        2. Open 02-Evidence-Index.csv to browse approved evidence by framework and control.
        3. Open Evidence/<framework>/<control>/ to review the PNG and adjacent metadata.
        4. Each PNG has an immutable capture manifest (.json), review lifecycle (.review.json), and—when uploaded—a signed server receipt (.receipt.json).
        5. Follow 04-Verification.txt to validate file hashes and the package signature.
        6. When present, follow 05-Jira-Handoff.txt before attaching files to a Jira issue.

        PACKAGE POLICY
        Only evidence marked Approved is included. Draft, In Review, Rejected, and Superseded artifacts are excluded. Automated and manual redactions are irreversible; original unredacted pixels are not retained. Cross-framework mappings are informational and require assessor validation.
        """
        let readmeData = Data(readme.utf8)
        let coverageData = Data((coverageRows.joined(separator: "\n") + "\n").utf8)
        let indexData = Data((csvRows.joined(separator: "\n") + "\n").utf8)
        try readmeData.write(to: packageRoot.appendingPathComponent("00-READ-ME.txt"), options: [.atomic])
        try coverageData.write(to: packageRoot.appendingPathComponent("01-Control-Coverage.csv"), options: [.atomic])
        try indexData.write(to: packageRoot.appendingPathComponent("02-Evidence-Index.csv"), options: [.atomic])

        let jiraGuideData = Data(JiraHandoff.packageGuide(settings: jiraSettings, entries: approved).utf8)
        if jiraSettings.includeGuideInPackages {
            try jiraGuideData.write(to: packageRoot.appendingPathComponent("05-Jira-Handoff.txt"), options: [.atomic])
        }

        var administrativeFiles: [[String: String]] = [
            ["path": "00-READ-ME.txt", "sha256": sha256(readmeData)],
            ["path": "01-Control-Coverage.csv", "sha256": sha256(coverageData)],
            ["path": "02-Evidence-Index.csv", "sha256": sha256(indexData)],
        ]
        if jiraSettings.includeGuideInPackages { administrativeFiles.append(["path": "05-Jira-Handoff.txt", "sha256": sha256(jiraGuideData)]) }

        let unsigned: [String: Any] = [
            "schemaVersion": 1, "packageId": packageID, "packageName": safePackageName, "generatedAt": generatedAt, "preparedBy": safePreparedBy,
            "frameworks": frameworks, "assessmentPeriods": periods, "policy": ["includedStatus": "Approved", "excludedStatuses": ["Draft", "In Review", "Rejected", "Superseded"]],
            "administrativeFiles": administrativeFiles,
            "evidence": artifactIndex,
        ]
        let canonical = try JSONSerialization.data(withJSONObject: unsigned, options: [.sortedKeys, .withoutEscapingSlashes])
        let signingKey: P256.Signing.PrivateKey
        if let stored = KeychainStore.readPackageSigningKey(), let key = try? P256.Signing.PrivateKey(rawRepresentation: stored) {
            signingKey = key
        } else {
            signingKey = P256.Signing.PrivateKey()
            try KeychainStore.savePackageSigningKey(signingKey.rawRepresentation)
        }
        let publicKeyFingerprint = sha256(signingKey.publicKey.x963Representation)
        let signature = try signingKey.signature(for: canonical)
        let envelope: [String: Any] = [
            "manifest": unsigned,
            "signature": ["algorithm": "ECDSA-P256-SHA256", "canonicalization": "JSON sorted keys", "valueDERBase64": signature.derRepresentation.base64EncodedString(), "publicKeyX963Base64": signingKey.publicKey.x963Representation.base64EncodedString(), "publicKeySha256": publicKeyFingerprint, "keyStorage": "macOS Keychain; device-bound persistent signing identity"],
        ]
        let manifestData = try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try manifestData.write(to: packageRoot.appendingPathComponent("03-Package-Manifest.json"), options: [.atomic])
        let verify = """
        VERIFYING THIS PACKAGE

        1. For every file listed in 03-Package-Manifest.json, calculate SHA-256 and compare it with that file's recorded sha256 value.
        2. Canonicalize the object under the manifest property as JSON with lexicographically sorted keys and no insignificant whitespace.
        3. Verify signature.valueDERBase64 over those canonical bytes using ECDSA P-256/SHA-256 and signature.publicKeyX963Base64.
        4. For every screenshot, confirm its SHA-256 equals screenshotSha256 and its captureChainEventHash matches the adjacent capture manifest.
        5. Confirm every lifecycle chain starts at GENESIS and that each event's previousHash matches the preceding eventHash.

        SIGNER IDENTITY
        Public-key SHA-256: \(publicKeyFingerprint)
        Confirm this fingerprint with the package preparer through a separate trusted channel. The signing key is persistent and device-bound in the preparer's macOS Keychain; it is not a publicly trusted certificate.

        Package ID: \(packageID)
        Manifest SHA-256: \(sha256(manifestData))
        """
        try Data(verify.utf8).write(to: packageRoot.appendingPathComponent("04-Verification.txt"), options: [.atomic])

        if fileManager.fileExists(atPath: destination.path) { try fileManager.removeItem(at: destination) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", packageRoot.path, destination.path]
        let errorPipe = Pipe(); process.standardError = errorPipe
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw AssessorPackageFailure.packageToolFailed(String(detail.prefix(500)))
        }
        let packageDigest = sha256(try Data(contentsOf: destination, options: [.mappedIfSafe]))
        let checksumURL = destination.appendingPathExtension("sha256.txt")
        try Data("\(packageDigest)  \(destination.lastPathComponent)\n".utf8).write(to: checksumURL, options: [.atomic])
        return AssessorPackageResult(zipURL: destination, checksumURL: checksumURL, evidenceCount: approved.count, sha256: packageDigest)
    }

    private static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func csv(_ value: String) -> String { "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\"" }
    private static func cleanLine(_ value: String, maximum: Int) -> String {
        String(value.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespacesAndNewlines).prefix(maximum))
    }
}
