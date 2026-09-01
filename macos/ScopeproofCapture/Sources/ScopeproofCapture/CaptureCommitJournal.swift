import Foundation

struct LocalCaptureCommitJournal: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let evidenceID: String
    let tenantID: String
    let workspaceID: String
    let evidenceRootPath: String
    let imagePath: String
    let manifestPath: String
    let lifecyclePath: String
    let startedAt: String
    var chainPreviousHash: String? = nil
    var chainSequence: Int? = nil
    var chainEventHash: String? = nil
    var signingKeyID: String? = nil

    var binding: TenantWorkspaceBinding? {
        TenantWorkspaceBinding.validated(tenantID: tenantID, workspaceID: workspaceID)
    }

    var prospectiveAnchor: LocalCaptureChainAnchor? {
        guard let chainPreviousHash, let chainSequence, let chainEventHash, let signingKeyID,
              chainSequence > 0,
              chainPreviousHash == "GENESIS" || chainPreviousHash.isSHA256,
              chainEventHash.isSHA256, signingKeyID.isSHA256 else { return nil }
        return LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: chainSequence, eventHash: chainEventHash,
            signingKeyID: signingKeyID, anchoredAt: startedAt
        )
    }

    var isValid: Bool {
        schemaVersion == Self.currentSchemaVersion && binding != nil
            && evidenceID.range(of: #"^EV-[A-Z0-9]+$"#, options: .regularExpression) != nil
            && ISO8601DateFormatter().date(from: startedAt) != nil
            && [evidenceRootPath, imagePath, manifestPath, lifecyclePath].allSatisfy {
                $0.utf8.count <= 4_096 && $0.hasPrefix("/")
            }
    }
}

enum CaptureCommitRecoveryFailure: LocalizedError {
    case invalidJournal
    case conflictingCapture
    case rollbackDetected

    var errorDescription: String? {
        switch self {
        case .invalidJournal: return "The pending capture recovery journal is malformed or belongs to a different workspace."
        case .conflictingCapture: return "Another capture transaction is still pending recovery."
        case .rollbackDetected: return "The pending capture conflicts with the Keychain-protected capture-chain head."
        }
    }
}

enum CaptureCommitRecovery {
    enum Outcome: Equatable { case none, discardedPartial(String), committed(String) }

    static func reconcile(evidenceRoot: URL, binding: TenantWorkspaceBinding) throws -> Outcome {
        guard let journal = try KeychainStore.captureCommitJournal() else { return .none }
        guard journal.isValid, journal.binding == binding,
              journal.evidenceRootPath == evidenceRoot.standardizedFileURL.path else {
            throw CaptureCommitRecoveryFailure.invalidJournal
        }
        let urls = [journal.imagePath, journal.manifestPath, journal.lifecyclePath]
            .map { URL(fileURLWithPath: $0).standardizedFileURL }
        guard urls.allSatisfy({ isWithin($0, root: evidenceRoot) }) else {
            throw CaptureCommitRecoveryFailure.invalidJournal
        }
        guard let prospective = journal.prospectiveAnchor,
              urls.allSatisfy({ FileManager.default.fileExists(atPath: $0.path) }) else {
            for url in urls where FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.removeItem(at: url)
            }
            KeychainStore.clearCaptureCommitJournal(evidenceID: journal.evidenceID)
            return .discardedPartial(journal.evidenceID)
        }
        let manifestData = try ValidatedEvidenceArtifact.readBoundedRegularFile(
            at: urls[1], within: evidenceRoot,
            maximumBytes: ValidatedEvidenceArtifact.maximumManifestBytes
        )
        guard let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: manifestData),
              manifest.evidenceID == journal.evidenceID,
              manifest.tenantBinding == binding else {
            throw CaptureCommitRecoveryFailure.invalidJournal
        }
        let entry = CaptureHistoryEntry(
            manifest: manifest, manifestURL: urls[1], imageURL: urls[0],
            receiptURL: urls[1].deletingPathExtension().appendingPathExtension("receipt.json"),
            evidenceRoot: evidenceRoot
        )
        _ = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, trustedAnchor: prospective)
        let current = try KeychainStore.captureChainAnchor(binding: binding)
        if current != prospective {
            let canAdvance: Bool
            if let current {
                canAdvance = current.sequence == prospective.sequence - 1
                    && current.eventHash == journal.chainPreviousHash
                    && current.signingKeyID == prospective.signingKeyID
            } else {
                canAdvance = prospective.sequence == 1 && journal.chainPreviousHash == "GENESIS"
            }
            guard canAdvance else {
                throw CaptureCommitRecoveryFailure.rollbackDetected
            }
            _ = try KeychainStore.advanceCaptureChain(
                previousHash: journal.chainPreviousHash ?? "",
                sequence: prospective.sequence, eventHash: prospective.eventHash,
                signingKeyID: prospective.signingKeyID, binding: binding
            )
        }
        KeychainStore.clearCaptureCommitJournal(evidenceID: journal.evidenceID)
        return .committed(journal.evidenceID)
    }

    private static func isWithin(_ url: URL, root: URL) -> Bool {
        let rootPath = root.standardizedFileURL.path.hasSuffix("/")
            ? root.standardizedFileURL.path : root.standardizedFileURL.path + "/"
        return url.path.hasPrefix(rootPath) && url.path != root.standardizedFileURL.path
    }
}

private extension String {
    var isSHA256: Bool {
        range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil
    }
}
