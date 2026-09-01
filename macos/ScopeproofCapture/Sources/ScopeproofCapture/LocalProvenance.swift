import CryptoKit
import Foundation

struct LocalProvenanceSignature: Codable, Equatable, Sendable {
    static let algorithm = "ECDSA-P256-SHA256"

    let algorithm: String
    let keyID: String
    let publicKeyX963Base64: String
    let valueDERBase64: String
}

struct LocalCaptureChainAnchor: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let sequence: Int
    let eventHash: String
    let signingKeyID: String
    let anchoredAt: String
}

enum LocalProvenanceFailure: LocalizedError, Equatable {
    case invalidKey
    case invalidSignature
    case invalidAnchor
    case rollbackDetected

    var errorDescription: String? {
        switch self {
        case .invalidKey:
            return "The device-bound evidence signing identity is unavailable or invalid."
        case .invalidSignature:
            return "The evidence provenance signature is invalid."
        case .invalidAnchor:
            return "The Keychain-protected evidence-chain anchor is malformed."
        case .rollbackDetected:
            return "The local evidence chain does not match its Keychain-protected rollback anchor."
        }
    }
}

enum LocalProvenance {
    static let manifestDomain = "scopeproof-local-capture-manifest-v1"
    static let lifecycleDomain = "scopeproof-local-lifecycle-event-v1"
    static let holdDomain = "scopeproof-local-evidence-hold-v1"

    static func signManifest(
        _ manifest: CaptureManifest, privateKeyData: Data? = nil
    ) throws -> LocalProvenanceSignature {
        try sign(
            payload: canonicalJSON(manifest, removingTopLevelKeys: ["provenance"]),
            domain: manifestDomain,
            privateKeyData: try privateKeyData ?? KeychainStore.localProvenancePrivateKey()
        )
    }

    static func verifyManifest(_ manifest: CaptureManifest) -> Bool {
        guard let signature = manifest.provenance,
              let payload = try? canonicalJSON(manifest, removingTopLevelKeys: ["provenance"]) else { return false }
        return verify(signature, payload: payload, domain: manifestDomain)
    }

    static func signLifecycleEvent(
        _ event: EvidenceLifecycleEvent, evidenceID: String, privateKeyData: Data? = nil
    ) throws -> LocalProvenanceSignature {
        let payload = try canonicalJSON(
            SignedLifecycleEvent(evidenceID: evidenceID, event: event),
            removingTopLevelKeys: ["provenance"]
        )
        return try sign(
            payload: payload, domain: lifecycleDomain,
            privateKeyData: try privateKeyData ?? KeychainStore.localProvenancePrivateKey()
        )
    }

    static func verifyLifecycleEvent(_ event: EvidenceLifecycleEvent, evidenceID: String) -> Bool {
        guard let signature = event.provenance,
              let payload = try? canonicalJSON(
                SignedLifecycleEvent(evidenceID: evidenceID, event: event),
                removingTopLevelKeys: ["provenance"]
              ) else { return false }
        return verify(signature, payload: payload, domain: lifecycleDomain)
    }

    static func signHold(
        _ hold: LocalEvidenceHoldRecord, privateKeyData: Data? = nil
    ) throws -> LocalProvenanceSignature {
        try sign(
            payload: canonicalJSON(hold, removingTopLevelKeys: ["provenance"]),
            domain: holdDomain,
            privateKeyData: try privateKeyData ?? KeychainStore.localProvenancePrivateKey()
        )
    }

    static func verifyHold(_ hold: LocalEvidenceHoldRecord) -> Bool {
        guard let signature = hold.provenance,
              let payload = try? canonicalJSON(hold, removingTopLevelKeys: ["provenance"]) else {
            return false
        }
        return verify(signature, payload: payload, domain: holdDomain)
    }

    static func sign(
        payload: Data, domain: String, privateKeyData: Data
    ) throws -> LocalProvenanceSignature {
        guard !domain.isEmpty, let key = try? P256.Signing.PrivateKey(rawRepresentation: privateKeyData) else {
            throw LocalProvenanceFailure.invalidKey
        }
        let publicKey = key.publicKey.x963Representation
        let signingPayload = domainSeparated(domain: domain, payload: payload)
        let signature = try key.signature(for: signingPayload)
        return LocalProvenanceSignature(
            algorithm: LocalProvenanceSignature.algorithm,
            keyID: sha256(publicKey),
            publicKeyX963Base64: publicKey.base64EncodedString(),
            valueDERBase64: signature.derRepresentation.base64EncodedString()
        )
    }

    static func verify(
        _ signature: LocalProvenanceSignature, payload: Data, domain: String
    ) -> Bool {
        guard signature.algorithm == LocalProvenanceSignature.algorithm,
              signature.keyID.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              let publicKeyData = Data(base64Encoded: signature.publicKeyX963Base64),
              publicKeyData.count == 65, sha256(publicKeyData) == signature.keyID,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyData),
              let signatureData = Data(base64Encoded: signature.valueDERBase64),
              signatureData.count <= 80,
              let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: signatureData) else {
            return false
        }
        return publicKey.isValidSignature(ecdsa, for: domainSeparated(domain: domain, payload: payload))
    }

    static func canonicalJSON<T: Encodable>(
        _ value: T, removingTopLevelKeys keys: Set<String> = []
    ) throws -> Data {
        let encoded = try JSONEncoder().encode(value)
        guard var object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
            throw LocalProvenanceFailure.invalidSignature
        }
        for key in keys { object.removeValue(forKey: key) }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func domainSeparated(domain: String, payload: Data) -> Data {
        var data = Data("\(domain.utf8.count):\(domain)\n\(payload.count):".utf8)
        data.append(payload)
        return data
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private struct SignedLifecycleEvent: Encodable {
        let evidenceID: String
        let event: EvidenceLifecycleEvent

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(evidenceID, forKey: .evidenceID)
            try container.encode(event.sequence, forKey: .sequence)
            try container.encode(event.occurredAt, forKey: .occurredAt)
            try container.encode(event.actor, forKey: .actor)
            try container.encode(event.action, forKey: .action)
            try container.encode(event.status, forKey: .status)
            try container.encode(event.owner, forKey: .owner)
            try container.encode(event.reviewer, forKey: .reviewer)
            try container.encode(event.reviewNotes, forKey: .reviewNotes)
            try container.encode(event.tags, forKey: .tags)
            try container.encodeIfPresent(event.supersedesEvidenceID, forKey: .supersedesEvidenceID)
            try container.encode(event.artifactSha256, forKey: .artifactSha256)
            try container.encode(event.policyVersion, forKey: .policyVersion)
            try container.encode(event.safetyScanPolicy, forKey: .safetyScanPolicy)
            try container.encode(event.previousHash, forKey: .previousHash)
            try container.encode(event.eventHash, forKey: .eventHash)
            try container.encodeIfPresent(event.provenance, forKey: .provenance)
        }

        private enum CodingKeys: String, CodingKey {
            case evidenceID, sequence, occurredAt, actor, action, status, owner, reviewer
            case reviewNotes, tags, supersedesEvidenceID, artifactSha256, policyVersion
            case safetyScanPolicy, previousHash, eventHash, provenance
        }
    }
}
