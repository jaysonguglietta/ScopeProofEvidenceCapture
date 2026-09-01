import Foundation

enum LocalTrustDomain: String, Codable, Sendable {
    case lifecycle = "lifecycle"
    case legalHold = "legal-hold"
    case audit = "audit"
}

struct LocalTrustHead: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let domain: LocalTrustDomain
    let scopeDigest: String
    let sequence: Int
    let eventHash: String
    let signingKeyID: String
    let anchoredAt: String

    func matches(sequence: Int, eventHash: String, signingKeyID: String) -> Bool {
        self.sequence == sequence && self.eventHash == eventHash && self.signingKeyID == signingKeyID
    }

    var isValid: Bool {
        schemaVersion == Self.currentSchemaVersion && sequence > 0
            && scopeDigest.isSHA256 && eventHash.isSHA256 && signingKeyID.isSHA256
            && ISO8601DateFormatter().date(from: anchoredAt) != nil
    }
}

struct LocalTrustAdvance: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let domain: LocalTrustDomain
    let scopeDigest: String
    let previousHash: String
    let head: LocalTrustHead

    var isValid: Bool {
        schemaVersion == Self.currentSchemaVersion && head.isValid
            && domain == head.domain && scopeDigest == head.scopeDigest
            && (previousHash == "GENESIS" || previousHash.isSHA256)
    }
}

private extension String {
    var isSHA256: Bool {
        range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil
    }
}
