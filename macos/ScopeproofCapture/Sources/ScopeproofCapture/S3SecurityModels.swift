import CryptoKit
import Foundation

enum S3SecurityProfile: String, Codable, CaseIterable, Sendable {
    case production = "Production compliance"
    case compatible = "Compatible S3"
}

enum S3EncryptionMode: String, Codable, CaseIterable, Sendable {
    case sseS3 = "AES256"
    case sseKMS = "aws:kms"
    case dsseKMS = "aws:kms:dsse"

    var displayName: String {
        switch self {
        case .sseS3: return "SSE-S3 (AES-256)"
        case .sseKMS: return "SSE-KMS"
        case .dsseKMS: return "DSSE-KMS"
        }
    }

    var needsKMSKey: Bool { self != .sseS3 }
}

enum S3RetentionMode: String, Codable, CaseIterable, Sendable {
    case governance = "GOVERNANCE"
    case compliance = "COMPLIANCE"

    var displayName: String { self == .compliance ? "Compliance" : "Governance" }
}

struct S3StorageSettings: Codable, Equatable, Sendable {
    var bucket: String
    var region: String
    var prefix: String
    var autoUpload: Bool
    var uploadsAllowed: Bool
    var securityProfile: S3SecurityProfile
    var encryptionMode: S3EncryptionMode
    var kmsKeyARN: String
    var retentionMode: S3RetentionMode
    var retentionDays: Int
    var archiveAfterDays: Int
    var downloadsAllowed: Bool
    var useFIPSEndpoint: Bool
    var replicationDestinationBucketARN: String
    var replicationRoleARN: String
    var replicationKMSKeyARN: String

    static let defaults = S3StorageSettings(
        bucket: "", region: "us-east-1", prefix: "scopeproof-evidence", autoUpload: false,
        uploadsAllowed: false, securityProfile: .production, encryptionMode: .sseKMS,
        kmsKeyARN: "", retentionMode: .governance, retentionDays: 365,
        archiveAfterDays: 90, downloadsAllowed: false, useFIPSEndpoint: false,
        replicationDestinationBucketARN: "", replicationRoleARN: "", replicationKMSKeyARN: ""
    )

    var isConfigured: Bool { !bucket.isEmpty && !region.isEmpty }
    var canUpload: Bool { isConfigured && uploadsAllowed }
    var replicationEnabled: Bool { !replicationDestinationBucketARN.isEmpty }

    init(
        bucket: String, region: String, prefix: String, autoUpload: Bool,
        uploadsAllowed: Bool = false, securityProfile: S3SecurityProfile = .compatible,
        encryptionMode: S3EncryptionMode = .sseS3, kmsKeyARN: String = "",
        retentionMode: S3RetentionMode = .governance, retentionDays: Int = 365,
        archiveAfterDays: Int = 0, downloadsAllowed: Bool = true, useFIPSEndpoint: Bool = false,
        replicationDestinationBucketARN: String = "", replicationRoleARN: String = "",
        replicationKMSKeyARN: String = ""
    ) {
        self.bucket = bucket
        self.region = region
        self.prefix = prefix
        self.autoUpload = autoUpload
        self.uploadsAllowed = uploadsAllowed
        self.securityProfile = securityProfile
        self.encryptionMode = encryptionMode
        self.kmsKeyARN = kmsKeyARN
        self.retentionMode = retentionMode
        self.retentionDays = retentionDays
        self.archiveAfterDays = archiveAfterDays
        self.downloadsAllowed = downloadsAllowed
        self.useFIPSEndpoint = useFIPSEndpoint
        self.replicationDestinationBucketARN = replicationDestinationBucketARN
        self.replicationRoleARN = replicationRoleARN
        self.replicationKMSKeyARN = replicationKMSKeyARN
    }

    private enum CodingKeys: String, CodingKey {
        case bucket, region, prefix, autoUpload, uploadsAllowed, securityProfile, encryptionMode, kmsKeyARN
        case retentionMode, retentionDays, archiveAfterDays, downloadsAllowed, useFIPSEndpoint
        case replicationDestinationBucketARN, replicationRoleARN, replicationKMSKeyARN
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        bucket = try values.decode(String.self, forKey: .bucket)
        region = try values.decode(String.self, forKey: .region)
        prefix = try values.decode(String.self, forKey: .prefix)
        autoUpload = try values.decode(Bool.self, forKey: .autoUpload)
        uploadsAllowed = try values.decodeIfPresent(Bool.self, forKey: .uploadsAllowed) ?? false
        securityProfile = try values.decodeIfPresent(S3SecurityProfile.self, forKey: .securityProfile) ?? .compatible
        encryptionMode = try values.decodeIfPresent(S3EncryptionMode.self, forKey: .encryptionMode) ?? .sseS3
        kmsKeyARN = try values.decodeIfPresent(String.self, forKey: .kmsKeyARN) ?? ""
        retentionMode = try values.decodeIfPresent(S3RetentionMode.self, forKey: .retentionMode) ?? .governance
        retentionDays = try values.decodeIfPresent(Int.self, forKey: .retentionDays) ?? 365
        archiveAfterDays = try values.decodeIfPresent(Int.self, forKey: .archiveAfterDays) ?? 0
        downloadsAllowed = try values.decodeIfPresent(Bool.self, forKey: .downloadsAllowed) ?? true
        useFIPSEndpoint = try values.decodeIfPresent(Bool.self, forKey: .useFIPSEndpoint) ?? false
        replicationDestinationBucketARN = try values.decodeIfPresent(String.self, forKey: .replicationDestinationBucketARN) ?? ""
        replicationRoleARN = try values.decodeIfPresent(String.self, forKey: .replicationRoleARN) ?? ""
        replicationKMSKeyARN = try values.decodeIfPresent(String.self, forKey: .replicationKMSKeyARN) ?? ""
    }

    static func validated(
        bucket: String, region: String, prefix: String, autoUpload: Bool, uploadsAllowed: Bool = false,
        securityProfile: S3SecurityProfile = .compatible, encryptionMode: S3EncryptionMode = .sseS3,
        kmsKeyARN: String = "", retentionMode: S3RetentionMode = .governance, retentionDays: Int = 365,
        archiveAfterDays: Int = 0, downloadsAllowed: Bool = true, useFIPSEndpoint: Bool = false,
        replicationDestinationBucketARN: String = "", replicationRoleARN: String = "",
        replicationKMSKeyARN: String = ""
    ) throws -> S3StorageSettings {
        let cleanBucket = bucket.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let cleanRegion = region.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var cleanPrefix = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
        while cleanPrefix.hasPrefix("/") { cleanPrefix.removeFirst() }
        while cleanPrefix.hasSuffix("/") { cleanPrefix.removeLast() }
        let cleanKMS = kmsKeyARN.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanDestination = replicationDestinationBucketARN.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanRole = replicationRoleARN.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanReplicaKMS = replicationKMSKeyARN.trimmingCharacters(in: .whitespacesAndNewlines)

        let reservedBucketName = cleanBucket.hasPrefix("xn--") || cleanBucket.hasPrefix("sthree-") || cleanBucket.hasPrefix("amzn_s3_demo_")
            || ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"].contains(where: cleanBucket.hasSuffix)
        let looksLikeIPAddress = cleanBucket.range(of: #"^\d{1,3}(?:\.\d{1,3}){3}$"#, options: .regularExpression) != nil
        guard cleanBucket.count >= 3, cleanBucket.count <= 63,
              cleanBucket.range(of: #"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"#, options: .regularExpression) != nil,
              !cleanBucket.contains(".."), !cleanBucket.contains(".-"), !cleanBucket.contains("-."),
              !reservedBucketName, !looksLikeIPAddress else { throw S3StorageFailure.invalidBucket }
        guard !cleanRegion.hasPrefix("cn-"),
              cleanRegion.range(of: #"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"#, options: .regularExpression) != nil else {
            throw S3StorageFailure.invalidRegion
        }
        let prefixSegments = cleanPrefix.split(separator: "/", omittingEmptySubsequences: false)
        guard cleanPrefix.count <= 240, !cleanPrefix.contains(".."), !cleanPrefix.contains("\\"), !cleanPrefix.contains("//"),
              prefixSegments.allSatisfy({ $0 != "." && $0 != ".." }),
              cleanPrefix.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else {
            throw S3StorageFailure.invalidPrefix
        }
        if securityProfile == .production && cleanPrefix.isEmpty { throw S3StorageFailure.productionPrefixRequired }
        guard (1...36_500).contains(retentionDays), archiveAfterDays == 0 || (30...36_500).contains(archiveAfterDays) else {
            throw S3StorageFailure.invalidRetention
        }

        if encryptionMode.needsKMSKey {
            guard isValidKMSKeyARN(cleanKMS, region: cleanRegion) else { throw S3StorageFailure.invalidKMSKey }
        } else if !cleanKMS.isEmpty {
            throw S3StorageFailure.kmsKeyNotApplicable
        }
        if securityProfile == .production && !encryptionMode.needsKMSKey { throw S3StorageFailure.productionKMSRequired }

        let replicationValues = [cleanDestination, cleanRole, cleanReplicaKMS]
        let hasAnyReplication = replicationValues.contains(where: { !$0.isEmpty })
        if hasAnyReplication {
            let partition = cleanRegion.hasPrefix("us-gov-") ? "aws-us-gov" : "aws"
            guard cleanDestination.range(of: #"^arn:"# + partition + #":s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"#, options: .regularExpression) != nil,
                  cleanRole.range(of: #"^arn:"# + partition + #":iam::\d{12}:role/[A-Za-z0-9+=,.@_\-/]{1,512}$"#, options: .regularExpression) != nil,
                  !encryptionMode.needsKMSKey || Self.isValidKMSKeyARN(cleanReplicaKMS, region: nil) else {
                throw S3StorageFailure.invalidReplication
            }
        }

        return S3StorageSettings(
            bucket: cleanBucket, region: cleanRegion, prefix: cleanPrefix, autoUpload: autoUpload,
            uploadsAllowed: uploadsAllowed, securityProfile: securityProfile, encryptionMode: encryptionMode,
            kmsKeyARN: cleanKMS, retentionMode: retentionMode, retentionDays: retentionDays,
            archiveAfterDays: archiveAfterDays, downloadsAllowed: downloadsAllowed, useFIPSEndpoint: useFIPSEndpoint,
            replicationDestinationBucketARN: cleanDestination, replicationRoleARN: cleanRole,
            replicationKMSKeyARN: cleanReplicaKMS
        )
    }

    private static func isValidKMSKeyARN(_ value: String, region: String?) -> Bool {
        let regionPattern = region.map(NSRegularExpression.escapedPattern(for:)) ?? #"[a-z]{2}(?:-gov)?-[a-z]+-\d"#
        return value.range(
            of: #"^arn:(?:aws|aws-us-gov):kms:"# + regionPattern + #":\d{12}:key/[A-Fa-f0-9-]{8,128}$"#,
            options: .regularExpression
        ) != nil
    }

    var securityBindingDigest: String {
        let fields = [
            bucket, region, prefix, securityProfile.rawValue, encryptionMode.rawValue, kmsKeyARN,
            retentionMode.rawValue, String(retentionDays), String(archiveAfterDays), String(downloadsAllowed),
            String(useFIPSEndpoint), replicationDestinationBucketARN, replicationRoleARN, replicationKMSKeyARN,
        ]
        return SHA256.hash(data: Data(fields.joined(separator: "\u{1f}").utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

struct S3Credentials: Codable, Equatable, Sendable {
    var accessKeyID: String
    var secretAccessKey: String
    var sessionToken: String
    var expiresAt: Date?

    init(accessKeyID: String, secretAccessKey: String, sessionToken: String, expiresAt: Date? = nil) {
        self.accessKeyID = accessKeyID
        self.secretAccessKey = secretAccessKey
        self.sessionToken = sessionToken
        self.expiresAt = expiresAt
    }

    var isTemporary: Bool { !sessionToken.isEmpty }
    var isExpired: Bool { expiresAt.map { $0 <= Date().addingTimeInterval(300) } ?? false }

    static func validated(accessKeyID: String, secretAccessKey: String, sessionToken: String, expiresAt: Date? = nil) throws -> S3Credentials {
        let access = accessKeyID.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret = secretAccessKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let session = sessionToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard access.count >= 16, access.count <= 128,
              access.range(of: #"^[A-Z0-9]+$"#, options: .regularExpression) != nil else { throw S3StorageFailure.invalidCredentials }
        guard secret.count >= 32, secret.count <= 128,
              secret.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7e }) else { throw S3StorageFailure.invalidCredentials }
        guard session.count <= 4_096,
              session.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7e }) else { throw S3StorageFailure.invalidCredentials }
        if let expiresAt, expiresAt <= Date().addingTimeInterval(300) { throw S3StorageFailure.expiredCredentials }
        return S3Credentials(accessKeyID: access, secretAccessKey: secret, sessionToken: session, expiresAt: expiresAt)
    }
}

struct S3CallerIdentity: Codable, Equatable, Sendable {
    let accountID: String
    let principalARN: String
    let userID: String
}

struct S3BucketPosture: Codable, Equatable, Sendable {
    let blockPublicAccess: Bool
    let versioningEnabled: Bool
    let ownershipEnforced: Bool
    let bucketPolicyEnforced: Bool
    let encryptionMode: S3EncryptionMode?
    let kmsKeyARN: String
    let objectLockEnabled: Bool
    let retentionMode: S3RetentionMode?
    let retentionDays: Int
    let lifecycleArchiveAfterDays: Int
    let replicationDestinationBucketARN: String

    init(
        blockPublicAccess: Bool, versioningEnabled: Bool, ownershipEnforced: Bool,
        bucketPolicyEnforced: Bool = false, encryptionMode: S3EncryptionMode?, kmsKeyARN: String,
        objectLockEnabled: Bool, retentionMode: S3RetentionMode?, retentionDays: Int,
        lifecycleArchiveAfterDays: Int, replicationDestinationBucketARN: String
    ) {
        self.blockPublicAccess = blockPublicAccess
        self.versioningEnabled = versioningEnabled
        self.ownershipEnforced = ownershipEnforced
        self.bucketPolicyEnforced = bucketPolicyEnforced
        self.encryptionMode = encryptionMode
        self.kmsKeyARN = kmsKeyARN
        self.objectLockEnabled = objectLockEnabled
        self.retentionMode = retentionMode
        self.retentionDays = retentionDays
        self.lifecycleArchiveAfterDays = lifecycleArchiveAfterDays
        self.replicationDestinationBucketARN = replicationDestinationBucketARN
    }

    func satisfies(_ settings: S3StorageSettings) -> Bool {
        guard blockPublicAccess, versioningEnabled, encryptionMode == settings.encryptionMode else { return false }
        if settings.encryptionMode.needsKMSKey && kmsKeyARN != settings.kmsKeyARN { return false }
        if settings.securityProfile == .production {
            guard ownershipEnforced, bucketPolicyEnforced, objectLockEnabled, retentionMode == settings.retentionMode,
                  retentionDays >= settings.retentionDays else { return false }
        }
        if settings.archiveAfterDays > 0 && lifecycleArchiveAfterDays != settings.archiveAfterDays { return false }
        if settings.replicationEnabled && replicationDestinationBucketARN != settings.replicationDestinationBucketARN { return false }
        return true
    }
}

struct S3VerifiedDestination: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let settingsDigest: String
    let accountID: String
    let principalARN: String
    let verifiedAt: Date
    let posture: S3BucketPosture

    func matches(_ settings: S3StorageSettings) -> Bool {
        schemaVersion == 1 && settingsDigest == settings.securityBindingDigest && posture.satisfies(settings)
    }
}

struct S3ObjectWriteReceipt: Codable, Equatable, Sendable {
    let eTag: String
    let versionID: String
    let checksumSHA256: String
    let requestID: String
    let extendedRequestID: String
    let encryptionMode: String
    let kmsKeyARN: String
}

struct S3DownloadResult: Equatable, Sendable {
    let sha256: String
    let versionID: String
    let requestID: String
    let contentValidated: Bool
}
