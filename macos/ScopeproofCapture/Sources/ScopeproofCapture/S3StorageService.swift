import CryptoKit
import Foundation

struct S3UploadReceipt: Codable, Sendable {
    let schemaVersion: Int
    let evidenceID: String
    let bucket: String
    let region: String
    let awsAccountID: String
    let principalARN: String
    let securityProfile: String
    let objectKeys: [String]
    let etags: [String: String]
    let versionIDs: [String: String]
    let s3ChecksumsSHA256: [String: String]
    let requestIDs: [String: String]
    let uploadedAt: String
    let encryption: String
    let kmsKeyARN: String
    let retentionMode: String
    let retentionDays: Int
    let retainUntilByObjectKey: [String: String]?
    let screenshotSHA256: String
    let manifestSHA256: String
}

struct S3StoredObject: Equatable, Hashable, Sendable {
    let key: String
    let size: Int64
    let lastModified: String
    let eTag: String
    let versionID: String
    let isLatest: Bool

    init(key: String, size: Int64, lastModified: String, eTag: String, versionID: String = "", isLatest: Bool = true) {
        self.key = key
        self.size = size
        self.lastModified = lastModified
        self.eTag = eTag
        self.versionID = versionID
        self.isLatest = isLatest
    }

    func relativeKey(prefix: String) -> String {
        let root = prefix.isEmpty ? "" : "\(prefix)/"
        return key.hasPrefix(root) ? String(key.dropFirst(root.count)) : key
    }
}

struct S3ObjectListPage: Equatable, Sendable {
    let objects: [S3StoredObject]
    let isTruncated: Bool
    let nextContinuationToken: String?
}

struct S3ObjectVersionListPage: Equatable, Sendable {
    let objects: [S3StoredObject]
    let isTruncated: Bool
    let nextKeyMarker: String?
    let nextVersionIDMarker: String?
}

struct S3ObjectRetentionExpectation: Equatable, Sendable {
    let mode: String
    let retainUntil: String
    let retainUntilDate: Date?
    let headers: [String: String]
}

enum S3StorageFailure: LocalizedError, Equatable {
    case notConfigured
    case verificationRequired
    case destinationBindingMismatch
    case invalidBucket
    case invalidRegion
    case invalidPrefix
    case productionPrefixRequired
    case invalidCredentials
    case expiredCredentials
    case temporaryCredentialsRequired
    case invalidIdentityCenterProfile
    case invalidAssumeRole
    case invalidExternalID
    case awsCLINotAvailable
    case awsCLIUnsafeExecutable
    case awsCLIRejected
    case awsCLITimedOut
    case identityCenterLoginRequired(String)
    case identityCenterLoginFailed
    case credentialIdentityMismatch
    case invalidKMSKey
    case kmsKeyNotApplicable
    case productionKMSRequired
    case productionComplianceRetentionRequired
    case kmsKeyIdentityMismatch
    case kmsKeyRejected(Int)
    case kmsKeyPostureFailed([String])
    case invalidRetention
    case invalidReplication
    case invalidEvidence
    case bucketCreationRejected(Int, String?)
    case bucketHardeningRejected(String, Int)
    case connectionRejected(Int, String?)
    case uploadRejected(Int, String?)
    case listRejected(Int)
    case listResponseTooLarge
    case tooManyObjects
    case objectOutsidePrefix
    case downloadRejected(Int)
    case downloadTooLarge
    case objectChanged
    case checksumMismatch
    case objectRetentionMismatch
    case unsupportedDownloadedContent
    case invalidDownloadDestination
    case bucketPostureFailed([String])
    case callerIdentityRejected(Int)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "Configure an S3 bucket and AWS credentials before using S3 storage."
        case .verificationRequired: return "Verify the S3 destination with Save & Verify or complete Create & Harden Bucket before uploading evidence."
        case .destinationBindingMismatch: return "The S3 destination no longer matches the Keychain-protected verified configuration. Run Save & Verify again."
        case .invalidBucket: return "Enter a valid S3 bucket name containing 3–63 lowercase letters, numbers, periods, or hyphens."
        case .invalidRegion: return "Enter an AWS region such as us-east-1 or us-gov-west-1."
        case .invalidPrefix: return "The S3 prefix must be a relative path no longer than 240 characters and cannot contain traversal or empty path segments."
        case .productionPrefixRequired: return "Production compliance mode requires a nonempty S3 prefix so IAM and audit events can be scoped to Scopeproof evidence."
        case .invalidCredentials: return "Enter a valid AWS access key ID and secret access key. Include the session token when using temporary credentials."
        case .expiredCredentials: return "The temporary AWS credentials are expired or expire within five minutes. Obtain a fresh STS session and try again."
        case .temporaryCredentialsRequired: return "Production compliance mode requires temporary STS credentials with a session token. Use a federated IAM Identity Center or AssumeRole session."
        case .invalidIdentityCenterProfile: return "Enter one named AWS CLI profile using only letters, numbers, periods, underscores, or hyphens. Configure it for IAM Identity Center before connecting."
        case .invalidAssumeRole: return "Enter one exact IAM role ARN in the same AWS partition as the S3 destination."
        case .invalidExternalID: return "The optional role external ID must be 2–1,224 characters and contain only AWS-supported letters, numbers, and _+=,.@:/- characters."
        case .awsCLINotAvailable: return "Install AWS CLI v2 in a trusted standard location, configure a named IAM Identity Center profile, and try again. Scopeproof never searches PATH or invokes a shell."
        case .awsCLIUnsafeExecutable: return "The AWS CLI executable resolved outside an approved installation directory or is writable by other users. Reinstall AWS CLI v2 in a trusted standard location."
        case .awsCLIRejected: return "AWS CLI could not provide a valid temporary credential set. Check the named profile, IAM permissions, network connection, and organization policy."
        case .awsCLITimedOut: return "AWS CLI did not finish before Scopeproof's safety deadline. Cancel any incomplete browser sign-in, check the network and named profile, then try again."
        case .identityCenterLoginRequired(let profile): return "IAM Identity Center profile \(profile) has no current session. Select ‘Sign in before verification’ or run aws sso login for that exact profile, then try again."
        case .identityCenterLoginFailed: return "IAM Identity Center sign-in did not complete. Confirm the browser authorization, profile configuration, network connection, and AWS CLI v2 installation."
        case .credentialIdentityMismatch: return "The refreshed AWS credential belongs to a different account or IAM role than the verified S3 destination. Uploads remain disabled until Save & Verify succeeds again."
        case .invalidKMSKey: return "Enter a customer-managed KMS key ARN in the same partition and region as the S3 bucket."
        case .kmsKeyNotApplicable: return "SSE-S3 does not use a KMS key. Select SSE-KMS or DSSE-KMS, or clear the KMS key ARN."
        case .productionKMSRequired: return "Production compliance mode requires SSE-KMS or DSSE-KMS with a customer-managed key."
        case .productionComplianceRetentionRequired: return "Production compliance mode requires COMPLIANCE Object Lock. Governance mode is for non-production evaluation only because privileged users can bypass or shorten its retention."
        case .kmsKeyIdentityMismatch: return "The KMS key ARN must use the verified AWS partition, S3 Region, and bucket-owner account. Uploads remain disabled."
        case .kmsKeyRejected(let status): return "AWS KMS rejected DescribeKey with HTTP \(status). Grant kms:DescribeKey on the exact key and verify the credentials, key policy, Region, and account."
        case .kmsKeyPostureFailed(let failures): return "The KMS key is not eligible for evidence encryption: " + failures.joined(separator: "; ")
        case .invalidRetention: return "Retention must be 1–36,500 days. Deep Archive transition must be 0 (disabled) or 30–36,500 days."
        case .invalidReplication: return "Replication requires a valid destination bucket ARN, IAM role ARN, and destination KMS key ARN when KMS encryption is enabled."
        case .invalidEvidence: return "The local evidence or manifest failed integrity validation and was not sent to S3."
        case .bucketCreationRejected(let status, let region):
            return region.map { "AWS rejected bucket creation with HTTP \(status) and reported region \($0). Bucket names are globally unique; verify the name, region, credentials, and s3:CreateBucket permission." }
                ?? "AWS rejected bucket creation with HTTP \(status). Bucket names are globally unique; verify the name, credentials, organization policies, and s3:CreateBucket permission."
        case .bucketHardeningRejected(let step, let status):
            return "The bucket may have been created, but AWS rejected \(step) with HTTP \(status). Automatic upload remains off. Grant the documented bucket-hardening permissions, then choose Create & Harden Bucket again."
        case .connectionRejected(let status, let region):
            return region.map { "S3 rejected the connection with HTTP \(status). The bucket reports region \($0); update the configured region or verify s3:ListBucket access." }
                ?? "S3 rejected the connection with HTTP \(status). Verify the bucket, region, credentials, clock, and s3:ListBucket permission."
        case .uploadRejected(let status, let region):
            return region.map { "S3 rejected the upload with HTTP \(status). The bucket reports region \($0); update the configured region and try again." }
                ?? "S3 rejected the upload with HTTP \(status). Verify s3:PutObject access, bucket policy, region, and encryption requirements."
        case .listRejected(let status): return "S3 rejected the evidence listing with HTTP \(status). Verify s3:ListBucket access for the configured prefix."
        case .listResponseTooLarge: return "The S3 listing exceeded the 5 MB safety limit and was rejected."
        case .tooManyObjects: return "The configured S3 prefix contains more than 5,000 files. Narrow the object prefix before browsing."
        case .objectOutsidePrefix: return "The selected object is outside the configured evidence prefix and cannot be downloaded."
        case .downloadRejected(let status): return status == 412 ? "The S3 object changed after it was listed. Refresh and select the current version." : "S3 rejected the download with HTTP \(status). Verify s3:GetObjectVersion and KMS decrypt access for the configured prefix."
        case .downloadTooLarge: return "The selected S3 object exceeds the 250 MB download safety limit."
        case .objectChanged: return "The S3 object changed while it was being downloaded. Refresh and try again."
        case .checksumMismatch: return "The checksum returned by S3 did not match the exact bytes Scopeproof sent or downloaded. The operation was rejected."
        case .objectRetentionMismatch: return "S3 did not confirm the configured Object Lock mode and retain-until timestamp on the exact uploaded object version."
        case .unsupportedDownloadedContent: return "The downloaded object does not contain a valid PNG or JSON evidence file and was rejected."
        case .invalidDownloadDestination: return "Choose a valid local file destination for the S3 download."
        case .bucketPostureFailed(let failures): return "The bucket is not production-ready: " + failures.joined(separator: "; ")
        case .callerIdentityRejected(let status): return "AWS STS rejected caller identity verification with HTTP \(status). Obtain fresh credentials and verify the configured region and clock."
        case .invalidResponse: return "AWS returned an invalid or redirected response. No credentials were sent to another host."
        }
    }
}

actor S3StorageService: S3CallerIdentityVerifying {
    static let maximumBrowsableObjects = 5_000
    static let maximumDownloadBytes: Int64 = 250 * 1024 * 1024
    private static let maximumListResponseBytes = 5 * 1024 * 1024
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 120
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        session = URLSession(configuration: configuration, delegate: S3RejectRedirectDelegate(), delegateQueue: nil)
    }

    func testConnection(settings: S3StorageSettings, credentials: S3Credentials) async throws -> S3VerifiedDestination {
        let cleanSettings = try Self.validatedSettings(settings)
        let cleanCredentials = try Self.validatedCredentials(credentials, for: cleanSettings)
        let identity = try await callerIdentity(settings: cleanSettings, credentials: cleanCredentials)
        let endpoint = try Self.endpoint(settings: cleanSettings, objectKey: nil)
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        var queryItems = [URLQueryItem(name: "list-type", value: "2"), URLQueryItem(name: "max-keys", value: "0")]
        if !cleanSettings.prefix.isEmpty { queryItems.append(URLQueryItem(name: "prefix", value: "\(cleanSettings.prefix)/")) }
        components?.queryItems = queryItems
        guard let url = components?.url else { throw S3StorageFailure.invalidResponse }
        let request = try Self.signedRequest(
            method: "GET", url: url, region: cleanSettings.region, body: Data(), contentType: nil,
            credentials: cleanCredentials, date: Date(), requireEncryption: false,
            expectedBucketOwner: identity.accountID
        )
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        guard http.statusCode == 200 else { throw S3StorageFailure.connectionRejected(http.statusCode, http.value(forHTTPHeaderField: "x-amz-bucket-region")) }
        let kmsKeyPosture = try await inspectKMSKey(
            settings: cleanSettings, credentials: cleanCredentials, expectedAccountID: identity.accountID
        )
        let posture = try await inspectBucketPosture(settings: cleanSettings, credentials: cleanCredentials, expectedOwner: identity.accountID)
        let failures = Self.postureFailures(posture, settings: cleanSettings)
        guard failures.isEmpty else { throw S3StorageFailure.bucketPostureFailed(failures) }
        return S3VerifiedDestination(
            schemaVersion: S3VerifiedDestination.currentSchemaVersion,
            settingsDigest: cleanSettings.securityBindingDigest,
            accountID: identity.accountID, principalARN: identity.principalARN,
            verifiedAt: Date(), posture: posture, kmsKeyPosture: kmsKeyPosture
        )
    }

    func createAndSecureBucket(settings: S3StorageSettings, credentials: S3Credentials) async throws -> S3VerifiedDestination {
        let cleanSettings = try Self.validatedSettings(settings)
        let cleanCredentials = try Self.validatedCredentials(credentials, for: cleanSettings)
        let identity = try await callerIdentity(settings: cleanSettings, credentials: cleanCredentials)
        _ = try await inspectKMSKey(
            settings: cleanSettings, credentials: cleanCredentials, expectedAccountID: identity.accountID
        )
        let createBody = Self.createBucketBody(region: cleanSettings.region)
        let createURL = try Self.endpoint(settings: cleanSettings, objectKey: nil)
        let createRequest = try Self.signedRequest(
            method: "PUT", url: createURL, region: cleanSettings.region, body: createBody,
            contentType: createBody.isEmpty ? nil : "application/xml", credentials: cleanCredentials,
            date: Date(), requireEncryption: false,
            extraHeaders: cleanSettings.securityProfile == .production ? ["x-amz-bucket-object-lock-enabled": "true"] : [:]
        )
        let (createResponseData, createResponse) = try await session.data(for: createRequest)
        guard let createHTTP = createResponse as? HTTPURLResponse, Self.isExpectedResponse(createHTTP, requestURL: createURL) else {
            throw S3StorageFailure.invalidResponse
        }
        let alreadyOwned = createHTTP.statusCode == 409 && Self.s3ErrorCode(createResponseData) == "BucketAlreadyOwnedByYou"
        guard (200...299).contains(createHTTP.statusCode) || alreadyOwned else {
            throw S3StorageFailure.bucketCreationRejected(createHTTP.statusCode, createHTTP.value(forHTTPHeaderField: "x-amz-bucket-region"))
        }

        try Task.checkCancellation()
        try await applyBucketSetting(
            operation: "publicAccessBlock", body: Self.publicAccessBlockBody,
            step: "Block Public Access", settings: cleanSettings, credentials: cleanCredentials,
            expectedOwner: identity.accountID
        )
        try Task.checkCancellation()
        try await applyBucketSetting(
            operation: "versioning", body: Self.versioningBody,
            step: "bucket versioning", settings: cleanSettings, credentials: cleanCredentials,
            expectedOwner: identity.accountID
        )
        try await applyBucketSetting(
            operation: "ownershipControls", body: Self.ownershipControlsBody,
            step: "bucket-owner-enforced object ownership", settings: cleanSettings,
            credentials: cleanCredentials, expectedOwner: identity.accountID
        )
        try await applyBucketSetting(
            operation: "encryption", body: Self.encryptionBody(settings: cleanSettings),
            step: "default bucket encryption", settings: cleanSettings,
            credentials: cleanCredentials, expectedOwner: identity.accountID
        )
        if !alreadyOwned && cleanSettings.securityProfile == .production {
            try await applyBucketSetting(
                operation: "policy", body: try Self.bucketPolicyBody(settings: cleanSettings),
                step: "TLS and KMS bucket policy", settings: cleanSettings,
                credentials: cleanCredentials, expectedOwner: identity.accountID,
                contentType: "application/json"
            )
        }
        if cleanSettings.securityProfile == .production {
            try await applyBucketSetting(
                operation: "object-lock", body: Self.objectLockBody(settings: cleanSettings),
                step: "Object Lock retention", settings: cleanSettings,
                credentials: cleanCredentials, expectedOwner: identity.accountID
            )
        }
        if !alreadyOwned && cleanSettings.archiveAfterDays > 0 {
            try await applyBucketSetting(
                operation: "lifecycle", body: Self.lifecycleBody(settings: cleanSettings),
                step: "Deep Archive lifecycle", settings: cleanSettings,
                credentials: cleanCredentials, expectedOwner: identity.accountID
            )
        }
        if !alreadyOwned && cleanSettings.replicationEnabled {
            try await applyBucketSetting(
                operation: "replication", body: Self.replicationBody(settings: cleanSettings),
                step: "cross-account replication", settings: cleanSettings,
                credentials: cleanCredentials, expectedOwner: identity.accountID
            )
        }
        return try await testConnection(settings: cleanSettings, credentials: cleanCredentials)
    }

    func upload(_ capture: CaptureResult, settings: S3StorageSettings, credentials: S3Credentials, binding: S3VerifiedDestination) async throws -> URL {
        guard settings.uploadsAllowed else { throw S3StorageFailure.verificationRequired }
        let cleanSettings = try Self.validatedSettings(settings)
        guard binding.matches(cleanSettings) else { throw S3StorageFailure.destinationBindingMismatch }
        let cleanCredentials = try Self.validatedCredentials(credentials, for: cleanSettings)
        let artifact: ValidatedEvidenceArtifact
        do { artifact = try ValidatedEvidenceArtifact.load(capture) }
        catch { throw S3StorageFailure.invalidEvidence }
        let image = artifact.imageData
        let manifestData = artifact.manifestData
        guard artifact.manifest.controlID == capture.context.controlID else { throw S3StorageFailure.invalidEvidence }

        let base = Self.objectBase(settings: cleanSettings, context: capture.context, evidenceID: capture.evidenceID)
        let imageKey = "\(base)/\(capture.imageURL.lastPathComponent)"
        let manifestKey = "\(base)/\(capture.manifestURL.lastPathComponent)"
        let imageWrite = try await put(
            image, contentType: "image/png", objectKey: imageKey, settings: cleanSettings,
            credentials: cleanCredentials, expectedOwner: binding.accountID
        )
        try Task.checkCancellation()
        let manifestWrite = try await put(
            manifestData, contentType: "application/json", objectKey: manifestKey, settings: cleanSettings,
            credentials: cleanCredentials, expectedOwner: binding.accountID
        )

        let receipt = S3UploadReceipt(
            schemaVersion: 3, evidenceID: capture.evidenceID, bucket: cleanSettings.bucket, region: cleanSettings.region,
            awsAccountID: binding.accountID, principalARN: binding.principalARN,
            securityProfile: cleanSettings.securityProfile.rawValue,
            objectKeys: [imageKey, manifestKey],
            etags: [imageKey: imageWrite.eTag, manifestKey: manifestWrite.eTag],
            versionIDs: [imageKey: imageWrite.versionID, manifestKey: manifestWrite.versionID],
            s3ChecksumsSHA256: [imageKey: imageWrite.checksumSHA256, manifestKey: manifestWrite.checksumSHA256],
            requestIDs: [imageKey: imageWrite.requestID, manifestKey: manifestWrite.requestID],
            uploadedAt: ISO8601DateFormatter().string(from: Date()), encryption: cleanSettings.encryptionMode.rawValue,
            kmsKeyARN: cleanSettings.kmsKeyARN, retentionMode: cleanSettings.retentionMode.rawValue,
            retentionDays: cleanSettings.retentionDays,
            retainUntilByObjectKey: [imageKey: imageWrite.retainUntil, manifestKey: manifestWrite.retainUntil],
            screenshotSHA256: Self.sha256(image), manifestSHA256: Self.sha256(manifestData)
        )
        let receiptURL = capture.manifestURL.deletingPathExtension().appendingPathExtension("s3.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(receipt).write(to: receiptURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
        return receiptURL
    }

    func listObjects(settings: S3StorageSettings, credentials: S3Credentials, binding: S3VerifiedDestination) async throws -> [S3StoredObject] {
        guard settings.canUpload else { throw S3StorageFailure.verificationRequired }
        let cleanSettings = try Self.validatedSettings(settings)
        guard binding.matches(cleanSettings) else { throw S3StorageFailure.destinationBindingMismatch }
        let cleanCredentials = try Self.validatedCredentials(credentials, for: cleanSettings)
        var objects: [S3StoredObject] = []
        var scannedObjectCount = 0
        var keyMarker: String?
        var versionIDMarker: String?
        repeat {
            try Task.checkCancellation()
            let url = try Self.listObjectVersionsEndpoint(
                settings: cleanSettings, maximumKeys: 1_000,
                keyMarker: keyMarker, versionIDMarker: versionIDMarker
            )
            let request = try Self.signedRequest(
                method: "GET", url: url, region: cleanSettings.region, body: Data(), contentType: nil,
                credentials: cleanCredentials, date: Date(), requireEncryption: false,
                expectedBucketOwner: binding.accountID
            )
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
            guard http.statusCode == 200 else { throw S3StorageFailure.listRejected(http.statusCode) }
            guard data.count <= Self.maximumListResponseBytes else { throw S3StorageFailure.listResponseTooLarge }
            let page = try Self.parseObjectVersionList(data, requiredPrefix: cleanSettings.prefix)
            guard scannedObjectCount + page.objects.count <= Self.maximumBrowsableObjects else { throw S3StorageFailure.tooManyObjects }
            scannedObjectCount += page.objects.count
            objects.append(contentsOf: page.objects.filter { !$0.key.hasSuffix("/") })
            if page.isTruncated {
                guard let nextKey = page.nextKeyMarker, let nextVersion = page.nextVersionIDMarker,
                      nextKey != keyMarker || nextVersion != versionIDMarker else { throw S3StorageFailure.invalidResponse }
                keyMarker = nextKey
                versionIDMarker = nextVersion
            } else {
                keyMarker = nil
                versionIDMarker = nil
            }
        } while keyMarker != nil
        return objects.sorted { $0.key.localizedStandardCompare($1.key) == .orderedAscending }
    }

    func downloadObject(
        _ object: S3StoredObject, settings: S3StorageSettings, credentials: S3Credentials,
        binding: S3VerifiedDestination, to destinationURL: URL
    ) async throws -> S3DownloadResult {
        guard settings.canUpload else { throw S3StorageFailure.verificationRequired }
        let cleanSettings = try Self.validatedSettings(settings)
        guard cleanSettings.downloadsAllowed else { throw S3StorageFailure.downloadRejected(403) }
        guard binding.matches(cleanSettings) else { throw S3StorageFailure.destinationBindingMismatch }
        let cleanCredentials = try Self.validatedCredentials(credentials, for: cleanSettings)
        let requiredPrefix = cleanSettings.prefix.isEmpty ? "" : "\(cleanSettings.prefix)/"
        guard destinationURL.isFileURL, !destinationURL.lastPathComponent.isEmpty else { throw S3StorageFailure.invalidDownloadDestination }
        guard Self.isSafeObjectKey(object.key), object.key.hasPrefix(requiredPrefix) else { throw S3StorageFailure.objectOutsidePrefix }
        guard object.size >= 0, object.size <= Self.maximumDownloadBytes else { throw S3StorageFailure.downloadTooLarge }
        let url = try Self.endpoint(settings: cleanSettings, objectKey: object.key, versionID: object.versionID.isEmpty ? nil : object.versionID)
        let request = try Self.signedRequest(
            method: "GET", url: url, region: cleanSettings.region, body: Data(), contentType: nil,
            credentials: cleanCredentials, date: Date(), requireEncryption: false, ifMatch: object.eTag,
            expectedBucketOwner: binding.accountID
        )
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        guard http.statusCode == 200 else { throw S3StorageFailure.downloadRejected(http.statusCode) }
        if response.expectedContentLength > Self.maximumDownloadBytes { throw S3StorageFailure.downloadTooLarge }
        if response.expectedContentLength >= 0, response.expectedContentLength != object.size { throw S3StorageFailure.objectChanged }

        let directory = destinationURL.deletingLastPathComponent()
        let temporaryURL = directory.appendingPathComponent(".scopeproof-download-\(UUID().uuidString).tmp", isDirectory: false)
        guard FileManager.default.createFile(atPath: temporaryURL.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw S3StorageFailure.invalidDownloadDestination
        }
        defer { try? FileManager.default.removeItem(at: temporaryURL) }
        let handle = try FileHandle(forWritingTo: temporaryURL)
        defer { try? handle.close() }
        var buffer = Data()
        buffer.reserveCapacity(64 * 1024)
        var prefixBytes = Data()
        prefixBytes.reserveCapacity(16)
        var jsonBytes = Data()
        let isJSON = object.key.lowercased().hasSuffix(".json")
        var hasher = SHA256()
        var received: Int64 = 0
        for try await byte in bytes {
            buffer.append(byte)
            if prefixBytes.count < 16 { prefixBytes.append(byte) }
            if isJSON {
                guard jsonBytes.count < 5 * 1024 * 1024 else { throw S3StorageFailure.unsupportedDownloadedContent }
                jsonBytes.append(byte)
            }
            received += 1
            guard received <= Self.maximumDownloadBytes, received <= object.size else { throw S3StorageFailure.downloadTooLarge }
            if buffer.count == 64 * 1024 {
                hasher.update(data: buffer)
                try handle.write(contentsOf: buffer)
                buffer.removeAll(keepingCapacity: true)
                try Task.checkCancellation()
            }
        }
        if !buffer.isEmpty { hasher.update(data: buffer); try handle.write(contentsOf: buffer) }
        try handle.synchronize()
        guard received == object.size else { throw S3StorageFailure.objectChanged }
        let digest = Data(hasher.finalize())
        if let remoteChecksum = http.value(forHTTPHeaderField: "x-amz-checksum-sha256"),
           remoteChecksum != digest.base64EncodedString() { throw S3StorageFailure.checksumMismatch }
        let contentValidated: Bool
        if object.key.lowercased().hasSuffix(".png") {
            contentValidated = prefixBytes.starts(with: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
        } else if isJSON {
            contentValidated = (try? JSONSerialization.jsonObject(with: jsonBytes, options: [.fragmentsAllowed])) != nil
        } else {
            contentValidated = false
        }
        guard contentValidated else { throw S3StorageFailure.unsupportedDownloadedContent }
        try handle.close()
        if FileManager.default.fileExists(atPath: destinationURL.path) {
            _ = try FileManager.default.replaceItemAt(destinationURL, withItemAt: temporaryURL)
        } else {
            try FileManager.default.moveItem(at: temporaryURL, to: destinationURL)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destinationURL.path)
        Self.applyQuarantine(to: destinationURL)
        return S3DownloadResult(
            sha256: digest.map { String(format: "%02x", $0) }.joined(),
            versionID: Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-version-id"), maximum: 1_024),
            requestID: Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-request-id"), maximum: 256),
            contentValidated: true
        )
    }

    private func put(
        _ data: Data, contentType: String, objectKey: String, settings: S3StorageSettings,
        credentials: S3Credentials, expectedOwner: String
    ) async throws -> S3ObjectWriteReceipt {
        let url = try Self.endpoint(settings: settings, objectKey: objectKey)
        let checksum = Self.sha256Base64(data)
        let retention = Self.objectRetention(settings: settings, now: Date())
        let request = try Self.signedRequest(
            method: "PUT", url: url, region: settings.region, body: data, contentType: contentType,
            credentials: credentials, date: Date(), requireEncryption: true,
            expectedBucketOwner: expectedOwner, encryptionMode: settings.encryptionMode,
            kmsKeyARN: settings.kmsKeyARN, checksumSHA256: checksum,
            extraHeaders: retention.headers
        )
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        guard http.statusCode == 200 else { throw S3StorageFailure.uploadRejected(http.statusCode, http.value(forHTTPHeaderField: "x-amz-bucket-region")) }
        guard http.value(forHTTPHeaderField: "x-amz-checksum-sha256") == checksum else { throw S3StorageFailure.checksumMismatch }
        let versionID = Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-version-id"), maximum: 1_024)
        guard !versionID.isEmpty, versionID != "null" else { throw S3StorageFailure.bucketPostureFailed(["S3 did not return a version ID"]) }
        let responseEncryption = Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-server-side-encryption"), maximum: 32)
        guard responseEncryption == settings.encryptionMode.rawValue else { throw S3StorageFailure.bucketPostureFailed(["S3 returned an unexpected encryption mode"]) }
        if settings.encryptionMode.needsKMSKey {
            guard http.value(forHTTPHeaderField: "x-amz-server-side-encryption-aws-kms-key-id") == settings.kmsKeyARN else {
                throw S3StorageFailure.bucketPostureFailed(["S3 returned an unexpected KMS key"])
            }
        }
        if settings.securityProfile == .production {
            try await verifyObjectRetention(
                objectKey: objectKey, versionID: versionID, expected: retention,
                settings: settings, credentials: credentials, expectedOwner: expectedOwner
            )
        }
        return S3ObjectWriteReceipt(
            eTag: String((http.value(forHTTPHeaderField: "ETag") ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "\" ")).prefix(200)),
            versionID: versionID, checksumSHA256: checksum,
            requestID: Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-request-id"), maximum: 256),
            extendedRequestID: Self.safeResponseHeader(http.value(forHTTPHeaderField: "x-amz-id-2"), maximum: 2_048),
            encryptionMode: responseEncryption, kmsKeyARN: settings.kmsKeyARN,
            retentionMode: retention.mode, retainUntil: retention.retainUntil
        )
    }

    private func verifyObjectRetention(
        objectKey: String, versionID: String, expected: S3ObjectRetentionExpectation,
        settings: S3StorageSettings, credentials: S3Credentials, expectedOwner: String
    ) async throws {
        let url = try Self.objectRetentionEndpoint(
            settings: settings, objectKey: objectKey, versionID: versionID
        )
        let request = try Self.signedRequest(
            method: "GET", url: url, region: settings.region, body: Data(), contentType: nil,
            credentials: credentials, date: Date(), requireEncryption: false,
            expectedBucketOwner: expectedOwner
        )
        let (data, response) = try await session.data(for: request)
        guard data.count <= 64 * 1024, let http = response as? HTTPURLResponse,
              Self.isExpectedResponse(http, requestURL: url), http.statusCode == 200,
              Self.objectRetentionResponseMatches(data, expected: expected) else {
            throw S3StorageFailure.objectRetentionMismatch
        }
    }

    private func applyBucketSetting(
        operation: String, body: Data, step: String, settings: S3StorageSettings,
        credentials: S3Credentials, expectedOwner: String, contentType: String = "application/xml"
    ) async throws {
        let url = try Self.bucketOperationEndpoint(settings: settings, operation: operation)
        let request = try Self.signedRequest(
            method: "PUT", url: url, region: settings.region, body: body, contentType: contentType,
            credentials: credentials, date: Date(), requireEncryption: false,
            contentMD5: Self.contentMD5(body), expectedBucketOwner: expectedOwner
        )
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        guard (200...299).contains(http.statusCode) else { throw S3StorageFailure.bucketHardeningRejected(step, http.statusCode) }
    }

    func callerIdentity(settings: S3StorageSettings, credentials: S3Credentials) async throws -> S3CallerIdentity {
        let url = try Self.stsEndpoint(settings: settings)
        let body = Data("Action=GetCallerIdentity&Version=2011-06-15".utf8)
        let request = try Self.signedAWSRequest(
            method: "POST", url: url, region: settings.region, service: "sts", body: body,
            contentType: "application/x-www-form-urlencoded; charset=utf-8", credentials: credentials,
            date: Date(), extraHeaders: [:]
        )
        let (data, response) = try await session.data(for: request)
        guard data.count <= 64 * 1024, let http = response as? HTTPURLResponse,
              Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        guard http.statusCode == 200 else { throw S3StorageFailure.callerIdentityRejected(http.statusCode) }
        let fields = try Self.parseBoundedXML(data)
        guard let account = fields.firstValue(named: "Account"), account.range(of: #"^\d{12}$"#, options: .regularExpression) != nil,
              let arn = fields.firstValue(named: "Arn"), Self.isSafeARN(arn),
              let userID = fields.firstValue(named: "UserId"), Self.isSafeResponseValue(userID, maximum: 1_024) else {
            throw S3StorageFailure.invalidResponse
        }
        return S3CallerIdentity(accountID: account, principalARN: arn, userID: userID)
    }

    private func inspectKMSKey(
        settings: S3StorageSettings, credentials: S3Credentials, expectedAccountID: String
    ) async throws -> S3KMSKeyPosture? {
        guard settings.encryptionMode.needsKMSKey else { return nil }
        guard Self.kmsKeyARNMatchesVerifiedDestination(
            settings.kmsKeyARN, region: settings.region, accountID: expectedAccountID
        ) else { throw S3StorageFailure.kmsKeyIdentityMismatch }
        let request = try Self.describeKMSKeyRequest(
            settings: settings, credentials: credentials, date: Date()
        )
        guard let requestURL = request.url else { throw S3StorageFailure.invalidResponse }
        let (data, response) = try await session.data(for: request)
        guard data.count <= 64 * 1024, let http = response as? HTTPURLResponse,
              Self.isExpectedResponse(http, requestURL: requestURL) else {
            throw S3StorageFailure.invalidResponse
        }
        guard http.statusCode == 200 else { throw S3StorageFailure.kmsKeyRejected(http.statusCode) }
        return try Self.parseKMSKeyPosture(
            data, expectedARN: settings.kmsKeyARN, region: settings.region,
            expectedAccountID: expectedAccountID
        )
    }

    private func inspectBucketPosture(
        settings: S3StorageSettings, credentials: S3Credentials, expectedOwner: String
    ) async throws -> S3BucketPosture {
        let publicAccess = try await bucketConfiguration(
            operation: "publicAccessBlock", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        )
        let versioning = try await bucketConfiguration(
            operation: "versioning", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        )
        let encryption = try await bucketConfiguration(
            operation: "encryption", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        )
        let ownership = settings.securityProfile == .production ? try await bucketConfiguration(
            operation: "ownershipControls", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        ) : nil
        let objectLock = settings.securityProfile == .production ? try await bucketConfiguration(
            operation: "object-lock", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        ) : nil
        let policy = settings.securityProfile == .production ? try await bucketConfiguration(
            operation: "policy", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: false
        ) : nil
        let inspectOptionalConfigurations = settings.securityProfile == .production
        let lifecycle = inspectOptionalConfigurations || settings.archiveAfterDays > 0 ? try await bucketConfiguration(
            operation: "lifecycle", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: settings.archiveAfterDays == 0
        ) : nil
        let replication = inspectOptionalConfigurations || settings.replicationEnabled ? try await bucketConfiguration(
            operation: "replication", settings: settings, credentials: credentials,
            expectedOwner: expectedOwner, missingAllowed: !settings.replicationEnabled
        ) : nil

        let publicFields = try publicAccess.map(Self.parseBoundedXML)
        let versionFields = try versioning.map(Self.parseBoundedXML)
        let encryptionFields = try encryption.map(Self.parseBoundedXML)
        let ownershipFields = try ownership.map(Self.parseBoundedXML)
        let lockFields = try objectLock.map(Self.parseBoundedXML)
        let allPublicBlocked = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            .allSatisfy { publicFields?.firstValue(named: $0) == "true" }
        let algorithm = encryptionFields?.firstValue(named: "SSEAlgorithm").flatMap(S3EncryptionMode.init(rawValue:))
        let bucketKeyEnabled: Bool? = switch encryptionFields?.firstValue(named: "BucketKeyEnabled") {
        case "true": true
        case "false": false
        default: nil
        }
        let mode = lockFields?.firstValue(named: "Mode").flatMap(S3RetentionMode.init(rawValue:))
        let retentionDays = Int(lockFields?.firstValue(named: "Days") ?? "") ?? 0
        let lifecycleIsExact = Self.lifecycleConfigurationIsSecure(lifecycle, settings: settings)
        let replicationIsExact = Self.replicationConfigurationIsSecure(replication, settings: settings)
        let archiveDays = lifecycleIsExact ? settings.archiveAfterDays : -1
        let replicationBucket = replicationIsExact
            ? (settings.replicationEnabled ? settings.replicationDestinationBucketARN : "")
            : "invalid-replication-configuration"
        return S3BucketPosture(
            blockPublicAccess: allPublicBlocked,
            versioningEnabled: versionFields?.firstValue(named: "Status") == "Enabled",
            ownershipEnforced: ownershipFields?.firstValue(named: "ObjectOwnership") == "BucketOwnerEnforced",
            bucketPolicyEnforced: policy.map { Self.bucketPolicyIsSecure($0, settings: settings) } ?? false,
            encryptionMode: algorithm,
            kmsKeyARN: encryptionFields?.firstValue(named: "KMSMasterKeyID") ?? "",
            bucketKeyEnabled: bucketKeyEnabled,
            objectLockEnabled: lockFields?.firstValue(named: "ObjectLockEnabled") == "Enabled",
            retentionMode: mode, retentionDays: retentionDays,
            lifecycleArchiveAfterDays: archiveDays,
            replicationDestinationBucketARN: replicationBucket
        )
    }

    private func bucketConfiguration(
        operation: String, settings: S3StorageSettings, credentials: S3Credentials,
        expectedOwner: String, missingAllowed: Bool
    ) async throws -> Data? {
        let url = try Self.bucketOperationEndpoint(settings: settings, operation: operation)
        let request = try Self.signedRequest(
            method: "GET", url: url, region: settings.region, body: Data(), contentType: nil,
            credentials: credentials, date: Date(), requireEncryption: false,
            expectedBucketOwner: expectedOwner
        )
        let (data, response) = try await session.data(for: request)
        guard data.count <= 1 * 1024 * 1024, let http = response as? HTTPURLResponse,
              Self.isExpectedResponse(http, requestURL: url) else { throw S3StorageFailure.invalidResponse }
        if http.statusCode == 404 && missingAllowed { return nil }
        guard http.statusCode == 200 else { throw S3StorageFailure.bucketHardeningRejected("verify \(operation)", http.statusCode) }
        return data
    }

    private nonisolated static func validatedSettings(_ settings: S3StorageSettings) throws -> S3StorageSettings {
        try S3StorageSettings.validated(
            bucket: settings.bucket, region: settings.region, prefix: settings.prefix,
            autoUpload: settings.autoUpload, uploadsAllowed: settings.uploadsAllowed,
            securityProfile: settings.securityProfile, encryptionMode: settings.encryptionMode,
            kmsKeyARN: settings.kmsKeyARN, retentionMode: settings.retentionMode,
            retentionDays: settings.retentionDays, archiveAfterDays: settings.archiveAfterDays,
            downloadsAllowed: settings.downloadsAllowed, useFIPSEndpoint: settings.useFIPSEndpoint,
            replicationDestinationBucketARN: settings.replicationDestinationBucketARN,
            replicationRoleARN: settings.replicationRoleARN,
            replicationKMSKeyARN: settings.replicationKMSKeyARN,
            authentication: settings.authentication
        )
    }

    private nonisolated static func validatedCredentials(
        _ credentials: S3Credentials, for settings: S3StorageSettings
    ) throws -> S3Credentials {
        let clean = try S3Credentials.validated(
            accessKeyID: credentials.accessKeyID, secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken, expiresAt: credentials.expiresAt
        )
        if clean.isExpired { throw S3StorageFailure.expiredCredentials }
        if settings.securityProfile == .production && (!clean.isTemporary || clean.expiresAt == nil) {
            throw S3StorageFailure.temporaryCredentialsRequired
        }
        return clean
    }

    nonisolated static func postureFailures(_ posture: S3BucketPosture, settings: S3StorageSettings) -> [String] {
        var failures: [String] = []
        if !posture.blockPublicAccess { failures.append("all four Block Public Access controls are required") }
        if !posture.versioningEnabled { failures.append("bucket versioning is not enabled") }
        if posture.encryptionMode != settings.encryptionMode { failures.append("default encryption does not match \(settings.encryptionMode.displayName)") }
        if settings.encryptionMode.needsKMSKey && posture.kmsKeyARN != settings.kmsKeyARN { failures.append("the customer-managed KMS key does not match") }
        if settings.securityProfile == .production {
            if settings.encryptionMode == .sseKMS && posture.bucketKeyEnabled != true {
                failures.append("S3 Bucket Keys must be enabled for SSE-KMS")
            }
            if !posture.ownershipEnforced { failures.append("Object Ownership must be BucketOwnerEnforced") }
            if !posture.bucketPolicyEnforced { failures.append("bucket policy must be the exact Scopeproof transport, encryption, and deletion-deny policy") }
            if !posture.objectLockEnabled { failures.append("Object Lock is not enabled") }
            if posture.retentionMode != settings.retentionMode { failures.append("Object Lock retention mode does not match") }
            if posture.retentionDays < settings.retentionDays { failures.append("Object Lock retention is shorter than \(settings.retentionDays) days") }
        }
        if (settings.securityProfile == .production || settings.archiveAfterDays > 0)
            && posture.lifecycleArchiveAfterDays != settings.archiveAfterDays {
            failures.append(settings.archiveAfterDays > 0
                ? "Deep Archive lifecycle is not the exact prefix-scoped \(settings.archiveAfterDays)-day configuration"
                : "an unexpected lifecycle configuration is present while archiving is disabled")
        }
        if (settings.securityProfile == .production || settings.replicationEnabled)
            && posture.replicationDestinationBucketARN != settings.replicationDestinationBucketARN {
            failures.append(settings.replicationEnabled
                ? "replication is not the exact prefix-scoped configured destination, role, and KMS configuration"
                : "an unexpected replication configuration is present while replication is disabled")
        }
        return failures
    }

    nonisolated static func objectBase(settings: S3StorageSettings, context: CaptureContext, evidenceID: String) -> String {
        let title = context.resolvedControlTitle.isEmpty ? context.controlID : "\(context.controlID) - \(context.resolvedControlTitle)"
        let control = safeObjectComponent(title)
        let period = safeObjectComponent(context.assessmentPeriod)
        return [settings.prefix, control, period, safeObjectComponent(evidenceID)].filter { !$0.isEmpty }.joined(separator: "/")
    }

    nonisolated static func endpoint(settings: S3StorageSettings, objectKey: String?, versionID: String? = nil) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        var pathParts: [String] = []
        if settings.useFIPSEndpoint {
            components.host = "s3-fips.\(settings.region).amazonaws.com"
            pathParts.append(settings.bucket)
        } else if settings.bucket.contains(".") {
            components.host = "s3.\(settings.region).amazonaws.com"
            pathParts.append(settings.bucket)
        } else {
            components.host = "\(settings.bucket).s3.\(settings.region).amazonaws.com"
        }
        if let objectKey { pathParts.append(contentsOf: objectKey.split(separator: "/", omittingEmptySubsequences: false).map(String.init)) }
        components.percentEncodedPath = "/" + pathParts.map(uriEncode).joined(separator: "/")
        if let versionID {
            guard isSafeResponseValue(versionID, maximum: 1_024) else { throw S3StorageFailure.invalidResponse }
            components.queryItems = [URLQueryItem(name: "versionId", value: versionID)]
        }
        guard let url = components.url, url.scheme == "https", let host = url.host,
              isAllowedS3Host(host, region: settings.region) else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func bucketOperationEndpoint(settings: S3StorageSettings, operation: String) throws -> URL {
        guard ["publicAccessBlock", "versioning", "encryption", "ownershipControls", "object-lock", "lifecycle", "replication", "policy"].contains(operation) else {
            throw S3StorageFailure.invalidResponse
        }
        let endpoint = try endpoint(settings: settings, objectKey: nil)
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        components?.percentEncodedQuery = operation
        guard let url = components?.url else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func objectRetentionEndpoint(
        settings: S3StorageSettings, objectKey: String, versionID: String
    ) throws -> URL {
        guard isSafeResponseValue(versionID, maximum: 1_024), !versionID.isEmpty, versionID != "null" else {
            throw S3StorageFailure.invalidResponse
        }
        let endpoint = try endpoint(settings: settings, objectKey: objectKey)
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "retention", value: nil),
            URLQueryItem(name: "versionId", value: versionID),
        ]
        guard let url = components?.url else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func objectRetention(
        settings: S3StorageSettings, now: Date
    ) -> S3ObjectRetentionExpectation {
        guard settings.securityProfile == .production else {
            return S3ObjectRetentionExpectation(mode: "", retainUntil: "", retainUntilDate: nil, headers: [:])
        }
        let retainUntil = now.addingTimeInterval(Double(settings.retentionDays) * 86_400)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let value = formatter.string(from: retainUntil)
        return S3ObjectRetentionExpectation(
            mode: settings.retentionMode.rawValue, retainUntil: value, retainUntilDate: retainUntil,
            headers: [
                "x-amz-object-lock-mode": settings.retentionMode.rawValue,
                "x-amz-object-lock-retain-until-date": value,
            ]
        )
    }

    nonisolated static func objectRetentionResponseMatches(
        _ data: Data, expected: S3ObjectRetentionExpectation
    ) -> Bool {
        guard !expected.mode.isEmpty, let minimumDate = expected.retainUntilDate,
              data.count <= 64 * 1024, let fields = try? parseBoundedXML(data),
              fields.firstValue(named: "Mode") == expected.mode,
              let rawDate = fields.firstValue(named: "RetainUntilDate"),
              let observedDate = parseISO8601(rawDate),
              observedDate >= minimumDate.addingTimeInterval(-1) else { return false }
        return true
    }

    private nonisolated static func parseISO8601(_ value: String) -> Date? {
        let standard = ISO8601DateFormatter()
        if let date = standard.date(from: value) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value)
    }

    nonisolated static func listObjectsEndpoint(settings: S3StorageSettings, maximumKeys: Int, continuationToken: String?) throws -> URL {
        guard maximumKeys >= 0, maximumKeys <= 1_000 else { throw S3StorageFailure.invalidResponse }
        if let continuationToken {
            guard continuationToken.utf8.count <= 4_096,
                  continuationToken.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else { throw S3StorageFailure.invalidResponse }
        }
        let endpoint = try endpoint(settings: settings, objectKey: nil)
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        var queryItems = [
            URLQueryItem(name: "list-type", value: "2"),
            URLQueryItem(name: "max-keys", value: String(maximumKeys)),
        ]
        if !settings.prefix.isEmpty { queryItems.append(URLQueryItem(name: "prefix", value: "\(settings.prefix)/")) }
        if let continuationToken { queryItems.append(URLQueryItem(name: "continuation-token", value: continuationToken)) }
        components?.queryItems = queryItems
        guard let url = components?.url else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func listObjectVersionsEndpoint(
        settings: S3StorageSettings, maximumKeys: Int, keyMarker: String?, versionIDMarker: String?
    ) throws -> URL {
        guard maximumKeys > 0, maximumKeys <= 1_000 else { throw S3StorageFailure.invalidResponse }
        for marker in [keyMarker, versionIDMarker].compactMap({ $0 }) {
            guard isSafeResponseValue(marker, maximum: 4_096) else { throw S3StorageFailure.invalidResponse }
        }
        guard (keyMarker == nil) == (versionIDMarker == nil) else { throw S3StorageFailure.invalidResponse }
        let endpoint = try endpoint(settings: settings, objectKey: nil)
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        var queryItems = [
            URLQueryItem(name: "versions", value: ""),
            URLQueryItem(name: "max-keys", value: String(maximumKeys)),
        ]
        if !settings.prefix.isEmpty { queryItems.append(URLQueryItem(name: "prefix", value: "\(settings.prefix)/")) }
        if let keyMarker, let versionIDMarker {
            queryItems.append(URLQueryItem(name: "key-marker", value: keyMarker))
            queryItems.append(URLQueryItem(name: "version-id-marker", value: versionIDMarker))
        }
        components?.queryItems = queryItems
        guard let url = components?.url else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func parseObjectList(_ data: Data, requiredPrefix: String) throws -> S3ObjectListPage {
        guard data.count <= maximumListResponseBytes else { throw S3StorageFailure.listResponseTooLarge }
        let parserDelegate = S3ObjectListXMLParser(requiredPrefix: requiredPrefix)
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = parserDelegate
        guard parser.parse(), let result = parserDelegate.result else { throw S3StorageFailure.invalidResponse }
        return result
    }

    nonisolated static func parseObjectVersionList(_ data: Data, requiredPrefix: String) throws -> S3ObjectVersionListPage {
        guard data.count <= maximumListResponseBytes else { throw S3StorageFailure.listResponseTooLarge }
        let delegate = S3ObjectVersionXMLParser(requiredPrefix: requiredPrefix)
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), let result = delegate.result else { throw S3StorageFailure.invalidResponse }
        return result
    }

    nonisolated static func createBucketBody(region: String) -> Data {
        guard region != "us-east-1" else { return Data() }
        return Data("<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>\(region)</LocationConstraint></CreateBucketConfiguration>".utf8)
    }

    nonisolated static let publicAccessBlockBody = Data("<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>".utf8)
    nonisolated static let versioningBody = Data("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>".utf8)
    nonisolated static let ownershipControlsBody = Data("<OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>".utf8)

    nonisolated static func encryptionBody(settings: S3StorageSettings) -> Data {
        var applied = "<SSEAlgorithm>\(settings.encryptionMode.rawValue)</SSEAlgorithm>"
        if settings.encryptionMode.needsKMSKey {
            applied += "<KMSMasterKeyID>\(xmlEscape(settings.kmsKeyARN))</KMSMasterKeyID>"
        }
        let bucketKey = settings.encryptionMode == .sseKMS ? "<BucketKeyEnabled>true</BucketKeyEnabled>" : ""
        return Data("<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ApplyServerSideEncryptionByDefault>\(applied)</ApplyServerSideEncryptionByDefault>\(bucketKey)</Rule></ServerSideEncryptionConfiguration>".utf8)
    }

    nonisolated static func objectLockBody(settings: S3StorageSettings) -> Data {
        Data("<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>\(settings.retentionMode.rawValue)</Mode><Days>\(settings.retentionDays)</Days></DefaultRetention></Rule></ObjectLockConfiguration>".utf8)
    }

    nonisolated static func lifecycleBody(settings: S3StorageSettings) -> Data {
        let prefix = settings.prefix.isEmpty ? "" : "<Filter><Prefix>\(xmlEscape(settings.prefix))/</Prefix></Filter>"
        return Data("<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ID>ScopeproofEvidenceDeepArchive</ID>\(prefix)<Status>Enabled</Status><Transition><Days>\(settings.archiveAfterDays)</Days><StorageClass>DEEP_ARCHIVE</StorageClass></Transition><NoncurrentVersionTransition><NoncurrentDays>\(settings.archiveAfterDays)</NoncurrentDays><StorageClass>DEEP_ARCHIVE</StorageClass></NoncurrentVersionTransition></Rule></LifecycleConfiguration>".utf8)
    }

    nonisolated static func replicationBody(settings: S3StorageSettings) -> Data {
        let filter = settings.prefix.isEmpty ? "" : "<Filter><Prefix>\(xmlEscape(settings.prefix))/</Prefix></Filter>"
        let encryption = settings.encryptionMode.needsKMSKey
            ? "<EncryptionConfiguration><ReplicaKmsKeyID>\(xmlEscape(settings.replicationKMSKeyARN))</ReplicaKmsKeyID></EncryptionConfiguration>"
            : ""
        let sourceSelection = settings.encryptionMode.needsKMSKey
            ? "<SourceSelectionCriteria><SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects></SourceSelectionCriteria>"
            : ""
        return Data("<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Role>\(xmlEscape(settings.replicationRoleARN))</Role><Rule><ID>ScopeproofEvidenceReplication</ID><Priority>1</Priority>\(filter)<Status>Enabled</Status><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>\(sourceSelection)<Destination><Bucket>\(xmlEscape(settings.replicationDestinationBucketARN))</Bucket>\(encryption)</Destination></Rule></ReplicationConfiguration>".utf8)
    }

    nonisolated static func bucketPolicyBody(settings: S3StorageSettings) throws -> Data {
        let partition = settings.region.hasPrefix("us-gov-") ? "aws-us-gov" : "aws"
        let bucketARN = "arn:\(partition):s3:::\(settings.bucket)"
        let objectARN = settings.prefix.isEmpty ? "\(bucketARN)/*" : "\(bucketARN)/\(settings.prefix)/*"
        var statements: [[String: Any]] = [
            [
                "Sid": "ScopeproofDenyInsecureTransport", "Effect": "Deny", "Principal": "*",
                "Action": "s3:*", "Resource": [bucketARN, "\(bucketARN)/*"],
                "Condition": ["Bool": ["aws:SecureTransport": "false"]],
            ],
            [
                "Sid": "ScopeproofDenyBucketDeletion", "Effect": "Deny", "Principal": "*",
                "Action": "s3:DeleteBucket", "Resource": bucketARN,
            ],
            [
                "Sid": "ScopeproofDenyEvidenceDeletion", "Effect": "Deny", "Principal": "*",
                "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"],
                "Resource": objectARN,
            ],
            [
                "Sid": "ScopeproofDenyWrongEncryption", "Effect": "Deny", "Principal": "*",
                "Action": "s3:PutObject", "Resource": objectARN,
                "Condition": ["StringNotEquals": ["s3:x-amz-server-side-encryption": settings.encryptionMode.rawValue]],
            ],
        ]
        if settings.encryptionMode.needsKMSKey {
            statements.append([
                "Sid": "ScopeproofDenyWrongKMSKey", "Effect": "Deny", "Principal": "*",
                "Action": "s3:PutObject", "Resource": objectARN,
                "Condition": ["StringNotEquals": ["s3:x-amz-server-side-encryption-aws-kms-key-id": settings.kmsKeyARN]],
            ])
        }
        return try JSONSerialization.data(
            withJSONObject: ["Version": "2012-10-17", "Statement": statements],
            options: [.sortedKeys]
        )
    }

    nonisolated static func bucketPolicyIsSecure(_ data: Data, settings: S3StorageSettings) -> Bool {
        guard data.count <= 1 * 1024 * 1024,
              let document = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let expectedData = try? bucketPolicyBody(settings: settings),
              let expected = try? JSONSerialization.jsonObject(with: expectedData) as? [String: Any] else { return false }
        // Resource-policy Allows can grant data access independently of the caller's identity policy.
        // Require the complete generated policy, not merely the presence of Scopeproof's deny Sids.
        return (document as NSDictionary).isEqual(expected as NSDictionary)
    }

    nonisolated static func lifecycleConfigurationIsSecure(_ data: Data?, settings: S3StorageSettings) -> Bool {
        guard settings.archiveAfterDays > 0 else { return data == nil }
        guard let data else { return false }
        return exactXMLConfiguration(data, matches: lifecycleBody(settings: settings))
    }

    nonisolated static func replicationConfigurationIsSecure(_ data: Data?, settings: S3StorageSettings) -> Bool {
        guard settings.replicationEnabled else { return data == nil }
        guard let data else { return false }
        return exactXMLConfiguration(data, matches: replicationBody(settings: settings))
    }

    private nonisolated static func exactXMLConfiguration(_ data: Data, matches expected: Data) -> Bool {
        guard data.count <= 1 * 1024 * 1024,
              let actualRecords = S3CanonicalXMLParser.records(in: data),
              let expectedRecords = S3CanonicalXMLParser.records(in: expected) else { return false }
        return actualRecords == expectedRecords
    }

    nonisolated static func stsEndpoint(settings: S3StorageSettings) throws -> URL {
        let label = settings.useFIPSEndpoint ? "sts-fips" : "sts"
        guard let url = URL(string: "https://\(label).\(settings.region).amazonaws.com/") else { throw S3StorageFailure.invalidResponse }
        return url
    }

    nonisolated static func kmsEndpoint(settings: S3StorageSettings) throws -> URL {
        let label = settings.useFIPSEndpoint ? "kms-fips" : "kms"
        guard let url = URL(string: "https://\(label).\(settings.region).amazonaws.com/") else {
            throw S3StorageFailure.invalidResponse
        }
        return url
    }

    nonisolated static func describeKMSKeyRequest(
        settings: S3StorageSettings, credentials: S3Credentials, date: Date
    ) throws -> URLRequest {
        guard settings.encryptionMode.needsKMSKey else { throw S3StorageFailure.kmsKeyNotApplicable }
        let body = try JSONSerialization.data(
            withJSONObject: ["KeyId": settings.kmsKeyARN], options: [.sortedKeys]
        )
        return try signedAWSRequest(
            method: "POST", url: kmsEndpoint(settings: settings), region: settings.region,
            service: "kms", body: body, contentType: "application/x-amz-json-1.1",
            credentials: credentials, date: date,
            extraHeaders: ["x-amz-target": "TrentService.DescribeKey"]
        )
    }

    nonisolated static func kmsKeyARNMatchesVerifiedDestination(
        _ arn: String, region: String, accountID: String
    ) -> Bool {
        let fields = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 6, fields[0] == "arn", fields[2] == "kms",
              fields[3] == region, fields[4] == accountID else { return false }
        let expectedPartition = region.hasPrefix("us-gov-") ? "aws-us-gov" : "aws"
        return fields[1] == expectedPartition
            && fields[5].range(
                of: #"^key/(?:[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}|mrk-[A-Fa-f0-9]{32})$"#,
                options: .regularExpression
            ) != nil
    }

    nonisolated static func parseKMSKeyPosture(
        _ data: Data, expectedARN: String, region: String, expectedAccountID: String
    ) throws -> S3KMSKeyPosture {
        guard data.count <= 64 * 1024,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let metadata = root["KeyMetadata"] as? [String: Any],
              let arn = metadata["Arn"] as? String,
              let accountID = metadata["AWSAccountId"] as? String,
              let keyManager = metadata["KeyManager"] as? String,
              let keyUsage = metadata["KeyUsage"] as? String,
              let keySpec = metadata["KeySpec"] as? String,
              let keyState = metadata["KeyState"] as? String,
              let enabled = metadata["Enabled"] as? Bool,
              isSafeResponseValue(arn, maximum: 2_048),
              isSafeResponseValue(accountID, maximum: 12),
              isSafeResponseValue(keyManager, maximum: 64),
              isSafeResponseValue(keyUsage, maximum: 64),
              isSafeResponseValue(keySpec, maximum: 64),
              isSafeResponseValue(keyState, maximum: 64) else {
            throw S3StorageFailure.invalidResponse
        }
        let fields = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 6 else { throw S3StorageFailure.invalidResponse }
        let posture = S3KMSKeyPosture(
            arn: arn, partition: fields[1], region: fields[3], accountID: accountID,
            keyManager: keyManager, keyUsage: keyUsage, keySpec: keySpec,
            keyState: keyState, enabled: enabled
        )
        var failures: [String] = []
        if arn != expectedARN { failures.append("DescribeKey returned a different key ARN") }
        if !kmsKeyARNMatchesVerifiedDestination(arn, region: region, accountID: expectedAccountID)
            || accountID != expectedAccountID {
            failures.append("key partition, Region, or account does not match the verified bucket owner")
        }
        if keyManager != "CUSTOMER" { failures.append("KeyManager must be CUSTOMER") }
        if keyUsage != "ENCRYPT_DECRYPT" { failures.append("KeyUsage must be ENCRYPT_DECRYPT") }
        if keySpec != "SYMMETRIC_DEFAULT" { failures.append("KeySpec must be SYMMETRIC_DEFAULT") }
        if !enabled || keyState != "Enabled" {
            failures.append("key must be Enabled and not pending deletion or otherwise unavailable")
        }
        guard failures.isEmpty else { throw S3StorageFailure.kmsKeyPostureFailed(failures) }
        return posture
    }

    nonisolated static func signedRequest(
        method: String, url: URL, region: String, body: Data, contentType: String?,
        credentials: S3Credentials, date: Date, requireEncryption: Bool,
        contentMD5: String? = nil, ifMatch: String? = nil, expectedBucketOwner: String? = nil,
        encryptionMode: S3EncryptionMode = .sseS3, kmsKeyARN: String = "",
        checksumSHA256: String? = nil, extraHeaders: [String: String] = [:]
    ) throws -> URLRequest {
        guard ["GET", "PUT"].contains(method), url.scheme == "https", let host = url.host,
              isAllowedS3Host(host, region: region) else { throw S3StorageFailure.invalidResponse }
        var headers = extraHeaders
        if let contentMD5 { headers["content-md5"] = contentMD5 }
        if let ifMatch {
            guard Self.isSafeETag(ifMatch) else { throw S3StorageFailure.invalidResponse }
            headers["if-match"] = "\"\(ifMatch)\""
        }
        if let expectedBucketOwner {
            guard expectedBucketOwner.range(of: #"^\d{12}$"#, options: .regularExpression) != nil else { throw S3StorageFailure.invalidResponse }
            headers["x-amz-expected-bucket-owner"] = expectedBucketOwner
        }
        if let checksumSHA256 {
            guard Data(base64Encoded: checksumSHA256)?.count == 32 else { throw S3StorageFailure.invalidResponse }
            headers["x-amz-checksum-sha256"] = checksumSHA256
        }
        if requireEncryption {
            headers["x-amz-server-side-encryption"] = encryptionMode.rawValue
            if encryptionMode.needsKMSKey { headers["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKeyARN }
            if encryptionMode == .sseKMS { headers["x-amz-server-side-encryption-bucket-key-enabled"] = "true" }
        }
        return try signedAWSRequest(
            method: method, url: url, region: region, service: "s3", body: body,
            contentType: contentType, credentials: credentials, date: date, extraHeaders: headers
        )
    }

    nonisolated static func signedAWSRequest(
        method: String, url: URL, region: String, service: String, body: Data, contentType: String?,
        credentials: S3Credentials, date: Date, extraHeaders: [String: String]
    ) throws -> URLRequest {
        guard ["GET", "PUT", "POST"].contains(method), ["s3", "sts", "kms"].contains(service),
              url.scheme == "https", let host = url.host, host.hasSuffix(".amazonaws.com") else {
            throw S3StorageFailure.invalidResponse
        }
        if service == "s3" && !isAllowedS3Host(host, region: region) { throw S3StorageFailure.invalidResponse }
        if service == "sts" && !isAllowedSTSHost(host, region: region) { throw S3StorageFailure.invalidResponse }
        if service == "kms" && !isAllowedKMSHost(host, region: region) { throw S3StorageFailure.invalidResponse }
        let timestamp = awsTimestamp(date)
        let dateStamp = String(timestamp.prefix(8))
        let payloadHash = sha256(body)
        var headers: [String: String] = [
            "host": host,
            "x-amz-content-sha256": payloadHash,
            "x-amz-date": timestamp,
        ]
        if let contentType { headers["content-type"] = contentType }
        for (rawName, value) in extraHeaders {
            let name = rawName.lowercased()
            guard name.range(of: #"^[a-z0-9-]{1,80}$"#, options: .regularExpression) != nil,
                  headers[name] == nil, isSafeResponseValue(value, maximum: 4_096) else { throw S3StorageFailure.invalidResponse }
            headers[name] = value
        }
        if !credentials.sessionToken.isEmpty { headers["x-amz-security-token"] = credentials.sessionToken }
        let signedHeaders = headers.keys.sorted().joined(separator: ";")
        let canonicalHeaders = headers.keys.sorted().map { "\($0):\(normalizedHeaderValue(headers[$0] ?? ""))\n" }.joined()
        let encodedPath = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? ""
        let canonicalURI = encodedPath.isEmpty ? "/" : encodedPath
        let canonicalRequest = "\(method)\n\(canonicalURI)\n\(canonicalQuery(url))\n\(canonicalHeaders)\n\(signedHeaders)\n\(payloadHash)"
        let scope = "\(dateStamp)/\(region)/\(service)/aws4_request"
        let stringToSign = "AWS4-HMAC-SHA256\n\(timestamp)\n\(scope)\n\(sha256(Data(canonicalRequest.utf8)))"
        let kDate = hmac(key: Data("AWS4\(credentials.secretAccessKey)".utf8), message: Data(dateStamp.utf8))
        let kRegion = hmac(key: kDate, message: Data(region.utf8))
        let kService = hmac(key: kRegion, message: Data(service.utf8))
        let kSigning = hmac(key: kService, message: Data("aws4_request".utf8))
        let signature = hmac(key: kSigning, message: Data(stringToSign.utf8)).map { String(format: "%02x", $0) }.joined()

        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 60)
        request.httpMethod = method
        if method == "PUT" || method == "POST" { request.httpBody = body }
        headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
        request.setValue("AWS4-HMAC-SHA256 Credential=\(credentials.accessKeyID)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)", forHTTPHeaderField: "Authorization")
        return request
    }

    private nonisolated static func isAllowedS3Host(_ host: String, region: String) -> Bool {
        guard host == host.lowercased(), host.hasSuffix(".amazonaws.com"),
              region.range(of: #"^(?:us|eu|ap|sa|ca|me|af)-(?:gov-)?[a-z]+-\d$"#, options: .regularExpression) != nil else {
            return false
        }
        let pathStyleHosts = [
            "s3.\(region).amazonaws.com",
            "s3-fips.\(region).amazonaws.com",
        ]
        if pathStyleHosts.contains(host) { return true }
        let virtualHostedSuffix = ".s3.\(region).amazonaws.com"
        guard host.hasSuffix(virtualHostedSuffix) else { return false }
        let bucket = String(host.dropLast(virtualHostedSuffix.count))
        return bucket.range(
            of: #"^(?!\d{1,3}(?:\.\d{1,3}){3}$)(?!.*\.\.)(?!.*\.-)(?!.*-\.)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"#,
            options: .regularExpression
        ) != nil
    }

    private nonisolated static func isAllowedSTSHost(_ host: String, region: String) -> Bool {
        guard host == host.lowercased(), host.hasSuffix(".amazonaws.com") else { return false }
        return host == "sts.\(region).amazonaws.com" || host == "sts-fips.\(region).amazonaws.com"
    }

    private nonisolated static func isAllowedKMSHost(_ host: String, region: String) -> Bool {
        guard host == host.lowercased(), host.hasSuffix(".amazonaws.com") else { return false }
        return host == "kms.\(region).amazonaws.com" || host == "kms-fips.\(region).amazonaws.com"
    }

    private nonisolated static func isExpectedResponse(_ response: HTTPURLResponse, requestURL: URL) -> Bool {
        response.url?.scheme == "https" && response.url?.host == requestURL.host && response.url?.path == requestURL.path
    }

    private nonisolated static func uriEncode(_ value: String) -> String {
        value.utf8.map { byte -> String in
            switch byte {
            case 0x41...0x5a, 0x61...0x7a, 0x30...0x39, 0x2d, 0x2e, 0x5f, 0x7e: return String(UnicodeScalar(byte))
            default: return String(format: "%%%02X", byte)
            }
        }.joined()
    }

    private nonisolated static func safeObjectComponent(_ value: String) -> String {
        var result = ComplianceCatalog.safeFileBase(value)
        while result.contains("--") { result = result.replacingOccurrences(of: "--", with: "-") }
        return result.trimmingCharacters(in: CharacterSet(charactersIn: ".-_"))
    }

    private nonisolated static func normalizedHeaderValue(_ value: String) -> String {
        value.split(whereSeparator: { $0 == " " || $0 == "\t" }).joined(separator: " ")
    }

    private nonisolated static func canonicalQuery(_ url: URL) -> String {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let encoded: [(name: String, value: String)] = items.map { (uriEncode($0.name), uriEncode($0.value ?? "")) }
        let sorted = encoded.sorted { left, right in left.name == right.name ? left.value < right.value : left.name < right.name }
        return sorted.map { pair in pair.name + "=" + pair.value }.joined(separator: "&")
    }

    private nonisolated static func xmlEscape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    private nonisolated static func parseBoundedXML(_ data: Data) throws -> S3BoundedXMLFields {
        guard data.count <= 1 * 1024 * 1024 else { throw S3StorageFailure.invalidResponse }
        let delegate = S3BoundedXMLParser()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), let fields = delegate.result else { throw S3StorageFailure.invalidResponse }
        return fields
    }

    private nonisolated static func s3ErrorCode(_ data: Data) -> String? {
        guard data.count <= 64 * 1024, let text = String(data: data, encoding: .utf8),
              let start = text.range(of: "<Code>"), let end = text.range(of: "</Code>", range: start.upperBound..<text.endIndex) else { return nil }
        let value = String(text[start.upperBound..<end.lowerBound])
        guard value.range(of: #"^[A-Za-z0-9]+$"#, options: .regularExpression) != nil else { return nil }
        return value
    }

    private nonisolated static func awsTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter.string(from: date)
    }

    nonisolated static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    nonisolated static func sha256Base64(_ data: Data) -> String { Data(SHA256.hash(data: data)).base64EncodedString() }
    nonisolated static func contentMD5(_ data: Data) -> String { Data(Insecure.MD5.hash(data: data)).base64EncodedString() }
    private nonisolated static func hmac(key: Data, message: Data) -> Data { Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))) }

    fileprivate nonisolated static func isSafeObjectKey(_ key: String) -> Bool {
        !key.isEmpty && key.utf8.count <= 1_024 && !key.hasPrefix("/") &&
            key.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f })
    }

    fileprivate nonisolated static func isSafeETag(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 128 && value.range(of: #"^[A-Fa-f0-9]+(?:-[0-9]+)?$"#, options: .regularExpression) != nil
    }

    private nonisolated static func isSafeARN(_ value: String) -> Bool {
        value.utf8.count <= 2_048 && value.range(of: #"^arn:(?:aws|aws-us-gov):(?:iam|sts)::\d{12}:[A-Za-z0-9+=,.@_\-/:]+$"#, options: .regularExpression) != nil
    }

    private nonisolated static func isSafeResponseValue(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && !value.contains("\r") && !value.contains("\n") &&
            value.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7f }
    }

    private nonisolated static func safeResponseHeader(_ value: String?, maximum: Int) -> String {
        guard let value, isSafeResponseValue(value, maximum: maximum) else { return "" }
        return value
    }

    private nonisolated static func applyQuarantine(to url: URL) {
        var mutableURL = url
        var values = URLResourceValues()
        values.quarantineProperties = [
            "LSQuarantineAgentName": "Scopeproof Capture",
            "LSQuarantineType": "LSQuarantineTypeOtherDownload",
            "LSQuarantineOriginURL": "https://aws.amazon.com/s3/",
        ]
        try? mutableURL.setResourceValues(values)
    }
}

private final class S3CanonicalXMLParser: NSObject, XMLParserDelegate {
    private var stack: [String] = []
    private var textStack: [String] = []
    private var recordCounts: [String: Int] = [:]
    private var elementCount = 0
    private var rootCount = 0
    private var invalid = false

    static func records(in data: Data) -> [String: Int]? {
        let delegate = S3CanonicalXMLParser()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), !delegate.invalid, delegate.rootCount == 1,
              delegate.stack.isEmpty, delegate.textStack.isEmpty else { return nil }
        return delegate.recordCounts
    }

    func parser(
        _ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
        qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]
    ) {
        elementCount += 1
        guard elementCount <= 2_000, stack.count < 32,
              attributeDict.keys.allSatisfy({ $0 == "xmlns" || $0.hasPrefix("xmlns:") }) else {
            invalid = true
            parser.abortParsing()
            return
        }
        if stack.isEmpty { rootCount += 1 }
        stack.append(elementName)
        textStack.append("")
        addRecord(kind: "element", path: stack, value: nil)
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard !textStack.isEmpty,
              textStack[textStack.count - 1].utf8.count + string.utf8.count <= 8_192 else {
            invalid = true
            parser.abortParsing()
            return
        }
        textStack[textStack.count - 1] += string
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        guard let value = String(data: CDATABlock, encoding: .utf8) else {
            invalid = true
            parser.abortParsing()
            return
        }
        self.parser(parser, foundCharacters: value)
    }

    func parser(
        _ parser: XMLParser, didEndElement elementName: String,
        namespaceURI: String?, qualifiedName qName: String?
    ) {
        guard stack.last == elementName, let rawText = textStack.last else {
            invalid = true
            parser.abortParsing()
            return
        }
        let value = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.isEmpty { addRecord(kind: "text", path: stack, value: value) }
        stack.removeLast()
        textStack.removeLast()
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
        invalid = true
        parser.abortParsing()
    }

    func parser(
        _ parser: XMLParser, foundExternalEntityDeclarationWithName name: String,
        publicID: String?, systemID: String?
    ) {
        invalid = true
        parser.abortParsing()
    }

    private func addRecord(kind: String, path: [String], value: String?) {
        let encodedPath = path.map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
        let encodedValue = value.map { "|\($0.utf8.count):\($0)" } ?? ""
        let key = "\(kind)|\(encodedPath)\(encodedValue)"
        recordCounts[key, default: 0] += 1
    }
}

private struct S3BoundedXMLFields {
    let values: [String: [String]]

    func firstValue(named name: String) -> String? { values[name]?.first }
}

private final class S3BoundedXMLParser: NSObject, XMLParserDelegate {
    private var stack: [String] = []
    private var text = ""
    private var values: [String: [String]] = [:]
    private var elementCount = 0
    private var invalid = false

    var result: S3BoundedXMLFields? { invalid || !stack.isEmpty ? nil : S3BoundedXMLFields(values: values) }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        elementCount += 1
        guard elementCount <= 2_000, stack.count < 32,
              attributeDict.keys.allSatisfy({ $0 == "xmlns" }) else { invalid = true; parser.abortParsing(); return }
        stack.append(elementName)
        text = ""
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard text.utf8.count + string.utf8.count <= 8_192 else { invalid = true; parser.abortParsing(); return }
        text += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        guard stack.last == elementName else { invalid = true; parser.abortParsing(); return }
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.isEmpty {
            var existing = values[elementName] ?? []
            guard existing.count < 64 else { invalid = true; parser.abortParsing(); return }
            existing.append(value)
            values[elementName] = existing
        }
        stack.removeLast()
        text = ""
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
        invalid = true
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
        invalid = true
        parser.abortParsing()
    }
}

private final class S3ObjectVersionXMLParser: NSObject, XMLParserDelegate {
    private let requiredPrefix: String
    private var currentText = ""
    private var currentVersion: [String: String] = [:]
    private var versions: [S3StoredObject] = []
    private var insideVersion = false
    private var insideDeleteMarker = false
    private var isTruncated = false
    private var sawIsTruncated = false
    private var nextKeyMarker: String?
    private var nextVersionIDMarker: String?
    private var invalid = false

    var result: S3ObjectVersionListPage? {
        guard !invalid, sawIsTruncated, !insideVersion, !insideDeleteMarker, versions.count <= 1_000 else { return nil }
        if isTruncated && (nextKeyMarker == nil || nextVersionIDMarker == nil) { return nil }
        return S3ObjectVersionListPage(
            objects: versions, isTruncated: isTruncated,
            nextKeyMarker: nextKeyMarker, nextVersionIDMarker: nextVersionIDMarker
        )
    }

    init(requiredPrefix: String) { self.requiredPrefix = requiredPrefix.isEmpty ? "" : "\(requiredPrefix)/" }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        guard attributeDict.keys.allSatisfy({ $0 == "xmlns" }) else { invalid = true; parser.abortParsing(); return }
        currentText = ""
        if elementName == "Version" {
            guard !insideVersion && !insideDeleteMarker else { invalid = true; parser.abortParsing(); return }
            insideVersion = true
            currentVersion = [:]
        } else if elementName == "DeleteMarker" {
            guard !insideVersion && !insideDeleteMarker else { invalid = true; parser.abortParsing(); return }
            insideDeleteMarker = true
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard currentText.utf8.count + string.utf8.count <= 8_192 else { invalid = true; parser.abortParsing(); return }
        currentText += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        let value = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        if insideVersion && ["Key", "VersionId", "IsLatest", "LastModified", "ETag", "Size"].contains(elementName) {
            guard currentVersion[elementName] == nil else { invalid = true; parser.abortParsing(); return }
            currentVersion[elementName] = value
        } else if elementName == "Version" {
            guard insideVersion,
                  let key = currentVersion["Key"], key.hasPrefix(requiredPrefix), S3StorageService.isSafeObjectKey(key),
                  let versionID = currentVersion["VersionId"], !versionID.isEmpty, versionID.utf8.count <= 1_024,
                  let latestText = currentVersion["IsLatest"], latestText == "true" || latestText == "false",
                  let sizeText = currentVersion["Size"], let size = Int64(sizeText), size >= 0,
                  let modified = currentVersion["LastModified"], modified.range(of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"#, options: .regularExpression) != nil,
                  let rawETag = currentVersion["ETag"] else { invalid = true; return }
            let eTag = rawETag.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            guard S3StorageService.isSafeETag(eTag) else { invalid = true; return }
            versions.append(S3StoredObject(
                key: key, size: size, lastModified: modified, eTag: eTag,
                versionID: versionID, isLatest: latestText == "true"
            ))
            if versions.count > 1_000 { invalid = true; parser.abortParsing() }
            insideVersion = false
            currentVersion = [:]
        } else if elementName == "DeleteMarker" {
            guard insideDeleteMarker else { invalid = true; return }
            insideDeleteMarker = false
        } else if !insideDeleteMarker && elementName == "IsTruncated" {
            guard !sawIsTruncated, value == "true" || value == "false" else { invalid = true; return }
            sawIsTruncated = true
            isTruncated = value == "true"
        } else if !insideDeleteMarker && elementName == "NextKeyMarker" {
            guard value.utf8.count <= 4_096 else { invalid = true; return }
            nextKeyMarker = value
        } else if !insideDeleteMarker && elementName == "NextVersionIdMarker" {
            guard value.utf8.count <= 4_096 else { invalid = true; return }
            nextVersionIDMarker = value
        }
        currentText = ""
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
        invalid = true
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
        invalid = true
        parser.abortParsing()
    }
}

private final class S3ObjectListXMLParser: NSObject, XMLParserDelegate {
    private let requiredPrefix: String
    private var currentElement = ""
    private var currentText = ""
    private var currentObject: [String: String] = [:]
    private var objects: [S3StoredObject] = []
    private var isTruncated = false
    private var sawIsTruncated = false
    private var nextContinuationToken: String?
    private var invalid = false
    var result: S3ObjectListPage? {
        guard !invalid, sawIsTruncated, objects.count <= 1_000 else { return nil }
        return S3ObjectListPage(objects: objects, isTruncated: isTruncated, nextContinuationToken: nextContinuationToken)
    }

    init(requiredPrefix: String) { self.requiredPrefix = requiredPrefix.isEmpty ? "" : "\(requiredPrefix)/" }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        currentElement = elementName
        currentText = ""
        if elementName == "Contents" { currentObject = [:] }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard currentText.utf8.count + string.utf8.count <= 8_192 else { invalid = true; parser.abortParsing(); return }
        currentText += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        let value = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        if ["Key", "Size", "LastModified", "ETag"].contains(elementName), !currentObject.isEmpty || elementName == "Key" {
            guard currentObject[elementName] == nil else { invalid = true; parser.abortParsing(); return }
            currentObject[elementName] = value
        } else if elementName == "IsTruncated" {
            guard !sawIsTruncated else { invalid = true; parser.abortParsing(); return }
            guard value == "true" || value == "false" else { invalid = true; return }
            sawIsTruncated = true
            isTruncated = value == "true"
        } else if elementName == "NextContinuationToken" {
            guard value.utf8.count <= 4_096 else { invalid = true; return }
            nextContinuationToken = value
        } else if elementName == "Contents" {
            guard let key = currentObject["Key"], key.hasPrefix(requiredPrefix), S3StorageService.isSafeObjectKey(key),
                  let sizeText = currentObject["Size"], let size = Int64(sizeText), size >= 0,
                  let modified = currentObject["LastModified"], modified.range(of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"#, options: .regularExpression) != nil,
                  let rawETag = currentObject["ETag"] else { invalid = true; return }
            let eTag = rawETag.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            guard S3StorageService.isSafeETag(eTag) else { invalid = true; return }
            objects.append(S3StoredObject(key: key, size: size, lastModified: modified, eTag: eTag))
            if objects.count > 1_000 { invalid = true; parser.abortParsing() }
            currentObject = [:]
        }
        currentElement = ""
        currentText = ""
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
        invalid = true
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
        invalid = true
        parser.abortParsing()
    }
}

private final class S3RejectRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
