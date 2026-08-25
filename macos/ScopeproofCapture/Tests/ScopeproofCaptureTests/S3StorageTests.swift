import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("AWS S3 evidence storage")
struct S3StorageTests {
    @Test("Validates bucket, region, prefix, and credentials")
    func validatesConfiguration() throws {
        let settings = try S3StorageSettings.validated(bucket: "company-evidence", region: "us-east-1", prefix: "/scopeproof/evidence/", autoUpload: true)
        #expect(settings.bucket == "company-evidence")
        #expect(settings.prefix == "scopeproof/evidence")
        #expect(settings.autoUpload)
        #expect(throws: S3StorageFailure.self) { try S3StorageSettings.validated(bucket: "../../bucket", region: "us-east-1", prefix: "evidence", autoUpload: false) }
        #expect(throws: S3StorageFailure.self) { try S3StorageSettings.validated(bucket: "company-evidence", region: "https://attacker.example", prefix: "evidence", autoUpload: false) }
        #expect(throws: S3StorageFailure.self) { try S3StorageSettings.validated(bucket: "company-evidence", region: "cn-north-1", prefix: "evidence", autoUpload: false) }
        #expect(throws: S3StorageFailure.self) { try S3StorageSettings.validated(bucket: "company-evidence", region: "us-east-1", prefix: "../evidence", autoUpload: false) }

        let credentials = try S3Credentials.validated(accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: "")
        #expect(credentials.accessKeyID == "AKIAIOSFODNN7EXAMPLE")
        #expect(throws: S3StorageFailure.self) { try S3Credentials.validated(accessKeyID: "short", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: "") }
        #expect(throws: S3StorageFailure.self) { try S3Credentials.validated(accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "secret\nvalue", sessionToken: "") }

        let legacy = Data(#"{"bucket":"company-evidence","region":"us-east-1","prefix":"scopeproof","autoUpload":true}"#.utf8)
        let migrated = try JSONDecoder().decode(S3StorageSettings.self, from: legacy)
        #expect(!migrated.canUpload)
        let verified = try S3StorageSettings.validated(bucket: migrated.bucket, region: migrated.region, prefix: migrated.prefix, autoUpload: true, uploadsAllowed: true)
        #expect(verified.canUpload)

        let kmsARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        let production = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .compliance, retentionDays: 2_555, archiveAfterDays: 90,
            downloadsAllowed: false, useFIPSEndpoint: true
        )
        #expect(production.securityProfile == .production)
        #expect(production.securityBindingDigest.count == 64)
        #expect(throws: S3StorageFailure.self) {
            try S3StorageSettings.validated(
                bucket: "company-evidence", region: "us-east-1", prefix: "", autoUpload: true,
                securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3StorageSettings.validated(
                bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
                securityProfile: .production, encryptionMode: .sseS3
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3StorageSettings.validated(
                bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false,
                securityProfile: .compatible, encryptionMode: .sseS3, kmsKeyARN: kmsARN
            )
        }
        #expect(S3StorageFailure.kmsKeyNotApplicable.errorDescription == "SSE-S3 does not use a KMS key. Select SSE-KMS or DSSE-KMS, or clear the KMS key ARN.")
    }

    @Test("Builds control-oriented object keys without traversal")
    func buildsSafeControlObjectKeys() {
        let settings = S3StorageSettings(bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false)
        let context = CaptureContext(sessionID: "session", sessionName: "Q3", controlID: "../../8.3.1", title: "MFA", system: "Okta", environment: "Production", assessmentPeriod: "../2026 Q3", description: "", complianceArea: "PCI DSS 4.0.1", controlTitle: "Strong authentication / MFA", customFileName: "MFA")
        let base = S3StorageService.objectBase(settings: settings, context: context, evidenceID: "EV-123")
        #expect(base == "scopeproof/8.3.1-Strong-authentication-MFA/2026-Q3/EV-123")
        #expect(!base.contains(".."))
    }

    @Test("Uses fixed AWS hosts and signs encrypted PUT requests")
    func signsRequestsWithoutExposingSecrets() throws {
        let settings = S3StorageSettings(bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false)
        let url = try S3StorageService.endpoint(settings: settings, objectKey: "scopeproof/8.3.1/EV-123/evidence.png")
        #expect(url.absoluteString == "https://company-evidence.s3.us-east-1.amazonaws.com/scopeproof/8.3.1/EV-123/evidence.png")
        let dotted = try S3StorageService.endpoint(settings: S3StorageSettings(bucket: "company.evidence", region: "us-west-2", prefix: "", autoUpload: false), objectKey: "evidence/file.json")
        #expect(dotted.absoluteString == "https://s3.us-west-2.amazonaws.com/company.evidence/evidence/file.json")

        let credentials = try S3Credentials.validated(accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: "temporary-token")
        let date = try #require(ISO8601DateFormatter().date(from: "2026-08-19T12:00:00Z"))
        let request = try S3StorageService.signedRequest(method: "PUT", url: url, region: settings.region, body: Data("evidence".utf8), contentType: "image/png", credentials: credentials, date: date, requireEncryption: true)
        let authorization = try #require(request.value(forHTTPHeaderField: "Authorization"))
        #expect(authorization.hasPrefix("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260819/us-east-1/s3/aws4_request"))
        #expect(authorization.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-server-side-encryption"))
        #expect(authorization.hasSuffix("Signature=180432ea34301f560f3b35a7b0f932bf453250759ebcb3a51b0412f790e927dd"))
        #expect(!authorization.contains(credentials.secretAccessKey))
        #expect(request.value(forHTTPHeaderField: "x-amz-server-side-encryption") == "AES256")
        #expect(request.value(forHTTPHeaderField: "x-amz-security-token") == "temporary-token")
        #expect(request.value(forHTTPHeaderField: "x-amz-content-sha256") == S3StorageService.sha256(Data("evidence".utf8)))

        let testURL = try #require(URL(string: "https://company-evidence.s3.us-east-1.amazonaws.com/?prefix=scopeproof%2F&max-keys=0&list-type=2"))
        let testRequest = try S3StorageService.signedRequest(method: "GET", url: testURL, region: settings.region, body: Data(), contentType: nil, credentials: credentials, date: date, requireEncryption: false)
        #expect(testRequest.value(forHTTPHeaderField: "Authorization")?.hasSuffix("Signature=5591db3aec7281f2b861221a58fcbecd8e2ded40cabdbedf3a6eaa8d0f467127") == true)

        let kmsARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        let checksum = S3StorageService.sha256Base64(Data("evidence".utf8))
        let kmsRequest = try S3StorageService.signedRequest(
            method: "PUT", url: url, region: settings.region, body: Data("evidence".utf8),
            contentType: "image/png", credentials: credentials, date: date, requireEncryption: true,
            expectedBucketOwner: "123456789012", encryptionMode: .sseKMS,
            kmsKeyARN: kmsARN, checksumSHA256: checksum
        )
        #expect(kmsRequest.value(forHTTPHeaderField: "x-amz-checksum-sha256") == checksum)
        #expect(kmsRequest.value(forHTTPHeaderField: "x-amz-expected-bucket-owner") == "123456789012")
        #expect(kmsRequest.value(forHTTPHeaderField: "x-amz-server-side-encryption") == "aws:kms")
        #expect(kmsRequest.value(forHTTPHeaderField: "x-amz-server-side-encryption-aws-kms-key-id") == kmsARN)
        #expect(kmsRequest.value(forHTTPHeaderField: "Authorization")?.contains("x-amz-checksum-sha256") == true)

        let lookalike = try #require(URL(string: "https://attacker-s3.amazonaws.com/evidence.png"))
        #expect(throws: S3StorageFailure.self) {
            try S3StorageService.signedRequest(
                method: "PUT", url: lookalike, region: settings.region, body: Data("evidence".utf8),
                contentType: "image/png", credentials: credentials, date: date, requireEncryption: true
            )
        }
        let wrongRegion = try #require(URL(string: "https://company-evidence.s3.us-west-2.amazonaws.com/evidence.png"))
        #expect(throws: S3StorageFailure.self) {
            try S3StorageService.signedRequest(
                method: "PUT", url: wrongRegion, region: settings.region, body: Data("evidence".utf8),
                contentType: "image/png", credentials: credentials, date: date, requireEncryption: true
            )
        }
    }

    @Test("Creates buckets with region-safe requests and secure defaults")
    func buildsSecureBucketCreationRequests() throws {
        let settings = S3StorageSettings(bucket: "company-evidence", region: "us-west-2", prefix: "scopeproof", autoUpload: true)
        let credentials = try S3Credentials.validated(accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: "")
        let date = try #require(ISO8601DateFormatter().date(from: "2026-08-19T12:00:00Z"))

        #expect(S3StorageService.createBucketBody(region: "us-east-1").isEmpty)
        let regionalBody = S3StorageService.createBucketBody(region: settings.region)
        #expect(String(data: regionalBody, encoding: .utf8)?.contains("<LocationConstraint>us-west-2</LocationConstraint>") == true)

        let publicAccessURL = try S3StorageService.bucketOperationEndpoint(settings: settings, operation: "publicAccessBlock")
        #expect(publicAccessURL.absoluteString == "https://company-evidence.s3.us-west-2.amazonaws.com/?publicAccessBlock")
        #expect(throws: S3StorageFailure.self) { try S3StorageService.bucketOperationEndpoint(settings: settings, operation: "acl") }

        let hardeningBody = S3StorageService.publicAccessBlockBody
        let request = try S3StorageService.signedRequest(
            method: "PUT", url: publicAccessURL, region: settings.region, body: hardeningBody,
            contentType: "application/xml", credentials: credentials, date: date,
            requireEncryption: false, contentMD5: S3StorageService.contentMD5(hardeningBody)
        )
        let authorization = try #require(request.value(forHTTPHeaderField: "Authorization"))
        #expect(request.value(forHTTPHeaderField: "Content-MD5") == S3StorageService.contentMD5(hardeningBody))
        #expect(authorization.contains("SignedHeaders=content-md5;content-type;host;x-amz-content-sha256;x-amz-date"))
        #expect(String(data: S3StorageService.publicAccessBlockBody, encoding: .utf8)?.contains("<RestrictPublicBuckets>true</RestrictPublicBuckets>") == true)
        #expect(String(data: S3StorageService.versioningBody, encoding: .utf8)?.contains("<Status>Enabled</Status>") == true)
        #expect(String(data: S3StorageService.ownershipControlsBody, encoding: .utf8)?.contains("BucketOwnerEnforced") == true)

        let kmsARN = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
        let hardened = try S3StorageSettings.validated(
            bucket: settings.bucket, region: settings.region, prefix: settings.prefix, autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .compliance, retentionDays: 2_555, archiveAfterDays: 90
        )
        #expect(String(data: S3StorageService.encryptionBody(settings: hardened), encoding: .utf8)?.contains(kmsARN) == true)
        #expect(String(data: S3StorageService.objectLockBody(settings: hardened), encoding: .utf8)?.contains("<Mode>COMPLIANCE</Mode><Days>2555</Days>") == true)
        #expect(String(data: S3StorageService.lifecycleBody(settings: hardened), encoding: .utf8)?.contains("<StorageClass>DEEP_ARCHIVE</StorageClass>") == true)
        let policy = try S3StorageService.bucketPolicyBody(settings: hardened)
        #expect(S3StorageService.bucketPolicyIsSecure(policy, settings: hardened))
        let weakenedPolicy = Data(String(decoding: policy, as: UTF8.self).replacingOccurrences(of: "aws:SecureTransport", with: "aws:SourceIp").utf8)
        #expect(!S3StorageService.bucketPolicyIsSecure(weakenedPolicy, settings: hardened))
        let fipsURL = try S3StorageService.endpoint(settings: hardened.withFIPS(), objectKey: "scopeproof/file.json")
        #expect(fipsURL.host == "s3-fips.us-west-2.amazonaws.com")
    }

    @Test("Parses bounded prefix-scoped listings and signs conditional downloads")
    func parsesListingsAndSignsDownloads() throws {
        let xml = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <IsTruncated>true</IsTruncated>
          <Contents>
            <Key>scopeproof/8.3.1-Strong-authentication/2026-Q3/EV-123/evidence&amp;review.png</Key>
            <LastModified>2026-08-20T12:34:56.000Z</LastModified>
            <ETag>&quot;0123456789abcdef0123456789abcdef&quot;</ETag>
            <Size>4096</Size>
          </Contents>
          <NextContinuationToken>token+/=value</NextContinuationToken>
        </ListBucketResult>
        """.utf8)
        let page = try S3StorageService.parseObjectList(xml, requiredPrefix: "scopeproof")
        #expect(page.isTruncated)
        #expect(page.nextContinuationToken == "token+/=value")
        let object = try #require(page.objects.first)
        #expect(object.key.hasSuffix("evidence&review.png"))
        #expect(object.size == 4_096)
        #expect(object.eTag == "0123456789abcdef0123456789abcdef")

        let settings = S3StorageSettings(bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false, uploadsAllowed: true)
        let nextURL = try S3StorageService.listObjectsEndpoint(settings: settings, maximumKeys: 1_000, continuationToken: page.nextContinuationToken)
        #expect(nextURL.host == "company-evidence.s3.us-east-1.amazonaws.com")
        #expect(URLComponents(url: nextURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "continuation-token" })?.value == "token+/=value")

        let credentials = try S3Credentials.validated(accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: "")
        let objectURL = try S3StorageService.endpoint(settings: settings, objectKey: object.key)
        let date = try #require(ISO8601DateFormatter().date(from: "2026-08-20T12:00:00Z"))
        let request = try S3StorageService.signedRequest(
            method: "GET", url: objectURL, region: settings.region, body: Data(), contentType: nil,
            credentials: credentials, date: date, requireEncryption: false, ifMatch: object.eTag
        )
        #expect(request.value(forHTTPHeaderField: "If-Match") == "\"0123456789abcdef0123456789abcdef\"")
        #expect(request.value(forHTTPHeaderField: "Authorization")?.contains("SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date") == true)

        let outside = Data(String(decoding: xml, as: UTF8.self).replacingOccurrences(of: "scopeproof/", with: "other-prefix/").utf8)
        #expect(throws: S3StorageFailure.self) { try S3StorageService.parseObjectList(outside, requiredPrefix: "scopeproof") }
        let missingTruncationState = Data(String(decoding: xml, as: UTF8.self).replacingOccurrences(of: "<IsTruncated>true</IsTruncated>", with: "").utf8)
        #expect(throws: S3StorageFailure.self) { try S3StorageService.parseObjectList(missingTruncationState, requiredPrefix: "scopeproof") }
        #expect(throws: S3StorageFailure.self) { try S3StorageService.listObjectsEndpoint(settings: settings, maximumKeys: 1_001, continuationToken: nil) }
    }

    @Test("Parses immutable object versions and binds downloads to a version ID")
    func parsesObjectVersions() throws {
        let xml = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <IsTruncated>false</IsTruncated>
          <Version>
            <Key>scopeproof/8.3.1/EV-123/evidence.png</Key>
            <VersionId>3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo</VersionId>
            <IsLatest>true</IsLatest>
            <LastModified>2026-08-20T12:34:56.000Z</LastModified>
            <ETag>&quot;0123456789abcdef0123456789abcdef&quot;</ETag>
            <Size>4096</Size>
          </Version>
        </ListVersionsResult>
        """.utf8)
        let page = try S3StorageService.parseObjectVersionList(xml, requiredPrefix: "scopeproof")
        let object = try #require(page.objects.first)
        #expect(object.isLatest)
        #expect(!object.versionID.isEmpty)

        let settings = S3StorageSettings(bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false)
        let url = try S3StorageService.endpoint(settings: settings, objectKey: object.key, versionID: object.versionID)
        #expect(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first?.name == "versionId")
        let listURL = try S3StorageService.listObjectVersionsEndpoint(settings: settings, maximumKeys: 1_000, keyMarker: nil, versionIDMarker: nil)
        #expect(URLComponents(url: listURL, resolvingAgainstBaseURL: false)?.queryItems?.contains(where: { $0.name == "versions" }) == true)
    }

    @Test("Reports production posture failures precisely")
    func verifiesPosture() throws {
        let kmsARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        let settings = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .governance, retentionDays: 365
        )
        let weak = S3BucketPosture(
            blockPublicAccess: false, versioningEnabled: true, ownershipEnforced: false,
            encryptionMode: .sseS3, kmsKeyARN: "", objectLockEnabled: false,
            retentionMode: nil, retentionDays: 0, lifecycleArchiveAfterDays: 0,
            replicationDestinationBucketARN: ""
        )
        let failures = S3StorageService.postureFailures(weak, settings: settings)
        #expect(failures.count >= 5)
    }
}

private extension S3StorageSettings {
    func withFIPS() -> S3StorageSettings {
        var copy = self
        copy.useFIPSEndpoint = true
        return copy
    }
}
