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
        #expect(S3StorageSettings.defaults.archiveAfterDays == 0)
        #expect(S3StorageSettings.defaults.retentionMode == .compliance)
        let customerBinding = try #require(TenantWorkspaceBinding.validated(
            tenantID: "customer-a", workspaceID: "audit-2026"
        ))
        let disconnected = S3StorageSettings.empty(for: customerBinding)
        #expect(disconnected.tenantBinding == customerBinding)
        #expect(!disconnected.isConfigured)
        #expect(disconnected.isBound(to: customerBinding))
        #expect(!disconnected.isBound(to: .localDefault))
        #expect(S3RetentionMode.governance.displayName.contains("non-production"))
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
        #expect(migrated.authentication == .manual)
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
        let multiRegionKeyARN = "arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
        #expect(try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: multiRegionKeyARN
        ).kmsKeyARN == multiRegionKeyARN)
        #expect(throws: S3StorageFailure.self) {
            try S3StorageSettings.validated(
                bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
                securityProfile: .production, encryptionMode: .sseKMS,
                kmsKeyARN: "arn:aws:kms:us-east-1:123456789012:key/mrk-not-a-valid-key-id"
            )
        }
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
                bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
                securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
                retentionMode: .governance
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3StorageSettings.validated(
                bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
                securityProfile: .production, encryptionMode: .sseKMS,
                kmsKeyARN: "arn:aws-us-gov:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
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

    @Test("Binds DescribeKey to the verified account and rejects ineligible KMS keys")
    func verifiesCustomerManagedKMSKeyPosture() throws {
        let kmsARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        let settings = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN
        )
        let credentials = try S3Credentials.validated(
            accessKeyID: "ASIAIOSFODNN7EXAMPLE",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            sessionToken: "temporary-session-token",
            expiresAt: Date().addingTimeInterval(3_600)
        )
        let date = try #require(ISO8601DateFormatter().date(from: "2026-08-28T12:00:00Z"))
        let request = try S3StorageService.describeKMSKeyRequest(
            settings: settings, credentials: credentials, date: date
        )
        #expect(request.url?.absoluteString == "https://kms.us-east-1.amazonaws.com/")
        #expect(request.value(forHTTPHeaderField: "x-amz-target") == "TrentService.DescribeKey")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/x-amz-json-1.1")
        #expect(request.value(forHTTPHeaderField: "Authorization")?.contains("/us-east-1/kms/aws4_request") == true)
        #expect((try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: String])?["KeyId"] == kmsARN)
        #expect(S3StorageService.kmsKeyARNMatchesVerifiedDestination(
            kmsARN, region: "us-east-1", accountID: "123456789012"
        ))
        #expect(!S3StorageService.kmsKeyARNMatchesVerifiedDestination(
            kmsARN, region: "us-east-1", accountID: "999999999999"
        ))

        let valid = Data(#"{"KeyMetadata":{"AWSAccountId":"123456789012","Arn":"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012","Enabled":true,"KeyManager":"CUSTOMER","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","KeyState":"Enabled"}}"#.utf8)
        let posture = try S3StorageService.parseKMSKeyPosture(
            valid, expectedARN: kmsARN, region: "us-east-1", expectedAccountID: "123456789012"
        )
        #expect(posture.satisfies(settings, accountID: "123456789012"))

        let awsManaged = Data(String(decoding: valid, as: UTF8.self)
            .replacingOccurrences(of: #""KeyManager":"CUSTOMER""#, with: #""KeyManager":"AWS""#).utf8)
        #expect(throws: S3StorageFailure.self) {
            try S3StorageService.parseKMSKeyPosture(
                awsManaged, expectedARN: kmsARN, region: "us-east-1", expectedAccountID: "123456789012"
            )
        }
        let pendingDeletion = Data(String(decoding: valid, as: UTF8.self)
            .replacingOccurrences(of: #""Enabled":true"#, with: #""Enabled":false"#)
            .replacingOccurrences(of: #""KeyState":"Enabled""#, with: #""KeyState":"PendingDeletion""#).utf8)
        #expect(throws: S3StorageFailure.self) {
            try S3StorageService.parseKMSKeyPosture(
                pendingDeletion, expectedARN: kmsARN, region: "us-east-1", expectedAccountID: "123456789012"
            )
        }
    }

    @Test("Builds control-oriented object keys without traversal")
    func buildsSafeControlObjectKeys() {
        let settings = S3StorageSettings(
            tenantID: "customer-a", workspaceID: "audit-2026",
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: false
        )
        let context = CaptureContext(sessionID: "session", sessionName: "Q3", controlID: "../../8.3.1", title: "MFA", system: "Okta", environment: "Production", assessmentPeriod: "../2026 Q3", description: "", complianceArea: "PCI DSS 4.0.1", controlTitle: "Strong authentication / MFA", customFileName: "MFA", tenantID: "customer-a", workspaceID: "audit-2026")
        let base = S3StorageService.objectBase(settings: settings, context: context, evidenceID: "EV-123")
        #expect(base == "scopeproof/tenants/customer-a/workspaces/audit-2026/8.3.1-Strong-authentication-MFA/2026-Q3/EV-123")
        #expect(!base.contains(".."))

        let listURL = try? S3StorageService.listObjectVersionsEndpoint(
            settings: settings, maximumKeys: 100, keyMarker: nil, versionIDMarker: nil
        )
        #expect(listURL?.query?.contains("prefix=scopeproof/tenants/customer-a/workspaces/audit-2026/") == true)
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
        let policyDocument = try #require(JSONSerialization.jsonObject(with: policy) as? [String: Any])
        let policyStatements = try #require(policyDocument["Statement"] as? [[String: Any]])
        #expect(policyStatements.compactMap { $0["Sid"] as? String } == [
            "ScopeproofDenyInsecureTransport", "ScopeproofDenyBucketDeletion",
            "ScopeproofDenyEvidenceDeletion", "ScopeproofDenyWrongEncryption",
            "ScopeproofDenyWrongKMSKey",
        ])
        let deletionStatement = try #require(policyStatements.first { $0["Sid"] as? String == "ScopeproofDenyEvidenceDeletion" })
        #expect(deletionStatement["Action"] as? [String] == [
            "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
        ])
        let weakenedPolicy = Data(String(decoding: policy, as: UTF8.self).replacingOccurrences(of: "aws:SecureTransport", with: "aws:SourceIp").utf8)
        #expect(!S3StorageService.bucketPolicyIsSecure(weakenedPolicy, settings: hardened))

        var crossAccountPolicy = try #require(JSONSerialization.jsonObject(with: policy) as? [String: Any])
        var crossAccountStatements = try #require(crossAccountPolicy["Statement"] as? [[String: Any]])
        crossAccountStatements.append([
            "Sid": "PermitExternalReader", "Effect": "Allow",
            "Principal": ["AWS": "arn:aws:iam::999999999999:root"],
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::company-evidence/scopeproof/*",
        ])
        crossAccountPolicy["Statement"] = crossAccountStatements
        let crossAccountData = try JSONSerialization.data(withJSONObject: crossAccountPolicy)
        #expect(!S3StorageService.bucketPolicyIsSecure(crossAccountData, settings: hardened))

        var publicPolicy = try #require(JSONSerialization.jsonObject(with: policy) as? [String: Any])
        var publicStatements = try #require(publicPolicy["Statement"] as? [[String: Any]])
        publicStatements.append([
            "Sid": "PermitPublicEvidence", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::company-evidence/scopeproof/*",
        ])
        publicPolicy["Statement"] = publicStatements
        let publicData = try JSONSerialization.data(withJSONObject: publicPolicy)
        #expect(!S3StorageService.bucketPolicyIsSecure(publicData, settings: hardened))
        let fipsURL = try S3StorageService.endpoint(settings: hardened.withFIPS(), objectKey: "scopeproof/file.json")
        #expect(fipsURL.host == "s3-fips.us-west-2.amazonaws.com")
    }

    @Test("Rejects hidden and non-exact lifecycle or replication configurations")
    func verifiesExactOptionalBucketConfigurations() throws {
        let kmsARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        let disabled = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .compliance, retentionDays: 365, archiveAfterDays: 0
        )
        let archived = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .compliance, retentionDays: 365, archiveAfterDays: 90
        )
        let lifecycle = S3StorageService.lifecycleBody(settings: archived)
        #expect(S3StorageService.lifecycleConfigurationIsSecure(nil, settings: disabled))
        #expect(!S3StorageService.lifecycleConfigurationIsSecure(lifecycle, settings: disabled))
        #expect(S3StorageService.lifecycleConfigurationIsSecure(lifecycle, settings: archived))
        let lifecycleWithDeletion = Data(String(decoding: lifecycle, as: UTF8.self).replacingOccurrences(
            of: "</LifecycleConfiguration>",
            with: "<Rule><ID>DeleteEvidence</ID><Filter><Prefix>scopeproof/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>365</Days></Expiration></Rule></LifecycleConfiguration>"
        ).utf8)
        #expect(!S3StorageService.lifecycleConfigurationIsSecure(lifecycleWithDeletion, settings: archived))

        let replicated = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            retentionMode: .compliance, retentionDays: 365, archiveAfterDays: 0,
            replicationDestinationBucketARN: "arn:aws:s3:::company-evidence-replica",
            replicationRoleARN: "arn:aws:iam::123456789012:role/scopeproof-replication",
            replicationKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/87654321-4321-4321-4321-210987654321"
        )
        let replication = S3StorageService.replicationBody(settings: replicated)
        #expect(S3StorageService.replicationConfigurationIsSecure(nil, settings: disabled))
        #expect(!S3StorageService.replicationConfigurationIsSecure(replication, settings: disabled))
        #expect(S3StorageService.replicationConfigurationIsSecure(replication, settings: replicated))
        let replicationWithExfiltration = Data(String(decoding: replication, as: UTF8.self).replacingOccurrences(
            of: "</ReplicationConfiguration>",
            with: "<Rule><ID>ExfiltrateEvidence</ID><Priority>2</Priority><Filter><Prefix>scopeproof/</Prefix></Filter><Status>Enabled</Status><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><SourceSelectionCriteria><SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects></SourceSelectionCriteria><Destination><Bucket>arn:aws:s3:::attacker-evidence</Bucket><EncryptionConfiguration><ReplicaKmsKeyID>arn:aws:kms:us-west-2:999999999999:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</ReplicaKmsKeyID></EncryptionConfiguration></Destination></Rule></ReplicationConfiguration>"
        ).utf8)
        #expect(!S3StorageService.replicationConfigurationIsSecure(replicationWithExfiltration, settings: replicated))

        let safePosture = S3BucketPosture(
            blockPublicAccess: true, versioningEnabled: true, ownershipEnforced: true,
            bucketPolicyEnforced: true, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            bucketKeyEnabled: true,
            objectLockEnabled: true, retentionMode: .compliance, retentionDays: 365,
            lifecycleArchiveAfterDays: 0, replicationDestinationBucketARN: ""
        )
        let kmsKeyPosture = S3KMSKeyPosture(
            arn: kmsARN, partition: "aws", region: "us-east-1", accountID: "123456789012",
            keyManager: "CUSTOMER", keyUsage: "ENCRYPT_DECRYPT", keySpec: "SYMMETRIC_DEFAULT",
            keyState: "Enabled", enabled: true
        )
        let obsoleteBinding = S3VerifiedDestination(
            schemaVersion: 1, settingsDigest: disabled.securityBindingDigest,
            accountID: "123456789012", principalARN: "arn:aws:iam::123456789012:role/scopeproof-evidence",
            verifiedAt: Date(timeIntervalSince1970: 0), posture: safePosture
        )
        #expect(!obsoleteBinding.matches(disabled))
        let verificationTime = Date()
        let currentBinding = S3VerifiedDestination(
            schemaVersion: S3VerifiedDestination.currentSchemaVersion,
            settingsDigest: disabled.securityBindingDigest,
            accountID: obsoleteBinding.accountID, principalARN: obsoleteBinding.principalARN,
            verifiedAt: verificationTime, posture: safePosture, kmsKeyPosture: kmsKeyPosture
        )
        #expect(currentBinding.matches(disabled, now: verificationTime))
        #expect(!currentBinding.matches(
            disabled,
            now: verificationTime.addingTimeInterval(S3VerifiedDestination.maximumVerificationAge + 1)
        ))
        let hiddenLifecyclePosture = S3BucketPosture(
            blockPublicAccess: true, versioningEnabled: true, ownershipEnforced: true,
            bucketPolicyEnforced: true, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            bucketKeyEnabled: true,
            objectLockEnabled: true, retentionMode: .compliance, retentionDays: 365,
            lifecycleArchiveAfterDays: -1, replicationDestinationBucketARN: ""
        )
        #expect(!S3VerifiedDestination(
            schemaVersion: S3VerifiedDestination.currentSchemaVersion,
            settingsDigest: disabled.securityBindingDigest, accountID: obsoleteBinding.accountID,
            principalARN: obsoleteBinding.principalARN, verifiedAt: obsoleteBinding.verifiedAt,
            posture: hiddenLifecyclePosture, kmsKeyPosture: kmsKeyPosture
        ).matches(disabled))

        let bucketKeyDisabledPosture = S3BucketPosture(
            blockPublicAccess: true, versioningEnabled: true, ownershipEnforced: true,
            bucketPolicyEnforced: true, encryptionMode: .sseKMS, kmsKeyARN: kmsARN,
            bucketKeyEnabled: false,
            objectLockEnabled: true, retentionMode: .compliance, retentionDays: 365,
            lifecycleArchiveAfterDays: 0, replicationDestinationBucketARN: ""
        )
        #expect(!bucketKeyDisabledPosture.satisfies(disabled))
        #expect(S3StorageService.postureFailures(bucketKeyDisabledPosture, settings: disabled)
            .contains("S3 Bucket Keys must be enabled for SSE-KMS"))
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
            retentionMode: .compliance, retentionDays: 365
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

    @Test("Rejects obsolete Keychain bindings and expires current verification")
    func enforcesCurrentVerifiedDestinationSchema() throws {
        let now = Date(timeIntervalSince1970: 1_787_900_000)
        let settings = S3StorageSettings(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof",
            autoUpload: false, uploadsAllowed: true
        )
        let posture = S3BucketPosture(
            blockPublicAccess: true, versioningEnabled: true, ownershipEnforced: true,
            encryptionMode: .sseS3, kmsKeyARN: "", objectLockEnabled: false,
            retentionMode: nil, retentionDays: 0, lifecycleArchiveAfterDays: 0,
            replicationDestinationBucketARN: ""
        )
        let obsolete = S3VerifiedDestination(
            schemaVersion: 1, settingsDigest: settings.securityBindingDigest,
            accountID: "123456789012", principalARN: "arn:aws:iam::123456789012:user/test",
            verifiedAt: now, posture: posture
        )
        let current = S3VerifiedDestination(
            schemaVersion: S3VerifiedDestination.currentSchemaVersion,
            settingsDigest: settings.securityBindingDigest,
            accountID: obsolete.accountID, principalARN: obsolete.principalARN,
            verifiedAt: now, posture: posture
        )
        #expect(KeychainStore.decodeS3VerifiedDestination(try JSONEncoder().encode(obsolete)) == nil)
        #expect(KeychainStore.decodeS3VerifiedDestination(try JSONEncoder().encode(current)) == current)
        #expect(current.matches(settings, now: now))
        #expect(!current.matches(
            settings,
            now: now.addingTimeInterval(S3VerifiedDestination.maximumVerificationAge + 1)
        ))
    }

    @Test("Writes and verifies exact-version Object Lock retention")
    func verifiesExactVersionRetention() throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2026-08-28T12:00:00Z"))
        let settings = try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof",
            autoUpload: true, uploadsAllowed: true, securityProfile: .production,
            encryptionMode: .sseKMS,
            kmsKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            retentionMode: .compliance, retentionDays: 365
        )
        let expected = S3StorageService.objectRetention(settings: settings, now: now)
        #expect(expected.headers["x-amz-object-lock-mode"] == "COMPLIANCE")
        #expect(expected.headers["x-amz-object-lock-retain-until-date"] == expected.retainUntil)
        let endpoint = try S3StorageService.objectRetentionEndpoint(
            settings: settings, objectKey: "scopeproof/EV-123/evidence.png",
            versionID: "version+/=value"
        )
        let query = try #require(URLComponents(url: endpoint, resolvingAgainstBaseURL: false)?.queryItems)
        #expect(query.contains { $0.name == "retention" })
        #expect(query.contains { $0.name == "versionId" && $0.value == "version+/=value" })

        let retained = Data("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2027-08-28T12:00:00Z</RetainUntilDate></Retention>".utf8)
        let weakened = Data("<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2027-08-28T12:00:00Z</RetainUntilDate></Retention>".utf8)
        let shortened = Data("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2026-08-29T12:00:00Z</RetainUntilDate></Retention>".utf8)
        #expect(S3StorageService.objectRetentionResponseMatches(retained, expected: expected))
        #expect(!S3StorageService.objectRetentionResponseMatches(weakened, expected: expected))
        #expect(!S3StorageService.objectRetentionResponseMatches(shortened, expected: expected))
    }
}

private extension S3StorageSettings {
    func withFIPS() -> S3StorageSettings {
        var copy = self
        copy.useFIPSEndpoint = true
        return copy
    }
}
