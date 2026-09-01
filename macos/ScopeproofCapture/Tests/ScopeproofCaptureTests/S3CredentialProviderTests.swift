import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("S3 credential providers")
struct S3CredentialProviderTests {
    @Test("Validates non-secret authentication configuration")
    func validatesAuthenticationConfiguration() throws {
        let profile = try S3AuthenticationConfiguration.validated(
            method: .identityCenterProfile, profileName: "scopeproof.production_1", region: "us-east-1"
        )
        #expect(profile.profileName == "scopeproof.production_1")
        #expect(profile.roleARN.isEmpty)

        let role = try S3AuthenticationConfiguration.validated(
            method: .identityCenterAssumeRole, profileName: "scopeproof-sso",
            roleARN: "arn:aws:iam::123456789012:role/scopeproof/evidence-uploader",
            externalID: "scopeproof:tenant/acme-1", region: "us-east-1"
        )
        #expect(role.method == .identityCenterAssumeRole)
        #expect(role.externalID == "scopeproof:tenant/acme-1")

        #expect(throws: S3StorageFailure.self) {
            try S3AuthenticationConfiguration.validated(
                method: .identityCenterProfile, profileName: "../../attacker", region: "us-east-1"
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3AuthenticationConfiguration.validated(
                method: .identityCenterAssumeRole, profileName: "valid",
                roleARN: "arn:aws:iam::123456789012:user/not-a-role", region: "us-east-1"
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3AuthenticationConfiguration.validated(
                method: .identityCenterAssumeRole, profileName: "valid",
                roleARN: "arn:aws:iam::123456789012:role/evidence", externalID: "bad value",
                region: "us-east-1"
            )
        }
        #expect(throws: S3StorageFailure.self) {
            try S3AuthenticationConfiguration.validated(
                method: .identityCenterAssumeRole, profileName: "valid",
                roleARN: "arn:aws:iam::123456789012:role/evidence", externalID: "--no-verify-ssl",
                region: "us-east-1"
            )
        }
    }

    @Test("Parses only bounded expiring process credentials")
    func parsesProcessCredentials() throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let data = Data(Self.processCredentialJSON(expiration: "2099-01-01T01:00:00Z").utf8)
        let credentials = try S3AWSCredentialOutputParser.parseProcessCredentials(data, now: now)
        #expect(credentials.accessKeyID == "ASIAIOSFODNN7EXAMPLE")
        #expect(credentials.isTemporary)

        let permanent = Data(Self.processCredentialJSON(
            accessKeyID: "AKIAIOSFODNN7EXAMPLE", expiration: "2099-01-01T01:00:00Z"
        ).utf8)
        #expect(throws: S3StorageFailure.self) {
            try S3AWSCredentialOutputParser.parseProcessCredentials(permanent, now: now)
        }
        let expired = Data(Self.processCredentialJSON(expiration: "2099-01-01T00:04:59Z").utf8)
        #expect(throws: S3StorageFailure.self) {
            try S3AWSCredentialOutputParser.parseProcessCredentials(expired, now: now)
        }
        #expect(throws: S3StorageFailure.self) {
            try S3AWSCredentialOutputParser.parseProcessCredentials(Data(repeating: 0x41, count: 65 * 1024), now: now)
        }
    }

    @Test("Pins AWS CLI discovery to reviewed installation roots")
    func validatesAWSCLIPaths() {
        #expect(S3AWSCLIExecutableLocator.isTrustedResolvedPath(
            "/opt/homebrew/Cellar/awscli/2.27.1/libexec/bin/aws"
        ))
        #expect(S3AWSCLIExecutableLocator.isTrustedResolvedPath(
            "/usr/local/aws-cli/v2/2.27.1/dist/aws"
        ))
        #expect(!S3AWSCLIExecutableLocator.isTrustedResolvedPath("/tmp/aws"))
        #expect(!S3AWSCLIExecutableLocator.isTrustedResolvedPath("/Users/example/bin/aws"))
        #expect(!S3AWSCLIExecutableLocator.isTrustedResolvedPath("/usr/local/bin/aws"))
        #expect(!S3AWSCLIExecutableLocator.isTrustedResolvedPath(
            "/usr/local/aws-cli/v2/2.27.1/dist/aws-malicious"
        ))
        #expect(!S3AWSCLIExecutableLocator.isTrustedResolvedPath(
            "/opt/homebrew/Cellar/awscli/2.27.1/libexec/bin/aws/child"
        ))
    }

    @Test("Requires a root-owned non-writable AWS CLI trust chain")
    func validatesAWSCLITrustChain() {
        let candidate = "/usr/local/bin/aws"
        let resolved = "/usr/local/aws-cli/v2/2.36.32/dist/aws"
        var metadata = Self.secureAWSCLIPathMetadata(candidate: candidate, resolved: resolved)

        #expect(S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))

        metadata["/usr/local"] = .init(ownerID: 501, permissions: 0o755, kind: .directory)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))
        metadata["/usr/local"] = .init(ownerID: 0, permissions: 0o775, kind: .directory)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))
    }

    @Test("Rejects attacker-controlled links, targets, and non-executable binaries")
    func rejectsUnsafeAWSCLIPathComponents() {
        let candidate = "/usr/local/bin/aws"
        let resolved = "/usr/local/aws-cli/v2/2.36.32/dist/aws"
        var metadata = Self.secureAWSCLIPathMetadata(candidate: candidate, resolved: resolved)

        metadata[candidate] = .init(ownerID: 501, permissions: 0o777, kind: .symbolicLink)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))

        metadata = Self.secureAWSCLIPathMetadata(candidate: candidate, resolved: resolved)
        metadata[resolved] = .init(ownerID: 0, permissions: 0o775, kind: .regularFile)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))

        metadata[resolved] = .init(ownerID: 0, permissions: 0o644, kind: .regularFile)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))

        metadata[resolved] = .init(ownerID: 0, permissions: 0o755, kind: .symbolicLink)
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))
    }

    @Test("Validates intermediate symlinks and their canonical target")
    func validatesIntermediateAWSCLISymlink() {
        let candidate = "/usr/local/aws-cli/v2/current/bin/aws"
        let resolved = "/usr/local/aws-cli/v2/2.36.32/dist/aws"
        var metadata = Self.secureAWSCLIPathMetadata(candidate: candidate, resolved: resolved)
        metadata[candidate] = .init(ownerID: 0, permissions: 0o755, kind: .regularFile)
        metadata["/usr/local/aws-cli/v2/current"] = .init(
            ownerID: 0, permissions: 0o777, kind: .symbolicLink
        )

        #expect(S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))

        metadata["/usr/local/aws-cli/v2/current"] = .init(
            ownerID: 501, permissions: 0o777, kind: .symbolicLink
        )
        #expect(!S3AWSCLIExecutableLocator.isTrustedExecutable(
            candidatePath: candidate, resolvedPath: resolved, metadata: { metadata[$0] }
        ))
    }

    @Test("Terminates an AWS CLI process that exceeds the output bound")
    func boundsCLIOutput() async {
        let executor = SystemS3AWSCLIExecutor(
            testExecutableURL: URL(fileURLWithPath: "/usr/bin/yes"),
            commandTimeoutSeconds: 2,
            maximumOutputBytes: 4_096
        )
        do {
            _ = try await executor.execute(arguments: ["scopeproof-test-output"])
            Issue.record("Expected excessive subprocess output to be rejected")
        } catch {
            #expect(error as? S3AWSCLIExecutionFailure == .outputTooLarge)
        }
    }

    @Test("Times out and cancels stalled AWS CLI processes")
    func stopsStalledCLIProcesses() async {
        let timeoutExecutor = SystemS3AWSCLIExecutor(
            testExecutableURL: URL(fileURLWithPath: "/bin/sleep"), commandTimeoutSeconds: 0.1
        )
        do {
            _ = try await timeoutExecutor.execute(arguments: ["10"])
            Issue.record("Expected the subprocess deadline to be enforced")
        } catch {
            #expect(error as? S3AWSCLIExecutionFailure == .timedOut)
        }

        let cancelExecutor = SystemS3AWSCLIExecutor(
            testExecutableURL: URL(fileURLWithPath: "/bin/sleep"), commandTimeoutSeconds: 10
        )
        let task = Task { try await cancelExecutor.execute(arguments: ["10"]) }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Expected cancellation to terminate the subprocess")
        } catch {
            #expect(error is CancellationError)
        }
    }

    @Test("Rejects profiles that can execute a credential process")
    func rejectsCredentialProcessProfile() async throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let cli = RecordingS3CLI { arguments in
            if arguments.count == 5, arguments[0] == "configure", arguments[1] == "get",
               arguments[2] == "credential_process" {
                return Data("/tmp/untrusted-credential-helper\n".utf8)
            }
            if let configuration = try Self.identityCenterConfigurationResponse(arguments) { return configuration }
            return Data(Self.processCredentialJSON(expiration: "2099-01-01T01:00:00Z").utf8)
        }
        let settings = try Self.productionSettings(authentication: S3AuthenticationConfiguration(
            method: .identityCenterProfile, profileName: "scopeproof-prod", roleARN: "", externalID: ""
        ))
        let provider = S3CredentialProvider(
            cli: cli,
            identityVerifier: RecordingIdentityVerifier(identity: S3CallerIdentity(
                accountID: "123456789012",
                principalARN: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Scopeproof/user",
                userID: "AROATEST:user"
            )),
            manualCredentialLoader: { nil }, clock: { now }
        )
        do {
            _ = try await provider.credentials(for: settings, binding: nil)
            Issue.record("Expected credential_process to be rejected")
        } catch {
            #expect(error as? S3StorageFailure == .invalidIdentityCenterProfile)
        }
    }

    @Test("Refreshes Identity Center credentials and enforces verified identity")
    func refreshesIdentityCenterCredentials() async throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let cli = RecordingS3CLI { arguments in
            if let configuration = try Self.identityCenterConfigurationResponse(arguments) { return configuration }
            #expect(arguments == [
                "configure", "export-credentials", "--profile", "scopeproof-prod", "--format", "process",
            ])
            return Data(Self.processCredentialJSON(expiration: "2099-01-01T01:00:00Z").utf8)
        }
        let settings = try Self.productionSettings(authentication: S3AuthenticationConfiguration(
            method: .identityCenterProfile, profileName: "scopeproof-prod", roleARN: "", externalID: ""
        ))
        let verifier = RecordingIdentityVerifier(identity: S3CallerIdentity(
            accountID: "123456789012",
            principalARN: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Scopeproof_abcd/refreshed-user",
            userID: "AROATEST:refreshed-user"
        ))
        let provider = S3CredentialProvider(
            cli: cli, identityVerifier: verifier, manualCredentialLoader: { nil }, clock: { now }
        )
        let binding = Self.binding(
            settings: settings,
            principalARN: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Scopeproof_abcd/original-user"
        )

        let first = try await provider.credentials(for: settings, binding: binding)
        let executionCountAfterFirst = await cli.executionCount
        let second = try await provider.credentials(for: settings, binding: binding)
        #expect(first == second)
        #expect(executionCountAfterFirst > 1)
        #expect(await cli.executionCount == executionCountAfterFirst)
        #expect(await verifier.executionCount == 1)
    }

    @Test("Rejects a refreshed credential from another AWS identity")
    func rejectsIdentityMismatch() async throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let cli = RecordingS3CLI { arguments in
            if let configuration = try Self.identityCenterConfigurationResponse(arguments) { return configuration }
            return Data(Self.processCredentialJSON(expiration: "2099-01-01T01:00:00Z").utf8)
        }
        let settings = try Self.productionSettings(authentication: S3AuthenticationConfiguration(
            method: .identityCenterProfile, profileName: "scopeproof-prod", roleARN: "", externalID: ""
        ))
        let verifier = RecordingIdentityVerifier(identity: S3CallerIdentity(
            accountID: "999999999999",
            principalARN: "arn:aws:sts::999999999999:assumed-role/AWSReservedSSO_Scopeproof_abcd/user",
            userID: "AROATEST:user"
        ))
        let provider = S3CredentialProvider(
            cli: cli, identityVerifier: verifier, manualCredentialLoader: { nil }, clock: { now }
        )
        do {
            _ = try await provider.credentials(
                for: settings,
                binding: Self.binding(
                    settings: settings,
                    principalARN: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Scopeproof_abcd/user"
                )
            )
            Issue.record("Expected the changed AWS identity to be rejected")
        } catch {
            #expect(error as? S3StorageFailure == .credentialIdentityMismatch)
        }
    }

    @Test("Uses fixed AssumeRole arguments and validates the returned role session")
    func assumesExactRole() async throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let roleARN = "arn:aws:iam::123456789012:role/scopeproof/evidence-uploader"
        let cli = RecordingS3CLI { arguments in
            if let configuration = try Self.identityCenterConfigurationResponse(arguments) { return configuration }
            if arguments.first == "configure" {
                #expect(arguments == [
                    "configure", "export-credentials", "--profile", "scopeproof-sso", "--format", "process",
                ])
                return Data(Self.processCredentialJSON(expiration: "2099-01-01T01:00:00Z").utf8)
            }
            let sessionIndex = try #require(arguments.firstIndex(of: "--role-session-name"))
            let sessionName = try #require(arguments[safe: sessionIndex + 1])
            #expect(arguments.containsSubsequence(["--profile", "scopeproof-sso"]))
            #expect(arguments.containsSubsequence(["--role-arn", roleARN]))
            #expect(arguments.containsSubsequence(["--endpoint-url", "https://sts.us-east-1.amazonaws.com/"]))
            #expect(arguments.containsSubsequence(["--external-id", "scopeproof:tenant/acme"]))
            return Data(Self.assumeRoleJSON(sessionName: sessionName, expiration: "2099-01-01T01:00:00Z").utf8)
        }
        let settings = try Self.productionSettings(authentication: S3AuthenticationConfiguration(
            method: .identityCenterAssumeRole, profileName: "scopeproof-sso",
            roleARN: roleARN, externalID: "scopeproof:tenant/acme"
        ))
        let provider = S3CredentialProvider(
            cli: cli,
            identityVerifier: RecordingIdentityVerifier(identity: S3CallerIdentity(
                accountID: "123456789012",
                principalARN: "arn:aws:sts::123456789012:assumed-role/evidence-uploader/runtime",
                userID: "AROATEST:runtime"
            )),
            manualCredentialLoader: { nil }, clock: { now }
        )
        let credentials = try await provider.credentials(for: settings, binding: nil)
        #expect(credentials.isTemporary)
        #expect(await cli.executionCount > 2)
    }

    @Test("Production rejects manually supplied long-lived credentials")
    func rejectsManualLongLivedCredentials() async throws {
        let settings = try Self.productionSettings(authentication: .manual)
        let permanent = try S3Credentials.validated(
            accessKeyID: "AKIAIOSFODNN7EXAMPLE",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sessionToken: ""
        )
        let provider = S3CredentialProvider(
            cli: RecordingS3CLI { _ in throw S3AWSCLIExecutionFailure.rejected },
            identityVerifier: RecordingIdentityVerifier(identity: S3CallerIdentity(
                accountID: "123456789012", principalARN: "arn:aws:iam::123456789012:user/test", userID: "test"
            )),
            manualCredentialLoader: { permanent }
        )
        do {
            _ = try await provider.credentials(for: settings, binding: nil)
            Issue.record("Expected production to reject a long-lived IAM key")
        } catch {
            #expect(error as? S3StorageFailure == .temporaryCredentialsRequired)
        }
    }

    @Test("AssumeRole rejects a source profile backed by a long-lived key")
    func rejectsLongLivedAssumeRoleSource() async throws {
        let now = try #require(ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z"))
        let cli = RecordingS3CLI { arguments in
            if let configuration = try Self.identityCenterConfigurationResponse(arguments) { return configuration }
            #expect(arguments.first == "configure")
            return Data(Self.processCredentialJSON(
                accessKeyID: "AKIAIOSFODNN7EXAMPLE", expiration: "2099-01-01T01:00:00Z"
            ).utf8)
        }
        let settings = try Self.productionSettings(authentication: S3AuthenticationConfiguration(
            method: .identityCenterAssumeRole, profileName: "not-actually-sso",
            roleARN: "arn:aws:iam::123456789012:role/evidence-uploader", externalID: ""
        ))
        let provider = S3CredentialProvider(
            cli: cli,
            identityVerifier: RecordingIdentityVerifier(identity: S3CallerIdentity(
                accountID: "123456789012",
                principalARN: "arn:aws:sts::123456789012:assumed-role/evidence-uploader/runtime",
                userID: "AROATEST:runtime"
            )),
            manualCredentialLoader: { nil }, clock: { now }
        )
        do {
            _ = try await provider.credentials(for: settings, binding: nil)
            Issue.record("Expected the non-SSO source profile to be rejected")
        } catch {
            #expect(error as? S3StorageFailure == .temporaryCredentialsRequired)
        }
        #expect(await cli.executionCount > 1)
    }

    private static func productionSettings(authentication: S3AuthenticationConfiguration) throws -> S3StorageSettings {
        try S3StorageSettings.validated(
            bucket: "company-evidence", region: "us-east-1", prefix: "scopeproof", autoUpload: true,
            securityProfile: .production, encryptionMode: .sseKMS,
            kmsKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            retentionMode: .compliance, retentionDays: 365, authentication: authentication
        )
    }

    private static func secureAWSCLIPathMetadata(
        candidate: String,
        resolved: String
    ) -> [String: S3AWSCLIPathMetadata] {
        var result: [String: S3AWSCLIPathMetadata] = [
            "/": .init(ownerID: 0, permissions: 0o755, kind: .directory),
        ]
        for path in [candidate, resolved] {
            let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
            var current = "/"
            for (index, component) in components.dropFirst().enumerated() {
                current = (current as NSString).appendingPathComponent(component)
                let isLast = index == components.count - 2
                result[current] = .init(
                    ownerID: 0,
                    permissions: isLast ? 0o755 : 0o755,
                    kind: isLast ? .regularFile : .directory
                )
            }
        }
        result[candidate] = .init(ownerID: 0, permissions: 0o777, kind: .symbolicLink)
        return result
    }

    private static func binding(settings: S3StorageSettings, principalARN: String) -> S3VerifiedDestination {
        S3VerifiedDestination(
            schemaVersion: S3VerifiedDestination.currentSchemaVersion,
            settingsDigest: settings.securityBindingDigest,
            accountID: "123456789012", principalARN: principalARN,
            verifiedAt: ISO8601DateFormatter().date(from: "2099-01-01T00:00:00Z")!,
            posture: S3BucketPosture(
                blockPublicAccess: true, versioningEnabled: true, ownershipEnforced: true,
                bucketPolicyEnforced: true, encryptionMode: .sseKMS, kmsKeyARN: settings.kmsKeyARN,
                bucketKeyEnabled: true,
                objectLockEnabled: true, retentionMode: .compliance, retentionDays: 365,
                lifecycleArchiveAfterDays: 0, replicationDestinationBucketARN: ""
            ),
            kmsKeyPosture: S3KMSKeyPosture(
                arn: settings.kmsKeyARN, partition: "aws", region: settings.region,
                accountID: "123456789012", keyManager: "CUSTOMER",
                keyUsage: "ENCRYPT_DECRYPT", keySpec: "SYMMETRIC_DEFAULT",
                keyState: "Enabled", enabled: true
            )
        )
    }

    private static func processCredentialJSON(
        accessKeyID: String = "ASIAIOSFODNN7EXAMPLE", expiration: String
    ) -> String {
        #"{"Version":1,"AccessKeyId":"\#(accessKeyID)","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"temporary-session-token-for-scopeproof-tests","Expiration":"\#(expiration)"}"#
    }

    private static func identityCenterConfigurationResponse(_ arguments: [String]) throws -> Data? {
        guard arguments.count == 5, arguments[0] == "configure", arguments[1] == "get",
              arguments[3] == "--profile" else { return nil }
        switch arguments[2] {
        case "sso_session": return Data("scopeproof-session\n".utf8)
        case "sso_account_id": return Data("123456789012\n".utf8)
        case "sso_role_name": return Data("ScopeproofEvidence\n".utf8)
        default: throw S3AWSCLIExecutionFailure.rejected
        }
    }

    private static func assumeRoleJSON(sessionName: String, expiration: String) -> String {
        #"{"Credentials":{"AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"temporary-session-token-for-scopeproof-tests","Expiration":"\#(expiration)"},"AssumedRoleUser":{"AssumedRoleId":"AROATEST:\#(sessionName)","Arn":"arn:aws:sts::123456789012:assumed-role/evidence-uploader/\#(sessionName)"}}"#
    }
}

private actor RecordingS3CLI: S3AWSCLIExecuting {
    typealias Handler = @Sendable ([String]) throws -> Data
    private let handler: Handler
    private(set) var executionCount = 0

    init(handler: @escaping Handler) { self.handler = handler }
    nonisolated func isAvailable() -> Bool { true }
    func execute(arguments: [String]) async throws -> Data {
        executionCount += 1
        return try handler(arguments)
    }
}

private actor RecordingIdentityVerifier: S3CallerIdentityVerifying {
    private let identity: S3CallerIdentity
    private(set) var executionCount = 0

    init(identity: S3CallerIdentity) { self.identity = identity }
    func callerIdentity(settings: S3StorageSettings, credentials: S3Credentials) async throws -> S3CallerIdentity {
        executionCount += 1
        return identity
    }
}

private extension Array where Element == String {
    func containsSubsequence(_ values: [String]) -> Bool {
        guard !values.isEmpty, values.count <= count else { return false }
        return indices.contains { index in
            let end = index + values.count
            return end <= count && Array(self[index..<end]) == values
        }
    }

    subscript(safe index: Int) -> String? { indices.contains(index) ? self[index] : nil }
}
