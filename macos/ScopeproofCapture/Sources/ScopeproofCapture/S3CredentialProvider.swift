import Darwin
import Foundation

protocol S3CallerIdentityVerifying: Sendable {
    func callerIdentity(settings: S3StorageSettings, credentials: S3Credentials) async throws -> S3CallerIdentity
}

protocol S3AWSCLIExecuting: Sendable {
    func isAvailable() -> Bool
    func execute(arguments: [String]) async throws -> Data
}

enum S3AWSCLIExecutionFailure: Error, Equatable, Sendable {
    case unavailable
    case unsafeExecutable
    case invalidArguments
    case loginRequired
    case rejected
    case outputTooLarge
    case timedOut
}

enum S3AWSCLIPathItemKind: Equatable, Sendable {
    case directory
    case regularFile
    case symbolicLink
    case other
}

struct S3AWSCLIPathMetadata: Equatable, Sendable {
    let ownerID: UInt32
    let permissions: UInt16
    let kind: S3AWSCLIPathItemKind
}

enum S3AWSCLIExecutableLocator {
    static let candidatePaths = [
        "/usr/local/bin/aws",
        "/usr/local/aws-cli/v2/current/bin/aws",
        "/opt/homebrew/bin/aws",
        "/Applications/AWSCLIV2.app/Contents/MacOS/aws",
    ]

    static func locate(fileManager: FileManager = .default) throws -> URL {
        var foundUnsafeCandidate = false
        for path in candidatePaths {
            guard fileManager.fileExists(atPath: path) else { continue }
            let candidate = URL(fileURLWithPath: path, isDirectory: false).standardizedFileURL
            let resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
            guard isTrustedExecutable(candidatePath: candidate.path, resolvedPath: resolved.path) else {
                foundUnsafeCandidate = true
                continue
            }
            guard fileManager.isExecutableFile(atPath: resolved.path) else {
                foundUnsafeCandidate = true
                continue
            }
            return resolved
        }
        throw foundUnsafeCandidate ? S3AWSCLIExecutionFailure.unsafeExecutable : S3AWSCLIExecutionFailure.unavailable
    }

    static func isTrustedResolvedPath(_ path: String) -> Bool {
        let clean = URL(fileURLWithPath: path, isDirectory: false).standardizedFileURL.path
        if clean == "/Applications/AWSCLIV2.app/Contents/MacOS/aws" { return true }

        let pathComponents = clean.split(separator: "/").map(String.init)
        if pathComponents.count == 7,
           pathComponents[0...3] == ["usr", "local", "aws-cli", "v2"],
           isVersionComponent(pathComponents[4]),
           pathComponents[5] == "dist", pathComponents[6] == "aws" {
            return true
        }
        if pathComponents.count == 8,
           (pathComponents[0...3] == ["opt", "homebrew", "Cellar", "awscli"]
            || pathComponents[0...3] == ["usr", "local", "Cellar", "awscli"]),
           isVersionComponent(pathComponents[4]),
           pathComponents[5] == "libexec", pathComponents[6] == "bin",
           pathComponents[7] == "aws" {
            return true
        }
        return false
    }

    static func isTrustedExecutable(
        candidatePath: String,
        resolvedPath: String,
        metadata: (String) -> S3AWSCLIPathMetadata? = pathMetadata(atPath:)
    ) -> Bool {
        let candidate = URL(fileURLWithPath: candidatePath, isDirectory: false).standardizedFileURL.path
        let resolved = URL(fileURLWithPath: resolvedPath, isDirectory: false).standardizedFileURL.path
        guard candidatePaths.contains(candidate), isTrustedResolvedPath(resolved) else { return false }

        // Symlink permission bits are not authorization controls on macOS. Their owner and every
        // containing directory are still checked, and the fully resolved target is validated as a
        // separate root-owned, non-writable chain. This prevents an unprivileged path replacement.
        guard pathChainIsTrusted(candidate, allowSymbolicLinks: true, metadata: metadata),
              pathChainIsTrusted(resolved, allowSymbolicLinks: false, metadata: metadata),
              let executable = metadata(resolved), executable.kind == .regularFile,
              executable.permissions & 0o111 != 0 else { return false }
        return true
    }

    private static func pathChainIsTrusted(
        _ path: String,
        allowSymbolicLinks: Bool,
        metadata: (String) -> S3AWSCLIPathMetadata?
    ) -> Bool {
        let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        guard components.first == "/", !components.dropFirst().isEmpty else { return false }

        var currentPath = "/"
        for (index, component) in components.dropFirst().enumerated() {
            currentPath = (currentPath as NSString).appendingPathComponent(component)
            guard let item = metadata(currentPath), item.ownerID == 0 else { return false }
            let isLast = index == components.count - 2
            switch item.kind {
            case .symbolicLink:
                guard allowSymbolicLinks else { return false }
                // A symlink's mode is ignored by Darwin; its containing directory controls
                // replacement. Root ownership is enforced here and the target chain below.
            case .directory:
                guard !isLast, item.permissions & 0o022 == 0 else { return false }
            case .regularFile:
                guard isLast, item.permissions & 0o022 == 0 else { return false }
            case .other:
                return false
            }
        }

        guard let root = metadata("/"), root.ownerID == 0, root.kind == .directory,
              root.permissions & 0o022 == 0 else { return false }
        return true
    }

    private static func pathMetadata(atPath path: String) -> S3AWSCLIPathMetadata? {
        var attributes = stat()
        guard lstat(path, &attributes) == 0 else { return nil }
        let itemKind: S3AWSCLIPathItemKind
        switch attributes.st_mode & mode_t(S_IFMT) {
        case mode_t(S_IFDIR): itemKind = .directory
        case mode_t(S_IFREG): itemKind = .regularFile
        case mode_t(S_IFLNK): itemKind = .symbolicLink
        default: itemKind = .other
        }
        return S3AWSCLIPathMetadata(
            ownerID: attributes.st_uid,
            permissions: UInt16(attributes.st_mode & 0o7777),
            kind: itemKind
        )
    }

    private static func isVersionComponent(_ component: String) -> Bool {
        let pieces = component.split(separator: ".", omittingEmptySubsequences: false)
        return pieces.count == 3 && pieces.first == "2" && pieces.allSatisfy { piece in
            !piece.isEmpty && piece.utf8.allSatisfy { (48...57).contains($0) }
        }
    }
}

struct SystemS3AWSCLIExecutor: S3AWSCLIExecuting {
    private static let defaultMaximumOutputBytes = 128 * 1024
    private let executableOverride: URL?
    private let commandTimeoutSeconds: TimeInterval
    private let loginTimeoutSeconds: TimeInterval
    private let maximumOutputBytes: Int

    init() {
        executableOverride = nil
        commandTimeoutSeconds = 45
        loginTimeoutSeconds = 10 * 60
        maximumOutputBytes = Self.defaultMaximumOutputBytes
    }

#if DEBUG
    init(testExecutableURL: URL, commandTimeoutSeconds: TimeInterval, maximumOutputBytes: Int = 128 * 1024) {
        executableOverride = testExecutableURL
        self.commandTimeoutSeconds = commandTimeoutSeconds
        loginTimeoutSeconds = commandTimeoutSeconds
        self.maximumOutputBytes = maximumOutputBytes
    }
#endif

    func isAvailable() -> Bool { executableOverride != nil || (try? S3AWSCLIExecutableLocator.locate()) != nil }

    func execute(arguments: [String]) async throws -> Data {
        let executable: URL
        do { executable = try executableOverride ?? S3AWSCLIExecutableLocator.locate() }
        catch let error as S3AWSCLIExecutionFailure { throw error }
        catch { throw S3AWSCLIExecutionFailure.unavailable }

        guard (1...32).contains(arguments.count), arguments.allSatisfy({ argument in
            (1...2_048).contains(argument.utf8.count)
                && !argument.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        }) else { throw S3AWSCLIExecutionFailure.invalidArguments }

        let process = Process()
        return try await withTaskCancellationHandler(operation: {
          do {
            let result = try await Task.detached(priority: .userInitiated) {
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.executableURL = executable
            process.arguments = arguments
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            process.environment = Self.minimumEnvironment()

            do { try process.run() }
            catch { throw S3AWSCLIExecutionFailure.rejected }
            let outputReader = Task.detached(priority: .userInitiated) {
                try Self.readBounded(outputPipe.fileHandleForReading, process: process, maximumBytes: maximumOutputBytes)
            }
            let errorReader = Task.detached(priority: .userInitiated) {
                try Self.readBounded(errorPipe.fileHandleForReading, process: process, maximumBytes: maximumOutputBytes)
            }
            let isInteractiveLogin = arguments.starts(with: ["sso", "login"])
            let timeout = isInteractiveLogin ? loginTimeoutSeconds : commandTimeoutSeconds
            let deadline = Date().addingTimeInterval(timeout)
            var pendingFailure: Error?
            while process.isRunning {
                if Task.isCancelled {
                    pendingFailure = CancellationError()
                    Self.stop(process)
                    break
                }
                if Date() >= deadline {
                    pendingFailure = S3AWSCLIExecutionFailure.timedOut
                    Self.stop(process)
                    break
                }
                do { try await Task.sleep(nanoseconds: 50_000_000) }
                catch {
                    pendingFailure = CancellationError()
                    Self.stop(process)
                    break
                }
            }
            if Task.isCancelled && pendingFailure == nil { pendingFailure = CancellationError() }
            process.waitUntilExit()

            var output = Data()
            var errorOutput = Data()
            do { output = try await outputReader.value }
            catch { pendingFailure = pendingFailure ?? error }
            do { errorOutput = try await errorReader.value }
            catch { pendingFailure = pendingFailure ?? error }
            defer {
                output.resetBytes(in: output.indices)
                errorOutput.resetBytes(in: errorOutput.indices)
            }
            if let pendingFailure { throw pendingFailure }
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                let diagnostic = String(decoding: errorOutput.prefix(32 * 1024), as: UTF8.self).lowercased()
                if diagnostic.contains("aws sso login") || diagnostic.contains("sso session")
                    || diagnostic.contains("sso token") || diagnostic.contains("token has expired") {
                    throw S3AWSCLIExecutionFailure.loginRequired
                }
                throw S3AWSCLIExecutionFailure.rejected
            }
              return Data(output)
            }.value
            try Task.checkCancellation()
            return result
          } catch {
            if Task.isCancelled { throw CancellationError() }
            throw error
          }
        }, onCancel: {
            Self.stop(process)
        })
    }

    private static func minimumEnvironment() -> [String: String] {
        [
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "TMPDIR": FileManager.default.temporaryDirectory.path,
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
            "AWS_PAGER": "",
            "AWS_CLI_AUTO_PROMPT": "off",
            "AWS_MAX_ATTEMPTS": "2",
        ]
    }

    private static func readBounded(_ handle: FileHandle, process: Process, maximumBytes: Int) throws -> Data {
        var result = Data()
        do {
            while true {
                let remaining = maximumBytes + 1 - result.count
                guard remaining > 0 else { throw S3AWSCLIExecutionFailure.outputTooLarge }
                let chunk = try handle.read(upToCount: min(8_192, remaining)) ?? Data()
                if chunk.isEmpty { break }
                result.append(chunk)
                if result.count > maximumBytes { throw S3AWSCLIExecutionFailure.outputTooLarge }
            }
            return result
        } catch {
            result.resetBytes(in: result.indices)
            stop(process)
            throw error
        }
    }

    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        for _ in 0..<20 where process.isRunning { Thread.sleep(forTimeInterval: 0.025) }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
    }
}

struct S3AssumedRoleCredentials: Equatable, Sendable {
    let credentials: S3Credentials
    let principalARN: String
}

enum S3AWSCredentialOutputParser {
    private struct ProcessCredentialOutput: Decodable {
        let version: Int
        let accessKeyID: String
        let secretAccessKey: String
        let sessionToken: String
        let expiration: String

        private enum CodingKeys: String, CodingKey {
            case version = "Version"
            case accessKeyID = "AccessKeyId"
            case secretAccessKey = "SecretAccessKey"
            case sessionToken = "SessionToken"
            case expiration = "Expiration"
        }
    }

    private struct AssumeRoleOutput: Decodable {
        struct CredentialOutput: Decodable {
            let accessKeyID: String
            let secretAccessKey: String
            let sessionToken: String
            let expiration: String

            private enum CodingKeys: String, CodingKey {
                case accessKeyID = "AccessKeyId"
                case secretAccessKey = "SecretAccessKey"
                case sessionToken = "SessionToken"
                case expiration = "Expiration"
            }
        }
        struct AssumedRoleUserOutput: Decodable {
            let arn: String
            private enum CodingKeys: String, CodingKey { case arn = "Arn" }
        }
        let credentials: CredentialOutput
        let assumedRoleUser: AssumedRoleUserOutput

        private enum CodingKeys: String, CodingKey {
            case credentials = "Credentials"
            case assumedRoleUser = "AssumedRoleUser"
        }
    }

    static func parseProcessCredentials(_ data: Data, now: Date = Date()) throws -> S3Credentials {
        guard (2...64 * 1024).contains(data.count),
              let envelope = try? JSONDecoder().decode(ProcessCredentialOutput.self, from: data),
              envelope.version == 1 else { throw S3StorageFailure.awsCLIRejected }
        return try temporaryCredentials(
            accessKeyID: envelope.accessKeyID, secretAccessKey: envelope.secretAccessKey,
            sessionToken: envelope.sessionToken, expiration: envelope.expiration, now: now
        )
    }

    static func parseAssumeRoleCredentials(
        _ data: Data, expectedRoleARN: String, expectedSessionName: String, now: Date = Date()
    ) throws -> S3AssumedRoleCredentials {
        guard (2...64 * 1024).contains(data.count),
              let envelope = try? JSONDecoder().decode(AssumeRoleOutput.self, from: data),
              S3PrincipalIdentity.matchesAssumedRole(
                principalARN: envelope.assumedRoleUser.arn,
                roleARN: expectedRoleARN,
                sessionName: expectedSessionName
              ) else { throw S3StorageFailure.awsCLIRejected }
        let credentials = try temporaryCredentials(
            accessKeyID: envelope.credentials.accessKeyID,
            secretAccessKey: envelope.credentials.secretAccessKey,
            sessionToken: envelope.credentials.sessionToken,
            expiration: envelope.credentials.expiration,
            now: now
        )
        return S3AssumedRoleCredentials(credentials: credentials, principalARN: envelope.assumedRoleUser.arn)
    }

    private static func temporaryCredentials(
        accessKeyID: String, secretAccessKey: String, sessionToken: String, expiration: String, now: Date
    ) throws -> S3Credentials {
        guard accessKeyID.hasPrefix("ASIA") else { throw S3StorageFailure.temporaryCredentialsRequired }
        guard let expiresAt = parseDate(expiration), expiresAt > now.addingTimeInterval(300),
              expiresAt <= now.addingTimeInterval(36 * 60 * 60) else {
            throw S3StorageFailure.expiredCredentials
        }
        let credentials = try S3Credentials.validated(
            accessKeyID: accessKeyID, secretAccessKey: secretAccessKey,
            sessionToken: sessionToken, expiresAt: expiresAt
        )
        guard credentials.isTemporary else { throw S3StorageFailure.temporaryCredentialsRequired }
        return credentials
    }

    private static func parseDate(_ value: String) -> Date? {
        let standard = ISO8601DateFormatter()
        if let date = standard.date(from: value) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value)
    }
}

enum S3PrincipalIdentity {
    static func stableScope(_ arn: String) -> String? {
        let components = arn.split(separator: ":", omittingEmptySubsequences: false)
        guard components.count == 6, components[0] == "arn",
              ["aws", "aws-us-gov"].contains(String(components[1])),
              String(components[4]).range(of: #"^\d{12}$"#, options: .regularExpression) != nil else { return nil }
        let service = String(components[2])
        let resource = String(components[5])
        if service == "sts", resource.hasPrefix("assumed-role/") {
            let parts = resource.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count >= 3, parts.dropFirst().dropLast().allSatisfy({ !$0.isEmpty }) else { return nil }
            let role = parts.dropFirst().dropLast().joined(separator: "/")
            return "arn:\(components[1]):sts::\(components[4]):assumed-role/\(role)"
        }
        guard service == "iam", resource.range(
            of: #"^(?:user|role)\/[A-Za-z0-9+=,.@_\/-]{1,512}$|^root$"#,
            options: .regularExpression
        ) != nil else { return nil }
        return arn
    }

    static func matchesAssumedRole(principalARN: String, roleARN: String, sessionName: String) -> Bool {
        let role = roleARN.split(separator: ":", omittingEmptySubsequences: false)
        let principal = principalARN.split(separator: ":", omittingEmptySubsequences: false)
        guard role.count == 6, principal.count == 6,
              role[0] == "arn", principal[0] == "arn", role[1] == principal[1],
              role[2] == "iam", principal[2] == "sts", role[4] == principal[4],
              role[5].hasPrefix("role/"), principal[5].hasPrefix("assumed-role/") else { return false }
        let roleName = role[5].split(separator: "/").last.map(String.init) ?? ""
        let principalParts = principal[5].split(separator: "/", omittingEmptySubsequences: false)
        guard principalParts.count == 3 else { return false }
        return principalParts[1] == Substring(roleName) && principalParts[2] == Substring(sessionName)
    }
}

extension S3VerifiedDestination {
    func accepts(identity: S3CallerIdentity, settings: S3StorageSettings) -> Bool {
        guard accountID == identity.accountID,
              let verifiedScope = S3PrincipalIdentity.stableScope(principalARN),
              let refreshedScope = S3PrincipalIdentity.stableScope(identity.principalARN),
              verifiedScope == refreshedScope else { return false }
        if settings.authentication.method == .identityCenterAssumeRole {
            let roleName = settings.authentication.roleARN.split(separator: "/").last.map(String.init) ?? ""
            guard refreshedScope.hasSuffix("assumed-role/\(roleName)") else { return false }
        }
        return true
    }
}

actor S3CredentialProvider {
    private struct CachedCredential: Sendable {
        let settingsDigest: String
        let credentials: S3Credentials
        var identity: S3CallerIdentity?
    }

    private let cli: any S3AWSCLIExecuting
    private let identityVerifier: any S3CallerIdentityVerifying
    private let manualCredentialLoader: @Sendable () -> S3Credentials?
    private let clock: @Sendable () -> Date
    private var cached: CachedCredential?

    init(
        cli: any S3AWSCLIExecuting = SystemS3AWSCLIExecutor(),
        identityVerifier: any S3CallerIdentityVerifying = S3StorageService(),
        manualCredentialLoader: @escaping @Sendable () -> S3Credentials? = { KeychainStore.readS3Credentials() },
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.cli = cli
        self.identityVerifier = identityVerifier
        self.manualCredentialLoader = manualCredentialLoader
        self.clock = clock
    }

    nonisolated static func hasConfiguredSource(_ settings: S3StorageSettings) -> Bool {
        switch settings.authentication.method {
        case .manualCredentials:
            return KeychainStore.readS3Credentials()?.tenantBinding == settings.tenantBinding
        case .identityCenterProfile, .identityCenterAssumeRole: return SystemS3AWSCLIExecutor().isAvailable()
        }
    }

    func invalidate() { cached = nil }

    func signIn(profileName: String) async throws {
        guard S3AuthenticationConfiguration.isValidProfileName(profileName) else {
            throw S3StorageFailure.invalidIdentityCenterProfile
        }
        do {
            try await validateIdentityCenterProfile(profileName)
            var output = try await cli.execute(arguments: ["sso", "login", "--profile", profileName, "--no-cli-pager"])
            output.resetBytes(in: output.indices)
            cached = nil
        } catch S3AWSCLIExecutionFailure.unavailable { throw S3StorageFailure.awsCLINotAvailable }
        catch S3AWSCLIExecutionFailure.unsafeExecutable { throw S3StorageFailure.awsCLIUnsafeExecutable }
        catch S3AWSCLIExecutionFailure.timedOut { throw S3StorageFailure.awsCLITimedOut }
        catch let error as S3StorageFailure { throw error }
        catch let error as CancellationError { throw error }
        catch { throw S3StorageFailure.identityCenterLoginFailed }
    }

    func credentials(
        for settings: S3StorageSettings, binding: S3VerifiedDestination?
    ) async throws -> S3Credentials {
        var entry: CachedCredential
        switch settings.authentication.method {
        case .manualCredentials:
            guard let loaded = manualCredentialLoader() else { throw S3StorageFailure.invalidCredentials }
            guard loaded.tenantBinding == settings.tenantBinding else {
                throw S3StorageFailure.credentialIdentityMismatch
            }
            let validated = try validatedCredentials(loaded, settings: settings)
            if let cached, cached.settingsDigest == settings.securityBindingDigest,
               cached.credentials == validated, !cached.credentials.isExpired {
                entry = cached
            } else {
                entry = CachedCredential(settingsDigest: settings.securityBindingDigest, credentials: validated, identity: nil)
            }
        case .identityCenterProfile, .identityCenterAssumeRole:
            if let cached, cached.settingsDigest == settings.securityBindingDigest, !cached.credentials.isExpired {
                entry = cached
            } else {
                entry = CachedCredential(
                    settingsDigest: settings.securityBindingDigest,
                    credentials: try await cliCredentials(for: settings), identity: nil
                )
            }
        }

        if let binding {
            guard binding.matches(settings, now: clock()) else { throw S3StorageFailure.destinationBindingMismatch }
            if entry.identity == nil {
                entry.identity = try await identityVerifier.callerIdentity(
                    settings: settings, credentials: entry.credentials
                )
            }
            guard let identity = entry.identity, binding.accepts(identity: identity, settings: settings) else {
                cached = nil
                throw S3StorageFailure.credentialIdentityMismatch
            }
        }
        cached = entry
        return entry.credentials
    }

    private func cliCredentials(for settings: S3StorageSettings) async throws -> S3Credentials {
        let authentication = settings.authentication
        do {
            if authentication.method.usesAWSCLI {
                try await validateIdentityCenterProfile(authentication.profileName)
            }
            switch authentication.method {
            case .manualCredentials:
                throw S3StorageFailure.invalidCredentials
            case .identityCenterProfile:
                var data = try await cli.execute(arguments: [
                    "configure", "export-credentials", "--profile", authentication.profileName,
                    "--format", "process",
                ])
                defer { data.resetBytes(in: data.indices) }
                return try S3AWSCredentialOutputParser.parseProcessCredentials(data, now: clock())
            case .identityCenterAssumeRole:
                // Prove the named source profile itself exports an expiring
                // session before asking the CLI to assume the destination role.
                // A profile backed directly by an AKIA long-lived key is rejected
                // by the process-credential parser and never becomes a production
                // authentication source.
                var sourceData = try await cli.execute(arguments: [
                    "configure", "export-credentials", "--profile", authentication.profileName,
                    "--format", "process",
                ])
                defer { sourceData.resetBytes(in: sourceData.indices) }
                _ = try S3AWSCredentialOutputParser.parseProcessCredentials(sourceData, now: clock())
                let sessionName = "scopeproof-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(32))"
                let stsLabel = settings.useFIPSEndpoint ? "sts-fips" : "sts"
                let stsEndpoint = "https://\(stsLabel).\(settings.region).amazonaws.com/"
                var arguments = [
                    "sts", "assume-role", "--profile", authentication.profileName,
                    "--region", settings.region, "--role-arn", authentication.roleARN,
                    "--role-session-name", sessionName, "--duration-seconds", "3600",
                    "--endpoint-url", stsEndpoint, "--output", "json", "--no-cli-pager",
                ]
                if !authentication.externalID.isEmpty {
                    arguments.append(contentsOf: ["--external-id", authentication.externalID])
                }
                var data = try await cli.execute(arguments: arguments)
                defer { data.resetBytes(in: data.indices) }
                return try S3AWSCredentialOutputParser.parseAssumeRoleCredentials(
                    data, expectedRoleARN: authentication.roleARN,
                    expectedSessionName: sessionName, now: clock()
                ).credentials
            }
        } catch S3AWSCLIExecutionFailure.unavailable { throw S3StorageFailure.awsCLINotAvailable }
        catch S3AWSCLIExecutionFailure.unsafeExecutable { throw S3StorageFailure.awsCLIUnsafeExecutable }
        catch S3AWSCLIExecutionFailure.timedOut { throw S3StorageFailure.awsCLITimedOut }
        catch S3AWSCLIExecutionFailure.loginRequired {
            throw S3StorageFailure.identityCenterLoginRequired(authentication.profileName)
        } catch let error as S3StorageFailure { throw error }
        catch let error as CancellationError { throw error }
        catch { throw S3StorageFailure.awsCLIRejected }
    }

    private func validateIdentityCenterProfile(_ profileName: String) async throws {
        guard S3AuthenticationConfiguration.isValidProfileName(profileName) else {
            throw S3StorageFailure.invalidIdentityCenterProfile
        }
        for forbidden in [
            "aws_access_key_id", "credential_process", "credential_source",
            "role_arn", "source_profile", "web_identity_token_file",
        ] {
            if try await cliConfigurationValue(forbidden, profileName: profileName) != nil {
                throw S3StorageFailure.invalidIdentityCenterProfile
            }
        }

        let session = try await cliConfigurationValue("sso_session", profileName: profileName)
        let startURL = try await cliConfigurationValue("sso_start_url", profileName: profileName)
        let ssoRegion = try await cliConfigurationValue("sso_region", profileName: profileName)
        let accountID = try await cliConfigurationValue("sso_account_id", profileName: profileName)
        let roleName = try await cliConfigurationValue("sso_role_name", profileName: profileName)
        let modern = session.map(S3AuthenticationConfiguration.isValidProfileName) == true
        let legacy = startURL.map(Self.isValidIdentityCenterStartURL) == true
            && ssoRegion?.range(of: #"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"#, options: .regularExpression) != nil
        guard modern || legacy,
              accountID?.range(of: #"^\d{12}$"#, options: .regularExpression) != nil,
              let roleName, (1...64).contains(roleName.utf8.count),
              roleName.range(of: #"^[A-Za-z0-9+=,.@_-]+$"#, options: .regularExpression) != nil else {
            throw S3StorageFailure.invalidIdentityCenterProfile
        }
    }

    private func cliConfigurationValue(_ name: String, profileName: String) async throws -> String? {
        do {
            var data = try await cli.execute(arguments: ["configure", "get", name, "--profile", profileName])
            defer { data.resetBytes(in: data.indices) }
            guard data.count <= 4_096 else { throw S3StorageFailure.invalidIdentityCenterProfile }
            let value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                return nil
            }
            return value
        } catch S3AWSCLIExecutionFailure.rejected { return nil }
        catch S3AWSCLIExecutionFailure.unavailable { throw S3StorageFailure.awsCLINotAvailable }
        catch S3AWSCLIExecutionFailure.unsafeExecutable { throw S3StorageFailure.awsCLIUnsafeExecutable }
        catch let error as S3StorageFailure { throw error }
        catch { throw S3StorageFailure.invalidIdentityCenterProfile }
    }

    private nonisolated static func isValidIdentityCenterStartURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value), components.scheme == "https",
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let host = components.host?.lowercased(), host.hasSuffix(".awsapps.com"),
              components.path == "/start" else { return false }
        return true
    }

    private func validatedCredentials(_ credentials: S3Credentials, settings: S3StorageSettings) throws -> S3Credentials {
        let clean = try S3Credentials.validated(
            accessKeyID: credentials.accessKeyID, secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken, expiresAt: credentials.expiresAt,
            tenantID: settings.tenantID, workspaceID: settings.workspaceID
        )
        if clean.isExpired { throw S3StorageFailure.expiredCredentials }
        if settings.securityProfile == .production && (!clean.isTemporary || clean.expiresAt == nil) {
            throw S3StorageFailure.temporaryCredentialsRequired
        }
        return clean
    }
}
