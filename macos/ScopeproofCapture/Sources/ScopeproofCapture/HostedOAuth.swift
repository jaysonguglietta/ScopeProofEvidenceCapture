import Foundation
import Security
import CryptoKit

enum HostedOAuthFailure: Error, Equatable, LocalizedError, Sendable {
    case invalidTenantIdentifier
    case invalidTenantName
    case invalidTenantDomain
    case invalidIssuer
    case invalidAuthorizationEndpoint
    case invalidTokenEndpoint
    case endpointOriginMismatch
    case invalidClientIdentifier
    case invalidScopes
    case invalidCallback
    case secureRandomFailure(Int32)
    case invalidRandomOutput
    case noPendingTransaction
    case transactionExpired
    case callbackStateMismatch
    case malformedCallback
    case authorizationServerError(String)
    case invalidAuthorizationCode
    case invalidRefreshToken
    case keychainDataInvalid
    case keychainFailure(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidTenantIdentifier: return "The hosted tenant identifier is invalid."
        case .invalidTenantName: return "The hosted tenant display name is invalid."
        case .invalidTenantDomain: return "An allowed tenant email domain is invalid."
        case .invalidIssuer: return "The OAuth issuer must be a canonical public HTTPS URL."
        case .invalidAuthorizationEndpoint: return "The OAuth authorization endpoint must be a canonical public HTTPS URL."
        case .invalidTokenEndpoint: return "The OAuth token endpoint must be a canonical public HTTPS URL."
        case .endpointOriginMismatch: return "The OAuth authorization and token endpoints must use the same HTTPS origin."
        case .invalidClientIdentifier: return "The OAuth public-client identifier is invalid."
        case .invalidScopes: return "The OAuth scopes are invalid or do not include openid."
        case .invalidCallback: return "The OAuth callback does not exactly match the configured app callback."
        case .secureRandomFailure: return "Secure random generation failed."
        case .invalidRandomOutput: return "The secure random provider returned an invalid result."
        case .noPendingTransaction: return "There is no pending hosted sign-in transaction."
        case .transactionExpired: return "The hosted sign-in transaction expired. Start sign-in again."
        case .callbackStateMismatch: return "The hosted sign-in callback state did not match."
        case .malformedCallback: return "The hosted sign-in callback is malformed."
        case .authorizationServerError(let code): return "The authorization server returned \(code)."
        case .invalidAuthorizationCode: return "The authorization server returned an invalid code."
        case .invalidRefreshToken: return "The hosted refresh token is invalid."
        case .keychainDataInvalid: return "The hosted credential in Keychain is invalid."
        case .keychainFailure(let status): return "Keychain returned status \(status)."
        }
    }
}

/// Non-secret customer identity and sign-in discovery metadata. Email domains are
/// a routing hint only; authorization always comes from a validated membership.
struct HostedTenantConfiguration: Equatable, Sendable {
    let tenantID: String
    let displayName: String
    let allowedEmailDomains: [String]

    init(tenantID: String, displayName: String, allowedEmailDomains: [String] = []) throws {
        guard Self.isValidIdentifier(tenantID) else { throw HostedOAuthFailure.invalidTenantIdentifier }

        let cleanName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanName == displayName, (1...100).contains(cleanName.count),
              !cleanName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw HostedOAuthFailure.invalidTenantName
        }

        guard allowedEmailDomains.count <= 25 else { throw HostedOAuthFailure.invalidTenantDomain }
        var seen = Set<String>()
        var cleanDomains: [String] = []
        for domain in allowedEmailDomains {
            let normalized = domain.lowercased()
            guard domain == normalized, Self.isValidDomain(normalized), seen.insert(normalized).inserted else {
                throw HostedOAuthFailure.invalidTenantDomain
            }
            cleanDomains.append(normalized)
        }

        self.tenantID = tenantID
        self.displayName = cleanName
        self.allowedEmailDomains = cleanDomains.sorted()
    }

    /// Suitable for selecting a sign-in configuration, never for granting access.
    func isEmailDomainHintMatch(_ emailAddress: String) -> Bool {
        let parts = emailAddress.lowercased().split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else { return false }
        let domain = String(parts[1])
        guard Self.isValidDomain(domain) else { return false }
        return allowedEmailDomains.contains { domain == $0 || domain.hasSuffix(".\($0)") }
    }

    private static func isValidIdentifier(_ value: String) -> Bool {
        guard value.utf8.count == 36, value.hasPrefix("ten_") else { return false }
        return value.dropFirst(4).utf8.allSatisfy {
            (0x61...0x66).contains($0) || (0x30...0x39).contains($0)
        }
    }

    fileprivate static func isValidDomain(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, value.contains("."),
              value == value.lowercased(), !value.hasPrefix("."), !value.hasSuffix("."),
              !value.contains(".."), !value.contains("*") else { return false }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            guard (1...63).contains(label.utf8.count),
                  let first = label.utf8.first, let last = label.utf8.last,
                  isASCIIAlphaNumeric(first), isASCIIAlphaNumeric(last) else { return false }
            return label.utf8.allSatisfy { isASCIIAlphaNumeric($0) || $0 == 0x2D }
        }
    }

    private static func isASCIILowerOrDigit(_ byte: UInt8) -> Bool {
        (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte)
    }

    fileprivate static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte)
    }
}

struct HostedOAuthConfiguration: Equatable, Sendable {
    let tenant: HostedTenantConfiguration
    let issuerURL: URL
    let authorizationEndpoint: URL
    let tokenEndpoint: URL
    let clientID: String
    let callbackURL: URL
    let scopes: [String]

    fileprivate let callbackTarget: HostedOAuthCallbackTarget

    init(
        tenant: HostedTenantConfiguration,
        issuerURL: URL,
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        clientID: String,
        callbackURL: URL,
        scopes: [String] = ["openid", "profile", "email"]
    ) throws {
        guard HostedOAuthURLValidator.isValidHTTPSURL(issuerURL, endpointRequired: false) else {
            throw HostedOAuthFailure.invalidIssuer
        }
        guard HostedOAuthURLValidator.isValidHTTPSURL(authorizationEndpoint, endpointRequired: true) else {
            throw HostedOAuthFailure.invalidAuthorizationEndpoint
        }
        guard HostedOAuthURLValidator.isValidHTTPSURL(tokenEndpoint, endpointRequired: true) else {
            throw HostedOAuthFailure.invalidTokenEndpoint
        }
        guard HostedOAuthURLValidator.sameOrigin(authorizationEndpoint, tokenEndpoint) else {
            throw HostedOAuthFailure.endpointOriginMismatch
        }
        guard (1...128).contains(clientID.utf8.count), clientID.utf8.allSatisfy({
            HostedOAuthURLValidator.isASCIIAlphaNumeric($0) || [0x2D, 0x2E, 0x5F, 0x7E].contains($0)
        }) else { throw HostedOAuthFailure.invalidClientIdentifier }

        guard (1...16).contains(scopes.count), Set(scopes).count == scopes.count, scopes.contains("openid"),
              scopes.allSatisfy({ scope in
                  (1...64).contains(scope.utf8.count) && scope.utf8.allSatisfy {
                      HostedOAuthURLValidator.isASCIIAlphaNumeric($0) || [0x2D, 0x2E, 0x2F, 0x3A, 0x5F].contains($0)
                  }
              }) else { throw HostedOAuthFailure.invalidScopes }

        let target = try HostedOAuthCallbackTarget(url: callbackURL)
        self.tenant = tenant
        self.issuerURL = issuerURL
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.clientID = clientID
        self.callbackURL = callbackURL
        self.scopes = scopes
        self.callbackTarget = target
    }
}

struct HostedOAuthAuthorizationRequest: Equatable, Sendable {
    let authorizationURL: URL
    let expiresAt: Date
}

struct HostedOAuthAuthorizationGrant: Equatable, Sendable {
    let tenantID: String
    let issuerURL: URL
    let tokenEndpoint: URL
    let clientID: String
    let redirectURI: URL
    let authorizationCode: String
    let codeVerifier: String
    /// Validate this value against the nonce in the cryptographically verified ID token.
    let expectedIDTokenNonce: String

    /// Builds, but does not send, the public-client authorization-code exchange.
    /// A client secret is intentionally neither accepted nor emitted.
    func tokenRequest() -> URLRequest {
        var request = URLRequest(url: tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let fields = [
            ("grant_type", "authorization_code"),
            ("client_id", clientID),
            ("code", authorizationCode),
            ("redirect_uri", redirectURI.absoluteString),
            ("code_verifier", codeVerifier),
        ]
        request.httpBody = Data(fields.map { "\(HostedOAuthFormEncoding.encode($0.0))=\(HostedOAuthFormEncoding.encode($0.1))" }.joined(separator: "&").utf8)
        return request
    }
}

actor HostedOAuthCoordinator {
    typealias RandomBytesProvider = @Sendable (_ count: Int) throws -> Data

    private struct PendingTransaction: Sendable {
        let configuration: HostedOAuthConfiguration
        let state: String
        let codeVerifier: String
        let nonce: String
        let expiresAt: Date
    }

    private let pendingLifetime: TimeInterval
    private let randomBytes: RandomBytesProvider
    private var pending: PendingTransaction?

    init(
        pendingLifetime: TimeInterval = 300,
        randomBytes: @escaping RandomBytesProvider = HostedSecureRandom.bytes(count:)
    ) {
        // OAuth browser transactions should be short-lived. Clamp caller mistakes
        // instead of allowing an indefinitely replayable pending state.
        self.pendingLifetime = pendingLifetime.isFinite ? min(max(pendingLifetime, 1), 600) : 300
        self.randomBytes = randomBytes
    }

    func begin(configuration: HostedOAuthConfiguration, now: Date = Date()) throws -> HostedOAuthAuthorizationRequest {
        let state = try randomURLSafeValue(byteCount: 32)
        let codeVerifier = try randomURLSafeValue(byteCount: 64)
        let nonce = try randomURLSafeValue(byteCount: 32)
        let codeChallenge = try HostedOAuthPKCE.challenge(for: codeVerifier)
        let expiresAt = now.addingTimeInterval(pendingLifetime)

        var components = URLComponents(url: configuration.authorizationEndpoint, resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.callbackURL.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        guard let authorizationURL = components?.url else { throw HostedOAuthFailure.invalidAuthorizationEndpoint }

        // A new explicit sign-in replaces an older unfinished attempt.
        pending = PendingTransaction(
            configuration: configuration, state: state, codeVerifier: codeVerifier,
            nonce: nonce, expiresAt: expiresAt
        )
        return HostedOAuthAuthorizationRequest(authorizationURL: authorizationURL, expiresAt: expiresAt)
    }

    func cancel() {
        pending = nil
    }

    func consume(callbackURL: URL, now: Date = Date()) throws -> HostedOAuthAuthorizationGrant {
        guard let transaction = pending else { throw HostedOAuthFailure.noPendingTransaction }
        guard now <= transaction.expiresAt else {
            pending = nil
            throw HostedOAuthFailure.transactionExpired
        }
        guard transaction.configuration.callbackTarget.matches(callbackURL) else {
            throw HostedOAuthFailure.invalidCallback
        }

        let response = try HostedOAuthCallbackResponse(url: callbackURL)
        guard HostedOAuthConstantTime.equals(response.state, transaction.state) else {
            throw HostedOAuthFailure.callbackStateMismatch
        }

        // A state-authenticated callback is consumed once, including an OAuth error.
        pending = nil

        if let issuer = response.issuer, issuer != transaction.configuration.issuerURL.absoluteString {
            throw HostedOAuthFailure.malformedCallback
        }
        if let error = response.error {
            throw HostedOAuthFailure.authorizationServerError(error)
        }
        guard let code = response.code, HostedOAuthCallbackResponse.isValidAuthorizationCode(code) else {
            throw HostedOAuthFailure.invalidAuthorizationCode
        }

        return HostedOAuthAuthorizationGrant(
            tenantID: transaction.configuration.tenant.tenantID,
            issuerURL: transaction.configuration.issuerURL,
            tokenEndpoint: transaction.configuration.tokenEndpoint,
            clientID: transaction.configuration.clientID,
            redirectURI: transaction.configuration.callbackURL,
            authorizationCode: code,
            codeVerifier: transaction.codeVerifier,
            expectedIDTokenNonce: transaction.nonce
        )
    }

    private func randomURLSafeValue(byteCount: Int) throws -> String {
        let data = try randomBytes(byteCount)
        guard data.count == byteCount else { throw HostedOAuthFailure.invalidRandomOutput }
        return HostedOAuthBase64URL.encode(data)
    }
}

enum HostedOAuthPKCE {
    static func challenge(for verifier: String) throws -> String {
        guard (43...128).contains(verifier.utf8.count), verifier.utf8.allSatisfy({
            HostedOAuthURLValidator.isASCIIAlphaNumeric($0) || [0x2D, 0x2E, 0x5F, 0x7E].contains($0)
        }) else { throw HostedOAuthFailure.invalidRandomOutput }
        return HostedOAuthBase64URL.encode(HostedSHA256.digest(Data(verifier.utf8)))
    }
}

private struct HostedOAuthCallbackTarget: Equatable, Sendable {
    let scheme: String
    let host: String
    let percentEncodedPath: String

    init(url: URL) throws {
        guard url.absoluteString.utf8.count <= 512, !url.absoluteString.contains("\\"),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil, components.port == nil,
              components.query == nil, components.fragment == nil,
              let scheme = components.scheme?.lowercased(), HostedOAuthURLValidator.isValidCallbackScheme(scheme),
              let host = components.host?.lowercased(), HostedOAuthURLValidator.isValidCallbackHost(host),
              !components.percentEncodedPath.isEmpty, components.percentEncodedPath != "/",
              HostedOAuthURLValidator.isCanonicalPath(components.percentEncodedPath) else {
            throw HostedOAuthFailure.invalidCallback
        }
        self.scheme = scheme
        self.host = host
        self.percentEncodedPath = components.percentEncodedPath
    }

    func matches(_ candidate: URL) -> Bool {
        guard candidate.absoluteString.utf8.count <= 12_000, !candidate.absoluteString.contains("\\"),
              let components = URLComponents(url: candidate, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil, components.port == nil,
              components.fragment == nil,
              components.scheme?.lowercased() == scheme,
              components.host?.lowercased() == host,
              components.percentEncodedPath == percentEncodedPath else { return false }
        return true
    }
}

private struct HostedOAuthCallbackResponse {
    let state: String
    let code: String?
    let error: String?
    let issuer: String?

    init(url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let query = components.percentEncodedQuery, !query.isEmpty, query.utf8.count <= 8_192 else {
            throw HostedOAuthFailure.malformedCallback
        }
        let allowed = Set(["code", "state", "error", "error_description", "error_uri", "iss"])
        var values: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard allowed.contains(item.name), values[item.name] == nil,
                  let value = item.value, value.utf8.count <= 2_048,
                  !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw HostedOAuthFailure.malformedCallback
            }
            values[item.name] = value
        }
        guard let state = values["state"], !state.isEmpty,
              (values["code"] != nil) != (values["error"] != nil) else {
            throw HostedOAuthFailure.malformedCallback
        }
        if values["error"] == nil, values["error_description"] != nil || values["error_uri"] != nil {
            throw HostedOAuthFailure.malformedCallback
        }
        if let error = values["error"], !Self.isValidErrorCode(error) {
            throw HostedOAuthFailure.malformedCallback
        }
        self.state = state
        self.code = values["code"]
        self.error = values["error"]
        self.issuer = values["iss"]
    }

    static func isValidAuthorizationCode(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 &&
            !value.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains($0) })
    }

    private static func isValidErrorCode(_ value: String) -> Bool {
        (1...64).contains(value.utf8.count) && value.utf8.allSatisfy {
            HostedOAuthURLValidator.isASCIIAlphaNumeric($0) || $0 == 0x2D || $0 == 0x5F
        }
    }
}

private enum HostedOAuthURLValidator {
    static func isValidHTTPSURL(_ url: URL, endpointRequired: Bool) -> Bool {
        guard url.absoluteString.utf8.count <= 2_048, !url.absoluteString.contains("\\"),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https", components.user == nil, components.password == nil,
              components.port == nil, components.query == nil, components.fragment == nil,
              let host = components.host?.lowercased(), HostedTenantConfiguration.isValidDomain(host),
              host != "localhost", !host.hasSuffix(".localhost"), !host.hasSuffix(".local"),
              !isIPAddress(host), isCanonicalPath(components.percentEncodedPath) else { return false }
        if endpointRequired && (components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/") { return false }
        if !endpointRequired && components.percentEncodedPath.count > 1 && components.percentEncodedPath.hasSuffix("/") { return false }
        return true
    }

    static func sameOrigin(_ lhs: URL, _ rhs: URL) -> Bool {
        guard let left = URLComponents(url: lhs, resolvingAgainstBaseURL: false),
              let right = URLComponents(url: rhs, resolvingAgainstBaseURL: false) else { return false }
        return left.scheme?.lowercased() == right.scheme?.lowercased()
            && left.host?.lowercased() == right.host?.lowercased()
            && left.port == right.port
    }

    static func isCanonicalPath(_ percentEncodedPath: String) -> Bool {
        guard !percentEncodedPath.contains("%"), !percentEncodedPath.contains("//") else { return false }
        let segments = percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false)
        return !segments.contains(".") && !segments.contains("..")
    }

    static func isValidCallbackScheme(_ value: String) -> Bool {
        guard (3...64).contains(value.utf8.count), !["http", "https", "file", "javascript", "data"].contains(value),
              let first = value.utf8.first, (0x61...0x7A).contains(first) else { return false }
        return value.utf8.allSatisfy { isASCIIAlphaNumeric($0) || [0x2B, 0x2D, 0x2E].contains($0) }
    }

    static func isValidCallbackHost(_ value: String) -> Bool {
        guard (1...63).contains(value.utf8.count),
              let first = value.utf8.first, let last = value.utf8.last,
              isASCIIAlphaNumeric(first), isASCIIAlphaNumeric(last) else { return false }
        return value.utf8.allSatisfy { isASCIIAlphaNumeric($0) || $0 == 0x2D }
    }

    static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x61...0x7A).contains(byte) || (0x41...0x5A).contains(byte) || (0x30...0x39).contains(byte)
    }

    private static func isIPAddress(_ host: String) -> Bool {
        if host.contains(":") { return true }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy(\.isNumber) && Int(part).map { (0...255).contains($0) } == true
        }
    }
}

private enum HostedSecureRandom {
    static func bytes(count: Int) throws -> Data {
        guard count > 0 else { throw HostedOAuthFailure.invalidRandomOutput }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else { return Int32(errSecParam) }
            return Int32(SecRandomCopyBytes(kSecRandomDefault, count, baseAddress))
        }
        guard status == errSecSuccess else { throw HostedOAuthFailure.secureRandomFailure(status) }
        return data
    }
}

private enum HostedOAuthBase64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private enum HostedOAuthConstantTime {
    static func equals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

private enum HostedOAuthFormEncoding {
    static func encode(_ value: String) -> String {
        var encoded = ""
        for byte in value.utf8 {
            if HostedOAuthURLValidator.isASCIIAlphaNumeric(byte) || [0x2D, 0x2E, 0x5F, 0x7E].contains(byte) {
                encoded.append(Character(UnicodeScalar(byte)))
            } else {
                encoded += String(format: "%%%02X", byte)
            }
        }
        return encoded
    }
}

/// Small CryptoKit wrapper retained to keep PKCE call sites explicit and
/// independently testable without maintaining a custom hash implementation.
enum HostedSHA256 {
    static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hexDigest(_ data: Data) -> String {
        digest(data).map { String(format: "%02x", $0) }.joined()
    }
}
