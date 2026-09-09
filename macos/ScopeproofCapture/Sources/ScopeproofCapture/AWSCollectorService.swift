import CryptoKit
import Foundation

enum AWSCollectorFailure: LocalizedError {
    case configuration, invalidResponse, signInRequired, enrollmentRejected, invalidSelection, rejected(Int)
    var errorDescription: String? {
        switch self {
        case .configuration: return "This release has no valid approved AWS customer sign-in configuration. Ask your administrator for the tenant-configured release; arbitrary API or OAuth destinations are not accepted."
        case .invalidResponse: return "The AWS customer response did not match this tenant or the expected contract. Nothing was selected."
        case .signInRequired: return "Sign in again: the session or token-bound device challenge is missing or expired."
        case .enrollmentRejected: return "This Mac's device key could not be confirmed. Ask a customer administrator to inspect device status; revoked keys cannot be reactivated here."
        case .invalidSelection: return "Choose an active, catalog-backed assessment and a control and system inside its current scope."
        case .rejected(let status): return "The customer API rejected the request (HTTP \(status)). Sign in again for 401; ask your administrator to check membership, device, and assessment access for 403 or 409."
        }
    }
}

struct AWSCollectorConfiguration: Sendable {
    let apiOrigin: URL
    let portalOrigin: URL?
    let oauth: HostedOAuthConfiguration

    init(fields: [String: String]) throws {
        guard let api = fields["apiOrigin"].flatMap(URL.init(string:)),
              let origin = BackendTrust.normalizedOrigin(api),
              let issuer = fields["issuer"].flatMap(URL.init(string:)),
              let auth = fields["authorizationEndpoint"].flatMap(URL.init(string:)),
              let token = fields["tokenEndpoint"].flatMap(URL.init(string:)),
              let callback = URL(string: "scopeproof-capture://oauth/callback") else { throw AWSCollectorFailure.configuration }
        apiOrigin = origin
        if let value = fields["portalOrigin"], let portal = URL(string: value), portal.scheme == "https", portal.port == nil,
           portal.user == nil, portal.password == nil, portal.query == nil, portal.fragment == nil,
           portal.path.isEmpty || portal.path == "/", let host = portal.host, host.contains("."), !host.contains(":") {
            portalOrigin = portal
        } else { portalOrigin = nil }
        oauth = try HostedOAuthConfiguration(tenant: HostedTenantConfiguration(tenantID: fields["tenantId"] ?? "", displayName: fields["displayName"] ?? ""),
            issuerURL: issuer, authorizationEndpoint: auth, tokenEndpoint: token, clientID: fields["clientId"] ?? "", callbackURL: callback,
            scopes: ["openid", "profile", "email", "scopeproof/evidence.collect"])
    }

    static var bundled: [AWSCollectorConfiguration] {
        (Bundle.main.object(forInfoDictionaryKey: "ScopeproofAWSHostedTenants") as? [[String: String]] ?? []).compactMap { try? Self(fields: $0) }
    }
    var keyScope: String { [apiOrigin.absoluteString, oauth.tenant.tenantID, oauth.issuerURL.absoluteString, oauth.clientID].joined(separator: "\n") }
}

struct AWSCollectorProfile: Codable, Sendable {
    let tenantId: String
    let tenantHostname: String
    let userId: String
    let membershipId: String
    let role: String
    let tokenExpiresAt: String
    let uploadProofChallenge: String?

    func validate(configuration: AWSCollectorConfiguration, now: Date = Date()) throws {
        guard tenantId == configuration.oauth.tenant.tenantID,
              tenantHostname == configuration.apiOrigin.host,
              AWSCollectorService.resourceID(userId, prefix: "usr"),
              AWSCollectorService.resourceID(membershipId, prefix: "mem"),
              ["admin", "compliance_lead", "collector"].contains(role),
              let expiry = AWSCollectorService.instant(tokenExpiresAt), expiry > now,
              let challenge = uploadProofChallenge, (1...512).contains(challenge.utf8.count),
              challenge.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else { throw AWSCollectorFailure.signInRequired }
    }
}

struct AWSCollectorDeviceIdentity: Codable, Sendable {
    let schemaVersion: Int
    let scope: String
    let userId: String
    let deviceId: String
    let privateKey: Data
    var publicKey: Data { get throws { try P256.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.derRepresentation } }
    var fingerprint: String { get throws { LocalEvidenceArchive.digest(try publicKey) } }
}

struct AWSCollectorEnrollment: Codable, Sendable {
    let tenantId: String
    let id: String
    let principalId: String
    let status: String
    let revision: Int
    let publicKeySha256: String
}

struct AWSCollectorAssessment: Codable, Sendable {
    let id: String
    let name: String
    let status: String
    let revision: Int
    let framework: String
    let catalogId: String?
    let systems: [String]
    let controls: [String]
    let periodStart: String
    let periodEnd: String
    let scopeLocked: Bool
}
struct AWSCollectorCatalog: Codable, Sendable {
    struct Control: Codable, Sendable { let id: String; let requirement: String; let title: String; let defaultEvidence: String }
    let id: String
    let title: String
    let framework: String
    let version: String
    let controls: [Control]
    let digestSha256: String
}
struct AWSCollectorAssessmentPage: Codable, Sendable {
    let tenantId: String
    let items: [AWSCollectorAssessment]
    let nextCursor: String?
    let catalogs: [AWSCollectorCatalog]
}
struct AWSCollectorSelection: Codable, Sendable {
    let tenantId: String
    let apiOrigin: String
    let userId: String
    let deviceId: String
    let assessmentId: String
    let assessmentRevision: Int
    let catalogId: String
    let catalogDigest: String
    let controlId: String
    let systemName: String
}

/// Access/ID tokens are never persisted. Identity and enrollment challenge come
/// only from the API's cryptographically verified /collector/me response. An ID
/// token is discarded, not decoded or used as a source of local authorization.
actor AWSCollectorService {
    typealias Transport = @Sendable (URLRequest, URL, Int) async throws -> (Data, HTTPURLResponse)
    let transport: Transport
    private var token: String?
    private var profile: AWSCollectorProfile?
    private var scope: String?
    private var enrolledDeviceID: String?
    init(transport: @escaping Transport = AWSCollectorHTTP.send) { self.transport = transport }

    func exchange(grant: HostedOAuthAuthorizationGrant, configuration: AWSCollectorConfiguration,
        store: any HostedRefreshTokenStoring = HostedKeychainRefreshTokenStore()) async throws -> AWSCollectorProfile {
        guard grant.tenantID == configuration.oauth.tenant.tenantID,
              grant.issuerURL == configuration.oauth.issuerURL, grant.clientID == configuration.oauth.clientID,
              grant.tokenEndpoint == configuration.oauth.tokenEndpoint else { throw AWSCollectorFailure.configuration }
        return try await acceptTokens(request: grant.tokenRequest(), configuration: configuration, store: store)
    }

    func resume(configuration: AWSCollectorConfiguration, store: any HostedRefreshTokenStoring = HostedKeychainRefreshTokenStore()) async throws -> AWSCollectorProfile {
        guard let stored = try store.load(for: configuration.oauth) else { throw AWSCollectorFailure.signInRequired }
        var request = URLRequest(url: configuration.oauth.tokenEndpoint)
        request.httpMethod = "POST"; request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(["grant_type": "refresh_token", "client_id": configuration.oauth.clientID, "refresh_token": stored.refreshToken]
            .sorted { $0.key < $1.key }.map { AWSCollectorHTTP.form($0.key) + "=" + AWSCollectorHTTP.form($0.value) }.joined(separator: "&").utf8)
        return try await acceptTokens(request: request, configuration: configuration, store: store)
    }

    private func acceptTokens(request: URLRequest, configuration: AWSCollectorConfiguration,
        store: any HostedRefreshTokenStoring = HostedKeychainRefreshTokenStore()) async throws -> AWSCollectorProfile {
        token = nil; profile = nil; scope = nil; enrolledDeviceID = nil
        let (data, response) = try await transport(request, configuration.oauth.tokenEndpoint, 64 * 1024)
        guard response.statusCode == 200,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = object["access_token"] as? String, HostedRefreshCredential.isValidToken(access),
              (object["token_type"] as? String)?.lowercased() == "bearer" else { throw AWSCollectorFailure.signInRequired }
        var me = URLRequest(url: configuration.apiOrigin.appendingPathComponent("v1/collector/me"))
        me.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
        let (identityData, identityResponse) = try await transport(me, me.url!, 32 * 1024)
        guard identityResponse.statusCode == 200 else { throw AWSCollectorFailure.rejected(identityResponse.statusCode) }
        let identity = try JSONDecoder().decode(AWSCollectorProfile.self, from: identityData)
        try identity.validate(configuration: configuration)
        if let refresh = object["refresh_token"] as? String { try store.save(refreshToken: refresh, for: configuration.oauth, storedAt: Date()) }
        token = access; profile = identity; scope = configuration.keyScope
        return identity
    }

    func enroll(configuration: AWSCollectorConfiguration, displayName: String) async throws -> (AWSCollectorDeviceIdentity, AWSCollectorEnrollment) {
        let identity = try currentProfile(configuration)
        let device = try KeychainStore.awsCollectorIdentity(scope: configuration.keyScope, userId: identity.userId)
        let body = try Self.enrollmentBody(profile: identity, device: device, displayName: displayName)
        let data = try await api(path: "v1/customer/devices/enroll", body: body, configuration: configuration)
        let enrollment = try JSONDecoder().decode(AWSCollectorEnrollment.self, from: data)
        guard enrollment.tenantId == identity.tenantId, enrollment.id == device.deviceId,
              enrollment.principalId == identity.userId, enrollment.status == "ACTIVE", enrollment.revision >= 0,
              enrollment.publicKeySha256 == (try device.fingerprint) else { throw AWSCollectorFailure.enrollmentRejected }
        try KeychainStore.saveAWSCollectorEnrollment(enrollment, scope: configuration.keyScope, userId: identity.userId)
        enrolledDeviceID = device.deviceId
        return (device, enrollment)
    }

    func assessments(configuration: AWSCollectorConfiguration, cursor: String? = nil) async throws -> AWSCollectorAssessmentPage {
        guard cursor == nil || cursor!.utf8.count <= 4_096 else { throw AWSCollectorFailure.invalidResponse }
        let data = try await api(path: "v1/customer/collector-assessments/search",
            body: ["cursor": cursor as Any? ?? NSNull(), "limit": 100], configuration: configuration)
        let page = try JSONDecoder().decode(AWSCollectorAssessmentPage.self, from: data)
        guard page.tenantId == configuration.oauth.tenant.tenantID, page.items.count <= 100, page.catalogs.count <= 100,
              Set(page.items.map(\.id)).count == page.items.count,
              Set(page.catalogs.map(\.id)).count == page.catalogs.count,
              page.nextCursor == nil || page.nextCursor!.utf8.count <= 4_096 else { throw AWSCollectorFailure.invalidResponse }
        return page
    }

    func select(assessment: AWSCollectorAssessment, catalog: AWSCollectorCatalog, control: String, system: String,
        device: AWSCollectorDeviceIdentity, configuration: AWSCollectorConfiguration) throws -> AWSCollectorSelection {
        let profile = try currentProfile(configuration)
        guard enrolledDeviceID == device.deviceId, device.scope == configuration.keyScope, device.userId == profile.userId,
              assessment.status == "ACTIVE", assessment.revision >= 0, Self.resourceID(assessment.id, prefix: "asm"),
              assessment.catalogId == catalog.id, assessment.framework == catalog.framework + " " + catalog.version,
              catalog.digestSha256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              assessment.controls.contains(control), catalog.controls.contains(where: { $0.id == control }),
              assessment.systems.contains(system), !system.isEmpty else { throw AWSCollectorFailure.invalidSelection }
        return AWSCollectorSelection(tenantId: profile.tenantId, apiOrigin: configuration.apiOrigin.absoluteString,
            userId: profile.userId, deviceId: device.deviceId, assessmentId: assessment.id, assessmentRevision: assessment.revision,
            catalogId: catalog.id, catalogDigest: catalog.digestSha256, controlId: control, systemName: system)
    }

    func api(path: String, body: [String: Any], configuration: AWSCollectorConfiguration) async throws -> Data {
        _ = try currentProfile(configuration)
        var request = URLRequest(url: configuration.apiOrigin.appendingPathComponent(path)); request.httpMethod = "POST"
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
        let (data, response) = try await transport(request, request.url!, 512 * 1024)
        guard (200...299).contains(response.statusCode) else { throw AWSCollectorFailure.rejected(response.statusCode) }
        return data
    }

    func currentProfile(_ configuration: AWSCollectorConfiguration) throws -> AWSCollectorProfile {
        guard token != nil, let profile, scope == configuration.keyScope else { throw AWSCollectorFailure.signInRequired }
        try profile.validate(configuration: configuration)
        return profile
    }
    func clear() { token = nil; profile = nil; scope = nil; enrolledDeviceID = nil }

    static func enrollmentBody(profile: AWSCollectorProfile, device: AWSCollectorDeviceIdentity, displayName: String, now: Date = Date()) throws -> [String: String] {
        guard device.schemaVersion == 1, device.userId == profile.userId, resourceID(device.deviceId, prefix: "dev"),
              let challenge = profile.uploadProofChallenge, !challenge.isEmpty,
              displayName == displayName.trimmingCharacters(in: .whitespacesAndNewlines), (1...120).contains(displayName.utf8.count),
              !displayName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw AWSCollectorFailure.enrollmentRejected }
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let signedAt = formatter.string(from: now)
        let manifest: [String: Any] = ["schemaVersion": 1, "tenantId": profile.tenantId, "userId": profile.userId,
            "deviceId": device.deviceId, "displayName": displayName, "publicKeySha256": try device.fingerprint,
            "challenge": challenge, "signedAt": signedAt]
        let canonical = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .withoutEscapingSlashes])
        let payload = Data("scopeproof-device-enrollment-v1\n".utf8) + canonical
        let signature = try P256.Signing.PrivateKey(rawRepresentation: device.privateKey).signature(for: payload).rawRepresentation
        return ["deviceId": device.deviceId, "displayName": displayName, "publicKeySpki": base64URL(try device.publicKey), "signature": base64URL(signature), "signedAt": signedAt]
    }
    static func base64URL(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    static func resourceID(_ value: String, prefix: String) -> Bool { value.range(of: "^\(prefix)_[a-f0-9]{32}$", options: .regularExpression) != nil }
    static func instant(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }
}

private final class AWSCollectorRedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}
enum AWSCollectorHTTP {
    static func send(_ request: URLRequest, expectedURL: URL, maximumBytes: Int) async throws -> (Data, HTTPURLResponse) {
        guard request.url == expectedURL, expectedURL.user == nil, expectedURL.password == nil,
              expectedURL.query == nil, expectedURL.fragment == nil, expectedURL.scheme == "https", maximumBytes > 0 else { throw AWSCollectorFailure.configuration }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false; configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData; configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration, delegate: AWSCollectorRedirectBlocker(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        guard response.url == expectedURL, let http = response as? HTTPURLResponse, response.expectedContentLength <= maximumBytes else { throw AWSCollectorFailure.invalidResponse }
        return (try await BackendHTTP.collect(bytes, maximumBytes: maximumBytes), http)
    }
    static func form(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")) ?? "" }
}
