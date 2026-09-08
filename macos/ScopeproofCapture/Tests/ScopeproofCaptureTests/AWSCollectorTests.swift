import CryptoKit
import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Native AWS customer onboarding", .serialized)
struct AWSCollectorTests {
    private let tenant = "ten_" + String(repeating: "a", count: 32)
    private let user = "usr_" + String(repeating: "b", count: 32)
    private let assessmentID = "asm_" + String(repeating: "d", count: 32)

    private func configuration() throws -> AWSCollectorConfiguration {
        try AWSCollectorConfiguration(fields: ["apiOrigin": "http://localhost:8787", "tenantId": tenant, "displayName": "Synthetic Customer",
            "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Test", "authorizationEndpoint": "https://synthetic.auth.us-east-1.amazoncognito.com/oauth2/authorize",
            "tokenEndpoint": "https://synthetic.auth.us-east-1.amazoncognito.com/oauth2/token", "clientId": "publicClient123"])
    }
    private func profile(challenge: String? = "verified-jti-synthetic") -> AWSCollectorProfile {
        AWSCollectorProfile(tenantId: tenant, tenantHostname: "localhost", userId: user,
            membershipId: "mem_" + String(repeating: "c", count: 32), role: "collector",
            tokenExpiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(3600)), uploadProofChallenge: challenge)
    }

    @Test("Profile trust requires expected tenant host, membership, expiry, and verified challenge")
    func checksProfileBoundary() throws {
        let configuration = try configuration()
        try profile().validate(configuration: configuration)
        #expect(throws: AWSCollectorFailure.self) { try profile(challenge: nil).validate(configuration: configuration) }
        #expect(throws: AWSCollectorFailure.self) { try profile().validate(configuration: configuration, now: Date().addingTimeInterval(7200)) }
        #expect(throws: AWSCollectorFailure.self) {
            try AWSCollectorConfiguration(fields: ["apiOrigin": "https://attacker.example", "tenantId": tenant])
        }
        let foreign = AWSCollectorProfile(tenantId: "ten_" + String(repeating: "e", count: 32), tenantHostname: "localhost", userId: user,
            membershipId: profile().membershipId, role: "collector", tokenExpiresAt: profile().tokenExpiresAt, uploadProofChallenge: profile().uploadProofChallenge)
        #expect(throws: AWSCollectorFailure.self) { try foreign.validate(configuration: configuration) }
    }

    @Test("Keychain device proof identity is stable and isolated by origin tenant and user")
    func isolatesDeviceIdentity() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let config = try configuration()
            let first = try KeychainStore.awsCollectorIdentity(scope: config.keyScope, userId: user)
            let repeated = try KeychainStore.awsCollectorIdentity(scope: config.keyScope, userId: user)
            let otherUser = try KeychainStore.awsCollectorIdentity(scope: config.keyScope, userId: "usr_" + String(repeating: "f", count: 32))
            let otherScope = try KeychainStore.awsCollectorIdentity(scope: config.keyScope + "-other", userId: user)
            #expect(first.deviceId == repeated.deviceId && first.privateKey == repeated.privateKey)
            #expect(first.deviceId != otherUser.deviceId && first.privateKey != otherScope.privateKey)
        }
    }

    @Test("Native enrollment signs the exact token-bound P256 SPKI/raw-signature wire contract")
    func signsEnrollmentContract() throws {
        try KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let identity = try KeychainStore.awsCollectorIdentity(scope: configuration().keyScope, userId: user)
            let profile = profile()
            let now = Date()
            let body = try AWSCollectorService.enrollmentBody(profile: profile, device: identity, displayName: "Synthetic Mac", now: now)
            #expect(Set(body.keys) == Set(["deviceId", "displayName", "publicKeySpki", "signature", "signedAt"]))
            let manifest: [String: Any] = ["schemaVersion": 1, "tenantId": tenant, "userId": user, "deviceId": identity.deviceId,
                "displayName": "Synthetic Mac", "publicKeySha256": try identity.fingerprint, "challenge": profile.uploadProofChallenge!, "signedAt": body["signedAt"]!]
            let payload = Data("scopeproof-device-enrollment-v1\n".utf8) + (try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .withoutEscapingSlashes]))
            let signatureData = try #require(Self.decode(body["signature"]!))
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
            let key = try P256.Signing.PublicKey(derRepresentation: #require(Self.decode(body["publicKeySpki"]!)))
            #expect(signatureData.count == 64 && key.isValidSignature(signature, for: payload))
            #expect(!key.isValidSignature(signature, for: payload + Data("changed".utf8)))
            // Optional generated interoperability fixture contains no private key,
            // access token, refresh token, customer evidence, or real identity.
            if let path = ProcessInfo.processInfo.environment["SCOPEPROOF_NATIVE_ENROLLMENT_FIXTURE_PATH"] {
                let fixture: [String: Any] = ["body": body, "actor": ["tenantId": tenant, "userId": user], "identity": ["jwtId": profile.uploadProofChallenge!], "now": ISO8601DateFormatter().string(from: now)]
                try JSONSerialization.data(withJSONObject: fixture, options: [.sortedKeys]).write(to: URL(fileURLWithPath: path))
            }
        }
    }

    @Test("Authenticated refresh enrollment and assessment selection honor real zero revisions and reject out-of-scope control")
    func runsSyntheticOnboarding() async throws {
        try await KeychainStore.$testStore.withValue(InMemoryKeychainTestStore()) {
            let config = try configuration()
            let profile = profile()
            let catalog = AWSCollectorCatalog(id: "pci-test", title: "Synthetic catalog", framework: "PCI DSS", version: "4.0.1",
                controls: [.init(id: "8.3.6", requirement: "Requirement 8", title: "Authentication factors", defaultEvidence: "Reviewed configuration")], digestSha256: String(repeating: "f", count: 64))
            let assessment = AWSCollectorAssessment(id: assessmentID, name: "Synthetic Assessment", status: "ACTIVE", revision: 0,
                framework: "PCI DSS 4.0.1", catalogId: catalog.id, systems: ["Identity"], controls: ["8.3.6"], periodStart: "2026-01-01", periodEnd: "2026-12-31", scopeLocked: true)
            let page = AWSCollectorAssessmentPage(tenantId: tenant, items: [assessment], nextCursor: nil, catalogs: [catalog])
            let transport: AWSCollectorService.Transport = { request, expectedURL, maximum in
                #expect(request.url == expectedURL && maximum <= 512 * 1024)
                let data: Data
                switch expectedURL.path {
                case "/oauth2/token": data = try JSONSerialization.data(withJSONObject: ["access_token": String(repeating: "synthetic", count: 10), "token_type": "Bearer"])
                case "/v1/collector/me": data = try JSONEncoder().encode(profile)
                case "/v1/customer/devices/enroll":
                    let requestData = try #require(request.httpBody)
                    let body = try #require(try JSONSerialization.jsonObject(with: requestData) as? [String: String])
                    let spki = try #require(Self.decode(body["publicKeySpki"]!))
                    data = try JSONEncoder().encode(AWSCollectorEnrollment(tenantId: profile.tenantId, id: body["deviceId"]!, principalId: profile.userId, status: "ACTIVE", revision: 0, publicKeySha256: LocalEvidenceArchive.digest(spki)))
                case "/v1/customer/collector-assessments/search": data = try JSONEncoder().encode(page)
                default: throw AWSCollectorFailure.invalidResponse
                }
                return (data, HTTPURLResponse(url: expectedURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
            let service = AWSCollectorService(transport: transport)
            _ = try await service.resume(configuration: config, store: AWSCollectorTestRefreshStore())
            let premature = try KeychainStore.awsCollectorIdentity(scope: config.keyScope, userId: user)
            await #expect(throws: AWSCollectorFailure.self) { try await service.select(assessment: assessment, catalog: catalog, control: "8.3.6", system: "Identity", device: premature, configuration: config) }
            let (device, result) = try await service.enroll(configuration: config, displayName: "Synthetic Mac")
            let fingerprint = try device.fingerprint
            #expect(result.revision == 0 && result.publicKeySha256 == fingerprint)
            let fetched = try await service.assessments(configuration: config)
            let selection = try await service.select(assessment: fetched.items[0], catalog: fetched.catalogs[0], control: "8.3.6", system: "Identity", device: device, configuration: config)
            #expect(selection.assessmentId == assessmentID && selection.deviceId == device.deviceId)
            await #expect(throws: AWSCollectorFailure.self) { try await service.select(assessment: assessment, catalog: catalog, control: "outside", system: "Identity", device: device, configuration: config) }
            await service.clear()
            await #expect(throws: AWSCollectorFailure.self) { try await service.assessments(configuration: config) }
        }
    }

    private static func decode(_ value: String) -> Data? {
        let base = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: base + String(repeating: "=", count: (4 - base.count % 4) % 4))
    }
}

private struct AWSCollectorTestRefreshStore: HostedRefreshTokenStoring {
    func load(for configuration: HostedOAuthConfiguration) throws -> HostedRefreshCredential? {
        try HostedRefreshCredential(configuration: configuration, refreshToken: String(repeating: "synthetic", count: 10))
    }
    func save(refreshToken: String, for configuration: HostedOAuthConfiguration, storedAt: Date) throws {}
    func delete(for configuration: HostedOAuthConfiguration) throws {}
}
