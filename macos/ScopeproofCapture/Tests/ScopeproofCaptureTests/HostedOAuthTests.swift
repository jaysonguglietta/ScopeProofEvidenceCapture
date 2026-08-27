import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Hosted Cognito OAuth")
struct HostedOAuthTests {
    @Test("Validates tenant configuration and treats email domains only as hints")
    func validatesTenantConfiguration() throws {
        let tenant = try HostedTenantConfiguration(
            tenantID: "ten_0123456789abcdef0123456789abcdef", displayName: "Acme Security",
            allowedEmailDomains: ["audit.acme.example", "acme.example"]
        )
        #expect(tenant.allowedEmailDomains == ["acme.example", "audit.acme.example"])
        #expect(tenant.isEmailDomainHintMatch("reviewer@acme.example"))
        #expect(tenant.isEmailDomainHintMatch("reviewer@security.acme.example"))
        #expect(!tenant.isEmailDomainHintMatch("reviewer@acme.example.attacker.test"))
        #expect(!tenant.isEmailDomainHintMatch("invalid-address"))

        #expect(throws: HostedOAuthFailure.self) {
            try HostedTenantConfiguration(tenantID: "Tenant A", displayName: "Acme")
        }
        #expect(throws: HostedOAuthFailure.self) {
            try HostedTenantConfiguration(tenantID: "tenant-a", displayName: " Acme")
        }
        #expect(throws: HostedOAuthFailure.self) {
            try HostedTenantConfiguration(tenantID: "tenant-a", displayName: "Acme", allowedEmailDomains: ["*.acme.example"])
        }
        #expect(throws: HostedOAuthFailure.self) {
            try HostedTenantConfiguration(tenantID: "tenant-a", displayName: "Acme", allowedEmailDomains: ["acme.example", "acme.example"])
        }
    }

    @Test("Accepts canonical Cognito public-client endpoints")
    func acceptsCanonicalCognitoConfiguration() throws {
        let configuration = try validConfiguration()
        #expect(configuration.issuerURL.absoluteString == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example")
        #expect(configuration.authorizationEndpoint.host == configuration.tokenEndpoint.host)
        #expect(configuration.callbackURL.absoluteString == "scopeproof-capture://oauth/callback")
        #expect(configuration.scopes.contains("openid"))
    }

    @Test("Rejects malicious issuer and endpoint URLs")
    func rejectsMaliciousEndpoints() throws {
        let tenant = try validTenant()
        let callback = try #require(URL(string: "scopeproof-capture://oauth/callback"))
        let authorization = try #require(URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/authorize"))
        let token = try #require(URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/token"))

        for issuerText in [
            "http://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example",
            "https://operator@cognito-idp.us-east-1.amazonaws.com/us-east-1_Example",
            "https://127.0.0.1/us-east-1_Example",
            "https://localhost/us-east-1_Example",
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example?tenant=other",
            "https://cognito-idp.us-east-1.amazonaws.com/a/../us-east-1_Example",
        ] {
            let issuer = try #require(URL(string: issuerText))
            #expect(throws: HostedOAuthFailure.self) {
                try HostedOAuthConfiguration(
                    tenant: tenant, issuerURL: issuer, authorizationEndpoint: authorization,
                    tokenEndpoint: token, clientID: "publicClient123", callbackURL: callback
                )
            }
        }

        let queriedAuthorization = try #require(URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/authorize?redirect=evil"))
        #expect(throws: HostedOAuthFailure.self) {
            try HostedOAuthConfiguration(
                tenant: tenant,
                issuerURL: URL(string: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example")!,
                authorizationEndpoint: queriedAuthorization, tokenEndpoint: token,
                clientID: "publicClient123", callbackURL: callback
            )
        }

        let otherOriginToken = try #require(URL(string: "https://attacker.example/oauth2/token"))
        #expect(throws: HostedOAuthFailure.self) {
            try HostedOAuthConfiguration(
                tenant: tenant,
                issuerURL: URL(string: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example")!,
                authorizationEndpoint: authorization, tokenEndpoint: otherOriginToken,
                clientID: "publicClient123", callbackURL: callback
            )
        }
    }

    @Test("Rejects weak client, scope, callback, and domain settings")
    func rejectsInvalidPublicClientConfiguration() throws {
        let tenant = try validTenant()
        let issuer = URL(string: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example")!
        let authorization = URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/authorize")!
        let token = URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/token")!

        for callbackText in [
            "https://oauth.example/callback",
            "file://oauth/callback",
            "scopeproof-capture://oauth/",
            "scopeproof-capture://operator@oauth/callback",
            "scopeproof-capture://oauth/call%62ack",
            "scopeproof-capture://oauth/callback?state=preset",
        ] {
            let callback = try #require(URL(string: callbackText))
            #expect(throws: HostedOAuthFailure.self) {
                try HostedOAuthConfiguration(
                    tenant: tenant, issuerURL: issuer, authorizationEndpoint: authorization,
                    tokenEndpoint: token, clientID: "publicClient123", callbackURL: callback
                )
            }
        }

        #expect(throws: HostedOAuthFailure.self) {
            try HostedOAuthConfiguration(
                tenant: tenant, issuerURL: issuer, authorizationEndpoint: authorization,
                tokenEndpoint: token, clientID: "client secret", callbackURL: URL(string: "scopeproof-capture://oauth/callback")!
            )
        }
        #expect(throws: HostedOAuthFailure.self) {
            try HostedOAuthConfiguration(
                tenant: tenant, issuerURL: issuer, authorizationEndpoint: authorization,
                tokenEndpoint: token, clientID: "publicClient123", callbackURL: URL(string: "scopeproof-capture://oauth/callback")!,
                scopes: ["profile", "email"]
            )
        }
    }

    @Test("Implements RFC 7636 S256 and standard SHA-256 vectors")
    func createsPKCEChallenge() throws {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        #expect(try HostedOAuthPKCE.challenge(for: verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        #expect(HostedSHA256.hexDigest(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(throws: HostedOAuthFailure.self) { try HostedOAuthPKCE.challenge(for: "too-short") }
    }

    @Test("Creates a short-lived authorization request without client secrets or AWS keys")
    func createsAuthorizationRequest() async throws {
        let configuration = try validConfiguration()
        let now = Date(timeIntervalSince1970: 1_788_000_000)
        let coordinator = HostedOAuthCoordinator(pendingLifetime: 300)
        let request = try await coordinator.begin(configuration: configuration, now: now)
        let query = queryValues(request.authorizationURL)

        #expect(request.expiresAt == now.addingTimeInterval(300))
        #expect(query["response_type"] == "code")
        #expect(query["client_id"] == configuration.clientID)
        #expect(query["redirect_uri"] == configuration.callbackURL.absoluteString)
        #expect(query["code_challenge_method"] == "S256")
        #expect(query["state"]?.count == 43)
        #expect(query["nonce"]?.count == 43)
        #expect(query["code_challenge"]?.count == 43)
        #expect(!request.authorizationURL.absoluteString.lowercased().contains("client_secret"))
        #expect(!request.authorizationURL.absoluteString.contains("AKIA"))
    }

    @Test("State mismatch fails without consuming the legitimate transaction")
    func rejectsStateMismatch() async throws {
        let configuration = try validConfiguration()
        let coordinator = HostedOAuthCoordinator()
        let request = try await coordinator.begin(configuration: configuration)
        let state = try #require(queryValues(request.authorizationURL)["state"])

        do {
            _ = try await coordinator.consume(callbackURL: callback(code: "valid-code", state: "wrong-state"))
            Issue.record("A mismatched state was accepted")
        } catch {
            #expect(error as? HostedOAuthFailure == .callbackStateMismatch)
        }

        let grant = try await coordinator.consume(callbackURL: callback(code: "valid-code", state: state))
        #expect(grant.authorizationCode == "valid-code")
        #expect(try HostedOAuthPKCE.challenge(for: grant.codeVerifier) == queryValues(request.authorizationURL)["code_challenge"])
        #expect(grant.expectedIDTokenNonce == queryValues(request.authorizationURL)["nonce"])
    }

    @Test("Pending transactions expire and are cleared")
    func rejectsExpiredTransaction() async throws {
        let configuration = try validConfiguration()
        let start = Date(timeIntervalSince1970: 1_788_000_000)
        let coordinator = HostedOAuthCoordinator(pendingLifetime: 60)
        let request = try await coordinator.begin(configuration: configuration, now: start)
        let state = try #require(queryValues(request.authorizationURL)["state"])
        let url = callback(code: "valid-code", state: state)

        do {
            _ = try await coordinator.consume(callbackURL: url, now: start.addingTimeInterval(61))
            Issue.record("An expired transaction was accepted")
        } catch {
            #expect(error as? HostedOAuthFailure == .transactionExpired)
        }
        do {
            _ = try await coordinator.consume(callbackURL: url, now: start.addingTimeInterval(62))
            Issue.record("An expired transaction was not cleared")
        } catch {
            #expect(error as? HostedOAuthFailure == .noPendingTransaction)
        }
    }

    @Test("A successful callback can be consumed only once")
    func consumesCallbackOnce() async throws {
        let coordinator = HostedOAuthCoordinator()
        let request = try await coordinator.begin(configuration: validConfiguration())
        let state = try #require(queryValues(request.authorizationURL)["state"])
        let url = callback(code: "single-use-code", state: state)

        let grant = try await coordinator.consume(callbackURL: url)
        #expect(grant.authorizationCode == "single-use-code")
        do {
            _ = try await coordinator.consume(callbackURL: url)
            Issue.record("A callback was consumed twice")
        } catch {
            #expect(error as? HostedOAuthFailure == .noPendingTransaction)
        }
    }

    @Test("Rejects callback origin, path, fragments, and duplicate parameters")
    func rejectsMaliciousCallbacks() async throws {
        let configuration = try validConfiguration()
        let coordinator = HostedOAuthCoordinator()
        let request = try await coordinator.begin(configuration: configuration)
        let state = try #require(queryValues(request.authorizationURL)["state"])
        let encodedState = state.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let candidates = [
            "scopeproof-capture://attacker/callback?code=x&state=\(encodedState)",
            "scopeproof-capture://oauth/other?code=x&state=\(encodedState)",
            "scopeproof-capture://oauth/%63allback?code=x&state=\(encodedState)",
            "scopeproof-capture://oauth/callback?code=x&state=\(encodedState)#fragment",
            "scopeproof-capture://oauth/callback?code=x&state=\(encodedState)&state=\(encodedState)",
            "scopeproof-capture://oauth/callback?code=x&state=\(encodedState)&unexpected=value",
        ]
        for text in candidates {
            let url = try #require(URL(string: text))
            do {
                _ = try await coordinator.consume(callbackURL: url)
                Issue.record("Accepted malicious callback: \(text)")
            } catch {
                #expect(error is HostedOAuthFailure)
            }
        }

        // Invalid callback attempts do not destroy a still-valid browser flow.
        let grant = try await coordinator.consume(callbackURL: callback(code: "valid-code", state: state))
        #expect(grant.tenantID == configuration.tenant.tenantID)
    }

    @Test("OAuth errors are state-bound and consume the transaction")
    func consumesAuthorizationServerError() async throws {
        let coordinator = HostedOAuthCoordinator()
        let request = try await coordinator.begin(configuration: validConfiguration())
        let state = try #require(queryValues(request.authorizationURL)["state"])
        var components = URLComponents(string: "scopeproof-capture://oauth/callback")!
        components.queryItems = [
            URLQueryItem(name: "error", value: "access_denied"),
            URLQueryItem(name: "error_description", value: "User cancelled"),
            URLQueryItem(name: "state", value: state),
        ]
        let url = try #require(components.url)

        do {
            _ = try await coordinator.consume(callbackURL: url)
            Issue.record("An OAuth error was accepted as a grant")
        } catch {
            #expect(error as? HostedOAuthFailure == .authorizationServerError("access_denied"))
        }
        do {
            _ = try await coordinator.consume(callbackURL: url)
            Issue.record("An OAuth error callback was consumed twice")
        } catch {
            #expect(error as? HostedOAuthFailure == .noPendingTransaction)
        }
    }

    @Test("Token exchange is a PKCE public-client request with no secret")
    func buildsPublicClientTokenRequest() async throws {
        let coordinator = HostedOAuthCoordinator()
        let request = try await coordinator.begin(configuration: validConfiguration())
        let state = try #require(queryValues(request.authorizationURL)["state"])
        let grant = try await coordinator.consume(callbackURL: callback(code: "auth-code-123", state: state))
        let tokenRequest = grant.tokenRequest()
        let body = String(data: try #require(tokenRequest.httpBody), encoding: .utf8) ?? ""

        #expect(tokenRequest.httpMethod == "POST")
        #expect(tokenRequest.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
        #expect(body.contains("grant_type=authorization_code"))
        #expect(body.contains("code_verifier="))
        #expect(body.contains("client_id=publicClient123"))
        #expect(!body.lowercased().contains("client_secret"))
        #expect(!body.lowercased().contains("access_key"))
        #expect(!body.lowercased().contains("secret_access_key"))
    }

    @Test("Refresh credential is bound to tenant, issuer, and public client")
    func bindsRefreshCredential() throws {
        let configuration = try validConfiguration()
        let credential = try HostedRefreshCredential(
            configuration: configuration,
            refreshToken: "refresh-token-value-that-is-long-enough"
        )
        #expect(credential.isBound(to: configuration))

        let otherTenant = try HostedTenantConfiguration(
            tenantID: "ten_fedcba9876543210fedcba9876543210", displayName: "Other", allowedEmailDomains: ["other.example"]
        )
        let otherConfiguration = try validConfiguration(tenant: otherTenant)
        #expect(!credential.isBound(to: otherConfiguration))
        #expect(throws: HostedOAuthFailure.self) {
            try HostedRefreshCredential(configuration: configuration, refreshToken: "short")
        }

        let encoded = String(data: try JSONEncoder().encode(credential), encoding: .utf8) ?? ""
        #expect(!encoded.contains("clientSecret"))
        #expect(!encoded.contains("secretAccessKey"))
        #expect(!encoded.contains("accessKeyID"))
    }

    private func validTenant() throws -> HostedTenantConfiguration {
        try HostedTenantConfiguration(
            tenantID: "ten_0123456789abcdef0123456789abcdef", displayName: "Acme Security", allowedEmailDomains: ["acme.example"]
        )
    }

    private func validConfiguration(tenant: HostedTenantConfiguration? = nil) throws -> HostedOAuthConfiguration {
        try HostedOAuthConfiguration(
            tenant: tenant ?? validTenant(),
            issuerURL: URL(string: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example")!,
            authorizationEndpoint: URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/authorize")!,
            tokenEndpoint: URL(string: "https://scopeproof.auth.us-east-1.amazoncognito.com/oauth2/token")!,
            clientID: "publicClient123",
            callbackURL: URL(string: "scopeproof-capture://oauth/callback")!,
            scopes: ["openid", "profile", "email", "scopeproof/evidence.read"]
        )
    }

    private func queryValues(_ url: URL) -> [String: String] {
        Dictionary(uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []).compactMap {
            guard let value = $0.value else { return nil }
            return ($0.name, value)
        })
    }

    private func callback(code: String, state: String) -> URL {
        var components = URLComponents(string: "scopeproof-capture://oauth/callback")!
        components.queryItems = [
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "state", value: state),
        ]
        return components.url!
    }
}
