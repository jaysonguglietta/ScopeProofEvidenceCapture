import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Sensitive data scanner")
struct SensitiveDataScannerTests {
    @Test("Detects Luhn-valid PANs and ignores invalid card-like values")
    func detectsLuhnValidPANAndIgnoresInvalidNumber() {
        #expect(SensitiveDataScanner.detectedKinds(in: "Card 4111 1111 1111 1111").contains(.pan))
        #expect(!SensitiveDataScanner.detectedKinds(in: "Order 4111111111111112").contains(.pan))
    }

    @Test("Detects credential families without retaining secret text")
    func detectsCredentialFamiliesWithoutRetainingSecretText() {
        #expect(SensitiveDataScanner.detectedKinds(in: "AKIAIOSFODNN7EXAMPLE").contains(.awsAccessKey))
        #expect(SensitiveDataScanner.detectedKinds(in: "api_token=very-sensitive-token-value-12345").contains(.apiToken))
        #expect(SensitiveDataScanner.detectedKinds(in: "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature").contains(.authorization))
    }

    @Test("Requires HTTPS except for loopback development servers", arguments: [
        ("https://scopeproof.example", true),
        ("http://localhost:3000", true),
        ("http://127.0.0.1:3000", true),
        ("http://scopeproof.example", false),
        ("file:///tmp/evidence", false),
    ])
    func validatesServerTransport(value: String, expected: Bool) {
        #expect(UploadService.isAllowedServerURL(URL(string: value)!) == expected)
    }
}
