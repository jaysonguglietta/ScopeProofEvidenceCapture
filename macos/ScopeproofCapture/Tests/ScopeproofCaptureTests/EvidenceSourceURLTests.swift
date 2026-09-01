import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Evidence source URL")
struct EvidenceSourceURLTests {
    @Test("Persists only the source origin while preserving one-time navigation")
    func separatesNavigationFromProvenance() throws {
        let source = "https://Admin.Example.com/security/settings/policy?view=effective&region=us-east-1#access-controls"
        let sanitized = try #require(EvidenceSourceURL.sanitized(source))
        #expect(sanitized.absoluteString == "https://admin.example.com")
        #expect(EvidenceSourceURL.navigationURL(source)?.absoluteString == "https://admin.example.com/security/settings/policy?view=effective&region=us-east-1#access-controls")
        #expect(EvidenceSourceURL.savedTarget(source)?.absoluteString == "https://admin.example.com/security/settings/policy")
    }

    @Test("Removes credentials and redacts sensitive URL values")
    func redactsSensitiveURLComponents() throws {
        let source = "https://operator:password@admin.example.com/settings?view=full&access_token=synthetic-secret-value&apiKey=AKIAIOSFODNN7EXAMPLE#overview"
        let sanitized = try #require(EvidenceSourceURL.sanitized(source))
        #expect(sanitized.user == nil)
        #expect(sanitized.password == nil)
        #expect(sanitized.absoluteString == "https://admin.example.com")
        #expect(!sanitized.absoluteString.contains("synthetic-secret-value"))
        #expect(!sanitized.absoluteString.contains("AKIAIOSFODNN7EXAMPLE"))
    }

    @Test("Rejects non-web and oversized source URLs")
    func rejectsUnsafeURLs() {
        #expect(EvidenceSourceURL.sanitized("file:///tmp/evidence") == nil)
        #expect(EvidenceSourceURL.sanitized("javascript:alert(1)") == nil)
        #expect(EvidenceSourceURL.sanitized("https://example.com/\(String(repeating: "a", count: 2_100))") == nil)
        #expect(EvidenceSourceURL.isValidOrEmpty(""))
    }

    @Test("Uses fixed browser automation targets")
    func usesFixedBrowserAutomationTargets() {
        #expect(BrowserPageURL.appleScriptSource(for: "Safari")?.contains("com.apple.Safari") == true)
        #expect(BrowserPageURL.appleScriptSource(for: "Google Chrome")?.contains("com.google.Chrome") == true)
        #expect(BrowserPageURL.appleScriptSource(for: "Microsoft Edge")?.contains("com.microsoft.edgemac") == true)
        #expect(BrowserPageURL.appleScriptSource(for: "Arc")?.contains("company.thebrowser.Browser") == true)
        #expect(BrowserPageURL.appleScriptSource(for: "Firefox") == nil)
        #expect(BrowserPageURL.appleScriptSource(for: "Google Chrome owned by attacker") == nil)
    }

    @Test("Sanitizes detected browser URLs before returning them")
    func sanitizesDetectedBrowserURL() throws {
        let detected = BrowserPageURL.detectedURL(for: "Google Chrome") { _ in
            "https://operator:password@Admin.Example.com/settings?view=full&access_token=secret-value"
        }
        let url = try #require(detected)
        #expect(url.absoluteString == "https://admin.example.com")
        #expect(BrowserPageURL.detectedURL(for: "Firefox") { _ in "https://example.com" } == nil)
    }
}
