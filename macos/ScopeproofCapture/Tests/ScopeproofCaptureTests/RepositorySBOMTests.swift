import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("One-time repository SBOM")
struct RepositorySBOMTests {
    @Test("Accepts only exact GitHub HTTPS repository URLs")
    func validatesRepositoryURLs() throws {
        let parsed = try RepositorySBOMService.parseRepositoryURL("https://github.com/Scopeproof/evidence-app.git")
        #expect(parsed.owner == "Scopeproof")
        #expect(parsed.repository == "evidence-app")
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("http://github.com/owner/repo") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("https://github.example/owner/repo") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("https://github.com/owner/repo/issues") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("https://token@github.com/owner/repo") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("https://github.com/owner/repo?ref=main") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.parseRepositoryURL("https://github.com/owner%2Frepo") }
    }

    @Test("Requires an ephemeral-shaped token and a bounded Git ref")
    func validatesCredentialsAndRef() throws {
        try RepositorySBOMService.validateToken("github_pat_1234567890_example")
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.validateToken("short") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.validateToken("github token with spaces") }
        #expect(try RepositorySBOMService.validateRef("release/2026.08") == "release/2026.08")
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.validateRef("../main") }
        #expect(throws: RepositorySBOMFailure.self) { try RepositorySBOMService.validateRef("main@{1}") }
    }

    @Test("Parses and deduplicates pinned components without executing repository content")
    func parsesPinnedComponents() throws {
        let packageLock = """
        {
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"left-pad": "1.3.0", "@scope/tool": "2.1.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/@scope/tool": {"name": "@scope/tool", "version": "2.1.0"}
          }
        }
        """
        let requirements = "requests==2.32.4\nleft-pad==1.3.0\n-r unsafe.txt\n"
        let components = try RepositorySBOMService.parseManifests([
            (path: "package-lock.json", text: packageLock),
            (path: "services/api/requirements.txt", text: requirements),
        ])
        #expect(components.count == 4)
        #expect(components.contains { $0.purl == "pkg:npm/left-pad@1.3.0" && $0.direct })
        #expect(components.contains { $0.purl == "pkg:npm/%40scope/tool@2.1.0" && $0.direct })
        #expect(components.contains { $0.purl == "pkg:pypi/requests@2.32.4" && $0.direct })
        #expect(!components.contains { $0.name == "-r" || $0.name == "unsafe.txt" })
    }

    @Test("Parses lockfile ecosystems supported by the local generator")
    func parsesAdditionalLockfiles() throws {
        let cargo = """
        [[package]]
        name = "serde"
        version = "1.0.219"
        """
        let go = "golang.org/x/text v0.28.0 h1:example\ngolang.org/x/text v0.28.0/go.mod h1:example\n"
        let gem = """
        GEM
          specs:
            rack (3.2.1)

        PLATFORMS
        """
        let components = try RepositorySBOMService.parseManifests([
            (path: "Cargo.lock", text: cargo),
            (path: "go.sum", text: go),
            (path: "Gemfile.lock", text: gem),
        ])
        #expect(components.contains { $0.purl == "pkg:cargo/serde@1.0.219" })
        #expect(components.contains { $0.purl == "pkg:golang/golang.org/x/text@v0.28.0" })
        #expect(components.contains { $0.purl == "pkg:gem/rack@3.2.1" })
    }
}
