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

    @Test("Legacy npm inventory retains nested and multiple installed versions without guessing directness")
    func recursivelyInventoriesLegacyNpm() throws {
        let inventory = try RepositorySBOMService.parseInventory([(path: "package-lock.json", text: """
        {"lockfileVersion":1,"dependencies":{"parent":{"version":"1.0.0","dependencies":{"shared":{"version":"1.2.3"}}},"shared":{"version":"2.0.0"}}}
        """)])
        #expect(Set(inventory.components.map(\.purl)) == ["pkg:npm/parent@1.0.0", "pkg:npm/shared@1.2.3", "pkg:npm/shared@2.0.0"])
        #expect(inventory.components.allSatisfy { !$0.direct && !$0.directKnown })
        #expect(inventory.complete)
    }

    @Test("Modern npm directness is path-specific and unsupported inputs never claim complete coverage")
    func reportsPartialAndUnsupportedManifestCoverage() throws {
        let modern = """
        {"lockfileVersion":3,"packages":{"":{"dependencies":{"shared":"2.0.0"}},"node_modules/shared":{"version":"2.0.0"},"node_modules/parent/node_modules/shared":{"version":"1.0.0"},"node_modules/local":{"link":true},"node_modules/range":{"version":"^1.0.0"}}}
        """
        let inventory = try RepositorySBOMService.parseInventory([
            (path: "package-lock.json", text: modern),
            (path: "service/yarn.lock", text: "__metadata:\n  version: 8\n"),
            (path: "service/requirements.txt", text: "requests==2.32.4\nunpinned>=1.0\n"),
        ])
        #expect(inventory.components.contains { $0.purl == "pkg:npm/shared@2.0.0" && $0.direct && $0.directKnown })
        #expect(inventory.components.contains { $0.purl == "pkg:npm/shared@1.0.0" && !$0.direct && $0.directKnown })
        #expect(!inventory.components.contains { $0.name == "range" || $0.name == "local" })
        #expect(!inventory.complete)
        #expect(inventory.coverage.count == 3 && inventory.coverage.allSatisfy { !$0.complete && !$0.warnings.isEmpty })
        #expect(inventory.coverage.first { $0.path.hasSuffix("yarn.lock") }?.componentCount == 0)
        #expect(throws: RepositorySBOMFailure.unsupportedManifestVersion("package-lock.json")) {
            try RepositorySBOMService.parseInventory([(path: "package-lock.json", text: "{\"lockfileVersion\":99,\"packages\":{}}")])
        }
        #expect(throws: RepositorySBOMFailure.self) {
            try RepositorySBOMService.parseInventory([(path: "package-lock.json", text: "{\"lockfileVersion\":3}")])
        }
    }

    @Test("Both generated document formats preserve inventory coverage and unknown directness")
    func emitsCoverageInActualDocuments() throws {
        let inventory = try RepositorySBOMService.parseInventory([
            (path: "package-lock.json", text: "{\"lockfileVersion\":1,\"dependencies\":{\"shared\":{\"version\":\"1.2.3\"}}}"),
            (path: "requirements.txt", text: "requests==2.32.4\n"),
        ])
        for format in RepositorySBOMFormat.allCases {
            let document = RepositorySBOMService.buildDocument(format: format, repository: "example/repository",
                commit: String(repeating: "a", count: 40), generatedAt: "2026-09-08T12:00:00Z",
                manifestSetSHA256: String(repeating: "b", count: 64), manifests: inventory.coverage.map(\.path),
                components: inventory.components, coverage: inventory.coverage)
            let data = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys, .prettyPrinted])
            let text = try #require(String(data: data, encoding: .utf8))
            #expect(text.contains("unknown") && (text.contains("coverage") || text.contains("Coverage")))
            if format == .cycloneDX { #expect(text.contains("bom-ref") && !text.contains("bom_ref")) }
            // Optional test-only fixture output for the pinned official-schema
            // validator. Never writes to the app's evidence directory.
            if let path = ProcessInfo.processInfo.environment["SCOPEPROOF_NATIVE_SBOM_FIXTURE_DIR"] {
                let root = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
                let isTemporary = root.path.hasPrefix("/private/tmp/") || root.path.hasPrefix("/tmp/")
                #expect(isTemporary)
                guard isTemporary else { continue }
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
                try data.write(to: root.appendingPathComponent(format.filenameLabel + ".json"))
            }
        }
    }
}
