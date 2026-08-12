import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Local evidence console", .serialized)
struct LocalConsoleTests {
    @Test("Creates a durable SQLite index with a verifiable immutable audit chain")
    func createsIndexAndAuditChain() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-local-console-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let index = try LocalEvidenceIndex(databaseURL: directory.appendingPathComponent("index.sqlite3"), auditKeyData: Data(repeating: 0xA5, count: 32))
        try index.sync(entries: [])
        try index.recordAudit(action: "console.test", resourceID: "local")
        #expect(try index.verifyAuditChain())
        let summary = try index.summary()
        #expect(summary.total == 0)
        #expect(summary.auditEvents == 1)
    }

    @Test("Ships a CSP-compatible local console without inline executable code")
    func shipsCSPCompatibleAssets() {
        #expect(LocalConsoleAssets.html.contains("src=\"/assets/app.js\""))
        #expect(!LocalConsoleAssets.html.contains("<script>"))
        #expect(LocalConsoleAssets.javascript.contains("credentials: 'same-origin'"))
        #expect(LocalConsoleAssets.html.contains("Private to this Mac"))
    }
}
