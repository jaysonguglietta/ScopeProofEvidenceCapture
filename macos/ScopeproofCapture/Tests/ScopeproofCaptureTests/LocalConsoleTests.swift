import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Local evidence console", .serialized)
struct LocalConsoleTests {
    @Test("Uses Documents for new evidence and retains the legacy Pictures root")
    func usesDocumentsEvidenceRootWithLegacyCompatibility() {
        let home = URL(fileURLWithPath: "/Users/tester", isDirectory: true)
        let primary = CaptureHistory.defaultEvidenceRoot(homeDirectory: home)
        let legacy = CaptureHistory.legacyEvidenceRoot(homeDirectory: home)
        #expect(primary.path == "/Users/tester/Documents/Scopeproof Evidence")
        #expect(legacy.path == "/Users/tester/Pictures/Scopeproof Evidence")
        let readablePaths = CaptureHistory.readableRoots(for: primary, homeDirectory: home).map(\.path)
        #expect(readablePaths == [primary.path, legacy.path])
        #expect(CaptureHistory.isWithinReadableRoots(primary.appendingPathComponent("PCI/8.3/evidence.png"), primaryDirectory: primary, homeDirectory: home))
        #expect(CaptureHistory.isWithinReadableRoots(legacy.appendingPathComponent("PCI/8.3/evidence.png"), primaryDirectory: primary, homeDirectory: home))
        #expect(!CaptureHistory.isWithinReadableRoots(home.appendingPathComponent("Downloads/evidence.png"), primaryDirectory: primary, homeDirectory: home))
    }

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
        #expect(LocalConsoleAssets.html.contains("storage-location"))
        #expect(LocalConsoleAssets.html.contains("assessment-period"))
        #expect(LocalConsoleAssets.html.contains("group-by"))
        #expect(LocalConsoleAssets.javascript.contains("/api/library"))
        #expect(!LocalConsoleAssets.javascript.localizedCaseInsensitiveContains("secretAccessKey"))
    }

    @Test("Uses one-time launch nonces and rotates bounded browser sessions")
    func rotatesLocalConsoleSessions() throws {
        var tokens = ["launch-one", "session-one", "launch-two", "session-two", "launch-three", "session-three"]
        var state = LocalConsoleSessionState(tokenGenerator: { tokens.removeFirst() })
        let start = Date(timeIntervalSince1970: 1_787_900_000)

        let firstLaunch = state.beginOpen(now: start)
        #expect(firstLaunch == "launch-one")
        let wrongLaunch = state.consumeLaunchNonce("wrong", now: start)
        #expect(wrongLaunch == nil)
        let firstConsumed = state.consumeLaunchNonce(firstLaunch, now: start)
        let firstSession = try #require(firstConsumed)
        #expect(firstSession == "session-one")
        let replay = state.consumeLaunchNonce(firstLaunch, now: start)
        #expect(replay == nil)
        let firstAuthorized = state.authorize(firstSession, now: start.addingTimeInterval(10))
        #expect(firstAuthorized)

        let secondLaunch = state.beginOpen(now: start.addingTimeInterval(20))
        let oldAuthorized = state.authorize(firstSession, now: start.addingTimeInterval(21))
        #expect(!oldAuthorized)
        let secondConsumed = state.consumeLaunchNonce(secondLaunch, now: start.addingTimeInterval(21))
        let secondSession = try #require(secondConsumed)
        let secondAuthorized = state.authorize(secondSession, now: start.addingTimeInterval(22))
        #expect(secondAuthorized)
        let idleExpired = state.authorize(
            secondSession,
            now: start.addingTimeInterval(22 + LocalConsoleSessionState.idleLifetime + 1)
        )
        #expect(!idleExpired)

        let thirdLaunch = state.beginOpen(now: start.addingTimeInterval(100))
        let expiredLaunch = state.consumeLaunchNonce(
            thirdLaunch,
            now: start.addingTimeInterval(100 + LocalConsoleSessionState.launchLifetime + 1)
        )
        #expect(expiredLaunch == nil)
    }
}
