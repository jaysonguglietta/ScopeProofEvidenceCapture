import CryptoKit
import Foundation
import SQLite3

struct LocalEvidenceRecord: Codable, Sendable {
    let evidenceID: String
    let capturedAt: String
    let localTimestamp: String
    let complianceArea: String
    let controlID: String
    let controlTitle: String
    let title: String
    let system: String
    let environment: String
    let assessmentPeriod: String
    let owner: String
    let reviewer: String
    let reviewStatus: String
    let reviewNotes: String
    let tags: [String]
    let jiraIssueKey: String?
    let sourceURL: String?
    let safetyStatus: String
    let sha256: String
    let uploaded: Bool
    let lifecycleValid: Bool
}

struct LocalEvidenceSummary: Codable, Sendable {
    let total: Int
    let approved: Int
    let needsReview: Int
    let uploaded: Int
    let integrityFailures: Int
    let auditEvents: Int
}

struct LocalEvidenceQuery: Sendable {
    var search = ""
    var complianceArea = ""
    var controlID = ""
    var reviewStatus = ""
}

enum LocalEvidenceIndexFailure: LocalizedError {
    case database(String)

    var errorDescription: String? {
        switch self {
        case .database(let detail): return "The local evidence index could not be updated. \(detail)"
        }
    }
}

final class LocalEvidenceIndex: @unchecked Sendable {
    private let lock = NSLock()
    private var database: OpaquePointer?
    private let auditKey: SymmetricKey

    init(databaseURL: URL, auditKeyData: Data) throws {
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(databaseURL.path, &handle, flags, nil) == SQLITE_OK, let handle else {
            let detail = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "SQLite could not open the index."
            if let handle { sqlite3_close(handle) }
            throw LocalEvidenceIndexFailure.database(detail)
        }
        database = handle
        auditKey = SymmetricKey(data: auditKeyData)
        sqlite3_busy_timeout(handle, 2_500)
        do {
            try execute("PRAGMA journal_mode = WAL")
            try execute("PRAGMA synchronous = FULL")
            try execute("PRAGMA foreign_keys = ON")
            try execute("PRAGMA trusted_schema = OFF")
            try execute("PRAGMA secure_delete = ON")
            try createSchema()
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: databaseURL.path)
        } catch {
            sqlite3_close(handle)
            database = nil
            throw error
        }
    }

    deinit {
        if let database { sqlite3_close(database) }
    }

    func sync(entries: [CaptureHistoryEntry]) throws {
        try locked {
            try executeUnlocked("BEGIN IMMEDIATE")
            do {
                try executeUnlocked("DELETE FROM evidence_index")
                let sql = """
                    INSERT INTO evidence_index (
                      evidence_id, captured_at, local_timestamp, compliance_area, control_id, control_title,
                      title, system_name, environment, assessment_period, owner, reviewer, review_status,
                      review_notes, tags_json, jira_issue_key, source_url, safety_status, sha256, uploaded,
                      lifecycle_valid, manifest_path, image_path, indexed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                for entry in entries {
                    let lifecycle = entry.lifecycle
                    let valid = EvidenceLifecycleStore.verify(lifecycle, artifactSha256: entry.manifest.sha256)
                    let tags = lifecycle.tags.isEmpty ? (entry.manifest.tags ?? []) : lifecycle.tags
                    let tagsJSON = String(data: try JSONEncoder().encode(tags), encoding: .utf8) ?? "[]"
                    try withStatementUnlocked(sql) { statement in
                        let values: [SQLiteValue] = [
                            .text(entry.manifest.evidenceID), .text(entry.manifest.capturedAt), .text(entry.manifest.localTimestamp),
                            .text(entry.manifest.complianceArea ?? "PCI DSS 4.0.1"), .text(entry.manifest.controlID),
                            .text(entry.manifest.controlTitle ?? ""), .text(entry.manifest.title), .text(entry.manifest.system),
                            .text(entry.manifest.environment), .text(entry.manifest.assessmentPeriod),
                            .text(lifecycle.owner.isEmpty ? (entry.manifest.evidenceOwner ?? "") : lifecycle.owner),
                            .text(lifecycle.reviewer), .text(lifecycle.status.rawValue), .text(lifecycle.reviewNotes),
                            .text(tagsJSON), entry.manifest.jiraIssueKey.map(SQLiteValue.text) ?? .null,
                            entry.manifest.sourceURL.map(SQLiteValue.text) ?? .null,
                            .text(entry.manifest.safetyStatus), .text(entry.manifest.sha256), .integer(entry.isUploaded ? 1 : 0),
                            .integer(valid ? 1 : 0), .text(entry.manifestURL.path), .text(entry.imageURL.path),
                            .text(ISO8601DateFormatter().string(from: Date())),
                        ]
                        try bind(values, to: statement)
                        guard sqlite3_step(statement) == SQLITE_DONE else { throw databaseErrorUnlocked() }
                    }
                }
                try executeUnlocked("COMMIT")
                try executeUnlocked("PRAGMA optimize")
            } catch {
                try? executeUnlocked("ROLLBACK")
                throw error
            }
        }
    }

    func search(_ query: LocalEvidenceQuery, limit: Int = 500) throws -> [LocalEvidenceRecord] {
        try locked {
            let cleanSearch = String(query.search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().prefix(200))
            let like = "%\(cleanSearch)%"
            let sql = """
                SELECT evidence_id, captured_at, local_timestamp, compliance_area, control_id, control_title,
                       title, system_name, environment, assessment_period, owner, reviewer, review_status,
                       review_notes, tags_json, jira_issue_key, source_url, safety_status, sha256, uploaded, lifecycle_valid
                FROM evidence_index
                WHERE (? = '' OR lower(title || ' ' || system_name || ' ' || owner || ' ' || tags_json || ' ' || evidence_id || ' ' || coalesce(jira_issue_key, '') || ' ' || coalesce(source_url, '')) LIKE ?)
                  AND (? = '' OR compliance_area = ?)
                  AND (? = '' OR control_id = ?)
                  AND (? = '' OR review_status = ?)
                ORDER BY captured_at DESC
                LIMIT ?
                """
            return try withStatementUnlocked(sql) { statement in
                try bind([
                    .text(cleanSearch), .text(like), .text(query.complianceArea), .text(query.complianceArea),
                    .text(query.controlID), .text(query.controlID), .text(query.reviewStatus), .text(query.reviewStatus),
                    .integer(Int64(max(1, min(limit, 5_000)))),
                ], to: statement)
                var records: [LocalEvidenceRecord] = []
                while sqlite3_step(statement) == SQLITE_ROW {
                    let tagsData = Data(columnText(statement, 14).utf8)
                    let tags = (try? JSONDecoder().decode([String].self, from: tagsData)) ?? []
                    records.append(LocalEvidenceRecord(
                        evidenceID: columnText(statement, 0), capturedAt: columnText(statement, 1), localTimestamp: columnText(statement, 2),
                        complianceArea: columnText(statement, 3), controlID: columnText(statement, 4), controlTitle: columnText(statement, 5),
                        title: columnText(statement, 6), system: columnText(statement, 7), environment: columnText(statement, 8),
                        assessmentPeriod: columnText(statement, 9), owner: columnText(statement, 10), reviewer: columnText(statement, 11),
                        reviewStatus: columnText(statement, 12), reviewNotes: columnText(statement, 13), tags: tags,
                        jiraIssueKey: sqlite3_column_type(statement, 15) == SQLITE_NULL ? nil : columnText(statement, 15),
                        sourceURL: sqlite3_column_type(statement, 16) == SQLITE_NULL ? nil : columnText(statement, 16),
                        safetyStatus: columnText(statement, 17), sha256: columnText(statement, 18),
                        uploaded: sqlite3_column_int(statement, 19) == 1, lifecycleValid: sqlite3_column_int(statement, 20) == 1
                    ))
                }
                return records
            }
        }
    }

    func summary() throws -> LocalEvidenceSummary {
        try locked {
            let sql = """
                SELECT count(*),
                       sum(CASE WHEN review_status = 'Approved' AND lifecycle_valid = 1 THEN 1 ELSE 0 END),
                       sum(CASE WHEN review_status IN ('Draft', 'In Review') THEN 1 ELSE 0 END),
                       sum(uploaded),
                       sum(CASE WHEN lifecycle_valid = 0 THEN 1 ELSE 0 END)
                FROM evidence_index
                """
            let counts: [Int] = try withStatementUnlocked(sql) { statement in
                guard sqlite3_step(statement) == SQLITE_ROW else { throw databaseErrorUnlocked() }
                return (0..<5).map { Int(sqlite3_column_int64(statement, Int32($0))) }
            }
            let auditCount: Int = try withStatementUnlocked("SELECT count(*) FROM local_audit_events") { statement in
                guard sqlite3_step(statement) == SQLITE_ROW else { throw databaseErrorUnlocked() }
                return Int(sqlite3_column_int64(statement, 0))
            }
            return LocalEvidenceSummary(total: counts[0], approved: counts[1], needsReview: counts[2], uploaded: counts[3], integrityFailures: counts[4], auditEvents: auditCount)
        }
    }

    func recordAudit(action: String, resourceID: String, details: [String: String] = [:]) throws {
        try locked {
            try verifyAuditChainUnlocked()
            let occurredAt = ISO8601DateFormatter().string(from: Date())
            let previousHash: String = try withStatementUnlocked("SELECT event_hash FROM local_audit_events ORDER BY sequence DESC LIMIT 1") { statement in
                sqlite3_step(statement) == SQLITE_ROW ? columnText(statement, 0) : "GENESIS"
            }
            let detailsData = try JSONSerialization.data(withJSONObject: details, options: [.sortedKeys])
            let detailsJSON = String(data: detailsData, encoding: .utf8) ?? "{}"
            let payload = [previousHash, occurredAt, action, resourceID, detailsJSON].map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
            let eventHash = SHA256.hash(data: Data(payload.utf8)).map { String(format: "%02x", $0) }.joined()
            let signature = Data(HMAC<SHA256>.authenticationCode(for: Data(eventHash.utf8), using: auditKey)).base64EncodedString()
            try withStatementUnlocked("INSERT INTO local_audit_events (occurred_at, action, resource_id, details_json, previous_hash, event_hash, signature) VALUES (?, ?, ?, ?, ?, ?, ?)") { statement in
                try bind([.text(occurredAt), .text(action), .text(resourceID), .text(detailsJSON), .text(previousHash), .text(eventHash), .text(signature)], to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw databaseErrorUnlocked() }
            }
        }
    }

    func verifyAuditChain() throws -> Bool {
        try locked {
            do { try verifyAuditChainUnlocked(); return true }
            catch { return false }
        }
    }

    private func createSchema() throws {
        try execute("""
            CREATE TABLE IF NOT EXISTS evidence_index (
              evidence_id TEXT PRIMARY KEY,
              captured_at TEXT NOT NULL,
              local_timestamp TEXT NOT NULL,
              compliance_area TEXT NOT NULL,
              control_id TEXT NOT NULL,
              control_title TEXT NOT NULL,
              title TEXT NOT NULL,
              system_name TEXT NOT NULL,
              environment TEXT NOT NULL,
              assessment_period TEXT NOT NULL,
              owner TEXT NOT NULL,
              reviewer TEXT NOT NULL,
              review_status TEXT NOT NULL,
              review_notes TEXT NOT NULL,
              tags_json TEXT NOT NULL,
              jira_issue_key TEXT,
              source_url TEXT,
              safety_status TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              uploaded INTEGER NOT NULL CHECK (uploaded IN (0, 1)),
              lifecycle_valid INTEGER NOT NULL CHECK (lifecycle_valid IN (0, 1)),
              manifest_path TEXT NOT NULL,
              image_path TEXT NOT NULL,
              indexed_at TEXT NOT NULL
            )
            """)
        try? execute("ALTER TABLE evidence_index ADD COLUMN source_url TEXT")
        try execute("CREATE INDEX IF NOT EXISTS idx_evidence_framework_control ON evidence_index(compliance_area, control_id, captured_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS idx_evidence_review_status ON evidence_index(review_status, captured_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS local_audit_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              occurred_at TEXT NOT NULL,
              action TEXT NOT NULL,
              resource_id TEXT NOT NULL,
              details_json TEXT NOT NULL,
              previous_hash TEXT NOT NULL,
              event_hash TEXT NOT NULL UNIQUE,
              signature TEXT NOT NULL
            )
            """)
        try execute("CREATE TRIGGER IF NOT EXISTS local_audit_no_update BEFORE UPDATE ON local_audit_events BEGIN SELECT RAISE(ABORT, 'local audit events are immutable'); END")
        try execute("CREATE TRIGGER IF NOT EXISTS local_audit_no_delete BEFORE DELETE ON local_audit_events BEGIN SELECT RAISE(ABORT, 'local audit events are immutable'); END")
    }

    private func verifyAuditChainUnlocked() throws {
        try withStatementUnlocked("SELECT sequence, occurred_at, action, resource_id, details_json, previous_hash, event_hash, signature FROM local_audit_events ORDER BY sequence") { statement in
            var expectedSequence: Int64 = 1
            var previousHash = "GENESIS"
            while sqlite3_step(statement) == SQLITE_ROW {
                let sequence = sqlite3_column_int64(statement, 0)
                let occurredAt = columnText(statement, 1)
                let action = columnText(statement, 2)
                let resourceID = columnText(statement, 3)
                let detailsJSON = columnText(statement, 4)
                let recordedPrevious = columnText(statement, 5)
                let eventHash = columnText(statement, 6)
                let signature = columnText(statement, 7)
                let payload = [recordedPrevious, occurredAt, action, resourceID, detailsJSON].map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
                let expectedHash = SHA256.hash(data: Data(payload.utf8)).map { String(format: "%02x", $0) }.joined()
                let expectedSignature = Data(HMAC<SHA256>.authenticationCode(for: Data(eventHash.utf8), using: auditKey)).base64EncodedString()
                guard sequence == expectedSequence, recordedPrevious == previousHash,
                      constantTimeEqual(eventHash, expectedHash), constantTimeEqual(signature, expectedSignature) else {
                    throw LocalEvidenceIndexFailure.database("The immutable local audit chain failed verification.")
                }
                expectedSequence += 1
                previousHash = eventHash
            }
        }
    }

    private func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        guard left.utf8.count == right.utf8.count else { return false }
        var difference: UInt8 = 0
        for (leftByte, rightByte) in zip(left.utf8, right.utf8) { difference |= leftByte ^ rightByte }
        return difference == 0
    }

    private func locked<T>(_ operation: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }

    private func execute(_ sql: String) throws {
        try locked { try executeUnlocked(sql) }
    }

    private func executeUnlocked(_ sql: String) throws {
        guard let database else { throw LocalEvidenceIndexFailure.database("The database is closed.") }
        var errorMessage: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(database, sql, nil, nil, &errorMessage) == SQLITE_OK else {
            let detail = errorMessage.map { String(cString: $0) } ?? String(cString: sqlite3_errmsg(database))
            sqlite3_free(errorMessage)
            throw LocalEvidenceIndexFailure.database(detail)
        }
    }

    private func withStatementUnlocked<T>(_ sql: String, _ operation: (OpaquePointer) throws -> T) throws -> T {
        guard let database else { throw LocalEvidenceIndexFailure.database("The database is closed.") }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw databaseErrorUnlocked() }
        defer { sqlite3_finalize(statement) }
        return try operation(statement)
    }

    private enum SQLiteValue {
        case text(String)
        case integer(Int64)
        case null
    }

    private func bind(_ values: [SQLiteValue], to statement: OpaquePointer) throws {
        for (offset, value) in values.enumerated() {
            let index = Int32(offset + 1)
            let result: Int32
            switch value {
            case .text(let text): result = sqlite3_bind_text(statement, index, text, -1, sqliteTransient)
            case .integer(let integer): result = sqlite3_bind_int64(statement, index, integer)
            case .null: result = sqlite3_bind_null(statement, index)
            }
            guard result == SQLITE_OK else { throw databaseErrorUnlocked() }
        }
    }

    private func columnText(_ statement: OpaquePointer, _ index: Int32) -> String {
        sqlite3_column_text(statement, index).map { String(cString: $0) } ?? ""
    }

    private func databaseErrorUnlocked() -> LocalEvidenceIndexFailure {
        guard let database else { return .database("The database is closed.") }
        return .database(String(cString: sqlite3_errmsg(database)))
    }
}

private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
