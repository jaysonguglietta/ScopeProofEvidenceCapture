@preconcurrency import LocalAuthentication
import Darwin
import Foundation

struct LocalReviewerIdentity: Codable, Equatable, Sendable {
    let subjectID: String
    let displayName: String
    let authenticationMethod: String
    let authenticatedAt: String

    static func captureWorkflow(owner: String, at date: Date = Date()) -> LocalReviewerIdentity {
        LocalReviewerIdentity(
            subjectID: "device-capture-workflow",
            displayName: owner.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? "Scopeproof capture workflow" : owner,
            authenticationMethod: "capture-workflow",
            authenticatedAt: ISO8601DateFormatter().string(from: date)
        )
    }

    static func testIdentity(_ name: String, at date: Date = Date()) -> LocalReviewerIdentity {
        LocalReviewerIdentity(
            subjectID: "test-reviewer", displayName: name,
            authenticationMethod: "test-override",
            authenticatedAt: ISO8601DateFormatter().string(from: date)
        )
    }
}

enum LocalReviewerAuthorizationFailure: LocalizedError {
    case denied
    case invalidIdentity

    var errorDescription: String? {
        switch self {
        case .denied:
            return "macOS user authentication was canceled or denied. The review decision was not saved."
        case .invalidIdentity:
            return "Scopeproof could not bind the review decision to the authenticated macOS account."
        }
    }
}

enum LocalReviewerAuthorizer {
    @MainActor
    static func authorize(reason: String) async throws -> LocalReviewerIdentity {
        let context = LAContext()
        context.localizedReason = reason
        let succeeded = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Bool, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: success) }
            }
        }
        guard succeeded else { throw LocalReviewerAuthorizationFailure.denied }
        let account = NSUserName().trimmingCharacters(in: .whitespacesAndNewlines)
        let display = NSFullUserName().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !account.isEmpty else { throw LocalReviewerAuthorizationFailure.invalidIdentity }
        return LocalReviewerIdentity(
            subjectID: "macos-uid:\(getuid()):\(account)",
            displayName: display.isEmpty ? account : display,
            authenticationMethod: "macos-device-owner-authentication",
            authenticatedAt: ISO8601DateFormatter().string(from: Date())
        )
    }
}
