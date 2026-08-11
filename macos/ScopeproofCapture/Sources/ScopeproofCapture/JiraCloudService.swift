import Foundation

struct JiraCloudConnection: Decodable, Sendable {
    let connected: Bool
    let configured: Bool
    let siteURL: String?
    let siteName: String?
    let allowedProjects: [String]?
    let status: String?

    private enum CodingKeys: String, CodingKey {
        case connected, configured, siteURL = "siteUrl", siteName, allowedProjects, status
    }
}

struct JiraCloudIssue: Decodable, Sendable {
    let key: String
    let summary: String
    let status: String
    let projectKey: String
    let url: URL
}

struct JiraCloudUploadReceipt: Decodable, Sendable {
    let receiptID: String
    let evidenceID: String
    let issueKey: String
    let siteURL: String
    let uploadedAt: String
    let receiptSHA256: String
    let signature: String

    private enum CodingKeys: String, CodingKey {
        case receiptID = "receiptId"
        case evidenceID = "evidenceId"
        case issueKey, siteURL = "siteUrl", uploadedAt, receiptSHA256 = "receiptSha256", signature
    }
}

enum JiraCloudFailure: LocalizedError {
    case invalidServer
    case notConnected
    case rejected(String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .invalidServer: return "The configured Scopeproof server URL is invalid."
        case .notConnected: return "Connect this Mac to Scopeproof, then authorize Jira Cloud under Scopeproof web → Connections."
        case .rejected(let message): return message
        case .invalidResponse: return "Scopeproof returned an invalid Jira Cloud response."
        }
    }
}

actor JiraCloudService {
    private struct ConnectionEnvelope: Decodable { let connection: JiraCloudConnection }
    private struct IssueEnvelope: Decodable { let issue: JiraCloudIssue }
    private struct ReceiptEnvelope: Decodable { let receipt: JiraCloudUploadReceipt }
    private var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.3.1" }

    func connection(serverURL: URL?) async throws -> JiraCloudConnection {
        let request = try authorizedRequest(serverURL: serverURL, path: "api/native/jira/status")
        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(ConnectionEnvelope.self, data: data, response: response).connection
    }

    func issue(_ issueKey: String, serverURL: URL?) async throws -> JiraCloudIssue {
        var request = try authorizedRequest(serverURL: serverURL, path: "api/native/jira/issue")
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["issueKey": issueKey])
        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(IssueEnvelope.self, data: data, response: response).issue
    }

    func upload(entry: CaptureHistoryEntry, serverURL: URL?) async throws -> URL {
        guard let token = KeychainStore.readToken(), !token.isEmpty else { throw JiraCloudFailure.notConnected }
        let lifecycleURL = EvidenceLifecycleStore.url(for: entry.manifestURL)
        let screenshot = try Data(contentsOf: entry.imageURL)
        let manifest = try Data(contentsOf: entry.manifestURL)
        let lifecycle = try Data(contentsOf: lifecycleURL)
        let files: [(String, String, String, Data)] = [
            ("screenshot", entry.imageURL.lastPathComponent, "image/png", screenshot),
            ("manifest", entry.manifestURL.lastPathComponent, "application/json", manifest),
            ("lifecycle", lifecycleURL.lastPathComponent, "application/json", lifecycle),
        ]
        let boundary = "ScopeproofJiraBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        var request = try authorizedRequest(serverURL: serverURL, path: "api/native/jira/upload")
        request.httpMethod = "POST"
        request.timeoutInterval = 90
        request.setValue(UploadService.uploadSignature(token: token, manifest: manifest, image: screenshot), forHTTPHeaderField: "X-Scopeproof-Upload-Signature")
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.httpBody = multipart(boundary: boundary, files: files)
        let (data, response) = try await URLSession.shared.data(for: request)
        _ = try decode(ReceiptEnvelope.self, data: data, response: response)
        let receiptURL = entry.jiraReceiptURL
        try data.write(to: receiptURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
        return receiptURL
    }

    private func authorizedRequest(serverURL: URL?, path: String) throws -> URLRequest {
        guard let token = KeychainStore.readToken(), !token.isEmpty else { throw JiraCloudFailure.notConnected }
        guard let serverURL, UploadService.isAllowedServerURL(serverURL) else { throw JiraCloudFailure.invalidServer }
        var request = URLRequest(url: serverURL.appendingPathComponent(path))
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(appVersion, forHTTPHeaderField: "X-Scopeproof-Version")
        request.timeoutInterval = 20
        return request
    }

    private func decode<T: Decodable>(_ type: T.Type, data: Data, response: URLResponse) throws -> T {
        guard let http = response as? HTTPURLResponse else { throw JiraCloudFailure.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw JiraCloudFailure.rejected(String(describing: body?["error"] ?? "Jira Cloud request failed (HTTP \(http.statusCode))."))
        }
        guard let value = try? JSONDecoder().decode(type, from: data) else { throw JiraCloudFailure.invalidResponse }
        return value
    }

    private func multipart(boundary: String, files: [(String, String, String, Data)]) -> Data {
        var data = Data()
        let append = { (value: String) in data.append(Data(value.utf8)) }
        for (name, filename, contentType, bytes) in files {
            let safeName = filename.replacingOccurrences(of: "\"", with: "")
            append("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(name)\"; filename=\"\(safeName)\"\r\nContent-Type: \(contentType)\r\n\r\n")
            data.append(bytes)
            append("\r\n")
        }
        append("--\(boundary)--\r\n")
        return data
    }
}
