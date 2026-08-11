import Foundation
import CryptoKit

struct ReleaseInfo: Decodable, Sendable {
    let version: String
    let downloadUrl: URL?
    let sha256: String?
    let notes: String
}

enum UploadFailure: LocalizedError {
    case notConfigured
    case invalidServer
    case rejected(String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "Connect this Mac from Settings using a device token created in Scopeproof Connections."
        case .invalidServer: return "The configured Scopeproof server URL is invalid."
        case .rejected(let message): return "Scopeproof rejected the upload: \(message)"
        case .invalidResponse: return "Scopeproof returned an invalid upload response."
        }
    }
}

actor UploadService {
    private var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.3.1" }

    func upload(_ capture: CaptureResult, serverURL: URL?) async throws -> URL {
        guard let token = KeychainStore.readToken(), !token.isEmpty else { throw UploadFailure.notConfigured }
        guard let serverURL, Self.isAllowedServerURL(serverURL) else { throw UploadFailure.invalidServer }
        let image = try Data(contentsOf: capture.imageURL)
        let manifest = try Data(contentsOf: capture.manifestURL)
        let manifestModel = try JSONDecoder().decode(CaptureManifest.self, from: manifest)
        let boundary = "ScopeproofBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        var request = URLRequest(url: serverURL.appendingPathComponent("api/native/evidence"))
        request.httpMethod = "POST"
        request.timeoutInterval = 60
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(appVersion, forHTTPHeaderField: "X-Scopeproof-Version")
        request.setValue(Self.uploadSignature(token: token, manifest: manifest, image: image), forHTTPHeaderField: "X-Scopeproof-Upload-Signature")
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.httpBody = multipart(boundary: boundary, files: [
            ("screenshot", manifestModel.screenshotFilename, "image/png", image),
            ("manifest", capture.manifestURL.lastPathComponent, "application/json", manifest),
        ])
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw UploadFailure.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw UploadFailure.rejected(String(describing: body?["error"] ?? "HTTP \(http.statusCode)"))
        }
        guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any], body["receipt"] != nil else { throw UploadFailure.invalidResponse }
        let receiptURL = capture.manifestURL.deletingPathExtension().appendingPathExtension("receipt.json")
        try data.write(to: receiptURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
        return receiptURL
    }

    func checkForUpdates(serverURL: URL?) async throws -> ReleaseInfo {
        guard let token = KeychainStore.readToken(), !token.isEmpty else { throw UploadFailure.notConfigured }
        guard let serverURL, Self.isAllowedServerURL(serverURL) else { throw UploadFailure.invalidServer }
        var request = URLRequest(url: serverURL.appendingPathComponent("api/native/releases/latest"))
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(appVersion, forHTTPHeaderField: "X-Scopeproof-Version")
        request.timeoutInterval = 20
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw UploadFailure.invalidResponse }
        return try JSONDecoder().decode(ReleaseInfo.self, from: data)
    }

    nonisolated static func isAllowedServerURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else { return false }
        if scheme == "https" { return true }
        return scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(host)
    }

    nonisolated static func uploadSignature(token: String, manifest: Data, image: Data) -> String {
        let manifestDigest = SHA256.hash(data: manifest).map { String(format: "%02x", $0) }.joined()
        let imageDigest = SHA256.hash(data: image).map { String(format: "%02x", $0) }.joined()
        let payload = Data("scopeproof-native-upload-v1\n\(manifestDigest)\n\(imageDigest)".utf8)
        let signature = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: Data(token.utf8)))
        return signature.map { String(format: "%02x", $0) }.joined()
    }

    private func multipart(boundary: String, files: [(String, String, String, Data)]) -> Data {
        var data = Data()
        let append = { (value: String) in data.append(Data(value.utf8)) }
        for (name, filename, contentType, bytes) in files {
            append("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(name)\"; filename=\"\(filename.replacingOccurrences(of: "\"", with: ""))\"\r\nContent-Type: \(contentType)\r\n\r\n")
            data.append(bytes)
            append("\r\n")
        }
        append("--\(boundary)--\r\n")
        return data
    }
}
