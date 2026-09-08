import CryptoKit
import Foundation
import Testing
@testable import ScopeproofCapture

struct NativeAWSUploadTestRefreshStore: HostedRefreshTokenStoring {
    func load(for configuration: HostedOAuthConfiguration) throws -> HostedRefreshCredential? { try HostedRefreshCredential(configuration: configuration, refreshToken: String(repeating: "synthetic", count: 10)) }
    func save(refreshToken: String, for configuration: HostedOAuthConfiguration, storedAt: Date) throws {}
    func delete(for configuration: HostedOAuthConfiguration) throws {}
}

actor NativeAWSUploadFixture {
    let profile: AWSCollectorProfile
    let page: AWSCollectorAssessmentPage
    let image: Data
    var requestData: Data?
    var putCount = 0
    var intentCount = 0
    private var status = "QUARANTINED"
    private var approvedBy: String?
    init(profile: AWSCollectorProfile, page: AWSCollectorAssessmentPage, image: Data) { self.profile = profile; self.page = page; self.image = image }
    func setStatus(_ value: String, approvedBy: String? = nil) { status = value; self.approvedBy = approvedBy }
    func put(request: URLRequest, digest: String) throws {
        #expect(request.httpMethod == "PUT" && request.httpBody == image)
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(digest == LocalEvidenceArchive.digest(image))
        putCount += 1
    }
    func response(request: URLRequest, expectedURL: URL, maximum: Int) throws -> (Data, HTTPURLResponse) {
        #expect(request.url == expectedURL && maximum <= 512 * 1024)
        let data: Data
        switch expectedURL.path {
        case "/oauth2/token": data = try JSONSerialization.data(withJSONObject: ["access_token": String(repeating: "synthetic", count: 10), "token_type": "Bearer"])
        case "/v1/collector/me": data = try JSONEncoder().encode(profile)
        case "/v1/customer/collector-assessments/search": data = try JSONEncoder().encode(page)
        case "/v1/upload-intents":
            intentCount += 1
            guard let suppliedBody = request.httpBody else { throw AWSCollectorFailure.invalidResponse }
            requestData = suppliedBody
            let body = try #require(try JSONSerialization.jsonObject(with: requestData!) as? [String: Any])
            let evidence = try #require(body["evidenceId"] as? String)
            let intentID = "upl_" + String(repeating: "1", count: 32)
            let digest = LocalEvidenceArchive.digest(image)
            let context = try JSONSerialization.data(withJSONObject: ["scopeproofPurpose": "quarantine", "scopeproofTenantId": profile.tenantId]).base64EncodedString()
            let headers = ["content-length": String(image.count), "content-type": "image/png", "x-amz-checksum-sha256": Data(SHA256.hash(data: image)).base64EncodedString(),
                "x-amz-meta-control-id": "8.3.1", "x-amz-meta-evidence-id": evidence, "x-amz-meta-expected-sha256": digest,
                "x-amz-meta-upload-nonce-digest": String(repeating: "2", count: 64), "x-amz-meta-tenant-id": profile.tenantId,
                "x-amz-meta-upload-intent-id": intentID, "x-amz-server-side-encryption": "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                "x-amz-server-side-encryption-context": context]
            var url = URLComponents(string: "https://synthetic-bucket.s3.us-east-1.amazonaws.com")!
            let now = Date()
            let dateFormatter = DateFormatter(); dateFormatter.locale = Locale(identifier: "en_US_POSIX"); dateFormatter.timeZone = TimeZone(secondsFromGMT: 0); dateFormatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
            let signedAt = dateFormatter.string(from: now)
            url.path = "/tenants/\(profile.tenantId)/controls/8.3.1/quarantine/\(intentID).upload"
            url.queryItems = [URLQueryItem(name: "X-Amz-Algorithm", value: "AWS4-HMAC-SHA256"), .init(name: "X-Amz-Credential", value: "SYNTHETIC/\(signedAt.prefix(8))/us-east-1/s3/aws4_request"),
                .init(name: "X-Amz-Date", value: signedAt), .init(name: "X-Amz-Expires", value: "300"), .init(name: "X-Amz-Security-Token", value: "synthetic-session-token"),
                .init(name: "X-Amz-Signature", value: String(repeating: "3", count: 64)), .init(name: "X-Amz-SignedHeaders", value: (Array(headers.keys) + ["host"]).sorted().joined(separator: ";"))]
            data = try JSONEncoder().encode(AWSCollectorUploadIntent(uploadIntentId: intentID, evidenceId: evidence,
                expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(300)), upload: .init(method: "PUT", url: url.url!.absoluteString, requiredHeaders: headers)))
        case "/v1/customer/collector-evidence/status":
            let body = try #require(try JSONSerialization.jsonObject(with: requestData!) as? [String: Any])
            data = try JSONEncoder().encode(AWSCollectorEvidenceStatus(tenantId: profile.tenantId, evidenceId: body["evidenceId"] as! String,
                assessmentId: body["assessmentId"] as! String, controlId: body["controlId"] as! String, systemName: body["systemName"] as! String,
                title: body["title"] as! String, status: status, revision: 0, createdBy: profile.userId, approvedBy: approvedBy,
                expiresAt: "2030-01-01T00:00:00.000Z", capturedAt: body["capturedAt"] as! String, checksumSha256: LocalEvidenceArchive.digest(image), byteSize: image.count))
        default: throw AWSCollectorFailure.invalidResponse
        }
        return (data, HTTPURLResponse(url: expectedURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
    }
}
