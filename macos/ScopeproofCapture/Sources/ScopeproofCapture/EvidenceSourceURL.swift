import Foundation

enum EvidenceSourceURL {
    static let maximumLength = 2_048

    static func sanitized(_ rawValue: String?) -> URL? {
        guard let rawValue else { return nil }
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= maximumLength,
              !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }),
              var components = URLComponents(string: value),
              ["http", "https"].contains(components.scheme?.lowercased() ?? ""),
              let host = components.host, !host.isEmpty else { return nil }

        components.scheme = components.scheme?.lowercased()
        components.host = host.lowercased()
        components.user = nil
        components.password = nil
        components.queryItems = components.queryItems?.map { item in
            guard let itemValue = item.value, shouldRedact(name: item.name, value: itemValue) else { return item }
            return URLQueryItem(name: item.name, value: "REDACTED")
        }
        if let fragment = components.fragment, SensitiveDataScanner.detectedKinds(in: fragment).isEmpty == false {
            components.fragment = "REDACTED"
        }
        guard let sanitized = components.url, sanitized.absoluteString.utf8.count <= maximumLength else { return nil }
        return sanitized
    }

    static func isValidOrEmpty(_ rawValue: String) -> Bool {
        rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || sanitized(rawValue) != nil
    }

    private static func shouldRedact(name: String, value: String) -> Bool {
        let normalizedName = name.lowercased().replacingOccurrences(of: #"[^a-z0-9]"#, with: "", options: .regularExpression)
        let sensitiveNames = [
            "accesstoken", "apikey", "apitoken", "assertion", "auth", "authorization", "clientsecret",
            "code", "credential", "idtoken", "jwt", "key", "password", "passwd", "pwd", "relaystate",
            "samlresponse", "secret", "session", "sessionid", "sid", "sig", "signature", "token",
        ]
        return sensitiveNames.contains(where: { normalizedName == $0 || normalizedName.hasSuffix($0) }) ||
            !SensitiveDataScanner.detectedKinds(in: value).isEmpty
    }
}
