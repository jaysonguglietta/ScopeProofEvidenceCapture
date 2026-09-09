import CryptoKit
import Foundation

enum RepositorySBOMFormat: String, CaseIterable, Sendable {
    case cycloneDX = "cyclonedx_json"
    case spdx = "spdx_json"

    var displayName: String {
        switch self {
        case .cycloneDX: return "CycloneDX 1.6 JSON"
        case .spdx: return "SPDX 2.3 JSON"
        }
    }

    var filenameLabel: String { self == .cycloneDX ? "cyclonedx" : "spdx" }
}

struct RepositorySBOMRequest: Sendable {
    let repositoryURL: String
    var token: String
    let ref: String
    let format: RepositorySBOMFormat
}

struct RepositorySBOMResult: Sendable {
    let data: Data
    let suggestedFilename: String
    let repository: String
    let requestedRef: String
    let resolvedCommit: String
    let manifestPaths: [String]
    let componentCount: Int
    let directDependencyCount: Int
    let artifactSHA256: String
    let coverage: [RepositoryManifestCoverage]
    var coverageComplete: Bool { coverage.allSatisfy(\.complete) }
}

struct RepositoryManifestCoverage: Codable, Sendable {
    let path: String
    let parser: String
    let complete: Bool
    let componentCount: Int
    let warnings: [String]
}

struct RepositorySBOMInventory: Sendable {
    let components: [RepositorySBOMComponent]
    let coverage: [RepositoryManifestCoverage]
    var complete: Bool { !coverage.isEmpty && coverage.allSatisfy(\.complete) }
}

struct RepositorySBOMComponent: Hashable, Sendable {
    let name: String
    let version: String
    let ecosystem: String
    let purl: String
    var direct: Bool
    var manifests: [String]
    var directKnown = false
}

enum RepositorySBOMFailure: LocalizedError, Equatable {
    case invalidRepositoryURL
    case invalidToken
    case invalidRef
    case authenticationFailed
    case repositoryOrRefNotFound
    case providerFailure(Int)
    case invalidProviderResponse
    case responseTooLarge
    case treeTooLarge
    case manifestTooLarge(String)
    case unsafeManifest(String)
    case noSupportedManifests
    case noComponents
    case tooManyComponents
    case unsupportedManifestVersion(String)
    case manifestTooComplex(String)

    var errorDescription: String? {
        switch self {
        case .invalidRepositoryURL: return "Enter an exact GitHub URL such as https://github.com/owner/repository."
        case .invalidToken: return "Enter a short-lived GitHub token containing 20–512 non-whitespace ASCII characters."
        case .invalidRef: return "Enter a branch, tag, or commit using ordinary Git ref characters."
        case .authenticationFailed: return "GitHub rejected the token. Confirm it is active, selected for this repository, and has Metadata: read and Contents: read access."
        case .repositoryOrRefNotFound: return "GitHub could not find that repository or ref with the supplied token."
        case .providerFailure(let status): return "GitHub returned HTTP \(status). No retry was attempted; submit a fresh one-time request."
        case .invalidProviderResponse: return "GitHub returned an invalid or unexpected response."
        case .responseTooLarge: return "GitHub returned more data than the bounded local scan permits."
        case .treeTooLarge: return "The repository tree is truncated or exceeds the 5,000-entry safety limit."
        case .manifestTooLarge(let path): return "Dependency manifest \(path) exceeds the local scan safety limit."
        case .unsafeManifest(let path): return "Dependency manifest \(path) is malformed or is not safe UTF-8 text."
        case .noSupportedManifests: return "No supported dependency lockfiles were found at this repository ref."
        case .noComponents: return "Supported lockfiles were found, but no pinned dependency versions could be parsed."
        case .tooManyComponents: return "The repository dependency inventory exceeds the 5,000-component safety limit."
        case .unsupportedManifestVersion(let path): return "Dependency manifest \(path) uses an unsupported lockfile version. npm versions 1, 2 and 3 are supported."
        case .manifestTooComplex(let path): return "Dependency manifest \(path) exceeds the 100-level nesting safety limit."
        }
    }
}

actor RepositorySBOMService {
    static let supportedManifestNames: Set<String> = [
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pipfile.lock", "poetry.lock", "cargo.lock", "go.sum",
        "gemfile.lock", "composer.lock",
    ]

    private static let maximumTreeBytes = 8 * 1024 * 1024
    private static let maximumTreeEntries = 5_000
    private static let maximumManifestCount = 100
    private static let maximumManifestBytes = 2 * 1024 * 1024
    private static let maximumSelectedBytes = 8 * 1024 * 1024
    private static let maximumComponents = 5_000
    private static let generatorName = "scopeproof-native-static-sbom"
    private static let generatorVersion = "1.1.0"

    private struct CommitResponse: Decodable { let sha: String }
    private struct TreeResponse: Decodable { let tree: [TreeEntry]; let truncated: Bool }
    private struct TreeEntry: Decodable { let path: String; let mode: String; let type: String; let sha: String; let size: Int? }
    private struct BlobResponse: Decodable { let content: String; let encoding: String; let size: Int }
    private struct RepositoryIdentity: Sendable { let owner: String; let name: String; var fullName: String { "\(owner)/\(name)" } }
    private struct Manifest: Sendable { let path: String; let data: Data; let text: String }

    static func parseRepositoryURL(_ raw: String) throws -> (owner: String, repository: String) {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value == raw, value.count <= 300, !value.contains("%"), let parts = URLComponents(string: value),
              parts.scheme == "https", parts.host?.lowercased() == "github.com", parts.port == nil,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil else {
            throw RepositorySBOMFailure.invalidRepositoryURL
        }
        let segments = parts.path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard segments.count == 2 else { throw RepositorySBOMFailure.invalidRepositoryURL }
        let owner = segments[0]
        let repository = segments[1].hasSuffix(".git") ? String(segments[1].dropLast(4)) : segments[1]
        guard owner.range(of: #"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$"#, options: .regularExpression) != nil, !owner.contains("--"),
              repository.range(of: #"^[A-Za-z0-9._-]{1,100}$"#, options: .regularExpression) != nil,
              repository != ".", repository != ".." else { throw RepositorySBOMFailure.invalidRepositoryURL }
        return (owner, repository)
    }

    static func validateToken(_ token: String) throws {
        guard token.count >= 20, token.count <= 512,
              token.unicodeScalars.allSatisfy({ $0.value >= 33 && $0.value <= 126 }) else {
            throw RepositorySBOMFailure.invalidToken
        }
    }

    static func validateRef(_ ref: String) throws -> String {
        let value = ref.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.count <= 200, value.range(of: #"^[A-Za-z0-9._/-]+$"#, options: .regularExpression) != nil,
              !value.hasPrefix("/"), !value.hasSuffix("/"), !value.contains(".."),
              !value.contains("//"), !value.contains("@{") else { throw RepositorySBOMFailure.invalidRef }
        return value
    }

    func generate(_ request: RepositorySBOMRequest) async throws -> RepositorySBOMResult {
        let parsed = try Self.parseRepositoryURL(request.repositoryURL)
        try Self.validateToken(request.token)
        let ref = try Self.validateRef(request.ref)
        let repository = RepositoryIdentity(owner: parsed.owner, name: parsed.repository)

        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 120
        configuration.httpAdditionalHeaders = ["Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Scopeproof-Native-SBOM"]
        let session = URLSession(configuration: configuration, delegate: RejectRedirectDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        let commitURL = try apiURL(["repos", repository.owner, repository.name, "commits", ref])
        let commit: CommitResponse = try await githubJSON(commitURL, token: request.token, maximumBytes: 2 * 1024 * 1024, session: session)
        guard commit.sha.range(of: #"^[a-f0-9]{40}$"#, options: .regularExpression) != nil else { throw RepositorySBOMFailure.invalidProviderResponse }

        var treeComponents = URLComponents(url: try apiURL(["repos", repository.owner, repository.name, "git", "trees", commit.sha]), resolvingAgainstBaseURL: false)
        treeComponents?.queryItems = [URLQueryItem(name: "recursive", value: "1")]
        guard let treeURL = treeComponents?.url else { throw RepositorySBOMFailure.invalidProviderResponse }
        let tree: TreeResponse = try await githubJSON(treeURL, token: request.token, maximumBytes: Self.maximumTreeBytes, session: session)
        guard !tree.truncated, tree.tree.count <= Self.maximumTreeEntries else { throw RepositorySBOMFailure.treeTooLarge }

        let selected = tree.tree.filter { entry in
            entry.type == "blob" && Self.supportedManifestNames.contains(Self.basename(entry.path))
        }.sorted { $0.path < $1.path }
        guard !selected.isEmpty else { throw RepositorySBOMFailure.noSupportedManifests }
        guard selected.count <= Self.maximumManifestCount else { throw RepositorySBOMFailure.treeTooLarge }
        var declaredBytes = 0
        for entry in selected {
            guard entry.path.count <= 1_024, !entry.path.contains("\0"), entry.sha.range(of: #"^[a-f0-9]{40}$"#, options: .regularExpression) != nil else { throw RepositorySBOMFailure.invalidProviderResponse }
            if let size = entry.size {
                guard size <= Self.maximumManifestBytes else { throw RepositorySBOMFailure.manifestTooLarge(entry.path) }
                declaredBytes += size
            }
        }
        guard declaredBytes <= Self.maximumSelectedBytes else { throw RepositorySBOMFailure.responseTooLarge }

        var manifests: [Manifest] = []
        var receivedBytes = 0
        for entry in selected {
            try Task.checkCancellation()
            let blobURL = try apiURL(["repos", repository.owner, repository.name, "git", "blobs", entry.sha])
            let blob: BlobResponse = try await githubJSON(blobURL, token: request.token, maximumBytes: 3 * 1024 * 1024, session: session)
            guard blob.encoding == "base64", blob.size <= Self.maximumManifestBytes else { throw RepositorySBOMFailure.manifestTooLarge(entry.path) }
            let normalized = blob.content.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "")
            guard let data = Data(base64Encoded: normalized), data.count == blob.size, !data.contains(0),
                  let text = String(data: data, encoding: .utf8) else { throw RepositorySBOMFailure.unsafeManifest(entry.path) }
            receivedBytes += data.count
            guard receivedBytes <= Self.maximumSelectedBytes else { throw RepositorySBOMFailure.responseTooLarge }
            manifests.append(Manifest(path: entry.path, data: data, text: text))
        }

        let inventory = try Self.parseInventory(manifests.map { ($0.path, $0.text) })
        let components = inventory.components
        guard !components.isEmpty else { throw RepositorySBOMFailure.noComponents }
        let generatedAt = ISO8601DateFormatter().string(from: Date())
        let manifestSetSHA256 = Self.manifestSetDigest(manifests)
        let document = Self.buildDocument(
            format: request.format,
            repository: repository.fullName,
            commit: commit.sha,
            generatedAt: generatedAt,
            manifestSetSHA256: manifestSetSHA256,
            manifests: manifests.map(\.path),
            components: components, coverage: inventory.coverage
        )
        guard JSONSerialization.isValidJSONObject(document) else { throw RepositorySBOMFailure.invalidProviderResponse }
        var data = try JSONSerialization.data(withJSONObject: document, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        data.append(0x0A)
        let artifactSHA256 = Self.sha256(data)
        return RepositorySBOMResult(
            data: data,
            suggestedFilename: "\(repository.owner)-\(repository.name)-\(commit.sha.prefix(12))-\(request.format.filenameLabel).json",
            repository: repository.fullName,
            requestedRef: ref,
            resolvedCommit: commit.sha,
            manifestPaths: manifests.map(\.path),
            componentCount: components.count,
            directDependencyCount: components.filter { $0.directKnown && $0.direct }.count,
            artifactSHA256: artifactSHA256, coverage: inventory.coverage
        )
    }

    private func githubJSON<T: Decodable>(_ url: URL, token: String, maximumBytes: Int, session: URLSession) async throws -> T {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 60)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.url?.scheme == "https", http.url?.host?.lowercased() == "api.github.com" else {
            throw RepositorySBOMFailure.invalidProviderResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw RepositorySBOMFailure.authenticationFailed
        case 404: throw RepositorySBOMFailure.repositoryOrRefNotFound
        default: throw RepositorySBOMFailure.providerFailure(http.statusCode)
        }
        if let length = http.value(forHTTPHeaderField: "Content-Length").flatMap(Int.init), length > maximumBytes { throw RepositorySBOMFailure.responseTooLarge }
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 256 * 1024))
        for try await byte in bytes {
            if data.count >= maximumBytes { throw RepositorySBOMFailure.responseTooLarge }
            data.append(byte)
        }
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw RepositorySBOMFailure.invalidProviderResponse }
    }

    private func apiURL(_ components: [String]) throws -> URL {
        guard components.allSatisfy({ !$0.isEmpty }) else { throw RepositorySBOMFailure.invalidProviderResponse }
        var parts = URLComponents()
        parts.scheme = "https"
        parts.host = "api.github.com"
        parts.percentEncodedPath = "/" + components.map(Self.encode).joined(separator: "/")
        guard let url = parts.url, url.scheme == "https", url.host == "api.github.com" else { throw RepositorySBOMFailure.invalidProviderResponse }
        return url
    }

    static func parseManifests(_ manifests: [(path: String, text: String)]) throws -> [RepositorySBOMComponent] {
        try parseInventory(manifests).components
    }

    static func parseInventory(_ manifests: [(path: String, text: String)]) throws -> RepositorySBOMInventory {
        guard manifests.count <= maximumManifestCount else { throw RepositorySBOMFailure.treeTooLarge }
        var found: [RepositorySBOMComponent] = []
        var coverage: [RepositoryManifestCoverage] = []
        for manifest in manifests {
            guard manifest.text.utf8.count <= maximumManifestBytes else { throw RepositorySBOMFailure.manifestTooLarge(manifest.path) }
            guard !manifest.text.contains("\0") else { throw RepositorySBOMFailure.unsafeManifest(manifest.path) }
            let parser = basename(manifest.path)
            guard supportedManifestNames.contains(parser) else { throw RepositorySBOMFailure.unsafeManifest(manifest.path) }
            var warnings: [String] = []
            let parsed: [RepositorySBOMComponent]
            switch parser {
            case "package-lock.json", "npm-shrinkwrap.json": parsed = try packageLock(path: manifest.path, text: manifest.text, warnings: &warnings)
            case "pipfile.lock", "composer.lock": parsed = try jsonDependencies(path: manifest.path, text: manifest.text)
            case "cargo.lock": parsed = blockPackages(path: manifest.path, text: manifest.text, ecosystem: "cargo")
            case "poetry.lock": parsed = blockPackages(path: manifest.path, text: manifest.text, ecosystem: "PyPI")
            default: parsed = lineManifest(path: manifest.path, text: manifest.text)
            }
            if !["package-lock.json", "npm-shrinkwrap.json"].contains(parser) {
                warnings.append("Static parser coverage is partial for this format. Independently validated replacement inventory is required before assessor approval.")
            }
            if parsed.isEmpty { warnings.append("No pinned components were extracted from this recognized manifest.") }
            coverage.append(RepositoryManifestCoverage(path: manifest.path, parser: parser,
                complete: warnings.isEmpty, componentCount: parsed.count, warnings: Array(Set(warnings)).sorted()))
            found += parsed
            if found.count > maximumComponents * 2 { throw RepositorySBOMFailure.tooManyComponents }
        }
        var merged: [String: RepositorySBOMComponent] = [:]
        for item in found {
            if var existing = merged[item.purl] {
                existing.direct = existing.direct || item.direct
                existing.directKnown = existing.direct || (existing.directKnown && item.directKnown)
                existing.manifests = Array(Set(existing.manifests + item.manifests)).sorted()
                merged[item.purl] = existing
            } else { merged[item.purl] = item }
        }
        let result = merged.values.sorted { $0.purl < $1.purl }
        guard result.count <= maximumComponents else { throw RepositorySBOMFailure.tooManyComponents }
        return RepositorySBOMInventory(components: result, coverage: coverage)
    }

    private static func packageLock(path: String, text: String, warnings: inout [String]) throws -> [RepositorySBOMComponent] {
        let data = try jsonObject(text, path: path)
        guard let version = data["lockfileVersion"] as? Int, [1, 2, 3].contains(version) else {
            throw RepositorySBOMFailure.unsupportedManifestVersion(path)
        }
        var found: [RepositorySBOMComponent] = []
        func add(_ name: String, value: [String: Any], direct: Bool) throws {
            guard let pinned = value["version"] as? String,
                  pinned.range(of: #"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"#, options: .regularExpression) != nil else {
                warnings.append("Non-registry, unpinned or malformed dependency versions were not inventoried.")
                return
            }
            guard var item = component(name: name, version: pinned, ecosystem: "npm", direct: direct, manifest: path) else {
                warnings.append("A dependency has an invalid component identity."); return
            }
            item.directKnown = version != 1
            found.append(item)
            if found.count > maximumComponents * 2 { throw RepositorySBOMFailure.tooManyComponents }
        }
        if version == 1 {
            func visit(_ raw: Any?, depth: Int) throws {
                guard depth <= 100 else { throw RepositorySBOMFailure.manifestTooComplex(path) }
                guard let dependencies = raw as? [String: Any] else {
                    warnings.append("The legacy lockfile has no valid dependency collection."); return
                }
                for (name, value) in dependencies {
                    guard let entry = value as? [String: Any] else { warnings.append("A dependency entry is malformed."); continue }
                    // Hoisted v1 dependencies do not identify directness without package.json.
                    try add(name, value: entry, direct: false)
                    if let children = entry["dependencies"] { try visit(children, depth: depth + 1) }
                }
            }
            try visit(data["dependencies"], depth: 0)
            return found
        }
        let packages = data["packages"] as? [String: Any]
        guard packages != nil else { throw RepositorySBOMFailure.unsafeManifest(path) }
        if packages?[""] as? [String: Any] == nil { warnings.append("The npm packages map has no valid root dependency metadata.") }
        let root = (packages?[""] as? [String: Any]) ?? data
        let directNames = Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap { key in
            (root[key] as? [String: Any])?.keys.map { $0 } ?? []
        })
        if let packages {
            for (location, raw) in packages where !location.isEmpty {
                guard let value = raw as? [String: Any] else { warnings.append("A packages-map entry is malformed."); continue }
                if value["link"] as? Bool == true { warnings.append("Workspace or linked dependencies require additional reviewed inventory."); continue }
                var name = value["name"] as? String ?? ""
                if name.isEmpty {
                    if let range = location.range(of: "/node_modules/", options: .backwards) { name = String(location[range.upperBound...]) }
                    else { name = location.replacingOccurrences(of: "node_modules/", with: "", options: .anchored) }
                }
                try add(name, value: value, direct: directNames.contains(name) && location == "node_modules/\(name)")
            }
        }
        return found
    }

    private static func jsonDependencies(path: String, text: String) throws -> [RepositorySBOMComponent] {
        let data = try jsonObject(text, path: path)
        if basename(path) == "pipfile.lock" {
            return ["default", "develop"].flatMap { group in
                ((data[group] as? [String: Any]) ?? [:]).compactMap { name, raw in
                    component(name: name, version: (raw as? [String: Any])?["version"], ecosystem: "PyPI", direct: true, manifest: path)
                }
            }
        }
        let direct = Set((data["require"] as? [String: Any])?.keys.map { $0 } ?? [])
        return ["packages", "packages-dev"].flatMap { group in
            ((data[group] as? [[String: Any]]) ?? []).compactMap { value in
                let name = value["name"] as? String ?? ""
                return component(name: name, version: value["version"], ecosystem: "composer", direct: direct.contains(name), manifest: path)
            }
        }
    }

    private static func blockPackages(path: String, text: String, ecosystem: String) -> [RepositorySBOMComponent] {
        let expression = try! NSRegularExpression(pattern: #"(?m)^\s*\[\[package\]\]\s*$"#)
        let marked = expression.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "\u{001E}")
        return marked.components(separatedBy: "\u{001E}").dropFirst().compactMap { block in
            let name = firstCapture(#"(?m)^name\s*=\s*[\"']([^\"']+)[\"']"#, in: block)
            let version = firstCapture(#"(?m)^version\s*=\s*[\"']([^\"']+)[\"']"#, in: block)
            return component(name: name ?? "", version: version, ecosystem: ecosystem, direct: false, manifest: path)
        }
    }

    private static func lineManifest(path: String, text: String) -> [RepositorySBOMComponent] {
        let name = basename(path)
        var found: [RepositorySBOMComponent] = []
        let lines = text.components(separatedBy: .newlines)
        if name == "requirements.txt" {
            for line in lines {
                if let match = captures(#"^\s*([A-Za-z0-9_.-]+)\s*={2,3}\s*([^\s;#]+)"#, in: line), let item = component(name: match[0], version: match[1], ecosystem: "PyPI", direct: true, manifest: path) { found.append(item) }
            }
        } else if name == "go.sum" {
            for line in lines {
                let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
                guard fields.count >= 2, !fields[1].hasSuffix("/go.mod"), let item = component(name: fields[0], version: fields[1], ecosystem: "golang", direct: false, manifest: path) else { continue }
                found.append(item)
            }
        } else if name == "gemfile.lock" {
            var inSpecs = false
            for line in lines {
                if line.range(of: #"^\s{2}specs:"#, options: .regularExpression) != nil { inSpecs = true; continue }
                if inSpecs && line.range(of: #"^\S"#, options: .regularExpression) != nil { inSpecs = false }
                if inSpecs, let match = captures(#"^\s{4}([^ (]+) \(([^ )]+)\)"#, in: line), let item = component(name: match[0], version: match[1], ecosystem: "gem", direct: false, manifest: path) { found.append(item) }
            }
        } else if name == "yarn.lock" {
            let expression = try! NSRegularExpression(pattern: #"\n(?=[^ \n][^\n]*:\n)"#)
            let marked = expression.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "\u{001E}")
            let blocks = marked.components(separatedBy: "\u{001E}")
            for block in blocks {
                guard let header = firstCapture(#"^([^\n]+):\n"#, in: block), let version = firstCapture(#"(?m)^\s{2}version\s+[\"']?([^\"'\s]+)"#, in: block) else { continue }
                let first = header.split(separator: ",", maxSplits: 1).first.map(String.init)?.trimmingCharacters(in: CharacterSet(charactersIn: " \"'")) ?? ""
                let packageName: String
                if first.hasPrefix("@"), let marker = first.dropFirst().firstIndex(of: "@") { packageName = String(first[..<marker]) }
                else { packageName = first.split(separator: "@", maxSplits: 1).first.map(String.init) ?? first }
                if let item = component(name: packageName, version: version, ecosystem: "npm", direct: false, manifest: path) { found.append(item) }
            }
        } else if name == "pnpm-lock.yaml" {
            for line in lines {
                if let match = captures(#"^\s{2,}[\"']?/?((?:@[^/@\s]+/)?[^@:'\"\s]+)@([^:'\"\s(]+)[\"']?:"#, in: line), let item = component(name: match[0], version: match[1], ecosystem: "npm", direct: false, manifest: path) { found.append(item) }
            }
        }
        return found
    }

    private static func component(name rawName: String, version rawVersion: Any?, ecosystem: String, direct: Bool, manifest: String) -> RepositorySBOMComponent? {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        var version = String(describing: rawVersion ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        while version.hasPrefix("=") { version.removeFirst() }
        guard !name.isEmpty, !version.isEmpty, name.count <= 300, version.count <= 200,
              (name + version).unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }) else { return nil }
        return RepositorySBOMComponent(name: name, version: version, ecosystem: ecosystem, purl: purl(ecosystem: ecosystem, name: name, version: version), direct: direct, manifests: [manifest])
    }

    private static func purl(ecosystem: String, name: String, version: String) -> String {
        let type = ["npm": "npm", "PyPI": "pypi", "cargo": "cargo", "golang": "golang", "gem": "gem", "composer": "composer"][ecosystem] ?? ecosystem.lowercased()
        return "pkg:\(type)/\(name.split(separator: "/", omittingEmptySubsequences: false).map { encode(String($0)) }.joined(separator: "/"))@\(encode(version))"
    }

    static func buildDocument(format: RepositorySBOMFormat, repository: String, commit: String, generatedAt: String, manifestSetSHA256: String, manifests: [String], components: [RepositorySBOMComponent], coverage: [RepositoryManifestCoverage]) -> [String: Any] {
        let complete = !coverage.isEmpty && coverage.allSatisfy(\.complete)
        let coverageJSON = String(data: (try? JSONEncoder().encode(coverage)) ?? Data(), encoding: .utf8) ?? "[]"
        if format == .spdx {
            let packages: [[String: Any]] = components.enumerated().map { index, item in
                ["SPDXID": "SPDXRef-Package-\(index)-\(safeIdentifier(item.name))", "name": item.name, "versionInfo": item.version, "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
                 "externalRefs": [["referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": item.purl]],
                 "annotations": [["annotationType": "OTHER", "annotator": "Tool: \(generatorName)-\(generatorVersion)", "annotationDate": generatedAt, "comment": "direct=\(item.directKnown ? String(item.direct) : "unknown"); manifests=\(item.manifests.joined(separator: ","))"]]]
            }
            let repositoryPackage: [String: Any] = ["SPDXID": "SPDXRef-Repository", "name": repository, "versionInfo": commit, "downloadLocation": "https://github.com/\(repository)", "filesAnalyzed": false]
            let relationships: [[String: Any]] = [["spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Repository"]] + packages.compactMap { package in
                guard let identifier = package["SPDXID"] as? String else { return nil }
                return ["spdxElementId": "SPDXRef-Repository", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier]
            }
            return ["spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "\(repository)-\(commit.prefix(12))-sbom",
                    "documentNamespace": "https://scopeproof.local/sbom/\(UUID().uuidString.lowercased())",
                    "creationInfo": ["created": generatedAt, "creators": ["Tool: \(generatorName)-\(generatorVersion)"], "comment": "Repository https://github.com/\(repository); commit \(commit); manifest-set SHA-256 \(manifestSetSHA256); manifests \(manifests.joined(separator: ",")); manifest coverage complete=\(complete); coverage=\(coverageJSON). Static manifest inventory does not prove the installed/runtime dependency graph."],
                    "packages": [repositoryPackage] + packages,
                    "relationships": relationships]
        }
        let properties: [[String: String]] = [
            ["name": "scopeproof:repository", "value": "https://github.com/\(repository)"],
            ["name": "scopeproof:commit", "value": commit],
            ["name": "scopeproof:manifestSetSha256", "value": manifestSetSHA256],
            ["name": "scopeproof:manifests", "value": manifests.joined(separator: ",")],
            ["name": "scopeproof:collectionMethod", "value": "github-git-data-api-static"],
            ["name": "scopeproof:manifestCoverageComplete", "value": String(complete)],
            ["name": "scopeproof:manifestCoverage", "value": coverageJSON],
            ["name": "scopeproof:limitation", "value": "Static manifest inventory does not prove the installed/runtime dependency graph."],
        ]
        return ["bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:\(UUID().uuidString.lowercased())", "version": 1,
                "metadata": ["timestamp": generatedAt, "tools": ["components": [["type": "application", "name": generatorName, "version": generatorVersion]]],
                             "component": ["type": "application", "name": repository, "version": commit, "bom-ref": "repository:\(repository)@\(commit)"], "properties": properties],
                "components": components.map { item in ["type": "library", "name": item.name, "version": item.version, "purl": item.purl, "bom-ref": item.purl,
                                                          "properties": [["name": "scopeproof:direct", "value": item.directKnown ? String(item.direct) : "unknown"], ["name": "scopeproof:manifests", "value": item.manifests.joined(separator: ",")]]] }]
    }

    private static func jsonObject(_ text: String, path: String) throws -> [String: Any] {
        guard let data = text.data(using: .utf8), let value = try? JSONSerialization.jsonObject(with: data), let object = value as? [String: Any] else { throw RepositorySBOMFailure.unsafeManifest(path) }
        return object
    }

    private static func manifestSetDigest(_ manifests: [Manifest]) -> String {
        var material = Data()
        for manifest in manifests.sorted(by: { $0.path < $1.path }) {
            material.append(Data(manifest.path.utf8)); material.append(0); material.append(Data(sha256(manifest.data).utf8)); material.append(0x0A)
        }
        return sha256(material)
    }

    private static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func basename(_ path: String) -> String { path.split(separator: "/").last.map { $0.lowercased() } ?? "" }
    private static func encode(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? "" }
    private static func safeIdentifier(_ value: String) -> String { String(value.map { $0.isLetter || $0.isNumber || ".-".contains($0) ? $0 : "-" }.prefix(80)) }

    private static func firstCapture(_ pattern: String, in value: String) -> String? { captures(pattern, in: value)?.first }
    private static func captures(_ pattern: String, in value: String) -> [String]? {
        guard let expression = try? NSRegularExpression(pattern: pattern), let match = expression.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)), match.numberOfRanges > 1 else { return nil }
        return (1..<match.numberOfRanges).compactMap { Range(match.range(at: $0), in: value).map { String(value[$0]) } }
    }
}

private final class RejectRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
