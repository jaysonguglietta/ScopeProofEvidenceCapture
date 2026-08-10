@preconcurrency import AppKit
import CoreGraphics
import Vision

enum SensitiveKind: String, Codable, Sendable {
    case pan
    case awsAccessKey = "aws_access_key"
    case githubToken = "github_token"
    case apiToken = "api_token"
    case jwt
    case privateKey = "private_key"
    case authorization
}

struct SensitiveFinding: Codable, Sendable {
    let kind: SensitiveKind
    let count: Int
}

struct ScanResult {
    let image: CGImage
    let findings: [SensitiveFinding]
    let redactedRegions: Int
}

enum SensitiveDataScanner {
    static func scanAndRedact(_ image: CGImage) throws -> ScanResult {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        try VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
        let observations = request.results ?? []
        var counts: [SensitiveKind: Int] = [:]
        var boxes: [CGRect] = []
        for observation in observations {
            guard let text = observation.topCandidates(1).first?.string else { continue }
            let kinds = detectedKinds(in: text)
            guard !kinds.isEmpty else { continue }
            kinds.forEach { counts[$0, default: 0] += 1 }
            boxes.append(observation.boundingBox)
        }
        guard !boxes.isEmpty else { return ScanResult(image: image, findings: [], redactedRegions: 0) }
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: image.width, height: image.height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw CaptureFailure.imageProcessingFailed }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        context.setFillColor(NSColor.black.cgColor)
        for box in boxes {
            let rect = CGRect(x: box.minX * CGFloat(image.width), y: box.minY * CGFloat(image.height), width: box.width * CGFloat(image.width), height: box.height * CGFloat(image.height)).insetBy(dx: -8, dy: -5)
            context.fill(rect)
        }
        guard let redacted = context.makeImage() else { throw CaptureFailure.imageProcessingFailed }
        let findings = counts.sorted { $0.key.rawValue < $1.key.rawValue }.map { SensitiveFinding(kind: $0.key, count: $0.value) }
        return ScanResult(image: redacted, findings: findings, redactedRegions: boxes.count)
    }

    static func detectedKinds(in text: String) -> Set<SensitiveKind> {
        var result = Set<SensitiveKind>()
        if containsPAN(text) { result.insert(.pan) }
        let patterns: [(SensitiveKind, String)] = [
            (.awsAccessKey, #"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"#),
            (.githubToken, #"\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b"#),
            (.jwt, #"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#),
            (.authorization, #"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+\S+"#),
            (.apiToken, #"(?i)\b(?:api[_-]?key|api[_-]?token|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_./+~-]{16,}"#),
            (.privateKey, #"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#),
        ]
        for (kind, pattern) in patterns where text.range(of: pattern, options: .regularExpression) != nil { result.insert(kind) }
        return result
    }

    private static func containsPAN(_ text: String) -> Bool {
        guard let expression = try? NSRegularExpression(pattern: #"\b(?:\d[ -]*?){13,19}\b"#) else { return false }
        let range = NSRange(text.startIndex..., in: text)
        return expression.matches(in: text, range: range).contains { match in
            guard let candidateRange = Range(match.range, in: text) else { return false }
            return luhn(String(text[candidateRange]))
        }
    }

    private static func luhn(_ candidate: String) -> Bool {
        let digits = candidate.compactMap { $0.wholeNumberValue }
        guard (13...19).contains(digits.count), Set(digits).count > 1 else { return false }
        let sum = digits.reversed().enumerated().reduce(0) { total, pair in
            var value = pair.element
            if pair.offset % 2 == 1 { value *= 2; if value > 9 { value -= 9 } }
            return total + value
        }
        return sum % 10 == 0
    }
}
