import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Bounded backend responses")
struct BackendResponseLimitTests {
    @Test func acceptsExactLimitAndEmptyResponse() async throws {
        let exact = AsyncStream<UInt8> { continuation in
            for byte in [UInt8(1), 2, 3] { continuation.yield(byte) }
            continuation.finish()
        }
        #expect(try await BackendHTTP.collect(exact, maximumBytes: 3) == Data([1, 2, 3]))
        let empty = AsyncStream<UInt8> { $0.finish() }
        #expect(try await BackendHTTP.collect(empty, maximumBytes: 3).isEmpty)
    }

    @Test func rejectsOneByteOverLimitAndInvalidLimit() async throws {
        let excess = AsyncStream<UInt8> { continuation in
            for _ in 0..<4 { continuation.yield(1) }
            continuation.finish()
        }
        await #expect(throws: BackendHTTP.ResponseFailure.exceedsByteLimit) {
            try await BackendHTTP.collect(excess, maximumBytes: 3)
        }
        await #expect(throws: BackendHTTP.ResponseFailure.invalidLimit) {
            try await BackendHTTP.collect(AsyncStream<UInt8> { $0.finish() }, maximumBytes: 0)
        }
    }

    @Test func rejectsWrongRequestOriginBeforeNetworking() async throws {
        let request = URLRequest(url: URL(string: "http://127.0.0.1:9001/private")!)
        await #expect(throws: UploadFailure.self) {
            try await BackendHTTP.data(for: request, audience: URL(string: "http://127.0.0.1:9002")!, maximumBytes: 8)
        }
    }
}
