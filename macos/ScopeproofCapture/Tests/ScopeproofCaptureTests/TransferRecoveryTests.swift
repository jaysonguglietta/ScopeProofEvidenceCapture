import Foundation
import Testing
@testable import ScopeproofCapture

struct TransferRecoveryTests {
    @Test func recoveryNeverInventsDeliveryOrRetainsRawErrors() {
        #expect(!TransferRecoveryState.pending.running)
        #expect(TransferRecoveryState.running.running)
        #expect(TransferRecoveryState.cancelled.summary.contains("uncertain"))
        let privateFailure = NSError(domain: "https://secret.example?token=private", code: 403, userInfo: [NSLocalizedDescriptionKey: "secret-access-token"])
        let safe = TransferRecoveryState.failureCode(privateFailure)
        #expect(!safe.contains("secret"))
        #expect(TransferRecoveryState.failureCode(NSError(domain: NSURLErrorDomain, code: -1009)) == "network -1009")
        #expect(TransferRecoveryState.failed(safe).summary.contains("Local evidence is preserved"))
    }
}
