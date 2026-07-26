import XCTest
import Foundation
@testable import CodewireKit

final class CodewireKitSmokeTests: XCTestCase {
    func testTokenInfoRoundTripsThroughJSON() throws {
        let token = TokenInfo(
            accessToken: "access-token",
            refreshToken: "refresh-token",
            expiresAt: Date(timeIntervalSince1970: 1_767_600_000)
        )
        let encoded = try JSONEncoder().encode(token)
        let decoded = try JSONDecoder().decode(TokenInfo.self, from: encoded)

        XCTAssertEqual(decoded, token)
    }
}
