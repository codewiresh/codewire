import XCTest
@testable import CodewireKit

final class TokenStoreTests: XCTestCase {
    func testRoundtrip() throws {
        let store = InMemoryTokenStore()
        let token = TokenInfo(
            accessToken: "acc-123",
            refreshToken: "ref-456",
            expiresAt: Date().addingTimeInterval(3600)
        )
        try store.save(token)
        let loaded = try store.load()
        XCTAssertEqual(loaded?.accessToken, "acc-123")
        XCTAssertEqual(loaded?.refreshToken, "ref-456")
    }

    func testDeleteClearsStore() throws {
        let store = InMemoryTokenStore()
        try store.save(TokenInfo(accessToken: "a", refreshToken: nil, expiresAt: Date()))
        try store.delete()
        XCTAssertNil(try store.load())
    }

    func testLoadWhenEmpty() throws {
        let store = InMemoryTokenStore()
        XCTAssertNil(try store.load())
    }
}
