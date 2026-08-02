import XCTest
@testable import CodewireKit

final class CodewireEndpointTests: XCTestCase {
    func testEndpointsHaveExactOriginsAndCredentialIsolation() {
        XCTAssertEqual(CodewireEndpoint.development.baseURL.absoluteString, "https://codewire-dev.sh")
        XCTAssertEqual(CodewireEndpoint.production.baseURL.absoluteString, "https://codewire.sh")
        XCTAssertNotEqual(
            CodewireEndpoint.development.keychainAccount,
            CodewireEndpoint.production.keychainAccount
        )
    }

    func testBuildDefaultMatchesConfiguration() {
        #if DEBUG
        XCTAssertEqual(CodewireEndpoint.defaultForBuild, .development)
        #else
        XCTAssertEqual(CodewireEndpoint.defaultForBuild, .production)
        #endif
    }
}
