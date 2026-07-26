import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import CodewireKit

final class OIDCFlowTests: XCTestCase {
    // RFC 7636 Appendix B KAT:
    //   verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    func testPKCEVerifierChallenge_RFC7636_KAT() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = OIDCFlow.computeS256Challenge(verifier: verifier)
        XCTAssertEqual(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testGeneratedVerifier_IsURLSafe_And43Chars() {
        let v = OIDCFlow.generateVerifier()
        XCTAssertEqual(v.count, 43)
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        XCTAssertTrue(v.unicodeScalars.allSatisfy { allowed.contains($0) })
    }

    func testBuildAuthorizeURL_IncludesRequiredParams() {
        let url = OIDCFlow.buildAuthorizeURL(
            baseURL: URL(string: "https://codewire.sh")!,
            clientID: "ios-app",
            redirectURI: "codewire://callback",
            codeChallenge: "abc123",
            state: "state-xyz"
        )
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let items = Dictionary(uniqueKeysWithValues:
            (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(items["client_id"], "ios-app")
        XCTAssertEqual(items["redirect_uri"], "codewire://callback")
        XCTAssertEqual(items["code_challenge"], "abc123")
        XCTAssertEqual(items["code_challenge_method"], "S256")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["state"], "state-xyz")
    }

    func testExchangeCode_parsesTokenResponse() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/oauth/token")!
        session.responses[url.absoluteString] = (
            Data(#"""
            {"access_token":"acc","refresh_token":"ref","expires_in":3600,"token_type":"Bearer"}
            """#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let token = try await OIDCFlow.exchangeCode(
            baseURL: URL(string: "https://codewire.sh")!,
            clientID: "ios-app",
            redirectURI: "codewire://cb",
            code: "the-code",
            verifier: "the-verifier",
            session: session
        )
        XCTAssertEqual(token.accessToken, "acc")
        XCTAssertEqual(token.refreshToken, "ref")
        XCTAssertGreaterThan(token.expiresAt, Date())

        XCTAssertEqual(session.recordedRequests.count, 1)
        let req = session.recordedRequests.first!
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"),
                       "application/x-www-form-urlencoded")
    }

    func testRefreshToken_returnsNewToken() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/oauth/token")!
        session.responses[url.absoluteString] = (
            Data(#"{"access_token":"new","refresh_token":"ref2","expires_in":3600}"#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let token = try await OIDCFlow.refresh(
            baseURL: URL(string: "https://codewire.sh")!,
            clientID: "ios-app",
            refreshToken: "old-ref",
            session: session
        )
        XCTAssertEqual(token.accessToken, "new")
        XCTAssertEqual(token.refreshToken, "ref2")
    }
}
