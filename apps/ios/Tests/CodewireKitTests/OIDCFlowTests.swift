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
        let verifier = OIDCFlow.generateVerifier()
        XCTAssertEqual(verifier.count, 43)
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        XCTAssertTrue(verifier.unicodeScalars.allSatisfy { allowed.contains($0) })
    }

    func testNativeAuthorization_usesExactPublicClientAndCallback() {
        let request = OIDCFlow.startNativeAuthorization(baseURL: URL(string: "https://codewire.sh")!)
        let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false)!
        let items = Dictionary(uniqueKeysWithValues:
            (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })

        XCTAssertEqual(request.url.path, "/api/oauth/authorize")
        XCTAssertEqual(items["client_id"], "codewire-ios")
        XCTAssertEqual(items["redirect_uri"], "sh.codewire.ios:/oauth/callback")
        XCTAssertEqual(items["scope"], "openid profile email offline_access codewire.api")
        XCTAssertEqual(items["code_challenge"], OIDCFlow.computeS256Challenge(verifier: request.verifier))
        XCTAssertEqual(items["code_challenge_method"], "S256")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["state"], request.state)
    }

    func testAuthorizationCode_requiresExactCallbackAndState() throws {
        let callback = URL(string: "sh.codewire.ios:/oauth/callback?code=the-code&state=state-xyz")!
        XCTAssertEqual(
            try OIDCFlow.authorizationCode(from: callback, expectedState: "state-xyz"),
            "the-code"
        )

        XCTAssertThrowsError(
            try OIDCFlow.authorizationCode(
                from: URL(string: "sh.codewire.ios:/wrong?code=the-code&state=state-xyz")!,
                expectedState: "state-xyz"
            )
        ) { error in
            XCTAssertEqual(error as? OAuthFlowError, .invalidCallback)
        }
        XCTAssertThrowsError(
            try OIDCFlow.authorizationCode(from: callback, expectedState: "other-state")
        ) { error in
            XCTAssertEqual(error as? OAuthFlowError, .stateMismatch)
        }
        XCTAssertThrowsError(
            try OIDCFlow.authorizationCode(
                from: URL(string: "sh.codewire.ios:/oauth/callback?error=access_denied&state=other-state")!,
                expectedState: "state-xyz"
            )
        ) { error in
            XCTAssertEqual(error as? OAuthFlowError, .stateMismatch)
        }
    }

    func testExchangeCode_usesPermanentOAuthEndpointAndEncodesForm() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/oauth/token")!
        session.responses[url.absoluteString] = (
            Data(#"""
            {"access_token":"acc","refresh_token":"ref","expires_in":3600,"token_type":"Bearer"}
            """#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let token = try await OIDCFlow.exchangeNativeAuthorizationCode(
            baseURL: URL(string: "https://codewire.sh")!,
            code: "a code&more",
            verifier: "the-verifier",
            session: session
        )
        XCTAssertEqual(token.accessToken, "acc")
        XCTAssertEqual(token.refreshToken, "ref")
        XCTAssertGreaterThan(token.expiresAt, Date())

        XCTAssertEqual(session.recordedRequests.count, 1)
        let request = session.recordedRequests[0]
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-www-form-urlencoded")
        let body = String(data: request.httpBody ?? Data(), encoding: .utf8)!
        let form = URLComponents(string: "https://form.invalid/?\(body)")!
        let values = Dictionary(uniqueKeysWithValues:
            (form.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(values["client_id"], "codewire-ios")
        XCTAssertEqual(values["redirect_uri"], "sh.codewire.ios:/oauth/callback")
        XCTAssertEqual(values["code"], "a code&more")
    }

    func testRefreshToken_returnsNewToken() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/oauth/token")!
        session.responses[url.absoluteString] = (
            Data(#"{"access_token":"new","refresh_token":"ref2","expires_in":3600}"#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let token = try await OIDCFlow.refresh(
            baseURL: URL(string: "https://codewire.sh")!,
            clientID: "codewire-ios",
            refreshToken: "old-ref",
            session: session
        )
        XCTAssertEqual(token.accessToken, "new")
        XCTAssertEqual(token.refreshToken, "ref2")
    }
}
