import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto

public enum OAuthFlowError: Error, Equatable, LocalizedError {
    case invalidCallback
    case stateMismatch
    case authorizationDenied
    case tokenRequestFailed(Int)
    case invalidTokenResponse

    public var errorDescription: String? {
        switch self {
        case .invalidCallback:
            return "The sign-in response was invalid. Please try again."
        case .stateMismatch:
            return "The sign-in response could not be verified. Please try again."
        case .authorizationDenied:
            return "Sign in was not completed."
        case .tokenRequestFailed:
            return "Unable to complete sign in. Please try again."
        case .invalidTokenResponse:
            return "The sign-in response was invalid. Please try again."
        }
    }
}

public enum OIDCFlow {
    public static let nativeClientID = "codewire-ios"
    public static let nativeRedirectURI = "sh.codewire.ios:/oauth/callback"
    public static let nativeCallbackScheme = "sh.codewire.ios"
    public static let nativeScopes = "openid profile email offline_access codewire.api"

    public struct AuthorizationRequest: Sendable {
        public let url: URL
        public let verifier: String
        public let state: String

        public init(url: URL, verifier: String, state: String) {
            self.url = url
            self.verifier = verifier
            self.state = state
        }
    }

    /// Generates a 32-byte random verifier and returns its base64url encoding.
    /// The result is 43 characters of [A-Za-z0-9\-_].
    public static func generateVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<bytes.count {
            bytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        return base64URL(Data(bytes))
    }

    /// Starts the native system-browser authorization-code flow. The verifier
    /// and state are intentionally kept only in the caller's active session.
    public static func startNativeAuthorization(baseURL: URL) -> AuthorizationRequest {
        let verifier = generateVerifier()
        let state = generateVerifier()
        return AuthorizationRequest(
            url: buildAuthorizeURL(
                baseURL: baseURL,
                clientID: nativeClientID,
                redirectURI: nativeRedirectURI,
                codeChallenge: computeS256Challenge(verifier: verifier),
                state: state,
                scope: nativeScopes
            ),
            verifier: verifier,
            state: state
        )
    }

    /// SHA256(verifier) base64url-encoded — the S256 code_challenge per RFC 7636.
    public static func computeS256Challenge(verifier: String) -> String {
        let hash = SHA256.hash(data: Data(verifier.utf8))
        return base64URL(Data(hash))
    }

    /// Builds the OIDC authorize URL with standard PKCE + OpenID query params.
    public static func buildAuthorizeURL(
        baseURL: URL,
        clientID: String,
        redirectURI: String,
        codeChallenge: String,
        state: String,
        scope: String = nativeScopes
    ) -> URL {
        var comps = URLComponents(
            url: baseURL.appendingPathComponent("api/oauth/authorize"),
            resolvingAgainstBaseURL: false
        )!
        comps.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "scope", value: scope),
        ]
        return comps.url!
    }

    /// Validates the exact custom callback before its authorization code is
    /// exchanged. An arbitrary deep link must never be accepted as OAuth.
    public static func authorizationCode(
        from callbackURL: URL,
        expectedState: String
    ) throws -> String {
        guard callbackURL.scheme?.lowercased() == nativeCallbackScheme,
              callbackURL.host == nil,
              callbackURL.path == "/oauth/callback",
              let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)
        else {
            throw OAuthFlowError.invalidCallback
        }

        let items = components.queryItems ?? []
        let states = items.compactMap { $0.name == "state" ? $0.value : nil }
        guard states.count == 1, let state = states.first
        else {
            throw OAuthFlowError.invalidCallback
        }
        guard state == expectedState else {
            throw OAuthFlowError.stateMismatch
        }
        if items.contains(where: { $0.name == "error" }) {
            throw OAuthFlowError.authorizationDenied
        }
        let codes = items.compactMap { $0.name == "code" ? $0.value : nil }
        guard codes.count == 1, let code = codes.first, !code.isEmpty else {
            throw OAuthFlowError.invalidCallback
        }
        return code
    }

    // MARK: - Internal helpers

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public protocol HTTPSession: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: HTTPSession {
    #if canImport(FoundationNetworking)
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            let task = self.dataTask(with: request) { data, response, error in
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let data = data, let response = response else {
                    continuation.resume(throwing: URLError(.badServerResponse))
                    return
                }
                continuation.resume(returning: (data, response))
            }
            task.resume()
        }
    }
    #endif
}

extension OIDCFlow {
    struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String?
        let expires_in: Int
    }

    public static func exchangeCode(
        baseURL: URL,
        clientID: String,
        redirectURI: String,
        code: String,
        verifier: String,
        session: HTTPSession = URLSession.shared
    ) async throws -> TokenInfo {
        var req = URLRequest(url: baseURL.appendingPathComponent("api/oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded",
                     forHTTPHeaderField: "Content-Type")
        req.httpBody = formData([
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "code_verifier", value: verifier),
        ])
        return try await tokenResponse(for: req, session: session)
    }

    public static func exchangeNativeAuthorizationCode(
        baseURL: URL,
        code: String,
        verifier: String,
        session: HTTPSession = URLSession.shared
    ) async throws -> TokenInfo {
        try await exchangeCode(
            baseURL: baseURL,
            clientID: nativeClientID,
            redirectURI: nativeRedirectURI,
            code: code,
            verifier: verifier,
            session: session
        )
    }

    public static func refresh(
        baseURL: URL,
        clientID: String,
        refreshToken: String,
        session: HTTPSession = URLSession.shared
    ) async throws -> TokenInfo {
        var req = URLRequest(url: baseURL.appendingPathComponent("api/oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded",
                     forHTTPHeaderField: "Content-Type")
        req.httpBody = formData([
            URLQueryItem(name: "grant_type", value: "refresh_token"),
            URLQueryItem(name: "refresh_token", value: refreshToken),
            URLQueryItem(name: "client_id", value: clientID),
        ])
        return try await tokenResponse(for: req, session: session)
    }

    private static func tokenResponse(
        for request: URLRequest,
        session: HTTPSession
    ) async throws -> TokenInfo {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw OAuthFlowError.invalidTokenResponse
        }
        guard (200...299).contains(http.statusCode) else {
            throw OAuthFlowError.tokenRequestFailed(http.statusCode)
        }
        let decoded: TokenResponse
        do {
            decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OAuthFlowError.invalidTokenResponse
        }
        return TokenInfo(
            accessToken: decoded.access_token,
            refreshToken: decoded.refresh_token,
            expiresAt: Date().addingTimeInterval(TimeInterval(decoded.expires_in))
        )
    }

    private static func formData(_ items: [URLQueryItem]) -> Data {
        var components = URLComponents()
        components.queryItems = items
        return Data((components.percentEncodedQuery ?? "").utf8)
    }
}
