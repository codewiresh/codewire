import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto

public enum OIDCFlow {
    /// Generates a 32-byte random verifier and returns its base64url encoding.
    /// The result is 43 characters of [A-Za-z0-9\-_].
    public static func generateVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<bytes.count {
            bytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        return base64URL(Data(bytes))
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
        state: String
    ) -> URL {
        var comps = URLComponents(
            url: baseURL.appendingPathComponent("/oauth/authorize"),
            resolvingAgainstBaseURL: false
        )!
        comps.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "scope", value: "openid profile email"),
        ]
        return comps.url!
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
        var req = URLRequest(url: baseURL.appendingPathComponent("/oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded",
                     forHTTPHeaderField: "Content-Type")
        let body = [
            "grant_type=authorization_code",
            "code=\(code)",
            "redirect_uri=\(redirectURI)",
            "client_id=\(clientID)",
            "code_verifier=\(verifier)",
        ].joined(separator: "&")
        req.httpBody = body.data(using: .utf8)
        let (data, _) = try await session.data(for: req)
        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        return TokenInfo(
            accessToken: decoded.access_token,
            refreshToken: decoded.refresh_token,
            expiresAt: Date().addingTimeInterval(TimeInterval(decoded.expires_in))
        )
    }

    public static func refresh(
        baseURL: URL,
        clientID: String,
        refreshToken: String,
        session: HTTPSession = URLSession.shared
    ) async throws -> TokenInfo {
        var req = URLRequest(url: baseURL.appendingPathComponent("/oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded",
                     forHTTPHeaderField: "Content-Type")
        let body = [
            "grant_type=refresh_token",
            "refresh_token=\(refreshToken)",
            "client_id=\(clientID)",
        ].joined(separator: "&")
        req.httpBody = body.data(using: .utf8)
        let (data, _) = try await session.data(for: req)
        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        return TokenInfo(
            accessToken: decoded.access_token,
            refreshToken: decoded.refresh_token,
            expiresAt: Date().addingTimeInterval(TimeInterval(decoded.expires_in))
        )
    }
}
