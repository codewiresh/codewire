import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum CodewireClientError: Error, Equatable, LocalizedError {
    case unauthorized
    case forbidden
    case notFound
    case serverError(Int)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .unauthorized: return "Session expired. Please sign in again."
        case .forbidden: return "You don't have permission for this action."
        case .notFound: return "Not found."
        case .serverError(let code): return "Server error (\(code)). Try again later."
        case .invalidResponse: return "Unexpected response from server."
        }
    }
}

public actor CodewireClient {
    private let baseURL: URL
    private let session: HTTPSession

    public init(baseURL: URL, session: HTTPSession = URLSession.shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public func listOrganizations(token: String) async throws -> [Organization] {
        try await get(path: "/api/v1/organizations", token: token)
    }

    public func listEnvironments(token: String, orgID: String) async throws -> [Environment] {
        try await get(path: "/api/v1/organizations/\(orgID)/environments", token: token)
    }

    // MARK: - Private

    public func startEnvironment(token: String, orgID: String, envID: String) async throws {
        try await post(path: "/api/v1/organizations/\(orgID)/environments/\(envID)/start", token: token)
    }

    public func stopEnvironment(token: String, orgID: String, envID: String) async throws {
        try await post(path: "/api/v1/organizations/\(orgID)/environments/\(envID)/stop", token: token)
    }

    public func deleteEnvironment(token: String, orgID: String, envID: String) async throws {
        try await delete(path: "/api/v1/organizations/\(orgID)/environments/\(envID)", token: token)
    }

    private func get<T: Decodable>(path: String, token: String) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "GET"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: req)
        try checkStatus(response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func post(path: String, token: String) async throws {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (_, response) = try await session.data(for: req)
        try checkStatus(response)
    }

    private func delete(path: String, token: String) async throws {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (_, response) = try await session.data(for: req)
        try checkStatus(response)
    }

    // MARK: - Sign In

    public struct SignInResponse: Decodable, Sendable {
        public let user: SignInUser?
        public let session: SignInSession?
        public let twoFactorRequired: Bool?
        public let twoFactorToken: String?

        public struct SignInUser: Decodable, Sendable {
            public let id: String
            public let email: String
            public let name: String?
        }

        public struct SignInSession: Decodable, Sendable {
            public let id: String
            public let token: String
            public let expiresAt: String

            enum CodingKeys: String, CodingKey {
                case id, token
                case expiresAt = "expires_at"
            }
        }
    }

    public func signIn(email: String, password: String) async throws -> SignInResponse {
        var req = URLRequest(url: baseURL.appendingPathComponent("/api/auth/sign-in"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["email": email, "password": password]
        req.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: req)
        try checkStatus(response)
        return try JSONDecoder().decode(SignInResponse.self, from: data)
    }

    public struct TwoFactorResponse: Decodable, Sendable {
        public let user: SignInResponse.SignInUser
        public let session: SignInResponse.SignInSession
    }

    public func validateTOTP(code: String, token: String) async throws -> TwoFactorResponse {
        var req = URLRequest(url: baseURL.appendingPathComponent("/api/auth/two-factor/validate"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["code": code, "token": token]
        req.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: req)
        try checkStatus(response)
        return try JSONDecoder().decode(TwoFactorResponse.self, from: data)
    }

    private func checkStatus(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else {
            throw CodewireClientError.invalidResponse
        }
        switch http.statusCode {
        case 200...299: return
        case 401: throw CodewireClientError.unauthorized
        case 403: throw CodewireClientError.forbidden
        case 404: throw CodewireClientError.notFound
        case 500...599: throw CodewireClientError.serverError(http.statusCode)
        default: throw CodewireClientError.invalidResponse
        }
    }
}
