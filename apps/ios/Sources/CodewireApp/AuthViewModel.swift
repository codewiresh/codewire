#if canImport(SwiftUI)
import SwiftUI
import CodewireKit

@MainActor
final class AuthViewModel: ObservableObject {
    @Published var isAuthenticated = false
    @Published var accessToken: String?
    @Published var error: String?
    @Published var isLoading = false
    @Published var needsTwoFactor = false

    let baseURL: URL
    let client: CodewireClient
    private let tokenStore: TokenStore
    private var twoFactorToken: String?

    init(
        baseURL: URL? = nil,
        tokenStore: TokenStore? = nil
    ) {
        let resolvedURL = baseURL ?? URL(string:
            ProcessInfo.processInfo.environment["CODEWIRE_URL"] ?? "https://codewire.sh"
        )!
        self.baseURL = resolvedURL
        self.tokenStore = tokenStore ?? KeychainTokenStore()
        self.client = CodewireClient(baseURL: resolvedURL)
    }

    func checkExistingToken() {
        do {
            guard let token = try tokenStore.load() else { return }
            if token.expiresAt > Date() {
                self.accessToken = token.accessToken
                self.isAuthenticated = true
            }
        } catch {
            // No stored token
        }
    }

    func signIn(email: String, password: String) {
        guard !email.isEmpty, !password.isEmpty else {
            self.error = "Email and password are required"
            return
        }
        isLoading = true
        error = nil
        Task {
            do {
                let response = try await client.signIn(email: email, password: password)
                if response.twoFactorRequired == true, let tfToken = response.twoFactorToken {
                    self.twoFactorToken = tfToken
                    self.needsTwoFactor = true
                    self.isLoading = false
                    return
                }
                guard let session = response.session else {
                    self.error = "No session in response"
                    self.isLoading = false
                    return
                }
                completeLogin(token: session.token, expiresAt: session.expiresAt)
            } catch CodewireClientError.unauthorized {
                self.error = "Invalid email or password"
            } catch {
                self.error = error.localizedDescription
            }
            self.isLoading = false
        }
    }

    func submitTOTP(code: String) {
        guard let tfToken = twoFactorToken, !code.isEmpty else {
            self.error = "Enter your 2FA code"
            return
        }
        isLoading = true
        error = nil
        Task {
            do {
                let response = try await client.validateTOTP(code: code, token: tfToken)
                completeLogin(token: response.session.token, expiresAt: response.session.expiresAt)
                self.needsTwoFactor = false
                self.twoFactorToken = nil
            } catch CodewireClientError.unauthorized {
                self.error = "Invalid 2FA code"
            } catch {
                self.error = error.localizedDescription
            }
            self.isLoading = false
        }
    }

    func signOut() {
        try? tokenStore.delete()
        accessToken = nil
        isAuthenticated = false
        needsTwoFactor = false
        twoFactorToken = nil
    }

    private func completeLogin(token: String, expiresAt: String) {
        let tokenInfo = TokenInfo(
            accessToken: token,
            refreshToken: nil,
            expiresAt: ISO8601DateFormatter().date(from: expiresAt) ?? Date().addingTimeInterval(86400)
        )
        try? tokenStore.save(tokenInfo)
        self.accessToken = token
        self.isAuthenticated = true
        self.error = nil
    }
}
#endif
