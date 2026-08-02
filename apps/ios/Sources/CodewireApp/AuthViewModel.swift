#if canImport(SwiftUI)
import SwiftUI
import CodewireKit
#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import UIKit
#endif

@MainActor
final class AuthViewModel: ObservableObject {
    @Published var isAuthenticated = false
    @Published var accessToken: String?
    @Published var error: String?
    @Published var isLoading = false

    @Published private(set) var environment: CodewireEndpoint
    private(set) var baseURL: URL
    private(set) var client: CodewireClient
    private var tokenStore: TokenStore

    #if DEBUG
    private static let environmentPreferenceKey = "codewire.ios.debug.endpoint"
    #endif

    #if canImport(AuthenticationServices) && canImport(UIKit)
    private var authenticationSession: ASWebAuthenticationSession?
    private var presentationContextProvider: AuthorizationPresentationContext?
    #endif

    init(
        environment: CodewireEndpoint? = nil,
        tokenStore: TokenStore? = nil
    ) {
        #if DEBUG
        let selected = environment ?? Self.selectedDebugEnvironment()
        #else
        _ = environment
        let selected = CodewireEndpoint.production
        #endif
        self.environment = selected
        self.baseURL = selected.baseURL
        self.tokenStore = tokenStore ?? KeychainTokenStore(account: selected.keychainAccount)
        self.client = CodewireClient(baseURL: selected.baseURL)
    }

    #if DEBUG
    func selectEnvironment(_ environment: CodewireEndpoint) {
        guard environment != self.environment, !isLoading else { return }

        Self.saveDebugEnvironment(environment)
        self.environment = environment
        baseURL = environment.baseURL
        client = CodewireClient(baseURL: environment.baseURL)
        tokenStore = KeychainTokenStore(account: environment.keychainAccount)
        accessToken = nil
        isAuthenticated = false
        error = nil
        checkExistingToken()
    }

    private static func selectedDebugEnvironment() -> CodewireEndpoint {
        guard let rawValue = UserDefaults.standard.string(forKey: environmentPreferenceKey),
              let environment = CodewireEndpoint(rawValue: rawValue)
        else {
            return .development
        }
        return environment
    }

    private static func saveDebugEnvironment(_ environment: CodewireEndpoint) {
        UserDefaults.standard.set(environment.rawValue, forKey: environmentPreferenceKey)
    }
    #endif

    func checkExistingToken() {
        do {
            guard let stored = try tokenStore.load() else { return }
            guard stored.expiresAt <= Date() else {
                completeLogin(stored)
                return
            }
            guard let refreshToken = stored.refreshToken, !refreshToken.isEmpty else {
                try tokenStore.delete()
                return
            }

            isLoading = true
            Task {
                defer { isLoading = false }
                do {
                    var refreshed = try await OIDCFlow.refresh(
                        baseURL: baseURL,
                        clientID: OIDCFlow.nativeClientID,
                        refreshToken: refreshToken
                    )
                    if refreshed.refreshToken == nil {
                        refreshed = TokenInfo(
                            accessToken: refreshed.accessToken,
                            refreshToken: refreshToken,
                            expiresAt: refreshed.expiresAt
                        )
                    }
                    try tokenStore.save(refreshed)
                    completeLogin(refreshed)
                } catch {
                    do {
                        try tokenStore.delete()
                    } catch {
                        // The expired credential remains unusable in memory;
                        // surface the persistence failure without exposing it.
                    }
                    accessToken = nil
                    isAuthenticated = false
                    self.error = "Your session expired. Please sign in again."
                }
            }
        } catch {
            accessToken = nil
            isAuthenticated = false
            self.error = "Unable to read the saved session. Please sign in again."
        }
    }

    #if canImport(AuthenticationServices) && canImport(UIKit)
    func beginSignIn() {
        guard !isLoading else { return }
        error = nil
        isLoading = true

        let request = OIDCFlow.startNativeAuthorization(baseURL: baseURL)
        let provider = AuthorizationPresentationContext()
        let session = ASWebAuthenticationSession(
            url: request.url,
            callbackURLScheme: OIDCFlow.nativeCallbackScheme
        ) { [weak self] callbackURL, sessionError in
            Task { @MainActor in
                await self?.finishAuthorization(
                    callbackURL: callbackURL,
                    sessionError: sessionError,
                    request: request
                )
            }
        }
        session.presentationContextProvider = provider
        session.prefersEphemeralWebBrowserSession = false
        presentationContextProvider = provider
        authenticationSession = session
        guard session.start() else {
            authenticationSession = nil
            presentationContextProvider = nil
            isLoading = false
            error = "Unable to start sign in. Please try again."
            return
        }
    }

    private func finishAuthorization(
        callbackURL: URL?,
        sessionError: Error?,
        request: OIDCFlow.AuthorizationRequest
    ) async {
        defer {
            authenticationSession = nil
            presentationContextProvider = nil
            isLoading = false
        }
        if let sessionError {
            if let sessionError = sessionError as? ASWebAuthenticationSessionError,
               sessionError.code == .canceledLogin {
                error = "Sign in was cancelled."
            } else {
                error = "Unable to complete sign in. Please try again."
            }
            return
        }
        guard let callbackURL else {
            error = "The sign-in response was invalid. Please try again."
            return
        }

        do {
            let code = try OIDCFlow.authorizationCode(
                from: callbackURL,
                expectedState: request.state
            )
            let token = try await OIDCFlow.exchangeNativeAuthorizationCode(
                baseURL: baseURL,
                code: code,
                verifier: request.verifier
            )
            try tokenStore.save(token)
            completeLogin(token)
        } catch let flowError as OAuthFlowError {
            error = flowError.localizedDescription
        } catch {
            self.error = "Unable to complete sign in. Please try again."
        }
    }
    #else
    func beginSignIn() {
        error = "System-browser sign in is unavailable on this device."
    }
    #endif

    func signOut() {
        do {
            try tokenStore.delete()
            accessToken = nil
            isAuthenticated = false
            error = nil
        } catch {
            self.error = "Unable to sign out. Please try again."
        }
    }

    private func completeLogin(_ token: TokenInfo) {
        accessToken = token.accessToken
        isAuthenticated = true
        error = nil
    }
}

#if canImport(AuthenticationServices) && canImport(UIKit)
private final class AuthorizationPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first(where: { $0.activationState == .foregroundActive })?
            .windows
            .first(where: { $0.isKeyWindow })
        ?? ASPresentationAnchor()
    }
}
#endif
#endif
