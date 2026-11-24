import Foundation

/// The bearer a request sends, and the one to send it once more with after
/// the server's auth layer refused it.
public protocol BearerSource: Sendable {
    func token() async throws -> String
    /// Another bearer after the auth layer itself refused `rejected`, or nil
    /// when there is none.
    func afterRefusal(_ rejected: String) async throws -> String?
}

/// A sign-in that renews its access token through its refresh token while
/// the app is open: once less than 10 minutes remain, and once after the
/// auth layer refuses it (docs/dev/AUTH-POLICY.md, "Native sign-in
/// lifetimes"). A renewal in progress is shared, so a refresh token is never
/// presented twice, which the IdP would take as a reuse and end the sign-in.
public actor SignIn: BearerSource {
    public static let refreshAhead: TimeInterval = 10 * 60

    private var current: TokenInfo
    private var renewal: Task<TokenInfo, Error>?
    private let store: TokenStore
    private let renew: @Sendable (String) async throws -> TokenInfo
    private let renewed: @Sendable (TokenInfo) -> Void
    private let now: @Sendable () -> Date

    /// `renew` exchanges a refresh token for a new pair; `renewed` hears each
    /// pair after it is saved.
    public init(
        token: TokenInfo,
        store: TokenStore,
        renew: @escaping @Sendable (String) async throws -> TokenInfo,
        renewed: @escaping @Sendable (TokenInfo) -> Void = { _ in },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.current = token
        self.store = store
        self.renew = renew
        self.renewed = renewed
        self.now = now
    }

    public func token() async throws -> String {
        let left = current.expiresAt.timeIntervalSince(now())
        // With no refresh token, the access token is used until it expires.
        let renewable = !(current.refreshToken ?? "").isEmpty
        if left > Self.refreshAhead || (!renewable && left > 0) {
            return current.accessToken
        }
        return try await renewedPair().accessToken
    }

    public func afterRefusal(_ rejected: String) async throws -> String? {
        if current.accessToken != rejected {
            // Another request already renewed it.
            return current.accessToken
        }
        return try await renewedPair().accessToken
    }

    private func renewedPair() async throws -> TokenInfo {
        if let renewal {
            return try await renewal.value
        }
        guard let refreshToken = current.refreshToken, !refreshToken.isEmpty else {
            throw CodewireClientError.unauthorized
        }
        let renew = renew
        let store = store
        let task = Task<TokenInfo, Error> {
            var next = try await renew(refreshToken)
            if next.refreshToken == nil {
                next = TokenInfo(
                    accessToken: next.accessToken,
                    refreshToken: refreshToken,
                    expiresAt: next.expiresAt
                )
            }
            try store.save(next)
            return next
        }
        renewal = task
        defer { renewal = nil }
        let next = try await task.value
        current = next
        renewed(next)
        return next
    }
}

/// A bearer that is never renewed, such as an API key.
public struct FixedBearer: BearerSource {
    private let value: String

    public init(_ value: String) {
        self.value = value
    }

    public func token() async throws -> String {
        value
    }

    public func afterRefusal(_ rejected: String) async throws -> String? {
        nil
    }
}
