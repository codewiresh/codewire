import Foundation

/// The product origins available to the native app.
///
/// Debug builds expose both targets so device smoke tests can use dev without
/// ever reusing a production OAuth credential. Release builds always select
/// production in `AuthViewModel` and do not expose a selector.
public enum CodewireEndpoint: String, CaseIterable, Identifiable, Sendable {
    case development
    case production

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .development:
            "Dev"
        case .production:
            "Production"
        }
    }

    public var baseURL: URL {
        switch self {
        case .development:
            URL(string: "https://codewire-dev.sh")!
        case .production:
            URL(string: "https://codewire.sh")!
        }
    }

    /// Keep credentials cryptographically and operationally scoped to their
    /// issuing origin. A selector switch must never reuse a token elsewhere.
    public var keychainAccount: String {
        "auth.\(rawValue)"
    }

    public static var defaultForBuild: Self {
        #if DEBUG
        .development
        #else
        .production
        #endif
    }
}
