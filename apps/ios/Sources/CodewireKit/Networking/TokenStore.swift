import Foundation
#if canImport(Security)
import Security
#endif

public struct TokenInfo: Codable, Equatable, Sendable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date

    public init(accessToken: String, refreshToken: String?, expiresAt: Date) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
    }
}

public protocol TokenStore: Sendable {
    func save(_ token: TokenInfo) throws
    func load() throws -> TokenInfo?
    func delete() throws
}

#if canImport(Security)
public enum TokenStoreError: Error, Equatable {
    case keychainStatus(OSStatus)
}
#endif

/// In-memory TokenStore for tests and non-Darwin hosts.
public final class InMemoryTokenStore: TokenStore, @unchecked Sendable {
    private var stored: TokenInfo?
    private let lock = NSLock()

    public init() {}

    public func save(_ token: TokenInfo) throws {
        lock.lock(); defer { lock.unlock() }
        stored = token
    }

    public func load() throws -> TokenInfo? {
        lock.lock(); defer { lock.unlock() }
        return stored
    }

    public func delete() throws {
        lock.lock(); defer { lock.unlock() }
        stored = nil
    }
}

#if canImport(Security)
/// Keychain-backed TokenStore for iOS. Not compiled on Linux.
public final class KeychainTokenStore: TokenStore, @unchecked Sendable {
    private let service: String
    private let account: String

    public init(service: String = "sh.codewire.ios", account: String = "auth") {
        self.service = service
        self.account = account
    }

    public func save(_ token: TokenInfo) throws {
        let data = try JSONEncoder().encode(token)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TokenStoreError.keychainStatus(status)
        }
    }

    public func load() throws -> TokenInfo? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw TokenStoreError.keychainStatus(status)
        }
        return try JSONDecoder().decode(TokenInfo.self, from: data)
    }

    public func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw TokenStoreError.keychainStatus(status)
        }
    }
}
#endif
