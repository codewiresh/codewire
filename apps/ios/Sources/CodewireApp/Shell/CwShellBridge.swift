#if canImport(SwiftUI)
import Foundation

struct CwShellDialConfig: Codable {
    let serverURL: String
    let token: String
    let orgID: String
    let envID: String
    let cols: UInt16
    let rows: UInt16

    enum CodingKeys: String, CodingKey {
        case serverURL = "server_url"
        case token
        case orgID = "org_id"
        case envID = "env_id"
        case cols
        case rows
    }
}

enum CwShellError: Error, LocalizedError {
    case bridge(String)
    case closed

    var errorDescription: String? {
        switch self {
        case .bridge(let msg): return msg
        case .closed: return "Shell handle is closed"
        }
    }
}

final class CwShellHandle: @unchecked Sendable {
    func read(into _: UnsafeMutablePointer<UInt8>, length _: Int) throws -> Int {
        throw CwShellError.closed
    }

    func write(_: [UInt8]) throws {
        throw CwShellError.closed
    }

    func resize(cols _: UInt16, rows _: UInt16) throws {
        throw CwShellError.closed
    }

    func close() {}

    static func dial(config _: CwShellDialConfig) throws -> CwShellHandle {
        throw CwShellError.bridge("iOS shell bridge is not available in this build")
    }
}
#endif
