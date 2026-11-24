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

/// Thin Connect JSON client for the iOS environment browser. The app keeps
/// display models separate from wire messages so a proto field or enum cannot
/// silently become a UI contract.
public actor CodewireClient {
    private let baseURL: URL
    private let session: HTTPSession

    public init(baseURL: URL, session: HTTPSession = URLSession.shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public func listOrganizations(bearer: BearerSource) async throws -> [Organization] {
        let response: ListOrganizationsResponse = try await postConnect(
            path: "codewire.v1.OrganizationService/ListOrganizations",
            bearer: bearer,
            request: EmptyRequest()
        )
        return try (response.organizations ?? []).map(Self.organization(from:))
    }

    public func listEnvironments(bearer: BearerSource, orgID: String) async throws -> [Environment] {
        let response: ListEnvironmentsResponse = try await postConnect(
            path: "codewire.v1.EnvironmentService/ListEnvironments",
            bearer: bearer,
            request: OrganizationRequest(orgId: orgID)
        )
        return try (response.environments ?? []).map(Self.environment(from:))
    }

    public func startEnvironment(bearer: BearerSource, orgID: String, envID: String) async throws {
        let _: EmptyResponse = try await postConnect(
            path: "codewire.v1.EnvironmentService/StartEnvironment",
            bearer: bearer,
            request: EnvironmentRequest(orgId: orgID, environmentId: envID)
        )
    }

    public func stopEnvironment(bearer: BearerSource, orgID: String, envID: String) async throws {
        let _: EmptyResponse = try await postConnect(
            path: "codewire.v1.EnvironmentService/StopEnvironment",
            bearer: bearer,
            request: EnvironmentRequest(orgId: orgID, environmentId: envID)
        )
    }

    public func deleteEnvironment(bearer: BearerSource, orgID: String, envID: String) async throws {
        let _: EmptyResponse = try await postConnect(
            path: "codewire.v1.EnvironmentService/DeleteEnvironment",
            bearer: bearer,
            request: EnvironmentRequest(orgId: orgID, environmentId: envID)
        )
    }

    // MARK: - Connect JSON transport

    /// Sends a unary call with the bearer `bearer` gives. When the auth layer
    /// refuses that bearer (`BEARER_REFUSED`), it is renewed and the call sent
    /// once more; any other answer, a second refusal included, is final
    /// (docs/dev/AUTH-POLICY.md, "Native sign-in lifetimes").
    private func postConnect<Request: Encodable, Response: Decodable>(
        path: String,
        bearer: BearerSource,
        request: Request
    ) async throws -> Response {
        var urlRequest = URLRequest(url: baseURL.appendingPathComponent(path))
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.httpBody = try JSONEncoder().encode(request)

        let token = try await bearer.token()
        urlRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        var (data, response) = try await session.data(for: urlRequest)
        if Self.bearerRefused(response, data: data),
           let renewed = try? await bearer.afterRefusal(token) {
            urlRequest.setValue("Bearer \(renewed)", forHTTPHeaderField: "Authorization")
            (data, response) = try await session.data(for: urlRequest)
        }
        try checkStatus(response, data: data)
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw CodewireClientError.invalidResponse
        }
    }

    private func checkStatus(_ response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw CodewireClientError.invalidResponse
        }
        guard !(200...299).contains(http.statusCode) else { return }

        // Connect error bodies carry canonical codes. Prefer them when they
        // exist, then retain HTTP mapping for gateway-level failures.
        if let connectError = try? JSONDecoder().decode(ConnectError.self, from: data),
           let code = connectError.code {
            switch code {
            case "unauthenticated": throw CodewireClientError.unauthorized
            case "permission_denied": throw CodewireClientError.forbidden
            case "not_found": throw CodewireClientError.notFound
            default: break
            }
        }
        switch http.statusCode {
        case 401: throw CodewireClientError.unauthorized
        case 403: throw CodewireClientError.forbidden
        case 404: throw CodewireClientError.notFound
        case 500...599: throw CodewireClientError.serverError(http.statusCode)
        default: throw CodewireClientError.invalidResponse
        }
    }

    /// Whether an answer is the auth layer's own refusal of the bearer: 401,
    /// `unauthenticated`, and a `google.rpc.ErrorInfo` with reason
    /// `BEARER_REFUSED` in domain `codewire.sh`. A handler's
    /// `unauthenticated` without it may follow a change and is never resent.
    static func bearerRefused(_ response: URLResponse, data: Data) -> Bool {
        guard (response as? HTTPURLResponse)?.statusCode == 401,
              let error = try? JSONDecoder().decode(ConnectError.self, from: data),
              error.code == "unauthenticated"
        else { return false }
        return (error.details ?? []).contains { detail in
            guard detail.type == "google.rpc.ErrorInfo",
                  let value = detail.value,
                  let info = ErrorInfoFields(base64: value)
            else { return false }
            return info.reason == "BEARER_REFUSED" && info.domain == "codewire.sh"
        }
    }

    // MARK: - Wire mapping

    private static func organization(from membership: OrganizationMembership) throws -> Organization {
        guard let organization = membership.organization,
              let id = organization.id, !id.isEmpty,
              let name = organization.name, !name.isEmpty,
              let slug = organization.slug, !slug.isEmpty,
              let role = organizationRole(membership.role)
        else {
            throw CodewireClientError.invalidResponse
        }
        return Organization(id: id, name: name, slug: slug, role: role)
    }

    private static func environment(from wire: EnvironmentWire) throws -> Environment {
        guard let id = wire.id, !id.isEmpty,
              let name = wire.name, !name.isEmpty,
              let orgID = wire.orgId, !orgID.isEmpty,
              let desiredState = desiredState(wire.desiredState),
              let state = environmentState(wire.state),
              let createdAt = wire.createdAt, !createdAt.isEmpty
        else {
            throw CodewireClientError.invalidResponse
        }
        return Environment(
            id: id,
            name: name,
            orgId: orgID,
            desiredState: desiredState,
            state: state,
            cpuMillicores: wire.cpuMillicores ?? 0,
            memoryMb: wire.memoryMb ?? 0,
            diskGb: wire.diskGb ?? 0,
            errorReason: wire.errorReason,
            createdAt: createdAt
        )
    }

    private static func organizationRole(_ value: String?) -> String? {
        switch value {
        case "ORG_ROLE_OWNER": return "owner"
        case "ORG_ROLE_ADMIN": return "admin"
        case "ORG_ROLE_MEMBER": return "member"
        default: return nil
        }
    }

    private static func desiredState(_ value: String?) -> String? {
        switch value {
        case "DESIRED_STATE_STARTED": return "started"
        case "DESIRED_STATE_STOPPED": return "stopped"
        case "DESIRED_STATE_DESTROYED": return "destroyed"
        case "DESIRED_STATE_ARCHIVED": return "archived"
        case "DESIRED_STATE_RESIZED": return "resized"
        default: return nil
        }
    }

    private static func environmentState(_ value: String?) -> String? {
        switch value {
        case "ENVIRONMENT_STATE_PENDING": return "pending"
        case "ENVIRONMENT_STATE_PENDING_BUILD": return "pending_build"
        case "ENVIRONMENT_STATE_BUILDING": return "building"
        case "ENVIRONMENT_STATE_BUILD_FAILED": return "build_failed"
        case "ENVIRONMENT_STATE_PULLING_SNAPSHOT": return "pulling_snapshot"
        case "ENVIRONMENT_STATE_CREATING": return "creating"
        case "ENVIRONMENT_STATE_STARTING": return "starting"
        case "ENVIRONMENT_STATE_RUNNING": return "running"
        case "ENVIRONMENT_STATE_STOPPING": return "stopping"
        case "ENVIRONMENT_STATE_STOPPED": return "stopped"
        case "ENVIRONMENT_STATE_ARCHIVING": return "archiving"
        case "ENVIRONMENT_STATE_ARCHIVED": return "archived"
        case "ENVIRONMENT_STATE_RESTORING": return "restoring"
        case "ENVIRONMENT_STATE_RESIZING": return "resizing"
        case "ENVIRONMENT_STATE_DESTROYING": return "destroying"
        case "ENVIRONMENT_STATE_DESTROYED": return "destroyed"
        case "ENVIRONMENT_STATE_ERROR": return "error"
        case "ENVIRONMENT_STATE_UNKNOWN": return "unknown"
        default: return nil
        }
    }
}

private struct EmptyRequest: Encodable {}
private struct EmptyResponse: Decodable {}
private struct OrganizationRequest: Encodable { let orgId: String }
private struct EnvironmentRequest: Encodable { let orgId: String; let environmentId: String }

// Wire messages follow proto3 JSON, which leaves out every field at its
// default: an empty list, an empty string, zero, an unset message or the
// zero enum value. So every field is optional here; a missing list or number
// means its default, and the mapping above rejects only what a display model
// cannot do without.

private struct ConnectError: Decodable {
    let code: String?
    let details: [ConnectErrorDetail]?
}

private struct ConnectErrorDetail: Decodable {
    let type: String?
    let value: String?
}

private struct ListOrganizationsResponse: Decodable {
    let organizations: [OrganizationMembership]?
}

private struct OrganizationMembership: Decodable {
    let organization: OrganizationWire?
    let role: String?
}

private struct OrganizationWire: Decodable {
    let id: String?
    let name: String?
    let slug: String?
}

private struct ListEnvironmentsResponse: Decodable {
    let environments: [EnvironmentWire]?
}

private struct EnvironmentWire: Decodable {
    let id: String?
    let orgId: String?
    let name: String?
    let desiredState: String?
    let state: String?
    let cpuMillicores: Int?
    let memoryMb: Int?
    let diskGb: Int?
    let errorReason: String?
    let createdAt: String?
}
