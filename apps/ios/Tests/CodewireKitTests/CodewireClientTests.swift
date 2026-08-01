import XCTest
@testable import CodewireKit

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class CodewireClientTests: XCTestCase {
    private let baseURL = URL(string: "https://codewire.sh")!

    func testListOrganizations_usesConnectJSONAndMapsMembership() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/codewire.v1.OrganizationService/ListOrganizations")!
        session.responses[url.absoluteString] = (
            Data(#"""
            {"organizations":[{"organization":{"id":"o1","name":"Acme","slug":"acme"},"role":"ORG_ROLE_ADMIN"}]}
            """#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(baseURL: baseURL, session: session)

        let organizations = try await client.listOrganizations(token: "tok")

        XCTAssertEqual(organizations, [Organization(id: "o1", name: "Acme", slug: "acme", role: "admin")])
        XCTAssertEqual(session.recordedRequests.count, 1)
        assertConnectRequest(session.recordedRequests[0], token: "tok", body: [:])
    }

    func testListEnvironments_usesConnectJSONAndMapsEnums() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/codewire.v1.EnvironmentService/ListEnvironments")!
        session.responses[url.absoluteString] = (
            Data(#"""
            {"environments":[{"id":"e1","name":"dev","orgId":"o1","desiredState":"DESIRED_STATE_STARTED","state":"ENVIRONMENT_STATE_RUNNING","cpuMillicores":2000,"memoryMb":4096,"diskGb":20,"createdAt":"2026-04-01T00:00:00Z"}]}
            """#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(baseURL: baseURL, session: session)

        let environments = try await client.listEnvironments(token: "tok", orgID: "o1")

        XCTAssertEqual(environments.count, 1)
        XCTAssertEqual(environments[0].state, "running")
        XCTAssertEqual(environments[0].desiredState, "started")
        XCTAssertEqual(session.recordedRequests.count, 1)
        assertConnectRequest(session.recordedRequests[0], token: "tok", body: ["orgId": "o1"])
    }

    func testListOrganizations_rejectsMalformedConnectMembership() async {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/codewire.v1.OrganizationService/ListOrganizations")!
        session.responses[url.absoluteString] = (
            Data(#"{"organizations":[{"organization":{"id":"o1","name":"Acme","slug":"acme"},"role":"ORG_ROLE_UNSPECIFIED"}]}"#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(baseURL: baseURL, session: session)

        do {
            _ = try await client.listOrganizations(token: "tok")
            XCTFail("expected invalid response")
        } catch CodewireClientError.invalidResponse {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testListOrganizations_401_throwsUnauthorized() async {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/codewire.v1.OrganizationService/ListOrganizations")!
        session.responses[url.absoluteString] = (
            Data(#"{"code":"unauthenticated"}"#.utf8),
            HTTPURLResponse(url: url, statusCode: 401, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(baseURL: baseURL, session: session)

        await assertError(.unauthorized) {
            _ = try await client.listOrganizations(token: "tok")
        }
    }

    func testListEnvironments_connectPermissionDenied_throwsForbidden() async {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/codewire.v1.EnvironmentService/ListEnvironments")!
        session.responses[url.absoluteString] = (
            Data(#"{"code":"permission_denied"}"#.utf8),
            HTTPURLResponse(url: url, statusCode: 400, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(baseURL: baseURL, session: session)

        await assertError(.forbidden) {
            _ = try await client.listEnvironments(token: "tok", orgID: "o1")
        }
    }

    func testEnvironmentActions_useConnectJSON() async throws {
        let session = MockHTTPSession()
        let actionPaths = [
            "StartEnvironment",
            "StopEnvironment",
            "DeleteEnvironment",
        ]
        for action in actionPaths {
            let url = URL(string: "https://codewire.sh/codewire.v1.EnvironmentService/\(action)")!
            session.responses[url.absoluteString] = (
                Data("{}".utf8),
                HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
            )
        }
        let client = CodewireClient(baseURL: baseURL, session: session)

        try await client.startEnvironment(token: "tok", orgID: "o1", envID: "e1")
        try await client.stopEnvironment(token: "tok", orgID: "o1", envID: "e1")
        try await client.deleteEnvironment(token: "tok", orgID: "o1", envID: "e1")

        XCTAssertEqual(session.recordedRequests.count, actionPaths.count)
        for (request, action) in zip(session.recordedRequests, actionPaths) {
            XCTAssertEqual(request.url?.path, "/codewire.v1.EnvironmentService/\(action)")
            assertConnectRequest(request, token: "tok", body: ["orgId": "o1", "environmentId": "e1"])
        }
    }

    private func assertConnectRequest(
        _ request: URLRequest,
        token: String,
        body: [String: String]
    ) {
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(token)")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
        let decoded = try? JSONDecoder().decode([String: String].self, from: request.httpBody ?? Data())
        XCTAssertEqual(decoded, body)
    }

    private func assertError(
        _ expected: CodewireClientError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("expected \(expected)")
        } catch let actual as CodewireClientError {
            XCTAssertEqual(actual, expected)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }
}
