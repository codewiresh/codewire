import XCTest
@testable import CodewireKit

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class CodewireClientTests: XCTestCase {
    func testListOrganizations_decodes() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations")!
        session.responses[url.absoluteString] = (
            Data(#"[{"id":"o1","name":"Acme","slug":"acme","role":"admin"}]"#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        let orgs = try await client.listOrganizations(token: "tok")
        XCTAssertEqual(orgs.count, 1)
        XCTAssertEqual(orgs[0].id, "o1")
        let req = session.recordedRequests.first!
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer tok")
    }

    func testListEnvironments_decodes() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations/o1/environments")!
        session.responses[url.absoluteString] = (
            Data(#"""
            [{"id":"e1","name":"dev","org_id":"o1","desired_state":"running","state":"running","cpu_millicores":2000,"memory_mb":4096,"disk_gb":20,"error_reason":null,"created_at":"2026-04-01T00:00:00Z"}]
            """#.utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        let envs = try await client.listEnvironments(token: "tok", orgID: "o1")
        XCTAssertEqual(envs.count, 1)
        XCTAssertEqual(envs[0].state, "running")
    }

    func testListOrganizations_401_throwsUnauthorized() async {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations")!
        session.responses[url.absoluteString] = (
            Data(),
            HTTPURLResponse(url: url, statusCode: 401, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        do {
            _ = try await client.listOrganizations(token: "tok")
            XCTFail("expected unauthorized error")
        } catch CodewireClientError.unauthorized {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testListEnvironments_403_throwsForbidden() async {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations/o1/environments")!
        session.responses[url.absoluteString] = (
            Data(),
            HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        do {
            _ = try await client.listEnvironments(token: "tok", orgID: "o1")
            XCTFail("expected forbidden error")
        } catch CodewireClientError.forbidden {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testStartEnvironment_postsToCorrectURL() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations/o1/environments/e1/start")!
        session.responses[url.absoluteString] = (
            Data("{}".utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        try await client.startEnvironment(token: "tok", orgID: "o1", envID: "e1")
        let req = session.recordedRequests.first!
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer tok")
    }

    func testStopEnvironment_postsToCorrectURL() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations/o1/environments/e1/stop")!
        session.responses[url.absoluteString] = (
            Data("{}".utf8),
            HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        try await client.stopEnvironment(token: "tok", orgID: "o1", envID: "e1")
        let req = session.recordedRequests.first!
        XCTAssertEqual(req.httpMethod, "POST")
    }

    func testDeleteEnvironment_sendsDelete() async throws {
        let session = MockHTTPSession()
        let url = URL(string: "https://codewire.sh/api/v1/organizations/o1/environments/e1")!
        session.responses[url.absoluteString] = (
            Data(),
            HTTPURLResponse(url: url, statusCode: 204, httpVersion: nil, headerFields: nil)!
        )
        let client = CodewireClient(
            baseURL: URL(string: "https://codewire.sh")!,
            session: session
        )
        try await client.deleteEnvironment(token: "tok", orgID: "o1", envID: "e1")
        let req = session.recordedRequests.first!
        XCTAssertEqual(req.httpMethod, "DELETE")
    }
}
