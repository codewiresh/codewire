import XCTest
@testable import CodewireKit

final class ModelsTests: XCTestCase {
    func testOrganization_decodes() throws {
        let json = #"{"id":"org_123","name":"Acme","slug":"acme","role":"admin"}"#
        let org = try JSONDecoder().decode(Organization.self, from: Data(json.utf8))
        XCTAssertEqual(org.id, "org_123")
        XCTAssertEqual(org.name, "Acme")
        XCTAssertEqual(org.slug, "acme")
        XCTAssertEqual(org.role, "admin")
    }

    func testEnvironment_decodes() throws {
        let json = #"""
        {"id":"env_1","name":"dev","org_id":"org_1","desired_state":"running","state":"running","cpu_millicores":2000,"memory_mb":4096,"disk_gb":20,"error_reason":null,"created_at":"2026-04-01T00:00:00Z"}
        """#
        let env = try JSONDecoder().decode(Environment.self, from: Data(json.utf8))
        XCTAssertEqual(env.id, "env_1")
        XCTAssertEqual(env.name, "dev")
        XCTAssertEqual(env.orgId, "org_1")
        XCTAssertEqual(env.desiredState, "running")
        XCTAssertEqual(env.state, "running")
        XCTAssertEqual(env.cpuMillicores, 2000)
        XCTAssertEqual(env.memoryMb, 4096)
        XCTAssertEqual(env.diskGb, 20)
        XCTAssertNil(env.errorReason)
        XCTAssertEqual(env.createdAt, "2026-04-01T00:00:00Z")
    }

    func testEnvironment_decodesErrorReason() throws {
        let json = #"""
        {"id":"env_2","name":"broken","org_id":"org_1","desired_state":"running","state":"error","cpu_millicores":1000,"memory_mb":2048,"disk_gb":10,"error_reason":"sidecar crashed","created_at":"2026-04-01T00:00:00Z"}
        """#
        let env = try JSONDecoder().decode(Environment.self, from: Data(json.utf8))
        XCTAssertEqual(env.errorReason, "sidecar crashed")
    }
}
