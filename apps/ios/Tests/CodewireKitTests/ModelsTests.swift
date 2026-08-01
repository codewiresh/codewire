import XCTest
@testable import CodewireKit

final class ModelsTests: XCTestCase {
    func testOrganization_initializesDisplayModel() {
        let organization = Organization(id: "org_123", name: "Acme", slug: "acme", role: "admin")
        XCTAssertEqual(organization.id, "org_123")
        XCTAssertEqual(organization.name, "Acme")
        XCTAssertEqual(organization.slug, "acme")
        XCTAssertEqual(organization.role, "admin")
    }

    func testEnvironment_initializesDisplayModel() {
        let environment = Environment(
            id: "env_1",
            name: "dev",
            orgId: "org_1",
            desiredState: "started",
            state: "running",
            cpuMillicores: 2000,
            memoryMb: 4096,
            diskGb: 20,
            errorReason: nil,
            createdAt: "2026-04-01T00:00:00Z"
        )
        XCTAssertEqual(environment.id, "env_1")
        XCTAssertEqual(environment.name, "dev")
        XCTAssertEqual(environment.orgId, "org_1")
        XCTAssertEqual(environment.desiredState, "started")
        XCTAssertEqual(environment.state, "running")
        XCTAssertEqual(environment.cpuMillicores, 2000)
        XCTAssertEqual(environment.memoryMb, 4096)
        XCTAssertEqual(environment.diskGb, 20)
        XCTAssertNil(environment.errorReason)
        XCTAssertEqual(environment.createdAt, "2026-04-01T00:00:00Z")
    }
}
