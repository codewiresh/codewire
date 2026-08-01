import Foundation

public struct Environment: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let orgId: String
    public let desiredState: String
    public let state: String
    public let cpuMillicores: Int
    public let memoryMb: Int
    public let diskGb: Int
    public let errorReason: String?
    public let createdAt: String

    public init(
        id: String,
        name: String,
        orgId: String,
        desiredState: String,
        state: String,
        cpuMillicores: Int,
        memoryMb: Int,
        diskGb: Int,
        errorReason: String?,
        createdAt: String
    ) {
        self.id = id
        self.name = name
        self.orgId = orgId
        self.desiredState = desiredState
        self.state = state
        self.cpuMillicores = cpuMillicores
        self.memoryMb = memoryMb
        self.diskGb = diskGb
        self.errorReason = errorReason
        self.createdAt = createdAt
    }
}
