import Foundation

public struct Organization: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let slug: String
    public let role: String

    public init(id: String, name: String, slug: String, role: String) {
        self.id = id
        self.name = name
        self.slug = slug
        self.role = role
    }
}
