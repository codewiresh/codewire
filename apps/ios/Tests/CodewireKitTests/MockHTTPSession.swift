import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import CodewireKit

final class MockHTTPSession: HTTPSession, @unchecked Sendable {
    var responses: [String: (Data, HTTPURLResponse)] = [:]
    var recordedRequests: [URLRequest] = []

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        recordedRequests.append(request)
        let key = request.url!.absoluteString
        guard let pair = responses[key] else {
            throw URLError(.badURL)
        }
        return (pair.0, pair.1)
    }
}
