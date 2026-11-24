import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import CodewireKit

/// The app renews its sign-in while open, 10 minutes ahead and once after a
/// refused bearer, and resends only that refusal (docs/dev/AUTH-POLICY.md,
/// "Native sign-in lifetimes").
final class SignInTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    private final class Renewals: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func next() -> Int {
            lock.lock(); defer { lock.unlock() }
            count += 1
            return count
        }
        var total: Int {
            lock.lock(); defer { lock.unlock() }
            return count
        }
    }

    private func signIn(left: TimeInterval, renewals: Renewals) -> SignIn {
        let start = start
        return SignIn(
            token: TokenInfo(accessToken: "old", refreshToken: "refresh", expiresAt: start.addingTimeInterval(left)),
            store: InMemoryTokenStore(),
            renew: { refreshToken in
                XCTAssertEqual(refreshToken, "refresh")
                let number = renewals.next()
                try await Task.sleep(nanoseconds: 50_000_000)
                return TokenInfo(accessToken: "new-\(number)", refreshToken: nil, expiresAt: start.addingTimeInterval(3600))
            },
            now: { start }
        )
    }

    func testATokenIsRenewedInsideItsLastTenMinutes() async throws {
        let renewals = Renewals()
        let early = signIn(left: 11 * 60, renewals: renewals)
        let token = try await early.token()
        XCTAssertEqual(token, "old")
        let late = signIn(left: 9 * 60, renewals: renewals)
        let renewed = try await late.token()
        XCTAssertEqual(renewed, "new-1")
        XCTAssertEqual(renewals.total, 1)
    }

    func testWithoutARefreshTokenTheTokenIsUsedUntilItExpires() async throws {
        let start = start
        let session = SignIn(
            token: TokenInfo(accessToken: "only", refreshToken: nil, expiresAt: start.addingTimeInterval(60)),
            store: InMemoryTokenStore(),
            renew: { _ in XCTFail("nothing to renew with"); throw CodewireClientError.unauthorized },
            now: { start }
        )
        let token = try await session.token()
        XCTAssertEqual(token, "only")
    }

    func testRefusalsAtOnceShareOneRenewal() async throws {
        let renewals = Renewals()
        let session = signIn(left: 3600, renewals: renewals)
        async let first = session.afterRefusal("old")
        async let second = session.afterRefusal("old")
        let tokens = try await [first, second]
        XCTAssertEqual(tokens, ["new-1", "new-1"])
        let again = try await session.afterRefusal("old")
        XCTAssertEqual(again, "new-1")
        XCTAssertEqual(renewals.total, 1)
    }

    func testAFixedBearerHasNoRenewal() async throws {
        let renewed = try await FixedBearer("cw_key").afterRefusal("cw_key")
        XCTAssertNil(renewed)
    }

    func testErrorInfoReasonAndDomainAreRead() {
        XCTAssertEqual(
            ErrorInfoFields(base64: Self.errorInfo(reason: "BEARER_REFUSED")),
            ErrorInfoFields(reason: "BEARER_REFUSED", domain: "codewire.sh")
        )
        XCTAssertNil(ErrorInfoFields(base64: "not base64!"))
    }

    func testARefusedBearerIsRenewedAndTheCallSentOnceMore() async throws {
        let session = QueuedSession([
            Self.refusal(reason: "BEARER_REFUSED"),
            (Data(#"{"organizations":[]}"#.utf8), 200),
        ])
        let renewals = Renewals()
        let client = CodewireClient(baseURL: URL(string: "https://codewire.test")!, session: session)
        let organizations = try await client.listOrganizations(bearer: signIn(left: 3600, renewals: renewals))
        XCTAssertEqual(organizations, [])
        XCTAssertEqual(session.authorizations, ["Bearer old", "Bearer new-1"])
        XCTAssertEqual(renewals.total, 1)
    }

    func testOnlyTheAuthLayersRefusalIsSentAgain() async {
        for answer in [Self.refusal(reason: nil), Self.refusal(reason: "SESSION_EXPIRED")] {
            let session = QueuedSession([answer, (Data(#"{"organizations":[]}"#.utf8), 200)])
            let renewals = Renewals()
            let client = CodewireClient(baseURL: URL(string: "https://codewire.test")!, session: session)
            do {
                _ = try await client.listOrganizations(bearer: signIn(left: 3600, renewals: renewals))
                XCTFail("expected the refusal")
            } catch {
                XCTAssertEqual(error as? CodewireClientError, .unauthorized)
            }
            XCTAssertEqual(session.authorizations, ["Bearer old"])
            XCTAssertEqual(renewals.total, 0)
        }
    }

    func testASecondRefusalEndsTheCall() async {
        let session = QueuedSession([Self.refusal(reason: "BEARER_REFUSED"), Self.refusal(reason: "BEARER_REFUSED")])
        let client = CodewireClient(baseURL: URL(string: "https://codewire.test")!, session: session)
        do {
            _ = try await client.listOrganizations(bearer: signIn(left: 3600, renewals: Renewals()))
            XCTFail("expected the refusal")
        } catch {
            XCTAssertEqual(error as? CodewireClientError, .unauthorized)
        }
        XCTAssertEqual(session.authorizations, ["Bearer old", "Bearer new-1"])
    }

    /// `google.rpc.ErrorInfo` with `reason` and domain `codewire.sh`, as
    /// protobuf, base64 without padding as Connect may send it.
    static func errorInfo(reason: String) -> String {
        func field(_ number: UInt8, _ text: String) -> [UInt8] {
            [number << 3 | 2, UInt8(text.utf8.count)] + Array(text.utf8)
        }
        let bytes = field(1, reason) + field(2, "codewire.sh")
        return Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    static func refusal(reason: String?) -> (Data, Int) {
        var body = #"{"code":"unauthenticated","message":"session expired""#
        if let reason {
            body += #","details":[{"type":"google.rpc.ErrorInfo","value":"\#(errorInfo(reason: reason))"}]"#
        }
        return (Data((body + "}").utf8), 401)
    }
}

/// Answers each request with the next queued answer and records the bearer
/// it carried.
private final class QueuedSession: HTTPSession, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [(Data, Int)]
    private(set) var authorizations: [String] = []

    init(_ answers: [(Data, Int)]) {
        self.answers = answers
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let (data, status) = try next(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (data, response)
    }

    private func next(_ request: URLRequest) throws -> (Data, Int) {
        lock.lock(); defer { lock.unlock() }
        authorizations.append(request.value(forHTTPHeaderField: "Authorization") ?? "")
        guard !answers.isEmpty else { throw URLError(.badServerResponse) }
        return answers.removeFirst()
    }
}
