import CodewireClientFFI
import Foundation
import XCTest

/// The app's calls into the Rust shell, through the generated bindings
/// (#3825). They need no environment: each stops before a shell would open.
final class ShellDialTests: XCTestCase {
    func testAnEmptyEnvironmentIsRefusedBeforeAnyNetwork() async {
        let observer = Recorder()
        var target = Self.target(serverUrl: "https://codewire.invalid")
        target.environmentId = " "
        do {
            _ = try await Shell.dial(target: target, observer: observer)
            XCTFail("dial accepted an empty environment")
        } catch let error as ShellError {
            XCTAssertEqual(error, .Invalid(message: "the environment is empty"))
        } catch {
            XCTFail("unexpected error \(error)")
        }
        XCTAssertEqual(observer.states, [])
    }

    /// Rust calls back into Swift: the observer hears the shell connect and
    /// end, and `dial` fails with the server's meaning.
    func testAnUnreachableServerFailsDialAndEndsTheShell() async {
        let observer = Recorder()
        do {
            _ = try await Shell.dial(
                target: Self.target(serverUrl: "http://127.0.0.1:1"),
                observer: observer
            )
            XCTFail("dial reached a closed port")
        } catch let error as ShellError {
            guard case .Unavailable = error else {
                return XCTFail("unexpected error \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
        let states = observer.states
        XCTAssertEqual(states.first, .connecting)
        guard case let .ended(exitStatus, error)? = states.last else {
            return XCTFail("the shell did not end: \(states)")
        }
        XCTAssertNil(exitStatus)
        XCTAssertNotNil(error)
    }

    private static func target(serverUrl: String) -> ShellTarget {
        ShellTarget(
            serverUrl: serverUrl,
            accessToken: "synthetic-token",
            orgId: "org",
            environmentId: "env",
            term: "xterm-256color",
            columns: 80,
            rows: 24
        )
    }
}

/// Records every state the shell reports, from whichever thread reports it.
private final class Recorder: ShellObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [ShellState] = []

    var states: [ShellState] {
        lock.withLock { recorded }
    }

    func stateChanged(state: ShellState) {
        lock.withLock { recorded.append(state) }
    }
}
