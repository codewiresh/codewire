#if canImport(SwiftUI) && canImport(CodewireClientFFI)
import CodewireClientFFI
import Foundation

/// The shell's connection, as the app shows it: the Rust shell reports each
/// change of state through `ShellObserver`, on its own thread.
@MainActor
final class ShellStatus: ObservableObject {
    @Published private(set) var state: ShellState = .connecting

    /// The observer the shell is dialled with. It forwards each state to the
    /// main queue, which keeps them in order: a late `.connected` never
    /// lands after `.ended`.
    nonisolated func observer() -> ShellObserver {
        StateRelay { [weak self] state in
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self?.state = state }
            }
        }
    }

    /// One line under the terminal: how the shell is connected, and why it
    /// isn't direct when it isn't.
    var line: String {
        switch state {
        case .connecting:
            return "Connecting…"
        case let .connected(path, reason):
            let via: String
            switch path {
            case .directUdp: via = "direct UDP"
            case .relay: via = "UDP relay"
            case .derp: via = "DERP relay"
            case .tailnet: via = "tailnet"
            case .api: via = "API"
            }
            return reason.map { "via \(via) · \($0)" } ?? "via \(via)"
        case let .reconnecting(reason):
            return "Reconnecting · \(reason)"
        case let .ended(exitStatus, error):
            if let error { return "Ended · \(error)" }
            return exitStatus.map { "Ended · exit \($0)" } ?? "Ended"
        }
    }

    var hasEnded: Bool {
        if case .ended = state { return true }
        return false
    }
}

extension ShellError {
    /// The server's or the shell's own words, without the case name.
    var message: String {
        switch self {
        case let .Unauthenticated(message), let .PermissionDenied(message),
             let .NotFound(message), let .Unavailable(message), let .Ended(message),
             let .Invalid(message):
            return message
        }
    }
}

private final class StateRelay: ShellObserver {
    private let forward: @Sendable (ShellState) -> Void

    init(_ forward: @escaping @Sendable (ShellState) -> Void) {
        self.forward = forward
    }

    func stateChanged(state: ShellState) {
        forward(state)
    }
}
#endif
