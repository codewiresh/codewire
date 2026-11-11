#if canImport(SwiftUI)
import SwiftUI
import CodewireKit
#if canImport(CodewireClientFFI)
import CodewireClientFFI
import SwiftTerm
#endif

struct ShellView: View {
    @EnvironmentObject var auth: AuthViewModel
    let env: CodewireKit.Environment
    @SwiftUI.Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            #if canImport(CodewireClientFFI)
            ShellSession(target: ShellTarget(
                serverUrl: auth.baseURL.absoluteString,
                accessToken: auth.accessToken ?? "",
                orgId: env.orgId,
                environmentId: env.id,
                term: "xterm-256color",
                columns: 80,
                rows: 24
            ))
            #else
            Text("This build has no shell. Build it on a Mac with apps/ios/scripts/build-rust.sh.")
                .foregroundStyle(.white)
                .padding()
            #endif
        }
        .overlay(alignment: .topLeading) {
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.white.opacity(0.7))
            }
            .padding()
        }
    }
}

#if canImport(CodewireClientFFI)
/// A shell and, once it has ended, a fresh one on Retry.
private struct ShellSession: View {
    let target: ShellTarget
    @State private var attempt = 0

    var body: some View {
        ShellAttempt(target: target) { attempt += 1 }
            .id(attempt)
    }
}

/// The terminal, with one status line under it: how the shell is connected,
/// or why it ended.
private struct ShellAttempt: View {
    let target: ShellTarget
    let retry: () -> Void
    @StateObject private var status = ShellStatus()

    var body: some View {
        VStack(spacing: 0) {
            TerminalContainer(target: target, status: status)
            HStack {
                Text(status.line)
                    .font(.caption.monospaced())
                    .foregroundStyle(.white.opacity(0.8))
                    .lineLimit(1)
                Spacer()
                if status.hasEnded {
                    Button("Retry", action: retry)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
    }
}

struct TerminalContainer: UIViewRepresentable {
    let target: ShellTarget
    let status: ShellStatus

    func makeUIView(context: Context) -> TerminalView {
        let view = TerminalView()
        view.terminalDelegate = context.coordinator
        context.coordinator.connect(to: view)
        return view
    }

    func updateUIView(_: TerminalView, context _: Context) {}

    static func dismantleUIView(_: TerminalView, coordinator: Coordinator) {
        coordinator.close()
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(target: target, observer: status.observer())
    }

    /// Feeds the shell's output to the terminal and the terminal's keys and
    /// size to the shell. A failed dial ends the status line with its reason.
    @MainActor
    final class Coordinator: NSObject {
        private let target: ShellTarget
        private let observer: ShellObserver
        private var shell: Shell?
        private var task: Task<Void, Never>?

        init(target: ShellTarget, observer: ShellObserver) {
            self.target = target
            self.observer = observer
        }

        func connect(to view: TerminalView) {
            let target = target
            let observer = observer
            task = Task { [weak self, weak view] in
                let shell: Shell
                do {
                    shell = try await Shell.dial(target: target, observer: observer)
                } catch {
                    // A refused target fails before the shell reports any
                    // state, and a shell that can't start may fail without
                    // ending; either way the status line says why.
                    let message = (error as? ShellError)?.message ?? "\(error)"
                    observer.stateChanged(state: .ended(exitStatus: nil, error: message))
                    return
                }
                guard let self, !Task.isCancelled else {
                    shell.close()
                    return
                }
                self.shell = shell
                // The terminal may have laid out before the shell existed.
                if let terminal = view?.getTerminal() {
                    try? shell.resize(columns: UInt16(terminal.cols), rows: UInt16(terminal.rows))
                }
                while let data = await shell.read() {
                    view?.feed(byteArray: ArraySlice([UInt8](data)))
                }
            }
        }

        func close() {
            task?.cancel()
            shell?.close()
            shell = nil
        }
    }
}

extension TerminalContainer.Coordinator: @preconcurrency TerminalViewDelegate {
    func send(source _: TerminalView, data: ArraySlice<UInt8>) {
        try? shell?.write(data: Data(data))
    }

    func sizeChanged(source _: TerminalView, newCols: Int, newRows: Int) {
        try? shell?.resize(columns: UInt16(newCols), rows: UInt16(newRows))
    }

    func scrolled(source _: TerminalView, position _: Double) {}
    func setTerminalTitle(source _: TerminalView, title _: String) {}
    func requestOpenLink(source _: TerminalView, link _: String, params _: [String: String]) {}
    func hostCurrentDirectoryUpdate(source _: TerminalView, directory _: String?) {}
    func rangeChanged(source _: TerminalView, startY _: Int, endY _: Int) {}
    func clipboardCopy(source _: TerminalView, content _: Data) {}
}
#endif
#endif
