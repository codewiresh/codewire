#if canImport(SwiftUI)
import SwiftUI
import SwiftTerm
import CodewireKit

/// Wrapper to safely send non-Sendable values across actor boundaries
/// when we know the usage is safe (e.g., only accessed on main actor).
private struct UnsafeSend<T>: @unchecked Sendable {
    let value: T
}

struct ShellView: View {
    @EnvironmentObject var auth: AuthViewModel
    let env: CodewireKit.Environment
    @SwiftUI.Environment(\.dismiss) private var dismiss

    @State private var error: String?
    @State private var isConnecting = true
    @State private var sessionEnded = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            if isConnecting {
                VStack(spacing: 16) {
                    ProgressView()
                        .tint(.white)
                    Text("Connecting to \(env.name)...")
                        .foregroundStyle(.white)
                }
            } else {
                TerminalContainer(
                    env: env,
                    serverURL: auth.baseURL.absoluteString,
                    token: auth.accessToken ?? "",
                    onError: { msg in error = msg },
                    onConnected: { isConnecting = false },
                    onEnded: { sessionEnded = true }
                )
            }
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
        .alert("Connection Failed", isPresented: .constant(error != nil)) {
            Button("Retry") {
                error = nil
                isConnecting = true
            }
            Button("Close") { dismiss() }
        } message: {
            Text(error ?? "")
        }
        .alert("Session Ended", isPresented: $sessionEnded) {
            Button("Close") { dismiss() }
        }
    }
}

struct TerminalContainer: UIViewRepresentable {
    let env: CodewireKit.Environment
    let serverURL: String
    let token: String
    let onError: (String) -> Void
    let onConnected: () -> Void
    let onEnded: () -> Void

    func makeUIView(context: Context) -> TerminalView {
        let tv = TerminalView()
        tv.terminalDelegate = context.coordinator
        context.coordinator.terminalView = tv
        context.coordinator.connect()
        return tv
    }

    func updateUIView(_ uiView: TerminalView, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(
            env: env,
            serverURL: serverURL,
            token: token,
            onError: onError,
            onConnected: onConnected,
            onEnded: onEnded
        )
    }

    class Coordinator: NSObject, TerminalViewDelegate, @unchecked Sendable {
        let env: CodewireKit.Environment
        let serverURL: String
        let token: String
        let onError: (String) -> Void
        let onConnected: () -> Void
        let onEnded: () -> Void

        weak var terminalView: TerminalView?
        private var handle: CwShellHandle?
        private var readTask: Task<Void, Never>?

        init(env: CodewireKit.Environment, serverURL: String, token: String,
             onError: @escaping (String) -> Void,
             onConnected: @escaping () -> Void,
             onEnded: @escaping () -> Void) {
            self.env = env
            self.serverURL = serverURL
            self.token = token
            self.onError = onError
            self.onConnected = onConnected
            self.onEnded = onEnded
        }

        func connect() {
            // Use default size for initial dial; real size sent via resize() after layout
            let cols: UInt16 = 80
            let rows: UInt16 = 24
            let serverURL = self.serverURL
            let token = self.token
            let orgId = self.env.orgId
            let envId = self.env.id
            let connected = UnsafeSend(value: self.onConnected)
            let errHandler = UnsafeSend(value: self.onError)
            let tv = UnsafeSend(value: self.terminalView)
            let ended = UnsafeSend(value: self.onEnded)
            Task.detached { [weak self] in
                do {
                    let config = CwShellDialConfig(
                        serverURL: serverURL, token: token,
                        orgID: orgId, envID: envId,
                        cols: cols, rows: rows
                    )
                    let h = try CwShellHandle.dial(config: config)
                    self?.handle = h
                    await MainActor.run { connected.value() }
                    let readTask = Task.detached {
                        var buffer = [UInt8](repeating: 0, count: 8192)
                        while !Task.isCancelled {
                            do {
                                let n = try buffer.withUnsafeMutableBufferPointer { buf in
                                    try h.read(into: buf.baseAddress!, length: buf.count)
                                }
                                if n == 0 { break }
                                let slice = Array(buffer[0..<n])
                                await MainActor.run { tv.value?.feed(byteArray: ArraySlice(slice)) }
                            } catch {
                                await MainActor.run { ended.value() }
                                break
                            }
                        }
                    }
                    self?.readTask = readTask
                } catch {
                    await MainActor.run { errHandler.value("\(error)") }
                }
            }
        }

        deinit {
            readTask?.cancel()
            handle?.close()
        }

        // MARK: - TerminalViewDelegate

        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            let bytes = Array(data)
            guard let handle = self.handle else { return }
            Task.detached {
                try? handle.write(bytes)
            }
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            guard let handle = self.handle else { return }
            Task.detached {
                try? handle.resize(cols: UInt16(newCols), rows: UInt16(newRows))
            }
        }

        func scrolled(source: TerminalView, position: Double) {}
        func setTerminalTitle(source: TerminalView, title: String) {}
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
        func clipboardCopy(source: TerminalView, content: Data) {}
    }
}
#endif
