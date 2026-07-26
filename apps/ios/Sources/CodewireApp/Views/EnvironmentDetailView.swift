#if canImport(SwiftUI)
import SwiftUI
import CodewireKit

struct EnvironmentDetailView: View {
    @EnvironmentObject var auth: AuthViewModel
    @SwiftUI.Environment(\.dismiss) private var dismiss
    let org: Organization
    @State var env: CodewireKit.Environment
    let onRefresh: () async -> Void

    @State private var isActioning = false
    @State private var error: String?
    @State private var showShell = false
    @State private var showDeleteConfirm = false

    var body: some View {
        List {
            Section("Status") {
                LabeledContent("State", value: env.state)
                LabeledContent("Desired", value: env.desiredState)
                if let reason = env.errorReason {
                    LabeledContent("Error") {
                        Text(reason)
                            .foregroundStyle(.red)
                    }
                }
            }

            Section("Resources") {
                LabeledContent("CPU", value: "\(env.cpuMillicores / 1000) cores")
                LabeledContent("Memory", value: "\(env.memoryMb / 1024) GB")
                LabeledContent("Disk", value: "\(env.diskGb) GB")
            }

            Section("Info") {
                LabeledContent("ID", value: env.id)
                LabeledContent("Created", value: env.createdAt)
            }

            Section {
                if env.state == "running" {
                    Button {
                        showShell = true
                    } label: {
                        Label("Open Shell", systemImage: "terminal")
                    }

                    Button(role: .destructive) {
                        Task { await stopEnvironment() }
                    } label: {
                        Label("Stop Environment", systemImage: "stop.circle")
                    }
                    .disabled(isActioning)
                } else if env.state == "stopped" {
                    Button {
                        Task { await startEnvironment() }
                    } label: {
                        Label("Start Environment", systemImage: "play.circle")
                    }
                    .disabled(isActioning)
                }

                Button(role: .destructive) {
                    showDeleteConfirm = true
                } label: {
                    Label("Delete Environment", systemImage: "trash")
                }
                .disabled(isActioning)
            }

            if isActioning {
                Section {
                    HStack {
                        ProgressView()
                        Text("Working...")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if let error = error {
                Section {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                }
            }
        }
        .navigationTitle(env.name)
        .confirmationDialog("Delete Environment", isPresented: $showDeleteConfirm) {
            Button("Delete \(env.name)", role: .destructive) {
                Task { await deleteEnvironment() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will permanently delete the environment and all its data.")
        }
        .fullScreenCover(isPresented: $showShell) {
            ShellView(env: env)
        }
    }

    // MARK: - Actions

    private func startEnvironment() async {
        guard let token = auth.accessToken else { return }
        isActioning = true
        do {
            try await auth.client.startEnvironment(token: token, orgID: org.id, envID: env.id)
            error = nil
            await onRefresh()
        } catch {
            self.error = error.localizedDescription
        }
        isActioning = false
    }

    private func stopEnvironment() async {
        guard let token = auth.accessToken else { return }
        isActioning = true
        do {
            try await auth.client.stopEnvironment(token: token, orgID: org.id, envID: env.id)
            error = nil
            await onRefresh()
        } catch {
            self.error = error.localizedDescription
        }
        isActioning = false
    }

    private func deleteEnvironment() async {
        guard let token = auth.accessToken else { return }
        isActioning = true
        do {
            try await auth.client.deleteEnvironment(token: token, orgID: org.id, envID: env.id)
            error = nil
            await onRefresh()
            dismiss()
        } catch {
            self.error = error.localizedDescription
            isActioning = false
        }
    }
}
#endif
