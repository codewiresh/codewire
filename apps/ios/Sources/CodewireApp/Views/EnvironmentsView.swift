#if canImport(SwiftUI)
import SwiftUI
import CodewireKit

struct EnvironmentsView: View {
    @EnvironmentObject var auth: AuthViewModel
    let org: Organization

    @State private var environments: [CodewireKit.Environment] = []
    @State private var error: String?
    @State private var isLoading = true

    var body: some View {
        Group {
            if isLoading {
                ProgressView("Loading environments...")
            } else if let error = error {
                ContentUnavailableView(
                    "Failed to load",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error)
                )
            } else if environments.isEmpty {
                ContentUnavailableView(
                    "No environments",
                    systemImage: "cube",
                    description: Text("Create an environment to get started")
                )
            } else {
                List {
                    ForEach(environments, id: \.id) { env in
                        NavigationLink(destination: EnvironmentDetailView(org: org, env: env, onRefresh: { await loadEnvironments() })) {
                            EnvironmentRow(env: env)
                        }
                    }
                }
            }
        }
        .navigationTitle(org.name)
        .task {
            await loadEnvironments()
        }
        .refreshable {
            await loadEnvironments()
        }
    }

    private func loadEnvironments() async {
        guard let token = auth.accessToken else { return }
        isLoading = true
        do {
            environments = try await auth.client.listEnvironments(token: token, orgID: org.id)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }
}

struct EnvironmentRow: View {
    let env: CodewireKit.Environment

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(env.name)
                    .font(.headline)

                HStack(spacing: 8) {
                    Text(env.state)
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(stateColor.opacity(0.15))
                        .foregroundStyle(stateColor)
                        .clipShape(Capsule())

                    Text("\(env.cpuMillicores / 1000) CPU, \(env.memoryMb / 1024) GB")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Image(systemName: stateIcon)
                .foregroundStyle(stateColor)
        }
        .padding(.vertical, 4)
    }

    private var stateColor: Color {
        switch env.state {
        case "running": return .green
        case "stopped": return .gray
        case "starting", "stopping": return .orange
        case "error": return .red
        default: return .secondary
        }
    }

    private var stateIcon: String {
        switch env.state {
        case "running": return "circle.fill"
        case "stopped": return "circle"
        case "starting", "stopping": return "circle.dotted"
        case "error": return "exclamationmark.circle.fill"
        default: return "questionmark.circle"
        }
    }
}
#endif
