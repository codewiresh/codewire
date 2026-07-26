#if canImport(SwiftUI)
import SwiftUI
import CodewireKit

struct OrganizationsView: View {
    @EnvironmentObject var auth: AuthViewModel
    @State private var orgs: [Organization] = []
    @State private var error: String?
    @State private var isLoading = true
    @State private var showSignOutConfirm = false

    var body: some View {
        NavigationStack {
            Group {
                if isLoading && orgs.isEmpty {
                    ProgressView("Loading organizations...")
                } else if let error = error, orgs.isEmpty {
                    ContentUnavailableView(
                        "Failed to load",
                        systemImage: "exclamationmark.triangle",
                        description: Text(error)
                    )
                } else if orgs.isEmpty {
                    ContentUnavailableView(
                        "No organizations",
                        systemImage: "building.2",
                        description: Text("You're not a member of any organizations yet")
                    )
                } else {
                    List(orgs, id: \.id) { org in
                        NavigationLink(destination: EnvironmentsView(org: org)) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(org.name)
                                    .font(.headline)
                                Text(org.slug)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Organizations")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Sign Out") {
                        showSignOutConfirm = true
                    }
                }
            }
            .confirmationDialog("Sign Out", isPresented: $showSignOutConfirm) {
                Button("Sign Out", role: .destructive) { auth.signOut() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Are you sure you want to sign out?")
            }
            .task {
                await loadOrgs()
            }
            .refreshable {
                await loadOrgs()
            }
        }
    }

    private func loadOrgs() async {
        guard let token = auth.accessToken else { return }
        isLoading = true
        do {
            orgs = try await auth.client.listOrganizations(token: token)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }
}
#endif
