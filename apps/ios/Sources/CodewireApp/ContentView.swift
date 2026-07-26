#if canImport(SwiftUI)
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var auth: AuthViewModel

    var body: some View {
        Group {
            if auth.isAuthenticated {
                OrganizationsView()
            } else {
                AuthView()
            }
        }
        .task {
            auth.checkExistingToken()
        }
    }
}
#endif
