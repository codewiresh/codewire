#if canImport(SwiftUI)
import SwiftUI

@main
struct CodewireApp: App {
    @StateObject private var auth = AuthViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
        }
    }
}
#endif
