#if canImport(SwiftUI)
import SwiftUI
import CodewireKit

struct AuthView: View {
    @EnvironmentObject var auth: AuthViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 32) {
                Spacer(minLength: 60)

                VStack(spacing: 12) {
                    Image(systemName: "cloud.fill")
                        .font(.system(size: 64))
                        .foregroundStyle(.blue)

                    Text("Codewire")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Cloud development environments")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: 40)

                VStack(spacing: 16) {
                    Text("Sign in securely in your browser to continue.")
                        .font(.subheadline)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)

                    Button(action: { auth.beginSignIn() }) {
                        Group {
                            if auth.isLoading {
                                ProgressView()
                            } else {
                                Text("Sign In")
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                    }
                    .background(.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .disabled(auth.isLoading)

                    #if DEBUG
                    Picker(
                        "Test server",
                        selection: Binding(
                            get: { auth.environment },
                            set: { auth.selectEnvironment($0) }
                        )
                    ) {
                        ForEach(CodewireEndpoint.allCases) { environment in
                            Text(environment.displayName).tag(environment)
                        }
                    }
                    .pickerStyle(.segmented)
                    .disabled(auth.isLoading)
                    .accessibilityHint("Debug builds only")
                    #endif

                    if let error = auth.error {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                    }
                }
                .padding(.horizontal, 32)
                .padding(.bottom, 48)
            }
        }
    }
}
#endif
