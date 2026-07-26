#if canImport(SwiftUI)
import SwiftUI

struct AuthView: View {
    @EnvironmentObject var auth: AuthViewModel
    @State private var email = ""
    @State private var password = ""
    @State private var totpCode = ""
    @FocusState private var focusedField: Field?

    enum Field { case email, password, totp }

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
                    if auth.needsTwoFactor {
                        Text("Enter your 2FA code")
                            .font(.headline)

                        TextField("123456", text: $totpCode)
                            .keyboardType(.numberPad)
                            .textFieldStyle(.roundedBorder)
                            .multilineTextAlignment(.center)
                            .font(.title2.monospacedDigit())
                            .focused($focusedField, equals: .totp)
                            .onSubmit { auth.submitTOTP(code: totpCode) }

                        Button(action: { auth.submitTOTP(code: totpCode) }) {
                            Group {
                                if auth.isLoading {
                                    ProgressView()
                                } else {
                                    Text("Verify")
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding()
                        }
                        .background(.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .disabled(auth.isLoading)

                        Button("Back") {
                            auth.needsTwoFactor = false
                            auth.error = nil
                            totpCode = ""
                        }
                        .font(.caption)
                    } else {
                        TextField("Email", text: $email)
                            .textContentType(.username)
                            .keyboardType(.emailAddress)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .textFieldStyle(.roundedBorder)
                            .focused($focusedField, equals: .email)
                            .submitLabel(.next)
                            .onSubmit { focusedField = .password }

                        SecureField("Password", text: $password)
                            .textContentType(.password)
                            .textFieldStyle(.roundedBorder)
                            .focused($focusedField, equals: .password)
                            .submitLabel(.go)
                            .onSubmit { auth.signIn(email: email, password: password) }

                        Button(action: { auth.signIn(email: email, password: password) }) {
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
                        .disabled(auth.isLoading || email.isEmpty || password.isEmpty)
                    }

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
        .onTapGesture { focusedField = nil }
    }
}
#endif
