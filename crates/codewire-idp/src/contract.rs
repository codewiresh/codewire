//! Rust-owned OpenAPI preview for IdP auth routes.
//!
//! This service-local preview records the IdP service's Rust DTOs and route
//! metadata for the merged canonical contract without changing runtime
//! handlers.

use codewire_api_contract::{Method, OpenApiBuilder, Operation, with_standard_health_routes};
use schemars::JsonSchema;
use serde::Serialize;

use crate::auth_session::{
    AuthResponse, SignInRequest, SignInResponseBody, SignOutBody, SignUpRequest,
};
use crate::email_password::{
    ForgetPasswordRequest, ForgetPasswordResponse, ResetPasswordRequest, ResetPasswordResponse,
    SendVerificationResponse, VerifyEmailResponse,
};
use crate::two_factor::{
    CodeRequest, DisableResponse, EnableResponse, ValidateRequest, VerifyResponse,
};

#[derive(Serialize, JsonSchema)]
#[serde(transparent)]
pub struct GetSessionResponse(Option<AuthResponse>);

pub fn rust_openapi_preview() -> serde_json::Value {
    let set_cookie = serde_json::json!({ "type": "string" });

    with_standard_health_routes(OpenApiBuilder::new(
        "Codewire IdP Rust API Preview",
        "0.1.0",
    ))
    .operation(
        "/api/auth/sign-up",
        Method::Post,
        Operation::new("signUp")
            .tag("auth")
            .summary("Create a new account")
            .json_request::<SignUpRequest>("SignUpRequest")
            .json_response::<AuthResponse>(200, "OK", "AuthResponse")
            .response_header(200, "Set-Cookie", set_cookie.clone()),
    )
    .operation(
        "/api/auth/sign-in",
        Method::Post,
        Operation::new("signIn")
            .tag("auth")
            .summary("Sign in to an existing account")
            .json_request::<SignInRequest>("SignInRequest")
            .json_response::<SignInResponseBody>(200, "OK", "SignInResponseBody")
            .response_header(200, "Set-Cookie", set_cookie.clone()),
    )
    .operation(
        "/api/auth/sign-out",
        Method::Post,
        Operation::new("signOut")
            .tag("auth")
            .summary("Sign out and invalidate session")
            .json_response::<SignOutBody>(200, "OK", "SignOutOutputBody")
            .response_header(200, "Set-Cookie", set_cookie.clone()),
    )
    .operation(
        "/api/auth/get-session",
        Method::Get,
        Operation::new("getSession")
            .tag("auth")
            .summary("Get current session")
            .json_response::<GetSessionResponse>(200, "OK", "GetSessionResponse"),
    )
    .operation(
        "/api/auth/verify-email",
        Method::Get,
        Operation::new("verifyEmail")
            .tag("auth")
            .summary("Verify email with token")
            .required_query_param(
                "token",
                serde_json::json!({
                    "type": "string",
                    "description": "Verification token",
                }),
            )
            .json_response::<VerifyEmailResponse>(200, "OK", "VerifyEmailOutputBody"),
    )
    .operation(
        "/api/auth/forget-password",
        Method::Post,
        Operation::new("forgetPassword")
            .tag("auth")
            .summary("Request a password reset email")
            .json_request::<ForgetPasswordRequest>("ForgetPasswordInputBody")
            .json_response::<ForgetPasswordResponse>(200, "OK", "ForgetPasswordOutputBody"),
    )
    .operation(
        "/api/auth/reset-password",
        Method::Post,
        Operation::new("resetPassword")
            .tag("auth")
            .summary("Reset password with token")
            .json_request::<ResetPasswordRequest>("ResetPasswordInputBody")
            .json_response::<ResetPasswordResponse>(200, "OK", "ResetPasswordOutputBody"),
    )
    .operation(
        "/api/auth/send-verification-email",
        Method::Post,
        Operation::new("sendVerificationEmail")
            .tag("auth")
            .summary("Send email verification link")
            .json_response::<SendVerificationResponse>(200, "OK", "SendVerificationOutputBody"),
    )
    .operation(
        "/api/auth/two-factor/enable",
        Method::Post,
        Operation::new("enableTwoFactor")
            .tag("two-factor")
            .summary("Start 2FA setup")
            .json_response::<EnableResponse>(200, "OK", "EnableTwoFactorResult"),
    )
    .operation(
        "/api/auth/two-factor/verify",
        Method::Post,
        Operation::new("verifyTwoFactor")
            .tag("two-factor")
            .summary("Confirm 2FA setup with TOTP code")
            .json_request::<CodeRequest>("TwoFactorCodeInputBody")
            .json_response::<VerifyResponse>(200, "OK", "TwoFactorVerifyOutputBody"),
    )
    .operation(
        "/api/auth/two-factor/disable",
        Method::Post,
        Operation::new("disableTwoFactor")
            .tag("two-factor")
            .summary("Disable 2FA")
            .json_response::<DisableResponse>(200, "OK", "TwoFactorDisableOutputBody"),
    )
    .operation(
        "/api/auth/two-factor/validate",
        Method::Post,
        Operation::new("validateTOTP")
            .tag("two-factor")
            .summary("Validate TOTP code during sign-in")
            .json_request::<ValidateRequest>("ValidateTOTPInputBody")
            .json_response::<AuthResponse>(200, "OK", "AuthResponse")
            .response_header(200, "Set-Cookie", set_cookie),
    )
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_contains_auth_route_families() {
        let doc = rust_openapi_preview();

        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(
            doc["paths"]["/healthz"]["get"]["responses"]["200"]["content"]["text/plain"]["schema"]
                ["type"],
            "string"
        );

        for path in [
            "/api/auth/sign-up",
            "/api/auth/sign-in",
            "/api/auth/sign-out",
            "/api/auth/get-session",
            "/api/auth/verify-email",
            "/api/auth/forget-password",
            "/api/auth/reset-password",
            "/api/auth/send-verification-email",
            "/api/auth/two-factor/enable",
            "/api/auth/two-factor/verify",
            "/api/auth/two-factor/disable",
            "/api/auth/two-factor/validate",
        ] {
            assert!(doc["paths"][path].is_object(), "missing {path}");
        }

        assert_eq!(
            doc["paths"]["/api/auth/sign-up"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/SignUpRequest"
        );
        assert_eq!(
            doc["paths"]["/api/auth/sign-up"]["post"]["responses"]["200"]["headers"]["Set-Cookie"]
                ["schema"]["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/api/auth/verify-email"]["get"]["parameters"][0]["required"],
            true
        );
        assert_eq!(
            doc["paths"]["/api/auth/two-factor/validate"]["post"]["responses"]["200"]["headers"]["Set-Cookie"]
                ["schema"]["type"],
            "string"
        );
    }

    #[test]
    fn preview_components_come_from_idp_rust_dtos() {
        let doc = rust_openapi_preview();

        assert_eq!(
            doc["components"]["schemas"]["AuthResponse"]["properties"]["skip_2fa_setup"]["type"],
            "boolean"
        );
        assert!(
            !doc["components"]["schemas"]["AuthResponse"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "skip_2fa_setup")
        );
        assert_eq!(
            doc["components"]["schemas"]["SignInResponseBody"]["properties"]["twoFactorRequired"]["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["ValidateTOTPInputBody"]["properties"]["token"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["SignUpRequest"]["required"],
            serde_json::json!(["email", "password"])
        );
        assert!(
            !doc["components"]["schemas"]["SignUpRequest"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "name" || value == "invite_code")
        );
        assert_eq!(
            doc["components"]["schemas"]["SignInRequest"]["required"],
            serde_json::json!(["email", "password"])
        );
        assert_eq!(
            doc["components"]["schemas"]["ForgetPasswordInputBody"]["required"],
            serde_json::json!(["email"])
        );
        assert_eq!(
            doc["components"]["schemas"]["ResetPasswordInputBody"]["required"],
            serde_json::json!(["token", "newPassword"])
        );
        assert_eq!(
            doc["components"]["schemas"]["TwoFactorCodeInputBody"]["required"],
            serde_json::json!(["code"])
        );
        assert_eq!(
            doc["components"]["schemas"]["ValidateTOTPInputBody"]["required"],
            serde_json::json!(["code", "token"])
        );
    }
}
