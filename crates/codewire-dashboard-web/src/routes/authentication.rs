use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use qrcode::{QrCode, render::svg};
use serde::{Deserialize, Serialize};

use crate::{
    auth::authenticated_identity,
    error::WebError,
    raw_auth::{forward_session_cookies, post_json, user_message},
    response::{error_page, redirect, render_page, render_template, safe_auth_continuation},
    security::{
        PASSWORD_RESET_COOKIE, TWO_FACTOR_CHALLENGE_COOKIE, canonical_cookie, clear_scoped_cookie,
        cookie_value, csrf_cookie, new_csrf_token, request_has_same_origin, scoped_secret_cookie,
        valid_csrf_token, with_csrf_cookie, with_response_cookie,
    },
    state::AppState,
    templates::{
        AuthFormTemplate, AuthStatusTemplate, SetupTwoFactorTemplate, TwoFactorRecoveryTemplate,
    },
    view::{
        AuthFormSubmission, AuthFormView, AuthQuery, SetupTwoFactorView, TwoFactorRecoveryView,
    },
};

const SECRET_TTL_SECONDS: u32 = 10 * 60;

#[derive(Serialize)]
struct CredentialsRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct SignUpRequest<'a> {
    email: &'a str,
    password: &'a str,
    name: &'a str,
    invite_code: &'a str,
}

#[derive(Serialize)]
struct EmailRequest<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct ResetPasswordRequest<'a> {
    token: &'a str,
    #[serde(rename = "newPassword")]
    new_password: &'a str,
}

#[derive(Serialize)]
struct CodeRequest<'a> {
    code: &'a str,
}

#[derive(Serialize)]
struct ValidateTwoFactorRequest<'a> {
    code: &'a str,
    token: &'a str,
}

#[derive(Debug, Deserialize)]
struct AuthUserResponse {
    #[serde(default)]
    two_factor_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct SignInResponse {
    user: Option<AuthUserResponse>,
    #[serde(default, rename = "twoFactorRequired")]
    two_factor_required: bool,
    #[serde(default, rename = "twoFactorToken")]
    two_factor_token: String,
}

#[derive(Debug, Deserialize)]
struct SuccessResponse {
    #[allow(dead_code)]
    #[serde(default)]
    success: bool,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    #[allow(dead_code)]
    user: AuthUserResponse,
}

#[derive(Debug, Deserialize)]
struct SentResponse {
    #[allow(dead_code)]
    sent: bool,
}

#[derive(Debug, Deserialize)]
struct ResetResponse {
    #[allow(dead_code)]
    reset: bool,
}

#[derive(Debug, Deserialize)]
struct TwoFactorEnableResponse {
    #[serde(rename = "totpUri")]
    totp_uri: String,
    secret: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EnabledResponse {
    #[allow(dead_code)]
    enabled: bool,
}

pub(super) async fn login(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Response {
    auth_form_response(&state, StatusCode::OK, login_view(query, String::new()))
}

pub(super) async fn login_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let query = form_query(&form);
    if form.email.trim().is_empty() || form.password.is_empty() {
        return auth_form_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            login_view(query, "Email and password are required.".to_owned()),
        );
    }
    let identity = match post_json::<_, SignInResponse>(
        &state,
        "/api/auth/sign-in",
        None,
        &CredentialsRequest {
            email: form.email.trim(),
            password: &form.password,
        },
    )
    .await
    {
        Ok(response) => response,
        Err(()) => {
            return auth_form_response(
                &state,
                StatusCode::BAD_GATEWAY,
                login_view(
                    query,
                    "The identity service is temporarily unavailable.".to_owned(),
                ),
            );
        }
    };
    if !identity.status.is_success() {
        return auth_form_response(
            &state,
            identity.status,
            login_view(query, user_message(identity.status, "sign-in").to_owned()),
        );
    }
    let body = match identity.body.as_ref() {
        Some(body) => body,
        None => return error_page(WebError::IdentityUnavailable),
    };
    let completion = completion_target(&form.auth_request_id, &form.return_to);
    if body.two_factor_required {
        let Some(cookie) = scoped_secret_cookie(
            &state.public_origin,
            TWO_FACTOR_CHALLENGE_COOKIE,
            &body.two_factor_token,
            "/two-factor",
            SECRET_TTL_SECONDS,
        ) else {
            return error_page(WebError::IdentityUnavailable);
        };
        let response = redirect(auth_path("/two-factor", &form), &headers);
        return with_response_cookie(response, cookie);
    }
    let target = if body
        .user
        .as_ref()
        .is_some_and(|user| user.two_factor_enabled)
    {
        completion
    } else {
        auth_url_for_target("/setup-2fa", &completion)
    };
    forward_session_cookies(redirect(target, &headers), &identity)
}

pub(super) async fn signup(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Response {
    auth_form_response(&state, StatusCode::OK, signup_view(query, String::new()))
}

pub(super) async fn signup_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let query = form_query(&form);
    let error = validate_new_password(&form);
    if !error.is_empty() || form.email.trim().is_empty() || form.name.trim().is_empty() {
        let error = if error.is_empty() {
            "Name and email are required.".to_owned()
        } else {
            error
        };
        return auth_form_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_view(query, error),
        );
    }
    let identity = match post_json::<_, AuthResponse>(
        &state,
        "/api/auth/sign-up",
        None,
        &SignUpRequest {
            email: form.email.trim(),
            password: &form.password,
            name: form.name.trim(),
            invite_code: form.invite_code.trim(),
        },
    )
    .await
    {
        Ok(response) => response,
        Err(()) => {
            return auth_form_response(
                &state,
                StatusCode::BAD_GATEWAY,
                signup_view(
                    query,
                    "The identity service is temporarily unavailable.".to_owned(),
                ),
            );
        }
    };
    if !identity.status.is_success() {
        return auth_form_response(
            &state,
            identity.status,
            signup_view(query, user_message(identity.status, "sign-up").to_owned()),
        );
    }
    let completion = completion_target(&form.auth_request_id, &form.return_to);
    forward_session_cookies(
        redirect(auth_url_for_target("/setup-2fa", &completion), &headers),
        &identity,
    )
}

pub(super) async fn forgot_password(State(state): State<AppState>) -> Response {
    auth_form_response(&state, StatusCode::OK, forgot_password_view(String::new()))
}

pub(super) async fn forgot_password_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    if form.email.trim().is_empty() {
        return auth_form_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            forgot_password_view("Email is required.".to_owned()),
        );
    }
    let result = post_json::<_, SentResponse>(
        &state,
        "/api/auth/forget-password",
        None,
        &EmailRequest {
            email: form.email.trim(),
        },
    )
    .await;
    if result
        .as_ref()
        .is_ok_and(|response| response.status.is_success())
    {
        return render_page(AuthStatusTemplate {
            title: "Check your email",
            description: "If an account exists for that address, a password reset link has been sent.",
            primary_label: "Back to sign in",
            primary_url: "/login",
        });
    }
    auth_form_response(
        &state,
        StatusCode::BAD_GATEWAY,
        forgot_password_view("The reset request could not be completed. Try again.".to_owned()),
    )
}

pub(super) async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    if !query.token.is_empty() {
        let Some(cookie) = scoped_secret_cookie(
            &state.public_origin,
            PASSWORD_RESET_COOKIE,
            &query.token,
            "/reset-password",
            SECRET_TTL_SECONDS,
        ) else {
            return invalid_reset_link();
        };
        return with_response_cookie(redirect("/reset-password".to_owned(), &headers), cookie);
    }
    if cookie_value(&headers, PASSWORD_RESET_COOKIE).is_none() {
        return invalid_reset_link();
    }
    auth_form_response(&state, StatusCode::OK, reset_password_view(String::new()))
}

pub(super) async fn reset_password_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let Some(token) = cookie_value(&headers, PASSWORD_RESET_COOKIE) else {
        return invalid_reset_link();
    };
    let error = validate_new_password(&form);
    if !error.is_empty() {
        return auth_form_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            reset_password_view(error),
        );
    }
    let identity = post_json::<_, ResetResponse>(
        &state,
        "/api/auth/reset-password",
        None,
        &ResetPasswordRequest {
            token,
            new_password: &form.password,
        },
    )
    .await;
    let response = match identity {
        Ok(response) if response.status.is_success() => render_page(AuthStatusTemplate {
            title: "Password reset",
            description: "Your password has been reset. You can now sign in with the new password.",
            primary_label: "Sign in",
            primary_url: "/login",
        }),
        Ok(response) => {
            return auth_form_response(
                &state,
                response.status,
                reset_password_view(user_message(response.status, "reset-password").to_owned()),
            );
        }
        Err(()) => {
            return auth_form_response(
                &state,
                StatusCode::BAD_GATEWAY,
                reset_password_view("The identity service is temporarily unavailable.".to_owned()),
            );
        }
    };
    with_response_cookie(
        response,
        clear_scoped_cookie(
            &state.public_origin,
            PASSWORD_RESET_COOKIE,
            "/reset-password",
        ),
    )
}

pub(super) async fn two_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    if cookie_value(&headers, TWO_FACTOR_CHALLENGE_COOKIE).is_none() {
        return auth_form_response(
            &state,
            StatusCode::BAD_REQUEST,
            two_factor_view(
                query,
                "The sign-in challenge is missing or expired.".to_owned(),
            ),
        );
    }
    auth_form_response(
        &state,
        StatusCode::OK,
        two_factor_view(query, String::new()),
    )
}

pub(super) async fn two_factor_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let Some(challenge) = cookie_value(&headers, TWO_FACTOR_CHALLENGE_COOKIE) else {
        return auth_form_response(
            &state,
            StatusCode::BAD_REQUEST,
            two_factor_view(
                form_query(&form),
                "The sign-in challenge is missing or expired.".to_owned(),
            ),
        );
    };
    let identity = match post_json::<_, AuthResponse>(
        &state,
        "/api/auth/two-factor/validate",
        None,
        &ValidateTwoFactorRequest {
            code: form.code.trim(),
            token: challenge,
        },
    )
    .await
    {
        Ok(response) => response,
        Err(()) => return error_page(WebError::IdentityUnavailable),
    };
    if !identity.status.is_success() {
        return auth_form_response(
            &state,
            identity.status,
            two_factor_view(
                form_query(&form),
                user_message(identity.status, "two-factor").to_owned(),
            ),
        );
    }
    let response = forward_session_cookies(
        redirect(
            completion_target(&form.auth_request_id, &form.return_to),
            &headers,
        ),
        &identity,
    );
    with_response_cookie(
        response,
        clear_scoped_cookie(
            &state.public_origin,
            TWO_FACTOR_CHALLENGE_COOKIE,
            "/two-factor",
        ),
    )
}

pub(super) async fn setup_two_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => {
            return redirect(
                auth_url_for_target("/login", setup_continuation(&query)),
                &headers,
            );
        }
        Err(error) => return error_page(error),
    };
    let target = safe_target(&query.return_to);
    if identity.two_factor_enabled() {
        return redirect(target, &headers);
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => {
            return redirect(
                auth_url_for_target("/login", setup_continuation(&query)),
                &headers,
            );
        }
    };
    let setup = match post_json::<_, TwoFactorEnableResponse>(
        &state,
        "/api/auth/two-factor/enable",
        Some(cookie),
        &EmptyRequest {},
    )
    .await
    {
        Ok(response) if response.status.is_success() => match response.body {
            Some(body) => body,
            None => return error_page(WebError::IdentityUnavailable),
        },
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            return redirect(
                auth_url_for_target("/login", setup_continuation(&query)),
                &headers,
            );
        }
        _ => return error_page(WebError::IdentityUnavailable),
    };
    setup_two_factor_response(&state, StatusCode::OK, &setup, target, String::new())
}

pub(super) async fn setup_two_factor_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return redirect(auth_url_for_target("/login", &form.return_to), &headers),
    };
    // Re-read the pending setup before verification. The IdP guarantees that
    // this is idempotent until verification, so an invalid form submission
    // can re-render the same QR and later reveal the same recovery-code set.
    let setup = match post_json::<_, TwoFactorEnableResponse>(
        &state,
        "/api/auth/two-factor/enable",
        Some(cookie.clone()),
        &EmptyRequest {},
    )
    .await
    {
        Ok(response) if response.status.is_success() => match response.body {
            Some(body) => body,
            None => return error_page(WebError::IdentityUnavailable),
        },
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            return redirect(auth_url_for_target("/login", &form.return_to), &headers);
        }
        _ => return error_page(WebError::IdentityUnavailable),
    };
    let result = post_json::<_, EnabledResponse>(
        &state,
        "/api/auth/two-factor/verify",
        Some(cookie),
        &CodeRequest {
            code: form.code.trim(),
        },
    )
    .await;
    match result {
        Ok(response) if response.status.is_success() => {
            let view = TwoFactorRecoveryView {
                return_to: safe_target(&form.return_to),
                backup_codes: setup.backup_codes,
            };
            render_page(TwoFactorRecoveryTemplate { view: &view })
        }
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            redirect(auth_url_for_target("/login", &form.return_to), &headers)
        }
        Ok(response) => setup_two_factor_response(
            &state,
            response.status,
            &setup,
            safe_target(&form.return_to),
            user_message(response.status, "two-factor-setup").to_owned(),
        ),
        Err(()) => error_page(WebError::IdentityUnavailable),
    }
}

fn setup_two_factor_response(
    state: &AppState,
    status: StatusCode,
    setup: &TwoFactorEnableResponse,
    return_to: String,
    error: String,
) -> Response {
    let qr_svg = match QrCode::new(setup.totp_uri.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(256, 256)
            .dark_color(svg::Color("#08090a"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(_) => return error_page(WebError::IdentityUnavailable),
    };
    let csrf = new_csrf_token();
    let view = SetupTwoFactorView {
        csrf_token: csrf.clone(),
        return_to,
        qr_svg,
        secret: setup.secret.clone(),
        error,
    };
    with_csrf_cookie(
        render_template(status, SetupTwoFactorTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

pub(super) async fn sign_out_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<crate::view::CsrfSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let cookie = canonical_cookie(&headers).ok();
    let identity =
        post_json::<_, SuccessResponse>(&state, "/api/auth/sign-out", cookie, &EmptyRequest {})
            .await;
    match identity {
        Ok(identity) => forward_session_cookies(redirect("/login".to_owned(), &headers), &identity),
        Err(()) => error_page(WebError::IdentityUnavailable),
    }
}

#[derive(Serialize)]
struct EmptyRequest {}

fn valid_form_request(state: &AppState, headers: &HeaderMap, csrf: &str) -> bool {
    request_has_same_origin(headers, &state.public_origin) && valid_csrf_token(headers, csrf)
}

fn auth_form_response(state: &AppState, status: StatusCode, mut view: AuthFormView) -> Response {
    let csrf = new_csrf_token();
    view.csrf_token = csrf.clone();
    with_csrf_cookie(
        render_template(status, AuthFormTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

fn form_query(form: &AuthFormSubmission) -> AuthQuery {
    AuthQuery {
        auth_request_id: form.auth_request_id.clone(),
        return_to: form.return_to.clone(),
        ..Default::default()
    }
}

fn base_view(query: AuthQuery) -> AuthFormView {
    AuthFormView {
        title: "",
        description: "",
        action: "",
        submit_label: "Continue",
        error: String::new(),
        csrf_token: String::new(),
        auth_request_id: clean_auth_request_id(&query.auth_request_id),
        return_to: safe_target(&query.return_to),
        show_email: false,
        show_password: false,
        new_password: false,
        show_confirm_password: false,
        show_name: false,
        show_invite_code: false,
        show_totp_code: false,
        forgot_password_link: false,
        secondary_label: "",
        secondary_url: String::new(),
    }
}

fn login_view(query: AuthQuery, error: String) -> AuthFormView {
    let mut view = base_view(query);
    view.title = "Sign in";
    view.description = "Welcome back to Codewire.";
    view.action = "/login/_actions/sign-in";
    view.submit_label = "Sign in";
    view.error = error;
    view.show_email = true;
    view.show_password = true;
    view.forgot_password_link = true;
    view.secondary_label = "Need an account? Create one";
    view.secondary_url = auth_path_from_view("/signup", &view);
    view
}

fn signup_view(query: AuthQuery, error: String) -> AuthFormView {
    let mut view = base_view(query);
    view.title = "Create your account";
    view.description = "Start running coding agents on dedicated machines.";
    view.action = "/signup/_actions/sign-up";
    view.submit_label = "Create account";
    view.error = error;
    view.show_email = true;
    view.show_password = true;
    view.new_password = true;
    view.show_confirm_password = true;
    view.show_name = true;
    // Preserve the current UI input and raw IdP field without inventing or
    // enforcing invite policy in this presentation adapter (#1352).
    view.show_invite_code = true;
    view.secondary_label = "Already have an account? Sign in";
    view.secondary_url = auth_path_from_view("/login", &view);
    view
}

fn forgot_password_view(error: String) -> AuthFormView {
    let mut view = base_view(AuthQuery::default());
    view.title = "Forgot password?";
    view.description = "Enter your email and we will send you a reset link.";
    view.action = "/forgot-password/_actions/request";
    view.submit_label = "Send reset link";
    view.error = error;
    view.show_email = true;
    view.secondary_label = "Back to sign in";
    view.secondary_url = "/login".to_owned();
    view
}

fn reset_password_view(error: String) -> AuthFormView {
    let mut view = base_view(AuthQuery::default());
    view.title = "Reset your password";
    view.description = "Enter a new password below.";
    view.action = "/reset-password/_actions/reset";
    view.submit_label = "Reset password";
    view.error = error;
    view.show_password = true;
    view.new_password = true;
    view.show_confirm_password = true;
    view
}

fn two_factor_view(query: AuthQuery, error: String) -> AuthFormView {
    let mut view = base_view(query);
    view.title = "Two-factor authentication";
    view.description = "Enter the six-digit code from your authenticator app or a recovery code.";
    view.action = "/two-factor/_actions/validate";
    view.submit_label = "Verify";
    view.error = error;
    view.show_totp_code = true;
    view
}

fn invalid_reset_link() -> Response {
    render_template(
        StatusCode::BAD_REQUEST,
        AuthStatusTemplate {
            title: "Invalid or expired link",
            description: "This password reset link is invalid or has expired. Request a new one.",
            primary_label: "Request a new reset link",
            primary_url: "/forgot-password",
        },
    )
}

fn validate_new_password(form: &AuthFormSubmission) -> String {
    if form.password != form.confirm_password {
        return "Passwords do not match.".to_owned();
    }
    let password = form.password.as_bytes();
    if password.len() < 12
        || !password.iter().any(u8::is_ascii_uppercase)
        || !password.iter().any(u8::is_ascii_lowercase)
        || !password.iter().any(u8::is_ascii_digit)
        || !password.iter().any(|byte| !byte.is_ascii_alphanumeric())
    {
        return "Use at least 12 characters with uppercase, lowercase, a number, and a symbol."
            .to_owned();
    }
    String::new()
}

fn completion_target(auth_request_id: &str, return_to: &str) -> String {
    let auth_request_id = clean_auth_request_id(auth_request_id);
    if !auth_request_id.is_empty() {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("id", &auth_request_id)
            .finish();
        format!("/api/oidc/callback?{query}")
    } else {
        safe_target(return_to)
    }
}

fn clean_auth_request_id(value: &str) -> String {
    if value.len() <= 256 && value.bytes().all(|byte| !byte.is_ascii_control()) {
        value.to_owned()
    } else {
        String::new()
    }
}

fn safe_target(value: &str) -> String {
    safe_auth_continuation(value)
        .unwrap_or("/dashboard")
        .to_owned()
}

fn auth_url_for_target(path: &str, target: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "return_to",
            safe_auth_continuation(target).unwrap_or("/dashboard"),
        )
        .finish();
    format!("{path}?{query}")
}

fn auth_path(path: &str, form: &AuthFormSubmission) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !clean_auth_request_id(&form.auth_request_id).is_empty() {
        query.append_pair("authRequestID", &form.auth_request_id);
    }
    if let Some(target) = safe_auth_continuation(&form.return_to) {
        query.append_pair("return_to", target);
    }
    let query = query.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

fn auth_path_from_view(path: &str, view: &AuthFormView) -> String {
    let form = AuthFormSubmission {
        csrf: String::new(),
        email: String::new(),
        password: String::new(),
        confirm_password: String::new(),
        name: String::new(),
        invite_code: String::new(),
        code: String::new(),
        auth_request_id: view.auth_request_id.clone(),
        return_to: view.return_to.clone(),
    };
    auth_path(path, &form)
}

fn setup_continuation(query: &AuthQuery) -> &str {
    safe_auth_continuation(&query.return_to).unwrap_or("/dashboard")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_and_challenges_are_not_part_of_auth_urls() {
        let form = AuthFormSubmission {
            csrf: "csrf".into(),
            email: "person@example.test".into(),
            password: "VerySecretPassword9!".into(),
            confirm_password: "VerySecretPassword9!".into(),
            name: "Person".into(),
            invite_code: "invite-secret".into(),
            code: "123456".into(),
            auth_request_id: "request-id".into(),
            return_to: "/dashboard".into(),
        };
        let url = auth_path("/two-factor", &form);
        assert!(url.contains("request-id"));
        for secret in [&form.password, &form.invite_code, &form.code, &form.email] {
            assert!(!url.contains(secret));
        }
    }

    #[test]
    fn password_validation_matches_the_idp_contract_shape() {
        let mut form = AuthFormSubmission {
            csrf: String::new(),
            email: String::new(),
            password: "weak".into(),
            confirm_password: "weak".into(),
            name: String::new(),
            invite_code: String::new(),
            code: String::new(),
            auth_request_id: String::new(),
            return_to: String::new(),
        };
        assert!(!validate_new_password(&form).is_empty());
        form.password = "CorrectHorse9#xy".into();
        form.confirm_password = form.password.clone();
        assert!(validate_new_password(&form).is_empty());
    }
}
