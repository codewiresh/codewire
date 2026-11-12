use std::fmt;

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use qrcode::{QrCode, render::svg};
use serde::{Deserialize, Serialize};

use crate::{
    auth::authenticated_identity,
    error::WebError,
    raw_auth::{
        IdentityErrorCode, forward_session_cookies, oauth_providers, post_json, user_message,
    },
    response::{error_page, redirect, render_page, render_template, safe_auth_continuation},
    security::{
        OAUTH_LINK_COOKIE, OAUTH_LINK_PATH, OAUTH_LINK_REQUESTER_COOKIE, OAUTH_SIGNUP_COOKIE,
        OAUTH_SIGNUP_PATH, PASSWORD_RESET_COOKIE, TWO_FACTOR_CHALLENGE_COOKIE, canonical_cookie,
        clear_scoped_cookie, cookie_value, csrf_cookie, lax_scoped_secret_cookie, new_csrf_token,
        request_has_same_origin, scoped_secret_cookie, valid_csrf_token, with_csrf_cookie,
        with_response_cookie,
    },
    state::AppState,
    templates::{
        AuthFormTemplate, AuthStatusTemplate, SetupTwoFactorTemplate, TwoFactorRecoveryTemplate,
    },
    view::{
        AuthFormSubmission, AuthFormView, AuthQuery, OAuthProviderLink, SetupTwoFactorView,
        TwoFactorRecoveryView,
    },
};

const SECRET_TTL_SECONDS: u32 = 10 * 60;
const LOGIN_ACTION: &str = "/login/_actions/sign-in";
/// What a person who signs in before verifying their email sees, with a
/// button that sends a new link, and what the button's answer says.
const CHECK_EMAIL: &str = "Check your email to verify your address.";
const VERIFICATION_SENT: &str = "Sent. Check your email; the link works for 24 hours.";
/// What a person whose account is waiting for access sees on sign-in, and
/// the title and text of the pages that end a sign-up waiting for access.
pub(crate) const ON_THE_LIST: &str = "You're on the list. We'll email you as soon as we open up more capacity — no need to sign up again.";
pub(crate) const ON_THE_LIST_TITLE: &str = "You're on the list";
pub(crate) const ON_THE_LIST_DETAIL: &str =
    "We'll email you as soon as we open up more capacity — no need to sign up again.";
const SIGNUP_ACTION: &str = "/signup/_actions/sign-up";
pub(crate) const SIGNUP_COMPLETE_ACTION: &str = "/signup/complete/_actions/complete";
const LINK_CONFIRM_ACTION: &str = "/login/link/_actions/confirm";
/// The emailed link confirmation is valid for thirty minutes; its cookie
/// lasts as long, so a page left open can still be confirmed.
const LINK_CONFIRM_TTL_SECONDS: u32 = 30 * 60;
/// Where the private-preview sign-in redirect returns a signed-out visitor:
/// the orchestration handoff (`AUTHORIZE_PATH`) with one sealed, URL-safe
/// base64 `challenge` (crates/codewire-orchestration/src/api/preview).
const PREVIEW_HANDOFF_CONTINUATION: &str = "/api/v1/preview-auth/authorize?challenge=";
const TURNSTILE_CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self' https://challenges.cloudflare.com; form-action 'self'; frame-ancestors 'none'; frame-src https://challenges.cloudflare.com; img-src 'self' data:; object-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'";

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
    reason: &'a str,
    #[serde(rename = "turnstile_token")]
    turnstile_token: &'a str,
}

#[derive(Serialize)]
struct OAuthSignupToken<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct OAuthSignupRequest<'a> {
    token: &'a str,
    invite_code: &'a str,
    reason: &'a str,
    #[serde(rename = "turnstile_token")]
    turnstile_token: &'a str,
}

/// The pending provider sign-up `/signup/complete` finishes.
#[derive(Deserialize)]
struct OAuthPendingSignup {
    provider: String,
    email: String,
}

impl fmt::Debug for OAuthPendingSignup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthPendingSignup")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct OAuthSignupResponse {
    #[serde(default, rename = "accessPending")]
    access_pending: bool,
    #[serde(default)]
    auth_request_id: String,
    #[serde(default)]
    return_to: String,
}

impl fmt::Debug for OAuthSignupResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthSignupResponse")
            .field("access_pending", &self.access_pending)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct EmailRequest<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct ResendVerificationRequest<'a> {
    token: &'a str,
}

#[derive(Deserialize)]
pub(super) struct ResendVerificationSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resend_token: String,
}

impl fmt::Debug for ResendVerificationSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResendVerificationSubmission")
            .finish_non_exhaustive()
    }
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

#[derive(Deserialize)]
struct SignInResponse {
    user: Option<AuthUserResponse>,
    #[serde(default, rename = "twoFactorRequired")]
    two_factor_required: bool,
    #[serde(default, rename = "twoFactorToken")]
    two_factor_token: String,
}

impl fmt::Debug for SignInResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignInResponse")
            .field("user", &self.user)
            .field("two_factor_required", &self.two_factor_required)
            .field(
                "two_factor_token",
                &(!self.two_factor_token.is_empty()).then_some("[REDACTED]"),
            )
            .finish()
    }
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
    #[serde(default, rename = "accessPending")]
    access_pending: bool,
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

#[derive(Deserialize)]
struct TwoFactorEnableResponse {
    #[serde(rename = "totpUri")]
    totp_uri: String,
    secret: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

impl fmt::Debug for TwoFactorEnableResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoFactorEnableResponse")
            .field("totp_uri", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("backup_code_count", &self.backup_codes.len())
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct EnabledResponse {
    #[allow(dead_code)]
    enabled: bool,
}

#[derive(Deserialize)]
struct SkipSetupResponse {
    #[allow(dead_code)]
    skipped: bool,
}

pub(super) async fn login(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Response {
    // A provider sign-in to an account still waiting for access is not an
    // error: it gets the same notice as a password sign-in.
    let (error, notice) = if query.oauth_error == "disabled" {
        ("", Some(ON_THE_LIST))
    } else {
        (
            oauth_error_message(&query.oauth_error).unwrap_or_default(),
            oauth_notice_message(&query.oauth_notice, &query.provider),
        )
    };
    let mut view = login_view(query, error.to_owned());
    view.notice = notice.unwrap_or_default();
    auth_entry_response(&state, StatusCode::OK, view).await
}

/// The message for a provider sign-in that needs the person's attention. It
/// names only a known provider; any other notice or provider shows nothing.
fn oauth_notice_message(code: &str, provider: &str) -> Option<&'static str> {
    match (code, provider) {
        ("link_sent", "github") => Some(
            "We emailed a link to your account's address. Open it to connect GitHub, then sign in with GitHub.",
        ),
        ("link_sent", "google") => Some(
            "We emailed a link to your account's address. Open it to connect Google, then sign in with Google.",
        ),
        _ => None,
    }
}

/// The message for each fixed code the IdP sends a failed provider sign-in
/// back with. Provider text is never shown; an unknown code gets the generic
/// message.
fn oauth_error_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "" => return None,
        "unavailable" => {
            "That sign-in option isn't available right now. Sign in with your email and password."
        }
        "cancelled" => "Sign-in was cancelled. Choose how you'd like to sign in.",
        "expired" => "That sign-in attempt expired or was started in another browser. Try again.",
        "unverified_email" => {
            "Your account with that provider has no verified email address. Verify it there, then try again."
        }
        "link_required" => {
            "An account with this email already exists. Sign in with your email and password, then link the provider from Settings."
        }
        "locked" => "Too many sign-in attempts. Wait a few minutes and try again.",
        "rate_limited" => {
            "Too many sign-in attempts from this network. Wait a few minutes and try again."
        }
        _ => {
            "Sign-in with that provider didn't finish. Try again, or sign in with your email and password."
        }
    })
}

/// A "Continue with …" link for each provider the IdP has configured,
/// carrying the page's return target. None when the IdP doesn't answer.
async fn provider_links(state: &AppState, view: &AuthFormView) -> Vec<OAuthProviderLink> {
    oauth_providers(state)
        .await
        .into_iter()
        .filter_map(|provider| {
            let (label, icon) = match provider {
                "github" => ("GitHub", "icon-github"),
                "google" => ("Google", "icon-google"),
                _ => return None,
            };
            Some(OAuthProviderLink {
                label,
                icon,
                href: auth_path_from_view(&format!("/api/auth/oauth/{provider}/start"), view),
            })
        })
        .collect()
}

/// The sign-in and sign-up pages, with the provider buttons.
async fn auth_entry_response(
    state: &AppState,
    status: StatusCode,
    mut view: AuthFormView,
) -> Response {
    view.oauth_providers = provider_links(state, &view).await;
    auth_form_response(state, status, view)
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
        return auth_entry_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            login_view(query, "Email and password are required.".to_owned()),
        )
        .await;
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
            return auth_entry_response(
                &state,
                StatusCode::BAD_GATEWAY,
                login_view(
                    query,
                    "The identity service is temporarily unavailable.".to_owned(),
                ),
            )
            .await;
        }
    };
    // The IdP answers 403 only after the password matched, for an account
    // that does not have access yet, so this reveals nothing to a stranger.
    // One that never verified its email is told to; only a verified one is
    // on the list.
    if identity.status == StatusCode::FORBIDDEN {
        let mut view = login_view(query, String::new());
        if identity.error_code == Some(IdentityErrorCode::EmailUnverified) {
            view.notice = CHECK_EMAIL;
            view.resend_token = identity.resend_token.unwrap_or_default();
        } else {
            view.notice = ON_THE_LIST;
        }
        return auth_entry_response(&state, identity.status, view).await;
    }
    if !identity.status.is_success() {
        return auth_entry_response(
            &state,
            identity.status,
            login_view(query, user_message(identity.status, "sign-in").to_owned()),
        )
        .await;
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
    auth_entry_response(&state, StatusCode::OK, signup_view(query, String::new())).await
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
    if !error.is_empty()
        || form.email.trim().is_empty()
        || form.name.trim().is_empty()
        || form.reason.trim().is_empty()
    {
        let error = if error.is_empty() {
            "Name, email, and what you want to build are required.".to_owned()
        } else {
            error
        };
        return auth_entry_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_view(query, error),
        )
        .await;
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
            reason: form.reason.trim(),
            turnstile_token: form.turnstile_response.trim(),
        },
    )
    .await
    {
        Ok(response) => response,
        Err(()) => {
            return auth_entry_response(
                &state,
                StatusCode::BAD_GATEWAY,
                signup_view(
                    query,
                    "The identity service is temporarily unavailable.".to_owned(),
                ),
            )
            .await;
        }
    };
    if !identity.status.is_success() {
        return auth_entry_response(
            &state,
            identity.status,
            signup_view(query, user_message(identity.status, "sign-up").to_owned()),
        )
        .await;
    }
    if identity
        .body
        .as_ref()
        .is_some_and(|body| body.access_pending)
    {
        return render_page(AuthStatusTemplate {
            title: "Verify your email",
            description: "We sent you a verification link. Once you verify your email, you're on the list, and we'll email you as soon as we open up more capacity.",
            primary_label: "Back to sign in",
            primary_url: "/login",
        });
    }
    let completion = completion_target(&form.auth_request_id, &form.return_to);
    forward_session_cookies(
        redirect(auth_url_for_target("/setup-2fa", &completion), &headers),
        &identity,
    )
}

/// `/signup/complete`: the last step of a provider sign-up for an email with
/// no Codewire account. It shows the provider and the email it verified and
/// asks what email sign-up asks besides the password: the access-request
/// reason, an optional invite code and Turnstile.
pub(super) async fn signup_complete(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = cookie_value(&headers, OAUTH_SIGNUP_COOKIE) else {
        return expired_oauth_signup(&state);
    };
    match pending_oauth_signup(&state, token).await {
        Ok(pending) => auth_form_response(
            &state,
            StatusCode::OK,
            signup_complete_view(&pending, String::new()),
        ),
        Err(unavailable) => unavailable.response(&state),
    }
}

pub(super) async fn signup_complete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let Some(token) = cookie_value(&headers, OAUTH_SIGNUP_COOKIE) else {
        return expired_oauth_signup(&state);
    };
    let pending = match pending_oauth_signup(&state, token).await {
        Ok(pending) => pending,
        Err(unavailable) => return unavailable.response(&state),
    };
    if form.reason.trim().is_empty() {
        return auth_form_response(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_complete_view(&pending, "Tell us what you want to build.".to_owned()),
        );
    }
    let identity = match post_json::<_, OAuthSignupResponse>(
        &state,
        "/api/auth/oauth/signup/complete",
        None,
        &OAuthSignupRequest {
            token,
            invite_code: form.invite_code.trim(),
            reason: form.reason.trim(),
            turnstile_token: form.turnstile_response.trim(),
        },
    )
    .await
    {
        Ok(identity) => identity,
        Err(()) => {
            return auth_form_response(
                &state,
                StatusCode::BAD_GATEWAY,
                signup_complete_view(
                    &pending,
                    "The identity service is temporarily unavailable.".to_owned(),
                ),
            );
        }
    };
    let clear = clear_scoped_cookie(&state.public_origin, OAUTH_SIGNUP_COOKIE, OAUTH_SIGNUP_PATH);
    match (identity.status, identity.body.as_ref()) {
        (status, Some(body)) if status.is_success() && body.access_pending => with_response_cookie(
            render_page(AuthStatusTemplate {
                title: ON_THE_LIST_TITLE,
                description: ON_THE_LIST_DETAIL,
                primary_label: "Back to Codewire",
                primary_url: "/",
            }),
            clear,
        ),
        (status, Some(body)) if status.is_success() => {
            let completion = completion_target(&body.auth_request_id, &body.return_to);
            let response = forward_session_cookies(
                redirect(auth_url_for_target("/setup-2fa", &completion), &headers),
                &identity,
            );
            with_response_cookie(response, clear)
        }
        (StatusCode::NOT_FOUND, _) => expired_oauth_signup(&state),
        (StatusCode::CONFLICT, _) => with_response_cookie(
            render_template(
                StatusCode::CONFLICT,
                AuthStatusTemplate {
                    title: "Account already exists",
                    description: "An account with this email already exists. Sign in with it, then link the provider from Settings.",
                    primary_label: "Sign in",
                    primary_url: "/login",
                },
            ),
            clear,
        ),
        (status, _) => auth_form_response(
            &state,
            if status.is_success() {
                StatusCode::BAD_GATEWAY
            } else {
                status
            },
            signup_complete_view(&pending, user_message(status, "oauth-sign-up").to_owned()),
        ),
    }
}

/// Read the pending sign-up the cookie names, or the page to show when it has
/// expired or the IdP can't be reached.
async fn pending_oauth_signup(
    state: &AppState,
    token: &str,
) -> Result<OAuthPendingSignup, PendingSignupUnavailable> {
    match post_json::<_, OAuthPendingSignup>(
        state,
        "/api/auth/oauth/signup/pending",
        None,
        &OAuthSignupToken { token },
    )
    .await
    {
        Ok(response) if response.status.is_success() => match response.body {
            Some(body) if provider_label(&body.provider).is_some() => Ok(body),
            _ => Err(PendingSignupUnavailable::Identity),
        },
        Ok(response) if response.status == StatusCode::NOT_FOUND => {
            Err(PendingSignupUnavailable::Expired)
        }
        _ => Err(PendingSignupUnavailable::Identity),
    }
}

/// Why `/signup/complete` cannot show a pending sign-up.
enum PendingSignupUnavailable {
    Expired,
    Identity,
}

impl PendingSignupUnavailable {
    fn response(self, state: &AppState) -> Response {
        match self {
            Self::Expired => expired_oauth_signup(state),
            Self::Identity => error_page(WebError::IdentityUnavailable),
        }
    }
}

fn provider_label(provider: &str) -> Option<&'static str> {
    match provider {
        "github" => Some("GitHub"),
        "google" => Some("Google"),
        _ => None,
    }
}

fn expired_oauth_signup(state: &AppState) -> Response {
    with_response_cookie(
        render_template(
            StatusCode::BAD_REQUEST,
            AuthStatusTemplate {
                title: "Sign-up expired",
                description: "This sign-up has expired or was already used. Start again to create your account.",
                primary_label: "Start again",
                primary_url: "/signup",
            },
        ),
        clear_scoped_cookie(&state.public_origin, OAUTH_SIGNUP_COOKIE, OAUTH_SIGNUP_PATH),
    )
}

fn signup_complete_view(pending: &OAuthPendingSignup, error: String) -> AuthFormView {
    let mut view = base_view(AuthQuery::default());
    view.title = "Finish creating your account";
    view.description = "Tell us what you want to build with Codewire.";
    view.action = SIGNUP_COMPLETE_ACTION;
    view.submit_label = "Request access";
    view.error = error;
    view.show_reason = true;
    view.show_invite_code = true;
    view.identity_provider = provider_label(&pending.provider).unwrap_or_default();
    view.identity_account = pending.email.clone();
    view.secondary_label = "Use a different account";
    view.secondary_url = "/signup".to_owned();
    // The IdP keeps the return target with the pending sign-up.
    view.return_to = String::new();
    view
}

pub(super) async fn forgot_password(State(state): State<AppState>) -> Response {
    auth_form_response(&state, StatusCode::OK, forgot_password_view(String::new()))
}

/// The "Resend verification email" button on the sign-in notice. It posts
/// the single-use token the IdP gave the sign-in, which proved the password,
/// so only the account holder can ask.
pub(super) async fn resend_verification_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ResendVerificationSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let status = match post_json::<_, SentResponse>(
        &state,
        "/api/auth/resend-verification",
        None,
        &ResendVerificationRequest {
            token: &form.resend_token,
        },
    )
    .await
    {
        Ok(response) => response.status,
        Err(()) => StatusCode::BAD_GATEWAY,
    };
    let mut view = login_view(AuthQuery::default(), String::new());
    match status {
        status if status.is_success() => view.notice = VERIFICATION_SENT,
        StatusCode::BAD_REQUEST => {
            view.error =
                "That request expired. Sign in again to resend the verification email.".to_owned();
        }
        _ => {
            view.error = "We couldn't send the email. Sign in again shortly to retry.".to_owned();
        }
    }
    auth_entry_response(&state, StatusCode::OK, view).await
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

#[derive(Deserialize)]
struct OAuthLinkResponse {
    provider: String,
    #[serde(default)]
    account: String,
}

#[derive(Serialize)]
struct OAuthLinkConfirmRequest<'a> {
    token: &'a str,
    requester: &'a str,
}

impl fmt::Debug for OAuthLinkResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthLinkResponse")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// `/login/link`: the page an emailed link confirmation opens. Opening it
/// changes nothing, so a mail scanner that fetches the link uses nothing up:
/// the token moves from the URL into a cookie scoped to this page (Lax,
/// because the link is opened from another site), and the page asks for a
/// CSRF-checked POST that connects the provider.
pub(super) async fn link_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    if !query.token.is_empty() {
        let Some(cookie) = lax_scoped_secret_cookie(
            &state.public_origin,
            OAUTH_LINK_COOKIE,
            &query.token,
            OAUTH_LINK_PATH,
            LINK_CONFIRM_TTL_SECONDS,
        ) else {
            return expired_link(&state);
        };
        return with_response_cookie(redirect(OAUTH_LINK_PATH.to_owned(), &headers), cookie);
    }
    let Some(token) = cookie_value(&headers, OAUTH_LINK_COOKIE) else {
        return expired_link(&state);
    };
    match post_json::<_, OAuthLinkResponse>(
        &state,
        "/api/auth/oauth/link/pending",
        None,
        &OAuthSignupToken { token },
    )
    .await
    {
        Ok(response) if response.status.is_success() => {
            match response
                .body
                .as_ref()
                .and_then(|body| link_confirm_view(&body.provider, &body.account))
            {
                Some(view) => auth_form_response(&state, StatusCode::OK, view),
                None => error_page(WebError::IdentityUnavailable),
            }
        }
        Ok(response) if response.status == StatusCode::NOT_FOUND => expired_link(&state),
        _ => error_page(WebError::IdentityUnavailable),
    }
}

pub(super) async fn link_confirm_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<crate::view::CsrfSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let Some(token) = cookie_value(&headers, OAUTH_LINK_COOKIE) else {
        return expired_link(&state);
    };
    // The browser that started the sign-in holds the requester secret under
    // this page's path; any other browser sends none and is refused.
    let requester = cookie_value(&headers, OAUTH_LINK_REQUESTER_COOKIE).unwrap_or_default();
    let result = post_json::<_, OAuthLinkResponse>(
        &state,
        "/api/auth/oauth/link/confirm",
        None,
        &OAuthLinkConfirmRequest { token, requester },
    )
    .await;
    let clear = clear_scoped_cookie(&state.public_origin, OAUTH_LINK_COOKIE, OAUTH_LINK_PATH);
    let clear_requester = clear_scoped_cookie(
        &state.public_origin,
        OAUTH_LINK_REQUESTER_COOKIE,
        OAUTH_LINK_PATH,
    );
    let page = match result {
        Ok(response) if response.status.is_success() => {
            let connected = response.body.as_ref().and_then(|body| match body.provider.as_str() {
                "github" => Some(AuthStatusTemplate {
                    title: "GitHub is connected",
                    description: "GitHub is connected to your Codewire account. Sign in with GitHub; your two-factor authentication still applies.",
                    primary_label: "Sign in",
                    primary_url: "/login",
                }),
                "google" => Some(AuthStatusTemplate {
                    title: "Google is connected",
                    description: "Google is connected to your Codewire account. Sign in with Google; your two-factor authentication still applies.",
                    primary_label: "Sign in",
                    primary_url: "/login",
                }),
                _ => None,
            });
            match connected {
                Some(page) => with_response_cookie(render_page(page), clear_requester),
                None => error_page(WebError::IdentityUnavailable),
            }
        }
        // Another browser: nothing changed and the link still works where
        // the sign-in started, so its cookie stays.
        Ok(response) if response.status == StatusCode::PRECONDITION_FAILED => {
            return wrong_browser(&state, token).await;
        }
        Ok(response) if response.status == StatusCode::NOT_FOUND => return expired_link(&state),
        Ok(response) if response.status == StatusCode::FORBIDDEN => render_template(
            StatusCode::FORBIDDEN,
            AuthStatusTemplate {
                title: "This account can't be connected",
                description: "The account can't be connected right now. Sign in with your email and password, or contact support.",
                primary_label: "Back to sign in",
                primary_url: "/login",
            },
        ),
        Ok(response) if response.status == StatusCode::CONFLICT => render_template(
            StatusCode::CONFLICT,
            AuthStatusTemplate {
                title: "Already connected elsewhere",
                description: "That provider account is connected to another Codewire account, so it wasn't connected to this one.",
                primary_label: "Back to sign in",
                primary_url: "/login",
            },
        ),
        _ => return error_page(WebError::IdentityUnavailable),
    };
    with_response_cookie(page, clear)
}

/// The page for a confirmation opened in a browser other than the one that
/// started the sign-in, naming the provider when the link is still live.
async fn wrong_browser(state: &AppState, token: &str) -> Response {
    let provider = post_json::<_, OAuthLinkResponse>(
        state,
        "/api/auth/oauth/link/pending",
        None,
        &OAuthSignupToken { token },
    )
    .await
    .ok()
    .and_then(|response| response.body)
    .map(|body| body.provider);
    render_template(
        StatusCode::FORBIDDEN,
        AuthStatusTemplate {
            title: "Open this link where you signed in",
            description: match provider.as_deref() {
                Some("github") => {
                    "Open this link in the browser where you started signing in with GitHub."
                }
                Some("google") => {
                    "Open this link in the browser where you started signing in with Google."
                }
                _ => "Open this link in the browser where you started signing in.",
            },
            primary_label: "Back to sign in",
            primary_url: "/login",
        },
    )
}

fn link_confirm_view(provider: &str, account: &str) -> Option<AuthFormView> {
    let (title, submit_label) = match provider {
        "github" => ("Connect GitHub to your Codewire account", "Connect GitHub"),
        "google" => ("Connect Google to your Codewire account", "Connect Google"),
        _ => return None,
    };
    let mut view = base_view(AuthQuery::default());
    view.title = title;
    view.description = "Only confirm if you just signed in with it yourself. It will then be able to sign in to your Codewire account; your two-factor authentication still applies.";
    view.action = LINK_CONFIRM_ACTION;
    view.submit_label = submit_label;
    view.secondary_label = "Not you? Back to sign in";
    view.secondary_url = "/login".to_owned();
    view.return_to = String::new();
    view.identity_provider = provider_label(provider)?;
    view.identity_account = account.to_owned();
    Some(view)
}

fn expired_link(state: &AppState) -> Response {
    with_response_cookie(
        render_template(
            StatusCode::BAD_REQUEST,
            AuthStatusTemplate {
                title: "Link expired",
                description: "This link has expired or was already used. Sign in with the provider again to get a new one.",
                primary_label: "Back to sign in",
                primary_url: "/login",
            },
        ),
        clear_scoped_cookie(&state.public_origin, OAUTH_LINK_COOKIE, OAUTH_LINK_PATH),
    )
}

pub(super) async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    if !query.token.is_empty() {
        // The reset link is opened from an email, a cross-site navigation, so
        // the cookie must be Lax to reach the GET this redirect leads to. The
        // reset POST stays guarded by the same-origin and CSRF checks.
        let Some(cookie) = lax_scoped_secret_cookie(
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

/// Skip two-factor setup for this browser session only. The IdP refuses an
/// account that already has a factor, and the next sign-in asks again.
pub(super) async fn skip_two_factor_setup_action(
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
    match post_json::<_, SkipSetupResponse>(
        &state,
        "/api/auth/two-factor/skip-setup",
        Some(cookie),
        &EmptyRequest {},
    )
    .await
    {
        Ok(response) if response.status.is_success() => {
            redirect(safe_target(&form.return_to), &headers)
        }
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            redirect(auth_url_for_target("/login", &form.return_to), &headers)
        }
        // An account that enabled a factor meanwhile continues normally.
        Ok(response) if response.status == StatusCode::BAD_REQUEST => {
            redirect(safe_target(&form.return_to), &headers)
        }
        _ => error_page(WebError::IdentityUnavailable),
    }
}

/// The authenticator setup QR code as inline SVG. Shared by first setup and
/// Account › Security replacement so both render the same one-time code.
pub(super) fn totp_qr_svg(totp_uri: &str) -> Option<String> {
    QrCode::new(totp_uri.as_bytes()).ok().map(|code| {
        code.render::<svg::Color>()
            .min_dimensions(256, 256)
            .dark_color(svg::Color("#08090a"))
            .light_color(svg::Color("#ffffff"))
            .build()
    })
}

fn setup_two_factor_response(
    state: &AppState,
    status: StatusCode,
    setup: &TwoFactorEnableResponse,
    return_to: String,
    error: String,
) -> Response {
    let Some(qr_svg) = totp_qr_svg(&setup.totp_uri) else {
        return error_page(WebError::IdentityUnavailable);
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
    if view.action == SIGNUP_ACTION || view.action == SIGNUP_COMPLETE_ACTION {
        view.turnstile_site_key = state.turnstile_site_key.clone();
    }
    let mut response = with_csrf_cookie(
        render_template(status, AuthFormTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    );
    if !view.turnstile_site_key.is_empty() {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(TURNSTILE_CSP),
        );
    }
    response
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
        notice: "",
        resend_token: String::new(),
        csrf_token: String::new(),
        auth_request_id: clean_auth_request_id(&query.auth_request_id),
        return_to: safe_target(&query.return_to),
        show_email: false,
        show_password: false,
        new_password: false,
        show_confirm_password: false,
        show_name: false,
        show_invite_code: false,
        show_reason: false,
        turnstile_site_key: String::new(),
        show_totp_code: false,
        forgot_password_link: false,
        preview_sign_in: false,
        secondary_label: "",
        secondary_url: String::new(),
        oauth_providers: Vec::new(),
        identity_provider: "",
        identity_account: String::new(),
    }
}

fn login_view(query: AuthQuery, error: String) -> AuthFormView {
    let mut view = base_view(query);
    view.title = "Sign in";
    view.description = "Welcome back to Codewire.";
    view.action = LOGIN_ACTION;
    view.submit_label = "Sign in";
    view.error = error;
    view.show_email = true;
    view.show_password = true;
    view.forgot_password_link = true;
    view.secondary_label = "Need an account? Create one";
    view.secondary_url = auth_path_from_view("/signup", &view);
    if continues_to_preview_handoff(&view) {
        view.title = "Sign in to view preview";
        view.preview_sign_in = true;
    }
    view
}

/// Whether a successful sign-in from this view finishes at the private-preview
/// handoff. Only the already-validated continuation decides, and it only picks
/// fixed copy: no part of it is shown. An OIDC request completes elsewhere.
fn continues_to_preview_handoff(view: &AuthFormView) -> bool {
    view.auth_request_id.is_empty()
        && view
            .return_to
            .strip_prefix(PREVIEW_HANDOFF_CONTINUATION)
            .is_some_and(|challenge| {
                !challenge.is_empty()
                    && challenge
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
}

fn signup_view(query: AuthQuery, error: String) -> AuthFormView {
    let mut view = base_view(query);
    view.title = "Request Codewire access";
    view.description = "Tell us what you want to build with Codewire.";
    view.action = SIGNUP_ACTION;
    view.submit_label = "Request access";
    view.error = error;
    view.show_email = true;
    view.show_password = true;
    view.new_password = true;
    view.show_confirm_password = true;
    view.show_name = true;
    view.show_reason = true;
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
        .unwrap_or("/dashboard/")
        .to_owned()
}

fn auth_url_for_target(path: &str, target: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "return_to",
            safe_auth_continuation(target).unwrap_or("/dashboard/"),
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
        reason: String::new(),
        turnstile_response: String::new(),
        code: String::new(),
        auth_request_id: view.auth_request_id.clone(),
        return_to: view.return_to.clone(),
    };
    auth_path(path, &form)
}

fn setup_continuation(query: &AuthQuery) -> &str {
    safe_auth_continuation(&query.return_to).unwrap_or("/dashboard/")
}

#[cfg(test)]
#[path = "oauth_sign_in_tests.rs"]
mod oauth_sign_in_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template as _;

    #[test]
    fn signup_form_carries_the_access_request_and_turnstile_contract() {
        let mut view = signup_view(AuthQuery::default(), String::new());
        view.turnstile_site_key = "site-key-marker".into();
        let body = AuthFormTemplate { view: &view }
            .render()
            .expect("render signup form");

        assert!(view.show_reason);
        assert!(body.contains("name=\"reason\""));
        assert!(body.contains("maxlength=\"2000\""));
        assert!(body.contains("cf-turnstile"));
        assert!(body.contains("data-sitekey=\"site-key-marker\""));
        assert!(body.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
    }

    #[test]
    fn only_the_signup_form_links_the_terms_and_privacy_policy() {
        let agreement = "By requesting access you agree to the <a href=\"/terms\">Terms</a> and the <a href=\"/privacy\">Privacy policy</a>.";
        let signup = signup_view(AuthQuery::default(), String::new());
        let body = AuthFormTemplate { view: &signup }
            .render()
            .expect("render signup form");
        assert_eq!(body.matches(agreement).count(), 1);

        let login = login_view(AuthQuery::default(), String::new());
        let body = AuthFormTemplate { view: &login }
            .render()
            .expect("render login form");
        assert!(!body.contains(agreement));
    }

    #[test]
    fn signup_request_uses_the_identity_turnstile_field_name() {
        let body = serde_json::to_value(SignUpRequest {
            email: "person@example.test",
            password: "CorrectHorse9#xy",
            name: "Person",
            invite_code: "",
            reason: "Build isolated coding environments",
            turnstile_token: "challenge-marker",
        })
        .expect("serialize signup request");

        assert_eq!(body["turnstile_token"], "challenge-marker");
        assert!(body.get("turnstileToken").is_none());
    }

    #[test]
    fn passwords_and_challenges_are_not_part_of_auth_urls() {
        let form = AuthFormSubmission {
            csrf: "csrf".into(),
            email: "person@example.test".into(),
            password: "VerySecretPassword9!".into(),
            confirm_password: "VerySecretPassword9!".into(),
            name: "Person".into(),
            invite_code: "invite-secret".into(),
            reason: "reason-secret".into(),
            turnstile_response: "turnstile-secret".into(),
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
    fn identity_response_debug_redacts_challenge_and_two_factor_setup_secrets() {
        let sign_in = SignInResponse {
            user: None,
            two_factor_required: true,
            two_factor_token: "challenge-token-marker".into(),
        };
        let sign_in_debug = format!("{sign_in:?}");
        assert!(!sign_in_debug.contains("challenge-token-marker"));
        assert!(sign_in_debug.contains("[REDACTED]"));

        let setup = TwoFactorEnableResponse {
            totp_uri: "otpauth://totp/example?secret=totp-uri-marker".into(),
            secret: "totp-secret-marker".into(),
            backup_codes: vec!["backup-code-marker".into()],
        };
        let setup_debug = format!("{setup:?}");
        assert!(!setup_debug.contains("totp-uri-marker"));
        assert!(!setup_debug.contains("totp-secret-marker"));
        assert!(!setup_debug.contains("backup-code-marker"));
        assert!(setup_debug.contains("backup_code_count: 1"));
    }

    const PREVIEW_CHALLENGE: &str = "c2VhbGVk-Y29udGludWF0aW9u_UHJldmlld01hcmtlcg";
    const PREVIEW_TITLE: &str = "<title>Sign in to view preview · Codewire</title>";
    const PREVIEW_HEADING: &str =
        "<h1 id=\"auth-title\" class=\"cw-page-title\">Sign in to view preview</h1>";
    const PREVIEW_CONTEXT: &str =
        "<p class=\"cw-auth-copy\">You'll return to the preview after signing in.</p>";
    const LOGIN_TITLE: &str = "<title>Sign in · Codewire</title>";
    const LOGIN_HEADING: &str =
        "<h1 id=\"auth-title\" class=\"cw-page-title\">Log in to Codewire</h1>";

    fn preview_continuation() -> String {
        format!("{PREVIEW_HANDOFF_CONTINUATION}{PREVIEW_CHALLENGE}")
    }

    fn between<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
        let (_, rest) = body.split_once(start).expect("start marker");
        rest.split_once(end).expect("end marker").0
    }

    async fn login_page(origin: &str, pairs: &[(&str, &str)]) -> String {
        // Encode exactly as the preview redirect does before following it.
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client")
            .get(format!("{origin}/login?{}", query.finish()))
            .send()
            .await
            .expect("login page");
        assert_eq!(response.status(), StatusCode::OK);
        response.text().await.expect("login body")
    }

    /// Serve the dashboard on a loopback port, as `https://app.example.test`
    /// with every backend unreachable.
    async fn serve_dashboard() -> (String, tokio::task::JoinHandle<()>) {
        let app = crate::app(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: "http://127.0.0.1:9".parse().unwrap(),
            credential_origin: "http://127.0.0.1:9".parse().unwrap(),
            identity_origin_string: "http://127.0.0.1:9".into(),
            browser_api_origin: "http://127.0.0.1:9".into(),
            billing_origin: "http://127.0.0.1:9".parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (origin, server)
    }

    #[tokio::test]
    async fn only_a_validated_preview_handoff_continuation_shows_preview_sign_in() {
        let (origin, server) = serve_dashboard().await;

        let continuation = preview_continuation();
        let body = login_page(&origin, &[("return_to", &continuation)]).await;
        for fragment in [PREVIEW_TITLE, PREVIEW_HEADING, PREVIEW_CONTEXT] {
            assert!(body.contains(fragment), "missing {fragment}");
        }
        assert!(!body.contains(LOGIN_HEADING));
        // The same sign-in form, still carrying the unchanged continuation.
        assert!(body.contains("action=\"/login/_actions/sign-in\""));
        assert!(body.contains("name=\"_csrf\""));
        assert!(body.contains("id=\"email\""));
        assert!(body.contains("id=\"password\""));
        // The continuation reaches only the places it already did: the hidden
        // return_to and the sign-up link. The context copy echoes none of it.
        assert_eq!(body.matches(PREVIEW_CHALLENGE).count(), 2);
        let header = between(&body, "<header class=\"cw-auth-header\">", "</header>");
        let copy: String = header
            .split("href=\"")
            .enumerate()
            .map(|(index, part)| match index {
                0 => part,
                _ => part.split_once('"').map_or("", |(_, rest)| rest),
            })
            .collect();
        let title = between(&body, "<title>", "</title>");
        for reflected in [PREVIEW_CHALLENGE, "preview-auth", "challenge", "authorize"] {
            assert!(
                !copy.contains(reflected),
                "context copy reflects {reflected}"
            );
            assert!(!title.contains(reflected), "title reflects {reflected}");
        }

        for return_to in [
            "/dashboard/",
            "",
            "https://evil.example/api/v1/preview-auth/authorize?challenge=abc",
            "//evil.example/api/v1/preview-auth/authorize?challenge=abc",
            "/\\evil.example/api/v1/preview-auth/authorize?challenge=abc",
            "/api/v1/preview-auth/authorize?challenge=",
            "/api/v1/preview-auth/authorize",
            "/api/v1/preview-auth/authorize?challenge=abc&next=/x",
            "/api/v1/preview-auth/authorize?challenge=abc#fragment",
            "/api/v1/preview-auth/authorize?challenge=%3Cscript%3E",
            "/api/v1/preview-auth/authorize?challenge=<script>",
            "/api/v1/preview-auth/authorize?challenge=abc\nLocation: https://evil.example",
            "/api/v1/preview-auth/authorizeX?challenge=abc",
            "/api/v1/preview-auth/../preview-auth/authorize?challenge=abc",
            "/dashboard/?next=/api/v1/preview-auth/authorize?challenge=abc",
        ] {
            let body = login_page(&origin, &[("return_to", return_to)]).await;
            assert!(body.contains(LOGIN_TITLE), "{return_to:?}");
            assert!(body.contains(LOGIN_HEADING), "{return_to:?}");
            assert!(!body.contains("Sign in to view preview"), "{return_to:?}");
            assert!(!body.contains(PREVIEW_CONTEXT), "{return_to:?}");
        }
        // An OIDC request completes at its callback, not the preview.
        let body = login_page(
            &origin,
            &[
                ("authRequestID", "request-id"),
                ("return_to", &continuation),
            ],
        )
        .await;
        assert!(body.contains(LOGIN_HEADING));
        assert!(!body.contains(PREVIEW_CONTEXT));
        server.abort();
    }

    /// Whether a browser sends a cookie on a top-level GET navigation whose
    /// redirect chain began on another site, such as a link opened from an
    /// email client. RFC 6265bis sends Lax (and unmarked, defaulting to Lax)
    /// and None cookies there, and withholds Strict ones.
    fn sent_on_cross_site_navigation(set_cookie: &str) -> bool {
        !set_cookie
            .split(';')
            .filter_map(|attribute| attribute.trim().strip_prefix("SameSite="))
            .any(|value| value.eq_ignore_ascii_case("Strict"))
    }

    #[tokio::test]
    async fn a_reset_link_opened_from_an_email_reaches_the_reset_form() {
        let (origin, server) = serve_dashboard().await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");

        // The link in the email: a cross-site, top-level navigation.
        let entry = client
            .get(format!("{origin}/reset-password?token=reset-token-marker"))
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "navigate")
            .send()
            .await
            .expect("reset link");
        assert_eq!(entry.status(), StatusCode::SEE_OTHER);
        assert_eq!(entry.headers()[header::LOCATION], "/reset-password");
        let cookies: Vec<_> = entry
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie").to_owned())
            .collect();
        assert_eq!(
            cookies,
            [
                "codewire_password_reset=reset-token-marker; Path=/reset-password; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
            ]
        );
        assert!(
            sent_on_cross_site_navigation(&cookies[0]),
            "the browser withholds the reset cookie from the redirected GET"
        );
        assert!(!sent_on_cross_site_navigation(
            "codewire_password_reset=x; Path=/reset-password; HttpOnly; SameSite=Strict"
        ));

        // The redirected GET, carrying what the browser sends with it.
        let pair = cookies[0].split(';').next().unwrap().to_owned();
        let form = client
            .get(format!("{origin}/reset-password"))
            .header(header::COOKIE, &pair)
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "navigate")
            .send()
            .await
            .expect("reset form");
        assert_eq!(form.status(), StatusCode::OK);
        let body = form.text().await.expect("form body");
        assert!(body.contains("action=\"/reset-password/_actions/reset\""));
        assert!(body.contains("name=\"_csrf\""));
        assert!(!body.contains("invalid or has expired"));

        // Without the cookie, the page reports the link as invalid: what a
        // Strict cookie produced.
        let missing = client
            .get(format!("{origin}/reset-password"))
            .send()
            .await
            .expect("bare reset page");
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert!(
            missing
                .text()
                .await
                .unwrap()
                .contains("invalid or has expired")
        );

        // The reset POST still needs the same origin and the Strict CSRF
        // cookie matching the form token; the reset cookie alone is refused.
        let csrf = new_csrf_token();
        let password = "password=CorrectHorse9%23xy&confirm_password=CorrectHorse9%23xy";
        for (origin_header, cookie) in [
            (
                "https://evil.example",
                format!("{pair}; codewire_ssr_csrf={csrf}"),
            ),
            ("https://app.example.test", pair.clone()),
        ] {
            let refused = client
                .post(format!("{origin}/reset-password/_actions/reset"))
                .header(header::ORIGIN, origin_header)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={csrf}&{password}"))
                .send()
                .await
                .expect("reset submission");
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{origin_header}");
        }
        server.abort();
    }

    #[test]
    fn a_rejected_preview_sign_in_keeps_its_context() {
        let form = AuthFormSubmission {
            csrf: String::new(),
            email: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            name: String::new(),
            invite_code: String::new(),
            reason: String::new(),
            turnstile_response: String::new(),
            code: String::new(),
            auth_request_id: String::new(),
            return_to: preview_continuation(),
        };
        let view = login_view(form_query(&form), "Email and password are required.".into());
        assert!(view.preview_sign_in);
        assert_eq!(view.return_to, preview_continuation());
        // Other auth forms keep their own copy for the same continuation.
        assert!(!signup_view(form_query(&form), String::new()).preview_sign_in);
        assert!(!two_factor_view(form_query(&form), String::new()).preview_sign_in);
    }

    #[test]
    fn preview_sign_in_template_and_fixture_share_the_copy_and_order() {
        let view = login_view(
            AuthQuery {
                return_to: preview_continuation(),
                ..Default::default()
            },
            String::new(),
        );
        let product = AuthFormTemplate { view: &view }
            .render()
            .expect("render preview sign-in");
        let fixture = include_str!(
            "../../../../packages/codewire-design/reference/fixtures/login-preview.html"
        );
        for html in [product.as_str(), fixture] {
            let mut from = 0;
            for fragment in [
                PREVIEW_TITLE,
                "<body class=\"cw-body cw-auth-body\" data-route=\"auth\">",
                "<main class=\"cw-auth-shell\">",
                "<section class=\"cw-auth-panel\" aria-labelledby=\"auth-title\">",
                "<header class=\"cw-auth-header\">",
                PREVIEW_HEADING,
                PREVIEW_CONTEXT,
                "<p class=\"cw-auth-switch\">Don't have an account? <a href=\"",
                "<form class=\"cw-form\" method=\"post\" action=\"/login/_actions/sign-in\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"",
                "<button class=\"cw-button cw-button--pill cw-button--large cw-auth-submit\" type=\"submit\">Sign in</button>",
            ] {
                let at = html[from..]
                    .find(fragment)
                    .unwrap_or_else(|| panic!("missing or out of order: {fragment}"));
                from += at + fragment.len();
            }
        }
    }

    #[test]
    fn preview_handoff_continuation_matches_the_preview_redirect() {
        let browser = include_str!("../../../codewire-orchestration/src/api/preview/browser.rs");
        let authorization =
            include_str!("../../../codewire-orchestration/src/api/preview/authorization.rs");
        assert!(browser.contains(
            "pub(super) const AUTHORIZE_PATH: &str = \"/api/v1/preview-auth/authorize\";"
        ));
        assert!(browser.contains("Ok(URL_SAFE_NO_PAD.encode(bytes))"));
        assert!(
            authorization.contains("let local = format!(\"{AUTHORIZE_PATH}?challenge={id}\");")
        );
        assert!(authorization.contains(".append_pair(\"return_to\", &local)"));
        assert!(authorization.contains("redirect(&format!(\"{frontend}/login?{query}\"))"));
        assert_eq!(
            PREVIEW_HANDOFF_CONTINUATION,
            "/api/v1/preview-auth/authorize?challenge="
        );
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
            reason: String::new(),
            turnstile_response: String::new(),
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
