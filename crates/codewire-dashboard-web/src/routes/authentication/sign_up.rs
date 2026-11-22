//! The sign-up pages and their actions: `/signup`, `/signup/invited` for an
//! invitation's visitor, and, for a provider sign-up, `/signup/complete`.

use codewire_server_core::client_address::forwarded_client_hop;

use super::*;
use crate::raw_auth::{
    IdentityErrorCode, IdentityResponse, SignupMode, post_json_for_client, signup_mode,
};
use crate::routes::invitations::{INVITATION_PATH, MAX_TOKEN_BYTES};

pub(in crate::routes) async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    let mode = signup_mode(&state).await;
    auth_entry_response(
        &state,
        &headers,
        StatusCode::OK,
        signup_view(query, String::new(), mode),
    )
    .await
}

/// `POST /signup/invited`: the invitation page's Create account (#3840). The
/// page posts the invitation's hand-off token and the invited address,
/// masked, so the token stays out of every URL.
pub(in crate::routes) async fn signup_invited(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let mode = signup_mode(&state).await;
    auth_entry_response(
        &state,
        &headers,
        StatusCode::OK,
        signup_form_view(&form, String::new(), mode),
    )
    .await
}

pub(in crate::routes) async fn signup_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthFormSubmission>,
) -> Response {
    if !valid_form_request(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let mode = signup_mode(&state).await;
    let reason_required = mode.reason && !invited(&form);
    let error = validate_new_password(&form);
    if !error.is_empty()
        || form.email.trim().is_empty()
        || form.name.trim().is_empty()
        || (reason_required && form.reason.trim().is_empty())
    {
        let error = match (error.is_empty(), reason_required) {
            (true, true) => "Name, email, and what you want to build are required.".to_owned(),
            (true, false) => "Name and email are required.".to_owned(),
            (false, _) => error,
        };
        return auth_entry_response(
            &state,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_form_view(&form, error, mode),
        )
        .await;
    }
    let identity = match post_json_for_client::<_, AuthResponse>(
        &state,
        "/api/auth/sign-up",
        None,
        forwarded_client_hop(&headers),
        &SignUpRequest {
            email: form.email.trim(),
            password: &form.password,
            name: form.name.trim(),
            invite_code: form.invite_code.trim(),
            reason: form.reason.trim(),
            turnstile_token: form.turnstile_response.trim(),
            invitation_token: invitation_token(&form.invitation_token),
        },
    )
    .await
    {
        Ok(response) => response,
        Err(()) => {
            return auth_entry_response(
                &state,
                &headers,
                StatusCode::BAD_GATEWAY,
                signup_form_view(
                    &form,
                    "The identity service is temporarily unavailable.".to_owned(),
                    mode,
                ),
            )
            .await;
        }
    };
    if !identity.status.is_success() {
        return auth_entry_response(
            &state,
            &headers,
            identity.status,
            signup_form_view(&form, sign_up_refusal(&form, &identity), mode),
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
    if identity
        .body
        .as_ref()
        .is_some_and(|body| body.verification_pending)
    {
        return render_page(AuthStatusTemplate {
            title: "Check your email",
            description: "We sent a verification link to your email address. Open it, then sign in with the password you chose.",
            primary_label: "Back to sign in",
            primary_url: "/login",
        });
    }
    let completion = completion_target(&form.auth_request_id, &form.return_to);
    forward_session_cookies(
        redirect(auth_url_for_target("/setup-2fa", &completion), &headers),
        &identity,
        &state.public_origin,
    )
}

/// `/signup/complete`: the last step of a provider sign-up for an email with
/// no Codewire account. It shows the provider and the email it verified and
/// asks what email sign-up asks besides the password: the access-request
/// reason, an optional invite code and Turnstile.
pub(in crate::routes) async fn signup_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = cookie_value(&headers, OAUTH_SIGNUP_COOKIE) else {
        return expired_oauth_signup(&state);
    };
    let mode = signup_mode(&state).await;
    match pending_oauth_signup(&state, token).await {
        Ok(pending) => auth_form_response(
            &state,
            &headers,
            StatusCode::OK,
            signup_complete_view(&pending, String::new(), mode),
        ),
        Err(unavailable) => unavailable.response(&state),
    }
}

pub(in crate::routes) async fn signup_complete_action(
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
    let mode = signup_mode(&state).await;
    if mode.reason && form.reason.trim().is_empty() {
        return auth_form_response(
            &state,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_complete_view(&pending, "Tell us what you want to build.".to_owned(), mode),
        );
    }
    let identity = match post_json_for_client::<_, OAuthSignupResponse>(
        &state,
        "/api/auth/oauth/signup/complete",
        None,
        forwarded_client_hop(&headers),
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
                &headers,
                StatusCode::BAD_GATEWAY,
                signup_complete_view(
                    &pending,
                    "The identity service is temporarily unavailable.".to_owned(),
                    mode,
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
                &state.public_origin,
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
            &headers,
            if status.is_success() {
                StatusCode::BAD_GATEWAY
            } else {
                status
            },
            signup_complete_view(&pending, refusal_message(&identity, "oauth-sign-up"), mode),
        ),
    }
}

/// What a refused email sign-up says. An invited one whose invitation isn't
/// live says so (#5908): the IdP refuses it `invitation_invalid`, or, on a
/// server with Turnstile's keys, fails its challenge first, since only a live
/// invitation skips it and the invited page shows none. Without a token a
/// failed challenge is just that, and every other refusal keeps its words.
fn sign_up_refusal(form: &AuthFormSubmission, identity: &IdentityResponse<AuthResponse>) -> String {
    match identity.error_code {
        Some(IdentityErrorCode::InvitationInvalid | IdentityErrorCode::HumanVerificationFailed)
            if invited(form) =>
        {
            INVITATION_NO_LONGER_VALID.to_owned()
        }
        _ => refusal_message(identity, "sign-up"),
    }
}

/// The `invite-signup` journey's words for an invitation that isn't live.
const INVITATION_NO_LONGER_VALID: &str = "This invitation is no longer valid. Ask for a new one.";

/// What a refused sign-up says. One the sign-up limits refused names what was
/// limited and when to try again (#4695). Only the code for an unsent
/// verification email says anything was saved (#4723). The IdP's own detail
/// never reaches the page.
fn refusal_message<T>(identity: &IdentityResponse<T>, operation: &'static str) -> String {
    match identity.error_code {
        Some(IdentityErrorCode::RateLimited) => limited_message(identity.retry_after),
        Some(IdentityErrorCode::RateLimitUnavailable) => {
            "Sign-up is temporarily unavailable. Try again in a few minutes.".to_owned()
        }
        Some(IdentityErrorCode::VerificationEmailUnsent) => {
            "Your request was saved, but verification email delivery is temporarily unavailable. Complete the challenge and submit again shortly.".to_owned()
        }
        _ => user_message(identity.status, operation).to_owned(),
    }
}

/// "Too many sign-ups right now. Try again in 12 minutes.", from the
/// refusal's `Retry-After` seconds, rounded up to whole minutes.
fn limited_message(retry_after: Option<u64>) -> String {
    match retry_after.map(|seconds| seconds.div_ceil(60).max(1)) {
        Some(1) => "Too many sign-ups right now. Try again in a minute.".to_owned(),
        Some(minutes) => {
            format!("Too many sign-ups right now. Try again in {minutes} minutes.")
        }
        None => "Too many sign-ups right now. Try again later.".to_owned(),
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

fn signup_complete_view(
    pending: &OAuthPendingSignup,
    error: String,
    mode: SignupMode,
) -> AuthFormView {
    let mut view = base_view(AuthQuery::default());
    view.title = "Finish creating your account";
    view.description = "Tell us what you want to build with Codewire.";
    view.action = SIGNUP_COMPLETE_ACTION;
    view.submit_label = "Request access";
    view.error = error;
    view.show_reason = mode.reason;
    view.show_invite_code = true;
    // Open sign-up admits everyone (#4121): no access request, no invite code.
    if mode.open {
        view.description = "Check the account below, then create it.";
        view.submit_label = "Create account";
        view.show_invite_code = false;
        view.open_signup = true;
    }
    view.identity_provider = provider_label(&pending.provider).unwrap_or_default();
    view.identity_account = pending.email.clone();
    view.secondary_label = "Use a different account";
    view.secondary_url = "/signup".to_owned();
    // The IdP keeps the return target with the pending sign-up.
    view.return_to = String::new();
    view
}

#[derive(Serialize)]
pub(super) struct SignUpRequest<'a> {
    pub(super) email: &'a str,
    pub(super) password: &'a str,
    pub(super) name: &'a str,
    pub(super) invite_code: &'a str,
    pub(super) reason: &'a str,
    #[serde(rename = "turnstile_token")]
    pub(super) turnstile_token: &'a str,
    pub(super) invitation_token: &'a str,
}

pub(super) fn signup_view(query: AuthQuery, error: String, mode: SignupMode) -> AuthFormView {
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
    view.show_reason = mode.reason;
    // Preserve the current UI input and raw IdP field without inventing or
    // enforcing invite policy in this presentation adapter (#1352).
    view.show_invite_code = true;
    // Open sign-up admits everyone (#4121): no access request, no invite code.
    if mode.open {
        view.title = "Create your Codewire account";
        view.description = "Sign up with your email address to start using Codewire.";
        view.submit_label = "Create account";
        view.show_invite_code = false;
        view.open_signup = true;
    }
    view.secondary_label = "Already have an account? Sign in";
    view.secondary_url = auth_path_from_view("/login", &view);
    view
}

/// The sign-up page again for a submitted form, keeping its invitation.
fn signup_form_view(form: &AuthFormSubmission, error: String, mode: SignupMode) -> AuthFormView {
    let mut view = signup_view(form_query(form), error, mode);
    if !invited(form) {
        return view;
    }
    view.invitation_token = invitation_token(&form.invitation_token).to_owned();
    view.invitation_email = email_hint(&form.email_hint);
    // Signing in from this page returns to the invitation.
    view.return_to = INVITATION_PATH.to_owned();
    view.secondary_url = auth_path_from_view("/login", &view);
    view.invited = true;
    view.title = "Create your Codewire account";
    view.submit_label = "Create account";
    view.show_reason = false;
    view.show_invite_code = false;
    view.open_signup = true;
    view
}

/// An invitation's sign-up, in every sign-up mode. The IdP admits a sign-up
/// whose token names a live invitation for the address typed at once, with
/// no invite code, review, reason or Turnstile, on every server (#4121,
/// `auth_session/email_sign_up.rs`), and refuses one whose token names none
/// rather than reviewing it. So the page asks for none of them; the IdP
/// decides whether the invitation is live.
fn invited(form: &AuthFormSubmission) -> bool {
    !invitation_token(&form.invitation_token).is_empty()
}

/// The posted invitation token, or empty when it can't be one.
fn invitation_token(token: &str) -> &str {
    let token = token.trim();
    if token.len() <= MAX_TOKEN_BYTES && token.bytes().all(|byte| byte.is_ascii_graphic()) {
        token
    } else {
        ""
    }
}

/// The invited address as the platform masked it, or empty when what was
/// posted isn't an address: the page only ever shows it as a hint.
fn email_hint(hint: &str) -> String {
    let hint = hint.trim();
    if hint.len() <= 254 && hint.contains('@') && !hint.chars().any(char::is_control) {
        hint.to_owned()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests;
