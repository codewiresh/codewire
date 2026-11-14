//! The sign-up pages and their actions: `/signup` and, for a provider
//! sign-up, `/signup/complete`. Moved out of `authentication.rs` unchanged.

use codewire_server_core::client_address::forwarded_client_hop;

use super::*;
use crate::raw_auth::post_json_for_client;

pub(in crate::routes) async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    auth_entry_response(
        &state,
        &headers,
        StatusCode::OK,
        signup_view(query, String::new()),
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
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_view(query, error),
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
            &headers,
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
    match pending_oauth_signup(&state, token).await {
        Ok(pending) => auth_form_response(
            &state,
            &headers,
            StatusCode::OK,
            signup_complete_view(&pending, String::new()),
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
    if form.reason.trim().is_empty() {
        return auth_form_response(
            &state,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            signup_complete_view(&pending, "Tell us what you want to build.".to_owned()),
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

#[cfg(test)]
mod tests;
