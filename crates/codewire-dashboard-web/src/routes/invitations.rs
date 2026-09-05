use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use connectrpc::ErrorCode;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    connect::{accept_invitation, invitation},
    error::WebError,
    response::{error_page, redirect, render_page, render_template, two_factor_redirect},
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{AuthStatusTemplate, InvitationTemplate},
    view::{AuthQuery, InvitationPageView, InvitationSubmission},
};

pub(super) async fn invitation_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    if query.token.is_empty() || query.token.len() > 512 {
        return invalid_invitation();
    }
    let invitation = match invitation(&state, query.token.clone()).await {
        Ok(invitation) => invitation,
        Err(WebError::Connect(error)) if error.code == ErrorCode::NotFound => {
            return invalid_invitation();
        }
        Err(error) => return error_page(error),
    };
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => Some(identity),
        Err(WebError::Unauthorized) => None,
        Err(error) => return error_page(error),
    };
    let continuation = invite_continuation(&query.token);
    let csrf = new_csrf_token();
    let view = InvitationPageView {
        email_matches: identity
            .as_ref()
            .is_some_and(|identity| identity.email().eq_ignore_ascii_case(&invitation.email)),
        authenticated: identity.is_some(),
        invitation,
        token: query.token,
        csrf_token: csrf.clone(),
        login_url: auth_continuation("/login", &continuation),
        signup_url: auth_continuation("/signup", &continuation),
        error: String::new(),
    };
    with_csrf_cookie(
        render_page(InvitationTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

pub(super) async fn accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<InvitationSubmission>,
) -> Response {
    let continuation = invite_continuation(&form.token);
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => {
            return redirect(auth_continuation("/login", &continuation), &headers);
        }
        Err(error) => return error_page(error),
    };
    if enforce_two_factor(&identity).is_err() {
        return two_factor_redirect(&continuation, &headers);
    }
    if !request_has_same_origin(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &form.csrf)
    {
        return error_page(WebError::CsrfRejected);
    }
    let invitation_view = match invitation(&state, form.token.clone()).await {
        Ok(invitation) => invitation,
        Err(WebError::Connect(error)) if error.code == ErrorCode::NotFound => {
            return invalid_invitation();
        }
        Err(error) => return error_page(error),
    };
    if !identity
        .email()
        .eq_ignore_ascii_case(&invitation_view.email)
    {
        return render_invitation_error(
            &state,
            invitation_view,
            form.token,
            "Sign in with the email address that received this invitation.",
        );
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return redirect(auth_continuation("/login", &continuation), &headers),
    };
    let token = form.token;
    match accept_invitation(&state, cookie, token.clone()).await {
        Ok(()) => render_page(AuthStatusTemplate {
            title: "Welcome to the team",
            description: "The invitation has been accepted and the organization is now available.",
            primary_label: "Go to dashboard",
            primary_url: "/dashboard/",
        }),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            redirect(auth_continuation("/login", &continuation), &headers)
        }
        Err(error) if error.code == ErrorCode::NotFound => invalid_invitation(),
        Err(_) => render_invitation_error(
            &state,
            invitation_view,
            token,
            "The invitation could not be accepted. Try again.",
        ),
    }
}

fn render_invitation_error(
    state: &AppState,
    invitation: crate::view::InvitationView,
    token: String,
    error: &'static str,
) -> Response {
    let csrf = new_csrf_token();
    let continuation = invite_continuation(&token);
    let view = InvitationPageView {
        invitation,
        token,
        csrf_token: csrf.clone(),
        authenticated: true,
        email_matches: true,
        login_url: auth_continuation("/login", &continuation),
        signup_url: auth_continuation("/signup", &continuation),
        error: error.to_owned(),
    };
    with_csrf_cookie(
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            InvitationTemplate { view: &view },
        ),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

fn invalid_invitation() -> Response {
    render_template(
        StatusCode::NOT_FOUND,
        AuthStatusTemplate {
            title: "Invalid invitation",
            description: "This invitation is invalid, expired, or has already been used.",
            primary_label: "Go to homepage",
            primary_url: "/",
        },
    )
}

pub(super) fn invite_continuation(token: &str) -> String {
    format!(
        "/accept-invite?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .finish()
    )
}

fn auth_continuation(path: &str, continuation: &str) -> String {
    format!(
        "{path}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", continuation)
            .finish()
    )
}
