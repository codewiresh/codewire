//! The invitation page (#3840). An invitation link is
//! `/accept-invite#t=<token>`: the token travels in the fragment, so no
//! request line, edge log, Cloudflare event or Referer holds it. The page's
//! script posts it once to `open`, which keeps it in a cookie scoped to
//! `/accept-invite`; the page then reads the invitation from that cookie. The
//! token never accepts or signs anyone in: accepting needs a signed-in account
//! whose verified address is the invited one.

use axum::{
    Form,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_server_core::org::masked_email;
use connectrpc::ErrorCode;

use crate::{
    account_sessions::mutation_origin_is_exact,
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    connect::{accept_invitation, invitation},
    error::WebError,
    response::{error_page, redirect, render_template, two_factor_redirect},
    security::{
        canonical_cookie, clear_scoped_cookie, cookie_value, csrf_cookie, page_csrf_token,
        request_has_same_origin, scoped_secret_cookie, valid_csrf_token, with_csrf_cookie,
        with_response_cookie,
    },
    state::AppState,
    templates::{AuthStatusTemplate, InvitationOpeningTemplate, InvitationTemplate},
    view::{
        CsrfSubmission, InvitationOpenSubmission, InvitationPageView, InvitationState,
        InvitationView,
    },
};

pub(super) const INVITATION_PATH: &str = "/accept-invite";
const OUT_OF_DATE_PATH: &str = "/accept-invite/out-of-date";
const INVITATION_COOKIE: &str = "codewire.invitation";
/// The longest an invitation lives; the cookie never outlasts its invitation.
const MAX_INVITATION_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(super) const MAX_TOKEN_BYTES: usize = 512;

/// The link to an invitation, in its one form (#3840): the token in the
/// fragment, form-encoded as the page's script reads it.
pub(crate) fn invitation_link(public_origin: &str, token: &str) -> String {
    format!(
        "{}{INVITATION_PATH}#{}",
        public_origin.trim_end_matches('/'),
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("t", token)
            .finish()
    )
}

pub(super) async fn invitation_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    // A link from before the fragment put the token in the query, where the
    // edge sees it. It is never resolved; the visitor asks for a new one.
    if query.as_deref().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "token")
    }) {
        return invitation_response(redirect(OUT_OF_DATE_PATH.to_owned(), &headers));
    }
    let csrf = page_csrf_token(&headers);
    let Some(token) = invitation_token(&headers) else {
        return invitation_response(with_csrf_cookie(
            render_template(
                StatusCode::OK,
                InvitationOpeningTemplate { csrf_token: &csrf },
            ),
            csrf_cookie(&state.public_origin, &csrf),
        ));
    };
    let invitation = match invitation(&state, token.to_owned(), forwarded_for(&headers)).await {
        Ok(invitation) => invitation,
        Err(error) => return lookup_failure(&state, error),
    };
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => Some(identity),
        Err(WebError::Unauthorized) => None,
        Err(error) => return invitation_response(error_page(error)),
    };
    let page_state = page_state(identity.as_ref(), &invitation.email);
    render_invitation(
        &state,
        &headers,
        invitation,
        page_state,
        identity.as_ref(),
        token,
        String::new(),
    )
}

/// Takes the token the page's script read from the link's fragment, checks
/// it names a live invitation, and keeps it in the invitation cookie.
pub(super) async fn open(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<InvitationOpenSubmission>,
) -> Response {
    if !mutation_origin_is_exact(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &form.csrf)
    {
        return invitation_response(error_page(WebError::CsrfRejected));
    }
    if form.t.is_empty() || form.t.len() > MAX_TOKEN_BYTES {
        return invalid_invitation(&state);
    }
    let invitation = match invitation(&state, form.t.clone(), forwarded_for(&headers)).await {
        Ok(invitation) => invitation,
        Err(error) => return lookup_failure(&state, error),
    };
    let lifetime = invitation
        .expires_at
        .saturating_sub(chrono::Utc::now().timestamp())
        .clamp(0, MAX_INVITATION_SECONDS);
    let Some(cookie) = scoped_secret_cookie(
        &state.public_origin,
        INVITATION_COOKIE,
        &form.t,
        INVITATION_PATH,
        u32::try_from(lifetime).unwrap_or(0),
    ) else {
        return invalid_invitation(&state);
    };
    invitation_response(with_response_cookie(
        redirect(INVITATION_PATH.to_owned(), &headers),
        cookie,
    ))
}

pub(super) async fn accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfSubmission>,
) -> Response {
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => {
            return invitation_response(redirect(login_url(), &headers));
        }
        Err(error) => return invitation_response(error_page(error)),
    };
    if enforce_two_factor(&identity).is_err() {
        return invitation_response(two_factor_redirect(INVITATION_PATH, &headers));
    }
    if !request_has_same_origin(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &form.csrf)
    {
        return invitation_response(error_page(WebError::CsrfRejected));
    }
    let Some(token) = invitation_token(&headers) else {
        return invitation_response(redirect(INVITATION_PATH.to_owned(), &headers));
    };
    let Ok(session) = canonical_cookie(&headers) else {
        return invitation_response(redirect(login_url(), &headers));
    };
    let accepted = accept_invitation(&state, session, token.to_owned()).await;
    let refusal = match accepted {
        Ok(()) => {
            return invitation_response(with_response_cookie(
                render_template(
                    StatusCode::OK,
                    AuthStatusTemplate {
                        title: "Welcome to the team",
                        description: "The invitation has been accepted and the organization is now available.",
                        primary_label: "Go to dashboard",
                        primary_url: "/dashboard/",
                    },
                ),
                clear_invitation_cookie(&state),
            ));
        }
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return invitation_response(redirect(login_url(), &headers));
        }
        // The platform accepts only for a verified address (#3840).
        Err(error) if error.code == ErrorCode::FailedPrecondition => {
            Some(InvitationState::Unverified)
        }
        // To another account the invitation does not exist.
        Err(error) if error.code == ErrorCode::NotFound => Some(InvitationState::OtherAccount),
        Err(_) => None,
    };
    let invitation = match invitation(&state, token.to_owned(), forwarded_for(&headers)).await {
        Ok(invitation) => invitation,
        Err(error) => return lookup_failure(&state, error),
    };
    let (page_state, error) = match refusal {
        Some(page_state) => (page_state, String::new()),
        None => (
            InvitationState::Ready,
            "The invitation could not be accepted. Try again.".to_owned(),
        ),
    };
    render_invitation(
        &state,
        &headers,
        invitation,
        page_state,
        Some(&identity),
        token,
        error,
    )
}

/// Signs out, then signs in again with the invited address and comes back.
pub(super) async fn switch_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfSubmission>,
) -> Response {
    invitation_response(
        super::authentication::sign_out_then(&state, &headers, &form.csrf, login_url()).await,
    )
}

pub(super) async fn out_of_date() -> Response {
    invitation_response(render_template(
        StatusCode::GONE,
        AuthStatusTemplate {
            title: "This link is out of date",
            description: "Ask for a new invitation.",
            primary_label: "Go to homepage",
            primary_url: "/",
        },
    ))
}

fn page_state(identity: Option<&IdentityUser>, invited: &str) -> InvitationState {
    match identity {
        None => InvitationState::SignedOut,
        // Masks only tell addresses apart; the platform decides a match.
        Some(identity) if masked_email(identity.email()) != invited => {
            InvitationState::OtherAccount
        }
        Some(identity) if !identity.email_verified() => InvitationState::Unverified,
        Some(_) => InvitationState::Ready,
    }
}

fn render_invitation(
    state: &AppState,
    headers: &HeaderMap,
    invitation: InvitationView,
    page_state: InvitationState,
    identity: Option<&IdentityUser>,
    token: &str,
    error: String,
) -> Response {
    let csrf = page_csrf_token(headers);
    let view = InvitationPageView {
        invitation,
        state: page_state,
        signed_in_as: identity
            .map(|identity| identity.email().to_owned())
            .unwrap_or_default(),
        csrf_token: csrf.clone(),
        // Only the signed-out page hands the token on, to sign-up's form body.
        signup_token: if page_state == InvitationState::SignedOut {
            token.to_owned()
        } else {
            String::new()
        },
        login_url: login_url(),
        error,
    };
    invitation_response(with_csrf_cookie(
        render_template(StatusCode::OK, InvitationTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    ))
}

/// A token that names no live invitation, of either kind, gets this one
/// answer, and the cookie is dropped.
fn invalid_invitation(state: &AppState) -> Response {
    invitation_response(with_response_cookie(
        render_template(
            StatusCode::NOT_FOUND,
            AuthStatusTemplate {
                title: "This invitation is no longer valid",
                description: "Ask for a new one.",
                primary_label: "Go to homepage",
                primary_url: "/",
            },
        ),
        clear_invitation_cookie(state),
    ))
}

fn lookup_failure(state: &AppState, error: WebError) -> Response {
    match error {
        WebError::Connect(error) if error.code == ErrorCode::NotFound => invalid_invitation(state),
        WebError::Connect(error) if error.code == ErrorCode::ResourceExhausted => {
            invitation_response(render_template(
                StatusCode::TOO_MANY_REQUESTS,
                AuthStatusTemplate {
                    title: "Too many tries",
                    description: "Wait a minute, then open the invitation again.",
                    primary_label: "Go to homepage",
                    primary_url: "/",
                },
            ))
        }
        error => invitation_response(error_page(error)),
    }
}

fn invitation_token(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, INVITATION_COOKIE)
        .filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN_BYTES)
}

fn clear_invitation_cookie(state: &AppState) -> String {
    clear_scoped_cookie(&state.public_origin, INVITATION_COOKIE, INVITATION_PATH)
}

fn forwarded_for(headers: &HeaderMap) -> Option<HeaderValue> {
    headers
        .get(header::HeaderName::from_static("x-forwarded-for"))
        .cloned()
}

fn login_url() -> String {
    format!(
        "/login?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", INVITATION_PATH)
            .finish()
    )
}

/// Every invitation response: nobody caches it, and no link on it sends a
/// Referer to another site. Not no-referrer: under it a browser sends
/// `Origin: null` on the page's own form posts, which the exact-origin checks
/// refuse, as `personal_secrets.rs` found. The token is in the URL fragment,
/// which no Referer carries.
fn invitation_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}
