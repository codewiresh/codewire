//! Settings › Invitations (#3840): the signed-in account's pending
//! invitations, each accepted by its id with no link or token.
//!
//! The platform lists an invitation only to the account whose verified email
//! address it was sent to, and accepts it by id only for that address
//! (ListMyInvitations, AcceptInvitation with `invitation_id`). The page never
//! sees an invitation token. While the account's address is unverified the
//! list is empty, so the page says to verify it and offers a new link.

use askama::Template;
use axum::{
    Form,
    extract::{Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_proto::codewire::v1::{InvitationStatus, OrgInvitation};
use connectrpc::ErrorCode;
use serde::Deserialize;

use crate::{
    account_sessions,
    auth::{authenticated_identity, enforce_two_factor},
    connect,
    error::WebError,
    organization_connect::future_time,
    response::{error_page, login_redirect, redirect, render_template, two_factor_redirect},
    security::{canonical_cookie, csrf_cookie, new_csrf_token, page_csrf_token, with_csrf_cookie},
    state::AppState,
    view::{ASSIGNMENTS, AssignmentView, DashboardView},
};

pub(super) const PATH: &str = "/settings/invitations/";
pub(super) const ACCEPT_PATH: &str = "/settings/invitations/_actions/accept";

#[derive(Debug, Default, Deserialize)]
pub(super) struct PageQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    error: String,
}

// No Debug: the CSRF field is request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcceptForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    invitation_id: String,
}

/// Why accepting from this page did not happen, carried back to the page in
/// its `error` query parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptError {
    /// Unknown, expired, revoked, already accepted, or sent to another address.
    NotFound,
    /// The account's email address is not verified.
    EmailUnverified,
    Unavailable,
}

impl AcceptError {
    fn from_code(code: ErrorCode) -> Self {
        match code {
            ErrorCode::NotFound | ErrorCode::InvalidArgument => Self::NotFound,
            ErrorCode::FailedPrecondition => Self::EmailUnverified,
            _ => Self::Unavailable,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "not-found" => Some(Self::NotFound),
            "email-unverified" => Some(Self::EmailUnverified),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::EmailUnverified => "email-unverified",
            Self::Unavailable => "unavailable",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::NotFound => {
                "That invitation is no longer pending. It may have expired, been revoked or been accepted."
            }
            Self::EmailUnverified => "Verify your email address, then accept the invitation again.",
            Self::Unavailable => "The invitation could not be accepted. Try again.",
        }
    }
}

/// One pending invitation as the page shows it. It carries no token.
#[derive(Debug)]
pub(super) struct MyInvitationRow {
    id: String,
    organization_name: String,
    role: &'static str,
    inviter_name: String,
    expires: String,
    assignments: Vec<AssignmentView>,
}

#[derive(Debug)]
pub(super) struct InvitationsPage {
    csrf_token: String,
    email: String,
    email_verified: bool,
    /// `None` when the list could not be read.
    invitations: Option<Vec<MyInvitationRow>>,
    error: &'static str,
}

#[derive(Template)]
#[template(path = "settings-invitations.html")]
struct InvitationsTemplate<'a> {
    view: &'a DashboardView,
    page: &'a InvitationsPage,
}

pub(super) async fn page(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Response {
    if !account_sessions::cookie_authority_is_unique(&headers) {
        return private(login_redirect(PATH, &headers));
    }
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return private(login_redirect(PATH, &headers)),
        Err(error) => return private(error_page(error)),
    };
    if enforce_two_factor(&identity).is_err() {
        return private(two_factor_redirect(PATH, &headers));
    }
    let Ok(cookie) = canonical_cookie(&headers) else {
        return private(login_redirect(PATH, &headers));
    };
    let (dashboard, invitations) = tokio::join!(
        super::dashboard::personal_settings_shell_view_from_identity(
            &state,
            &headers,
            &identity,
            cookie.clone(),
            &query.org,
        ),
        connect::my_invitations(&state, cookie),
    );
    let dashboard = match dashboard {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return private(login_redirect(PATH, &headers)),
        Err(WebError::TwoFactorRequired) => return private(two_factor_redirect(PATH, &headers)),
        Err(error) => return private(error_page(error)),
    };
    let invitations = match invitations {
        Ok(invitations) => Some(rows(invitations, unix_now())),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return private(login_redirect(PATH, &headers));
        }
        // The list is the page's only content; an outage says so in place
        // and keeps the navigation and the verification state.
        Err(_) => None,
    };
    let page = InvitationsPage {
        csrf_token: page_csrf_token(&headers),
        email: identity.email().to_owned(),
        email_verified: identity.email_verified(),
        invitations,
        error: AcceptError::parse(&query.error).map_or("", AcceptError::message),
    };
    private(with_csrf_cookie(
        render_template(
            StatusCode::OK,
            InvitationsTemplate {
                view: &dashboard,
                page: &page,
            },
        ),
        csrf_cookie(&state.public_origin, &page.csrf_token),
    ))
}

/// Accept one of the account's own invitations by id. Same origin, the CSRF
/// token and two-factor are checked before the platform is asked.
pub(super) async fn accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<AcceptForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let cookie = match super::settings::mutation_cookie(&state, &headers, &form.csrf, PATH).await {
        Ok(cookie) => cookie,
        Err(response) => return private(response),
    };
    if !super::organization_governance::valid_identifier(&form.invitation_id) {
        return private(back(&state, &headers, AcceptError::NotFound));
    }
    match connect::accept_invitation_by_id(&state, cookie.clone(), form.invitation_id).await {
        Ok(org_id) => private(joined(&state, &headers, cookie, &org_id).await),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            private(login_redirect(PATH, &headers))
        }
        Err(error) => private(back(&state, &headers, AcceptError::from_code(error.code))),
    }
}

/// Open the organization just joined, or the account home when it cannot be
/// found among the account's memberships yet.
async fn joined(
    state: &AppState,
    headers: &HeaderMap,
    cookie: HeaderValue,
    org_id: &str,
) -> Response {
    let target = connect::organizations(state, cookie)
        .await
        .ok()
        .and_then(|organizations| {
            organizations
                .into_iter()
                .find(|organization| organization.id == org_id)
        })
        .map_or_else(
            || super::DASHBOARD_PATH.to_owned(),
            |organization| organization.url,
        );
    with_csrf_cookie(
        redirect(target, headers),
        csrf_cookie(&state.public_origin, &new_csrf_token()),
    )
}

fn back(state: &AppState, headers: &HeaderMap, error: AcceptError) -> Response {
    super::organization_governance::mutation_redirect(
        state,
        PATH.to_owned(),
        "",
        error.code(),
        headers,
    )
}

/// The pending invitations as rows, newest first as the platform sends them.
fn rows(invitations: Vec<OrgInvitation>, now: i64) -> Vec<MyInvitationRow> {
    invitations
        .into_iter()
        .filter(|invitation| {
            invitation.status.to_i32() == InvitationStatus::Pending as i32
                && invitation
                    .expires_at
                    .as_option()
                    .is_none_or(|expires| expires.seconds > now)
        })
        .map(|invitation| MyInvitationRow {
            organization_name: if invitation.org_name.trim().is_empty() {
                invitation.org_slug
            } else {
                invitation.org_name
            },
            role: connect::role_name(invitation.role.to_i32()),
            inviter_name: invitation
                .inviter_name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "a team administrator".to_owned()),
            expires: invitation
                .expires_at
                .into_option()
                .map(|timestamp| future_time(timestamp.seconds))
                .unwrap_or_else(|| "soon".to_owned()),
            assignments: ASSIGNMENTS
                .iter()
                .copied()
                .filter(|assignment| {
                    invitation
                        .assignments
                        .iter()
                        .any(|selected| selected == assignment.value)
                })
                .collect(),
            id: invitation.id,
        })
        .collect()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

#[cfg(test)]
mod tests;
