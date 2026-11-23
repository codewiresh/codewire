//! Adapter for an admin's deletion of someone else's account (#4541), the
//! IdP's `POST /api/admin/accounts/{user_id}/delete`.
//!
//! Like the factor controls it sends only the canonical session cookie, the
//! public Origin and the browser's User-Agent, never follows redirects and
//! bounds the response. From an error body it keeps only a code from a closed
//! list and, with the hourly cap, the IdP's sentence saying when it resets.
//! The password and code are never logged; no type here implements `Debug`.

use axum::http::{HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};

use crate::account_sessions::valid_id;
use crate::account_two_factor::{bounded_json, post};
use crate::state::AppState;

const MAX_EMAIL_BYTES: usize = 320;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_PROOF_BYTES: usize = 64;
const MAX_DETAIL_BYTES: usize = 200;

/// Why a deletion did not start. Nothing was deleted in any of them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The admin's session is gone; sign in again.
    Unauthorized,
    /// The session is no longer an admin's.
    Forbidden,
    /// The account no longer exists.
    NotFound,
    /// The admin's password or code was wrong.
    ProofRejected,
    /// The admin's account is locked after repeated failures.
    Locked,
    /// The admin asked for more deletions than an hour allows. The IdP's
    /// sentence says when the window resets.
    RateLimited(String),
    /// The address did not match, the account is an admin, or one of its
    /// organizations is in the way. The page reads the plan again to say
    /// which.
    Refused,
    /// The IdP could not be reached or answered something else.
    Unavailable,
}

impl Refusal {
    /// A fixed name for the log, never the IdP's sentence.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::ProofRejected => "proof_rejected",
            Self::Locked => "locked",
            Self::RateLimited(_) => "rate_limited",
            Self::Refused => "refused",
            Self::Unavailable => "identity_unavailable",
        }
    }
}

/// Where an admin deletion that did not start was stopped.
#[derive(Clone, Copy)]
pub(crate) enum Stage {
    /// The dashboard's own checks, before any call to the IdP.
    Dashboard,
    /// The IdP's answer.
    IdentityService,
}

/// Logs an admin deletion that did not start (#5770), so a refusal leaves a
/// trace even where the IdP counts and audits nothing: where it stopped, a
/// fixed reason, and the target account's id when the form named a valid
/// one. Never the typed address, the password or the code.
pub(crate) fn log_refused(stage: Stage, reason: &'static str, target_user_id: Option<&str>) {
    let stage = match stage {
        Stage::Dashboard => "dashboard",
        Stage::IdentityService => "identity_service",
    };
    tracing::warn!(
        stage,
        reason,
        target_user_id = target_user_id.unwrap_or(""),
        "admin account deletion not started"
    );
    #[cfg(test)]
    REFUSALS_LOGGED.with(|logged| {
        logged
            .borrow_mut()
            .push((stage, reason, target_user_id.unwrap_or("").to_owned()));
    });
}

// What `log_refused` logged on this thread, for tests: a test's handlers run
// on its own thread, so this reads only that test's refusals.
#[cfg(test)]
thread_local! {
    pub(crate) static REFUSALS_LOGGED: std::cell::RefCell<Vec<(&'static str, &'static str, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[derive(Serialize)]
struct DeleteRequest<'a> {
    confirm_email: &'a str,
    password: &'a str,
    proof: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Started {
    operation_id: String,
}

/// The parts of an IdP error body the page acts on; the rest is ignored.
#[derive(Deserialize)]
struct ErrorBody {
    code: Option<String>,
    detail: Option<String>,
}

/// The confirmation a browser sent: the account's address, the admin's
/// password and an authenticator or recovery code.
pub(crate) struct Confirmation<'a> {
    pub(crate) email: &'a str,
    pub(crate) password: &'a str,
    pub(crate) proof: &'a str,
}

impl Confirmation<'_> {
    fn proof_is_well_formed(&self) -> bool {
        !self.password.is_empty()
            && self.password.len() <= MAX_PASSWORD_BYTES
            && !self.proof.trim().is_empty()
            && self.proof.len() <= MAX_PROOF_BYTES
    }
}

/// Ask the IdP to delete `user_id`'s account, as the admin whose session
/// `cookie` is.
pub(crate) async fn delete_account(
    state: &AppState,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    user_id: &str,
    confirmation: &Confirmation<'_>,
) -> Result<(), Refusal> {
    if !valid_id(user_id) {
        log_refused(Stage::Dashboard, "invalid_account_id", None);
        return Err(Refusal::NotFound);
    }
    let email = confirmation.email.trim();
    if email.is_empty() || email.len() > MAX_EMAIL_BYTES {
        log_refused(Stage::Dashboard, "confirm_email_unusable", Some(user_id));
        return Err(Refusal::Refused);
    }
    if !confirmation.proof_is_well_formed() {
        log_refused(Stage::Dashboard, "proof_unusable", Some(user_id));
        return Err(Refusal::ProofRejected);
    }
    let response = post(
        state,
        &format!("/api/admin/accounts/{user_id}/delete"),
        cookie,
        user_agent,
        &DeleteRequest {
            confirm_email: email,
            password: confirmation.password,
            proof: confirmation.proof,
        },
    )
    .await
    .map_err(|()| {
        log_refused(
            Stage::IdentityService,
            "identity_unreachable",
            Some(user_id),
        );
        Refusal::Unavailable
    })?;
    let status = response.status();
    if status == StatusCode::OK {
        let started = bounded_json::<Started>(response)
            .await
            .ok()
            .filter(|started| {
                started.operation_id.starts_with("account-deletion/")
                    && started.operation_id.len() <= 128
            });
        if started.is_none() {
            log_refused(
                Stage::IdentityService,
                "identity_answer_unreadable",
                Some(user_id),
            );
            return Err(Refusal::Unavailable);
        }
        tracing::info!(target_user_id = user_id, "admin account deletion started");
        return Ok(());
    }
    let body = bounded_json::<ErrorBody>(response).await.ok();
    let refused = refusal(status, body);
    log_refused(Stage::IdentityService, refused.code(), Some(user_id));
    Err(refused)
}

fn refusal(status: StatusCode, body: Option<ErrorBody>) -> Refusal {
    let code = body.as_ref().and_then(|body| body.code.as_deref());
    match (status, code) {
        (StatusCode::UNAUTHORIZED, _) => Refusal::Unauthorized,
        (StatusCode::FORBIDDEN, _) => Refusal::Forbidden,
        (StatusCode::NOT_FOUND, _) => Refusal::NotFound,
        (StatusCode::UNPROCESSABLE_ENTITY, Some("proof_rejected")) => Refusal::ProofRejected,
        (StatusCode::TOO_MANY_REQUESTS, Some("account_locked")) => Refusal::Locked,
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")) => {
            match body
                .and_then(|body| body.detail)
                .filter(|detail| plain(detail))
            {
                Some(detail) => Refusal::RateLimited(detail),
                None => Refusal::Unavailable,
            }
        }
        (StatusCode::BAD_REQUEST, _) => Refusal::Refused,
        _ => Refusal::Unavailable,
    }
}

/// A short single line of text, safe to show as the IdP wrote it.
fn plain(detail: &str) -> bool {
    !detail.is_empty() && detail.len() <= MAX_DETAIL_BYTES && !detail.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(code: &str, detail: &str) -> Option<ErrorBody> {
        Some(ErrorBody {
            code: Some(code.into()),
            detail: Some(detail.into()),
        })
    }

    #[test]
    fn only_closed_codes_and_a_plain_cap_sentence_leave_the_idp() {
        let cap = "at most 10 account deletions an hour; try again after 14:05:00 UTC";
        assert!(
            refusal(StatusCode::TOO_MANY_REQUESTS, body("rate_limited", cap))
                == Refusal::RateLimited(cap.into())
        );
        assert!(
            refusal(StatusCode::TOO_MANY_REQUESTS, body("account_locked", "x")) == Refusal::Locked
        );
        assert!(
            refusal(
                StatusCode::UNPROCESSABLE_ENTITY,
                body("proof_rejected", "upstream-private-canary")
            ) == Refusal::ProofRejected
        );
        for detail in ["", "line\nbreak", &"a".repeat(201)] {
            assert!(
                refusal(StatusCode::TOO_MANY_REQUESTS, body("rate_limited", detail))
                    == Refusal::Unavailable,
                "{detail:?}"
            );
        }
        assert!(refusal(StatusCode::TOO_MANY_REQUESTS, None) == Refusal::Unavailable);
        assert!(refusal(StatusCode::BAD_REQUEST, body("", "the address")) == Refusal::Refused);
        assert!(refusal(StatusCode::CONFLICT, None) == Refusal::Unavailable);
    }
}
