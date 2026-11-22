//! Retry setup from the Sandbox page (#4767). The server decides whether the
//! Sandbox can retry and whether the retry clones again; a retry that would
//! delete repository directories returns to the page with its confirmation
//! open, and only that confirmation sends `confirm_reclone`. A retry that
//! starts returns to the page with the time it was asked for, so the page's
//! step list shows the failed run and then follows the retry's.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use codewire_proto::codewire::v1::RetryEnvironmentSetupRequest;
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    environment_connect::environment_client,
    response::login_redirect,
    routes::organization_governance::{action_context, mutation_redirect},
    state::AppState,
    view::{SandboxListContext, connect_error_reason},
};

use super::environments::{lifecycle_feedback_path, mutation_error};
use super::terminal::canonical_environment_id;

#[derive(Deserialize)]
pub(super) struct RetrySetupSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    #[serde(default)]
    confirm_reclone: String,
    #[serde(flatten)]
    list_context: SandboxListContext,
}

/// Whether a refusal asks the person to confirm the clone: orchestration's
/// `reclone_unconfirmed` (`connect_error.rs`).
fn asks_to_confirm_reclone(error: &ConnectError) -> bool {
    error.code == ErrorCode::FailedPrecondition
        && connect_error_reason(error).as_deref() == Some("RECLONE_UNCONFIRMED")
}

/// Where a refused, unconfirmed reclone returns: the Sandbox page with its
/// confirmation open.
fn confirm_path(detail: &str) -> String {
    format!("{detail}{}confirm=reclone", separator(detail))
}

/// Where a started retry returns: the Sandbox page, with when it was asked
/// for (`TerminalQuery::setup_retry_since` reads it).
pub(super) fn retried_path(detail: &str, asked_at: DateTime<Utc>) -> String {
    let asked_at = asked_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    format!("{detail}{}setup_retry={asked_at}", separator(detail))
}

fn separator(detail: &str) -> char {
    if detail.contains('?') { '&' } else { '?' }
}

pub(super) async fn retry_setup(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<RetrySetupSubmission>,
) -> Response {
    let list_context = submission.list_context.normalized();
    if !canonical_environment_id(&submission.environment_id) {
        return mutation_redirect(
            lifecycle_feedback_path(&list_context.list_url(&slug), "", "invalid"),
            "",
            "",
            &headers,
        );
    }
    let detail = list_context.detail_url(&slug, &submission.environment_id);
    let (_, organization, cookie) =
        match action_context(&state, &headers, &slug, &submission.csrf, detail.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    // Before the request, so the failed run ended before it and the retry's
    // run after.
    let asked_at = Utc::now();
    let request = RetryEnvironmentSetupRequest {
        org_id: organization.id,
        environment_id: submission.environment_id,
        confirm_reclone: submission.confirm_reclone == "1",
        ..Default::default()
    };
    match environment_client(&state, cookie)
        .retry_environment_setup(request)
        .await
    {
        // The page follows the retry in its step list; nothing else is said.
        Ok(_) => mutation_redirect(retried_path(&detail, asked_at), "", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&detail, &headers),
        Err(error) if asks_to_confirm_reclone(&error) => {
            mutation_redirect(confirm_path(&detail), "", "", &headers)
        }
        Err(error) => mutation_redirect(
            lifecycle_feedback_path(&detail, "", mutation_error(&error)),
            "",
            "",
            &headers,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(reason: &str) -> ConnectError {
        let info = codewire_proto::google::rpc::ErrorInfo {
            reason: reason.to_owned(),
            domain: "codewire.sh".to_owned(),
            ..Default::default()
        };
        ConnectError::failed_precondition("refused").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &info),
        )
    }

    #[test]
    fn only_an_unconfirmed_reclone_opens_the_confirmation() {
        assert!(asks_to_confirm_reclone(&refusal("RECLONE_UNCONFIRMED")));
        // Every other refusal says why on the page instead.
        assert!(!asks_to_confirm_reclone(&refusal("INVALID_STATE")));
        assert!(!asks_to_confirm_reclone(
            &ConnectError::failed_precondition("no reason")
        ));
    }

    #[test]
    fn an_unconfirmed_reclone_returns_with_its_confirmation_open() {
        let id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        assert_eq!(
            confirm_path(&format!("/org/{id}/")),
            format!("/org/{id}/?confirm=reclone")
        );
        assert_eq!(
            confirm_path(&format!("/org/{id}/?list_state=running")),
            format!("/org/{id}/?list_state=running&confirm=reclone")
        );
    }

    #[test]
    fn a_started_retry_returns_with_when_it_was_asked_for() {
        let id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let asked_at = DateTime::parse_from_rfc3339("2026-10-06T10:00:00.25Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            retried_path(&format!("/org/{id}/"), asked_at),
            format!("/org/{id}/?setup_retry=2026-10-06T10:00:00.250Z")
        );
        assert_eq!(
            retried_path(&format!("/org/{id}/?list_state=running"), asked_at),
            format!("/org/{id}/?list_state=running&setup_retry=2026-10-06T10:00:00.250Z")
        );
    }
}
