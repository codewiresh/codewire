//! Retry setup from the Sandbox page (#4767). The server decides whether the
//! Sandbox can retry and whether the retry clones again; a retry that would
//! delete repository directories returns to the page with its confirmation
//! open, and only that confirmation sends `confirm_reclone`.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
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
    let separator = if detail.contains('?') { '&' } else { '?' };
    format!("{detail}{separator}confirm=reclone")
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
        Ok(_) => mutation_redirect(detail, "", "", &headers),
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
}
