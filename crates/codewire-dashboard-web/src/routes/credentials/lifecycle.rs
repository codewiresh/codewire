//! Revoking and deleting a credential from Settings → Credentials, each at
//! the exact revision the page showed.

use axum::{Form, extract::State, http::HeaderMap, response::Response};

use super::{
    CredentialQuery, CredentialRevisionSubmission, QueryParameters, credential_mutation_error,
    mutation_cookie, page_error_redirect, page_redirect, row_action_dialog, valid_generation,
};
use crate::{
    credentials_connect::{self, DeleteError, GitHubAnswer},
    environment_source_forms::exact_id,
    state::AppState,
};

pub(in crate::routes) async fn revoke_credential_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, false).await
}

pub(in crate::routes) async fn delete_credential_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, true).await
}

async fn credential_revision_action(
    state: AppState,
    query: QueryParameters,
    headers: HeaderMap,
    form: CredentialRevisionSubmission,
    delete: bool,
) -> Response {
    let dialog = row_action_dialog(
        "credential",
        &form.credential_id,
        if delete { "delete" } else { "revoke" },
    );
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, !delete)
    {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    }
    let result = if delete {
        credentials_connect::delete_credential(
            &state,
            cookie,
            form.credential_id,
            form.expected_revocation_generation,
        )
        .await
    } else {
        credentials_connect::revoke_credential(
            &state,
            cookie,
            form.credential_id,
            form.expected_revocation_generation,
        )
        .await
        .map(|()| None)
        .map_err(DeleteError::Unchanged)
    };
    // A GitHub disconnect says what GitHub still holds (#4717 C6).
    let done = match result {
        Ok(Some(GitHubAnswer::Confirmed)) => "github-disconnected-confirmed",
        Ok(Some(GitHubAnswer::NotConfirmed)) => "github-disconnected",
        Ok(None) if delete => "credential-deleted",
        Ok(None) => "credential-revoked",
        Err(DeleteError::RevokedNotRemoved) => {
            return page_error_redirect(GITHUB_REVOKED_NOT_REMOVED, &dialog, &query, &headers);
        }
        Err(DeleteError::Unchanged(error)) => {
            return credential_mutation_error(error.code, delete, &dialog, &query, &headers);
        }
    };
    page_redirect(done, false, &query, &headers)
}

const GITHUB_REVOKED_NOT_REMOVED: &str = "github-revoked-not-removed";

/// What a GitHub disconnect says once it's done (#4717 C6).
pub(super) fn github_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "github-disconnected" => {
            "GitHub disconnected. The Codewire app stays installed on GitHub; to remove it, uninstall it at https://github.com/settings/installations."
        }
        "github-disconnected-confirmed" => {
            "GitHub disconnected, and GitHub confirmed Codewire's access is revoked. The Codewire app stays installed on GitHub; to remove it, uninstall it at https://github.com/settings/installations."
        }
        _ => return None,
    })
}

/// What a GitHub disconnect says when the revoke held but its record
/// stayed (owner, 2026-11-17, on #4717).
pub(super) fn github_error(code: &str) -> Option<&'static str> {
    (code == GITHUB_REVOKED_NOT_REMOVED).then_some(
        "GitHub is disconnected, but Codewire couldn't remove its record. Disconnect again to finish.",
    )
}

#[cfg(test)]
#[path = "disconnect_tests.rs"]
mod disconnect_tests;
