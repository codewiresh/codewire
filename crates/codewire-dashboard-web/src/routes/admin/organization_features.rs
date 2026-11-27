//! An organization's feature switches on its admin page, one list of
//! checkboxes saved together (#5602): confidential environments, systemd
//! workspaces, the standard runtime and dedicated CPU. Each switch the page
//! could read carries the value it showed; only the switches whose box now
//! differs are changed, each through its own audited call, in this order.

use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use connectrpc::ErrorCode;
use serde::Deserialize;

use super::{
    AdminQuery, admin_action_page_context_for, admin_redirect_to, mutation_error,
    organization_path, valid_organization_id,
};
use crate::admin_connect;
use crate::error::WebError;
use crate::response::{error_page, login_redirect};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(in crate::routes) struct FeaturesSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    organization_id: String,
    organization_slug: String,
    /// The value the page showed, present only for a switch it could read.
    confidential_was: Option<bool>,
    /// A checked box; absent when unchecked.
    confidential: Option<String>,
    systemd_was: Option<bool>,
    systemd: Option<String>,
    standard_was: Option<bool>,
    standard: Option<String>,
    dedicated_cpu_was: Option<bool>,
    dedicated_cpu: Option<String>,
    agent_chat_was: Option<bool>,
    agent_chat: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Feature {
    Confidential,
    Systemd,
    Standard,
    DedicatedCpu,
    AgentChat,
}

/// The switches the administrator changed, with their new values: each one
/// the page could read whose box now differs from what it showed.
pub(super) fn changes(form: &FeaturesSubmission) -> Vec<(Feature, bool)> {
    [
        (
            Feature::Confidential,
            form.confidential_was,
            form.confidential.is_some(),
        ),
        (Feature::Systemd, form.systemd_was, form.systemd.is_some()),
        (
            Feature::Standard,
            form.standard_was,
            form.standard.is_some(),
        ),
        (
            Feature::DedicatedCpu,
            form.dedicated_cpu_was,
            form.dedicated_cpu.is_some(),
        ),
        (
            Feature::AgentChat,
            form.agent_chat_was,
            form.agent_chat.is_some(),
        ),
    ]
    .into_iter()
    .filter_map(|(feature, was, now)| was.filter(|was| *was != now).map(|_| (feature, now)))
    .collect()
}

/// Save an organization's switches from its admin page. Global
/// administrators only; each service checks the administrator again and
/// writes its own audit entry.
pub(in crate::routes) async fn set_organization_features(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<FeaturesSubmission>,
) -> Response {
    if !valid_organization_id(&submission.organization_id) {
        return error_page(WebError::NotFound);
    }
    let path = organization_path(&submission.organization_id);
    let cookie =
        match admin_action_page_context_for(&state, &headers, &submission.csrf, &query.org, &path)
            .await
        {
            Ok((_, cookie)) => cookie,
            Err(response) => return response,
        };
    let slug = &submission.organization_slug;
    if !codewire_server_core::organization_slug::valid_organization_slug(slug) {
        return admin_redirect_to(&path, "", "not-found", &headers);
    }
    let changes = changes(&submission);
    if changes.is_empty() {
        return admin_redirect_to(&path, "features-unchanged", "", &headers);
    }
    let organization_id = submission.organization_id.as_str();
    for (feature, enabled) in changes {
        let cookie = cookie.clone();
        let result = match feature {
            Feature::Confidential => {
                admin_connect::set_confidential_environments(&state, cookie, slug.clone(), enabled)
                    .await
            }
            Feature::Systemd => {
                admin_connect::set_systemd_environments(&state, cookie, slug.clone(), enabled).await
            }
            Feature::Standard => {
                admin_connect::set_standard_runtime(&state, cookie, organization_id, enabled).await
            }
            Feature::DedicatedCpu => {
                admin_connect::set_organization_dedicated_cpu(
                    &state,
                    cookie,
                    organization_id,
                    enabled,
                )
                .await
            }
            Feature::AgentChat => {
                admin_connect::set_organization_agent_chat(&state, cookie, organization_id, enabled)
                    .await
            }
        };
        match result {
            Ok(()) => {}
            Err(error) if error.code == ErrorCode::Unauthenticated => {
                return login_redirect(&path, &headers);
            }
            Err(error) => {
                return admin_redirect_to(&path, "", failure(feature, &error), &headers);
            }
        }
    }
    admin_redirect_to(&path, "features-saved", "", &headers)
}

/// The error a failed switch shows.
fn failure(feature: Feature, error: &connectrpc::ConnectError) -> &'static str {
    match (feature, error.code, mutation_error(error)) {
        (Feature::Standard, ErrorCode::FailedPrecondition, _) => "standard-not-offered",
        (Feature::Confidential, _, "unavailable" | "conflict") => "confidential-unavailable",
        (Feature::Systemd, _, "unavailable" | "conflict") => "systemd-unavailable",
        (Feature::Standard, _, "unavailable" | "conflict") => "standard-unavailable",
        (_, _, code) => code,
    }
}

#[cfg(test)]
mod tests;
