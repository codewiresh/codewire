//! A create request's body, read from its wire form.

use super::*;

pub(super) fn create_body(
    request: proto::CreateEnvironmentRequest,
) -> AppResult<CreateEnvironmentBody> {
    let project_spec = request
        .project_spec
        .into_option()
        .ok_or_else(|| {
            crate::api::environments::coded(
                axum::http::StatusCode::BAD_REQUEST,
                "project_spec_required",
                "project_spec is required",
            )
        })
        .and_then(|value| {
            codewire_project_proto::from_proto(value).map_err(|error| {
                crate::api::environments::coded_owned(
                    axum::http::StatusCode::BAD_REQUEST,
                    "invalid_project_spec",
                    error.to_string(),
                )
            })
        })?;
    Ok(CreateEnvironmentBody {
        preset_id: request.preset_id,
        name: request.name,
        ttl_seconds: request.ttl_seconds,
        idle_stop_seconds: request.idle_stop_seconds,
        idle_suspend_seconds: request.idle_suspend_seconds,
        idle_hibernate_seconds: request.idle_hibernate_seconds,
        isolation_tier: match request.isolation_tier.as_known() {
            Some(proto::IsolationTier::Unspecified) | Some(proto::IsolationTier::Standard) => {
                String::new()
            }
            Some(proto::IsolationTier::Confidential) => "confidential".to_string(),
            None => format!("unknown-enum-value-{}", request.isolation_tier.to_i32()),
        },
        project_spec,
        expected_profile_revision: request.expected_profile_revision,
        confirm_personal_credentials: request.confirm_personal_credentials,
        confirm_personal_secrets: request.confirm_personal_secrets,
        // The handler sets it from the request's authentication.
        confirmed_with: Default::default(),
        omit_application_previews: request.omit_application_previews,
        network: (!request.network.is_empty()).then_some(request.network),
        source_snapshot_id: (!request.source_snapshot_id.is_empty())
            .then_some(request.source_snapshot_id),
        // A placement message names its one choice; an empty host is refused
        // by the create, not read as no placement.
        placement_host: request
            .placement
            .as_option()
            .map(|placement| placement.host.clone()),
        request_id: (!request.request_id.is_empty()).then_some(request.request_id),
        network_policy: (!request.network_policy.is_empty()).then_some(request.network_policy),
    })
}
