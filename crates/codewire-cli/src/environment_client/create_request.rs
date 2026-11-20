//! A create request, to and from its wire form.

use super::*;

pub(super) fn proto_create_environment_request(
    org_id: &str,
    request: &CreateEnvironmentRequest,
) -> rpc::CreateEnvironmentRequest {
    rpc::CreateEnvironmentRequest {
        org_id: org_id.to_string(),
        preset_id: request.preset_id.clone(),
        name: request.name.clone(),
        ttl_seconds: request.ttl_seconds,
        idle_stop_seconds: request.idle_stop_seconds,
        isolation_tier: match request.isolation_tier.as_str() {
            "" | "standard" => rpc::IsolationTier::Standard.into(),
            "confidential" => rpc::IsolationTier::Confidential.into(),
            _ => rpc::IsolationTier::Unspecified.into(),
        },
        project_spec: Some(codewire_project_proto::to_proto(
            request.project_spec.clone(),
        ))
        .into(),
        expected_profile_revision: request.expected_profile_revision,
        confirm_personal_credentials: request.confirm_personal_credentials,
        confirm_personal_secrets: request.confirm_personal_secrets,
        omit_application_previews: request.omit_application_previews,
        network: request.network.clone().unwrap_or_default(),
        network_policy: request.network_policy.clone().unwrap_or_default(),
        source_snapshot_id: request.source_snapshot_id.clone().unwrap_or_default(),
        placement: request
            .placement_host
            .clone()
            .map(|host| rpc::EnvironmentPlacement {
                host,
                ..Default::default()
            })
            .into(),
        request_id: request.request_id.clone().unwrap_or_default(),
        ..Default::default()
    }
}

pub(super) fn create_environment_request_from_proto(
    value: rpc::CreateEnvironmentRequest,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let project_spec = value
        .project_spec
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("CreateEnvironmentRequest omitted project_spec"))
        .and_then(|value| codewire_project_proto::from_proto(value).map_err(Into::into))?;
    Ok(CreateEnvironmentRequest {
        preset_id: value.preset_id,
        name: value.name,
        ttl_seconds: value.ttl_seconds,
        idle_stop_seconds: value.idle_stop_seconds,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                String::new()
            }
        },
        project_spec,
        expected_profile_revision: value.expected_profile_revision,
        confirm_personal_credentials: value.confirm_personal_credentials,
        confirm_personal_secrets: value.confirm_personal_secrets,
        omit_application_previews: value.omit_application_previews,
        network: empty_to_none(value.network),
        network_policy: empty_to_none(value.network_policy),
        source_snapshot_id: empty_to_none(value.source_snapshot_id),
        placement_host: value
            .placement
            .into_option()
            .map(|placement| placement.host),
        request_id: empty_to_none(value.request_id),
    })
}
