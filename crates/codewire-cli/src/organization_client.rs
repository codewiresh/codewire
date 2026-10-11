use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use codewire_client::{self as rpc, ClientConfig, CodewireClient, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::CLI_VERSION;
use crate::config::{ResolvedPlatformConfig, normalize_server_url};
use crate::environment_client::display_client_error;

const ORGANIZATION_DELETION_POLL_INTERVAL: Duration = Duration::from_secs(2);
const ORGANIZATION_DELETION_POLL_WINDOW: Duration = Duration::from_secs(300);

/// Typed OrganizationService and PresetService facade for CLI presentation.
///
/// The shared `codewire-client` crate owns generated Connect transport and
/// authentication. This facade preserves the CLI's established output DTOs
/// after the command surface moved to the shared Connect client.
#[derive(Clone)]
pub struct OrganizationClient {
    inner: CodewireClient,
    public_origin: String,
}

impl OrganizationClient {
    pub fn new(config: &ResolvedPlatformConfig) -> anyhow::Result<Self> {
        let client_config = ClientConfig::new(&config.server_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
        Ok(Self {
            inner: CodewireClient::with_token_provider(client_config, config.token_provider()?)?,
            public_origin: normalize_server_url(&config.server_url),
        })
    }

    pub async fn list_orgs(&self) -> anyhow::Result<Vec<OrgWithRole>> {
        let response = self
            .inner
            .list_organizations(rpc::ListOrganizationsRequest::default())
            .await
            .map_err(display_client_error)?;
        response
            .organizations
            .into_iter()
            .map(legacy_org_with_role)
            .collect()
    }

    pub async fn create_org(&self, request: &CreateOrgRequest) -> anyhow::Result<Organization> {
        let response = self
            .inner
            .create_organization(rpc::CreateOrganizationRequest {
                name: request.name.clone(),
                slug: request.slug.clone(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .organization
            .into_option()
            .map(legacy_organization)
            .ok_or_else(|| anyhow::anyhow!("CreateOrganization returned no organization"))
    }

    pub async fn delete_org(&self, org_id: &str) -> anyhow::Result<OrganizationDeletionStart> {
        let response = self
            .inner
            .delete_organization(rpc::DeleteOrganizationRequest {
                org_id: org_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let state = response.state.as_known();
        if state != Some(rpc::OrganizationDeletionState::Deleting) {
            anyhow::bail!(
                "organization deletion response has unexpected state {:?}",
                state
            );
        }
        if response.operation_id.trim().is_empty() {
            anyhow::bail!("organization deletion response is missing operation_id");
        }
        Ok(OrganizationDeletionStart::Accepted(
            OrganizationDeletionOperation {
                operation_id: response.operation_id,
                state: OrganizationDeletionState::Deleting,
            },
        ))
    }

    pub async fn wait_for_org_deletion(
        &self,
        org_id: &str,
        operation_id: &str,
    ) -> anyhow::Result<OrganizationDeletionOutcome> {
        self.wait_for_org_deletion_with_policy(
            org_id,
            operation_id,
            ORGANIZATION_DELETION_POLL_INTERVAL,
            ORGANIZATION_DELETION_POLL_WINDOW,
        )
        .await
    }

    async fn wait_for_org_deletion_with_policy(
        &self,
        org_id: &str,
        operation_id: &str,
        poll_interval: Duration,
        poll_window: Duration,
    ) -> anyhow::Result<OrganizationDeletionOutcome> {
        let deadline = tokio::time::Instant::now() + poll_window;
        loop {
            let response = match self
                .inner
                .get_organization(rpc::GetOrganizationRequest {
                    org_id: org_id.to_string(),
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response,
                Err(error) if error.code() == ErrorCode::NotFound => {
                    return Ok(OrganizationDeletionOutcome::Completed);
                }
                Err(error) => return Err(display_client_error(error)).context("get organization"),
            };
            let organization = response
                .organization
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("GetOrganization returned no organization"))?;

            if let Some(observed_operation_id) = organization.deletion_operation_id.as_deref()
                && observed_operation_id != operation_id
            {
                anyhow::bail!(
                    "organization deletion operation changed from {operation_id} to {observed_operation_id}"
                );
            }

            match organization
                .deletion_state
                .as_ref()
                .and_then(|state| state.as_known())
            {
                Some(rpc::OrganizationDeletionState::DeleteFailed) => {
                    return Ok(OrganizationDeletionOutcome::Failed {
                        operation_id: operation_id.to_string(),
                        failure_code: organization
                            .deletion_failure_code
                            .filter(|code| !code.trim().is_empty())
                            .unwrap_or_else(|| "organization_deletion_failed".to_string()),
                    });
                }
                Some(rpc::OrganizationDeletionState::Deleting) | None => {}
                Some(rpc::OrganizationDeletionState::Active) => {
                    anyhow::bail!(
                        "organization deletion {operation_id} unexpectedly returned to active"
                    );
                }
                Some(rpc::OrganizationDeletionState::Unspecified) => {
                    anyhow::bail!(
                        "organization deletion {operation_id} returned an unspecified state"
                    );
                }
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(OrganizationDeletionOutcome::PollingStopped {
                    operation_id: operation_id.to_string(),
                });
            }
            tokio::time::sleep(poll_interval.min(deadline - now)).await;
        }
    }

    pub async fn create_invitation(
        &self,
        org_id: &str,
        request: &CreateInvitationRequest,
    ) -> anyhow::Result<CreatedInvitation> {
        let response = self
            .inner
            .create_invitation(rpc::CreateInvitationRequest {
                org_id: org_id.to_string(),
                email: request.email.clone(),
                role: parse_org_role(&request.role)?.into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let invitation = response
            .invitation
            .into_option()
            .map(legacy_invitation)
            .ok_or_else(|| anyhow::anyhow!("CreateInvitation returned no invitation"))?;
        let url = invitation_url(&self.public_origin, &response.token)?;
        Ok(CreatedInvitation { invitation, url })
    }

    pub async fn list_presets(&self, org_id: &str) -> anyhow::Result<Vec<Preset>> {
        let response = self
            .inner
            .list_presets(rpc::ListPresetsRequest {
                org_id: org_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .presets
            .into_iter()
            .map(preset_from_proto)
            .collect()
    }

    pub async fn create_preset(
        &self,
        org_id: &str,
        request: &CreatePresetRequest,
    ) -> anyhow::Result<Preset> {
        let response = self
            .inner
            .create_preset(rpc::CreatePresetRequest {
                org_id: org_id.to_string(),
                name: request.name.clone(),
                slug: request.slug.clone(),
                description: (!request.description.is_empty()).then(|| request.description.clone()),
                default_ttl_seconds: request.default_ttl_seconds,
                project_spec: Some(codewire_project_proto::to_proto(
                    request.project_spec.clone(),
                ))
                .into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .preset
            .into_option()
            .map(preset_from_proto)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("CreatePreset returned no preset"))
    }

    pub async fn delete_preset(&self, org_id: &str, preset_id: &str) -> anyhow::Result<()> {
        self.inner
            .delete_preset(rpc::DeletePresetRequest {
                org_id: org_id.to_string(),
                preset_id: preset_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct OrgWithRole {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
    pub role: String,
    #[serde(rename = "billingPlan", skip_serializing_if = "String::is_empty")]
    pub billing_plan: String,
    #[serde(rename = "billingStatus", skip_serializing_if = "String::is_empty")]
    pub billing_status: String,
    #[serde(rename = "trialEndsAt", skip_serializing_if = "Option::is_none")]
    pub trial_ends_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationDeletionState {
    Active,
    Deleting,
    DeleteFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationDeletionOperation {
    pub operation_id: String,
    pub state: OrganizationDeletionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrganizationDeletionStart {
    Accepted(OrganizationDeletionOperation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrganizationDeletionOutcome {
    Completed,
    Failed {
        operation_id: String,
        failure_code: String,
    },
    PollingStopped {
        operation_id: String,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct OrgInvitation {
    pub id: String,
    pub org_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org_name: String,
    pub email: String,
    pub role: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub invited_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_name: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub expires_at: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

/// Invitation metadata plus the one-time URL returned only by create.
/// List/read invitation models never carry this capability.
pub struct CreatedInvitation {
    pub invitation: OrgInvitation,
    pub url: String,
}

impl std::fmt::Debug for CreatedInvitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedInvitation")
            .field("invitation", &self.invitation)
            .field("url", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Preset {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub official: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub build_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<i32>,
    pub project_spec: codewire_project::ProjectSpec,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CreatePresetRequest {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub slug: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<i32>,
    pub project_spec: codewire_project::ProjectSpec,
}

fn legacy_org_with_role(value: rpc::OrganizationMembership) -> anyhow::Result<OrgWithRole> {
    let organization = value.organization.into_option().ok_or_else(|| {
        anyhow::anyhow!("ListOrganizations returned a membership without organization")
    })?;
    Ok(OrgWithRole {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        created_at: organization
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        role: legacy_org_role(value.role.as_known()),
        billing_plan: value.billing_plan,
        billing_status: value.billing_status,
        trial_ends_at: value.trial_ends_at.into_option().map(timestamp_to_rfc3339),
    })
}

fn legacy_organization(value: rpc::Organization) -> Organization {
    Organization {
        id: value.id,
        name: value.name,
        slug: value.slug,
        created_by: value.created_by,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        updated_at: value
            .updated_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    }
}

fn legacy_invitation(value: rpc::OrgInvitation) -> OrgInvitation {
    OrgInvitation {
        id: value.id,
        org_id: value.org_id,
        org_name: value.org_name,
        email: value.email,
        role: legacy_org_role(value.role.as_known()),
        invited_by: value.invited_by,
        inviter_name: value.inviter_name,
        status: legacy_invitation_status(value.status.as_known()),
        expires_at: value
            .expires_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        accepted_at: value.accepted_at.into_option().map(timestamp_to_rfc3339),
    }
}

fn invitation_url(public_origin: &str, token: &str) -> anyhow::Result<String> {
    if token.is_empty() {
        anyhow::bail!("CreateInvitation returned no one-time token");
    }
    let mut url = url::Url::parse(public_origin).context("parse public invitation origin")?;
    url.set_path("/accept-invite");
    url.set_query(None);
    url.set_fragment(None);
    url.query_pairs_mut().append_pair("token", token);
    Ok(url.into())
}

pub(crate) fn preset_from_proto(value: rpc::Preset) -> anyhow::Result<Preset> {
    let project_spec = value
        .project_spec
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Preset omitted project_spec"))
        .and_then(|spec| codewire_project_proto::from_proto(spec).map_err(Into::into))?;
    Ok(Preset {
        id: value.id,
        org_id: value.org_id,
        name: value.name,
        slug: value.slug,
        language: value.language,
        official: value.official,
        description: value.description,
        build_status: value.build_status,
        build_error: value.build_error,
        default_ttl_seconds: value.default_ttl_seconds,
        project_spec,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    })
}

fn parse_org_role(value: &str) -> anyhow::Result<rpc::OrgRole> {
    match value {
        "owner" => Ok(rpc::OrgRole::Owner),
        "admin" => Ok(rpc::OrgRole::Admin),
        "member" => Ok(rpc::OrgRole::Member),
        value => anyhow::bail!("invalid organization role {value:?}"),
    }
}

fn legacy_org_role(value: Option<rpc::OrgRole>) -> String {
    match value {
        Some(rpc::OrgRole::Unspecified) => String::new(),
        Some(rpc::OrgRole::Owner) => "owner".to_string(),
        Some(rpc::OrgRole::Admin) => "admin".to_string(),
        Some(rpc::OrgRole::Member) => "member".to_string(),
        None => "unknown".to_string(),
    }
}

fn legacy_invitation_status(value: Option<rpc::InvitationStatus>) -> String {
    match value {
        Some(rpc::InvitationStatus::Unspecified) => String::new(),
        Some(rpc::InvitationStatus::Pending) => "pending".to_string(),
        Some(rpc::InvitationStatus::Accepted) => "accepted".to_string(),
        Some(rpc::InvitationStatus::Revoked) => "revoked".to_string(),
        Some(rpc::InvitationStatus::Expired) => "expired".to_string(),
        None => "unknown".to_string(),
    }
}

fn timestamp_to_rfc3339(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_invitation_url_is_canonical_and_debug_redacted() {
        let token = "synthetic/invitation capability?marker";
        let url = invitation_url("https://codewire.test/api/", token).unwrap();
        assert_eq!(
            url,
            "https://codewire.test/accept-invite?token=synthetic%2Finvitation+capability%3Fmarker"
        );

        let created = CreatedInvitation {
            invitation: OrgInvitation {
                id: "invitation-1".into(),
                email: "member@example.test".into(),
                ..Default::default()
            },
            url,
        };
        let diagnostic = format!("{created:?}");
        assert!(diagnostic.contains("member@example.test"));
        assert!(!diagnostic.contains("synthetic%2F"));
        assert!(!diagnostic.contains("capability"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn organization_and_preset_adapters_preserve_cli_json_and_canonical_project_intent() {
        let organization = legacy_org_with_role(rpc::OrganizationMembership {
            organization: Some(rpc::Organization {
                id: "org_123".into(),
                name: "Acme".into(),
                slug: "acme".into(),
                created_at: Some(rpc::Timestamp {
                    seconds: 1_767_225_600,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            role: rpc::OrgRole::Owner.into(),
            billing_plan: "team".into(),
            billing_status: "active".into(),
            trial_ends_at: Some(rpc::Timestamp {
                seconds: 1_767_312_000,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .expect("organization membership");
        assert_eq!(
            serde_json::to_value(organization).expect("organization JSON"),
            serde_json::json!({
                "id": "org_123",
                "name": "Acme",
                "slug": "acme",
                "created_at": "2026-01-01T00:00:00Z",
                "role": "owner",
                "billingPlan": "team",
                "billingStatus": "active",
                "trialEndsAt": "2026-01-02T00:00:00Z"
            })
        );

        let project_spec = codewire_project::parse_project_yaml(
            &r#"
version: 1
image: CANONICAL_WORKSPACE_IMAGE
repositories:
  - source: https://example.test/org/app.git
    destination: /workspace/app
working_directory: /workspace/app
install_command: cargo fetch
startup_script: cargo test
environment: {RUST_LOG: info}
agents: {install: false, tools: [codex]}
ports: [{port: 8080, label: api, access: private}]
cpu: "2"
memory: "8Gi"
disk: "40Gi"
"#
            .replace(
                "CANONICAL_WORKSPACE_IMAGE",
                codewire_workspace_image::PUBLIC_IMAGE,
            ),
        )
        .unwrap()
        .spec;
        let preset = preset_from_proto(rpc::Preset {
            id: "preset_123".into(),
            org_id: Some("org_123".into()),
            name: "Rust".into(),
            slug: Some("rust".into()),
            project_spec: Some(codewire_project_proto::to_proto(project_spec.clone())).into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .expect("preset");
        let json = serde_json::to_value(&preset).expect("preset JSON");
        assert_eq!(json["id"], "preset_123");
        assert_eq!(json["org_id"], "org_123");
        assert_eq!(json["slug"], "rust");
        assert_eq!(json["created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(preset.project_spec, project_spec);
    }

    #[test]
    fn preset_adapter_requires_canonical_project_spec_presence() {
        let error = preset_from_proto(rpc::Preset::default()).unwrap_err();
        assert!(error.to_string().contains("omitted project_spec"));

        let request = CreatePresetRequest {
            name: "Canonical".to_string(),
            project_spec: codewire_project::ProjectSpec::default(),
            ..Default::default()
        };
        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("project_spec").is_some());
        for removed in ["image", "env_vars", "agents", "agent_env"] {
            assert!(
                value.get(removed).is_none(),
                "unexpected top-level {removed}"
            );
        }
    }

    #[test]
    fn organization_enum_adapters_preserve_public_values() {
        assert_eq!(legacy_org_role(Some(rpc::OrgRole::Admin)), "admin");
        assert_eq!(
            legacy_invitation_status(Some(rpc::InvitationStatus::Pending)),
            "pending"
        );
    }
}
