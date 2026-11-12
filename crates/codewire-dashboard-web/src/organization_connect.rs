use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    ApiKeyServiceClient, CreateApiKeyRequest, CreateInvitationRequest, DeleteApiKeyRequest,
    InvitationStatus, ListApiKeysRequest, ListInvitationsRequest, ListMembersRequest,
    OrgInvitation, OrgRole, OrganizationServiceClient, RemoveMemberRequest,
    RevokeInvitationRequest, UpdateApiKeyRequest, UpdateMemberAssignmentsRequest,
    UpdateMemberRoleRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    state::AppState,
    transport::BrowserTransport,
    view::{ASSIGNMENTS, ApiKeyRow, InvitationRow, MemberRow},
};

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn client_config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone())
        .with_default_timeout(std::time::Duration::from_secs(10))
}

/// The raw invitation capability returned only by CreateInvitation.
/// Diagnostics are deliberately value-blind and list/read models use
/// [`InvitationRow`], which cannot carry this value.
pub(crate) struct CreatedInvitation {
    pub(crate) token: String,
}

impl std::fmt::Debug for CreatedInvitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedInvitation")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

pub(crate) async fn members(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    include_invitations: bool,
) -> Result<(Vec<MemberRow>, Vec<InvitationRow>), ConnectError> {
    let member_client =
        OrganizationServiceClient::new(transport(state, cookie.clone()), client_config(state));
    let member_response = member_client
        .list_members(ListMembersRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();

    let members = member_response
        .members
        .into_iter()
        .map(|member| {
            let role = role_name(member.role.to_i32());
            let display_name = member
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| member.email.clone());
            let initial = display_name
                .chars()
                .next()
                .unwrap_or('?')
                .to_ascii_uppercase();
            let selected_assignments = member.assignments;
            let assignments = ASSIGNMENTS
                .iter()
                .copied()
                .filter(|assignment| {
                    selected_assignments
                        .iter()
                        .any(|selected| selected == assignment.value)
                })
                .collect();
            MemberRow {
                id: member.id,
                user_id: member.user_id,
                display_name,
                email: member.email,
                initial,
                role,
                is_owner: role == "Owner",
                assignments,
                selected_assignments,
            }
        })
        .collect();

    if !include_invitations {
        return Ok((members, Vec::new()));
    }

    let invitation_client =
        OrganizationServiceClient::new(transport(state, cookie), client_config(state));
    let invitation_response = invitation_client
        .list_invitations(ListInvitationsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();

    let invitations = invitation_response
        .invitations
        .into_iter()
        .filter_map(invitation_row)
        .collect();

    Ok((members, invitations))
}

fn invitation_row(invitation: OrgInvitation) -> Option<InvitationRow> {
    if invitation.status.to_i32() != InvitationStatus::Pending as i32 {
        return None;
    }
    Some(InvitationRow {
        id: invitation.id,
        email: invitation.email,
        inviter_name: invitation
            .inviter_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "a team administrator".to_owned()),
        role: role_name(invitation.role.to_i32()),
        expires: invitation
            .expires_at
            .into_option()
            .map(|timestamp| future_time(timestamp.seconds))
            .unwrap_or_else(|| "soon".to_owned()),
    })
}

pub(crate) async fn create_invitation(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    email: String,
    role: OrgRole,
    assignments: Vec<String>,
) -> Result<CreatedInvitation, ConnectError> {
    let response = OrganizationServiceClient::new(transport(state, cookie), client_config(state))
        .create_invitation(CreateInvitationRequest {
            org_id,
            email,
            role: role.into(),
            assignments,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(CreatedInvitation {
        token: response.token,
    })
}

pub(crate) async fn update_member_role(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    user_id: String,
    role: OrgRole,
) -> Result<(), ConnectError> {
    OrganizationServiceClient::new(transport(state, cookie), client_config(state))
        .update_member_role(UpdateMemberRoleRequest {
            org_id,
            user_id,
            role: role.into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_member_assignments(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    member_id: String,
    assignments: Vec<String>,
) -> Result<(), ConnectError> {
    OrganizationServiceClient::new(transport(state, cookie), client_config(state))
        .update_member_assignments(UpdateMemberAssignmentsRequest {
            org_id,
            member_id,
            assignments,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn remove_member(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    user_id: String,
) -> Result<(), ConnectError> {
    OrganizationServiceClient::new(transport(state, cookie), client_config(state))
        .remove_member(RemoveMemberRequest {
            org_id,
            user_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn revoke_invitation(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    invitation_id: String,
) -> Result<(), ConnectError> {
    OrganizationServiceClient::new(transport(state, cookie), client_config(state))
        .revoke_invitation(RevokeInvitationRequest {
            org_id,
            invitation_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn api_keys(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<Vec<ApiKeyRow>, ConnectError> {
    let response = ApiKeyServiceClient::new(transport(state, cookie), client_config(state))
        .list_api_keys(ListApiKeysRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let now = unix_now();
    Ok(response
        .api_keys
        .into_iter()
        .map(|key| {
            let disabled = key.disabled_at.is_set();
            let expired = key
                .expires_at
                .into_option()
                .is_some_and(|timestamp| timestamp.seconds < now);
            let (status, status_tone) = if disabled {
                ("Disabled", "warning")
            } else if expired {
                ("Expired", "danger")
            } else {
                ("Active", "success")
            };
            let created_by = if !key.created_by_name.trim().is_empty() {
                key.created_by_name
            } else if !key.created_by_email.trim().is_empty() {
                key.created_by_email
            } else {
                "—".to_owned()
            };
            ApiKeyRow {
                id: key.id,
                name: key.name,
                prefix: format!("cw_{}…", key.key_prefix),
                created_by,
                created: key
                    .created_at
                    .into_option()
                    .map(|timestamp| past_time(timestamp.seconds))
                    .unwrap_or_else(|| "—".to_owned()),
                last_used: key
                    .last_used_at
                    .into_option()
                    .map(|timestamp| past_time(timestamp.seconds))
                    .unwrap_or_else(|| "Never".to_owned()),
                status,
                status_tone,
                disabled,
                expired,
            }
        })
        .collect())
}

pub(crate) async fn create_api_key(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    name: String,
    expires_in_days: Option<i32>,
) -> Result<String, ConnectError> {
    let response = ApiKeyServiceClient::new(transport(state, cookie), client_config(state))
        .create_api_key(CreateApiKeyRequest {
            org_id,
            name,
            scopes: Vec::new(),
            expires_in_days,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response.key)
}

pub(crate) async fn update_api_key(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    key_id: String,
    disabled: bool,
) -> Result<(), ConnectError> {
    ApiKeyServiceClient::new(transport(state, cookie), client_config(state))
        .update_api_key(UpdateApiKeyRequest {
            org_id,
            key_id,
            disabled: Some(disabled),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn delete_api_key(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    key_id: String,
) -> Result<(), ConnectError> {
    ApiKeyServiceClient::new(transport(state, cookie), client_config(state))
        .delete_api_key(DeleteApiKeyRequest {
            org_id,
            key_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn role_name(value: i32) -> &'static str {
    match value {
        1 => "Owner",
        2 => "Admin",
        3 => "Member",
        _ => "Member",
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

pub(crate) fn past_time(seconds: i64) -> String {
    let elapsed = unix_now().saturating_sub(seconds);
    if elapsed < 60 {
        "just now".to_owned()
    } else if elapsed < 3_600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("{}h ago", elapsed / 3_600)
    } else {
        format!("{}d ago", elapsed / 86_400)
    }
}

fn future_time(seconds: i64) -> String {
    let remaining = seconds.saturating_sub(unix_now());
    if remaining <= 0 {
        "now".to_owned()
    } else if remaining < 86_400 {
        "in less than a day".to_owned()
    } else {
        format!("in {} days", (remaining + 86_399) / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_labels_are_bounded_and_human_readable() {
        let now = unix_now();
        assert_eq!(past_time(now), "just now");
        assert_eq!(past_time(now - 7_200), "2h ago");
        assert_eq!(future_time(now + 172_800), "in 2 days");
    }

    #[test]
    fn invitation_mapping_contains_only_display_metadata() {
        let row = invitation_row(OrgInvitation {
            id: "invitation-1".into(),
            email: "member@example.test".into(),
            role: OrgRole::Member.into(),
            status: InvitationStatus::Pending.into(),
            ..Default::default()
        })
        .expect("pending invitation");
        let diagnostic = format!("{row:?}");
        assert!(diagnostic.contains("member@example.test"));
    }

    #[test]
    fn created_invitation_debug_redacts_one_time_token() {
        let created = CreatedInvitation {
            token: "synthetic-invitation-capability-marker".into(),
        };
        let diagnostic = format!("{created:?}");
        assert!(!diagnostic.contains("synthetic-invitation-capability-marker"));
        assert!(diagnostic.contains("[REDACTED]"));
    }
}
