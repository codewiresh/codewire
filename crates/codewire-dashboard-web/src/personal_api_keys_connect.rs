//! Current-user views over the existing organization-scoped API-key services.
//! Membership and mutation admission remain with the authenticated route owner;
//! this adapter validates complete service metadata before filtering by actor.

use std::{collections::HashSet, fmt, time::Duration};

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    ApiKey, ApiKeyServiceClient, CreateApiKeyRequest, CreateApiKeyResponse, DeleteApiKeyRequest,
    ListApiKeysRequest, ListApiKeysResponse, ListOrganizationsRequest, ListOrganizationsResponse,
    OrganizationServiceClient, UpdateApiKeyRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    account_sessions::valid_id, state::AppState, transport::BrowserTransport, view::OrganizationRow,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ORGANIZATIONS: usize = 256;
const MAX_API_KEYS: usize = 2000;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_SCOPES: usize = 64;
const MAX_SCOPE_BYTES: usize = 128;
const MAX_EXPIRES_IN_DAYS: i32 = 3650;

/// Request-scoped, one-time material. Never serialize, clone, or store this in
/// an inventory view; an optional post-create list failure must not replace it.
pub(crate) struct CreatedPersonalApiKey {
    pub(crate) metadata: ApiKey,
    pub(crate) key: String,
}

impl fmt::Debug for CreatedPersonalApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedPersonalApiKey")
            .field("metadata", &self.metadata)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone())
        .with_default_timeout(REQUEST_TIMEOUT)
        .with_default_max_message_size(MAX_RESPONSE_BYTES)
}

fn key_client(state: &AppState, cookie: HeaderValue) -> ApiKeyServiceClient<BrowserTransport> {
    ApiKeyServiceClient::new(transport(state, cookie), config(state))
}

fn invalid_request() -> ConnectError {
    ConnectError::invalid_argument("Invalid personal API-key request")
}

fn invalid_metadata() -> ConnectError {
    // Never retain a response body, key, provider text, or malformed identifier.
    ConnectError::unavailable("Personal API-key metadata could not be confirmed")
}

fn validate_actor(org_id: &str, user_id: &str) -> Result<(), ConnectError> {
    if !valid_id(org_id) || !valid_id(user_id) {
        return Err(invalid_request());
    }
    Ok(())
}

pub(crate) async fn organizations(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<OrganizationRow>, ConnectError> {
    let response = OrganizationServiceClient::new(transport(state, cookie), config(state))
        .list_organizations(ListOrganizationsRequest::default())
        .await?
        .into_owned();
    organization_rows(response)
}

fn organization_rows(
    response: ListOrganizationsResponse,
) -> Result<Vec<OrganizationRow>, ConnectError> {
    if response.organizations.len() > MAX_ORGANIZATIONS || !response.next_page_token.is_empty() {
        return Err(invalid_metadata());
    }
    let mut ids = HashSet::new();
    let mut slugs = HashSet::new();
    let mut rows = Vec::with_capacity(response.organizations.len());
    for membership in response.organizations {
        let organization = membership
            .organization
            .into_option()
            .ok_or_else(invalid_metadata)?;
        let role = match membership.role.to_i32() {
            1 => "Owner",
            2 => "Admin",
            3 => "Member",
            _ => return Err(invalid_metadata()),
        };
        if !valid_id(&organization.id)
            || (!organization.created_by.is_empty() && !valid_id(&organization.created_by))
            || !crate::view::valid_organization_slug(&organization.slug)
            || organization.name.trim().is_empty()
            || organization.name.len() > MAX_TEXT_BYTES
            || membership.billing_plan.len() > MAX_TEXT_BYTES
            || membership.assignments.len() > MAX_SCOPES
            || membership.assignments.iter().any(|assignment| {
                assignment.is_empty()
                    || assignment.len() > MAX_SCOPE_BYTES
                    || assignment.chars().any(char::is_control)
            })
            || !ids.insert(organization.id.clone())
            || !slugs.insert(organization.slug.clone())
        {
            return Err(invalid_metadata());
        }
        rows.push(OrganizationRow {
            id: organization.id,
            name: organization.name,
            url: format!("/{}/", organization.slug),
            slug: organization.slug,
            role,
            can_admin: matches!(role, "Owner" | "Admin")
                || membership
                    .assignments
                    .iter()
                    .any(|assignment| assignment == "super_admin"),
            billing_plan: membership.billing_plan,
        });
    }
    Ok(rows)
}

pub(crate) async fn list_for_user(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    user_id: &str,
) -> Result<Vec<ApiKey>, ConnectError> {
    validate_actor(org_id, user_id)?;
    // This RPC ignores page_size and requires an empty server page token.
    let response = key_client(state, cookie)
        .list_api_keys(ListApiKeysRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    owned_keys(response, org_id, user_id)
}

fn owned_keys(
    response: ListApiKeysResponse,
    org_id: &str,
    user_id: &str,
) -> Result<Vec<ApiKey>, ConnectError> {
    validate_actor(org_id, user_id)?;
    if response.api_keys.len() > MAX_API_KEYS || !response.next_page_token.is_empty() {
        return Err(invalid_metadata());
    }
    let mut ids = HashSet::new();
    // Validate every row, including other actors, before exposing any subset.
    for row in &response.api_keys {
        validate_key_metadata(row, org_id)?;
        if !ids.insert(row.id.as_str()) {
            return Err(invalid_metadata());
        }
    }
    Ok(response
        .api_keys
        .into_iter()
        .filter(|row| row.user_id == user_id)
        .collect())
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() == 8
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_key_metadata(row: &ApiKey, org_id: &str) -> Result<(), ConnectError> {
    if !valid_id(&row.id)
        || !valid_id(&row.user_id)
        || !valid_id(&row.org_id)
        || row.org_id != org_id
        || row.name.trim().is_empty()
        || row.name.len() > MAX_TEXT_BYTES
        || !valid_prefix(&row.key_prefix)
        || row.scopes.len() > MAX_SCOPES
        || row
            .scopes
            .iter()
            .any(|scope| scope.len() > MAX_SCOPE_BYTES || scope.chars().any(char::is_control))
        || row.created_by_name.len() > MAX_TEXT_BYTES
        || row.created_by_email.len() > MAX_TEXT_BYTES
        || row.created_at.as_option().is_none()
        || [
            row.created_at.as_option(),
            row.last_used_at.as_option(),
            row.expires_at.as_option(),
            row.disabled_at.as_option(),
        ]
        .into_iter()
        .flatten()
        .any(|timestamp| {
            !(-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
                || !(0..=999_999_999).contains(&timestamp.nanos)
        })
    {
        return Err(invalid_metadata());
    }
    Ok(())
}

pub(crate) async fn create_for_user(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    user_id: &str,
    name: &str,
    expires_in_days: Option<i32>,
) -> Result<CreatedPersonalApiKey, ConnectError> {
    validate_actor(org_id, user_id)?;
    let name = name.trim();
    if name.is_empty()
        || name.len() > MAX_TEXT_BYTES
        || !expires_in_days.is_none_or(|days| (1..=MAX_EXPIRES_IN_DAYS).contains(&days))
    {
        return Err(invalid_request());
    }
    let response = key_client(state, cookie)
        .create_api_key(CreateApiKeyRequest {
            org_id: org_id.to_owned(),
            name: name.to_owned(),
            expires_in_days,
            ..Default::default()
        })
        .await?
        .into_owned();
    created_key(response, org_id, user_id, name, expires_in_days)
}

fn created_key(
    response: CreateApiKeyResponse,
    org_id: &str,
    user_id: &str,
    name: &str,
    expires_in_days: Option<i32>,
) -> Result<CreatedPersonalApiKey, ConnectError> {
    let metadata = response
        .api_key
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_key_metadata(&metadata, org_id)?;
    let raw_suffix = response
        .key
        .strip_prefix("cw_")
        .ok_or_else(invalid_metadata)?;
    if metadata.user_id != user_id
        || metadata.name != name
        || metadata.disabled_at.as_option().is_some()
        || metadata.last_used_at.as_option().is_some()
        || metadata.expires_at.as_option().is_some() != expires_in_days.is_some()
        || !metadata.scopes.is_empty()
        || raw_suffix.len() != 64
        || !raw_suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !raw_suffix.starts_with(&metadata.key_prefix)
    {
        return Err(invalid_metadata());
    }
    Ok(CreatedPersonalApiKey {
        metadata,
        key: response.key,
    })
}

pub(crate) async fn update_for_user(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    user_id: &str,
    key_id: &str,
    disabled: bool,
) -> Result<(), ConnectError> {
    validate_actor(org_id, user_id)?;
    if !valid_id(key_id) {
        return Err(invalid_request());
    }
    let response = key_client(state, cookie)
        .update_api_key(UpdateApiKeyRequest {
            org_id: org_id.to_owned(),
            key_id: key_id.to_owned(),
            disabled: Some(disabled),
            ..Default::default()
        })
        .await?
        .into_owned();
    let metadata = response
        .api_key
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_update(&metadata, org_id, user_id, key_id, disabled)
}

fn validate_update(
    metadata: &ApiKey,
    org_id: &str,
    user_id: &str,
    key_id: &str,
    disabled: bool,
) -> Result<(), ConnectError> {
    validate_key_metadata(metadata, org_id)?;
    if metadata.id != key_id
        || metadata.user_id != user_id
        || metadata.disabled_at.as_option().is_some() != disabled
    {
        return Err(invalid_metadata());
    }
    Ok(())
}

pub(crate) async fn delete(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    key_id: &str,
) -> Result<(), ConnectError> {
    if !valid_id(org_id) || !valid_id(key_id) {
        return Err(invalid_request());
    }
    key_client(state, cookie)
        .delete_api_key(DeleteApiKeyRequest {
            org_id: org_id.to_owned(),
            key_id: key_id.to_owned(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::v1::{OrgRole, Organization, OrganizationMembership};

    fn key() -> ApiKey {
        ApiKey {
            id: "key_opaque-1".into(),
            user_id: "actor_opaque-1".into(),
            org_id: "org_opaque-1".into(),
            name: "Personal key".into(),
            key_prefix: "01234567".into(),
            created_at: Some(Default::default()).into(),
            created_by_name: "Verified owner".into(),
            created_by_email: "owner@example.test".into(),
            ..Default::default()
        }
    }

    fn membership() -> OrganizationMembership {
        OrganizationMembership {
            organization: Some(Organization {
                id: "org_opaque-1".into(),
                slug: "example-org".into(),
                name: "Example organization".into(),
                created_by: "actor_opaque-1".into(),
                ..Default::default()
            })
            .into(),
            role: OrgRole::Member.into(),
            billing_plan: "free".into(),
            ..Default::default()
        }
    }

    fn list(keys: Vec<ApiKey>) -> ListApiKeysResponse {
        ListApiKeysResponse {
            api_keys: keys,
            ..Default::default()
        }
    }
    fn orgs(rows: Vec<OrganizationMembership>) -> ListOrganizationsResponse {
        ListOrganizationsResponse {
            organizations: rows,
            ..Default::default()
        }
    }
    fn created() -> CreateApiKeyResponse {
        CreateApiKeyResponse {
            api_key: Some(key()).into(),
            key: format!("cw_01234567{}", "a".repeat(56)),
            ..Default::default()
        }
    }

    #[test]
    fn complete_metadata_is_preserved_but_other_actor_rows_are_not_returned() {
        let mut other = key();
        other.id = "key_other".into();
        other.user_id = "actor_other".into();
        let mut own = key();
        own.scopes = vec!["stored-label-not-an-enforced-permission".into()];
        let rows = owned_keys(
            list(vec![other, own.clone()]),
            "org_opaque-1",
            "actor_opaque-1",
        )
        .unwrap();
        assert_eq!(rows, vec![own]);
        assert!(validate_actor("legacy_org-opaque", "legacy_actor-opaque").is_ok());
        for invalid in ["", "actor/other", "actor\nother", &"a".repeat(129)] {
            assert!(validate_actor("org_opaque-1", invalid).is_err());
        }
    }

    #[test]
    fn malformed_other_actor_metadata_and_duplicate_ids_fail_before_filtering() {
        let mut other = key();
        other.user_id = "actor_other".into();
        assert!(
            owned_keys(
                list(vec![key(), other.clone()]),
                "org_opaque-1",
                "actor_opaque-1"
            )
            .is_err()
        );
        other.id = "key_other".into();
        other.org_id = "org_other".into();
        assert!(owned_keys(list(vec![other]), "org_opaque-1", "actor_opaque-1").is_err());
        for field in ["id", "user", "org", "prefix", "created"] {
            let mut malformed = key();
            match field {
                "id" => malformed.id = "bad/id".into(),
                "user" => malformed.user_id.clear(),
                "org" => malformed.org_id.clear(),
                "prefix" => malformed.key_prefix = "0123456G".into(),
                _ => malformed.created_at = None.into(),
            }
            assert!(owned_keys(list(vec![malformed]), "org_opaque-1", "actor_opaque-1").is_err());
        }
    }

    #[test]
    fn complete_key_inventory_rejects_pagination_and_applies_the_explicit_cap() {
        let mut paginated = list(vec![key()]);
        paginated.next_page_token = "unexpected".into();
        assert!(owned_keys(paginated, "org_opaque-1", "actor_opaque-1").is_err());
        let rows = (0..=MAX_API_KEYS)
            .map(|index| {
                let mut row = key();
                row.id = format!("key_{index}");
                row
            })
            .collect::<Vec<_>>();
        assert!(owned_keys(list(rows.clone()), "org_opaque-1", "actor_opaque-1").is_err());
        assert_eq!(
            owned_keys(
                list(rows[..MAX_API_KEYS].to_vec()),
                "org_opaque-1",
                "actor_opaque-1"
            )
            .unwrap()
            .len(),
            MAX_API_KEYS
        );
    }

    #[test]
    fn organization_roles_and_assignments_preserve_the_existing_admin_contract() {
        for (role, assignments, expected) in [
            (OrgRole::Member, vec![], false),
            (OrgRole::Owner, vec![], true),
            (OrgRole::Admin, vec![], true),
            (OrgRole::Member, vec!["super_admin".into()], true),
            (OrgRole::Member, vec!["super_admin_other".into()], false),
        ] {
            let mut member = membership();
            member.role = role.into();
            member.assignments = assignments;
            let rows = organization_rows(orgs(vec![member])).unwrap();
            assert_eq!(rows[0].can_admin, expected);
            assert_eq!(rows[0].id, "org_opaque-1");
            assert_eq!(rows[0].url, "/example-org/");
            assert_eq!(rows[0].billing_plan, "free");
        }
    }

    #[test]
    fn organization_inventory_rejects_malformed_duplicate_or_partial_memberships() {
        assert!(organization_rows(orgs(vec![membership(), membership()])).is_err());
        let mut same_slug = membership();
        same_slug.organization.as_option_mut().unwrap().id = "org_other".into();
        assert!(organization_rows(orgs(vec![membership(), same_slug])).is_err());
        let mut paginated = orgs(vec![membership()]);
        paginated.next_page_token = "unexpected".into();
        assert!(organization_rows(paginated).is_err());
        for field in ["missing", "role", "id", "creator", "slug"] {
            let mut malformed = membership();
            match field {
                "missing" => malformed.organization = None.into(),
                "role" => malformed.role = OrgRole::Unspecified.into(),
                "id" => malformed.organization.as_option_mut().unwrap().id.clear(),
                "creator" => {
                    malformed.organization.as_option_mut().unwrap().created_by = "bad/actor".into()
                }
                _ => malformed.organization.as_option_mut().unwrap().slug = "settings".into(),
            }
            assert!(organization_rows(orgs(vec![malformed])).is_err());
        }
        let rows = (0..=MAX_ORGANIZATIONS)
            .map(|index| {
                let mut row = membership();
                let org = row.organization.as_option_mut().unwrap();
                org.id = format!("org_{index}");
                org.slug = format!("org-{index}");
                row
            })
            .collect::<Vec<_>>();
        assert!(organization_rows(orgs(rows.clone())).is_err());
        assert_eq!(
            organization_rows(orgs(rows[..MAX_ORGANIZATIONS].to_vec()))
                .unwrap()
                .len(),
            MAX_ORGANIZATIONS
        );
    }

    #[test]
    fn one_time_creation_validates_actor_org_name_format_and_public_prefix() {
        let valid = created_key(
            created(),
            "org_opaque-1",
            "actor_opaque-1",
            "Personal key",
            None,
        )
        .unwrap();
        assert_eq!(valid.metadata, key());
        assert_eq!(valid.key.len(), 67);
        for field in [
            "missing",
            "actor",
            "org",
            "name",
            "format",
            "uppercase",
            "prefix",
            "expiry",
            "disabled",
            "scopes",
        ] {
            let mut response = created();
            match field {
                "missing" => response.api_key = None.into(),
                "actor" => response.api_key.as_option_mut().unwrap().user_id = "actor_other".into(),
                "org" => response.api_key.as_option_mut().unwrap().org_id = "org_other".into(),
                "name" => response.api_key.as_option_mut().unwrap().name = "Different key".into(),
                "format" => response.key = "cw_short".into(),
                "uppercase" => response.key = format!("cw_{}", "A".repeat(64)),
                "prefix" => {
                    response.api_key.as_option_mut().unwrap().key_prefix = "abcdefab".into()
                }
                "expiry" => {
                    response.api_key.as_option_mut().unwrap().expires_at =
                        Some(Default::default()).into()
                }
                "disabled" => {
                    response.api_key.as_option_mut().unwrap().disabled_at =
                        Some(Default::default()).into()
                }
                _ => response.api_key.as_option_mut().unwrap().scopes = vec!["unexpected".into()],
            }
            assert!(
                created_key(
                    response,
                    "org_opaque-1",
                    "actor_opaque-1",
                    "Personal key",
                    None
                )
                .is_err()
            );
        }
    }

    #[test]
    fn update_acknowledgment_must_match_owned_key_and_requested_disabled_state() {
        let mut disabled = key();
        disabled.disabled_at = Some(Default::default()).into();
        assert!(
            validate_update(
                &disabled,
                "org_opaque-1",
                "actor_opaque-1",
                "key_opaque-1",
                true
            )
            .is_ok()
        );
        assert!(
            validate_update(
                &key(),
                "org_opaque-1",
                "actor_opaque-1",
                "key_opaque-1",
                false
            )
            .is_ok()
        );
        for (org, actor, id, requested_disabled) in [
            ("org_other", "actor_opaque-1", "key_opaque-1", true),
            ("org_opaque-1", "actor_other", "key_opaque-1", true),
            ("org_opaque-1", "actor_opaque-1", "key_other", true),
            ("org_opaque-1", "actor_opaque-1", "key_opaque-1", false),
        ] {
            assert!(validate_update(&disabled, org, actor, id, requested_disabled).is_err());
        }
    }

    #[test]
    fn raw_creation_material_is_redacted_from_debug_and_validation_errors() {
        let created = created_key(
            created(),
            "org_opaque-1",
            "actor_opaque-1",
            "Personal key",
            None,
        )
        .unwrap();
        let rendered = format!("{created:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&created.key));
        let malformed = CreateApiKeyResponse {
            key: created.key,
            ..Default::default()
        };
        let error = created_key(
            malformed,
            "org_opaque-1",
            "actor_opaque-1",
            "Personal key",
            None,
        )
        .unwrap_err();
        assert!(!format!("{error:?}").contains("cw_"));
    }
}
