//! Transport-independent Mesh product operations.
//!
//! Transitional REST adapters and generated Connect handlers both resolve the
//! caller through this service and invoke these operations. Capability inputs
//! are reduced to digests before store access and never enter response or
//! error values.

use chrono::{Duration, Utc};
use codewire_proto::codewire::internal::v1::MeshAuthorizationContext;
use codewire_server_core::{AppError, AppResult};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::mesh_authorization::{
    ForwardedMeshCredential, MeshAuthorizationAdapter, MeshAuthorizationAdapterError,
    is_network_product_principal,
};
use crate::store::{
    GROUP_DEBUG_FULL, GROUP_DEBUG_NONE, GROUP_DEBUG_OBSERVE_ONLY, GROUP_MESSAGES_INTERNAL_ONLY,
    GROUP_MESSAGES_OPEN, Group, GroupMember, GroupPolicy, Invite, KVEntry, NETWORK_ROLE_MEMBER,
    NETWORK_ROLE_OWNER, Network, NodeEnrollment, NodeRecord, SharedStore, StoreError,
};

const INVITE_CODE_PREFIX: &str = "cw_inv_";
const INVITE_CODE_BYTES: usize = 32;

#[derive(Clone)]
pub(crate) struct MeshProductService {
    store: SharedStore,
    authorization: Option<MeshAuthorizationAdapter>,
}

pub(crate) struct CreatedInvite {
    pub invite: Invite,
    pub invite_code: String,
}

pub(crate) struct CreatedNodeEnrollment {
    pub enrollment: NodeEnrollment,
    pub enrollment_code: String,
}

pub(crate) struct RedeemedNodeEnrollment {
    pub organization_id: String,
    pub node: NodeRecord,
    pub enrollment: NodeEnrollment,
}

pub(crate) struct KeyValueWrite<'a> {
    pub organization_id: &'a str,
    pub network_id: &'a str,
    pub namespace: &'a str,
    pub key: &'a str,
    pub value: Vec<u8>,
    pub ttl: Option<Duration>,
}

#[derive(Clone)]
pub(crate) struct GroupView {
    pub group: Group,
    pub members: Vec<GroupMember>,
    pub policy: Option<GroupPolicy>,
}

#[derive(Clone, Copy)]
pub(crate) enum RequiredRole {
    Member,
    Owner,
}

impl MeshProductService {
    pub(crate) fn new(store: SharedStore, authorization: Option<MeshAuthorizationAdapter>) -> Self {
        Self {
            store,
            authorization,
        }
    }

    pub(crate) async fn authorize_org(
        &self,
        organization_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<MeshAuthorizationContext> {
        let organization_id = required_identifier(organization_id, "org_id")?;
        let adapter = self.authorization.as_ref().ok_or_else(|| {
            AppError::ServiceUnavailable("Mesh authorization is unavailable".into())
        })?;
        let context = adapter
            .resolve(&organization_id, credential)
            .await
            .map_err(authorization_error)?;
        if context.org_id != organization_id || !is_network_product_principal(&context) {
            return Err(AppError::Forbidden);
        }
        Ok(context)
    }

    pub(crate) async fn authorize_network(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
        required_role: RequiredRole,
    ) -> AppResult<MeshAuthorizationContext> {
        let network_id = validate_network_id(network_id)?;
        let context = self.authorize_org(organization_id, credential).await?;
        match self
            .store
            .network_organization_id(&network_id)
            .await
            .map_err(store_error)?
        {
            Some(owner_organization_id) if owner_organization_id == context.org_id => {}
            Some(_) => return Err(AppError::Forbidden),
            None => return Err(AppError::NotFound("Mesh network not found".into())),
        }
        let member = self
            .store
            .network_member_get(&network_id, &context.principal_id)
            .await
            .map_err(store_error)?
            .ok_or(AppError::Forbidden)?;
        let allowed = match required_role {
            RequiredRole::Member => {
                matches!(
                    member.role.as_str(),
                    NETWORK_ROLE_MEMBER | NETWORK_ROLE_OWNER
                )
            }
            RequiredRole::Owner => member.role == NETWORK_ROLE_OWNER,
        };
        if !allowed {
            return Err(AppError::Forbidden);
        }
        Ok(context)
    }

    pub(crate) async fn authorize_coordinate(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<MeshAuthorizationContext> {
        self.authorize_network(
            organization_id,
            network_id,
            credential,
            RequiredRole::Member,
        )
        .await
    }

    pub(crate) async fn organization_for_network(&self, network_id: &str) -> AppResult<String> {
        let network_id = validate_network_id(network_id)?;
        self.store
            .network_organization_id(&network_id)
            .await
            .map_err(store_error)?
            .ok_or_else(|| AppError::NotFound("Mesh network not found".into()))
    }

    pub(crate) async fn list_networks(
        &self,
        organization_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Vec<Network>> {
        let context = self.authorize_org(organization_id, credential).await?;
        self.store
            .network_list_by_member(&context.org_id, &context.principal_id)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn create_network(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Network> {
        let network_id = validate_network_id(network_id)?;
        let context = self.authorize_org(organization_id, credential).await?;
        let now = Utc::now();
        self.store
            .network_create_with_owner(&network_id, &context.org_id, &context.principal_id, now)
            .await
            .map_err(store_error)?;
        self.network_for_org(&context.org_id, &network_id).await
    }

    pub(crate) async fn list_invites(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Vec<Invite>> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        self.store
            .invite_list(network_id)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn create_invite(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
        ttl: Duration,
    ) -> AppResult<CreatedInvite> {
        if ttl <= Duration::zero() {
            return Err(AppError::BadRequest("ttl must be positive".into()));
        }
        let context = self
            .authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let invite_code = generate_invite_code();
        let now = Utc::now();
        let invite = Invite {
            id: uuid::Uuid::new_v4().simple().to_string(),
            network_id: network_id.to_owned(),
            organization_id: context.org_id,
            created_by_user_id: context.principal_id,
            code_hash: hash_invite_code(&invite_code),
            expires_at: now + ttl,
            created_at: now,
        };
        self.store
            .invite_create(invite.clone())
            .await
            .map_err(store_error)?;
        Ok(CreatedInvite {
            invite,
            invite_code,
        })
    }

    pub(crate) async fn delete_invite(
        &self,
        organization_id: &str,
        network_id: &str,
        invite_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<()> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let invite_id = required_identifier(invite_id, "invite_id")?;
        self.store
            .invite_delete(network_id, &invite_id)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn join_network(
        &self,
        invite_code: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Network> {
        let invite_code = required_identifier(invite_code, "invite_code")?;
        let code_hash = hash_invite_code(&invite_code);
        let now = Utc::now();
        let invitation = self
            .store
            .invite_get_by_code_hash(&code_hash, now)
            .await
            .map_err(store_error)?
            .ok_or(AppError::Forbidden)?;
        let principal = self
            .authorize_org(&invitation.organization_id, credential)
            .await?;
        let invitation = self
            .store
            .invite_consume_and_join(&code_hash, now, &principal.org_id, &principal.principal_id)
            .await
            .map_err(store_error)?
            .ok_or(AppError::Forbidden)?;
        if invitation.organization_id != principal.org_id {
            return Err(AppError::Forbidden);
        }
        self.network_for_org(&invitation.organization_id, &invitation.network_id)
            .await
    }

    pub(crate) async fn list_nodes(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Vec<NodeRecord>> {
        self.authorize_network(
            organization_id,
            network_id,
            credential,
            RequiredRole::Member,
        )
        .await?;
        self.store.node_list(network_id).await.map_err(store_error)
    }

    pub(crate) async fn revoke_node(
        &self,
        organization_id: &str,
        network_id: &str,
        node_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<()> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let node_name = required_identifier(node_name, "node_name")?;
        if self
            .store
            .node_get(network_id, &node_name)
            .await
            .map_err(store_error)?
            .is_none()
        {
            return Err(AppError::NotFound("Mesh node not found".into()));
        }
        self.store
            .node_delete(network_id, &node_name)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn create_node_enrollment(
        &self,
        organization_id: &str,
        network_id: &str,
        node_name: &str,
        credential: ForwardedMeshCredential,
        ttl: Duration,
    ) -> AppResult<CreatedNodeEnrollment> {
        if ttl <= Duration::zero() {
            return Err(AppError::BadRequest("ttl must be positive".into()));
        }
        let principal = self
            .authorize_network(
                organization_id,
                network_id,
                credential,
                RequiredRole::Member,
            )
            .await?;
        let enrollment_code = format!("cw_enr_{}", random_hex(32));
        let now = Utc::now();
        let enrollment = NodeEnrollment {
            id: random_hex(32),
            network_id: network_id.to_owned(),
            owner_subject: principal.principal_id.clone(),
            issued_by: principal.principal_id,
            node_name: node_name.trim().to_owned(),
            token_hash: hash_capability(&enrollment_code),
            uses_remaining: 1,
            expires_at: now + ttl,
            created_at: now,
            redeemed_at: None,
        };
        self.store
            .node_enrollment_create(enrollment.clone())
            .await
            .map_err(store_error)?;
        Ok(CreatedNodeEnrollment {
            enrollment,
            enrollment_code,
        })
    }

    pub(crate) async fn redeem_node_enrollment(
        &self,
        enrollment_code: &str,
        requested_node_name: &str,
        peer_url: &str,
    ) -> AppResult<RedeemedNodeEnrollment> {
        self.redeem_node_enrollment_scoped(
            enrollment_code,
            requested_node_name,
            peer_url,
            None,
            false,
        )
        .await
    }

    /// Consume one fixed-name enrollment directly as setup authority for one
    /// exact peer coordinate stream. The capability is resolved by Mesh and
    /// never forwarded to the platform authorization adapter.
    pub(crate) async fn redeem_coordinate_enrollment(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: &ForwardedMeshCredential,
    ) -> AppResult<RedeemedNodeEnrollment> {
        let enrollment_code = credential
            .node_enrollment_code()
            .ok_or(AppError::Unauthorized)?;
        self.redeem_node_enrollment_scoped(
            enrollment_code,
            "",
            "",
            Some((organization_id, network_id)),
            true,
        )
        .await
    }

    async fn redeem_node_enrollment_scoped(
        &self,
        enrollment_code: &str,
        requested_node_name: &str,
        peer_url: &str,
        expected_scope: Option<(&str, &str)>,
        require_fixed_name: bool,
    ) -> AppResult<RedeemedNodeEnrollment> {
        let enrollment_code = required_identifier(enrollment_code, "enrollment_code")?;
        let token_hash = hash_capability(&enrollment_code);
        let now = Utc::now();
        let enrollment = self
            .store
            .node_enrollment_get_by_token_hash(&token_hash)
            .await
            .map_err(store_error)?
            .ok_or(AppError::Forbidden)?;
        if enrollment.expires_at <= now || enrollment.uses_remaining <= 0 {
            return Err(AppError::Forbidden);
        }

        let expected_scope = expected_scope
            .map(|(organization_id, network_id)| -> AppResult<_> {
                Ok((
                    required_identifier(organization_id, "org_id")?,
                    validate_network_id(network_id)?,
                ))
            })
            .transpose()?;
        if expected_scope
            .as_ref()
            .is_some_and(|(_, network_id)| enrollment.network_id != network_id.as_str())
        {
            return Err(AppError::Forbidden);
        }

        if require_fixed_name && enrollment.node_name.trim().is_empty() {
            return Err(AppError::Forbidden);
        }
        let node_name = match (enrollment.node_name.trim(), requested_node_name.trim()) {
            (fixed, "") if !fixed.is_empty() => fixed.to_owned(),
            (fixed, requested) if !fixed.is_empty() && fixed != requested => {
                return Err(AppError::Forbidden);
            }
            (_, "") => return Err(AppError::BadRequest("node_name is required".into())),
            (_, requested) => requested.to_owned(),
        };
        let organization_id = self
            .organization_for_network(&enrollment.network_id)
            .await?;
        if expected_scope
            .as_ref()
            .is_some_and(|(expected, _)| organization_id != expected.as_str())
        {
            return Err(AppError::Forbidden);
        }
        let node = NodeRecord {
            network_id: enrollment.network_id.clone(),
            name: node_name,
            peer_url: peer_url.trim().to_owned(),
            github_id: None,
            owner_subject: enrollment.owner_subject.clone(),
            authorized_by: enrollment.issued_by.clone(),
            enrollment_id: enrollment.id.clone(),
            authorized_at: now,
            last_seen_at: now,
        };
        let enrollment = self
            .store
            .node_enrollment_consume_and_register(&token_hash, now, node.clone())
            .await
            .map_err(store_error)?
            .ok_or(AppError::Forbidden)?;

        Ok(RedeemedNodeEnrollment {
            organization_id,
            node,
            enrollment,
        })
    }

    pub(crate) async fn list_groups(
        &self,
        organization_id: &str,
        network_id: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Vec<GroupView>> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let groups = self
            .store
            .group_list(network_id)
            .await
            .map_err(store_error)?;
        let mut views = Vec::with_capacity(groups.len());
        for group in groups {
            views.push(self.group_view(group, false).await?);
        }
        Ok(views)
    }

    pub(crate) async fn create_group(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<GroupView> {
        let principal = self
            .authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let group = Group {
            network_id: network_id.to_owned(),
            name: validate_group_name(group_name)?,
            created_at: Utc::now(),
            created_by: principal.principal_id,
        };
        self.store
            .group_create(group.clone())
            .await
            .map_err(store_error)?;
        self.group_view(group, true).await
    }

    pub(crate) async fn get_group(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<GroupView> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let group_name = validate_group_name(group_name)?;
        let group = self
            .store
            .group_get(network_id, &group_name)
            .await
            .map_err(store_error)?
            .ok_or_else(|| AppError::NotFound("Mesh group not found".into()))?;
        self.group_view(group, true).await
    }

    pub(crate) async fn delete_group(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<()> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let group_name = validate_group_name(group_name)?;
        self.store
            .group_delete(network_id, &group_name)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn set_group_policy(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        messages_policy: &str,
        debug_policy: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<GroupPolicy> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let policy = GroupPolicy {
            network_id: network_id.to_owned(),
            group_name: validate_group_name(group_name)?,
            messages_policy: normalize_group_messages_policy(messages_policy)?,
            debug_policy: normalize_group_debug_policy(debug_policy)?,
            updated_at: Utc::now(),
        };
        self.store
            .group_policy_set(policy.clone())
            .await
            .map_err(store_error)?;
        Ok(policy)
    }

    pub(crate) async fn add_group_member(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        node_name: &str,
        session_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<GroupMember> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        let member = GroupMember {
            network_id: network_id.to_owned(),
            group_name: validate_group_name(group_name)?,
            node_name: required_identifier(node_name, "node_name")?,
            session_name: required_identifier(session_name, "session_name")?,
            created_at: Utc::now(),
        };
        self.store
            .group_member_add(member.clone())
            .await
            .map_err(store_error)?;
        Ok(member)
    }

    pub(crate) async fn remove_group_member(
        &self,
        organization_id: &str,
        network_id: &str,
        group_name: &str,
        node_name: &str,
        session_name: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<()> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        self.store
            .group_member_remove(
                network_id,
                &validate_group_name(group_name)?,
                &required_identifier(node_name, "node_name")?,
                &required_identifier(session_name, "session_name")?,
            )
            .await
            .map_err(store_error)
    }

    pub(crate) async fn list_key_values(
        &self,
        organization_id: &str,
        network_id: &str,
        namespace: &str,
        prefix: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<Vec<KVEntry>> {
        self.authorize_network(
            organization_id,
            network_id,
            credential,
            RequiredRole::Member,
        )
        .await?;
        let namespace = required_identifier(namespace, "namespace")?;
        self.store
            .kv_list(network_id, &namespace, prefix)
            .await
            .map_err(store_error)
    }

    pub(crate) async fn get_key_value(
        &self,
        organization_id: &str,
        network_id: &str,
        namespace: &str,
        key: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<KVEntry> {
        self.authorize_network(
            organization_id,
            network_id,
            credential,
            RequiredRole::Member,
        )
        .await?;
        let namespace = required_identifier(namespace, "namespace")?;
        let key = required_identifier(key, "key")?;
        self.store
            .kv_get_entry(network_id, &namespace, &key)
            .await
            .map_err(store_error)?
            .ok_or_else(|| AppError::NotFound("Mesh key-value not found".into()))
    }

    pub(crate) async fn set_key_value(
        &self,
        write: KeyValueWrite<'_>,
        credential: ForwardedMeshCredential,
    ) -> AppResult<KVEntry> {
        self.authorize_network(
            write.organization_id,
            write.network_id,
            credential,
            RequiredRole::Member,
        )
        .await?;
        let namespace = required_identifier(write.namespace, "namespace")?;
        let key = required_identifier(write.key, "key")?;
        if write.ttl.is_some_and(|ttl| ttl <= Duration::zero()) {
            return Err(AppError::BadRequest("ttl must be positive".into()));
        }
        self.store
            .kv_set(write.network_id, &namespace, &key, write.value, write.ttl)
            .await
            .map_err(store_error)?;
        self.store
            .kv_get_entry(write.network_id, &namespace, &key)
            .await
            .map_err(store_error)?
            .ok_or_else(|| AppError::InternalMsg("Mesh key-value write was not visible".into()))
    }

    pub(crate) async fn delete_key_value(
        &self,
        organization_id: &str,
        network_id: &str,
        namespace: &str,
        key: &str,
        credential: ForwardedMeshCredential,
    ) -> AppResult<()> {
        self.authorize_network(organization_id, network_id, credential, RequiredRole::Owner)
            .await?;
        self.store
            .kv_delete(
                network_id,
                &required_identifier(namespace, "namespace")?,
                &required_identifier(key, "key")?,
            )
            .await
            .map_err(store_error)
    }

    pub(crate) async fn network_for_org(
        &self,
        organization_id: &str,
        network_id: &str,
    ) -> AppResult<Network> {
        self.store
            .network_list_by_organization(organization_id)
            .await
            .map_err(store_error)?
            .into_iter()
            .find(|network| network.id == network_id)
            .ok_or_else(|| AppError::NotFound("Mesh network not found".into()))
    }

    async fn group_view(&self, group: Group, include_members: bool) -> AppResult<GroupView> {
        let members = if include_members {
            self.store
                .group_member_list(&group.network_id, &group.name)
                .await
                .map_err(store_error)?
        } else {
            Vec::new()
        };
        let policy = self
            .store
            .group_policy_get(&group.network_id, &group.name)
            .await
            .map_err(store_error)?;
        Ok(GroupView {
            group,
            members,
            policy,
        })
    }
}

pub(crate) fn required_identifier(raw: &str, field: &'static str) -> AppResult<String> {
    let value = raw.trim();
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| AppError::BadRequest(format!("{field} is required").into()))
}

pub(crate) fn validate_network_id(raw: &str) -> AppResult<String> {
    let network_id = required_identifier(raw, "network_id")?;
    if network_id.chars().all(|ch| {
        ch.is_ascii_lowercase()
            || ch.is_ascii_uppercase()
            || ch.is_ascii_digit()
            || ch == '-'
            || ch == '_'
    }) {
        Ok(network_id)
    } else {
        Err(AppError::BadRequest(
            "network_id may only contain letters, numbers, '-' or '_'".into(),
        ))
    }
}

pub(crate) fn validate_group_name(raw: &str) -> AppResult<String> {
    let group_name = required_identifier(raw, "group_name")?;
    if group_name.chars().all(|ch| {
        ch.is_ascii_lowercase()
            || ch.is_ascii_uppercase()
            || ch.is_ascii_digit()
            || ch == '-'
            || ch == '_'
    }) {
        Ok(group_name)
    } else {
        Err(AppError::BadRequest(
            "group_name may only contain letters, numbers, '-' or '_'".into(),
        ))
    }
}

pub(crate) fn normalize_group_messages_policy(raw: &str) -> AppResult<String> {
    match raw.trim() {
        "" | GROUP_MESSAGES_INTERNAL_ONLY => Ok(GROUP_MESSAGES_INTERNAL_ONLY.to_owned()),
        GROUP_MESSAGES_OPEN => Ok(GROUP_MESSAGES_OPEN.to_owned()),
        _ => Err(AppError::BadRequest("invalid messages_policy".into())),
    }
}

pub(crate) fn normalize_group_debug_policy(raw: &str) -> AppResult<String> {
    match raw.trim() {
        "" | GROUP_DEBUG_OBSERVE_ONLY => Ok(GROUP_DEBUG_OBSERVE_ONLY.to_owned()),
        GROUP_DEBUG_NONE => Ok(GROUP_DEBUG_NONE.to_owned()),
        GROUP_DEBUG_FULL => Ok(GROUP_DEBUG_FULL.to_owned()),
        _ => Err(AppError::BadRequest("invalid debug_policy".into())),
    }
}

pub(crate) fn store_error(error: StoreError) -> AppError {
    match error {
        StoreError::NotFound => AppError::NotFound("Mesh resource not found".into()),
        StoreError::AlreadyExists => AppError::Conflict("Mesh resource already exists".into()),
        StoreError::Invalid(message) => AppError::BadRequest(message.into()),
        StoreError::Sqlx(error) => AppError::Internal(anyhow::Error::new(error)),
    }
}

fn authorization_error(error: MeshAuthorizationAdapterError) -> AppError {
    match error.status_code() {
        axum::http::StatusCode::UNAUTHORIZED => AppError::Unauthorized,
        axum::http::StatusCode::FORBIDDEN => AppError::Forbidden,
        axum::http::StatusCode::SERVICE_UNAVAILABLE => {
            AppError::ServiceUnavailable("Mesh authorization is unavailable".into())
        }
        _ => AppError::Upstream("Mesh authorization is unavailable".into()),
    }
}

fn generate_invite_code() -> String {
    let mut bytes = [0_u8; INVITE_CODE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{INVITE_CODE_PREFIX}{}", lower_hex(&bytes))
}

pub(crate) fn hash_invite_code(invite_code: &str) -> String {
    hash_capability(invite_code)
}

fn hash_capability(capability: &str) -> String {
    lower_hex(&Sha256::digest(capability.as_bytes()))
}

fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    lower_hex(&bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    value
}
