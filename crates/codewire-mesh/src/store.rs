use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use sqlx::migrate::Migrator;
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;

use crate::Config;

static MESH_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub const NETWORK_ROLE_OWNER: &str = "owner";
pub const NETWORK_ROLE_MEMBER: &str = "member";
pub const GROUP_MESSAGES_INTERNAL_ONLY: &str = "internal-only";
pub const GROUP_MESSAGES_OPEN: &str = "open";
pub const GROUP_DEBUG_NONE: &str = "none";
pub const GROUP_DEBUG_OBSERVE_ONLY: &str = "observe-only";
pub const GROUP_DEBUG_FULL: &str = "full";

pub type SharedStore = Arc<dyn MeshStore>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Network {
    pub id: String,
    pub organization_id: String,
    pub created_at: DateTime<Utc>,
    pub node_count: i64,
    pub invite_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KVEntry {
    pub key: String,
    #[serde(serialize_with = "serialize_base64")]
    pub value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Group {
    pub network_id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupMember {
    pub network_id: String,
    pub group_name: String,
    pub node_name: String,
    pub session_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupPolicy {
    pub network_id: String,
    pub group_name: String,
    pub messages_policy: String,
    pub debug_policy: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupBinding {
    pub group_name: String,
    pub messages_policy: String,
    pub debug_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkMember {
    pub network_id: String,
    pub subject: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Invite {
    pub id: String,
    pub network_id: String,
    pub organization_id: String,
    pub created_by_user_id: String,
    #[serde(skip_serializing)]
    pub code_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for Invite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Invite")
            .field("id", &self.id)
            .field("network_id", &self.network_id)
            .field("organization_id", &self.organization_id)
            .field("created_by_user_id", &self.created_by_user_id)
            .field("code_hash", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeRecord {
    pub network_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub peer_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_id: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner_subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub authorized_by: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_id: String,
    pub authorized_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeEnrollment {
    pub id: String,
    pub network_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner_subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issued_by: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub node_name: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub uses_remaining: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeemed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccessGrant {
    pub id: String,
    pub network_id: String,
    pub target_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub verbs: Vec<String>,
    pub audience_subject_kind: String,
    pub audience_subject_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub audience_display: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issued_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessGrantFilter {
    pub target_node: String,
    pub audience_subject_id: String,
    pub active_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskEvent {
    pub event_id: String,
    pub network_id: String,
    pub node_name: String,
    pub session_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub summary: String,
    pub state: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatestTaskValue {
    pub event_id: String,
    pub stream_seq: i64,
    pub network_id: String,
    pub node_name: String,
    pub session_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub summary: String,
    pub state: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskFilter {
    pub network_id: String,
    pub node_name: String,
    pub session_id: Option<u32>,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskWatchEvent {
    pub seq: i64,
    pub event: TaskEvent,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("forbidden")]
    Forbidden,
    #[error("Mesh network has registered nodes; revoke them before deleting the network")]
    NetworkNotEmpty,
    #[error("Mesh network name was deleted and cannot be reused")]
    NetworkRetired,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait MeshStore: Send + Sync + 'static {
    async fn kv_set(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError>;
    async fn kv_get(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError>;
    async fn kv_get_entry(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KVEntry>, StoreError>;
    async fn kv_delete(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<(), StoreError>;
    async fn kv_list(
        &self,
        network_id: &str,
        namespace: &str,
        prefix: &str,
    ) -> Result<Vec<KVEntry>, StoreError>;
    async fn group_create(&self, group: Group) -> Result<(), StoreError>;
    async fn group_list(&self, network_id: &str) -> Result<Vec<Group>, StoreError>;
    async fn group_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<Group>, StoreError>;
    async fn group_delete(&self, network_id: &str, group_name: &str) -> Result<(), StoreError>;
    async fn group_member_add(&self, member: GroupMember) -> Result<(), StoreError>;
    async fn group_member_remove(
        &self,
        network_id: &str,
        group_name: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<(), StoreError>;
    async fn group_member_list(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Vec<GroupMember>, StoreError>;
    async fn group_bindings_for_session(
        &self,
        network_id: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<Vec<GroupBinding>, StoreError>;
    async fn group_policy_set(&self, policy: GroupPolicy) -> Result<(), StoreError>;
    async fn group_policy_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<GroupPolicy>, StoreError>;
    async fn network_list(&self) -> Result<Vec<Network>, StoreError>;
    async fn network_list_by_member(
        &self,
        organization_id: &str,
        subject: &str,
    ) -> Result<Vec<Network>, StoreError>;
    async fn network_list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Network>, StoreError>;
    /// Atomically creates a network and its first owner membership. A retry by
    /// that same owner is idempotent; no other caller can claim an existing
    /// network or acquire ownership through this operation.
    async fn network_create_with_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    /// Recheck the exact organization and owner, refuse registered nodes, and
    /// atomically delete all network metadata while permanently retiring its name.
    async fn network_delete_by_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
    ) -> Result<(), StoreError>;
    async fn network_organization_id(&self, network_id: &str)
    -> Result<Option<String>, StoreError>;
    /// Compatibility name retained only while old non-network handlers remain
    /// in the binary. It now verifies that an already-owned row exists; it
    /// never creates a fallback network.
    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError>;
    async fn network_member_get(
        &self,
        network_id: &str,
        subject: &str,
    ) -> Result<Option<NetworkMember>, StoreError>;
    async fn network_member_count(&self, network_id: &str) -> Result<i64, StoreError>;
    async fn network_member_upsert(&self, member: NetworkMember) -> Result<(), StoreError>;
    async fn invite_create(&self, invite: Invite) -> Result<(), StoreError>;
    async fn invite_get_by_id(
        &self,
        network_id: &str,
        invite_id: &str,
    ) -> Result<Option<Invite>, StoreError>;
    async fn invite_get_by_code_hash(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Invite>, StoreError>;
    /// Atomically consumes one live invitation in the already-authorized
    /// organization and inserts the joining member. An existing membership is
    /// preserved so an owner can never be demoted by redeeming an invitation.
    async fn invite_consume_and_join(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
        organization_id: &str,
        subject: &str,
    ) -> Result<Option<Invite>, StoreError>;
    async fn invite_list(&self, network_id: &str) -> Result<Vec<Invite>, StoreError>;
    async fn invite_delete(&self, network_id: &str, invite_id: &str) -> Result<(), StoreError>;
    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError>;
    async fn node_get(
        &self,
        network_id: &str,
        name: &str,
    ) -> Result<Option<NodeRecord>, StoreError>;
    async fn node_list(&self, network_id: &str) -> Result<Vec<NodeRecord>, StoreError>;
    async fn node_list_all(&self) -> Result<Vec<NodeRecord>, StoreError>;
    /// Delete a node and invalidate every unconsumed enrollment fixed to its
    /// name as one atomic store operation.
    async fn node_delete(&self, network_id: &str, name: &str) -> Result<(), StoreError>;
    async fn node_enrollment_create(&self, enrollment: NodeEnrollment) -> Result<(), StoreError>;
    async fn node_enrollment_get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<NodeEnrollment>, StoreError>;
    /// Atomically consume an enrollment and register its exact node. Ownership
    /// collisions roll back the capability consumption.
    async fn node_enrollment_consume_and_register(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
        node: NodeRecord,
    ) -> Result<Option<NodeEnrollment>, StoreError>;
    async fn access_grant_create(&self, grant: AccessGrant) -> Result<(), StoreError>;
    async fn access_grant_get(
        &self,
        network_id: &str,
        grant_id: &str,
    ) -> Result<Option<AccessGrant>, StoreError>;
    async fn access_grant_list(
        &self,
        network_id: &str,
        filter: AccessGrantFilter,
    ) -> Result<Vec<AccessGrant>, StoreError>;
    async fn access_grant_revoke(
        &self,
        network_id: &str,
        grant_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    async fn task_event_create(&self, event: TaskEvent) -> Result<LatestTaskValue, StoreError>;
    async fn task_latest_list(
        &self,
        filter: TaskFilter,
    ) -> Result<Vec<LatestTaskValue>, StoreError>;
    async fn task_events_after(
        &self,
        filter: TaskFilter,
        after_seq: i64,
    ) -> Result<Vec<TaskWatchEvent>, StoreError>;
    async fn task_earliest_seq(&self, network_id: &str) -> Result<i64, StoreError>;
}

pub async fn store_from_config(config: &Config) -> anyhow::Result<SharedStore> {
    match config.database_url.as_deref() {
        Some(url) if !url.trim().is_empty() => {
            Ok(Arc::new(PostgresMeshStore::connect(url).await?) as SharedStore)
        }
        _ => Ok(Arc::new(MemoryStore::new()) as SharedStore),
    }
}

#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    networks: HashMap<String, MemoryNetwork>,
    retired_network_names: HashSet<String>,
    kv: HashMap<(String, String, String), KVEntry>,
    groups: HashMap<(String, String), Group>,
    group_members: HashMap<(String, String, String, String), GroupMember>,
    group_policies: HashMap<(String, String), GroupPolicy>,
    members: HashMap<(String, String), NetworkMember>,
    invites: HashMap<String, Invite>,
    nodes: HashMap<(String, String), NodeRecord>,
    node_enrollments: HashMap<String, NodeEnrollment>,
    access_grants: HashMap<(String, String), AccessGrant>,
    task_events: Vec<TaskWatchEvent>,
    next_task_seq: i64,
}

#[derive(Clone)]
struct MemoryNetwork {
    organization_id: String,
    created_at: DateTime<Utc>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MeshStore for MemoryStore {
    async fn kv_set(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(network_id) {
            return Err(StoreError::NotFound);
        }
        let expires_at = ttl.map(|ttl| Utc::now() + ttl);
        state.kv.insert(
            (
                network_id.to_string(),
                namespace.to_string(),
                key.to_string(),
            ),
            KVEntry {
                key: key.to_string(),
                value,
                expires_at,
            },
        );
        Ok(())
    }

    async fn kv_get(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .kv
            .get(&(
                network_id.to_string(),
                namespace.to_string(),
                key.to_string(),
            ))
            .filter(|entry| entry.expires_at.is_none_or(|expires_at| expires_at > now))
            .map(|entry| entry.value.clone()))
    }

    async fn kv_get_entry(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KVEntry>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .kv
            .get(&(
                network_id.to_string(),
                namespace.to_string(),
                key.to_string(),
            ))
            .filter(|entry| entry.expires_at.is_none_or(|expires_at| expires_at > now))
            .cloned())
    }

    async fn kv_delete(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state.kv.remove(&(
            network_id.to_string(),
            namespace.to_string(),
            key.to_string(),
        ));
        Ok(())
    }

    async fn kv_list(
        &self,
        network_id: &str,
        namespace: &str,
        prefix: &str,
    ) -> Result<Vec<KVEntry>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        let mut entries = state
            .kv
            .iter()
            .filter(|((entry_network, entry_namespace, entry_key), entry)| {
                entry_network == network_id
                    && entry_namespace == namespace
                    && entry_key.starts_with(prefix)
                    && entry.expires_at.is_none_or(|expires_at| expires_at > now)
            })
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }

    async fn group_create(&self, group: Group) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&group.network_id) {
            return Err(StoreError::NotFound);
        }
        let key = (group.network_id.clone(), group.name.clone());
        if state.groups.contains_key(&key) {
            return Err(StoreError::AlreadyExists);
        }
        state.groups.insert(key.clone(), group.clone());
        state.group_policies.entry(key).or_insert(GroupPolicy {
            network_id: group.network_id,
            group_name: group.name,
            messages_policy: GROUP_MESSAGES_INTERNAL_ONLY.to_string(),
            debug_policy: GROUP_DEBUG_OBSERVE_ONLY.to_string(),
            updated_at: group.created_at,
        });
        Ok(())
    }

    async fn group_list(&self, network_id: &str) -> Result<Vec<Group>, StoreError> {
        let state = self.state.lock().await;
        let mut groups = state
            .groups
            .values()
            .filter(|group| group.network_id == network_id)
            .cloned()
            .collect::<Vec<_>>();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(groups)
    }

    async fn group_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<Group>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .groups
            .get(&(network_id.to_string(), group_name.to_string()))
            .cloned())
    }

    async fn group_delete(&self, network_id: &str, group_name: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let key = (network_id.to_string(), group_name.to_string());
        state
            .group_members
            .retain(|(member_network_id, member_group_name, _, _), _| {
                member_network_id != network_id || member_group_name != group_name
            });
        state.group_policies.remove(&key);
        if state.groups.remove(&key).is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn group_member_add(&self, member: GroupMember) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state
            .groups
            .contains_key(&(member.network_id.clone(), member.group_name.clone()))
        {
            return Err(StoreError::NotFound);
        }
        state
            .group_members
            .entry((
                member.network_id.clone(),
                member.group_name.clone(),
                member.node_name.clone(),
                member.session_name.clone(),
            ))
            .or_insert(member);
        Ok(())
    }

    async fn group_member_remove(
        &self,
        network_id: &str,
        group_name: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let removed = state.group_members.remove(&(
            network_id.to_string(),
            group_name.to_string(),
            node_name.to_string(),
            session_name.to_string(),
        ));
        if removed.is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn group_member_list(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Vec<GroupMember>, StoreError> {
        let state = self.state.lock().await;
        let mut members = state
            .group_members
            .values()
            .filter(|member| member.network_id == network_id && member.group_name == group_name)
            .cloned()
            .collect::<Vec<_>>();
        members.sort_by(|a, b| {
            a.node_name
                .cmp(&b.node_name)
                .then_with(|| a.session_name.cmp(&b.session_name))
        });
        Ok(members)
    }

    async fn group_bindings_for_session(
        &self,
        network_id: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<Vec<GroupBinding>, StoreError> {
        let state = self.state.lock().await;
        let mut bindings = state
            .group_members
            .values()
            .filter(|member| {
                member.network_id == network_id
                    && member.node_name == node_name
                    && member.session_name == session_name
            })
            .map(|member| {
                let policy = state
                    .group_policies
                    .get(&(member.network_id.clone(), member.group_name.clone()));
                GroupBinding {
                    group_name: member.group_name.clone(),
                    messages_policy: policy
                        .map(|policy| policy.messages_policy.clone())
                        .unwrap_or_else(|| GROUP_MESSAGES_INTERNAL_ONLY.to_string()),
                    debug_policy: policy
                        .map(|policy| policy.debug_policy.clone())
                        .unwrap_or_else(|| GROUP_DEBUG_OBSERVE_ONLY.to_string()),
                }
            })
            .collect::<Vec<_>>();
        bindings.sort_by(|a, b| a.group_name.cmp(&b.group_name));
        Ok(bindings)
    }

    async fn group_policy_set(&self, policy: GroupPolicy) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let key = (policy.network_id.clone(), policy.group_name.clone());
        if !state.groups.contains_key(&key) {
            return Err(StoreError::NotFound);
        }
        state.group_policies.insert(key, policy);
        Ok(())
    }

    async fn group_policy_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<GroupPolicy>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .group_policies
            .get(&(network_id.to_string(), group_name.to_string()))
            .cloned())
    }

    async fn network_list(&self) -> Result<Vec<Network>, StoreError> {
        let state = self.state.lock().await;
        Ok(networks_from_state(&state, None))
    }

    async fn network_list_by_member(
        &self,
        organization_id: &str,
        subject: &str,
    ) -> Result<Vec<Network>, StoreError> {
        let state = self.state.lock().await;
        let allowed = state
            .members
            .iter()
            .filter_map(|((network_id, member_subject), _)| {
                (member_subject == subject).then_some(network_id.as_str())
            })
            .collect::<HashSet<_>>();
        Ok(networks_from_state(&state, Some(&allowed))
            .into_iter()
            .filter(|network| network.organization_id == organization_id)
            .collect())
    }

    async fn network_list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Network>, StoreError> {
        let state = self.state.lock().await;
        Ok(networks_from_state(&state, None)
            .into_iter()
            .filter(|network| network.organization_id == organization_id)
            .collect())
    }

    async fn network_create_with_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let network_id = required_identifier(network_id, "network_id")?;
        let organization_id = required_identifier(organization_id, "organization_id")?;
        let owner_subject = required_identifier(owner_subject, "owner_subject")?;
        let mut state = self.state.lock().await;
        if state.retired_network_names.contains(&network_id) {
            return Err(StoreError::NetworkRetired);
        }
        if let Some(existing) = state.networks.get(&network_id) {
            return if existing.organization_id == organization_id
                && state
                    .members
                    .get(&(network_id, owner_subject))
                    .is_some_and(|member| member.role == NETWORK_ROLE_OWNER)
            {
                Ok(())
            } else {
                Err(StoreError::AlreadyExists)
            };
        }
        state.networks.insert(
            network_id.clone(),
            MemoryNetwork {
                organization_id,
                created_at,
            },
        );
        state.members.insert(
            (network_id.clone(), owner_subject.clone()),
            NetworkMember {
                network_id,
                subject: owner_subject.clone(),
                role: NETWORK_ROLE_OWNER.to_owned(),
                created_at,
                created_by: owner_subject,
            },
        );
        Ok(())
    }

    async fn network_delete_by_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let network = state.networks.get(network_id).ok_or(StoreError::NotFound)?;
        if network.organization_id != organization_id
            || state
                .members
                .get(&(network_id.to_owned(), owner_subject.to_owned()))
                .is_none_or(|member| member.role != NETWORK_ROLE_OWNER)
        {
            return Err(StoreError::Forbidden);
        }
        if state.nodes.keys().any(|(id, _)| id == network_id) {
            return Err(StoreError::NetworkNotEmpty);
        }
        state.retired_network_names.insert(network_id.to_owned());
        state.members.retain(|(id, _), _| id != network_id);
        state
            .invites
            .retain(|_, invite| invite.network_id != network_id);
        state
            .node_enrollments
            .retain(|_, enrollment| enrollment.network_id != network_id);
        state.groups.retain(|(id, _), _| id != network_id);
        state
            .group_members
            .retain(|(id, _, _, _), _| id != network_id);
        state.group_policies.retain(|(id, _), _| id != network_id);
        state.kv.retain(|(id, _, _), _| id != network_id);
        state.access_grants.retain(|(id, _), _| id != network_id);
        state
            .task_events
            .retain(|event| event.event.network_id != network_id);
        state.networks.remove(network_id);
        Ok(())
    }

    async fn network_organization_id(
        &self,
        network_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .networks
            .get(network_id)
            .map(|network| network.organization_id.clone()))
    }

    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError> {
        self.network_organization_id(network_id)
            .await?
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }

    async fn network_member_get(
        &self,
        network_id: &str,
        subject: &str,
    ) -> Result<Option<NetworkMember>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .members
            .get(&(network_id.to_string(), subject.to_string()))
            .cloned())
    }

    async fn network_member_count(&self, network_id: &str) -> Result<i64, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .members
            .keys()
            .filter(|(member_network, _)| member_network == network_id)
            .count() as i64)
    }

    async fn network_member_upsert(&self, member: NetworkMember) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&member.network_id) {
            return Err(StoreError::NotFound);
        }
        let key = (member.network_id.clone(), member.subject.clone());
        if let Some(existing) = state.members.get_mut(&key) {
            existing.role = member.role;
        } else {
            state.members.insert(key, member);
        }
        Ok(())
    }

    async fn invite_create(&self, invite: Invite) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let Some(network) = state.networks.get(&invite.network_id) else {
            return Err(StoreError::NotFound);
        };
        if network.organization_id != invite.organization_id {
            return Err(StoreError::NotFound);
        }
        if state.invites.contains_key(&invite.id)
            || state
                .invites
                .values()
                .any(|existing| existing.code_hash == invite.code_hash)
        {
            return Err(StoreError::AlreadyExists);
        }
        state.invites.insert(invite.id.clone(), invite);
        Ok(())
    }

    async fn invite_get_by_id(
        &self,
        network_id: &str,
        invite_id: &str,
    ) -> Result<Option<Invite>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .invites
            .get(invite_id)
            .filter(|invite| invite.network_id == network_id && invite.expires_at > now)
            .cloned())
    }

    async fn invite_get_by_code_hash(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Invite>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .invites
            .values()
            .find(|invite| invite.code_hash == code_hash && invite.expires_at > now)
            .cloned())
    }

    async fn invite_consume_and_join(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
        organization_id: &str,
        subject: &str,
    ) -> Result<Option<Invite>, StoreError> {
        let organization_id = required_identifier(organization_id, "organization_id")?;
        let subject = required_identifier(subject, "subject")?;
        let mut state = self.state.lock().await;
        let invitation = state
            .invites
            .values()
            .find(|invite| {
                invite.code_hash == code_hash
                    && invite.organization_id == organization_id
                    && invite.expires_at > now
            })
            .cloned();
        let Some(invitation) = invitation else {
            return Ok(None);
        };
        let Some(network) = state.networks.get(&invitation.network_id) else {
            return Err(StoreError::NotFound);
        };
        if network.organization_id != invitation.organization_id {
            return Err(StoreError::NotFound);
        }
        state
            .members
            .entry((invitation.network_id.clone(), subject.clone()))
            .or_insert_with(|| NetworkMember {
                network_id: invitation.network_id.clone(),
                subject,
                role: NETWORK_ROLE_MEMBER.to_owned(),
                created_at: now,
                created_by: format!("invite:{}", invitation.id),
            });
        state.invites.remove(&invitation.id);
        Ok(Some(invitation))
    }

    async fn invite_list(&self, network_id: &str) -> Result<Vec<Invite>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        let mut invites = state
            .invites
            .values()
            .filter(|invite| invite.network_id == network_id && invite.expires_at > now)
            .cloned()
            .collect::<Vec<_>>();
        invites.sort_by_key(|invite| invite.created_at);
        Ok(invites)
    }

    async fn invite_delete(&self, network_id: &str, invite_id: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if state
            .invites
            .get(invite_id)
            .is_some_and(|invite| invite.network_id == network_id)
        {
            state.invites.remove(invite_id);
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&node.network_id) {
            return Err(StoreError::NotFound);
        }
        let key = (node.network_id.clone(), node.name.clone());
        if let Some(existing) = state.nodes.get_mut(&key) {
            if existing.owner_subject != node.owner_subject {
                return Err(StoreError::AlreadyExists);
            }
            existing.peer_url = node.peer_url;
            existing.github_id = node.github_id;
            existing.authorized_by = node.authorized_by;
            existing.enrollment_id = node.enrollment_id;
            existing.last_seen_at = node.last_seen_at;
        } else {
            state.nodes.insert(key, node);
        }
        Ok(())
    }

    async fn node_get(
        &self,
        network_id: &str,
        name: &str,
    ) -> Result<Option<NodeRecord>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .nodes
            .get(&(network_id.to_string(), name.to_string()))
            .cloned())
    }

    async fn node_list(&self, network_id: &str) -> Result<Vec<NodeRecord>, StoreError> {
        let state = self.state.lock().await;
        let mut nodes = state
            .nodes
            .values()
            .filter(|node| node.network_id == network_id)
            .cloned()
            .collect::<Vec<_>>();
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(nodes)
    }

    async fn node_list_all(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let state = self.state.lock().await;
        let mut nodes = state.nodes.values().cloned().collect::<Vec<_>>();
        nodes.sort_by(|a, b| {
            a.network_id
                .cmp(&b.network_id)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(nodes)
    }

    async fn node_delete(&self, network_id: &str, name: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        for enrollment in state.node_enrollments.values_mut() {
            if enrollment.network_id == network_id
                && enrollment.node_name == name
                && enrollment.uses_remaining > 0
            {
                enrollment.uses_remaining = 0;
            }
        }
        state
            .nodes
            .remove(&(network_id.to_string(), name.to_string()));
        Ok(())
    }

    async fn node_enrollment_create(&self, enrollment: NodeEnrollment) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&enrollment.network_id) {
            return Err(StoreError::NotFound);
        }
        state
            .node_enrollments
            .insert(enrollment.token_hash.clone(), enrollment);
        Ok(())
    }

    async fn node_enrollment_get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
        let state = self.state.lock().await;
        Ok(state.node_enrollments.get(token_hash).cloned())
    }

    async fn node_enrollment_consume_and_register(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
        node: NodeRecord,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
        let mut state = self.state.lock().await;
        let Some(enrollment) = state.node_enrollments.get(token_hash).cloned() else {
            return Ok(None);
        };
        if enrollment.uses_remaining <= 0 || enrollment.expires_at <= redeemed_at {
            return Ok(None);
        }
        validate_enrollment_node_binding(&enrollment, &node)?;
        if !state.networks.contains_key(&node.network_id) {
            return Err(StoreError::NotFound);
        }
        let node_key = (node.network_id.clone(), node.name.clone());
        if state
            .nodes
            .get(&node_key)
            .is_some_and(|existing| existing.owner_subject != node.owner_subject)
        {
            return Err(StoreError::AlreadyExists);
        }

        let enrollment = state
            .node_enrollments
            .get_mut(token_hash)
            .expect("enrollment remains present while the memory store lock is held");
        enrollment.uses_remaining -= 1;
        if enrollment.uses_remaining == 0 {
            enrollment.redeemed_at = Some(redeemed_at);
        }
        let redeemed = enrollment.clone();

        if let Some(existing) = state.nodes.get_mut(&node_key) {
            existing.peer_url = node.peer_url;
            existing.github_id = node.github_id;
            existing.authorized_by = node.authorized_by;
            existing.enrollment_id = node.enrollment_id;
            existing.last_seen_at = node.last_seen_at;
        } else {
            state.nodes.insert(node_key, node);
        }
        Ok(Some(redeemed))
    }

    async fn access_grant_create(&self, grant: AccessGrant) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&grant.network_id) {
            return Err(StoreError::NotFound);
        }
        state
            .access_grants
            .insert((grant.network_id.clone(), grant.id.clone()), grant);
        Ok(())
    }

    async fn access_grant_get(
        &self,
        network_id: &str,
        grant_id: &str,
    ) -> Result<Option<AccessGrant>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .access_grants
            .get(&(network_id.to_string(), grant_id.to_string()))
            .cloned())
    }

    async fn access_grant_list(
        &self,
        network_id: &str,
        filter: AccessGrantFilter,
    ) -> Result<Vec<AccessGrant>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        let mut grants = state
            .access_grants
            .values()
            .filter(|grant| grant.network_id == network_id)
            .filter(|grant| {
                filter.target_node.trim().is_empty()
                    || grant.target_node == filter.target_node.trim()
            })
            .filter(|grant| {
                filter.audience_subject_id.trim().is_empty()
                    || grant.audience_subject_id == filter.audience_subject_id.trim()
            })
            .filter(|grant| {
                !filter.active_only || (grant.expires_at > now && grant.revoked_at.is_none())
            })
            .cloned()
            .collect::<Vec<_>>();
        grants.sort_by_key(|grant| std::cmp::Reverse(grant.created_at));
        Ok(grants)
    }

    async fn access_grant_revoke(
        &self,
        network_id: &str,
        grant_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let Some(grant) = state
            .access_grants
            .get_mut(&(network_id.to_string(), grant_id.to_string()))
        else {
            return Err(StoreError::NotFound);
        };
        if grant.revoked_at.is_some() {
            return Err(StoreError::NotFound);
        }
        grant.revoked_at = Some(revoked_at);
        Ok(())
    }

    async fn task_event_create(&self, event: TaskEvent) -> Result<LatestTaskValue, StoreError> {
        let mut state = self.state.lock().await;
        if !state.networks.contains_key(&event.network_id) {
            return Err(StoreError::NotFound);
        }
        state.next_task_seq += 1;
        let seq = state.next_task_seq;
        state.task_events.push(TaskWatchEvent {
            seq,
            event: event.clone(),
        });
        Ok(latest_task_from_event(seq, &event))
    }

    async fn task_latest_list(
        &self,
        filter: TaskFilter,
    ) -> Result<Vec<LatestTaskValue>, StoreError> {
        let state = self.state.lock().await;
        let mut event_filter = filter.clone();
        event_filter.state.clear();
        let mut latest: HashMap<(String, String, u32), LatestTaskValue> = HashMap::new();
        for watch in &state.task_events {
            if !task_filter_matches_event(&watch.event, &event_filter) {
                continue;
            }
            let key = (
                watch.event.network_id.clone(),
                watch.event.node_name.clone(),
                watch.event.session_id,
            );
            let value = latest_task_from_event(watch.seq, &watch.event);
            if latest
                .get(&key)
                .is_none_or(|existing| existing.stream_seq < value.stream_seq)
            {
                latest.insert(key, value);
            }
        }
        let mut values = latest.into_values().collect::<Vec<_>>();
        retain_latest_by_state(&mut values, &filter);
        sort_latest_tasks(&mut values);
        Ok(values)
    }

    async fn task_events_after(
        &self,
        filter: TaskFilter,
        after_seq: i64,
    ) -> Result<Vec<TaskWatchEvent>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .task_events
            .iter()
            .filter(|watch| {
                watch.seq > after_seq && task_filter_matches_event(&watch.event, &filter)
            })
            .cloned()
            .collect())
    }

    async fn task_earliest_seq(&self, network_id: &str) -> Result<i64, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .task_events
            .iter()
            .filter(|watch| watch.event.network_id == network_id)
            .map(|watch| watch.seq)
            .min()
            .unwrap_or(0))
    }
}

fn latest_task_from_event(seq: i64, event: &TaskEvent) -> LatestTaskValue {
    LatestTaskValue {
        event_id: event.event_id.clone(),
        stream_seq: seq,
        network_id: event.network_id.clone(),
        node_name: event.node_name.clone(),
        session_id: event.session_id,
        session_name: event.session_name.clone(),
        summary: event.summary.clone(),
        state: event.state.clone(),
        timestamp: event.timestamp.clone(),
    }
}

fn sort_latest_tasks(values: &mut [LatestTaskValue]) {
    values.sort_by(|a, b| {
        a.node_name
            .cmp(&b.node_name)
            .then_with(|| a.session_name.cmp(&b.session_name))
            .then_with(|| a.session_id.cmp(&b.session_id))
    });
}

fn retain_latest_by_state(values: &mut Vec<LatestTaskValue>, filter: &TaskFilter) {
    let state = filter.state.trim();
    if !state.is_empty() {
        values.retain(|value| value.state == state);
    }
}

fn task_filter_matches_event(event: &TaskEvent, filter: &TaskFilter) -> bool {
    let network_id = filter.network_id.trim();
    if !network_id.is_empty() && event.network_id != network_id {
        return false;
    }
    let node_name = filter.node_name.trim();
    if !node_name.is_empty() && event.node_name != node_name {
        return false;
    }
    if let Some(session_id) = filter.session_id
        && event.session_id != session_id
    {
        return false;
    }
    let state = filter.state.trim();
    if !state.is_empty() && event.state != state {
        return false;
    }
    true
}

fn networks_from_state(state: &MemoryState, allowed: Option<&HashSet<&str>>) -> Vec<Network> {
    let now = Utc::now();
    let mut networks = state
        .networks
        .iter()
        .filter_map(|(id, network)| {
            if allowed.is_none_or(|allowed| allowed.contains(id.as_str())) {
                Some(Network {
                    id: id.clone(),
                    organization_id: network.organization_id.clone(),
                    created_at: network.created_at,
                    node_count: state
                        .nodes
                        .keys()
                        .filter(|(node_network, _)| node_network == id)
                        .count() as i64,
                    invite_count: state
                        .invites
                        .values()
                        .filter(|invite| invite.network_id == *id && invite.expires_at > now)
                        .count() as i64,
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    networks.sort_by(|a, b| a.id.cmp(&b.id));
    networks
}

pub struct PostgresMeshStore {
    pool: PgPool,
}

/// Always acquire the parent before child row locks. Network deletion takes
/// FOR UPDATE and cascades into those children in the same transaction.
async fn lock_network(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    network_id: &str,
) -> Result<(), StoreError> {
    sqlx::query_scalar::<_, String>(
        "SELECT network_id FROM networks WHERE network_id = $1 FOR KEY SHARE",
    )
    .bind(network_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::NotFound)?;
    Ok(())
}

impl PostgresMeshStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = codewire_server_core::db::connect(database_url)
            .await
            .context("connect codewire-mesh database")?;
        MESH_MIGRATOR
            .run(&pool)
            .await
            .context("run codewire-mesh database migrations")?;
        Ok(Self { pool })
    }

    async fn task_event_rows(
        &self,
        filter: TaskFilter,
        after_seq: Option<i64>,
    ) -> Result<Vec<sqlx::postgres::PgRow>, StoreError> {
        let network_id = filter.network_id.trim().to_string();
        if network_id.is_empty() {
            return Err(StoreError::Invalid("network_id required".to_string()));
        }
        let node_name =
            (!filter.node_name.trim().is_empty()).then(|| filter.node_name.trim().to_string());
        let session_id = filter
            .session_id
            .map(i32::try_from)
            .transpose()
            .map_err(|_| StoreError::Invalid("session_id out of range".to_string()))?;
        let state = (!filter.state.trim().is_empty()).then(|| filter.state.trim().to_string());

        let mut query = task_event_select_sql("WHERE network_id = $1");
        let mut param = 2;
        if node_name.is_some() {
            query.push_str(&format!(" AND node_name = ${param}"));
            param += 1;
        }
        if session_id.is_some() {
            query.push_str(&format!(" AND session_id = ${param}"));
            param += 1;
        }
        if state.is_some() {
            query.push_str(&format!(" AND state = ${param}"));
            param += 1;
        }
        if after_seq.is_some() {
            query.push_str(&format!(" AND stream_seq > ${param}"));
        }
        query.push_str(" ORDER BY stream_seq ASC");

        let mut q = sqlx::query(&query).bind(network_id);
        if let Some(node_name) = node_name {
            q = q.bind(node_name);
        }
        if let Some(session_id) = session_id {
            q = q.bind(session_id);
        }
        if let Some(state) = state {
            q = q.bind(state);
        }
        if let Some(after_seq) = after_seq {
            q = q.bind(after_seq);
        }
        Ok(q.fetch_all(&self.pool).await?)
    }
}

#[async_trait]
impl MeshStore for PostgresMeshStore {
    async fn kv_set(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        let expires_at = ttl.map(|ttl| Utc::now() + ttl);
        sqlx::query(
            r#"
            INSERT INTO kv (network_id, namespace, key, value, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (network_id, namespace, key) DO UPDATE SET
                value = EXCLUDED.value,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(network_id)
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn kv_get(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let value = sqlx::query_scalar(
            r#"
            SELECT value
            FROM kv
            WHERE network_id = $1
                AND namespace = $2
                AND key = $3
                AND (expires_at IS NULL OR expires_at > $4)
            "#,
        )
        .bind(network_id)
        .bind(namespace)
        .bind(key)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;
        Ok(value)
    }

    async fn kv_get_entry(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KVEntry>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT key, value, expires_at
            FROM kv
            WHERE network_id = $1
                AND namespace = $2
                AND key = $3
                AND (expires_at IS NULL OR expires_at > $4)
            "#,
        )
        .bind(network_id)
        .bind(namespace)
        .bind(key)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(KVEntry {
                key: row.try_get("key")?,
                value: row.try_get("value")?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .transpose()
    }

    async fn kv_delete(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(r#"DELETE FROM kv WHERE network_id = $1 AND namespace = $2 AND key = $3"#)
            .bind(network_id)
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn kv_list(
        &self,
        network_id: &str,
        namespace: &str,
        prefix: &str,
    ) -> Result<Vec<KVEntry>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT key, value, expires_at
            FROM kv
            WHERE network_id = $1
                AND namespace = $2
                AND key LIKE $3
                AND (expires_at IS NULL OR expires_at > $4)
            ORDER BY key
            "#,
        )
        .bind(network_id)
        .bind(namespace)
        .bind(format!("{prefix}%"))
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_kv_entry).collect()
    }

    async fn group_create(&self, group: Group) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        lock_network(&mut tx, &group.network_id).await?;

        let result = sqlx::query(
            r#"
            INSERT INTO groups (network_id, name, created_at, created_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&group.network_id)
        .bind(&group.name)
        .bind(group.created_at)
        .bind(&group.created_by)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::AlreadyExists);
        }

        sqlx::query(
            r#"
            INSERT INTO group_policies
                (network_id, group_name, messages_policy, debug_policy, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&group.network_id)
        .bind(&group.name)
        .bind(GROUP_MESSAGES_INTERNAL_ONLY)
        .bind(GROUP_DEBUG_OBSERVE_ONLY)
        .bind(group.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn group_list(&self, network_id: &str) -> Result<Vec<Group>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT network_id, name, created_at, created_by
            FROM groups
            WHERE network_id = $1
            ORDER BY name
            "#,
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_group).collect()
    }

    async fn group_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<Group>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, name, created_at, created_by
            FROM groups
            WHERE network_id = $1 AND name = $2
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_group).transpose()
    }

    async fn group_delete(&self, network_id: &str, group_name: &str) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            DELETE FROM group_members
            WHERE network_id = $1 AND group_name = $2
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            DELETE FROM group_policies
            WHERE network_id = $1 AND group_name = $2
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query(
            r#"
            DELETE FROM groups
            WHERE network_id = $1 AND name = $2
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        tx.commit().await?;
        Ok(())
    }

    async fn group_member_add(&self, member: GroupMember) -> Result<(), StoreError> {
        let exists: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM groups
            WHERE network_id = $1 AND name = $2
            "#,
        )
        .bind(&member.network_id)
        .bind(&member.group_name)
        .fetch_one(&self.pool)
        .await?;
        if exists == 0 {
            return Err(StoreError::NotFound);
        }

        sqlx::query(
            r#"
            INSERT INTO group_members
                (network_id, group_name, node_name, session_name, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&member.network_id)
        .bind(&member.group_name)
        .bind(&member.node_name)
        .bind(&member.session_name)
        .bind(member.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn group_member_remove(
        &self,
        network_id: &str,
        group_name: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM group_members
            WHERE network_id = $1
                AND group_name = $2
                AND node_name = $3
                AND session_name = $4
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .bind(node_name)
        .bind(session_name)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn group_member_list(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Vec<GroupMember>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT network_id, group_name, node_name, session_name, created_at
            FROM group_members
            WHERE network_id = $1 AND group_name = $2
            ORDER BY node_name, session_name
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_group_member).collect()
    }

    async fn group_bindings_for_session(
        &self,
        network_id: &str,
        node_name: &str,
        session_name: &str,
    ) -> Result<Vec<GroupBinding>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT gm.group_name,
                   COALESCE(gp.messages_policy, $1) AS messages_policy,
                   COALESCE(gp.debug_policy, $2) AS debug_policy
            FROM group_members gm
            LEFT JOIN group_policies gp
                ON gp.network_id = gm.network_id
                AND gp.group_name = gm.group_name
            WHERE gm.network_id = $3
                AND gm.node_name = $4
                AND gm.session_name = $5
            ORDER BY gm.group_name
            "#,
        )
        .bind(GROUP_MESSAGES_INTERNAL_ONLY)
        .bind(GROUP_DEBUG_OBSERVE_ONLY)
        .bind(network_id)
        .bind(node_name)
        .bind(session_name)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(GroupBinding {
                    group_name: row.try_get("group_name")?,
                    messages_policy: row.try_get("messages_policy")?,
                    debug_policy: row.try_get("debug_policy")?,
                })
            })
            .collect()
    }

    async fn group_policy_set(&self, policy: GroupPolicy) -> Result<(), StoreError> {
        let exists: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM groups
            WHERE network_id = $1 AND name = $2
            "#,
        )
        .bind(&policy.network_id)
        .bind(&policy.group_name)
        .fetch_one(&self.pool)
        .await?;
        if exists == 0 {
            return Err(StoreError::NotFound);
        }

        sqlx::query(
            r#"
            INSERT INTO group_policies
                (network_id, group_name, messages_policy, debug_policy, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (network_id, group_name) DO UPDATE SET
                messages_policy = EXCLUDED.messages_policy,
                debug_policy = EXCLUDED.debug_policy,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&policy.network_id)
        .bind(&policy.group_name)
        .bind(&policy.messages_policy)
        .bind(&policy.debug_policy)
        .bind(policy.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn group_policy_get(
        &self,
        network_id: &str,
        group_name: &str,
    ) -> Result<Option<GroupPolicy>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, group_name, messages_policy, debug_policy, updated_at
            FROM group_policies
            WHERE network_id = $1 AND group_name = $2
            "#,
        )
        .bind(network_id)
        .bind(group_name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_group_policy).transpose()
    }

    async fn network_list(&self) -> Result<Vec<Network>, StoreError> {
        let rows = sqlx::query(network_list_sql(None))
            .bind(Utc::now())
            .fetch_all(&self.pool)
            .await?;
        rows_to_networks(rows)
    }

    async fn network_list_by_member(
        &self,
        organization_id: &str,
        subject: &str,
    ) -> Result<Vec<Network>, StoreError> {
        let rows = sqlx::query(network_list_sql(Some(subject)))
            .bind(Utc::now())
            .bind(subject)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        rows_to_networks(rows)
    }

    async fn network_list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Network>, StoreError> {
        let rows = sqlx::query(network_list_by_organization_sql())
            .bind(Utc::now())
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        rows_to_networks(rows)
    }

    async fn network_create_with_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let network_id = required_identifier(network_id, "network_id")?;
        let organization_id = required_identifier(organization_id, "organization_id")?;
        let owner_subject = required_identifier(owner_subject, "owner_subject")?;
        let mut transaction = self.pool.begin().await?;
        let created: Option<String> = sqlx::query_scalar(
            r#"
            INSERT INTO networks (network_id, organization_id, created_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (network_id) DO NOTHING
            RETURNING network_id
            "#,
        )
        .bind(&network_id)
        .bind(&organization_id)
        .bind(created_at)
        .fetch_optional(&mut *transaction)
        .await?;
        // Check after INSERT has waited on a concurrent deletion. A check
        // before INSERT alone could miss the retirement committed during that wait.
        let retired: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM retired_network_names WHERE network_id = $1)",
        )
        .bind(&network_id)
        .fetch_one(&mut *transaction)
        .await?;
        if retired {
            return Err(StoreError::NetworkRetired);
        }
        if created.is_some() {
            sqlx::query(
                r#"
                INSERT INTO network_members
                    (network_id, subject, role, created_at, created_by)
                VALUES ($1, $2, $3, $4, $2)
                "#,
            )
            .bind(&network_id)
            .bind(&owner_subject)
            .bind(NETWORK_ROLE_OWNER)
            .bind(created_at)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(());
        }

        let same_owner: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM networks n
                JOIN network_members nm ON nm.network_id = n.network_id
                WHERE n.network_id = $1
                  AND n.organization_id = $2
                  AND nm.subject = $3
                  AND nm.role = $4
            )
            "#,
        )
        .bind(&network_id)
        .bind(&organization_id)
        .bind(&owner_subject)
        .bind(NETWORK_ROLE_OWNER)
        .fetch_one(&mut *transaction)
        .await?;
        if !same_owner {
            return Err(StoreError::AlreadyExists);
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn network_delete_by_owner(
        &self,
        network_id: &str,
        organization_id: &str,
        owner_subject: &str,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        let actual_org: Option<String> = sqlx::query_scalar(
            "SELECT organization_id FROM networks WHERE network_id = $1 FOR UPDATE",
        )
        .bind(network_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let actual_org = actual_org.ok_or(StoreError::NotFound)?;
        if actual_org != organization_id {
            return Err(StoreError::Forbidden);
        }
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM network_members WHERE network_id = $1 AND subject = $2 FOR UPDATE",
        )
        .bind(network_id)
        .bind(owner_subject)
        .fetch_optional(&mut *transaction)
        .await?;
        if role.as_deref() != Some(NETWORK_ROLE_OWNER) {
            return Err(StoreError::Forbidden);
        }
        // A separate statement observes child inserts which completed while
        // the parent lock was pending. Immediate FKs block later inserts.
        let has_nodes: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM nodes WHERE network_id = $1)")
                .bind(network_id)
                .fetch_one(&mut *transaction)
                .await?;
        if has_nodes {
            return Err(StoreError::NetworkNotEmpty);
        }
        sqlx::query(
            "INSERT INTO retired_network_names (network_id, retired_at) VALUES ($1, now())",
        )
        .bind(network_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM networks WHERE network_id = $1")
            .bind(network_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn network_organization_id(
        &self,
        network_id: &str,
    ) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT organization_id FROM networks WHERE network_id = $1")
            .bind(network_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::from)
    }

    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError> {
        self.network_organization_id(network_id)
            .await?
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }

    async fn network_member_get(
        &self,
        network_id: &str,
        subject: &str,
    ) -> Result<Option<NetworkMember>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, subject, role, created_at, created_by
            FROM network_members
            WHERE network_id = $1 AND subject = $2
            "#,
        )
        .bind(network_id)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(NetworkMember {
                network_id: row.try_get("network_id")?,
                subject: row.try_get("subject")?,
                role: row.try_get("role")?,
                created_at: row.try_get("created_at")?,
                created_by: row.try_get("created_by")?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn network_member_count(&self, network_id: &str) -> Result<i64, StoreError> {
        Ok(
            sqlx::query_scalar(r#"SELECT COUNT(*) FROM network_members WHERE network_id = $1"#)
                .bind(network_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn network_member_upsert(&self, member: NetworkMember) -> Result<(), StoreError> {
        self.network_ensure(&member.network_id).await?;
        sqlx::query(
            r#"
            INSERT INTO network_members (network_id, subject, role, created_at, created_by)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (network_id, subject) DO UPDATE SET
                role = EXCLUDED.role
            "#,
        )
        .bind(&member.network_id)
        .bind(&member.subject)
        .bind(&member.role)
        .bind(member.created_at)
        .bind(&member.created_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn invite_create(&self, invite: Invite) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            INSERT INTO invites
                (id, network_id, organization_id, created_by_user_id,
                 code_hash, expires_at, created_at)
            SELECT $1, n.network_id, n.organization_id, $4, $5, $6, $7
            FROM networks n
            WHERE n.network_id = $2 AND n.organization_id = $3
            "#,
        )
        .bind(&invite.id)
        .bind(&invite.network_id)
        .bind(&invite.organization_id)
        .bind(&invite.created_by_user_id)
        .bind(&invite.code_hash)
        .bind(invite.expires_at)
        .bind(invite.created_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn invite_get_by_id(
        &self,
        network_id: &str,
        invite_id: &str,
    ) -> Result<Option<Invite>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, network_id, organization_id, created_by_user_id,
                   code_hash, expires_at, created_at
            FROM invites
            WHERE network_id = $1 AND id = $2 AND expires_at > $3
            "#,
        )
        .bind(network_id)
        .bind(invite_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_invite).transpose()
    }

    async fn invite_get_by_code_hash(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Invite>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, network_id, organization_id, created_by_user_id,
                   code_hash, expires_at, created_at
            FROM invites
            WHERE code_hash = $1 AND expires_at > $2
            "#,
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_invite).transpose()
    }

    async fn invite_consume_and_join(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
        organization_id: &str,
        subject: &str,
    ) -> Result<Option<Invite>, StoreError> {
        let organization_id = required_identifier(organization_id, "organization_id")?;
        let subject = required_identifier(subject, "subject")?;
        let mut transaction = self.pool.begin().await?;
        let network_id: Option<String> = sqlx::query_scalar(
            "SELECT network_id FROM invites WHERE code_hash = $1 AND organization_id = $2 AND expires_at > $3",
        )
        .bind(code_hash)
        .bind(&organization_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(network_id) = network_id else {
            return Ok(None);
        };
        lock_network(&mut transaction, &network_id).await?;
        let row = sqlx::query(
            r#"
            DELETE FROM invites
            WHERE code_hash = $1 AND organization_id = $2 AND expires_at > $3
            RETURNING id, network_id, organization_id, created_by_user_id,
                      code_hash, expires_at, created_at
            "#,
        )
        .bind(code_hash)
        .bind(&organization_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let invitation = row_to_invite(row)?;
        let network_matches: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM networks
                WHERE network_id = $1 AND organization_id = $2
            )
            "#,
        )
        .bind(&invitation.network_id)
        .bind(&invitation.organization_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !network_matches {
            return Err(StoreError::NotFound);
        }
        sqlx::query(
            r#"
            INSERT INTO network_members
                (network_id, subject, role, created_at, created_by)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (network_id, subject) DO NOTHING
            "#,
        )
        .bind(&invitation.network_id)
        .bind(&subject)
        .bind(NETWORK_ROLE_MEMBER)
        .bind(now)
        .bind(format!("invite:{}", invitation.id))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(invitation))
    }

    async fn invite_list(&self, network_id: &str) -> Result<Vec<Invite>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, network_id, organization_id, created_by_user_id,
                   code_hash, expires_at, created_at
            FROM invites
            WHERE network_id = $1 AND expires_at > $2
            ORDER BY created_at
            "#,
        )
        .bind(network_id)
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_invite).collect()
    }

    async fn invite_delete(&self, network_id: &str, invite_id: &str) -> Result<(), StoreError> {
        let result = sqlx::query(r#"DELETE FROM invites WHERE network_id = $1 AND id = $2"#)
            .bind(network_id)
            .bind(invite_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError> {
        self.network_ensure(&node.network_id).await?;
        let result = sqlx::query(
            r#"
            INSERT INTO nodes
                (network_id, name, peer_url, github_id, owner_subject, authorized_by,
                 enrollment_id, authorized_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (network_id, name) DO UPDATE SET
                peer_url = EXCLUDED.peer_url,
                github_id = EXCLUDED.github_id,
                authorized_by = EXCLUDED.authorized_by,
                enrollment_id = EXCLUDED.enrollment_id,
                last_seen_at = EXCLUDED.last_seen_at
            WHERE nodes.owner_subject = EXCLUDED.owner_subject
            "#,
        )
        .bind(&node.network_id)
        .bind(&node.name)
        .bind(&node.peer_url)
        .bind(node.github_id)
        .bind(&node.owner_subject)
        .bind(&node.authorized_by)
        .bind(&node.enrollment_id)
        .bind(node.authorized_at)
        .bind(node.last_seen_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(StoreError::AlreadyExists);
        }
        Ok(())
    }

    async fn node_get(
        &self,
        network_id: &str,
        name: &str,
    ) -> Result<Option<NodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, name, peer_url, github_id, owner_subject, authorized_by,
                   enrollment_id, authorized_at, last_seen_at
            FROM nodes
            WHERE network_id = $1 AND name = $2
            "#,
        )
        .bind(network_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(row_to_node(row)?))
        } else {
            Ok(None)
        }
    }

    async fn node_list(&self, network_id: &str) -> Result<Vec<NodeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT network_id, name, peer_url, github_id, owner_subject, authorized_by,
                   enrollment_id, authorized_at, last_seen_at
            FROM nodes
            WHERE network_id = $1
            ORDER BY name
            "#,
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_node).collect()
    }

    async fn node_list_all(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT network_id, name, peer_url, github_id, owner_subject, authorized_by,
                   enrollment_id, authorized_at, last_seen_at
            FROM nodes
            ORDER BY network_id, name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_node).collect()
    }

    async fn node_delete(&self, network_id: &str, name: &str) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            SELECT owner_subject
            FROM nodes
            WHERE network_id = $1 AND name = $2
            FOR UPDATE
            "#,
        )
        .bind(network_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE node_enrollments
            SET uses_remaining = 0
            WHERE network_id = $1 AND node_name = $2 AND uses_remaining > 0
            "#,
        )
        .bind(network_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
        sqlx::query(r#"DELETE FROM nodes WHERE network_id = $1 AND name = $2"#)
            .bind(network_id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn node_enrollment_create(&self, enrollment: NodeEnrollment) -> Result<(), StoreError> {
        self.network_ensure(&enrollment.network_id).await?;
        sqlx::query(
            r#"
            INSERT INTO node_enrollments
                (id, network_id, owner_subject, issued_by, node_name, token_hash,
                 uses_remaining, expires_at, created_at, redeemed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&enrollment.id)
        .bind(&enrollment.network_id)
        .bind(&enrollment.owner_subject)
        .bind(&enrollment.issued_by)
        .bind(&enrollment.node_name)
        .bind(&enrollment.token_hash)
        .bind(enrollment.uses_remaining)
        .bind(enrollment.expires_at)
        .bind(enrollment.created_at)
        .bind(enrollment.redeemed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn node_enrollment_get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, network_id, owner_subject, issued_by, node_name, token_hash,
                   uses_remaining, expires_at, created_at, redeemed_at
            FROM node_enrollments
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(row_to_node_enrollment(row)?))
        } else {
            Ok(None)
        }
    }

    async fn node_enrollment_consume_and_register(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
        node: NodeRecord,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
        let mut tx = self.pool.begin().await?;
        lock_network(&mut tx, &node.network_id).await?;
        let existing_owner: Option<String> = sqlx::query_scalar(
            r#"
            SELECT owner_subject
            FROM nodes
            WHERE network_id = $1 AND name = $2
            FOR UPDATE
            "#,
        )
        .bind(&node.network_id)
        .bind(&node.name)
        .fetch_optional(&mut *tx)
        .await?;
        if existing_owner
            .as_ref()
            .is_some_and(|owner| owner != &node.owner_subject)
        {
            return Err(StoreError::AlreadyExists);
        }

        let row = sqlx::query(
            r#"
            SELECT id, network_id, owner_subject, issued_by, node_name, token_hash,
                   uses_remaining, expires_at, created_at, redeemed_at
            FROM node_enrollments
            WHERE token_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let enrollment = row_to_node_enrollment(row)?;
        if enrollment.uses_remaining <= 0 || enrollment.expires_at <= redeemed_at {
            tx.rollback().await?;
            return Ok(None);
        }
        validate_enrollment_node_binding(&enrollment, &node)?;

        let row = sqlx::query(
            r#"
            UPDATE node_enrollments
            SET uses_remaining = uses_remaining - 1,
                redeemed_at = CASE WHEN uses_remaining = 1 THEN $1 ELSE redeemed_at END
            WHERE token_hash = $2 AND uses_remaining > 0 AND expires_at > $1
            RETURNING id, network_id, owner_subject, issued_by, node_name, token_hash,
                      uses_remaining, expires_at, created_at, redeemed_at
            "#,
        )
        .bind(redeemed_at)
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let redeemed = row
            .map(row_to_node_enrollment)
            .transpose()?
            .ok_or_else(|| StoreError::Invalid("locked enrollment changed".to_owned()))?;

        let result = sqlx::query(
            r#"
            INSERT INTO nodes
                (network_id, name, peer_url, github_id, owner_subject, authorized_by,
                 enrollment_id, authorized_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (network_id, name) DO UPDATE SET
                peer_url = EXCLUDED.peer_url,
                github_id = EXCLUDED.github_id,
                authorized_by = EXCLUDED.authorized_by,
                enrollment_id = EXCLUDED.enrollment_id,
                last_seen_at = EXCLUDED.last_seen_at
            WHERE nodes.owner_subject = EXCLUDED.owner_subject
            "#,
        )
        .bind(&node.network_id)
        .bind(&node.name)
        .bind(&node.peer_url)
        .bind(node.github_id)
        .bind(&node.owner_subject)
        .bind(&node.authorized_by)
        .bind(&node.enrollment_id)
        .bind(node.authorized_at)
        .bind(node.last_seen_at)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(StoreError::AlreadyExists);
        }
        tx.commit().await?;
        Ok(Some(redeemed))
    }

    async fn access_grant_create(&self, grant: AccessGrant) -> Result<(), StoreError> {
        self.network_ensure(&grant.network_id).await?;
        let verbs = serde_json::to_string(&grant.verbs).map_err(|_| StoreError::NotFound)?;
        let session_id = grant.session_id.map(i64::from);
        sqlx::query(
            r#"
            INSERT INTO access_grants
                (id, network_id, target_node, session_id, session_name, verbs,
                 audience_subject_kind, audience_subject_id, audience_display, issued_by,
                 created_at, expires_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(&grant.id)
        .bind(&grant.network_id)
        .bind(&grant.target_node)
        .bind(session_id)
        .bind(&grant.session_name)
        .bind(verbs)
        .bind(&grant.audience_subject_kind)
        .bind(&grant.audience_subject_id)
        .bind(&grant.audience_display)
        .bind(&grant.issued_by)
        .bind(grant.created_at)
        .bind(grant.expires_at)
        .bind(grant.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn access_grant_get(
        &self,
        network_id: &str,
        grant_id: &str,
    ) -> Result<Option<AccessGrant>, StoreError> {
        let row = sqlx::query(&access_grant_select_sql(
            "WHERE network_id = $1 AND id = $2",
        ))
        .bind(network_id)
        .bind(grant_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_access_grant).transpose()
    }

    async fn access_grant_list(
        &self,
        network_id: &str,
        filter: AccessGrantFilter,
    ) -> Result<Vec<AccessGrant>, StoreError> {
        let mut query = access_grant_select_sql("WHERE network_id = $1").to_string();
        let mut param = 2;
        let mut target_node = None;
        let mut audience_subject_id = None;
        if !filter.target_node.trim().is_empty() {
            query.push_str(&format!(" AND target_node = ${param}"));
            target_node = Some(filter.target_node.trim().to_string());
            param += 1;
        }
        if !filter.audience_subject_id.trim().is_empty() {
            query.push_str(&format!(" AND audience_subject_id = ${param}"));
            audience_subject_id = Some(filter.audience_subject_id.trim().to_string());
            param += 1;
        }
        if filter.active_only {
            query.push_str(&format!(
                " AND expires_at > ${param} AND revoked_at IS NULL"
            ));
        }
        query.push_str(" ORDER BY created_at DESC");

        let mut q = sqlx::query(&query).bind(network_id);
        if let Some(target_node) = target_node {
            q = q.bind(target_node);
        }
        if let Some(audience_subject_id) = audience_subject_id {
            q = q.bind(audience_subject_id);
        }
        if filter.active_only {
            q = q.bind(Utc::now());
        }

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_access_grant).collect()
    }

    async fn access_grant_revoke(
        &self,
        network_id: &str,
        grant_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE access_grants
            SET revoked_at = $1
            WHERE network_id = $2 AND id = $3 AND revoked_at IS NULL
            "#,
        )
        .bind(revoked_at)
        .bind(network_id)
        .bind(grant_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn task_event_create(&self, event: TaskEvent) -> Result<LatestTaskValue, StoreError> {
        self.network_ensure(&event.network_id).await?;
        let session_id = i32::try_from(event.session_id)
            .map_err(|_| StoreError::Invalid("session_id out of range".to_string()))?;
        let timestamp = parse_task_timestamp(&event.timestamp)?;
        let row = sqlx::query(
            r#"
            INSERT INTO task_events
                (event_id, network_id, node_name, session_id, session_name, summary, state, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING stream_seq
            "#,
        )
        .bind(&event.event_id)
        .bind(&event.network_id)
        .bind(&event.node_name)
        .bind(session_id)
        .bind(&event.session_name)
        .bind(&event.summary)
        .bind(&event.state)
        .bind(timestamp)
        .fetch_optional(&self.pool)
        .await?;

        let watch = if let Some(row) = row {
            TaskWatchEvent {
                seq: row.try_get("stream_seq")?,
                event,
            }
        } else {
            let row = sqlx::query(&task_event_select_sql("WHERE event_id = $1"))
                .bind(&event.event_id)
                .fetch_one(&self.pool)
                .await?;
            row_to_task_watch_event(row)?
        };
        Ok(latest_task_from_event(watch.seq, &watch.event))
    }

    async fn task_latest_list(
        &self,
        filter: TaskFilter,
    ) -> Result<Vec<LatestTaskValue>, StoreError> {
        let mut event_filter = filter.clone();
        event_filter.state.clear();
        let rows = self.task_event_rows(event_filter, None).await?;
        let mut latest: HashMap<(String, String, u32), LatestTaskValue> = HashMap::new();
        for watch in rows.into_iter().map(row_to_task_watch_event) {
            let watch = watch?;
            let key = (
                watch.event.network_id.clone(),
                watch.event.node_name.clone(),
                watch.event.session_id,
            );
            let value = latest_task_from_event(watch.seq, &watch.event);
            if latest
                .get(&key)
                .is_none_or(|existing| existing.stream_seq < value.stream_seq)
            {
                latest.insert(key, value);
            }
        }
        let mut values = latest.into_values().collect::<Vec<_>>();
        retain_latest_by_state(&mut values, &filter);
        sort_latest_tasks(&mut values);
        Ok(values)
    }

    async fn task_events_after(
        &self,
        filter: TaskFilter,
        after_seq: i64,
    ) -> Result<Vec<TaskWatchEvent>, StoreError> {
        let rows = self.task_event_rows(filter, Some(after_seq)).await?;
        rows.into_iter().map(row_to_task_watch_event).collect()
    }

    async fn task_earliest_seq(&self, network_id: &str) -> Result<i64, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT COALESCE(MIN(stream_seq), 0)::BIGINT AS earliest
            FROM task_events
            WHERE network_id = $1
            "#,
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("earliest")?)
    }
}

fn network_list_sql(subject: Option<&str>) -> &'static str {
    match subject {
        None => {
            r#"
            SELECT
                n.network_id,
                n.organization_id,
                n.created_at,
                COALESCE(node_counts.count, 0) AS node_count,
                COALESCE(invite_counts.count, 0) AS invite_count
            FROM networks n
            LEFT JOIN (
                SELECT network_id, COUNT(*) AS count
                FROM nodes
                GROUP BY network_id
            ) node_counts ON node_counts.network_id = n.network_id
            LEFT JOIN (
                SELECT network_id, COUNT(*) AS count
                FROM invites
                WHERE expires_at > $1
                GROUP BY network_id
            ) invite_counts ON invite_counts.network_id = n.network_id
            ORDER BY n.network_id
            "#
        }
        Some(_) => {
            r#"
            SELECT
                n.network_id,
                n.organization_id,
                n.created_at,
                COALESCE(node_counts.count, 0) AS node_count,
                COALESCE(invite_counts.count, 0) AS invite_count
            FROM networks n
            INNER JOIN network_members nm ON nm.network_id = n.network_id
            LEFT JOIN (
                SELECT network_id, COUNT(*) AS count
                FROM nodes
                GROUP BY network_id
            ) node_counts ON node_counts.network_id = n.network_id
            LEFT JOIN (
                SELECT network_id, COUNT(*) AS count
                FROM invites
                WHERE expires_at > $1
                GROUP BY network_id
            ) invite_counts ON invite_counts.network_id = n.network_id
            WHERE nm.subject = $2
              AND n.organization_id = $3
            ORDER BY n.network_id
            "#
        }
    }
}

fn network_list_by_organization_sql() -> &'static str {
    r#"
    SELECT
        n.network_id,
        n.organization_id,
        n.created_at,
        COALESCE(node_counts.count, 0) AS node_count,
        COALESCE(invite_counts.count, 0) AS invite_count
    FROM networks n
    LEFT JOIN (
        SELECT network_id, COUNT(*) AS count
        FROM nodes
        GROUP BY network_id
    ) node_counts ON node_counts.network_id = n.network_id
    LEFT JOIN (
        SELECT network_id, COUNT(*) AS count
        FROM invites
        WHERE expires_at > $1
        GROUP BY network_id
    ) invite_counts ON invite_counts.network_id = n.network_id
    WHERE n.organization_id = $2
    ORDER BY n.network_id
    "#
}

fn rows_to_networks(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<Network>, StoreError> {
    rows.into_iter()
        .map(|row| {
            Ok(Network {
                id: row.try_get("network_id")?,
                organization_id: row.try_get("organization_id")?,
                created_at: row.try_get("created_at")?,
                node_count: row.try_get("node_count")?,
                invite_count: row.try_get("invite_count")?,
            })
        })
        .collect()
}

fn row_to_invite(row: sqlx::postgres::PgRow) -> Result<Invite, StoreError> {
    Ok(Invite {
        id: row.try_get("id")?,
        network_id: row.try_get("network_id")?,
        organization_id: row.try_get("organization_id")?,
        created_by_user_id: row.try_get("created_by_user_id")?,
        code_hash: row.try_get("code_hash")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn required_identifier(value: &str, field: &str) -> Result<String, StoreError> {
    let value = value.trim();
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| StoreError::Invalid(format!("{field} required")))
}

fn validate_enrollment_node_binding(
    enrollment: &NodeEnrollment,
    node: &NodeRecord,
) -> Result<(), StoreError> {
    let fixed_name = enrollment.node_name.trim();
    if node.network_id != enrollment.network_id
        || node.owner_subject != enrollment.owner_subject
        || node.authorized_by != enrollment.issued_by
        || node.enrollment_id != enrollment.id
        || node.name.trim().is_empty()
        || (!fixed_name.is_empty() && node.name != fixed_name)
    {
        return Err(StoreError::Invalid(
            "node does not match enrollment authority".to_owned(),
        ));
    }
    Ok(())
}

fn row_to_kv_entry(row: sqlx::postgres::PgRow) -> Result<KVEntry, StoreError> {
    Ok(KVEntry {
        key: row.try_get("key")?,
        value: row.try_get("value")?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn row_to_group(row: sqlx::postgres::PgRow) -> Result<Group, StoreError> {
    Ok(Group {
        network_id: row.try_get("network_id")?,
        name: row.try_get("name")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

fn row_to_group_member(row: sqlx::postgres::PgRow) -> Result<GroupMember, StoreError> {
    Ok(GroupMember {
        network_id: row.try_get("network_id")?,
        group_name: row.try_get("group_name")?,
        node_name: row.try_get("node_name")?,
        session_name: row.try_get("session_name")?,
        created_at: row.try_get("created_at")?,
    })
}

fn row_to_group_policy(row: sqlx::postgres::PgRow) -> Result<GroupPolicy, StoreError> {
    Ok(GroupPolicy {
        network_id: row.try_get("network_id")?,
        group_name: row.try_get("group_name")?,
        messages_policy: row.try_get("messages_policy")?,
        debug_policy: row.try_get("debug_policy")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_node(row: sqlx::postgres::PgRow) -> Result<NodeRecord, StoreError> {
    Ok(NodeRecord {
        network_id: row.try_get("network_id")?,
        name: row.try_get("name")?,
        peer_url: row.try_get("peer_url")?,
        github_id: row.try_get("github_id")?,
        owner_subject: row.try_get("owner_subject")?,
        authorized_by: row.try_get("authorized_by")?,
        enrollment_id: row.try_get("enrollment_id")?,
        authorized_at: row.try_get("authorized_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}

fn serialize_base64<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(value))
}

fn row_to_node_enrollment(row: sqlx::postgres::PgRow) -> Result<NodeEnrollment, StoreError> {
    Ok(NodeEnrollment {
        id: row.try_get("id")?,
        network_id: row.try_get("network_id")?,
        owner_subject: row.try_get("owner_subject")?,
        issued_by: row.try_get("issued_by")?,
        node_name: row.try_get("node_name")?,
        token_hash: row.try_get("token_hash")?,
        uses_remaining: row.try_get("uses_remaining")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        redeemed_at: row.try_get("redeemed_at")?,
    })
}

fn access_grant_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, network_id, target_node, session_id::BIGINT AS session_id,
               session_name, verbs, audience_subject_kind, audience_subject_id,
               audience_display, issued_by, created_at, expires_at, revoked_at
        FROM access_grants
        {where_clause}
        "#
    )
}

fn row_to_access_grant(row: sqlx::postgres::PgRow) -> Result<AccessGrant, StoreError> {
    let session_id: Option<i64> = row.try_get("session_id")?;
    let verbs_json: String = row.try_get("verbs")?;
    let verbs = if verbs_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&verbs_json).map_err(|_| StoreError::NotFound)?
    };

    Ok(AccessGrant {
        id: row.try_get("id")?,
        network_id: row.try_get("network_id")?,
        target_node: row.try_get("target_node")?,
        session_id: session_id.and_then(|id| u32::try_from(id).ok()),
        session_name: row.try_get("session_name")?,
        verbs,
        audience_subject_kind: row.try_get("audience_subject_kind")?,
        audience_subject_id: row.try_get("audience_subject_id")?,
        audience_display: row.try_get("audience_display")?,
        issued_by: row.try_get("issued_by")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn task_event_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT stream_seq, event_id, network_id, node_name, session_id::BIGINT AS session_id,
               session_name, summary, state, timestamp
        FROM task_events
        {where_clause}
        "#
    )
}

fn row_to_task_watch_event(row: sqlx::postgres::PgRow) -> Result<TaskWatchEvent, StoreError> {
    let session_id: i64 = row.try_get("session_id")?;
    let timestamp: DateTime<Utc> = row.try_get("timestamp")?;
    Ok(TaskWatchEvent {
        seq: row.try_get("stream_seq")?,
        event: TaskEvent {
            event_id: row.try_get("event_id")?,
            network_id: row.try_get("network_id")?,
            node_name: row.try_get("node_name")?,
            session_id: u32::try_from(session_id)
                .map_err(|_| StoreError::Invalid("session_id out of range".to_string()))?,
            session_name: row.try_get("session_name")?,
            summary: row.try_get("summary")?,
            state: row.try_get("state")?,
            timestamp: timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        },
    })
}

fn parse_task_timestamp(raw: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| StoreError::Invalid("invalid timestamp".to_string()))
}

#[cfg(test)]
mod migration_tests {
    use std::sync::Arc;

    use sha2::{Digest, Sha256};
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    const EXPECTED_MESH_MIGRATION_COUNT: usize = 7;

    include!("store/network_deletion_tests.rs");

    #[derive(Debug, PartialEq, Eq)]
    struct AppliedMigration {
        version: i64,
        description: String,
        success: bool,
        checksum: Vec<u8>,
    }

    async fn applied_migrations(pool: &PgPool) -> anyhow::Result<Vec<AppliedMigration>> {
        sqlx::query(
            r#"
            SELECT version, description, success, checksum
            FROM _sqlx_migrations
            ORDER BY version
            "#,
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| {
            Ok(AppliedMigration {
                version: row.try_get("version")?,
                description: row.try_get("description")?,
                success: row.try_get("success")?,
                checksum: row.try_get("checksum")?,
            })
        })
        .collect()
    }

    async fn startup(database_url: String) -> anyhow::Result<()> {
        PostgresMeshStore::connect(&database_url).await?;
        Ok(())
    }

    fn test_database_url() -> anyhow::Result<String> {
        std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL must be set for Mesh migration tests")
    }

    #[tokio::test]
    async fn invite_consumption_is_bound_to_the_authorized_organization() -> anyhow::Result<()> {
        let store = MemoryStore::new();
        let now = Utc::now();
        store
            .network_create_with_owner("network-beta", "org-beta", "owner-beta", now)
            .await?;
        store
            .invite_create(Invite {
                id: "invite-beta".to_owned(),
                network_id: "network-beta".to_owned(),
                organization_id: "org-beta".to_owned(),
                created_by_user_id: "owner-beta".to_owned(),
                code_hash: "synthetic-hash-beta".to_owned(),
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await?;

        let mismatched = store
            .invite_consume_and_join("synthetic-hash-beta", now, "org-alpha", "member-alpha")
            .await?;
        anyhow::ensure!(mismatched.is_none());
        anyhow::ensure!(
            store
                .invite_get_by_id("network-beta", "invite-beta")
                .await?
                .is_some(),
            "organization mismatch consumed the invitation"
        );
        anyhow::ensure!(
            store
                .network_member_get("network-beta", "member-alpha")
                .await?
                .is_none(),
            "organization mismatch created a cross-organization membership"
        );

        let matched = store
            .invite_consume_and_join("synthetic-hash-beta", now, "org-beta", "member-beta")
            .await?;
        anyhow::ensure!(matched.is_some());
        anyhow::ensure!(
            store
                .network_member_get("network-beta", "member-beta")
                .await?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn mesh_migration_versions_checksums_and_count_are_fixed() {
        let migrations: Vec<_> = MESH_MIGRATOR.iter().collect();
        assert_eq!(migrations.len(), EXPECTED_MESH_MIGRATION_COUNT);

        let versions: Vec<_> = migrations
            .iter()
            .map(|migration| migration.version)
            .collect();
        let mut sorted_unique = versions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();
        assert_eq!(versions, sorted_unique);

        assert_eq!(
            migrations
                .iter()
                .map(|migration| (migration.version, migration.description.to_string()))
                .collect::<Vec<_>>(),
            vec![
                (1, "initial schema".to_string()),
                (2, "network organization ownership".to_string()),
                (3, "contract native invitations".to_string()),
                (4, "retire persistent node bearer".to_string()),
                (5, "retire network auth issuer".to_string()),
                (6, "retire raw auth session device state".to_string()),
                (7, "network deletion".to_string()),
            ]
        );
        assert!(
            migrations
                .iter()
                .all(|migration| migration.checksum.len() == 48)
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn fresh_database_records_mesh_ledger() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let store = PostgresMeshStore::connect(&test_db.url).await?;
            let applied = applied_migrations(&store.pool).await?;
            let registered: Vec<_> = MESH_MIGRATOR.iter().collect();

            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(
                applied
                    .iter()
                    .zip(&registered)
                    .all(|(applied, registered)| {
                        applied.version == registered.version
                            && applied.description == registered.description
                            && applied.success
                            && applied.checksum == registered.checksum.as_ref()
                    })
            );

            let schema_exists: bool =
                sqlx::query_scalar("SELECT to_regclass('public.networks') IS NOT NULL")
                    .fetch_one(&store.pool)
                    .await?;
            anyhow::ensure!(schema_exists);
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn preledger_schema_with_unowned_network_fails_closed_without_backfill()
    -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::raw_sql(include_str!("../migrations/001_initial_schema.sql"))
                .execute(&pool)
                .await?;
            sqlx::query("INSERT INTO networks (network_id, created_at) VALUES ($1, now())")
                .bind("preserved-network")
                .execute(&pool)
                .await?;
            let startup = PostgresMeshStore::connect(&test_db.url).await;
            anyhow::ensure!(
                startup.is_err(),
                "unowned pre-launch network unexpectedly migrated"
            );
            let preserved: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM networks WHERE network_id = $1)")
                    .bind("preserved-network")
                    .fetch_one(&pool)
                    .await?;
            let organization_id_column_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'networks' AND column_name = 'organization_id')",
            )
            .fetch_one(&pool)
            .await?;

            anyhow::ensure!(preserved);
            anyhow::ensure!(!organization_id_column_exists);
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn contract_native_invitation_migration_rejects_nonempty_legacy_table()
    -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::raw_sql(include_str!("../migrations/001_initial_schema.sql"))
                .execute(&pool)
                .await?;
            sqlx::query(
                r#"
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                    success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL,
                    execution_time BIGINT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await?;
            let initial = MESH_MIGRATOR
                .iter()
                .next()
                .context("initial migration missing")?;
            sqlx::query(
                r#"
                INSERT INTO _sqlx_migrations
                    (version, description, success, checksum, execution_time)
                VALUES ($1, $2, true, $3, 0)
                "#,
            )
            .bind(initial.version)
            .bind(initial.description.as_ref())
            .bind(initial.checksum.as_ref())
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO invites
                    (network_id, token, uses_remaining, expires_at, created_at)
                VALUES ('legacy-network', 'legacy-plaintext-capability', 3,
                        now() + interval '1 hour', now())
                "#,
            )
            .execute(&pool)
            .await?;

            let startup = PostgresMeshStore::connect(&test_db.url).await;
            anyhow::ensure!(
                startup.is_err(),
                "nonempty legacy invitation table unexpectedly migrated"
            );
            let preserved: String =
                sqlx::query_scalar("SELECT token FROM invites LIMIT 1")
                    .fetch_one(&pool)
                    .await?;
            let contract_id_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invites' AND column_name = 'id')",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(preserved == "legacy-plaintext-capability");
            anyhow::ensure!(!contract_id_exists);
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn contract_native_invitations_are_hash_only_owned_and_atomically_one_use()
    -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let store = Arc::new(PostgresMeshStore::connect(&test_db.url).await?);
            store
                .network_create_with_owner(
                    "network-alpha",
                    "org-alpha",
                    "user-primary-alpha",
                    Utc::now(),
                )
                .await?;
            let owner = store
                .network_member_get("network-alpha", "user-primary-alpha")
                .await?
                .context("network creation omitted its owner membership")?;
            anyhow::ensure!(owner.role == NETWORK_ROLE_OWNER);
            let raw_code = "cw_inv_contract_capability_must_never_persist";
            let code_hash = format!("{:x}", Sha256::digest(raw_code.as_bytes()));
            // PostgreSQL stores `timestamptz` at microsecond precision. Match
            // that precision so the round-trip assertion compares product
            // fields rather than Chrono's discarded sub-microsecond tail.
            let now = DateTime::<Utc>::from_timestamp_micros(Utc::now().timestamp_micros())
                .context("current time was outside Chrono's supported range")?;
            let invitation = Invite {
                id: "invite-opaque-alpha".to_string(),
                network_id: "network-alpha".to_string(),
                organization_id: "org-alpha".to_string(),
                created_by_user_id: "user-primary-alpha".to_string(),
                code_hash: code_hash.clone(),
                expires_at: now + Duration::hours(1),
                created_at: now,
            };
            store.invite_create(invitation.clone()).await?;

            let stored = store
                .invite_get_by_id("network-alpha", "invite-opaque-alpha")
                .await?
                .context("opaque invitation ID lookup failed")?;
            anyhow::ensure!(stored == invitation);
            anyhow::ensure!(
                store
                    .invite_get_by_id("network-other", "invite-opaque-alpha")
                    .await?
                    .is_none()
            );
            let persisted: (String, String, String, String, String) = sqlx::query_as(
                r#"
                SELECT id, network_id, organization_id, created_by_user_id, code_hash
                FROM invites
                WHERE id = $1
                "#,
            )
            .bind("invite-opaque-alpha")
            .fetch_one(&store.pool)
            .await?;
            anyhow::ensure!(persisted.0 == invitation.id);
            anyhow::ensure!(persisted.1 == invitation.network_id);
            anyhow::ensure!(persisted.2 == invitation.organization_id);
            anyhow::ensure!(persisted.3 == invitation.created_by_user_id);
            anyhow::ensure!(persisted.4 == code_hash);
            anyhow::ensure!(
                ![
                    persisted.0,
                    persisted.1,
                    persisted.2,
                    persisted.3,
                    persisted.4
                ]
                .iter()
                .any(|value| value.contains(raw_code))
            );

            anyhow::ensure!(
                store
                    .invite_consume_and_join(&code_hash, now, "org-other", "cross-org-member")
                    .await?
                    .is_none(),
                "an authorization for another organization consumed the invitation"
            );
            anyhow::ensure!(
                store
                    .invite_get_by_id("network-alpha", "invite-opaque-alpha")
                    .await?
                    .is_some()
            );
            anyhow::ensure!(
                store
                    .network_member_get("network-alpha", "cross-org-member")
                    .await?
                    .is_none()
            );

            let first_store = store.clone();
            let first_hash = code_hash.clone();
            let first = tokio::spawn(async move {
                first_store
                    .invite_consume_and_join(&first_hash, now, "org-alpha", "member-first")
                    .await
            });
            let second_store = store.clone();
            let second_hash = code_hash.clone();
            let second = tokio::spawn(async move {
                second_store
                    .invite_consume_and_join(&second_hash, now, "org-alpha", "member-second")
                    .await
            });
            let consumed = [first.await??, second.await??];
            anyhow::ensure!(
                consumed.iter().filter(|invite| invite.is_some()).count() == 1,
                "one-use invitation was not consumed exactly once"
            );
            anyhow::ensure!(
                store.network_member_count("network-alpha").await? == 2,
                "invitation consumption did not atomically create one member"
            );
            anyhow::ensure!(
                store
                    .invite_get_by_id("network-alpha", "invite-opaque-alpha")
                    .await?
                    .is_none()
            );

            let expired_code = "cw_inv_expired_capability";
            let expired_hash = format!("{:x}", Sha256::digest(expired_code.as_bytes()));
            store
                .invite_create(Invite {
                    id: "invite-expired".to_string(),
                    network_id: "network-alpha".to_string(),
                    organization_id: "org-alpha".to_string(),
                    created_by_user_id: "user-primary-alpha".to_string(),
                    code_hash: expired_hash.clone(),
                    expires_at: now - Duration::seconds(1),
                    created_at: now - Duration::hours(1),
                })
                .await?;
            anyhow::ensure!(
                store
                    .invite_consume_and_join(&expired_hash, now, "org-alpha", "member-expired")
                    .await?
                    .is_none(),
                "expired invitation was consumed"
            );
            let expired_still_stored: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM invites WHERE id = 'invite-expired')",
            )
            .fetch_one(&store.pool)
            .await?;
            anyhow::ensure!(expired_still_stored);
            anyhow::ensure!(store.invite_list("network-alpha").await?.is_empty());
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn network_owner_and_invite_join_transactions_roll_back_on_failure_and_cancellation()
    -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let store = Arc::new(PostgresMeshStore::connect(&test_db.url).await?);
            sqlx::raw_sql(
                r#"
                CREATE FUNCTION reject_or_block_synthetic_mesh_member()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    IF NEW.subject IN ('owner-rejected', 'member-rejected') THEN
                        RAISE EXCEPTION 'synthetic membership rejection';
                    ELSIF NEW.subject = 'member-cancelled' THEN
                        PERFORM pg_advisory_xact_lock(1922);
                    END IF;
                    RETURN NEW;
                END
                $$;
                CREATE TRIGGER reject_or_block_synthetic_mesh_member
                BEFORE INSERT ON network_members
                FOR EACH ROW
                EXECUTE FUNCTION reject_or_block_synthetic_mesh_member();
                "#,
            )
            .execute(&store.pool)
            .await?;

            anyhow::ensure!(
                store
                    .network_create_with_owner(
                        "network-owner-rejected",
                        "org-alpha",
                        "owner-rejected",
                        Utc::now(),
                    )
                    .await
                    .is_err()
            );
            let rejected_network_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM networks WHERE network_id = $1)",
            )
            .bind("network-owner-rejected")
            .fetch_one(&store.pool)
            .await?;
            anyhow::ensure!(
                !rejected_network_exists,
                "failed owner insert left a network without its owner"
            );

            store
                .network_create_with_owner(
                    "network-transaction",
                    "org-alpha",
                    "owner-alpha",
                    Utc::now(),
                )
                .await?;
            let now = Utc::now();
            let rejected_hash = format!("{:x}", Sha256::digest(b"cw_inv_rejected"));
            store
                .invite_create(Invite {
                    id: "invite-rejected".to_owned(),
                    network_id: "network-transaction".to_owned(),
                    organization_id: "org-alpha".to_owned(),
                    created_by_user_id: "owner-alpha".to_owned(),
                    code_hash: rejected_hash.clone(),
                    expires_at: now + Duration::hours(1),
                    created_at: now,
                })
                .await?;
            anyhow::ensure!(
                store
                    .invite_consume_and_join(
                        &rejected_hash,
                        now,
                        "org-alpha",
                        "member-rejected",
                    )
                    .await
                    .is_err()
            );
            anyhow::ensure!(
                store
                    .invite_get_by_id("network-transaction", "invite-rejected")
                    .await?
                    .is_some(),
                "failed membership insert consumed its invitation"
            );
            anyhow::ensure!(
                store
                    .network_member_get("network-transaction", "member-rejected")
                    .await?
                    .is_none()
            );

            let cancelled_hash = format!("{:x}", Sha256::digest(b"cw_inv_cancelled"));
            store
                .invite_create(Invite {
                    id: "invite-cancelled".to_owned(),
                    network_id: "network-transaction".to_owned(),
                    organization_id: "org-alpha".to_owned(),
                    created_by_user_id: "owner-alpha".to_owned(),
                    code_hash: cancelled_hash.clone(),
                    expires_at: now + Duration::hours(1),
                    created_at: now,
                })
                .await?;
            let mut lock_holder = store.pool.acquire().await?;
            sqlx::query("SELECT pg_advisory_lock(1922)")
                .execute(&mut *lock_holder)
                .await?;
            let cancelled_store = Arc::clone(&store);
            let join = tokio::spawn(async move {
                cancelled_store
                    .invite_consume_and_join(
                        &cancelled_hash,
                        now,
                        "org-alpha",
                        "member-cancelled",
                    )
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)",
                    )
                    .fetch_one(&store.pool)
                    .await?;
                    if waiting {
                        return anyhow::Ok(());
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .context("invite join did not reach the transactional membership insert")??;
            join.abort();
            anyhow::ensure!(join.await.is_err_and(|error| error.is_cancelled()));
            sqlx::query("SELECT pg_advisory_unlock(1922)")
                .execute(&mut *lock_holder)
                .await?;
            drop(lock_holder);

            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let invite_exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM invites WHERE id = 'invite-cancelled')",
                    )
                    .fetch_one(&store.pool)
                    .await?;
                    let member_exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM network_members WHERE network_id = 'network-transaction' AND subject = 'member-cancelled')",
                    )
                    .fetch_one(&store.pool)
                    .await?;
                    if invite_exists && !member_exists {
                        return anyhow::Ok(());
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .context("cancelled invite join did not roll back")??;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn raw_auth_retirement_drops_only_empty_legacy_state() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::raw_sql(include_str!("../migrations/001_initial_schema.sql"))
                .execute(&pool)
                .await?;
            sqlx::raw_sql(include_str!(
                "../migrations/002_network_organization_ownership.sql"
            ))
            .execute(&pool)
            .await?;
            sqlx::raw_sql(include_str!(
                "../migrations/003_contract_native_invitations.sql"
            ))
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                    success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL,
                    execution_time BIGINT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await?;
            for migration in MESH_MIGRATOR.iter().take(5) {
                sqlx::query(
                    r#"
                    INSERT INTO _sqlx_migrations
                        (version, description, success, checksum, execution_time)
                    VALUES ($1, $2, true, $3, 0)
                    "#,
                )
                .bind(migration.version)
                .bind(migration.description.as_ref())
                .bind(migration.checksum.as_ref())
                .execute(&pool)
                .await?;
            }
            sqlx::query(
                r#"
                INSERT INTO networks (network_id, created_at, organization_id)
                VALUES ('network-alpha', now(), 'org-alpha')
                "#,
            )
            .execute(&pool)
            .await?;
            drop(pool);

            let store = PostgresMeshStore::connect(&test_db.url).await?;
            let legacy_relations: i64 = sqlx::query_scalar(
                r#"
                SELECT count(*)
                FROM pg_class
                WHERE relnamespace = 'public'::regnamespace
                  AND relname IN (
                    'users', 'sessions', 'oauth_state', 'oidc_users',
                    'oidc_sessions', 'oidc_device_flows', 'device_codes',
                    'github_app'
                  )
                "#,
            )
            .fetch_one(&store.pool)
            .await?;
            let node_token_column_exists: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'nodes'
                      AND column_name = 'token'
                )
                "#,
            )
            .fetch_one(&store.pool)
            .await?;
            let retained_network: String = sqlx::query_scalar(
                "SELECT organization_id FROM networks WHERE network_id = 'network-alpha'",
            )
            .fetch_one(&store.pool)
            .await?;
            let applied = applied_migrations(&store.pool).await?;

            anyhow::ensure!(legacy_relations == 0);
            anyhow::ensure!(!node_token_column_exists);
            anyhow::ensure!(retained_network == "org-alpha");
            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(applied.last().map(|migration| migration.version) == Some(7));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn raw_auth_retirement_refuses_nonempty_legacy_state() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            for migration_sql in [
                include_str!("../migrations/001_initial_schema.sql"),
                include_str!("../migrations/002_network_organization_ownership.sql"),
                include_str!("../migrations/003_contract_native_invitations.sql"),
                include_str!("../migrations/004_retire_persistent_node_bearer.sql"),
                include_str!("../migrations/005_retire_network_auth_issuer.sql"),
            ] {
                sqlx::raw_sql(migration_sql).execute(&pool).await?;
            }
            sqlx::query(
                r#"
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                    success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL,
                    execution_time BIGINT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await?;
            for migration in MESH_MIGRATOR.iter().take(5) {
                sqlx::query(
                    r#"
                    INSERT INTO _sqlx_migrations
                        (version, description, success, checksum, execution_time)
                    VALUES ($1, $2, true, $3, 0)
                    "#,
                )
                .bind(migration.version)
                .bind(migration.description.as_ref())
                .bind(migration.checksum.as_ref())
                .execute(&pool)
                .await?;
            }
            sqlx::query(
                r#"
                INSERT INTO users (github_id, username, created_at, last_login_at)
                VALUES (1, 'legacy-mesh-user', now(), now())
                "#,
            )
            .execute(&pool)
            .await?;
            drop(pool);

            let startup = PostgresMeshStore::connect(&test_db.url).await;
            anyhow::ensure!(
                startup.is_err(),
                "nonempty legacy auth state unexpectedly retired"
            );

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let retained_user_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM users WHERE github_id = 1")
                    .fetch_one(&pool)
                    .await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(retained_user_count == 1);
            anyhow::ensure!(applied.len() == 5);
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn network_auth_issuer_migration_deletes_only_legacy_namespace() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            for migration_sql in [
                include_str!("../migrations/001_initial_schema.sql"),
                include_str!("../migrations/002_network_organization_ownership.sql"),
                include_str!("../migrations/003_contract_native_invitations.sql"),
                include_str!("../migrations/004_retire_persistent_node_bearer.sql"),
            ] {
                sqlx::raw_sql(migration_sql).execute(&pool).await?;
            }
            sqlx::query(
                r#"
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                    success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL,
                    execution_time BIGINT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await?;
            for migration in MESH_MIGRATOR.iter().take(4) {
                sqlx::query(
                    r#"
                    INSERT INTO _sqlx_migrations
                        (version, description, success, checksum, execution_time)
                    VALUES ($1, $2, true, $3, 0)
                    "#,
                )
                .bind(migration.version)
                .bind(migration.description.as_ref())
                .bind(migration.checksum.as_ref())
                .execute(&pool)
                .await?;
            }
            sqlx::query(
                "INSERT INTO networks (network_id, organization_id, created_at) VALUES ('network-alpha', 'org-alpha', now())",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO kv (network_id, namespace, key, value)
                VALUES
                    ('network-alpha', 'mesh.networkauth', 'issuer', '\x0102'),
                    ('network-alpha', 'product.settings', 'retained', '\x0304')
                "#,
            )
            .execute(&pool)
            .await?;
            drop(pool);

            let store = PostgresMeshStore::connect(&test_db.url).await?;
            let legacy_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM kv WHERE namespace = 'mesh.networkauth'")
                    .fetch_one(&store.pool)
                    .await?;
            let retained_value: Vec<u8> = sqlx::query_scalar(
                "SELECT value FROM kv WHERE namespace = 'product.settings' AND key = 'retained'",
            )
            .fetch_one(&store.pool)
            .await?;
            let applied = applied_migrations(&store.pool).await?;

            anyhow::ensure!(legacy_count == 0);
            anyhow::ensure!(retained_value == vec![0x03, 0x04]);
            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(applied.last().map(|migration| migration.version) == Some(7));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn repeated_startup_preserves_ledger_count_and_checksum() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let first_store = PostgresMeshStore::connect(&test_db.url).await?;
            let first = applied_migrations(&first_store.pool).await?;
            drop(first_store);

            let second_store = PostgresMeshStore::connect(&test_db.url).await?;
            let second = applied_migrations(&second_store.pool).await?;

            anyhow::ensure!(first.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(second == first);
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn concurrent_startups_serialize_and_converge() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let mut startups = tokio::task::JoinSet::new();
            for _ in 0..4 {
                startups.spawn(startup(test_db.url.clone()));
            }

            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                while let Some(joined) = startups.join_next().await {
                    joined.context("Mesh startup task panicked")??;
                }
                anyhow::Ok(())
            })
            .await
            .context("concurrent Mesh migrations did not converge")??;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(applied.iter().all(|migration| migration.success));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn conflicting_ledger_fails_closed() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                r#"
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY,
                    description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                    success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL,
                    execution_time BIGINT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO _sqlx_migrations
                    (version, description, success, checksum, execution_time)
                VALUES (1, 'conflicting migration history', true, $1, 0)
                "#,
            )
            .bind(vec![0_u8; 48])
            .execute(&pool)
            .await?;
            drop(pool);

            let startup = PostgresMeshStore::connect(&test_db.url).await;
            anyhow::ensure!(startup.is_err(), "conflicting ledger unexpectedly booted");

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(applied.len() == 1);
            anyhow::ensure!(applied[0].description == "conflicting migration history");
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    struct TestDatabase {
        admin_url: String,
        name: String,
        url: String,
    }

    impl TestDatabase {
        async fn create(admin_url: &str) -> anyhow::Result<Self> {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = format!("cw_rust_mig_test_{}_{seq}_{now}", std::process::id());
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(admin_url)
                .await?;
            sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
                .execute(&admin)
                .await?;
            drop(admin);

            let mut url = url::Url::parse(admin_url)?;
            url.set_path(&name);
            Ok(Self {
                admin_url: admin_url.to_string(),
                name,
                url: url.to_string(),
            })
        }

        async fn drop(self) -> anyhow::Result<()> {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await?;
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote_ident(&self.name)
            ))
            .execute(&admin)
            .await?;
            Ok(())
        }
    }

    fn quote_ident(identifier: &str) -> String {
        format!(r#""{}""#, identifier.replace('"', r#""""#))
    }
}
