use std::collections::{HashMap, HashSet};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub user_id: Option<i64>,
    pub sub: Option<String>,
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Network {
    pub id: String,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Invite {
    pub network_id: String,
    pub token: String,
    pub created_by: Option<i64>,
    pub uses_remaining: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeRecord {
    pub network_id: String,
    pub name: String,
    pub token: String,
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
pub struct User {
    pub github_id: i64,
    pub username: String,
    pub avatar_url: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OidcUser {
    pub sub: String,
    pub username: String,
    pub avatar_url: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthState {
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OidcSession {
    pub token: String,
    pub sub: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcDeviceFlow {
    pub poll_token: String,
    pub device_code: String,
    pub network_id: String,
    pub node_name: String,
    pub node_token: String,
    pub expires_at: DateTime<Utc>,
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
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait MeshStore: Send + Sync + 'static {
    async fn session_identity(&self, token: &str) -> Result<Option<SessionIdentity>, StoreError>;
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
    async fn network_list_by_member(&self, subject: &str) -> Result<Vec<Network>, StoreError>;
    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError>;
    async fn network_member_get(
        &self,
        network_id: &str,
        subject: &str,
    ) -> Result<Option<NetworkMember>, StoreError>;
    async fn network_member_count(&self, network_id: &str) -> Result<i64, StoreError>;
    async fn network_member_upsert(&self, member: NetworkMember) -> Result<(), StoreError>;
    async fn invite_create(&self, invite: Invite) -> Result<(), StoreError>;
    async fn invite_get(&self, token: &str) -> Result<Option<Invite>, StoreError>;
    async fn invite_consume(&self, token: &str) -> Result<(), StoreError>;
    async fn invite_list(&self, network_id: &str) -> Result<Vec<Invite>, StoreError>;
    async fn invite_delete(&self, network_id: &str, token: &str) -> Result<(), StoreError>;
    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError>;
    async fn node_get(
        &self,
        network_id: &str,
        name: &str,
    ) -> Result<Option<NodeRecord>, StoreError>;
    async fn node_get_by_token(&self, token: &str) -> Result<Option<NodeRecord>, StoreError>;
    async fn node_list(&self, network_id: &str) -> Result<Vec<NodeRecord>, StoreError>;
    async fn node_list_all(&self) -> Result<Vec<NodeRecord>, StoreError>;
    async fn node_delete(&self, network_id: &str, name: &str) -> Result<(), StoreError>;
    async fn node_enrollment_create(&self, enrollment: NodeEnrollment) -> Result<(), StoreError>;
    async fn node_enrollment_get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<NodeEnrollment>, StoreError>;
    async fn node_enrollment_consume(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
    ) -> Result<Option<NodeEnrollment>, StoreError>;
    async fn user_get_by_username(&self, username: &str) -> Result<Option<User>, StoreError>;
    async fn oauth_state_create(&self, state: OAuthState) -> Result<(), StoreError>;
    async fn oauth_state_consume(&self, state: &str) -> Result<(), StoreError>;
    async fn oidc_user_upsert(&self, user: OidcUser) -> Result<(), StoreError>;
    async fn oidc_user_get_by_sub(&self, sub: &str) -> Result<Option<OidcUser>, StoreError>;
    async fn oidc_user_list_by_username(&self, username: &str)
    -> Result<Vec<OidcUser>, StoreError>;
    async fn oidc_session_create(&self, session: OidcSession) -> Result<(), StoreError>;
    async fn oidc_session_get(&self, token: &str) -> Result<Option<OidcSession>, StoreError>;
    async fn oidc_device_flow_create(&self, flow: OidcDeviceFlow) -> Result<(), StoreError>;
    async fn oidc_device_flow_get(
        &self,
        poll_token: &str,
    ) -> Result<Option<OidcDeviceFlow>, StoreError>;
    async fn oidc_device_flow_complete(
        &self,
        poll_token: &str,
        node_token: &str,
    ) -> Result<(), StoreError>;
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
    networks: HashMap<String, DateTime<Utc>>,
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
    github_users: HashMap<i64, MemoryGitHubUser>,
    github_sessions: HashMap<String, MemoryGitHubSession>,
    oauth_states: HashMap<String, OAuthState>,
    oidc_users: HashMap<String, MemoryOidcUser>,
    oidc_sessions: HashMap<String, OidcSession>,
    oidc_device_flows: HashMap<String, OidcDeviceFlow>,
}

struct MemoryGitHubUser {
    username: String,
}

struct MemoryGitHubSession {
    github_id: i64,
    expires_at: DateTime<Utc>,
}

struct MemoryOidcUser {
    username: String,
    avatar_url: String,
    created_at: DateTime<Utc>,
    last_login_at: DateTime<Utc>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn upsert_github_session(
        &self,
        token: impl Into<String>,
        github_id: i64,
        username: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) {
        let mut state = self.state.lock().await;
        state.github_users.insert(
            github_id,
            MemoryGitHubUser {
                username: username.into(),
            },
        );
        state.github_sessions.insert(
            token.into(),
            MemoryGitHubSession {
                github_id,
                expires_at,
            },
        );
    }

    pub async fn upsert_oidc_session(
        &self,
        token: impl Into<String>,
        sub: impl Into<String>,
        username: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) {
        let mut state = self.state.lock().await;
        let sub = sub.into();
        let token = token.into();
        let now = Utc::now();
        state.oidc_users.insert(
            sub.clone(),
            MemoryOidcUser {
                username: username.into(),
                avatar_url: String::new(),
                created_at: now,
                last_login_at: now,
            },
        );
        state.oidc_sessions.insert(
            token.clone(),
            OidcSession {
                token,
                sub,
                created_at: now,
                expires_at,
            },
        );
    }
}

#[async_trait]
impl MeshStore for MemoryStore {
    async fn session_identity(&self, token: &str) -> Result<Option<SessionIdentity>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();

        if let Some(session) = state.oidc_sessions.get(token)
            && session.expires_at > now
        {
            let username = state
                .oidc_users
                .get(&session.sub)
                .map(|user| user.username.clone())
                .unwrap_or_default();
            return Ok(Some(SessionIdentity {
                user_id: None,
                sub: Some(session.sub.clone()),
                username,
            }));
        }

        if let Some(session) = state.github_sessions.get(token)
            && session.expires_at > now
            && let Some(user) = state.github_users.get(&session.github_id)
        {
            return Ok(Some(SessionIdentity {
                user_id: Some(session.github_id),
                sub: None,
                username: user.username.clone(),
            }));
        }

        Ok(None)
    }

    async fn kv_set(
        &self,
        network_id: &str,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
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
        state
            .networks
            .entry(group.network_id.clone())
            .or_insert_with(Utc::now);
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

    async fn network_list_by_member(&self, subject: &str) -> Result<Vec<Network>, StoreError> {
        let state = self.state.lock().await;
        let allowed = state
            .members
            .iter()
            .filter_map(|((network_id, member_subject), _)| {
                (member_subject == subject).then_some(network_id.as_str())
            })
            .collect::<HashSet<_>>();
        Ok(networks_from_state(&state, Some(&allowed)))
    }

    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .networks
            .entry(network_id.to_string())
            .or_insert_with(Utc::now);
        Ok(())
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
        state
            .networks
            .entry(member.network_id.clone())
            .or_insert_with(Utc::now);
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
        state
            .networks
            .entry(invite.network_id.clone())
            .or_insert_with(Utc::now);
        state.invites.insert(invite.token.clone(), invite);
        Ok(())
    }

    async fn invite_get(&self, token: &str) -> Result<Option<Invite>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .invites
            .get(token)
            .filter(|invite| invite.expires_at > now)
            .cloned())
    }

    async fn invite_consume(&self, token: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let now = Utc::now();
        let invite = state.invites.get_mut(token).ok_or(StoreError::NotFound)?;
        if invite.uses_remaining <= 0 || invite.expires_at <= now {
            return Err(StoreError::NotFound);
        }
        invite.uses_remaining -= 1;
        if invite.uses_remaining <= 0 {
            state.invites.remove(token);
        }
        Ok(())
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

    async fn invite_delete(&self, network_id: &str, token: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if state
            .invites
            .get(token)
            .is_some_and(|invite| invite.network_id == network_id)
        {
            state.invites.remove(token);
        }
        Ok(())
    }

    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .networks
            .entry(node.network_id.clone())
            .or_insert_with(Utc::now);
        let key = (node.network_id.clone(), node.name.clone());
        if let Some(existing) = state.nodes.get_mut(&key) {
            existing.token = node.token;
            existing.peer_url = node.peer_url;
            existing.github_id = node.github_id;
            existing.owner_subject = node.owner_subject;
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

    async fn node_get_by_token(&self, token: &str) -> Result<Option<NodeRecord>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .nodes
            .values()
            .find(|node| node.token == token)
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
        state
            .nodes
            .remove(&(network_id.to_string(), name.to_string()));
        Ok(())
    }

    async fn node_enrollment_create(&self, enrollment: NodeEnrollment) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .networks
            .entry(enrollment.network_id.clone())
            .or_insert_with(Utc::now);
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

    async fn node_enrollment_consume(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
        let mut state = self.state.lock().await;
        let Some(enrollment) = state.node_enrollments.get_mut(token_hash) else {
            return Ok(None);
        };
        if enrollment.uses_remaining <= 0 || enrollment.expires_at <= redeemed_at {
            return Ok(None);
        }
        enrollment.uses_remaining -= 1;
        if enrollment.uses_remaining == 0 {
            enrollment.redeemed_at = Some(redeemed_at);
        }
        Ok(Some(enrollment.clone()))
    }

    async fn user_get_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .github_users
            .iter()
            .find(|(_, user)| user.username == username)
            .map(|(github_id, user)| User {
                github_id: *github_id,
                username: user.username.clone(),
                avatar_url: String::new(),
                created_at: now,
                last_login_at: now,
            }))
    }

    async fn oauth_state_create(&self, state_value: OAuthState) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .oauth_states
            .insert(state_value.state.clone(), state_value);
        Ok(())
    }

    async fn oauth_state_consume(&self, state_value: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let Some(stored) = state.oauth_states.remove(state_value) else {
            return Err(StoreError::NotFound);
        };
        if stored.expires_at <= Utc::now() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn oidc_user_upsert(&self, user: OidcUser) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state.oidc_users.insert(
            user.sub,
            MemoryOidcUser {
                username: user.username,
                avatar_url: user.avatar_url,
                created_at: user.created_at,
                last_login_at: user.last_login_at,
            },
        );
        Ok(())
    }

    async fn oidc_user_get_by_sub(&self, sub: &str) -> Result<Option<OidcUser>, StoreError> {
        let state = self.state.lock().await;
        Ok(state.oidc_users.get(sub).map(|user| OidcUser {
            sub: sub.to_string(),
            username: user.username.clone(),
            avatar_url: user.avatar_url.clone(),
            created_at: user.created_at,
            last_login_at: user.last_login_at,
        }))
    }

    async fn oidc_user_list_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<OidcUser>, StoreError> {
        let state = self.state.lock().await;
        let mut users = state
            .oidc_users
            .iter()
            .filter(|(_, user)| user.username == username)
            .map(|(sub, user)| OidcUser {
                sub: sub.clone(),
                username: user.username.clone(),
                avatar_url: user.avatar_url.clone(),
                created_at: user.created_at,
                last_login_at: user.last_login_at,
            })
            .collect::<Vec<_>>();
        users.sort_by(|a, b| a.sub.cmp(&b.sub));
        Ok(users)
    }

    async fn oidc_session_create(&self, session: OidcSession) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state.oidc_sessions.insert(session.token.clone(), session);
        Ok(())
    }

    async fn oidc_session_get(&self, token: &str) -> Result<Option<OidcSession>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .oidc_sessions
            .get(token)
            .filter(|session| session.expires_at > now)
            .cloned())
    }

    async fn oidc_device_flow_create(&self, flow: OidcDeviceFlow) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .oidc_device_flows
            .insert(flow.poll_token.clone(), flow);
        Ok(())
    }

    async fn oidc_device_flow_get(
        &self,
        poll_token: &str,
    ) -> Result<Option<OidcDeviceFlow>, StoreError> {
        let state = self.state.lock().await;
        let now = Utc::now();
        Ok(state
            .oidc_device_flows
            .get(poll_token)
            .filter(|flow| flow.expires_at > now)
            .cloned())
    }

    async fn oidc_device_flow_complete(
        &self,
        poll_token: &str,
        node_token: &str,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let Some(flow) = state.oidc_device_flows.get_mut(poll_token) else {
            return Err(StoreError::NotFound);
        };
        if flow.expires_at <= Utc::now() {
            return Err(StoreError::NotFound);
        }
        flow.node_token = node_token.to_string();
        Ok(())
    }

    async fn access_grant_create(&self, grant: AccessGrant) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        state
            .networks
            .entry(grant.network_id.clone())
            .or_insert_with(Utc::now);
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
        state
            .networks
            .entry(event.network_id.clone())
            .or_insert_with(Utc::now);
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
        .filter_map(|(id, created_at)| {
            if allowed.is_none_or(|allowed| allowed.contains(id.as_str())) {
                Some(Network {
                    id: id.clone(),
                    created_at: *created_at,
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
    async fn session_identity(&self, token: &str) -> Result<Option<SessionIdentity>, StoreError> {
        let now = Utc::now();

        if let Some(row) = sqlx::query(
            r#"
            SELECT s.sub, COALESCE(u.username, '') AS username
            FROM oidc_sessions s
            LEFT JOIN oidc_users u ON u.sub = s.sub
            WHERE s.token = $1 AND s.expires_at > $2
            "#,
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        {
            return Ok(Some(SessionIdentity {
                user_id: None,
                sub: Some(row.try_get("sub")?),
                username: row.try_get("username")?,
            }));
        }

        let row = sqlx::query(
            r#"
            SELECT s.github_id, u.username
            FROM sessions s
            INNER JOIN users u ON u.github_id = s.github_id
            WHERE s.token = $1 AND s.expires_at > $2
            "#,
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(SessionIdentity {
                user_id: Some(row.try_get("github_id")?),
                sub: None,
                username: row.try_get("username")?,
            }))
        } else {
            Ok(None)
        }
    }

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
        sqlx::query(
            r#"
            INSERT INTO networks (network_id, created_at)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&group.network_id)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;

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

    async fn network_list_by_member(&self, subject: &str) -> Result<Vec<Network>, StoreError> {
        let rows = sqlx::query(network_list_sql(Some(subject)))
            .bind(Utc::now())
            .bind(subject)
            .fetch_all(&self.pool)
            .await?;
        rows_to_networks(rows)
    }

    async fn network_ensure(&self, network_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO networks (network_id, created_at)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(network_id)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
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
        self.network_ensure(&invite.network_id).await?;
        sqlx::query(
            r#"
            INSERT INTO invites
                (network_id, token, created_by, uses_remaining, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&invite.network_id)
        .bind(&invite.token)
        .bind(invite.created_by)
        .bind(invite.uses_remaining)
        .bind(invite.expires_at)
        .bind(invite.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn invite_get(&self, token: &str) -> Result<Option<Invite>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, token, created_by, uses_remaining, expires_at, created_at
            FROM invites
            WHERE token = $1 AND expires_at > $2
            "#,
        )
        .bind(token)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(Invite {
                network_id: row.try_get("network_id")?,
                token: row.try_get("token")?,
                created_by: row.try_get("created_by")?,
                uses_remaining: row.try_get("uses_remaining")?,
                expires_at: row.try_get("expires_at")?,
                created_at: row.try_get("created_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn invite_consume(&self, token: &str) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE invites
            SET uses_remaining = uses_remaining - 1
            WHERE token = $1 AND uses_remaining > 0 AND expires_at > $2
            "#,
        )
        .bind(token)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        let _ = sqlx::query(r#"DELETE FROM invites WHERE token = $1 AND uses_remaining <= 0"#)
            .bind(token)
            .execute(&self.pool)
            .await;
        Ok(())
    }

    async fn invite_list(&self, network_id: &str) -> Result<Vec<Invite>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT network_id, token, created_by, uses_remaining, expires_at, created_at
            FROM invites
            WHERE network_id = $1 AND expires_at > $2
            ORDER BY created_at
            "#,
        )
        .bind(network_id)
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(Invite {
                    network_id: row.try_get("network_id")?,
                    token: row.try_get("token")?,
                    created_by: row.try_get("created_by")?,
                    uses_remaining: row.try_get("uses_remaining")?,
                    expires_at: row.try_get("expires_at")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn invite_delete(&self, network_id: &str, token: &str) -> Result<(), StoreError> {
        sqlx::query(r#"DELETE FROM invites WHERE network_id = $1 AND token = $2"#)
            .bind(network_id)
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn node_register(&self, node: NodeRecord) -> Result<(), StoreError> {
        self.network_ensure(&node.network_id).await?;
        sqlx::query(
            r#"
            INSERT INTO nodes
                (network_id, name, token, peer_url, github_id, owner_subject, authorized_by,
                 enrollment_id, authorized_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (network_id, name) DO UPDATE SET
                token = EXCLUDED.token,
                peer_url = EXCLUDED.peer_url,
                github_id = EXCLUDED.github_id,
                owner_subject = EXCLUDED.owner_subject,
                authorized_by = EXCLUDED.authorized_by,
                enrollment_id = EXCLUDED.enrollment_id,
                last_seen_at = EXCLUDED.last_seen_at
            "#,
        )
        .bind(&node.network_id)
        .bind(&node.name)
        .bind(&node.token)
        .bind(&node.peer_url)
        .bind(node.github_id)
        .bind(&node.owner_subject)
        .bind(&node.authorized_by)
        .bind(&node.enrollment_id)
        .bind(node.authorized_at)
        .bind(node.last_seen_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn node_get_by_token(&self, token: &str) -> Result<Option<NodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, name, token, peer_url, github_id, owner_subject, authorized_by,
                   enrollment_id, authorized_at, last_seen_at
            FROM nodes
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(row_to_node(row)?))
        } else {
            Ok(None)
        }
    }

    async fn node_get(
        &self,
        network_id: &str,
        name: &str,
    ) -> Result<Option<NodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT network_id, name, token, peer_url, github_id, owner_subject, authorized_by,
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
            SELECT network_id, name, token, peer_url, github_id, owner_subject, authorized_by,
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
            SELECT network_id, name, token, peer_url, github_id, owner_subject, authorized_by,
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
        sqlx::query(r#"DELETE FROM nodes WHERE network_id = $1 AND name = $2"#)
            .bind(network_id)
            .bind(name)
            .execute(&self.pool)
            .await?;
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

    async fn node_enrollment_consume(
        &self,
        token_hash: &str,
        redeemed_at: DateTime<Utc>,
    ) -> Result<Option<NodeEnrollment>, StoreError> {
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
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(row_to_node_enrollment(row)?))
        } else {
            Ok(None)
        }
    }

    async fn user_get_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT github_id, username, avatar_url, created_at, last_login_at
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_user).transpose()
    }

    async fn oauth_state_create(&self, state: OAuthState) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_state (state, created_at, expires_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&state.state)
        .bind(state.created_at)
        .bind(state.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn oauth_state_consume(&self, state: &str) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM oauth_state
            WHERE state = $1 AND expires_at > $2
            "#,
        )
        .bind(state)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn oidc_user_upsert(&self, user: OidcUser) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oidc_users (sub, username, avatar_url, created_at, last_login_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (sub) DO UPDATE SET
                username = EXCLUDED.username,
                avatar_url = EXCLUDED.avatar_url,
                last_login_at = EXCLUDED.last_login_at
            "#,
        )
        .bind(&user.sub)
        .bind(&user.username)
        .bind(&user.avatar_url)
        .bind(user.created_at)
        .bind(user.last_login_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn oidc_user_get_by_sub(&self, sub: &str) -> Result<Option<OidcUser>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT sub, username, avatar_url, created_at, last_login_at
            FROM oidc_users
            WHERE sub = $1
            "#,
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_oidc_user).transpose()
    }

    async fn oidc_user_list_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<OidcUser>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT sub, username, avatar_url, created_at, last_login_at
            FROM oidc_users
            WHERE username = $1
            ORDER BY sub
            "#,
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_oidc_user).collect()
    }

    async fn oidc_session_create(&self, session: OidcSession) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oidc_sessions (token, sub, created_at, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&session.token)
        .bind(&session.sub)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn oidc_session_get(&self, token: &str) -> Result<Option<OidcSession>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT token, sub, created_at, expires_at
            FROM oidc_sessions
            WHERE token = $1 AND expires_at > $2
            "#,
        )
        .bind(token)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_oidc_session).transpose()
    }

    async fn oidc_device_flow_create(&self, flow: OidcDeviceFlow) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oidc_device_flows
                (poll_token, device_code, network_id, node_name, node_token, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&flow.poll_token)
        .bind(&flow.device_code)
        .bind(&flow.network_id)
        .bind(&flow.node_name)
        .bind(&flow.node_token)
        .bind(flow.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn oidc_device_flow_get(
        &self,
        poll_token: &str,
    ) -> Result<Option<OidcDeviceFlow>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT poll_token, device_code, network_id, node_name, node_token, expires_at
            FROM oidc_device_flows
            WHERE poll_token = $1 AND expires_at > $2
            "#,
        )
        .bind(poll_token)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_oidc_device_flow).transpose()
    }

    async fn oidc_device_flow_complete(
        &self,
        poll_token: &str,
        node_token: &str,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE oidc_device_flows
            SET node_token = $1
            WHERE poll_token = $2 AND expires_at > $3
            "#,
        )
        .bind(node_token)
        .bind(poll_token)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
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
            ORDER BY n.network_id
            "#
        }
    }
}

fn rows_to_networks(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<Network>, StoreError> {
    rows.into_iter()
        .map(|row| {
            Ok(Network {
                id: row.try_get("network_id")?,
                created_at: row.try_get("created_at")?,
                node_count: row.try_get("node_count")?,
                invite_count: row.try_get("invite_count")?,
            })
        })
        .collect()
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
        token: row.try_get("token")?,
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

fn row_to_user(row: sqlx::postgres::PgRow) -> Result<User, StoreError> {
    Ok(User {
        github_id: row.try_get("github_id")?,
        username: row.try_get("username")?,
        avatar_url: row.try_get("avatar_url")?,
        created_at: row.try_get("created_at")?,
        last_login_at: row.try_get("last_login_at")?,
    })
}

fn row_to_oidc_user(row: sqlx::postgres::PgRow) -> Result<OidcUser, StoreError> {
    Ok(OidcUser {
        sub: row.try_get("sub")?,
        username: row.try_get("username")?,
        avatar_url: row.try_get("avatar_url")?,
        created_at: row.try_get("created_at")?,
        last_login_at: row.try_get("last_login_at")?,
    })
}

fn row_to_oidc_session(row: sqlx::postgres::PgRow) -> Result<OidcSession, StoreError> {
    Ok(OidcSession {
        token: row.try_get("token")?,
        sub: row.try_get("sub")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn row_to_oidc_device_flow(row: sqlx::postgres::PgRow) -> Result<OidcDeviceFlow, StoreError> {
    Ok(OidcDeviceFlow {
        poll_token: row.try_get("poll_token")?,
        device_code: row.try_get("device_code")?,
        network_id: row.try_get("network_id")?,
        node_name: row.try_get("node_name")?,
        node_token: row.try_get("node_token")?,
        expires_at: row.try_get("expires_at")?,
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
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    const EXPECTED_MESH_MIGRATION_COUNT: usize = 1;

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

        let initial = migrations[0];
        assert_eq!(initial.version, 1);
        assert_eq!(initial.description, "initial schema");
        assert_eq!(initial.checksum.len(), 48);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn fresh_database_records_mesh_ledger() -> anyhow::Result<()> {
        let test_db = TestDatabase::create(&test_database_url()?).await?;
        let result = async {
            let store = PostgresMeshStore::connect(&test_db.url).await?;
            let applied = applied_migrations(&store.pool).await?;
            let registered = MESH_MIGRATOR
                .iter()
                .next()
                .context("Mesh migrator must register its initial migration")?;

            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(applied[0].version == registered.version);
            anyhow::ensure!(applied[0].description == registered.description);
            anyhow::ensure!(applied[0].success);
            anyhow::ensure!(applied[0].checksum == registered.checksum.as_ref());

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
    async fn preledger_schema_gains_ledger_without_losing_data() -> anyhow::Result<()> {
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
            drop(pool);

            let store = PostgresMeshStore::connect(&test_db.url).await?;
            let preserved: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM networks WHERE network_id = $1)")
                    .bind("preserved-network")
                    .fetch_one(&store.pool)
                    .await?;
            let applied = applied_migrations(&store.pool).await?;

            anyhow::ensure!(preserved);
            anyhow::ensure!(applied.len() == EXPECTED_MESH_MIGRATION_COUNT);
            anyhow::ensure!(applied[0].success);
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
