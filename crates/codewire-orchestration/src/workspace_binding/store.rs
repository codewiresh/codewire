//! Binding lookup and wakeups for `BindWorkspace` (design §3.6, §4.5).
//!
//! The lookup is one statement over the binding, the backend pointer and the
//! environment, so a released binding, a moved pointer or a non-bindable
//! environment all read as "nothing recorded". The recorder announces a new
//! binding with `pg_notify('workspace_bindings', <pod_uid>)` inside its
//! transaction, so the notification arrives at commit; each process runs one
//! `PgListener` and wakes the waiter for that Pod UID. Waiters also re-query
//! on an interval in case a notification is missed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::Notify;

use crate::worker::environment_auth::WorkspaceCredentialScope;

/// Notification channel the binding recorder publishes Pod UIDs on.
pub const WORKSPACE_BINDINGS_CHANNEL: &str = "workspace_bindings";

/// The listener's own pool: tenant-driven traffic can never exhaust
/// orchestration's main pool.
const BINDING_POOL_CONNECTIONS: u32 = 4;
const BINDING_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(1);
const LISTENER_RETRY: Duration = Duration::from_secs(2);

/// One live binding, read with every bindability condition applied.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveBinding {
    pub environment_id: String,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub claim_uid: String,
    pub sandbox_uid: String,
    pub operation_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub credential_scope: WorkspaceCredentialScope,
    /// The environment's current operation generation, read in the same
    /// statement. Peer tokens and host keys are bound to it.
    pub environment_generation: i64,
    /// The environment's declared working directory, or empty. Read on every
    /// bind, so a restarted Pod gets the current value.
    pub working_directory: String,
    /// The saved project defaults and Git author the daemon writes on every
    /// bind (#3684), read in the same statement. `None` when the stored
    /// environment is not a string map, so setup writes them as before.
    pub defaults: Option<BindDefaults>,
}

/// What [`LiveBinding::defaults`] carries. No `Debug`: the values are the
/// project's own environment defaults and its creator's identity.
#[derive(Clone, PartialEq, Eq)]
pub struct BindDefaults {
    pub environment: std::collections::BTreeMap<String, String>,
    /// `(email, name)`, resolved as setup resolves it; `None` without a user.
    pub git: Option<(String, String)>,
}

impl std::fmt::Debug for LiveBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Identifiers only; a binding holds no credential.
        formatter
            .debug_struct("LiveBinding")
            .field("environment_id", &self.environment_id)
            .field("pod_uid", &self.pod_uid)
            .field("credential_scope", &self.credential_scope)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("workspace binding store is unavailable")]
pub struct BindingStoreUnavailable;

/// Outcome of recording an SSH host public key, write-once per bound Pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyRecord {
    /// The key is now the Pod's key.
    Recorded,
    /// The same key was already recorded for this Pod.
    Unchanged,
    /// A different key (or another environment) is already recorded for
    /// this Pod.
    Conflict,
}

#[async_trait]
pub trait BindingStore: Send + Sync {
    /// The live binding of the reviewed Pod, if one is recorded and its
    /// environment is bindable.
    async fn live_binding(
        &self,
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable>;

    /// Records `public_key` as the SSH host key of the reviewed, bound
    /// `pod_uid` of `environment_id`, noting `generation`. Never overwrites.
    async fn record_host_key(
        &self,
        _environment_id: &str,
        _generation: i64,
        _pod_uid: &str,
        _public_key: &str,
    ) -> Result<HostKeyRecord, BindingStoreUnavailable> {
        Err(BindingStoreUnavailable)
    }

    /// The enabled runtime transport zone `name`, if any.
    async fn transport_zone(
        &self,
        _name: &str,
    ) -> Result<Option<crate::runtime_transport::RuntimeTransportZone>, BindingStoreUnavailable>
    {
        Ok(None)
    }

    /// The environment's exposed application ports, for its access grant.
    async fn app_ports(&self, _environment_id: &str) -> Result<Vec<i32>, BindingStoreUnavailable> {
        Ok(Vec::new())
    }

    /// The Mesh network the environment joins, if any.
    async fn mesh_attachment(
        &self,
        _environment_id: &str,
    ) -> Result<Option<MeshAttachment>, BindingStoreUnavailable> {
        Ok(None)
    }

    /// Stores the digest of one Mesh enrollment code for the bound
    /// `pod_uid` at `generation`.
    async fn issue_mesh_enrollment(
        &self,
        _environment_id: &str,
        _pod_uid: &str,
        _generation: i64,
        _code_sha256: &str,
    ) -> Result<MeshIssueOutcome, BindingStoreUnavailable> {
        Err(BindingStoreUnavailable)
    }

    /// Records the bound `pod_uid`'s Mesh membership report. False when the
    /// environment joins no network.
    async fn report_mesh_attachment(
        &self,
        _environment_id: &str,
        _pod_uid: &str,
        _report: MeshAttachmentReport,
    ) -> Result<bool, BindingStoreUnavailable> {
        Err(BindingStoreUnavailable)
    }
}

pub use crate::environment_mesh::{
    Attachment as MeshAttachment, AttachmentReport as MeshAttachmentReport,
    IssueOutcome as MeshIssueOutcome,
};

fn mesh_store_unavailable(error: sqlx::Error) -> BindingStoreUnavailable {
    tracing::warn!(error = %error, "workspace Mesh attachment store failed");
    BindingStoreUnavailable
}

/// PostgreSQL-backed lookup on the listener's own bounded pool.
pub struct PgBindingStore {
    pool: PgPool,
}

impl PgBindingStore {
    /// A lazily connected pool of [`BINDING_POOL_CONNECTIONS`] with a 1s
    /// acquire timeout, so a flood waits briefly and then fails closed.
    pub fn connect_lazy(database_url: &str) -> anyhow::Result<Self> {
        let pool = codewire_server_core::db::checked_pool_options()
            .max_connections(BINDING_POOL_CONNECTIONS)
            .min_connections(0)
            .acquire_timeout(BINDING_POOL_ACQUIRE_TIMEOUT)
            .idle_timeout(Some(Duration::from_secs(5 * 60)))
            .max_lifetime(Some(Duration::from_secs(30 * 60)))
            .connect_lazy(database_url)?;
        Ok(Self { pool })
    }

    #[cfg(test)]
    pub(crate) fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// One row of the bind statement, named so it reads like the columns.
#[derive(sqlx::FromRow)]
struct LiveBindingRow {
    environment_id: String,
    pod_uid: String,
    namespace: String,
    pod_name: String,
    claim_uid: String,
    sandbox_uid: String,
    operation_generation: i64,
    projection_selection_sha256: Option<String>,
    managed_credential_clients: String,
    credential_scope: String,
    environment_generation: i64,
    working_directory: String,
    environment: Option<serde_json::Value>,
    git_name: Option<String>,
    git_email: Option<String>,
    account_name: Option<String>,
    email: Option<String>,
}

#[async_trait]
impl BindingStore for PgBindingStore {
    async fn live_binding(
        &self,
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        let row: Option<LiveBindingRow> = sqlx::query_as(
            r#"SELECT w.environment_id,
                      w.pod_uid,
                      w.namespace,
                      w.pod_name,
                      w.claim_uid,
                      w.sandbox_uid,
                      w.operation_generation,
                      w.projection_selection_sha256,
                      w.managed_credential_clients,
                      w.credential_scope,
                      e.environment_operation_generation AS environment_generation,
                      COALESCE(e.project_spec->>'working_directory', '') AS working_directory,
                      e.project_spec->'environment' AS environment,
                      u.git_name,
                      u.git_email,
                      u.name AS account_name,
                      u.email
                 FROM sandbox_workspace_bindings w
                 JOIN sandbox_environment_backend b
                   ON b.environment_id = w.environment_id
                  AND b.pod_uid = w.pod_uid
                 JOIN environments e ON e.id = w.environment_id
            LEFT JOIN users u ON u.id = e.created_by
                WHERE w.pod_uid = $1
                  AND w.namespace = $2
                  AND w.pod_name = $3
                  AND w.released_at IS NULL
                  AND b.namespace = w.namespace
                  AND b.bound_at IS NOT NULL
                  AND e.type = 'sandbox'
                  AND e.state IN ('pending', 'creating', 'starting', 'running', 'resizing')
                  AND (e.desired_state = 'started'
                       OR (e.state = 'resizing' AND e.desired_state = 'resized'))
                  AND e.deletion_requested_at IS NULL"#,
        )
        .bind(pod_uid)
        .bind(namespace)
        .bind(pod_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "workspace binding lookup failed");
            BindingStoreUnavailable
        })?;
        row.map(live_binding_from_row).transpose()
    }

    async fn record_host_key(
        &self,
        environment_id: &str,
        generation: i64,
        pod_uid: &str,
        public_key: &str,
    ) -> Result<HostKeyRecord, BindingStoreUnavailable> {
        let unavailable = |error: sqlx::Error| {
            tracing::warn!(error = %error, "workspace SSH host key record failed");
            BindingStoreUnavailable
        };
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Only the bound Pod's key is ever trusted: keys of the environment's
        // released bindings go, so the table stays bounded.
        sqlx::query(
            r#"DELETE FROM sandbox_ssh_host_keys k
                WHERE k.environment_id = $1
                  AND k.pod_uid <> $2
                  AND NOT EXISTS (
                      SELECT 1 FROM sandbox_workspace_bindings w
                       WHERE w.environment_id = k.environment_id
                         AND w.pod_uid = k.pod_uid
                         AND w.released_at IS NULL)"#,
        )
        .bind(environment_id)
        .bind(pod_uid)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        // Write-once per Pod: a recorded key is never replaced.
        let inserted = sqlx::query(
            r#"INSERT INTO sandbox_ssh_host_keys
                   (environment_id, operation_generation, pod_uid, public_key)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (pod_uid) DO NOTHING"#,
        )
        .bind(environment_id)
        .bind(generation)
        .bind(pod_uid)
        .bind(public_key)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?
        .rows_affected();
        let outcome = if inserted == 1 {
            HostKeyRecord::Recorded
        } else {
            let existing: Option<(String, String)> = sqlx::query_as(
                r#"SELECT environment_id, public_key FROM sandbox_ssh_host_keys
                    WHERE pod_uid = $1"#,
            )
            .bind(pod_uid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            match existing {
                Some((environment, key)) if environment == environment_id && key == public_key => {
                    HostKeyRecord::Unchanged
                }
                Some(_) => HostKeyRecord::Conflict,
                None => return Err(BindingStoreUnavailable),
            }
        };
        tx.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    async fn transport_zone(
        &self,
        name: &str,
    ) -> Result<Option<crate::runtime_transport::RuntimeTransportZone>, BindingStoreUnavailable>
    {
        crate::runtime_transport::load_enabled_zone(&self.pool, name)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "workspace binding transport zone lookup failed");
                BindingStoreUnavailable
            })
    }

    async fn app_ports(&self, environment_id: &str) -> Result<Vec<i32>, BindingStoreUnavailable> {
        exposed_app_ports(&self.pool, environment_id)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "workspace binding app port lookup failed");
                BindingStoreUnavailable
            })
    }

    async fn mesh_attachment(
        &self,
        environment_id: &str,
    ) -> Result<Option<MeshAttachment>, BindingStoreUnavailable> {
        crate::environment_mesh::attachment_for(&self.pool, environment_id)
            .await
            .map_err(mesh_store_unavailable)
    }

    async fn issue_mesh_enrollment(
        &self,
        environment_id: &str,
        pod_uid: &str,
        generation: i64,
        code_sha256: &str,
    ) -> Result<MeshIssueOutcome, BindingStoreUnavailable> {
        crate::environment_mesh::issue_enrollment(
            &self.pool,
            environment_id,
            pod_uid,
            generation,
            code_sha256,
        )
        .await
        .map_err(mesh_store_unavailable)
    }

    async fn report_mesh_attachment(
        &self,
        environment_id: &str,
        pod_uid: &str,
        report: MeshAttachmentReport,
    ) -> Result<bool, BindingStoreUnavailable> {
        crate::environment_mesh::report_attachment(&self.pool, environment_id, pod_uid, report)
            .await
            .map_err(mesh_store_unavailable)
    }
}

/// The environment's exposed application ports, ascending and distinct:
/// the set its daemon serves on its tailnet address. A port whose removal
/// was requested is no longer exposed.
pub async fn exposed_app_ports(
    pool: &sqlx::PgPool,
    environment_id: &str,
) -> Result<Vec<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT port FROM environment_ports \
         WHERE environment_id = $1 AND deletion_requested_at IS NULL \
           AND port BETWEEN 1 AND 65535 \
         ORDER BY port",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await
}

/// The SSH host public key recorded by the Pod `environment_id` is currently
/// bound to, with the generation it was recorded at, for the authenticated
/// known-hosts read. `None` when the environment has no live binding or its
/// bound Pod has not recorded a key: a released or replaced Pod's key is
/// never returned.
pub async fn current_host_key(
    pool: &sqlx::PgPool,
    environment_id: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT k.operation_generation, k.public_key
             FROM sandbox_environment_backend b
             JOIN sandbox_workspace_bindings w
               ON w.environment_id = b.environment_id
              AND w.pod_uid = b.pod_uid
              AND w.released_at IS NULL
             JOIN sandbox_ssh_host_keys k
               ON k.environment_id = b.environment_id
              AND k.pod_uid = b.pod_uid
            WHERE b.environment_id = $1"#,
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await
}

fn live_binding_from_row(
    LiveBindingRow {
        environment_id,
        pod_uid,
        namespace,
        pod_name,
        claim_uid,
        sandbox_uid,
        operation_generation,
        projection_selection_sha256,
        managed_credential_clients,
        credential_scope,
        environment_generation,
        working_directory,
        environment,
        git_name,
        git_email,
        account_name,
        email,
    }: LiveBindingRow,
) -> Result<LiveBinding, BindingStoreUnavailable> {
    // The schema constrains the scope; anything else is a broken store.
    let credential_scope =
        WorkspaceCredentialScope::parse(&credential_scope).ok_or(BindingStoreUnavailable)?;
    Ok(LiveBinding {
        environment_id,
        pod_uid,
        namespace,
        pod_name,
        claim_uid,
        sandbox_uid,
        operation_generation,
        projection_selection_sha256,
        managed_credential_clients,
        credential_scope,
        environment_generation,
        working_directory,
        defaults: bind_defaults(environment, git_name, git_email, account_name, email),
    })
}

/// The daemon's defaults from the bind statement's columns. A missing or
/// null `environment` is the empty map, as setup writes it; anything that is
/// not a string map sends no defaults at all.
fn bind_defaults(
    environment: Option<serde_json::Value>,
    git_name: Option<String>,
    git_email: Option<String>,
    account_name: Option<String>,
    email: Option<String>,
) -> Option<BindDefaults> {
    let environment = match environment {
        None | Some(serde_json::Value::Null) => Default::default(),
        Some(value) => serde_json::from_value(value).ok()?,
    };
    let git = email.map(|email| {
        let name = crate::worker::setup::resolve_git_field(
            git_name.as_deref(),
            account_name.as_deref(),
            &email,
        );
        let email = git_email
            .filter(|git_email| !git_email.is_empty())
            .unwrap_or(email);
        (email, name)
    });
    Some(BindDefaults { environment, git })
}

/// Fan-out from the one process-wide listener to the waiter for a Pod UID.
/// Each request holds the only in-flight slot for its Pod UID, so there is at
/// most one waiter per key; `notify_one` keeps a wakeup that arrives between
/// a waiter's query and its wait.
#[derive(Default)]
pub struct BindingNotifications {
    waiters: Mutex<HashMap<String, Arc<Notify>>>,
}

impl BindingNotifications {
    pub(super) fn subscribe(self: &Arc<Self>, pod_uid: &str) -> BindingSubscription {
        let notify = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(pod_uid.to_owned())
            .or_default()
            .clone();
        BindingSubscription {
            notifications: self.clone(),
            pod_uid: pod_uid.to_owned(),
            notify,
        }
    }

    /// Wakes the waiter for `pod_uid`, if any.
    pub fn notify(&self, pod_uid: &str) {
        if let Some(notify) = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(pod_uid)
        {
            notify.notify_one();
        }
    }

    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.waiters.lock().unwrap().len()
    }
}

pub(super) struct BindingSubscription {
    notifications: Arc<BindingNotifications>,
    pod_uid: String,
    notify: Arc<Notify>,
}

impl BindingSubscription {
    pub(super) async fn notified(&self) {
        self.notify.notified().await;
    }
}

impl Drop for BindingSubscription {
    fn drop(&mut self) {
        let mut waiters = self
            .notifications
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The map and this subscription hold the only references.
        if waiters.get(&self.pod_uid).is_some_and(|notify| {
            Arc::ptr_eq(notify, &self.notify) && Arc::strong_count(notify) <= 2
        }) {
            waiters.remove(&self.pod_uid);
        }
    }
}

/// Runs the process-wide `LISTEN workspace_bindings` loop on `pool`,
/// reconnecting after failures. Payloads that are not canonical UIDs are
/// ignored.
pub fn spawn_binding_notification_listener(
    pool: PgPool,
    notifications: Arc<BindingNotifications>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = listen(&pool, &notifications).await {
                tracing::warn!(error = %error, "workspace binding notification listener failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    })
}

async fn listen(pool: &PgPool, notifications: &BindingNotifications) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(WORKSPACE_BINDINGS_CHANNEL).await?;
    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();
        if super::authorize::canonical_uid(payload) {
            notifications.notify(payload);
        }
    }
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";

    #[tokio::test]
    async fn a_notification_between_query_and_wait_is_kept() {
        let notifications = Arc::new(BindingNotifications::default());
        let subscription = notifications.subscribe(POD);
        notifications.notify(POD);
        tokio::time::timeout(Duration::from_secs(1), subscription.notified())
            .await
            .expect("stored wakeup");
        drop(subscription);
        assert_eq!(notifications.waiting(), 0);
        // No subscriber: nothing is stored for a later request.
        notifications.notify(POD);
        assert_eq!(notifications.waiting(), 0);
    }

    #[test]
    fn rows_with_an_unknown_scope_are_refused() {
        let row = |scope: &str| -> LiveBindingRow {
            LiveBindingRow {
                environment_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                pod_uid: POD.into(),
                namespace: "sandboxes".into(),
                pod_name: "workspace".into(),
                claim_uid: "c0ffee00-0bd2-4f11-8b16-9c239851eb52".into(),
                sandbox_uid: "5a4db0c5-0bd2-4f11-8b16-9c239851eb52".into(),
                operation_generation: 3,
                projection_selection_sha256: None,
                managed_credential_clients: String::new(),
                credential_scope: scope.into(),
                environment_generation: 7,
                working_directory: "/workspace/app".into(),
                environment: None,
                git_name: None,
                git_email: None,
                account_name: None,
                email: None,
            }
        };
        assert_eq!(
            live_binding_from_row(row("pod")).unwrap().credential_scope,
            WorkspaceCredentialScope::Pod
        );
        assert_eq!(
            live_binding_from_row(row("node")),
            Err(BindingStoreUnavailable)
        );
    }
    /// #3684: what the daemon is told to write on every bind.
    #[test]
    fn bind_defaults_follow_the_saved_project_and_the_creators_git_author() {
        let defaults = |environment,
                        git_name: Option<&str>,
                        git_email: Option<&str>,
                        name: Option<&str>,
                        email: Option<&str>| {
            bind_defaults(
                environment,
                git_name.map(str::to_owned),
                git_email.map(str::to_owned),
                name.map(str::to_owned),
                email.map(str::to_owned),
            )
        };
        // No declared environment is the empty map, as setup writes it.
        let empty = defaults(None, None, None, None, None).expect("defaults");
        assert!(empty.environment.is_empty());
        assert_eq!(empty.git, None);
        assert_eq!(
            defaults(Some(serde_json::Value::Null), None, None, None, None)
                .expect("defaults")
                .environment
                .len(),
            0
        );
        // The Git author resolves as setup resolves it.
        let set = defaults(
            Some(serde_json::json!({"APP_MODE": "test"})),
            Some("Git Name"),
            Some("git@example.invalid"),
            Some("Account"),
            Some("account@example.invalid"),
        )
        .expect("defaults");
        assert_eq!(set.environment["APP_MODE"], "test");
        assert_eq!(
            set.git,
            Some(("git@example.invalid".into(), "Git Name".into()))
        );
        assert_eq!(
            defaults(None, Some(""), Some(""), None, Some("user@example.invalid"))
                .expect("defaults")
                .git,
            Some(("user@example.invalid".into(), "user".into()))
        );
        // Anything that is not a string map sends no defaults: setup writes them.
        assert!(defaults(Some(serde_json::json!({"A": 1})), None, None, None, None).is_none());
        assert!(defaults(Some(serde_json::json!("A")), None, None, None, None).is_none());
    }
}
