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
use sqlx::postgres::{PgListener, PgPoolOptions};
use tokio::sync::Notify;

use crate::worker::gatewayauth::WorkspaceCredentialScope;

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

/// Outcome of recording an SSH host public key, write-once per environment
/// and operation generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyRecord {
    /// The key is now the generation's key.
    Recorded,
    /// The same key was already recorded.
    Unchanged,
    /// A different key is already recorded for this generation.
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

    /// Records `public_key` as the SSH host key of `environment_id` at
    /// `generation`, from the reviewed `pod_uid`. Never overwrites.
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
}

/// PostgreSQL-backed lookup on the listener's own bounded pool.
pub struct PgBindingStore {
    pool: PgPool,
}

impl PgBindingStore {
    /// A lazily connected pool of [`BINDING_POOL_CONNECTIONS`] with a 1s
    /// acquire timeout, so a flood waits briefly and then fails closed.
    pub fn connect_lazy(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
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

type LiveBindingRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<String>,
    String,
    String,
    i64,
);

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
                      e.environment_operation_generation
                 FROM sandbox_workspace_bindings w
                 JOIN sandbox_environment_backend b
                   ON b.environment_id = w.environment_id
                  AND b.pod_uid = w.pod_uid
                 JOIN environments e ON e.id = w.environment_id
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
        // Only the current generation's key is ever trusted; earlier ones go.
        sqlx::query(
            r#"DELETE FROM sandbox_ssh_host_keys
                WHERE environment_id = $1 AND operation_generation < $2"#,
        )
        .bind(environment_id)
        .bind(generation)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        // Write-once: a recorded key is never replaced.
        let inserted = sqlx::query(
            r#"INSERT INTO sandbox_ssh_host_keys
                   (environment_id, operation_generation, pod_uid, public_key)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (environment_id, operation_generation) DO NOTHING"#,
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
            let existing: Option<String> = sqlx::query_scalar(
                r#"SELECT public_key FROM sandbox_ssh_host_keys
                    WHERE environment_id = $1 AND operation_generation = $2"#,
            )
            .bind(environment_id)
            .bind(generation)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            match existing {
                Some(existing) if existing == public_key => HostKeyRecord::Unchanged,
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

/// The SSH host public key recorded for `environment_id` at its current
/// operation generation, for the authenticated known-hosts read. `None`
/// when the current generation has not recorded one.
pub async fn current_host_key(
    pool: &sqlx::PgPool,
    environment_id: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT k.operation_generation, k.public_key
             FROM sandbox_ssh_host_keys k
             JOIN environments e
               ON e.id = k.environment_id
              AND e.environment_operation_generation = k.operation_generation
            WHERE k.environment_id = $1"#,
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await
}

fn live_binding_from_row(
    (
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
    ): LiveBindingRow,
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
    })
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
            (
                "550e8400-e29b-41d4-a716-446655440000".into(),
                POD.into(),
                "sandboxes".into(),
                "workspace".into(),
                "c0ffee00-0bd2-4f11-8b16-9c239851eb52".into(),
                "5a4db0c5-0bd2-4f11-8b16-9c239851eb52".into(),
                3,
                None,
                String::new(),
                scope.into(),
                7,
            )
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
}
