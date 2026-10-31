//! Environment lifecycle service.
//!
//! Every state mutation goes through `exec_logged`: the UPDATE plus,
//! when a row actually changed, an `environment_logs` row and an
//! `environment_lifecycle_journal` entry in the same transaction —
//! so the journal stays a faithful recovery record for every transition.

use sqlx::PgPool;

use crate::worker::activity_authority::ActivityAuthority;

/// Mirrors `environmentlifecycle.Snapshot`.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub id: String,
    pub state: String,
    pub desired_state: String,
    pub external_cleanup_complete: bool,
}

/// Mirrors `environmentlifecycle.Action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Noop,
    Create,
    Start,
    Stop,
    RestartSources,
    /// Resume an active resize operation, for example one whose worker
    /// stopped during its final attempt.
    Resize,
    Destroy,
    Unhandled,
}

/// Mirrors `ErrStateNotTransitioned` — matched by callers that treat a
/// lost CAS as a warning.
pub const STATE_NOT_TRANSITIONED: &str = "environment state did not transition";

/// The instant one destroy attempt began proving that an environment's
/// runtime is gone, read from the database clock that also stamps lease
/// transitions.
///
/// A runtime dispatch that settled as ambiguous before this instant had
/// already stopped acting, so every runtime effect it could have left on the
/// environment is removed or proven absent by the cleanup steps that follow.
/// One that settled later may have acted while the proof ran, so it needs a
/// new attempt. Lease expiry is never part of this decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAbsenceProof {
    started_at: chrono::NaiveDateTime,
}

impl RuntimeAbsenceProof {
    /// Call before the first cleanup step of a destroy attempt.
    pub async fn begin(pool: &PgPool) -> anyhow::Result<Self> {
        let started_at = sqlx::query_scalar("SELECT LOCALTIMESTAMP")
            .fetch_one(pool)
            .await
            .map_err(|error| anyhow::anyhow!("read runtime absence proof start: {error}"))?;
        Ok(Self { started_at })
    }
}

/// Mirrors `environmentlifecycle.Store` (the slice the worker needs).
pub trait LifecycleStore {
    fn reset_for_retry(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn compare_and_swap(
        &self,
        env_id: &str,
        from_state: &str,
        to_state: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn compare_and_swap_any(
        &self,
        env_id: &str,
        from_states: &[&str],
        to_state: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn mark_error(
        &self,
        env_id: &str,
        reason: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn mark_started(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn mark_stopped(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn complete_external_cleanup(
        &self,
        env_id: &str,
        already_destroyed: bool,
        proof: RuntimeAbsenceProof,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn schedule_shutdown_after_ttl(
        &self,
        env_id: &str,
        ttl_seconds: i32,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn set_desired_state(
        &self,
        env_id: &str,
        desired_state: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn clear_deletion_grace(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn mark_ttl_warning_sent(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn mark_error_for_states(
        &self,
        env_id: &str,
        reason: &str,
        states: &[&str],
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn refuse_for_no_capacity(
        &self,
        env_id: &str,
        refusal: NoCapacityRefusal,
        states: &[&str],
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn protect(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn unprotect(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn cancel_deletion(
        &self,
        env_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    fn extend_ttl(
        &self,
        env_id: &str,
        additional_seconds: i32,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
}

/// What a start asks of its organization's environment quota: the limits,
/// read before the admission transaction, and the environment's own shape.
pub(crate) struct StartQuota<'a> {
    pub(crate) quota: crate::api::environments::OrgQuota,
    pub(crate) env_type: &'a str,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
}

/// Mirrors `environmentlifecycle.Service` over any store.
pub struct Service<S> {
    store: S,
}

impl Service<PgLifecycleStore> {
    /// Mirrors `NewForPool`.
    pub fn for_pool(pool: PgPool) -> Self {
        Service {
            store: PgLifecycleStore {
                pool,
                authority: None,
            },
        }
    }

    /// Lifecycle service for a Temporal activity. Every mutation and its
    /// paired log/journal rows are fenced by the captured durable intent.
    pub fn for_activity(pool: PgPool, authority: ActivityAuthority) -> Self {
        Service {
            store: PgLifecycleStore {
                pool,
                authority: Some(authority),
            },
        }
    }

    /// Admits a start: under the organization row lock it checks the
    /// environment quota (#3256), the same for every tier (#3381), then
    /// records the start intent, all in one transaction. A
    /// stopped environment that intends to start counts as active, so
    /// concurrent starts in one organization cannot both pass admission
    /// before either becomes active. A refused quota surfaces as the
    /// [`AppError`](codewire_server_core::AppError) inside the error.
    pub(crate) async fn admit_start(
        &self,
        env_id: &str,
        org_id: &str,
        isolation_tier: &str,
        quota: StartQuota<'_>,
    ) -> anyhow::Result<()> {
        if isolation_tier != "standard" && isolation_tier != "confidential" {
            anyhow::bail!("unsupported environment isolation tier {isolation_tier:?}");
        }

        let mut tx = self.store.pool.begin().await?;
        sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await?;
        crate::api::environments::check_quota_in(
            &mut tx,
            quota.quota,
            org_id,
            quota.env_type,
            quota.cpu_millicores,
            quota.memory_mb,
        )
        .await?;
        let entry = if isolation_tier == "confidential" {
            let changed = sqlx::query(
                "UPDATE environments SET desired_state = 'started', error_reason = CASE WHEN error_code = 'no_capacity' THEN NULL ELSE error_reason END, error_code = NULL, state_changed_at = NOW() WHERE id = $1 AND org_id = $2 AND state = 'stopped'",
            )
            .bind(env_id)
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
            if changed.rows_affected() != 1 {
                anyhow::bail!("environment is no longer stopped");
            }
            LogEntry {
                phase: "lifecycle_intent",
                status: "completed",
                message: "desired state -> started (confidential)".into(),
                metadata: serde_json::json!({"kind": "desired_state", "desired_state": "started", "isolation_tier": "confidential"}),
            }
        } else {
            let changed = sqlx::query(
                "UPDATE environments SET desired_state = 'started', error_reason = CASE WHEN error_code = 'no_capacity' THEN NULL ELSE error_reason END, error_code = NULL, state_changed_at = NOW() WHERE id = $1 AND org_id = $2",
            )
            .bind(env_id)
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
            if changed.rows_affected() != 1 {
                anyhow::bail!("environment not found");
            }
            LogEntry {
                phase: "lifecycle_intent",
                status: "completed",
                message: "desired state -> started".into(),
                metadata: serde_json::json!({"kind": "desired_state", "desired_state": "started"}),
            }
        };
        PgLifecycleStore::append_log_and_journal(&mut tx, env_id, entry).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Retries an errored Confidential start: moves it back to pending with
    /// the start intent, fenced on its organization.
    pub async fn retry_confidential_start(&self, env_id: &str, org_id: &str) -> anyhow::Result<()> {
        let mut tx = self.store.pool.begin().await?;
        let changed = sqlx::query(
            r#"UPDATE environments SET state = 'pending', desired_state = 'started', error_reason = NULL, error_code = NULL,
               retry_count = retry_count + 1, state_changed_at = NOW()
               WHERE id = $1 AND org_id = $2 AND state = 'error'"#,
        )
        .bind(env_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            anyhow::bail!("environment is no longer errored");
        }
        PgLifecycleStore::append_log_and_journal(
            &mut tx,
            env_id,
            LogEntry {
                phase: "lifecycle_transition",
                status: "completed",
                message: "state transition error -> pending (confidential)".into(),
                metadata: serde_json::json!({
                    "kind": "state_transition",
                    "from": "error",
                    "to": "pending",
                    "strategy": "retry_reset",
                    "isolation_tier": "confidential",
                }),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

impl<S: LifecycleStore> Service<S> {
    pub fn new(store: S) -> Self {
        Service { store }
    }

    pub async fn reset_for_retry(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .reset_for_retry(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("reset to pending: {e:#}"))
    }

    /// Mirrors `Transition`.
    pub async fn transition(&self, env_id: &str, from: &str, to: &str) -> anyhow::Result<()> {
        let ok = self
            .store
            .compare_and_swap(env_id, from, to)
            .await
            .map_err(|e| anyhow::anyhow!("transition {from}->{to}: {e:#}"))?;
        if !ok {
            anyhow::bail!("transition {from}->{to}: {STATE_NOT_TRANSITIONED}");
        }
        Ok(())
    }

    /// Mirrors `TransitionAny`.
    pub async fn transition_any(
        &self,
        env_id: &str,
        to: &str,
        from_states: &[&str],
    ) -> anyhow::Result<()> {
        let ok = self
            .store
            .compare_and_swap_any(env_id, from_states, to)
            .await
            .map_err(|e| anyhow::anyhow!("transition {from_states:?}->{to}: {e:#}"))?;
        if !ok {
            anyhow::bail!("transition {from_states:?}->{to}: {STATE_NOT_TRANSITIONED}");
        }
        Ok(())
    }

    pub async fn mark_error(&self, env_id: &str, reason: &str) -> anyhow::Result<()> {
        self.store
            .mark_error(env_id, reason)
            .await
            .map_err(|e| anyhow::anyhow!("mark error: {e:#}"))
    }

    pub async fn mark_started(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .mark_started(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("mark started: {e:#}"))
    }

    pub async fn mark_stopped(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .mark_stopped(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("mark stopped: {e:#}"))
    }

    /// Write the durable cleanup marker after `proof`'s attempt removed the
    /// environment's runtime.
    pub async fn complete_external_cleanup(
        &self,
        env_id: &str,
        already_destroyed: bool,
        proof: RuntimeAbsenceProof,
    ) -> anyhow::Result<()> {
        self.store
            .complete_external_cleanup(env_id, already_destroyed, proof)
            .await
            .map_err(|e| anyhow::anyhow!("complete external cleanup: {e:#}"))
    }

    pub async fn schedule_shutdown_after_ttl(
        &self,
        env_id: &str,
        ttl_seconds: i32,
    ) -> anyhow::Result<()> {
        self.store
            .schedule_shutdown_after_ttl(env_id, ttl_seconds)
            .await
            .map_err(|e| anyhow::anyhow!("schedule shutdown after ttl: {e:#}"))
    }

    pub async fn set_desired_state(&self, env_id: &str, desired: &str) -> anyhow::Result<()> {
        self.store
            .set_desired_state(env_id, desired)
            .await
            .map_err(|e| anyhow::anyhow!("set desired state to {desired}: {e:#}"))
    }

    pub async fn clear_deletion_grace(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .clear_deletion_grace(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("clear deletion grace: {e:#}"))
    }

    pub async fn mark_ttl_warning_sent(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .mark_ttl_warning_sent(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("mark ttl warning sent: {e:#}"))
    }

    pub async fn mark_error_for_states(
        &self,
        env_id: &str,
        reason: &str,
        states: &[&str],
    ) -> anyhow::Result<bool> {
        self.store
            .mark_error_for_states(env_id, reason, states)
            .await
            .map_err(|e| anyhow::anyhow!("mark error for states {states:?}: {e:#}"))
    }

    /// Ends a create or a start the cluster has no room for, with its code and
    /// message, and states the next step: the next reconcile destroys a create
    /// and stops a start. Nothing retries it (#3635).
    pub async fn refuse_for_no_capacity(
        &self,
        env_id: &str,
        refusal: NoCapacityRefusal,
        states: &[&str],
    ) -> anyhow::Result<bool> {
        self.store
            .refuse_for_no_capacity(env_id, refusal, states)
            .await
            .map_err(|e| anyhow::anyhow!("refuse for no capacity from {states:?}: {e:#}"))
    }

    /// Mirrors `Protect`: Ok(true) → a live row was protected.
    pub async fn protect(&self, env_id: &str) -> anyhow::Result<bool> {
        self.store
            .protect(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("protect environment: {e:#}"))
    }

    pub async fn unprotect(&self, env_id: &str) -> anyhow::Result<()> {
        self.store
            .unprotect(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("unprotect environment: {e:#}"))
    }

    /// Mirrors `CancelDeletion`: Ok(true) → a pending deletion existed.
    pub async fn cancel_deletion(&self, env_id: &str) -> anyhow::Result<bool> {
        self.store
            .cancel_deletion(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("cancel deletion: {e:#}"))
    }

    /// Mirrors `ExtendTTL`: Ok(true) → the environment was live.
    pub async fn extend_ttl(&self, env_id: &str, additional_seconds: i32) -> anyhow::Result<bool> {
        self.store
            .extend_ttl(env_id, additional_seconds)
            .await
            .map_err(|e| anyhow::anyhow!("extend ttl: {e:#}"))
    }

    /// Mirrors `PrepareStop`: Ok(true) → proceed with the stop.
    pub async fn prepare_stop(&self, snap: &Snapshot) -> anyhow::Result<bool> {
        match snap.state.as_str() {
            "running" => {
                self.transition(&snap.id, "running", "stopping").await?;
                Ok(true)
            }
            "stopping" => Ok(true),
            _ => Ok(false),
        }
    }

    pub async fn complete_stop(&self, env_id: &str) -> anyhow::Result<()> {
        self.transition(env_id, "stopping", "stopped").await
    }

    /// Mirrors `PrepareStart`.
    pub async fn prepare_start(&self, snap: &Snapshot) -> anyhow::Result<bool> {
        match snap.state.as_str() {
            "stopped" | "error" => {
                self.transition_any(&snap.id, "starting", &["stopped", "error"])
                    .await?;
                Ok(true)
            }
            // An interrupted Start resumes its runtime checks without
            // resetting the persisted setup/install phase.
            "starting" => Ok(true),
            _ => Ok(false),
        }
    }

    pub async fn complete_start(&self, env_id: &str) -> anyhow::Result<()> {
        self.transition(env_id, "starting", "running").await
    }

    /// Mirrors `PrepareDestroy`.
    pub async fn prepare_destroy(&self, snap: &Snapshot) -> anyhow::Result<bool> {
        match snap.state.as_str() {
            "destroyed" => Ok(!snap.external_cleanup_complete),
            "destroying" => Ok(true),
            other => {
                self.transition(&snap.id, other, "destroying").await?;
                Ok(true)
            }
        }
    }

    pub async fn complete_destroy(
        &self,
        env_id: &str,
        proof: RuntimeAbsenceProof,
    ) -> anyhow::Result<()> {
        self.complete_external_cleanup(env_id, false, proof).await
    }

    /// Mirrors `Reconcile`: next action from the snapshot; the
    /// error→pending retry reset happens here, like in Go.
    pub async fn reconcile(&self, snap: &Snapshot) -> anyhow::Result<Action> {
        if snap.desired_state == "destroyed" && !snap.external_cleanup_complete {
            return Ok(Action::Destroy);
        }
        if snap.state == snap.desired_state
            || (snap.desired_state == "started" && snap.state == "running")
        {
            return Ok(Action::Noop);
        }
        let (d, s) = (snap.desired_state.as_str(), snap.state.as_str());
        match (d, s) {
            ("started", "creating") => Ok(Action::Create),
            ("started", "starting") => Ok(Action::Create),
            ("started", "stopped") => Ok(Action::Start),
            ("stopped", "running") => Ok(Action::Stop),
            ("started", "pending") => Ok(Action::Create),
            ("started", "error") => {
                self.reset_for_retry(&snap.id).await?;
                Ok(Action::Create)
            }
            ("stopped", "stopping") => Ok(Action::Stop),
            ("started", "stopping") => Ok(Action::RestartSources),
            ("resized", "resizing") => Ok(Action::Resize),
            ("destroyed", _) => Ok(Action::Destroy),
            _ => Ok(Action::Unhandled),
        }
    }
}

/// `environments.error_code` of a create or start the cluster had no room for.
pub const NO_CAPACITY_ERROR_CODE: &str = "no_capacity";

/// How a create or a start ends when the cluster has no room for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoCapacityRefusal {
    pub message: &'static str,
    pub state: &'static str,
    pub desired_state: &'static str,
}

impl NoCapacityRefusal {
    /// The create handler also resumes a start and retries an errored sandbox,
    /// so only one that never ran may be destroyed; any other keeps its files.
    pub fn for_create(never_ran: bool) -> Self {
        if never_ran { Self::CREATE } else { Self::START }
    }

    /// A create leaves nothing behind: the next reconcile destroys it through
    /// the normal destroy, and it stops counting against quota now.
    pub const CREATE: Self = Self {
        message: "No capacity right now. Try again shortly.",
        state: "error",
        desired_state: "destroyed",
    };
    /// A stopped sandbox's volume cannot leave its node, so it goes back to
    /// stopped, through the normal stop, with its files untouched.
    pub const START: Self = Self {
        message: "The node holding this sandbox is full. Its files are safe. Try again shortly.",
        state: "stopping",
        desired_state: "stopped",
    };
}

// ── Postgres store (port of pgstore.go, worker-used slice) ─────────────

#[derive(Clone)]
pub struct PgLifecycleStore {
    pub pool: PgPool,
    authority: Option<ActivityAuthority>,
}

struct LogEntry {
    phase: &'static str,
    status: &'static str,
    message: String,
    metadata: serde_json::Value,
}

impl PgLifecycleStore {
    /// Mirrors `execLogged`: UPDATE + (rows>0 → lifecycle log + journal)
    /// in one transaction. Returns rows_affected.
    async fn exec_logged(
        &self,
        env_id: &str,
        query: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
        entry: LogEntry,
    ) -> anyhow::Result<u64> {
        let mut tx = self.pool.begin().await?;
        if let Some(authority) = &self.authority {
            authority.lock_transaction(&mut tx).await?;
        }
        let tag = query.execute(&mut *tx).await?;
        if tag.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(0);
        }

        Self::append_log_and_journal(&mut tx, env_id, entry).await?;
        tx.commit().await?;
        Ok(tag.rows_affected())
    }

    async fn append_log_and_journal(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        env_id: &str,
        entry: LogEntry,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO environment_logs (id, environment_id, phase, status, message, metadata)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(env_id)
        .bind(entry.phase)
        .bind(entry.status)
        .bind(&entry.message)
        .bind(&entry.metadata)
        .execute(&mut **tx)
        .await?;

        // journalEntryFromLifecycleLog: kind/actor/from/to/checkpoint
        // derived from the phase + string-typed metadata values.
        let meta_str = |key: &str| -> Option<String> {
            entry
                .metadata
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let (kind, from_state, to_state, checkpoint) = match entry.phase {
            "lifecycle_transition" => ("transition", meta_str("from"), meta_str("to"), None),
            "lifecycle_checkpoint" => ("checkpoint", None, None, meta_str("kind")),
            "lifecycle_error" => ("error", meta_str("from"), None, None),
            "lifecycle_intent" => ("intent", None, meta_str("desired_state"), meta_str("kind")),
            "lifecycle_warning" => ("warning", None, None, meta_str("kind")),
            "lifecycle_observation" => ("observation", None, None, meta_str("kind")),
            other => (other, None, None, None),
        };
        let null_if_empty = |v: Option<String>| v.filter(|s| !s.is_empty());

        sqlx::query(
            r#"INSERT INTO environment_lifecycle_journal
               (id, environment_id, kind, actor, phase, status, from_state, to_state, checkpoint, reason, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(env_id)
        .bind(kind)
        .bind("lifecycle_service")
        .bind(entry.phase)
        .bind(entry.status)
        .bind(null_if_empty(from_state))
        .bind(null_if_empty(to_state))
        .bind(null_if_empty(checkpoint))
        .bind(if entry.message.is_empty() {
            None
        } else {
            Some(entry.message.as_str())
        })
        .bind(&entry.metadata)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

impl LifecycleStore for PgLifecycleStore {
    async fn reset_for_retry(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                r#"UPDATE environments SET state = 'pending', error_reason = NULL, error_code = NULL,
                   retry_count = retry_count + 1, state_changed_at = NOW()
                   WHERE id = $1 AND state = 'error'"#,
            )
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_transition",
                status: "completed",
                message: "state transition error -> pending (retry reset)".into(),
                metadata: serde_json::json!({
                    "kind": "state_transition",
                    "from": "error",
                    "to": "pending",
                    "strategy": "retry_reset",
                }),
            },
        )
        .await?;
        Ok(())
    }

    async fn compare_and_swap(
        &self,
        env_id: &str,
        from_state: &str,
        to_state: &str,
    ) -> anyhow::Result<bool> {
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET state = $1, state_changed_at = NOW()
                       WHERE id = $2 AND state = $3"#,
                )
                .bind(to_state)
                .bind(env_id)
                .bind(from_state),
                LogEntry {
                    phase: "lifecycle_transition",
                    status: "completed",
                    message: format!("state transition {from_state} -> {to_state}"),
                    metadata: serde_json::json!({
                        "kind": "state_transition",
                        "from": from_state,
                        "to": to_state,
                    }),
                },
            )
            .await?;
        Ok(rows == 1)
    }

    async fn compare_and_swap_any(
        &self,
        env_id: &str,
        from_states: &[&str],
        to_state: &str,
    ) -> anyhow::Result<bool> {
        let from_vec: Vec<String> = from_states.iter().map(|s| s.to_string()).collect();
        // Go renders []string with %v: "[a b]".
        let from_disp = format!("[{}]", from_vec.join(" "));
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET state = $3, state_changed_at = NOW()
                       WHERE id = $1 AND state = ANY($2)"#,
                )
                .bind(env_id)
                .bind(from_vec.clone())
                .bind(to_state),
                LogEntry {
                    phase: "lifecycle_transition",
                    status: "completed",
                    message: format!("state transition {from_disp} -> {to_state}"),
                    metadata: serde_json::json!({
                        "kind": "state_transition",
                        "from": from_vec,
                        "to": to_state,
                    }),
                },
            )
            .await?;
        Ok(rows == 1)
    }

    async fn mark_error(&self, env_id: &str, reason: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                r#"UPDATE environments SET state = 'error', error_reason = $1, state_changed_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(reason)
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_error",
                status: "failed",
                message: reason.to_string(),
                metadata: serde_json::json!({ "kind": "error", "reason": reason }),
            },
        )
        .await?;
        Ok(())
    }

    async fn mark_started(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                "UPDATE environments SET started_at = NOW(), stopped_at = NULL
                  WHERE id = $1 AND state = 'running'",
            )
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_checkpoint",
                status: "completed",
                message: "started timestamp recorded".into(),
                metadata: serde_json::json!({ "kind": "started_at" }),
            },
        )
        .await?;
        Ok(())
    }

    async fn mark_stopped(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                "UPDATE environments SET stopped_at = NOW()
                  WHERE id = $1 AND state = 'stopped'",
            )
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_checkpoint",
                status: "completed",
                message: "stopped timestamp recorded".into(),
                metadata: serde_json::json!({ "kind": "stopped_at" }),
            },
        )
        .await?;
        Ok(())
    }

    async fn complete_external_cleanup(
        &self,
        env_id: &str,
        already_destroyed: bool,
        proof: RuntimeAbsenceProof,
    ) -> anyhow::Result<()> {
        let (phase, message, metadata) = if already_destroyed {
            (
                "lifecycle_checkpoint",
                "historical destroyed environment external cleanup verified",
                serde_json::json!({ "kind": "external_cleanup_complete" }),
            )
        } else {
            (
                "lifecycle_transition",
                "external cleanup verified and environment destroyed",
                serde_json::json!({
                    "kind": "external_cleanup_complete",
                    "from": "destroying",
                    "to": "destroyed",
                }),
            )
        };
        let mut tx = self.pool.begin().await?;
        let organization_id: Option<String> =
            sqlx::query_scalar("SELECT org_id FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(&mut *tx)
                .await?;
        let organization_id = organization_id
            .ok_or_else(|| anyhow::anyhow!("environment external cleanup target not found"))?;
        let organization_locked: Option<String> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(&organization_id)
                .fetch_optional(&mut *tx)
                .await?;
        if organization_locked.is_none() {
            return Err(anyhow::anyhow!(
                "environment external cleanup organization not found"
            ));
        }
        if let Some(authority) = &self.authority {
            authority.lock_transaction(&mut tx).await?;
        }
        // The organization row lock above orders this statement after every
        // committed runtime admission; a later admission sees the marker and
        // releases itself. Only dispatches that may target this environment
        // (its own, and organization-wide ones such as creation or leases
        // admitted before leases recorded their environment) can block it:
        // - an active one may still be acting;
        // - an ambiguous one that settled after `proof` began may have acted
        //   while the proof ran, so the next attempt must prove absence again.
        // This environment's ambiguous dispatches that settled before `proof`
        // began are resolved here, in the same statement as the marker: the
        // proof covers every runtime effect they could have left. An
        // organization-wide one may concern another environment, so it stays
        // for organization deletion to resolve after every environment's
        // proof. A live workspace binding also blocks the marker: destroy
        // releases it once its Pod is observed absent (design §10).
        let tag = sqlx::query(
            r#"WITH target AS (
                       SELECT id, org_id
                       FROM environments
                       WHERE id = $1
                         AND desired_state = 'destroyed'
                         AND state = CASE WHEN $2 THEN 'destroyed' ELSE 'destroying' END
                         AND external_cleanup_completed_at IS NULL
                         AND NOT EXISTS (
                             SELECT 1
                             FROM organization_mutation_leases lease
                             WHERE lease.organization_id = environments.org_id
                               AND lease.mutation_class = 'environment_runtime_dispatch'
                               AND (lease.environment_id = environments.id
                                    OR lease.environment_id IS NULL)
                               AND (lease.state = 'active'
                                    OR (lease.state = 'resolution_required'
                                        AND lease.resolution_required_at >= $3))
                         )
                         AND NOT EXISTS (
                             SELECT 1
                             FROM environment_ports port
                             WHERE port.environment_id = environments.id
                         )
                         AND NOT EXISTS (
                             SELECT 1
                             FROM sandbox_workspace_bindings binding
                             WHERE binding.environment_id = environments.id
                               AND binding.released_at IS NULL
                         )
                       FOR UPDATE
                   ), resolved_dispatches AS (
                       UPDATE organization_mutation_leases lease
                       SET state = 'resolved', resolved_at = NOW(), updated_at = NOW()
                       FROM target
                       WHERE lease.organization_id = target.org_id
                         AND lease.mutation_class = 'environment_runtime_dispatch'
                         AND lease.environment_id = target.id
                         AND lease.state = 'resolution_required'
                         AND lease.resolution_required_at < $3
                       RETURNING lease.id
                   ), closed_sessions AS (
                       UPDATE sandbox_running_sessions session
                       SET ended_at = COALESCE(session.ended_at, NOW()),
                           end_reason = COALESCE(session.end_reason, 'environment_destroyed'),
                           updated_at = CASE
                               WHEN session.ended_at IS NULL THEN NOW()
                               ELSE session.updated_at
                           END
                       FROM target
                       WHERE session.environment_id = target.id
                         AND session.ended_at IS NULL
                       RETURNING session.id
                   ), removed_backend AS (
                       DELETE FROM sandbox_environment_backend backend
                       USING target
                       WHERE backend.environment_id = target.id
                       RETURNING backend.environment_id
                   ), removed_access_binding AS (
                       DELETE FROM platform_environment_access_bindings binding
                       USING target
                       WHERE binding.environment_id = target.id
                       RETURNING binding.environment_id
                   )
                   UPDATE environments env
                   SET state = 'destroyed',
                       state_changed_at = CASE
                           WHEN env.state = 'destroying' THEN NOW()
                           ELSE env.state_changed_at
                       END,
                       destroyed_at = COALESCE(env.destroyed_at, NOW()),
                       external_cleanup_completed_at = NOW()
                   FROM target
                   WHERE env.id = target.id"#,
        )
        .bind(env_id)
        .bind(already_destroyed)
        .bind(proof.started_at)
        .execute(&mut *tx)
        .await?;
        if tag.rows_affected() == 1 {
            Self::append_log_and_journal(
                &mut tx,
                env_id,
                LogEntry {
                    phase,
                    status: "completed",
                    message: message.into(),
                    metadata,
                },
            )
            .await?;
        }
        tx.commit().await?;
        if tag.rows_affected() == 1 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "external cleanup preconditions are not satisfied"
            ))
        }
    }

    async fn schedule_shutdown_after_ttl(
        &self,
        env_id: &str,
        ttl_seconds: i32,
    ) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                r#"UPDATE environments
                   SET shutdown_at = NOW() + make_interval(secs => $1)
                   WHERE id = $2 AND state = 'running'"#,
            )
            .bind(f64::from(ttl_seconds))
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_checkpoint",
                status: "completed",
                message: format!("scheduled shutdown after ttl {ttl_seconds}s"),
                metadata: serde_json::json!({ "kind": "shutdown_at", "ttl_seconds": ttl_seconds }),
            },
        )
        .await?;
        Ok(())
    }

    async fn set_desired_state(&self, env_id: &str, desired_state: &str) -> anyhow::Result<()> {
        // Mirrors SetDesiredState's protection gate on destruction.
        if desired_state == "destroyed" {
            let protected: Option<(bool,)> =
                sqlx::query_as("SELECT protected FROM environments WHERE id = $1")
                    .bind(env_id)
                    .fetch_optional(&self.pool)
                    .await
                    .unwrap_or(None);
            if protected.is_some_and(|(p,)| p) {
                anyhow::bail!("environment is protected from deletion");
            }
        }
        self.exec_logged(
            env_id,
            sqlx::query(
                r#"UPDATE environments SET desired_state = $2, state_changed_at = NOW()
                   WHERE id = $1"#,
            )
            .bind(env_id)
            .bind(desired_state),
            LogEntry {
                phase: "lifecycle_intent",
                status: "completed",
                message: format!("desired state -> {desired_state}"),
                metadata: serde_json::json!({ "kind": "desired_state", "desired_state": desired_state }),
            },
        )
        .await?;
        Ok(())
    }

    async fn clear_deletion_grace(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query(
                r#"UPDATE environments
                   SET deletion_requested_at = NULL,
                       deletion_requested_by = NULL,
                       deletion_grace_until = NULL
                   WHERE id = $1"#,
            )
            .bind(env_id),
            LogEntry {
                phase: "lifecycle_intent",
                status: "completed",
                message: "cleared deletion grace metadata".into(),
                metadata: serde_json::json!({ "kind": "clear_deletion_grace" }),
            },
        )
        .await?;
        Ok(())
    }

    async fn mark_ttl_warning_sent(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query("UPDATE environments SET ttl_warning_sent_at = NOW() WHERE id = $1")
                .bind(env_id),
            LogEntry {
                phase: "lifecycle_warning",
                status: "completed",
                message: "ttl warning sent".into(),
                metadata: serde_json::json!({ "kind": "ttl_warning_sent" }),
            },
        )
        .await?;
        Ok(())
    }

    async fn mark_error_for_states(
        &self,
        env_id: &str,
        reason: &str,
        states: &[&str],
    ) -> anyhow::Result<bool> {
        let states_vec: Vec<String> = states.iter().map(|s| s.to_string()).collect();
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET state = 'error', error_reason = $1, state_changed_at = NOW()
                       WHERE id = $2 AND state = ANY($3)"#,
                )
                .bind(reason)
                .bind(env_id)
                .bind(states_vec.clone()),
                LogEntry {
                    phase: "lifecycle_error",
                    status: "failed",
                    message: reason.to_string(),
                    metadata: serde_json::json!({ "kind": "error", "reason": reason, "from": states_vec }),
                },
            )
            .await?;
        Ok(rows > 0)
    }

    async fn refuse_for_no_capacity(
        &self,
        env_id: &str,
        refusal: NoCapacityRefusal,
        states: &[&str],
    ) -> anyhow::Result<bool> {
        let states_vec: Vec<String> = states.iter().map(|s| s.to_string()).collect();
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments
                       SET state = $1, desired_state = $2, error_code = $3, error_reason = $4,
                           state_changed_at = NOW()
                       WHERE id = $5 AND state = ANY($6) AND desired_state = 'started'"#,
                )
                .bind(refusal.state)
                .bind(refusal.desired_state)
                .bind(NO_CAPACITY_ERROR_CODE)
                .bind(refusal.message)
                .bind(env_id)
                .bind(states_vec.clone()),
                LogEntry {
                    phase: "lifecycle_no_capacity",
                    status: "failed",
                    message: refusal.message.to_string(),
                    metadata: serde_json::json!({
                        "kind": "no_capacity",
                        "from": states_vec,
                        "state": refusal.state,
                        "desired_state": refusal.desired_state,
                    }),
                },
            )
            .await?;
        Ok(rows > 0)
    }

    async fn protect(&self, env_id: &str) -> anyhow::Result<bool> {
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET protected = true,
                       deletion_requested_at = NULL, deletion_requested_by = NULL, deletion_grace_until = NULL
                       WHERE id = $1 AND state NOT IN ('destroyed', 'destroying')"#,
                )
                .bind(env_id),
                LogEntry {
                    phase: "lifecycle_intent",
                    status: "completed",
                    message: "environment protected".into(),
                    metadata: serde_json::json!({ "kind": "protect" }),
                },
            )
            .await?;
        Ok(rows > 0)
    }

    async fn unprotect(&self, env_id: &str) -> anyhow::Result<()> {
        self.exec_logged(
            env_id,
            sqlx::query("UPDATE environments SET protected = false WHERE id = $1").bind(env_id),
            LogEntry {
                phase: "lifecycle_intent",
                status: "completed",
                message: "environment unprotected".into(),
                metadata: serde_json::json!({ "kind": "unprotect" }),
            },
        )
        .await?;
        Ok(())
    }

    async fn cancel_deletion(&self, env_id: &str) -> anyhow::Result<bool> {
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET
                       deletion_requested_at = NULL,
                       deletion_requested_by = NULL,
                       deletion_grace_until = NULL
                       WHERE id = $1 AND deletion_grace_until IS NOT NULL"#,
                )
                .bind(env_id),
                LogEntry {
                    phase: "lifecycle_intent",
                    status: "completed",
                    message: "pending deletion cancelled".into(),
                    metadata: serde_json::json!({ "kind": "cancel_deletion" }),
                },
            )
            .await?;
        Ok(rows > 0)
    }

    async fn extend_ttl(&self, env_id: &str, additional_seconds: i32) -> anyhow::Result<bool> {
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    r#"UPDATE environments SET
                       shutdown_at = GREATEST(COALESCE(shutdown_at, NOW()), NOW()) + make_interval(secs => $1),
                       ttl_warning_sent_at = NULL,
                       deletion_requested_at = NULL,
                       deletion_requested_by = NULL,
                       deletion_grace_until = NULL
                       WHERE id = $2 AND state NOT IN ('destroyed', 'destroying')"#,
                )
                .bind(f64::from(additional_seconds))
                .bind(env_id),
                LogEntry {
                    phase: "lifecycle_intent",
                    status: "completed",
                    message: format!("ttl extended by {additional_seconds}s"),
                    metadata: serde_json::json!({
                        "kind": "extend_ttl",
                        "additional_seconds": additional_seconds,
                    }),
                },
            )
            .await?;
        Ok(rows > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockState {
        calls: Vec<String>,
        cas_result: bool,
    }

    #[derive(Clone)]
    struct MockStore(Arc<Mutex<MockState>>);

    impl MockStore {
        fn new(cas_result: bool) -> Self {
            MockStore(Arc::new(Mutex::new(MockState {
                cas_result,
                ..Default::default()
            })))
        }
        fn calls(&self) -> Vec<String> {
            self.0.lock().unwrap().calls.clone()
        }
    }

    impl LifecycleStore for MockStore {
        async fn reset_for_retry(&self, _: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().calls.push("reset_for_retry".into());
            Ok(())
        }
        async fn compare_and_swap(&self, _: &str, from: &str, to: &str) -> anyhow::Result<bool> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("cas:{from}->{to}"));
            Ok(s.cas_result)
        }
        async fn compare_and_swap_any(
            &self,
            _: &str,
            from: &[&str],
            to: &str,
        ) -> anyhow::Result<bool> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("cas_any:{from:?}->{to}"));
            Ok(s.cas_result)
        }
        async fn mark_error(&self, _: &str, _: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().calls.push("mark_error".into());
            Ok(())
        }
        async fn mark_started(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn mark_stopped(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn complete_external_cleanup(
            &self,
            _: &str,
            _: bool,
            _: RuntimeAbsenceProof,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .calls
                .push("complete_external_cleanup".into());
            Ok(())
        }
        async fn schedule_shutdown_after_ttl(&self, _: &str, _: i32) -> anyhow::Result<()> {
            Ok(())
        }
        async fn set_desired_state(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn clear_deletion_grace(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn mark_ttl_warning_sent(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn mark_error_for_states(
            &self,
            _: &str,
            _: &str,
            _: &[&str],
        ) -> anyhow::Result<bool> {
            Ok(true)
        }
        async fn refuse_for_no_capacity(
            &self,
            _: &str,
            _: NoCapacityRefusal,
            _: &[&str],
        ) -> anyhow::Result<bool> {
            Ok(true)
        }
        async fn protect(&self, _: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
        async fn unprotect(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn cancel_deletion(&self, _: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
        async fn extend_ttl(&self, _: &str, _: i32) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    fn snap(state: &str, desired: &str) -> Snapshot {
        Snapshot {
            id: "env-1".into(),
            state: state.into(),
            desired_state: desired.into(),
            external_cleanup_complete: false,
        }
    }

    #[tokio::test]
    async fn reconcile_matrix_mirrors_go() {
        let svc = Service::new(MockStore::new(true));
        // Noop cases.
        assert_eq!(
            svc.reconcile(&snap("running", "started")).await.unwrap(),
            Action::Noop
        );
        assert_eq!(
            svc.reconcile(&snap("stopped", "stopped")).await.unwrap(),
            Action::Noop
        );
        // Create cases.
        for s in ["creating", "starting", "pending"] {
            assert_eq!(
                svc.reconcile(&snap(s, "started")).await.unwrap(),
                Action::Create,
                "{s}"
            );
        }
        // Start / stop.
        assert_eq!(
            svc.reconcile(&snap("stopped", "started")).await.unwrap(),
            Action::Start
        );
        assert_eq!(
            svc.reconcile(&snap("running", "stopped")).await.unwrap(),
            Action::Stop
        );
        assert_eq!(
            svc.reconcile(&snap("stopping", "stopped")).await.unwrap(),
            Action::Stop
        );
        // Destroy regardless of current state.
        assert_eq!(
            svc.reconcile(&snap("running", "destroyed")).await.unwrap(),
            Action::Destroy
        );
        assert_eq!(
            svc.reconcile(&snap("error", "destroyed")).await.unwrap(),
            Action::Destroy
        );
        // Durable managed source restart does not fall into create recovery.
        assert_eq!(
            svc.reconcile(&snap("stopping", "started")).await.unwrap(),
            Action::RestartSources
        );
        // An interrupted resize resumes its own operation.
        assert_eq!(
            svc.reconcile(&snap("resizing", "resized")).await.unwrap(),
            Action::Resize
        );
    }

    #[tokio::test]
    async fn reconcile_error_started_resets_then_creates() {
        let store = MockStore::new(true);
        let svc = Service::new(store.clone());
        assert_eq!(
            svc.reconcile(&snap("error", "started")).await.unwrap(),
            Action::Create
        );
        assert_eq!(store.calls(), vec!["reset_for_retry".to_string()]);
    }

    #[tokio::test]
    async fn prepare_stop_transitions_only_from_running() {
        let store = MockStore::new(true);
        let svc = Service::new(store.clone());
        assert!(svc.prepare_stop(&snap("running", "stopped")).await.unwrap());
        assert_eq!(store.calls(), vec!["cas:running->stopping".to_string()]);
        assert!(
            svc.prepare_stop(&snap("stopping", "stopped"))
                .await
                .unwrap()
        );
        assert!(!svc.prepare_stop(&snap("stopped", "stopped")).await.unwrap());
        assert!(!svc.prepare_stop(&snap("pending", "stopped")).await.unwrap());
    }

    #[tokio::test]
    async fn prepare_start_accepts_stopped_and_error() {
        let store = MockStore::new(true);
        let svc = Service::new(store.clone());
        assert!(
            svc.prepare_start(&snap("stopped", "started"))
                .await
                .unwrap()
        );
        assert!(svc.prepare_start(&snap("error", "started")).await.unwrap());
        assert!(
            svc.prepare_start(&snap("starting", "started"))
                .await
                .unwrap()
        );
        assert!(
            !svc.prepare_start(&snap("running", "started"))
                .await
                .unwrap()
        );
        assert_eq!(
            store.calls(),
            vec![
                r#"cas_any:["stopped", "error"]->starting"#.to_string(),
                r#"cas_any:["stopped", "error"]->starting"#.to_string()
            ]
        );
    }

    #[tokio::test]
    async fn complete_start_drives_starting_to_running() {
        // The start activity reaches `running` via this CAS once the
        // claim is Ready and the pod IP is recorded (mirroring the create
        // path's MarkRunning), independent of the post-running SSH access
        // steps. A winning CAS (starting -> running) succeeds.
        let store = MockStore::new(true);
        let svc = Service::new(store.clone());
        svc.complete_start("env-1").await.unwrap();
        assert_eq!(store.calls(), vec!["cas:starting->running".to_string()]);
    }

    #[tokio::test]
    async fn complete_start_is_idempotent_when_already_running() {
        // A lost CAS (the env is already `running` — e.g. a Temporal retry
        // of the start activity, or a reconcile that already advanced it)
        // surfaces StateNotTransitioned. The start handler treats this as a
        // no-op rather than a failure, so a stop->start that already
        // reached `running` is not re-flipped to `error`.
        let svc = Service::new(MockStore::new(false));
        let err = svc.complete_start("env-1").await.unwrap_err();
        assert!(
            format!("{err:#}").contains(STATE_NOT_TRANSITIONED),
            "lost complete_start CAS must surface StateNotTransitioned: {err:#}"
        );
    }

    #[tokio::test]
    async fn prepare_destroy_skips_destroyed_resumes_destroying() {
        let store = MockStore::new(true);
        let svc = Service::new(store.clone());
        assert!(
            svc.prepare_destroy(&snap("destroyed", "destroyed"))
                .await
                .unwrap()
        );
        assert!(
            svc.prepare_destroy(&snap("destroying", "destroyed"))
                .await
                .unwrap()
        );
        assert!(
            svc.prepare_destroy(&snap("running", "destroyed"))
                .await
                .unwrap()
        );
        assert_eq!(store.calls(), vec!["cas:running->destroying".to_string()]);
    }

    #[tokio::test]
    async fn prepare_destroy_skips_only_a_proven_destroyed_environment() {
        let store = MockStore::new(true);
        let svc = Service::new(store);
        let mut snapshot = snap("destroyed", "destroyed");
        snapshot.external_cleanup_complete = true;
        assert!(!svc.prepare_destroy(&snapshot).await.unwrap());
    }

    #[tokio::test]
    async fn lost_cas_surfaces_state_not_transitioned() {
        let svc = Service::new(MockStore::new(false));
        let err = svc
            .prepare_stop(&snap("running", "stopped"))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains(STATE_NOT_TRANSITIONED),
            "{err:#}"
        );
        let err = svc.complete_start("env-1").await.unwrap_err();
        assert!(
            format!("{err:#}").contains("transition starting->running"),
            "{err:#}"
        );
    }
}
