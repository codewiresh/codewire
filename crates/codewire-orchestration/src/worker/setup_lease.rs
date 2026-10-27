//! Durable setup phase/process authority for Temporal environment activities.

use std::time::Duration;

use sqlx::{PgPool, Postgres, Transaction};

use super::activity_authority::{ActivityAuthority, AuthorityLost};
use super::env_log::emit_environment_log_in_transaction;
use super::start_timing::{since_accepted, with_since_accepted};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupActivityIdentity {
    pub generation: i64,
    pub activity_id: String,
    pub attempt: i32,
}

impl SetupActivityIdentity {
    pub fn new(generation: i64, activity_id: String, attempt: u32) -> anyhow::Result<Self> {
        let attempt: i32 = attempt.try_into().map_err(|_| AuthorityLost)?;
        if generation <= 0 || activity_id.trim().is_empty() || attempt <= 0 {
            return Err(AuthorityLost.into());
        }
        Ok(Self {
            generation,
            activity_id,
            attempt,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupLeaseStatus {
    Claimed,
    Running,
    Reaping,
}

impl SetupLeaseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::Reaping => "reaping",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "running" => Ok(Self::Running),
            "reaping" => Ok(Self::Reaping),
            _ => Err(AuthorityLost.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupLeaseRecord {
    pub identity: SetupActivityIdentity,
    pub phase: i32,
    pub status: SetupLeaseStatus,
    pub pod_uid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseAcquire {
    Acquired,
    AlreadyComplete(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhasePreparation {
    Ready(PhaseAcquire),
    Recover(SetupLeaseRecord),
}

struct LockedSetupRow {
    generation: i64,
    desired_state: String,
    state: String,
    setup_phase: i32,
    setup_complete: bool,
    setup_owner_generation: Option<i64>,
    setup_owner_activity_id: Option<String>,
    setup_owner_attempt: Option<i32>,
    setup_owner_phase: Option<i32>,
    setup_owner_status: Option<String>,
    setup_owner_pod_uid: Option<String>,
}

#[derive(sqlx::FromRow)]
struct LockedEnvironmentRow {
    generation: i64,
    desired_state: String,
    state: String,
}

#[derive(sqlx::FromRow)]
struct LockedBackendRow {
    setup_phase: i32,
    setup_complete: bool,
    setup_owner_generation: Option<i64>,
    setup_owner_activity_id: Option<String>,
    setup_owner_attempt: Option<i32>,
    setup_owner_phase: Option<i32>,
    setup_owner_status: Option<String>,
    setup_owner_pod_uid: Option<String>,
}

impl LockedSetupRow {
    fn owner(&self) -> anyhow::Result<Option<SetupLeaseRecord>> {
        let absent = self.setup_owner_generation.is_none()
            && self.setup_owner_activity_id.is_none()
            && self.setup_owner_attempt.is_none()
            && self.setup_owner_phase.is_none()
            && self.setup_owner_status.is_none()
            && self.setup_owner_pod_uid.is_none();
        if absent {
            return Ok(None);
        }
        let identity = SetupActivityIdentity {
            generation: self.setup_owner_generation.ok_or(AuthorityLost)?,
            activity_id: self.setup_owner_activity_id.clone().ok_or(AuthorityLost)?,
            attempt: self.setup_owner_attempt.ok_or(AuthorityLost)?,
        };
        if identity.generation <= 0
            || identity.activity_id.trim().is_empty()
            || identity.attempt <= 0
        {
            return Err(AuthorityLost.into());
        }
        let phase = self.setup_owner_phase.ok_or(AuthorityLost)?;
        if phase < 0 {
            return Err(AuthorityLost.into());
        }
        let status =
            SetupLeaseStatus::parse(self.setup_owner_status.as_deref().ok_or(AuthorityLost)?)?;
        let pod_uid = self.setup_owner_pod_uid.clone();
        match status {
            SetupLeaseStatus::Claimed if pod_uid.is_some() => return Err(AuthorityLost.into()),
            SetupLeaseStatus::Running | SetupLeaseStatus::Reaping
                if pod_uid.as_deref().is_none_or(|uid| uid.trim().is_empty()) =>
            {
                return Err(AuthorityLost.into());
            }
            _ => {}
        }
        Ok(Some(SetupLeaseRecord {
            identity,
            phase,
            status,
            pod_uid,
        }))
    }
}

pub struct SetupExecGuard {
    tx: Transaction<'static, Postgres>,
}

pub struct SetupResumeGuard {
    tx: Transaction<'static, Postgres>,
}

pub struct SetupReapGuard {
    tx: Transaction<'static, Postgres>,
}

impl SetupResumeGuard {
    pub async fn commit(self) -> anyhow::Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

impl SetupExecGuard {
    pub async fn commit(self) -> anyhow::Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

impl SetupReapGuard {
    pub async fn commit(self) -> anyhow::Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SetupPhaseAuthority {
    pool: PgPool,
    environment_id: String,
    identity: SetupActivityIdentity,
}

impl SetupPhaseAuthority {
    pub fn new(
        activity_authority: ActivityAuthority,
        identity: SetupActivityIdentity,
    ) -> anyhow::Result<Self> {
        if identity.generation != activity_authority.operation_generation() {
            return Err(AuthorityLost.into());
        }
        Ok(Self {
            pool: activity_authority.pool().clone(),
            environment_id: activity_authority.environment_id().to_string(),
            identity,
        })
    }

    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    pub fn identity(&self) -> &SetupActivityIdentity {
        &self.identity
    }

    pub async fn prepare_phase(&self, phase: i32) -> anyhow::Result<PhasePreparation> {
        self.prepare_phase_inner(phase, false).await
    }

    pub async fn prepare_post_start_mutation(
        &self,
        phase: i32,
    ) -> anyhow::Result<PhasePreparation> {
        self.prepare_phase_inner(phase, true).await
    }

    async fn prepare_phase_inner(
        &self,
        phase: i32,
        allow_setup_complete: bool,
    ) -> anyhow::Result<PhasePreparation> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        if (!allow_setup_complete && row.setup_complete) || row.setup_phase > phase {
            tx.commit().await?;
            return Ok(PhasePreparation::Ready(PhaseAcquire::AlreadyComplete(
                row.setup_phase,
            )));
        }
        if row.setup_phase != phase {
            return Err(AuthorityLost.into());
        }
        let owner = row.owner()?;
        if owner
            .as_ref()
            .is_some_and(|owner| owner.phase != row.setup_phase)
        {
            return Err(AuthorityLost.into());
        }
        match owner {
            None => {
                write_claimed(&mut tx, &self.environment_id, identity, phase).await?;
                tx.commit().await?;
                Ok(PhasePreparation::Ready(PhaseAcquire::Acquired))
            }
            Some(owner) if owner.identity == *identity => match owner.status {
                SetupLeaseStatus::Claimed => {
                    tx.commit().await?;
                    Ok(PhasePreparation::Ready(PhaseAcquire::Acquired))
                }
                SetupLeaseStatus::Running | SetupLeaseStatus::Reaping => {
                    mark_reaping(&mut tx, &self.environment_id, &owner).await?;
                    tx.commit().await?;
                    Ok(PhasePreparation::Recover(owner))
                }
            },
            Some(owner) if takeover_allowed(identity, &owner.identity) => match owner.status {
                SetupLeaseStatus::Claimed => {
                    write_claimed(&mut tx, &self.environment_id, identity, phase).await?;
                    tx.commit().await?;
                    Ok(PhasePreparation::Ready(PhaseAcquire::Acquired))
                }
                SetupLeaseStatus::Running | SetupLeaseStatus::Reaping => {
                    mark_reaping(&mut tx, &self.environment_id, &owner).await?;
                    tx.commit().await?;
                    Ok(PhasePreparation::Recover(owner))
                }
            },
            Some(_) => Err(AuthorityLost.into()),
        }
    }

    /// Release an exact post-start mutation lease without advancing the
    /// resumable setup phase.
    pub async fn complete_post_start_mutation(&self, phase: i32) -> anyhow::Result<()> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        require_exact_active_owner(&row, identity, phase)?;
        let result = sqlx::query(
            "UPDATE sandbox_environment_backend
                SET setup_owner_generation = NULL,
                    setup_owner_activity_id = NULL,
                    setup_owner_attempt = NULL,
                    setup_owner_phase = NULL,
                    setup_owner_status = NULL,
                    setup_owner_pod_uid = NULL
              WHERE environment_id = $1
                AND setup_owner_generation = $2
                AND setup_owner_activity_id = $3
                AND setup_owner_attempt = $4
                AND setup_owner_phase = $5
                AND setup_owner_status IN ('claimed', 'running')",
        )
        .bind(&self.environment_id)
        .bind(identity.generation)
        .bind(&identity.activity_id)
        .bind(identity.attempt)
        .bind(phase)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityLost.into());
        }
        tx.commit().await?;
        Ok(())
    }

    /// Transfer a reaped old tuple to this activity after the caller has
    /// observed the old Pod absent and completed the launch quiescence wait.
    pub async fn finish_recovery(
        &self,
        old_owner: &SetupLeaseRecord,
    ) -> anyhow::Result<PhaseAcquire> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        let current_owner = row.owner()?.ok_or(AuthorityLost)?;
        if current_owner.identity != old_owner.identity
            || current_owner.phase != old_owner.phase
            || current_owner.status != SetupLeaseStatus::Reaping
            || current_owner.pod_uid != old_owner.pod_uid
        {
            return Err(AuthorityLost.into());
        }
        if row.generation != identity.generation
            || row.desired_state != "started"
            || row.state != "running"
            || row.setup_phase != old_owner.phase
        {
            tx.commit().await?;
            return Err(AuthorityLost.into());
        }
        write_claimed(&mut tx, &self.environment_id, identity, old_owner.phase).await?;
        tx.commit().await?;
        Ok(PhaseAcquire::Acquired)
    }

    /// Lock the old reaping tuple and current environment authority across the
    /// bounded Sandbox resume request. `None` means current intent no longer
    /// permits setup; the old reaping tuple remains as exit evidence and the
    /// workspace stays down.
    pub async fn begin_resume(
        &self,
        old_owner: &SetupLeaseRecord,
    ) -> anyhow::Result<Option<SetupResumeGuard>> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        set_guard_timeouts(&mut tx).await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        let owner = row.owner()?.ok_or(AuthorityLost)?;
        if owner.identity != old_owner.identity
            || owner.phase != old_owner.phase
            || owner.status != SetupLeaseStatus::Reaping
            || owner.pod_uid != old_owner.pod_uid
        {
            return Err(AuthorityLost.into());
        }
        if row.generation != identity.generation
            || row.desired_state != "started"
            || row.state != "running"
            || row.setup_phase != old_owner.phase
        {
            tx.commit().await?;
            return Ok(None);
        }
        Ok(Some(SetupResumeGuard { tx }))
    }

    /// Serialize the bounded scale-to-zero request against every setup lease
    /// transition and exec attachment. Teardown authority is intentionally
    /// tied to the persisted old tuple even after it loses current generation.
    pub async fn begin_reap(&self, old_owner: &SetupLeaseRecord) -> anyhow::Result<SetupReapGuard> {
        let mut tx = self.pool.begin().await?;
        set_guard_timeouts(&mut tx).await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        let owner = row.owner()?.ok_or(AuthorityLost)?;
        if owner.identity != old_owner.identity
            || owner.phase != old_owner.phase
            || owner.status != SetupLeaseStatus::Reaping
            || owner.pod_uid != old_owner.pod_uid
        {
            return Err(AuthorityLost.into());
        }
        Ok(SetupReapGuard { tx })
    }

    pub async fn mark_running(&self, phase: i32, pod_uid: &str) -> anyhow::Result<()> {
        let identity = &self.identity;
        if pod_uid.trim().is_empty() {
            return Err(AuthorityLost.into());
        }
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        if row.setup_phase != phase {
            return Err(AuthorityLost.into());
        }
        let owner = row.owner()?.ok_or(AuthorityLost)?;
        if owner.identity != *identity || owner.phase != phase {
            return Err(AuthorityLost.into());
        }
        match owner.status {
            SetupLeaseStatus::Claimed => {
                let result = sqlx::query(
                    "UPDATE sandbox_environment_backend
                        SET setup_owner_status = 'running', setup_owner_pod_uid = $1
                      WHERE environment_id = $2
                        AND setup_owner_generation = $3
                        AND setup_owner_activity_id = $4
                        AND setup_owner_attempt = $5
                        AND setup_owner_phase = $6
                        AND setup_owner_status = 'claimed'
                        AND setup_owner_pod_uid IS NULL",
                )
                .bind(pod_uid)
                .bind(&self.environment_id)
                .bind(identity.generation)
                .bind(&identity.activity_id)
                .bind(identity.attempt)
                .bind(phase)
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(AuthorityLost.into());
                }
            }
            SetupLeaseStatus::Running if owner.pod_uid.as_deref() == Some(pod_uid) => {}
            SetupLeaseStatus::Running | SetupLeaseStatus::Reaping => {
                return Err(AuthorityLost.into());
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn begin_exec(&self, phase: i32, pod_uid: &str) -> anyhow::Result<SetupExecGuard> {
        let identity = &self.identity;
        if pod_uid.trim().is_empty() {
            return Err(AuthorityLost.into());
        }
        let mut tx = self.pool.begin().await?;
        set_guard_timeouts(&mut tx).await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        if row.setup_phase != phase {
            return Err(AuthorityLost.into());
        }
        let owner = row.owner()?.ok_or(AuthorityLost)?;
        if owner.identity != *identity || owner.phase != phase {
            return Err(AuthorityLost.into());
        }
        if owner.status != SetupLeaseStatus::Running || owner.pod_uid.as_deref() != Some(pod_uid) {
            return Err(AuthorityLost.into());
        }
        Ok(SetupExecGuard { tx })
    }

    pub async fn ensure_active(&self, phase: i32) -> anyhow::Result<()> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        require_exact_active_owner(&row, identity, phase)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_current_reaping(
        &self,
        phase: i32,
    ) -> anyhow::Result<Option<SetupLeaseRecord>> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        let owner = row.owner()?.ok_or(AuthorityLost)?;
        if owner.identity != *identity || owner.phase != phase {
            return Err(AuthorityLost.into());
        }
        if owner.status == SetupLeaseStatus::Claimed {
            tx.commit().await?;
            return Ok(None);
        }
        if owner.status == SetupLeaseStatus::Running {
            mark_reaping(&mut tx, &self.environment_id, &owner).await?;
        }
        tx.commit().await?;
        Ok(Some(owner))
    }

    /// Prepare a cancellation/authority-loss exit that happened between
    /// workspace execs. A claimed lease has launched no process and can be
    /// released immediately. A running lease becomes reaping and must be
    /// followed by the no-Pod fence before the activity returns.
    pub async fn prepare_control_flow_exit(
        &self,
        phase: i32,
    ) -> anyhow::Result<Option<SetupLeaseRecord>> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let Some(row) = lock_setup_rows_optional(&mut tx, &self.environment_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };
        let Some(owner) = row.owner()? else {
            tx.commit().await?;
            return Ok(None);
        };
        if owner.identity != *identity {
            // A replacement already transferred ownership and is responsible
            // for any recovery attached to its persisted tuple.
            tx.commit().await?;
            return Ok(None);
        }
        if owner.phase != phase || owner.phase != row.setup_phase {
            return Err(AuthorityLost.into());
        }
        match owner.status {
            SetupLeaseStatus::Claimed => {
                clear_owner(&mut tx, &self.environment_id, &owner).await?;
                tx.commit().await?;
                Ok(None)
            }
            SetupLeaseStatus::Running => {
                mark_reaping(&mut tx, &self.environment_id, &owner).await?;
                tx.commit().await?;
                Ok(Some(owner))
            }
            SetupLeaseStatus::Reaping => {
                tx.commit().await?;
                Ok(Some(owner))
            }
        }
    }

    /// Finish a teardown-only recovery after the exact Pod is absent.
    ///
    /// When the same generation has moved out of started/running, clearing the
    /// old tuple lets a later start activity claim the phase. When a newer
    /// generation or same-command retry still owns started/running intent, the
    /// reaping tuple stays as durable exit evidence for that replacement to
    /// transfer through `finish_recovery`.
    pub async fn finish_teardown_after_no_pod(
        &self,
        old_owner: &SetupLeaseRecord,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = lock_setup_rows_optional(&mut tx, &self.environment_id).await? else {
            tx.commit().await?;
            return Ok(());
        };
        let Some(owner) = row.owner()? else {
            tx.commit().await?;
            return Ok(());
        };
        if owner != *old_owner {
            tx.commit().await?;
            return Ok(());
        }
        if owner.status != SetupLeaseStatus::Reaping {
            return Err(AuthorityLost.into());
        }
        if row.generation == old_owner.identity.generation
            && (row.desired_state != "started" || row.state != "running")
        {
            clear_owner(&mut tx, &self.environment_id, &owner).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn emit_log(
        &self,
        phase_number: i32,
        phase: &str,
        status: &str,
        message: &str,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let identity = &self.identity;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, identity)?;
        require_exact_active_owner(&row, identity, phase_number)?;
        emit_environment_log_in_transaction(
            &mut tx,
            &self.environment_id,
            phase,
            status,
            message,
            metadata,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn complete_phase(
        &self,
        phase_number: i32,
        next_phase: i32,
        phase: &str,
        status: &str,
        message: &str,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, &self.identity)?;
        require_exact_active_owner(&row, &self.identity, phase_number)?;
        emit_environment_log_in_transaction(
            &mut tx,
            &self.environment_id,
            phase,
            status,
            message,
            metadata,
        )
        .await?;
        let result = sqlx::query(
            "UPDATE sandbox_environment_backend
                SET setup_phase = $1,
                    setup_owner_generation = NULL,
                    setup_owner_activity_id = NULL,
                    setup_owner_attempt = NULL,
                    setup_owner_phase = NULL,
                    setup_owner_status = NULL,
                    setup_owner_pod_uid = NULL
              WHERE environment_id = $2 AND setup_phase = $3",
        )
        .bind(next_phase)
        .bind(&self.environment_id)
        .bind(phase_number)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityLost.into());
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_error(&self, phase: i32, message: &str) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, &self.identity)?;
        require_exact_active_owner(&row, &self.identity, phase)?;
        let result = sqlx::query(
            "UPDATE sandbox_environment_backend
                SET setup_error = $1,
                    setup_owner_generation = NULL,
                    setup_owner_activity_id = NULL,
                    setup_owner_attempt = NULL,
                    setup_owner_phase = NULL,
                    setup_owner_status = NULL,
                    setup_owner_pod_uid = NULL
              WHERE environment_id = $2 AND setup_phase = $3",
        )
        .bind(message)
        .bind(&self.environment_id)
        .bind(phase)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityLost.into());
        }
        tx.commit().await?;
        Ok(())
    }

    /// Commit setup and its `complete` row. Returns how long after the API
    /// accepted the create setup completed (Program #2238's `setup_complete`
    /// milestone), the time the row carries as `since_accepted_ms`, when it
    /// was read. It is read just before this transaction, on its own
    /// connection, so a failed read cannot abort the commit.
    pub async fn complete_setup(
        &self,
        phase: i32,
        ttl_seconds: Option<i32>,
    ) -> anyhow::Result<Option<Duration>> {
        let accepted = since_accepted(&self.pool, &self.environment_id).await;
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, &self.identity)?;
        require_exact_active_owner(&row, &self.identity, phase)?;
        emit_environment_log_in_transaction(
            &mut tx,
            &self.environment_id,
            "complete",
            "completed",
            "Setup complete",
            with_since_accepted(None, accepted),
        )
        .await?;
        let result = sqlx::query(
            "UPDATE sandbox_environment_backend
                SET setup_complete = true,
                    setup_error = NULL,
                    setup_owner_generation = NULL,
                    setup_owner_activity_id = NULL,
                    setup_owner_attempt = NULL,
                    setup_owner_phase = NULL,
                    setup_owner_status = NULL,
                    setup_owner_pod_uid = NULL
              WHERE environment_id = $1 AND setup_phase = $2",
        )
        .bind(&self.environment_id)
        .bind(phase)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityLost.into());
        }

        if let Some(ttl_seconds) = ttl_seconds.filter(|ttl| *ttl > 0) {
            let result = sqlx::query(
                "UPDATE environments
                    SET shutdown_at = NOW() + make_interval(secs => $1)
                  WHERE id = $2",
            )
            .bind(f64::from(ttl_seconds))
            .bind(&self.environment_id)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() != 1 {
                return Err(AuthorityLost.into());
            }
            let message = format!("scheduled shutdown after ttl {ttl_seconds}s");
            let metadata = serde_json::json!({ "kind": "shutdown_at", "ttl_seconds": ttl_seconds });
            emit_environment_log_in_transaction(
                &mut tx,
                &self.environment_id,
                "lifecycle_checkpoint",
                "completed",
                &message,
                Some(metadata.clone()),
            )
            .await?;
            sqlx::query(
                r#"INSERT INTO environment_lifecycle_journal
                   (id, environment_id, kind, actor, phase, status, from_state, to_state, checkpoint, reason, metadata)
                   VALUES ($1, $2, 'checkpoint', 'lifecycle_service', 'lifecycle_checkpoint',
                           'completed', NULL, NULL, 'shutdown_at', $3, $4)"#,
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&self.environment_id)
            .bind(&message)
            .bind(&metadata)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(accepted)
    }

    pub async fn insert_port(
        &self,
        phase: i32,
        port: i32,
        label: &str,
        access: &str,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = lock_setup_rows(&mut tx, &self.environment_id).await?;
        require_current(&row, &self.identity)?;
        require_exact_active_owner(&row, &self.identity, phase)?;
        sqlx::query(
            "INSERT INTO environment_ports (environment_id, port, label, access)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&self.environment_id)
        .bind(port)
        .bind(label)
        .bind(access)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

fn takeover_allowed(current: &SetupActivityIdentity, owner: &SetupActivityIdentity) -> bool {
    current.generation > owner.generation
        || (current.generation == owner.generation
            && current.activity_id == owner.activity_id
            && current.attempt > owner.attempt)
}

fn require_current(row: &LockedSetupRow, identity: &SetupActivityIdentity) -> anyhow::Result<()> {
    if row.generation != identity.generation
        || row.desired_state != "started"
        || row.state != "running"
    {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

fn require_exact_active_owner(
    row: &LockedSetupRow,
    identity: &SetupActivityIdentity,
    phase: i32,
) -> anyhow::Result<SetupLeaseRecord> {
    if row.setup_phase != phase {
        return Err(AuthorityLost.into());
    }
    let owner = row.owner()?.ok_or(AuthorityLost)?;
    if owner.identity != *identity
        || owner.phase != phase
        || owner.status == SetupLeaseStatus::Reaping
    {
        return Err(AuthorityLost.into());
    }
    Ok(owner)
}

async fn lock_setup_rows(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
) -> anyhow::Result<LockedSetupRow> {
    lock_setup_rows_optional(tx, environment_id)
        .await?
        .ok_or_else(|| AuthorityLost.into())
}

async fn lock_setup_rows_optional(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
) -> anyhow::Result<Option<LockedSetupRow>> {
    // This explicit two-query acquisition is the program-wide lock order.
    // A joined `FOR UPDATE OF e, b` does not promise which relation PostgreSQL
    // locks first and can deadlock with lifecycle transactions.
    let environment = sqlx::query_as::<_, LockedEnvironmentRow>(
        "SELECT environment_operation_generation AS generation, desired_state, state
           FROM environments WHERE id = $1 FOR UPDATE",
    )
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(environment) = environment else {
        return Ok(None);
    };
    let backend = sqlx::query_as::<_, LockedBackendRow>(
        "SELECT setup_phase,
                setup_complete,
                setup_owner_generation,
                setup_owner_activity_id,
                setup_owner_attempt,
                setup_owner_phase,
                setup_owner_status,
                setup_owner_pod_uid
           FROM sandbox_environment_backend
          WHERE environment_id = $1
          FOR UPDATE",
    )
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AuthorityLost)?;
    Ok(Some(LockedSetupRow {
        generation: environment.generation,
        desired_state: environment.desired_state,
        state: environment.state,
        setup_phase: backend.setup_phase,
        setup_complete: backend.setup_complete,
        setup_owner_generation: backend.setup_owner_generation,
        setup_owner_activity_id: backend.setup_owner_activity_id,
        setup_owner_attempt: backend.setup_owner_attempt,
        setup_owner_phase: backend.setup_owner_phase,
        setup_owner_status: backend.setup_owner_status,
        setup_owner_pod_uid: backend.setup_owner_pod_uid,
    }))
}

async fn clear_owner(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
    owner: &SetupLeaseRecord,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        "UPDATE sandbox_environment_backend
            SET setup_owner_generation = NULL,
                setup_owner_activity_id = NULL,
                setup_owner_attempt = NULL,
                setup_owner_phase = NULL,
                setup_owner_status = NULL,
                setup_owner_pod_uid = NULL
          WHERE environment_id = $1
            AND setup_owner_generation = $2
            AND setup_owner_activity_id = $3
            AND setup_owner_attempt = $4
            AND setup_owner_phase = $5
            AND setup_owner_status = $6
            AND setup_owner_pod_uid IS NOT DISTINCT FROM $7",
    )
    .bind(environment_id)
    .bind(owner.identity.generation)
    .bind(&owner.identity.activity_id)
    .bind(owner.identity.attempt)
    .bind(owner.phase)
    .bind(owner.status.as_str())
    .bind(&owner.pod_uid)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

async fn write_claimed(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
    identity: &SetupActivityIdentity,
    phase: i32,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        "UPDATE sandbox_environment_backend
            SET setup_owner_generation = $1,
                setup_owner_activity_id = $2,
                setup_owner_attempt = $3,
                setup_owner_phase = $4,
                setup_owner_status = 'claimed',
                setup_owner_pod_uid = NULL
          WHERE environment_id = $5",
    )
    .bind(identity.generation)
    .bind(&identity.activity_id)
    .bind(identity.attempt)
    .bind(phase)
    .bind(environment_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

async fn mark_reaping(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
    owner: &SetupLeaseRecord,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        "UPDATE sandbox_environment_backend SET setup_owner_status = 'reaping'
          WHERE environment_id = $1
            AND setup_owner_generation = $2
            AND setup_owner_activity_id = $3
            AND setup_owner_attempt = $4
            AND setup_owner_phase = $5
            AND setup_owner_status = $6
            AND setup_owner_pod_uid = $7",
    )
    .bind(environment_id)
    .bind(owner.identity.generation)
    .bind(&owner.identity.activity_id)
    .bind(owner.identity.attempt)
    .bind(owner.phase)
    .bind(owner.status.as_str())
    .bind(owner.pod_uid.as_deref())
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

async fn set_guard_timeouts(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    sqlx::query("SET LOCAL lock_timeout = '35s'")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '35s'")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '35s'")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(generation: i64, activity: &str, attempt: i32) -> SetupActivityIdentity {
        SetupActivityIdentity {
            generation,
            activity_id: activity.to_string(),
            attempt,
        }
    }

    #[test]
    fn only_new_generation_or_later_same_activity_attempt_can_take_over() {
        let old = identity(7, "setup", 1);
        assert!(takeover_allowed(&identity(8, "replacement", 1), &old));
        assert!(takeover_allowed(&identity(7, "setup", 2), &old));
        assert!(!takeover_allowed(&identity(7, "other", 2), &old));
        assert!(!takeover_allowed(&identity(7, "setup", 1), &old));
        assert!(!takeover_allowed(&identity(6, "setup", 3), &old));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_setup_lease_fences_stale_attempt_writes_and_recovers() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPool::connect(&database_url).await.unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("usr_setup_lease_{suffix}");
        let org_id = format!("org_setup_lease_{suffix}");
        let preset_id = format!("pre_setup_lease_{suffix}");
        let environment_id = format!("env_setup_lease_{suffix}");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{suffix}@setup-lease.invalid"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org_id)
        .bind("Setup lease test")
        .bind(format!("setup-lease-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
             VALUES ($1, $2, $3, $4, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(&preset_id)
        .bind(&org_id)
        .bind("Setup lease test")
        .bind(format!("setup-lease-{suffix}"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environments
                    (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
             VALUES ($1, $2, $3, 'sandbox', 'running', 'started', $4,
                     '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(&environment_id)
        .bind(&org_id)
        .bind(&user_id)
        .bind(&preset_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sandbox_environment_backend (environment_id, namespace)
             VALUES ($1, 'setup-lease-test')",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();

        let partial_owner = sqlx::query(
            "UPDATE sandbox_environment_backend SET setup_owner_generation = 1
              WHERE environment_id = $1",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await;
        assert!(
            partial_owner.is_err(),
            "the schema must reject a partial setup owner tuple"
        );

        let generation = ActivityAuthority::claim(&pool, &environment_id, "run-setup", 10)
            .await
            .unwrap();
        let authority = ActivityAuthority::capture(&pool, &environment_id, generation)
            .await
            .unwrap();
        let first = SetupPhaseAuthority::new(
            authority.clone(),
            SetupActivityIdentity::new(generation, "setup".into(), 1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            first.prepare_phase(0).await.unwrap(),
            PhasePreparation::Ready(PhaseAcquire::Acquired)
        );
        first
            .emit_log(0, "health_check", "started", "", None)
            .await
            .unwrap();
        first.mark_running(0, "pod-old").await.unwrap();

        let retry = SetupPhaseAuthority::new(
            authority,
            SetupActivityIdentity::new(generation, "setup".into(), 2).unwrap(),
        )
        .unwrap();
        let old_owner = match retry.prepare_phase(0).await.unwrap() {
            PhasePreparation::Recover(owner) => owner,
            other => panic!("later attempt must recover the old running lease, got {other:?}"),
        };

        for stale_result in [
            first.emit_log(0, "stale", "failed", "", None).await,
            first.set_error(0, "stale error").await,
            first.insert_port(0, 43210, "stale", "creator").await,
            first
                .complete_phase(0, 1, "stale", "completed", "", None)
                .await,
            first.complete_setup(0, None).await.map(|_| ()),
        ] {
            assert!(
                stale_result.is_err_and(|error| {
                    super::super::activity_authority::is_authority_lost(&error)
                }),
                "a stale setup owner must not write"
            );
        }

        retry
            .begin_reap(&old_owner)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        retry
            .begin_resume(&old_owner)
            .await
            .unwrap()
            .expect("current retry retains resume authority")
            .commit()
            .await
            .unwrap();
        assert_eq!(
            retry.finish_recovery(&old_owner).await.unwrap(),
            PhaseAcquire::Acquired
        );
        retry.mark_running(0, "pod-new").await.unwrap();
        retry
            .complete_phase(0, 1, "health_check", "completed", "", None)
            .await
            .unwrap();

        assert_eq!(
            retry.prepare_phase(1).await.unwrap(),
            PhasePreparation::Ready(PhaseAcquire::Acquired)
        );
        retry.mark_running(1, "pod-attempt-two").await.unwrap();
        let replacement_generation =
            ActivityAuthority::claim(&pool, &environment_id, "run-replacement", 20)
                .await
                .unwrap();
        let replacement_authority =
            ActivityAuthority::capture(&pool, &environment_id, replacement_generation)
                .await
                .unwrap();
        let replacement = SetupPhaseAuthority::new(
            replacement_authority,
            SetupActivityIdentity::new(replacement_generation, "replacement-setup".into(), 1)
                .unwrap(),
        )
        .unwrap();
        let dead_worker_owner = match replacement.prepare_phase(1).await.unwrap() {
            PhasePreparation::Recover(owner) => owner,
            other => panic!("new generation must recover dead worker lease, got {other:?}"),
        };
        let stale_after_replacement = retry
            .emit_log(1, "stale", "failed", "", None)
            .await
            .unwrap_err();
        assert!(super::super::activity_authority::is_authority_lost(
            &stale_after_replacement
        ));
        replacement
            .begin_reap(&dead_worker_owner)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        replacement
            .begin_resume(&dead_worker_owner)
            .await
            .unwrap()
            .expect("replacement generation retains resume authority")
            .commit()
            .await
            .unwrap();
        replacement
            .finish_recovery(&dead_worker_owner)
            .await
            .unwrap();
        replacement
            .mark_running(1, "pod-generation-two")
            .await
            .unwrap();
        replacement
            .complete_phase(1, 2, "configure_environment", "completed", "", None)
            .await
            .unwrap();

        // Program #2238: setup's `complete` row carries how long after the
        // API accepted the create it landed, by the database clock.
        sqlx::query(
            "UPDATE environments SET created_at = created_at - interval '2500 milliseconds'
              WHERE id = $1",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            replacement.prepare_phase(2).await.unwrap(),
            PhasePreparation::Ready(PhaseAcquire::Acquired)
        );
        let since_accepted = replacement
            .complete_setup(2, None)
            .await
            .unwrap()
            .expect("the accepted time is read for an existing environment");
        assert!(
            since_accepted >= Duration::from_millis(2_500)
                && since_accepted < Duration::from_secs(60),
            "since accepted {since_accepted:?}"
        );
        let (complete_ms, setup_complete): (Option<i64>, bool) = sqlx::query_as(
            "SELECT (l.metadata->>'since_accepted_ms')::bigint, b.setup_complete
               FROM environment_logs l
               JOIN sandbox_environment_backend b ON b.environment_id = l.environment_id
              WHERE l.environment_id = $1 AND l.phase = 'complete' AND l.status = 'completed'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(setup_complete);
        assert_eq!(
            complete_ms,
            Some(i64::try_from(since_accepted.as_millis()).unwrap())
        );
        assert_eq!(
            super::super::start_timing::since_accepted(&pool, "env_setup_lease_missing").await,
            None
        );

        let (phase, setup_error, stale_ports, stale_logs, owner_generation): (
            i32,
            Option<String>,
            i64,
            i64,
            Option<i64>,
        ) = sqlx::query_as(
            "SELECT b.setup_phase,
                    b.setup_error,
                    (SELECT COUNT(*) FROM environment_ports p
                      WHERE p.environment_id = b.environment_id AND p.label = 'stale'),
                    (SELECT COUNT(*) FROM environment_logs l
                      WHERE l.environment_id = b.environment_id AND l.phase = 'stale'),
                    b.setup_owner_generation
               FROM sandbox_environment_backend b
              WHERE b.environment_id = $1",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(phase, 2);
        assert_eq!(setup_error, None);
        assert_eq!(stale_ports, 0);
        assert_eq!(stale_logs, 0);
        assert_eq!(owner_generation, None);

        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(&environment_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
