//! Durable authority fence for Temporal environment activities.
//!
//! A workflow execution ID only serializes work inside one live run. The
//! durable command authority is the environment's committed `desired_state`
//! plus its required operation generation. Database mutations take a row lock
//! and verify both in the same transaction as the write.

use std::future::Future;
use std::time::Duration;

use anyhow::Context as _;
use sqlx::postgres::{PgArguments, PgQueryResult};
use sqlx::query::Query;
use sqlx::{PgPool, Postgres, Transaction};
use temporalio_common::protos::temporal::api::enums::v1::WorkflowExecutionStatus;

const AUTHORITY_POLL_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) const EXTERNAL_MUTATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct AuthorityLost;

impl std::fmt::Display for AuthorityLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("environment activity lost authority")
    }
}

impl std::error::Error for AuthorityLost {}

pub fn is_authority_lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<AuthorityLost>())
}

#[derive(Clone, Debug)]
pub struct ActivityAuthority {
    pool: PgPool,
    environment_id: String,
    desired_state: String,
    operation_generation: i64,
    /// The run the generation's claim row named at capture. A run that takes
    /// the generation over renames the row, so every check compares it as
    /// well as the generation (#6103). `None` only where no claim row exists
    /// for the generation.
    claim_run: Option<String>,
}

/// An environment's lifecycle intent and the run its current generation's
/// claim row names, read together.
#[derive(sqlx::FromRow)]
struct CurrentAuthority {
    desired_state: String,
    state: String,
    generation: i64,
    claim_run: Option<String>,
}

async fn read_current(pool: &PgPool, environment_id: &str) -> anyhow::Result<CurrentAuthority> {
    sqlx::query_as::<_, CurrentAuthority>(
        "SELECT e.desired_state, e.state, e.environment_operation_generation AS generation,
                c.workflow_run_id AS claim_run
           FROM environments e
           LEFT JOIN environment_operation_generation_claims c
             ON c.environment_id = e.id
            AND c.generation = e.environment_operation_generation
          WHERE e.id = $1",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AuthorityLost.into())
}

/// Locks the claim row of `generation` `FOR SHARE` and requires it still to
/// name `claim_run`, the run an authority was captured for (#6103). A run
/// that takes the generation over renames the row under `FOR UPDATE`, so a
/// write guarded by this check commits before the takeover or is refused
/// after it. The claim row is locked before the environment row, the order
/// the takeover takes them in.
pub(crate) async fn lock_claim_run(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: &str,
    generation: i64,
    claim_run: Option<&str>,
) -> anyhow::Result<()> {
    let current: Option<String> = sqlx::query_scalar(
        "SELECT workflow_run_id FROM environment_operation_generation_claims
          WHERE environment_id = $1 AND generation = $2
          FOR SHARE",
    )
    .bind(environment_id)
    .bind(generation)
    .fetch_optional(&mut **tx)
    .await?;
    if current.as_deref() != claim_run {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

/// A short-lived environment-row lock held across one external mutation.
///
/// Kubernetes and Cloudflare cannot participate in the Postgres transaction,
/// but the API commits every lifecycle state/intent change through this same
/// row. Holding the lock until the external mutation and its durable bookkeeping
/// complete gives them one serialization boundary: a replacement command
/// either commits before this guard (and the guard refuses to run) or after it
/// (and therefore observes the side effect it must reconcile).
pub struct ExternalMutationGuard {
    tx: Transaction<'static, Postgres>,
}

impl ExternalMutationGuard {
    pub fn transaction(&mut self) -> &mut Transaction<'static, Postgres> {
        &mut self.tx
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        await_external_mutation(async move {
            self.tx.commit().await?;
            Ok(())
        })
        .await
    }
}

impl ActivityAuthority {
    /// Capture the currently committed intent for an environment activity.
    ///
    /// The generation is required and must exactly match the current durable
    /// generation. A hard-deleted row is ordinary authority loss. The run
    /// holding the generation's claim at capture is pinned with it, so a
    /// caller outside a workflow run is fenced by a takeover too.
    pub async fn capture(
        pool: &PgPool,
        environment_id: &str,
        operation_generation: i64,
    ) -> anyhow::Result<Self> {
        if operation_generation <= 0 {
            return Err(AuthorityLost.into());
        }
        let current = read_current(pool, environment_id).await?;
        if operation_generation != current.generation {
            return Err(AuthorityLost.into());
        }
        Ok(Self {
            pool: pool.clone(),
            environment_id: environment_id.to_string(),
            desired_state: current.desired_state,
            operation_generation,
            claim_run: current.claim_run,
        })
    }

    /// As [`Self::capture`], for an activity of run `workflow_run_id`: the
    /// generation's claim row must name that run (#6103). An activity still
    /// executing for a run whose generation another run has taken over is
    /// refused here and at every later check.
    pub async fn capture_for_run(
        pool: &PgPool,
        environment_id: &str,
        operation_generation: i64,
        workflow_run_id: &str,
    ) -> anyhow::Result<Self> {
        let authority = Self::capture(pool, environment_id, operation_generation).await?;
        if authority.claim_run.as_deref() != Some(workflow_run_id) {
            return Err(AuthorityLost.into());
        }
        Ok(authority)
    }

    /// Capture authority only when the command still matches its required
    /// lifecycle intent. A mismatched command is stale before it starts.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %environment_id))]
    pub async fn capture_required(
        pool: &PgPool,
        environment_id: &str,
        desired_state: &str,
        operation_generation: i64,
    ) -> anyhow::Result<Self> {
        let authority = Self::capture(pool, environment_id, operation_generation).await?;
        if authority.desired_state != desired_state {
            return Err(AuthorityLost.into());
        }
        Ok(authority)
    }

    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn desired_state(&self) -> &str {
        &self.desired_state
    }

    pub fn operation_generation(&self) -> i64 {
        self.operation_generation
    }

    /// The run the generation's claim row named at capture.
    pub fn claim_run(&self) -> Option<&str> {
        self.claim_run.as_deref()
    }

    /// Whether `current` still carries this authority's intent, generation
    /// and claim run.
    fn holds(&self, current: &CurrentAuthority) -> bool {
        current.desired_state == self.desired_state
            && current.generation == self.operation_generation
            && current.claim_run == self.claim_run
    }

    /// Locks this authority's claim row, as [`lock_claim_run`] does.
    async fn lock_claim(&self, tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
        lock_claim_run(
            tx,
            &self.environment_id,
            self.operation_generation,
            self.claim_run.as_deref(),
        )
        .await
    }

    /// Claim the next workflow-execution generation before any environment
    /// activity is dispatched for the run.
    pub async fn claim(
        pool: &PgPool,
        environment_id: &str,
        workflow_run_id: &str,
        scheduled_at_unix_nanos: i64,
    ) -> anyhow::Result<i64> {
        Self::claim_taking_over(
            pool,
            environment_id,
            workflow_run_id,
            scheduled_at_unix_nanos,
            None,
        )
        .await
    }

    /// As [`Self::claim`], after asking Temporal about the run that holds the
    /// current generation (#6103). `read_status` reads that run's status:
    /// `Ok(None)` when Temporal has no record of it, an error when the read
    /// failed. A failed read claims nothing and returns the error, so the
    /// claim activity retries; it never moves the generation. A holder that
    /// Temporal describes as closed hands its generation on through
    /// [`Self::claim_taking_over`]; any other holder is replaced as a new run
    /// replaces it.
    pub async fn claim_after_holder<R, F>(
        pool: &PgPool,
        environment_id: &str,
        workflow_run_id: &str,
        scheduled_at_unix_nanos: i64,
        read_status: R,
    ) -> anyhow::Result<i64>
    where
        R: FnOnce(String) -> F,
        F: Future<Output = anyhow::Result<Option<WorkflowExecutionStatus>>>,
    {
        let closed_holder =
            match Self::current_holder(pool, environment_id, workflow_run_id).await? {
                Some(holder) => {
                    let status = read_status(holder.clone())
                        .await
                        .context("read the run that holds the current generation")?;
                    is_closed(status).then_some(holder)
                }
                None => None,
            };
        Self::claim_taking_over(
            pool,
            environment_id,
            workflow_run_id,
            scheduled_at_unix_nanos,
            closed_holder.as_deref(),
        )
        .await
    }

    /// The run named by the current generation's claim row, when that is a
    /// run other than `workflow_run_id`.
    async fn current_holder(
        pool: &PgPool,
        environment_id: &str,
        workflow_run_id: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT c.workflow_run_id
               FROM environments e
               JOIN environment_operation_generation_claims c
                 ON c.environment_id = e.id
                AND c.generation = e.environment_operation_generation
              WHERE e.id = $1 AND c.workflow_run_id <> $2",
        )
        .bind(environment_id)
        .bind(workflow_run_id)
        .fetch_optional(pool)
        .await?)
    }

    /// As [`Self::claim`], taking over `closed_holder`'s claim (#5950,
    /// #6103). `closed_holder` is a run Temporal describes as closed; it
    /// never comes from a command. When it holds the current
    /// generation's claim row and was scheduled earlier, this run takes the
    /// row over, once, and keeps the generation, so a running credentialed
    /// Sandbox's binding, daemon and credential bridge stay current. Anything
    /// else claims as a new run does.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %environment_id))]
    pub async fn claim_taking_over(
        pool: &PgPool,
        environment_id: &str,
        workflow_run_id: &str,
        scheduled_at_unix_nanos: i64,
        closed_holder: Option<&str>,
    ) -> anyhow::Result<i64> {
        if workflow_run_id.trim().is_empty() || scheduled_at_unix_nanos < 0 {
            return Err(AuthorityLost.into());
        }
        #[cfg(feature = "kind-e2e")]
        super::fencing_evidence::emit(
            super::fencing_evidence::FencingEvidence::ClaimAttemptStarted {
                environment_id: environment_id.to_string(),
                workflow_run_id: workflow_run_id.to_string(),
            },
        );
        let mut tx = pool.begin().await?;
        let closed_holder = closed_holder.filter(|run| *run != workflow_run_id);
        if let Some(holder) = closed_holder {
            // The claim row first, then the environment row: the order every
            // fenced write takes them in (`lock_claim_run`).
            sqlx::query(
                "SELECT 1 FROM environment_operation_generation_claims
                  WHERE environment_id = $1 AND workflow_run_id = $2
                  FOR UPDATE",
            )
            .bind(environment_id)
            .bind(holder)
            .execute(&mut *tx)
            .await?;
        }
        let current_generation: Option<i64> = sqlx::query_scalar(
            "SELECT environment_operation_generation
               FROM environments
              WHERE id = $1
                FOR UPDATE",
        )
        .bind(environment_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current_generation) = current_generation else {
            return Err(AuthorityLost.into());
        };

        let existing: Option<(i64, i64)> = sqlx::query_as(
            "SELECT generation, scheduled_at_unix_nanos
               FROM environment_operation_generation_claims
              WHERE environment_id = $1 AND workflow_run_id = $2",
        )
        .bind(environment_id)
        .bind(workflow_run_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((generation, original_scheduled_at)) = existing {
            if generation == current_generation && original_scheduled_at == scheduled_at_unix_nanos
            {
                tx.commit().await?;
                return Ok(generation);
            }
            return Err(AuthorityLost.into());
        }

        // The take-over renames the holder's exact row, so it happens once,
        // the holder's own retries and still-executing activities are fenced
        // as a replaced run's are, and a row that changed since the holder
        // was read matches nothing.
        if let Some(holder) = closed_holder {
            let taken = sqlx::query(
                "UPDATE environment_operation_generation_claims
                    SET workflow_run_id = $3, scheduled_at_unix_nanos = $4
                  WHERE environment_id = $1 AND generation = $2
                    AND workflow_run_id = $5 AND scheduled_at_unix_nanos < $4",
            )
            .bind(environment_id)
            .bind(current_generation)
            .bind(workflow_run_id)
            .bind(scheduled_at_unix_nanos)
            .bind(holder)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if taken == 1 {
                // The holder's setup owner shares this generation and may
                // share an activity id, which is a per-run sequence; this
                // run's setup starts as a fresh owner.
                sqlx::query(
                    "UPDATE sandbox_environment_backend
                        SET setup_owner_generation = NULL,
                            setup_owner_activity_id = NULL,
                            setup_owner_attempt = NULL,
                            setup_owner_phase = NULL,
                            setup_owner_status = NULL,
                            setup_owner_pod_uid = NULL
                      WHERE environment_id = $1 AND setup_owner_generation = $2",
                )
                .bind(environment_id)
                .bind(current_generation)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Ok(current_generation);
            }
        }

        let current_scheduled_at: Option<i64> = sqlx::query_scalar(
            "SELECT scheduled_at_unix_nanos
               FROM environment_operation_generation_claims
              WHERE environment_id = $1 AND generation = $2",
        )
        .bind(environment_id)
        .bind(current_generation)
        .fetch_optional(&mut *tx)
        .await?;
        match current_scheduled_at {
            Some(current) if scheduled_at_unix_nanos <= current => {
                return Err(AuthorityLost.into());
            }
            None if current_generation != 0 => return Err(AuthorityLost.into()),
            _ => {}
        }

        let generation = current_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("environment operation generation exhausted"))?;
        sqlx::query(
            "UPDATE environments
                SET environment_operation_generation = $1
              WHERE id = $2",
        )
        .bind(generation)
        .bind(environment_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO environment_operation_generation_claims
                    (environment_id, workflow_run_id, generation, scheduled_at_unix_nanos)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(environment_id)
        .bind(workflow_run_id)
        .bind(generation)
        .bind(scheduled_at_unix_nanos)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(generation)
    }

    /// Revalidate intent without taking a long-lived lock. Use this before
    /// external side effects and periodically while waiting.
    pub async fn ensure(&self) -> anyhow::Result<()> {
        let current = read_current(&self.pool, &self.environment_id).await?;
        if !self.holds(&current) {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Revalidate both the durable intent and the lifecycle states in which a
    /// particular operation is allowed to mutate. The state predicate is what
    /// fences an older same-intent run after its replacement has progressed.
    pub async fn ensure_for_states(&self, states: &[&str]) -> anyhow::Result<()> {
        let current = read_current(&self.pool, &self.environment_id).await?;
        if !self.holds(&current) || !states.contains(&current.state.as_str()) {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Lock the claim row and the environment row and verify authority. The
    /// locks keep a takeover or an API intent update from racing the guarded
    /// write that follows.
    pub async fn lock_transaction(&self, tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
        self.lock_claim(tx).await?;
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT desired_state, environment_operation_generation
               FROM environments WHERE id = $1 FOR UPDATE",
        )
        .bind(&self.environment_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((desired_state, generation)) = current else {
            return Err(AuthorityLost.into());
        };
        if desired_state != self.desired_state || self.operation_generation != generation {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Lock the claim row and the environment row and require both the
    /// captured authority and an operation-specific lifecycle state.
    pub async fn lock_transaction_for_states(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        states: &[&str],
    ) -> anyhow::Result<()> {
        self.lock_claim(tx).await?;
        let current: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT desired_state, state, environment_operation_generation
               FROM environments WHERE id = $1 FOR UPDATE",
        )
        .bind(&self.environment_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((desired_state, state, generation)) = current else {
            return Err(AuthorityLost.into());
        };
        if desired_state != self.desired_state
            || self.operation_generation != generation
            || !states.contains(&state.as_str())
        {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Lock lifecycle intent while allowing a separate provider connection to
    /// insert rows that reference this immutable environment identifier.
    ///
    /// PostgreSQL foreign-key validation takes `KEY SHARE` on the parent row.
    /// `FOR NO KEY UPDATE` still conflicts with every lifecycle intent update
    /// while avoiding a self-deadlock when external-provider bookkeeping uses
    /// another pooled connection under this guard.
    async fn lock_external_mutation_transaction_for_states(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        states: &[&str],
    ) -> anyhow::Result<()> {
        self.lock_claim(tx).await?;
        let current: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT desired_state, state, environment_operation_generation
               FROM environments WHERE id = $1 FOR NO KEY UPDATE",
        )
        .bind(&self.environment_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((desired_state, state, generation)) = current else {
            return Err(AuthorityLost.into());
        };
        if desired_state != self.desired_state
            || self.operation_generation != generation
            || !states.contains(&state.as_str())
        {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Execute one durable mutation under the environment authority lock.
    pub async fn execute<'q>(
        &self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> anyhow::Result<PgQueryResult> {
        let mut tx = self.pool.begin().await?;
        self.lock_transaction(&mut tx).await?;
        let result = query.execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Execute one durable mutation under intent + lifecycle-state authority.
    pub async fn execute_for_states<'q>(
        &self,
        states: &[&str],
        query: Query<'q, Postgres, PgArguments>,
    ) -> anyhow::Result<PgQueryResult> {
        let mut tx = self.pool.begin().await?;
        self.lock_transaction_for_states(&mut tx, states).await?;
        let result = query.execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Begin the serialization guard for a short external mutation. Callers
    /// may use the transaction for the matching durable bookkeeping, then must
    /// commit the guard. Dropping it rolls the database work back and releases
    /// the row lock.
    pub async fn begin_external_mutation(
        &self,
        states: &[&str],
    ) -> anyhow::Result<ExternalMutationGuard> {
        await_external_mutation(async {
            let mut tx = self.pool.begin().await?;
            // Bound all three ways this transaction could otherwise pin a pooled
            // connection: waiting for the environment lock, a bookkeeping query,
            // or an external future stalled while the transaction is idle. The
            // client-side deadline is shorter so normal expiry rolls back cleanly
            // before Postgres has to sever the session.
            sqlx::query("SET LOCAL lock_timeout = '35s'")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL statement_timeout = '35s'")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '35s'")
                .execute(&mut *tx)
                .await?;
            self.lock_external_mutation_transaction_for_states(&mut tx, states)
                .await?;
            Ok(ExternalMutationGuard { tx })
        })
        .await
    }

    /// Run one short external mutation while state/intent changes are
    /// serialized on the environment row.
    pub async fn run_external_mutation<F, T>(&self, states: &[&str], future: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        let guard = self.begin_external_mutation(states).await?;
        let value = await_external_mutation(future).await?;
        guard.commit().await?;
        Ok(value)
    }

    /// Poll durable intent while an underlying Kubernetes/gateway wait is
    /// pending. Losing authority drops the wait future immediately.
    pub async fn run_while_authoritative<F, T>(&self, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        tokio::pin!(future);
        let mut interval = tokio::time::interval(AUTHORITY_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = &mut future => return result,
                _ = interval.tick() => self.ensure().await?,
            }
        }
    }

    /// Poll durable intent, generation, and operation-specific lifecycle state
    /// while an underlying wait or remote operation is pending.
    pub async fn run_while_authoritative_for_states<F, T>(
        &self,
        states: &[&str],
        future: F,
    ) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        tokio::pin!(future);
        let mut interval = tokio::time::interval(AUTHORITY_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = &mut future => return result,
                _ = interval.tick() => self.ensure_for_states(states).await?,
            }
        }
    }
}

/// Whether Temporal describes a run as closed, with any close status. Only
/// an explicit close counts: a running run, an unspecified status and a run
/// Temporal has no record of (`None`) do not. A closed run's activities that
/// are still executing are fenced by the claim row's run id, not by the
/// generation (docs/dev/ORCHESTRATION-FENCING.md).
fn is_closed(status: Option<WorkflowExecutionStatus>) -> bool {
    matches!(
        status,
        Some(
            WorkflowExecutionStatus::ContinuedAsNew
                | WorkflowExecutionStatus::Completed
                | WorkflowExecutionStatus::Failed
                | WorkflowExecutionStatus::Terminated
                | WorkflowExecutionStatus::TimedOut
                | WorkflowExecutionStatus::Canceled
        )
    )
}

pub(crate) async fn await_external_mutation<F, T>(future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    await_external_mutation_with_timeout(EXTERNAL_MUTATION_TIMEOUT, future).await
}

async fn await_external_mutation_with_timeout<F, T>(
    timeout: Duration,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| anyhow::anyhow!("external mutation exceeded {timeout:?}"))?
}

#[cfg(test)]
mod tests;
