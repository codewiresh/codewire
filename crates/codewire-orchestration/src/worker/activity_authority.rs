//! Durable authority fence for Temporal environment activities.
//!
//! A workflow execution ID only serializes work inside one live run. The
//! durable command authority is the environment's committed `desired_state`
//! plus its required operation generation. Database mutations take a row lock
//! and verify both in the same transaction as the write.

use std::future::Future;
use std::time::Duration;

use sqlx::postgres::{PgArguments, PgQueryResult};
use sqlx::query::Query;
use sqlx::{PgPool, Postgres, Transaction};

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
    /// generation. A hard-deleted row is ordinary authority loss.
    pub async fn capture(
        pool: &PgPool,
        environment_id: &str,
        operation_generation: i64,
    ) -> anyhow::Result<Self> {
        if operation_generation <= 0 {
            return Err(AuthorityLost.into());
        }
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT desired_state, environment_operation_generation
               FROM environments WHERE id = $1",
        )
        .bind(environment_id)
        .fetch_optional(pool)
        .await?;
        let Some((desired_state, current_generation)) = current else {
            return Err(AuthorityLost.into());
        };
        if operation_generation != current_generation {
            return Err(AuthorityLost.into());
        }
        Ok(Self {
            pool: pool.clone(),
            environment_id: environment_id.to_string(),
            desired_state,
            operation_generation,
        })
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

    /// Claim the next workflow-execution generation before any environment
    /// activity is dispatched for the run.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %environment_id))]
    pub async fn claim(
        pool: &PgPool,
        environment_id: &str,
        workflow_run_id: &str,
        scheduled_at_unix_nanos: i64,
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
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT desired_state, environment_operation_generation
               FROM environments WHERE id = $1",
        )
        .bind(&self.environment_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((desired_state, generation)) = current else {
            return Err(AuthorityLost.into());
        };
        if desired_state != self.desired_state || self.operation_generation != generation {
            return Err(AuthorityLost.into());
        }
        Ok(())
    }

    /// Revalidate both the durable intent and the lifecycle states in which a
    /// particular operation is allowed to mutate. The state predicate is what
    /// fences an older same-intent run after its replacement has progressed.
    pub async fn ensure_for_states(&self, states: &[&str]) -> anyhow::Result<()> {
        let current: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT desired_state, state, environment_operation_generation
               FROM environments WHERE id = $1",
        )
        .bind(&self.environment_id)
        .fetch_optional(&self.pool)
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

    /// Lock the environment row and verify authority. The lock keeps an API
    /// intent update from racing the guarded write that follows.
    pub async fn lock_transaction(&self, tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
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

    /// Lock the environment row and require both the captured intent and an
    /// operation-specific lifecycle state.
    pub async fn lock_transaction_for_states(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        states: &[&str],
    ) -> anyhow::Result<()> {
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn external_mutation_wait_is_bounded() {
        let result = await_external_mutation_with_timeout(
            Duration::from_millis(5),
            std::future::pending::<anyhow::Result<()>>(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("external mutation exceeded")
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn generation_claim_and_external_mutation_locking_are_fenced() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPool::connect(&database_url).await.unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("usr_authority_{suffix}");
        let org_id = format!("org_authority_{suffix}");
        let preset_id = format!("pre_authority_{suffix}");
        let environment_id = format!("env_authority_{suffix}");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{suffix}@authority.invalid"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org_id)
        .bind("Authority test")
        .bind(format!("authority-{suffix}"))
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
        .bind("Authority test")
        .bind(format!("authority-{suffix}"))
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
             VALUES ($1, 'authority-test')",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();

        let old = ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
            .await
            .unwrap();
        assert_eq!(old, 1);
        let old_authority = ActivityAuthority::capture(&pool, &environment_id, old)
            .await
            .unwrap();
        assert_eq!(
            ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
                .await
                .unwrap(),
            old,
            "an activity retry must reuse its workflow execution generation"
        );
        let mismatched_retry = ActivityAuthority::claim(&pool, &environment_id, "run-old", 11)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&mismatched_retry));

        let replacement = ActivityAuthority::claim(&pool, &environment_id, "run-new", 20)
            .await
            .unwrap();
        assert_eq!(replacement, 2);
        let old_retry = ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&old_retry));
        let delayed_old = ActivityAuthority::claim(&pool, &environment_id, "run-delayed", 15)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&delayed_old));

        let stale_backend = old_authority
            .execute_for_states(
                &["running"],
                sqlx::query(
                    "UPDATE sandbox_environment_backend SET namespace = 'stale'
                      WHERE environment_id = $1",
                )
                .bind(&environment_id),
            )
            .await
            .unwrap_err();
        assert!(is_authority_lost(&stale_backend));
        let stale_state = old_authority
            .execute_for_states(
                &["running"],
                sqlx::query("UPDATE environments SET error_reason = 'stale' WHERE id = $1")
                    .bind(&environment_id),
            )
            .await
            .unwrap_err();
        assert!(is_authority_lost(&stale_state));
        let stale_log = super::super::env_log::emit_authoritative_environment_log_for_states(
            &old_authority,
            &["running"],
            "stale",
            "failed",
            "stale",
            None,
        )
        .await
        .unwrap_err();
        assert!(is_authority_lost(&stale_log));
        let stale_log_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_logs
              WHERE environment_id = $1 AND phase = 'stale'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stale_log_count, 0);

        let current_authority = ActivityAuthority::capture(&pool, &environment_id, replacement)
            .await
            .expect("current generation retains authority");

        let guard = current_authority
            .begin_external_mutation(&["running"])
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query(
                "INSERT INTO confidential_storage_keys
                        (environment_id, kbs_uri, openbao_path, version, state)
                 VALUES ($1, $2, $3, 1, 'provisioning')",
            )
            .bind(&environment_id)
            .bind(format!(
                "kbs:///default/codewire-workspace-luks/{environment_id}"
            ))
            .bind(format!("confidential-storage/{environment_id}"))
            .execute(&pool),
        )
        .await
        .expect("child foreign-key insert blocked behind its own authority guard")
        .unwrap();

        let mut competing = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut *competing)
            .await
            .unwrap();
        let error = sqlx::query("UPDATE environments SET desired_state = 'stopped' WHERE id = $1")
            .bind(&environment_id)
            .execute(&mut *competing)
            .await
            .unwrap_err();
        match error {
            sqlx::Error::Database(database) => {
                assert_eq!(database.code().as_deref(), Some("55P03"));
            }
            other => panic!("expected PostgreSQL lock timeout, got {other}"),
        }
        competing.rollback().await.unwrap();
        guard.commit().await.unwrap();

        let stale = ActivityAuthority::capture(&pool, &environment_id, old)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&stale));

        let missing_generation = ActivityAuthority::capture(&pool, &environment_id, 0)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&missing_generation));

        let empty_run = ActivityAuthority::claim(&pool, &environment_id, "", 30)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&empty_run));

        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(&environment_id)
            .execute(&pool)
            .await
            .unwrap();
        let missing = ActivityAuthority::capture(&pool, &environment_id, replacement)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&missing));
        let missing_claim = ActivityAuthority::claim(&pool, &environment_id, "run-missing", 30)
            .await
            .unwrap_err();
        assert!(is_authority_lost(&missing_claim));
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
