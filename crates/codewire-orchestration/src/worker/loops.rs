//! Leader-gated background loops — port of `worker/leader.go`,
//! `worker/reconciler.go` (the environment reconciliation half; trial
//! expiry lives in the billing service), and `worker/sandbox_liveness.go`.
//!
//! `WORKER_LOOPS` is the allow-list of loops this worker runs; the
//! orchestration replicas elect a leader among themselves under a
//! dedicated pg advisory lock so only one runs the loops at a time.
//! The `image-cache` loop is the exception: it runs on every replica. The
//! `warm-pool` loop is leader-gated and inert until warm-pool shapes are
//! configured.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sqlx::{Connection, PgConnection, PgPool, Row};
use tokio::sync::Notify;

use super::WorkerContext;
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::runtime::{Placement, ProbeResult, RuntimeDriver};
use crate::worker::activity_authority::{ActivityAuthority, is_authority_lost};

/// The orchestration worker's leadership domain (see module docs).
const ADVISORY_LOCK_ID: i64 = 0x636F646577697265; // "codewire"

const RECONCILER_INTERVAL: Duration = Duration::from_secs(30);
const SANDBOX_LIVENESS_INTERVAL: Duration = Duration::from_secs(5);
const SANDBOX_TRANSITIONAL_LIVENESS_GRACE: Duration = Duration::from_secs(60);
/// A sandbox that stops this soon after reaching `running` waits for the
/// stuck-state sweep instead of restarting at once, so one that can't stay up
/// doesn't restart in a tight loop (#3851).
const CRASH_RECOVERY_MIN_RUNNING: Duration = Duration::from_secs(60);
const RECOVERY_ACTIVITY_WINDOW_SECS: i32 = 300; // environmentRecoveryActivityWindow
const PENDING_CREATE_RECOVERY_SECS: i32 = 60;
const DESTROY_WITHOUT_BACKEND_RECOVERY_SECS: i32 = 60;
const INCOMPLETE_EXTERNAL_CLEANUP_STATES: [&str; 3] = ["destroying", "destroyed", "error"];

/// Mirrors `RecoveryJournalKinds`.
const RECOVERY_JOURNAL_KINDS: [&str; 4] =
    ["transition", "checkpoint", "error", "reconcile_request"];

/// Launches the requested loops. `is_leader` is shared with the
/// leader-election task spawned here.
pub fn start_loops(ctx: Arc<WorkerContext>, database_url: String, loops: &[String]) {
    if loops.is_empty() {
        return;
    }
    let is_leader = Arc::new(AtomicBool::new(false));
    let leader_notify = Arc::new(Notify::new());

    {
        let is_leader = is_leader.clone();
        let leader_notify = leader_notify.clone();
        tokio::spawn(async move {
            leader_loop(&database_url, is_leader, leader_notify).await;
        });
    }

    for name in loops {
        match name.as_str() {
            "env-reconciler" => {
                // Program #2238 B1: shadow-record claim-time workspace
                // bindings and first PVC UIDs as their own leader task, off
                // the reconciler's cadence and with their own time budget.
                // Nothing reads the records yet.
                let backfill_ctx = ctx.clone();
                let backfill_leader = is_leader.clone();
                tokio::spawn(async move {
                    super::workspace_binding::workspace_binding_backfill_loop(
                        backfill_ctx,
                        backfill_leader,
                    )
                    .await;
                });
                let ctx = ctx.clone();
                let is_leader = is_leader.clone();
                let leader_notify = leader_notify.clone();
                tokio::spawn(async move {
                    reconciler_loop(ctx, is_leader, leader_notify).await;
                });
            }
            "sandbox-liveness" => {
                let ctx = ctx.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    sandbox_liveness_loop(ctx, is_leader).await;
                });
            }
            // Sandbox billing-session lifecycle controller (port of
            // `internal/billing/sessions`).
            "billing-session" => {
                let ctx = ctx.clone();
                let is_leader = is_leader.clone();
                // Mirrors the retired Go composition-root default:
                // firstNonEmpty(BillingControllerNamespace, SandboxNamespace).
                let namespace = ctx.sandbox_cfg.sandbox_namespace.clone();
                tokio::spawn(async move {
                    super::billing_sessions::billing_session_loop(ctx, is_leader, namespace).await;
                });
            }
            // Program #2238 C2: shared identity-free warm pools. Inert, with no
            // Kubernetes access at all, until SANDBOX_WARM_POOL_SHAPES names a
            // shape.
            "warm-pool" => {
                let ctx = ctx.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    super::warm_pool::warm_pool_loop(ctx, is_leader).await;
                });
            }
            // Design §4: the credential relay pulls every bound daemon's
            // bridge to the broker. Leader-gated, so one relay serves each
            // environment; inert without the platform credential runtime.
            "credential-relay" => {
                let ctx = ctx.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    super::credential_relay::credential_relay_loop(ctx, is_leader).await;
                });
            }
            // Not leader-gated: every orchestration Pod adds the image set it
            // renders, so a rolling deploy's new Pods warm their release
            // before the old leader steps down.
            "image-cache" => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    super::image_cache::image_cache_loop(ctx).await;
                });
            }
            other => {
                tracing::warn!(name = other, "worker: unknown loop name, ignoring");
            }
        }
    }
    tracing::info!(count = loops.len(), "worker loops started");
}

/// Mirrors `runLeaderLoop`/`holdLock`: a dedicated connection holds
/// pg_try_advisory_lock; lost connection = lost leadership.
async fn leader_loop(database_url: &str, is_leader: Arc<AtomicBool>, leader_notify: Arc<Notify>) {
    loop {
        let mut conn = match PgConnection::connect(database_url).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "leader: failed to acquire connection");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let acquired: bool =
            match sqlx::query(&format!("SELECT pg_try_advisory_lock({ADVISORY_LOCK_ID})"))
                .fetch_one(&mut conn)
                .await
                .and_then(|r| r.try_get(0))
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "leader: failed to acquire advisory lock");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        if !acquired {
            tracing::debug!("leader: lock held by another instance, retrying");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        tracing::info!("leader: acquired leadership");
        is_leader.store(true, Ordering::SeqCst);
        leader_notify.notify_waiters();

        // Hold the lock with periodic pings; connection loss drops it.
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = conn.ping().await {
                tracing::error!(error = %e, "leader: connection health check failed");
                break;
            }
        }
        is_leader.store(false, Ordering::SeqCst);
        tracing::warn!("leader: connection lost, will retry");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Mirrors `StartReconciler`'s tick loop: startup recovery once per
/// leadership acquisition, then the reconciliation cycle every 30s.
async fn reconciler_loop(
    ctx: Arc<WorkerContext>,
    is_leader: Arc<AtomicBool>,
    leader_notify: Arc<Notify>,
) {
    let mut ticker = tokio::time::interval(RECONCILER_INTERVAL);
    ticker.tick().await; // align with Go's NewTicker (first fire after interval)
    let mut startup_recovery_observed = false;
    let mut legacy_warm_pool_retirement_complete = false;
    loop {
        tokio::select! {
            _ = leader_notify.notified() => {
                if is_leader.load(Ordering::SeqCst) {
                    legacy_warm_pool_retirement_complete = retire_legacy_shared_warm_pools(ctx.runtime.as_deref(), &ctx.sandbox_cfg.sandbox_namespace).await;
                    recover_on_startup(&ctx).await;
                    startup_recovery_observed = true;
                }
            }
            _ = ticker.tick() => {
                if is_leader.load(Ordering::SeqCst) {
                    // Notify does not retain a permit when leadership is won
                    // before this task begins waiting. The first leader tick
                    // is therefore the fallback that makes startup recovery,
                    // including CPV authorization migration, deterministic.
                    if !startup_recovery_observed {
                        recover_on_startup(&ctx).await;
                        startup_recovery_observed = true;
                    }
                    if !legacy_warm_pool_retirement_complete {
                        legacy_warm_pool_retirement_complete = retire_legacy_shared_warm_pools(ctx.runtime.as_deref(), &ctx.sandbox_cfg.sandbox_namespace).await;
                    }
                    run_reconciliation(&ctx).await;
                } else {
                    startup_recovery_observed = false;
                    legacy_warm_pool_retirement_complete = false;
                }
            }
        }
    }
}

async fn retire_legacy_shared_warm_pools(
    runtime: Option<&dyn RuntimeDriver>,
    namespace: &str,
) -> bool {
    let Some(runtime) = runtime else {
        tracing::warn!("reconciler: legacy shared warm-pool retirement requires Kubernetes access");
        return false;
    };
    match runtime
        .retire_legacy_shared_pools(&Placement::new(namespace))
        .await
    {
        Ok(0) => {
            tracing::info!("reconciler: legacy shared warm-pool retirement complete");
            true
        }
        Ok(retired) => {
            tracing::info!(
                retired,
                "reconciler: legacy shared warm-pool retirement requested"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "reconciler: legacy shared warm-pool retirement remains pending"
            );
            false
        }
    }
}

async fn run_reconciliation(ctx: &WorkerContext) {
    tracing::debug!("reconciler: running reconciliation cycle");
    reconcile_pending_organization_deletions(ctx).await;
    reconcile_pending_account_deletions(ctx).await;
    evict_expired_environments(ctx).await;
    stop_credit_exhausted_environments(ctx).await;
    process_graced_deletions(ctx).await;
    warn_expiring_environments(ctx).await;
    reconcile_incomplete_external_cleanup(ctx).await;
    recover_pending_creates(ctx).await;
    reconcile_stuck_environments(ctx).await;
    if let Err(error) = super::snapshots::reconcile_snapshots(ctx).await {
        tracing::warn!(error = %error, "reconciler: hosted snapshot reconcile failed");
    }
    // Trial expiry checks stay with the Go reconciler until the
    // billing-usage port (billing concern, not orchestration).
}

/// Mirrors `evictExpiredEnvironments`.
async fn evict_expired_environments(ctx: &WorkerContext) {
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT id FROM environments
           WHERE shutdown_at < NOW()
           AND state NOT IN ('destroyed', 'destroying', 'error')
           AND NOT protected"#,
    )
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query expired environments");
            return;
        }
    };

    for (id,) in ids {
        tracing::info!(
            environment_id = id,
            "reconciler: evicting expired environment"
        );
        if let Err(e) = svc.set_desired_state(&id, "destroyed").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: set desired_state=destroyed for expired environment");
            continue;
        }
        if let Err(e) = enqueue_environment_reconcile(ctx, &id, false, "ttl eviction").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: failed to enqueue reconcile for expired environment");
        }
    }
}

/// Stops the running sandboxes of organizations that have had no compute
/// credit, and no way to get it, for 24 hours (#3381). Storage is kept.
async fn stop_credit_exhausted_environments(ctx: &WorkerContext) {
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    let ids = match super::credit_stop::credit_exhausted_environment_ids(
        &ctx.pool,
        ctx.credit_enforcement,
    )
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query credit-exhausted environments");
            return;
        }
    };
    for id in ids {
        tracing::info!(
            environment_id = id,
            "reconciler: stopping a sandbox whose organization ran out of credit"
        );
        if let Err(e) = svc.set_desired_state(&id, "stopped").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: set desired_state=stopped for credit exhaustion");
            continue;
        }
        if let Err(e) = enqueue_environment_reconcile(ctx, &id, false, "credit exhausted").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: failed to enqueue reconcile for credit exhaustion");
        }
    }
}

/// Mirrors `processGracedDeletions`.
async fn process_graced_deletions(ctx: &WorkerContext) {
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT id FROM environments
           WHERE deletion_grace_until IS NOT NULL
           AND deletion_grace_until < NOW()
           AND desired_state != 'destroyed'
           AND state NOT IN ('destroyed', 'destroying')
           AND NOT protected"#,
    )
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query graced deletions");
            return;
        }
    };

    for (id,) in ids {
        tracing::info!(
            environment_id = id,
            "reconciler: grace period expired, destroying environment"
        );
        if let Err(e) = svc.clear_deletion_grace(&id).await {
            tracing::error!(environment_id = id, error = %e, "reconciler: clear deletion grace for expired request");
            continue;
        }
        if let Err(e) = svc.set_desired_state(&id, "destroyed").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: set desired_state=destroyed for graced deletion");
            continue;
        }
        if let Err(e) = enqueue_environment_reconcile(ctx, &id, false, "grace period expired").await
        {
            tracing::error!(environment_id = id, error = %e, "reconciler: failed to enqueue reconcile for graced deletion");
        }
    }
}

/// Mirrors `warnExpiringEnvironments`.
async fn warn_expiring_environments(ctx: &WorkerContext) {
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT id FROM environments
           WHERE shutdown_at IS NOT NULL
           AND shutdown_at BETWEEN NOW() AND NOW() + INTERVAL '5 minutes'
           AND state = 'running'
           AND NOT protected
           AND ttl_warning_sent_at IS NULL"#,
    )
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query expiring environments");
            return;
        }
    };

    for (id,) in ids {
        tracing::info!(environment_id = id, "reconciler: environment expiring soon");
        if let Err(e) = svc.mark_ttl_warning_sent(&id).await {
            tracing::error!(environment_id = id, error = %e, "reconciler: mark ttl warning sent");
        }
    }
}

/// Re-signal environments that accepted create but stayed pending long
/// enough that the primary SignalWithStart path may have been lost or
/// delayed. The create activity is idempotent, so duplicate signals are
/// safer than leaving a user-visible env in pending until the general
/// 5-minute stuck-state recovery window.
async fn recover_pending_creates(ctx: &WorkerContext) {
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT id
             FROM environments
            WHERE state = 'pending'
              AND desired_state = 'started'
              AND state_changed_at < NOW() - ($1 * INTERVAL '1 second')"#,
    )
    .bind(PENDING_CREATE_RECOVERY_SECS)
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query pending create environments");
            return;
        }
    };

    for (id,) in ids {
        if let Err(e) = enqueue_environment_create(ctx, &id, "pending-create recovery").await {
            tracing::error!(environment_id = id, error = %e, "reconciler: enqueue pending create failed");
        }
    }
}

/// Retry every destroy whose external absence proof is still missing. This
/// includes historical `destroyed` rows: state alone is not provider absence
/// evidence. Provider failures record `error` without clearing destroyed
/// intent, so those rows must also return to the canonical Temporal workflow,
/// which re-enumerates retained backend/session namespaces before writing the
/// marker.
async fn reconcile_incomplete_external_cleanup(ctx: &WorkerContext) {
    let states: Vec<String> = INCOMPLETE_EXTERNAL_CLEANUP_STATES
        .iter()
        .map(|state| (*state).to_string())
        .collect();
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT e.id
             FROM environments e
            WHERE e.state = ANY($1)
              AND e.desired_state = 'destroyed'
              AND e.external_cleanup_completed_at IS NULL
              AND e.state_changed_at < NOW() - ($2 * INTERVAL '1 second')"#,
    )
    .bind(&states)
    .bind(DESTROY_WITHOUT_BACKEND_RECOVERY_SECS)
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query incomplete external cleanup");
            return;
        }
    };

    if ids.is_empty() {
        return;
    }

    for (id,) in ids {
        tracing::info!(
            environment_id = id,
            "reconciler: retrying incomplete external cleanup"
        );
        if let Err(e) =
            enqueue_environment_reconcile(ctx, &id, true, "external-cleanup recovery").await
        {
            tracing::error!(environment_id = id, error = %e, "reconciler: enqueue external cleanup failed");
        }
    }
}

/// Mirrors `reconcileStuckEnvironments`.
async fn reconcile_stuck_environments(ctx: &WorkerContext) {
    let kinds: Vec<String> = RECOVERY_JOURNAL_KINDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let ids: Vec<(String,)> = match sqlx::query_as(
        r#"SELECT e.id
             FROM environments e
             LEFT JOIN LATERAL (
               SELECT MAX(created_at) AS last_activity_at
                 FROM environment_lifecycle_journal
                WHERE environment_id = e.id
                  AND kind = ANY($1)
             ) log_activity ON true
            WHERE e.state != e.desired_state
              AND GREATEST(e.state_changed_at, COALESCE(log_activity.last_activity_at, e.state_changed_at)) < NOW() - ($2 * INTERVAL '1 second')
              AND e.state NOT IN ('destroyed', 'build_failed')
              AND (e.state != 'error' OR e.retry_count < 3)"#,
    )
    .bind(&kinds)
    .bind(RECOVERY_ACTIVITY_WINDOW_SECS)
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query stuck environments");
            return;
        }
    };

    for (id,) in ids {
        if let Err(e) = enqueue_environment_reconcile(ctx, &id, false, "stuck-state recovery").await
        {
            tracing::error!(environment_id = id, error = %e, "reconciler: enqueue stuck environment reconcile failed");
        }
    }
}

/// Mirrors `recoverOnStartup` + `recoverInterruptedEnvironments`.
async fn recover_on_startup(ctx: &WorkerContext) {
    reconcile_pending_organization_deletions(ctx).await;
    reconcile_pending_account_deletions(ctx).await;

    let kinds: Vec<String> = RECOVERY_JOURNAL_KINDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let rows: Vec<(String, String)> = match sqlx::query_as(
        r#"SELECT e.id, e.state
             FROM environments e
             LEFT JOIN LATERAL (
               SELECT MAX(created_at) AS last_activity_at
                 FROM environment_lifecycle_journal
                WHERE environment_id = e.id
                  AND kind = ANY($1)
             ) log_activity ON true
            WHERE e.state IN ('creating', 'starting', 'stopping', 'destroying')
              AND (
                log_activity.last_activity_at IS NULL OR
                log_activity.last_activity_at < NOW() - ($2 * INTERVAL '1 second')
              )"#,
    )
    .bind(&kinds)
    .bind(RECOVERY_ACTIVITY_WINDOW_SECS)
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: startup recovery query interrupted environments");
            return;
        }
    };

    let mut recovered = 0;
    for (id, state) in rows {
        if let Err(e) = enqueue_environment_reconcile(ctx, &id, true, "startup recovery").await {
            tracing::error!(environment_id = id, state, error = %e, "reconciler: startup recovery enqueue failed");
            continue;
        }
        recovered += 1;
    }
    if recovered > 0 {
        tracing::info!(recovered, "reconciler: startup recovery complete");
    } else {
        tracing::debug!("reconciler: startup recovery — no interrupted environments found");
    }
}

/// Recover the transactionally committed organization-deletion outbox. A
/// start attempt is recorded before Temporal is contacted, and the operation
/// is acknowledged only after the deterministic workflow start succeeds.
/// `UseExisting` in the trigger closes the crash window between those events.
async fn reconcile_pending_organization_deletions(ctx: &WorkerContext) {
    use codewire_server_core::org_deletion::{
        mark_organization_deletion_started, pending_organization_deletion_operations,
        record_organization_deletion_start_attempt,
    };

    let operations = match pending_organization_deletion_operations(&ctx.pool, 100).await {
        Ok(operations) => operations,
        Err(error) => {
            tracing::error!(error = %error, "reconciler: query pending organization deletions");
            return;
        }
    };

    for operation in operations {
        if let Err(error) = record_organization_deletion_start_attempt(
            &ctx.pool,
            &operation.id,
            operation.generation,
        )
        .await
        {
            tracing::warn!(
                operation_id = operation.id,
                organization_id = operation.organization_id,
                generation = operation.generation,
                error = %error,
                "reconciler: organization deletion start attempt was not recorded"
            );
            continue;
        }

        let input = super::organization_deletion::OrganizationDeletionWorkflowInput {
            operation_id: operation.id.clone(),
            organization_id: operation.organization_id.clone(),
            generation: operation.generation,
        };
        if let Err(error) = ctx
            .temporal_trigger
            .trigger_organization_deletion(input)
            .await
        {
            tracing::warn!(
                operation_id = operation.id,
                organization_id = operation.organization_id,
                generation = operation.generation,
                error = %error,
                "reconciler: organization deletion workflow start remains pending"
            );
            continue;
        }

        match mark_organization_deletion_started(&ctx.pool, &operation.id, operation.generation)
            .await
        {
            Ok(_) => tracing::info!(
                operation_id = operation.id,
                organization_id = operation.organization_id,
                generation = operation.generation,
                "reconciler: organization deletion workflow started"
            ),
            Err(error) => tracing::warn!(
                operation_id = operation.id,
                organization_id = operation.organization_id,
                generation = operation.generation,
                error = %error,
                "reconciler: organization deletion workflow start acknowledgement remains pending"
            ),
        }
    }
}

/// Recover the transactionally committed account-deletion outbox (#3679), as
/// for organization deletions: record the attempt, start the deterministic
/// workflow, then acknowledge it.
async fn reconcile_pending_account_deletions(ctx: &WorkerContext) {
    use codewire_server_core::account_deletion::{
        AccountDeletionWorkflowInput, mark_account_deletion_started,
        pending_account_deletion_operations, record_account_deletion_start_attempt,
    };

    let operations = match pending_account_deletion_operations(&ctx.pool, 100).await {
        Ok(operations) => operations,
        Err(error) => {
            tracing::error!(error = %error, "reconciler: query pending account deletions");
            return;
        }
    };

    for operation in operations {
        if let Err(error) = record_account_deletion_start_attempt(&ctx.pool, &operation.id).await {
            tracing::warn!(
                operation_id = operation.id,
                error = %error,
                "reconciler: account deletion start attempt was not recorded"
            );
            continue;
        }
        let input = AccountDeletionWorkflowInput {
            operation_id: operation.id.clone(),
        };
        if let Err(error) = ctx.temporal_trigger.trigger_account_deletion(input).await {
            tracing::warn!(
                operation_id = operation.id,
                error = %error,
                "reconciler: account deletion workflow start remains pending"
            );
            continue;
        }
        match mark_account_deletion_started(&ctx.pool, &operation.id).await {
            Ok(()) => tracing::info!(
                operation_id = operation.id,
                "reconciler: account deletion workflow started"
            ),
            Err(error) => tracing::warn!(
                operation_id = operation.id,
                error = %error,
                "reconciler: account deletion workflow start acknowledgement remains pending"
            ),
        }
    }
}

async fn enqueue_environment_create(
    ctx: &WorkerContext,
    env_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    if let Err(e) = ctx
        .temporal_trigger
        .trigger_environment(env_id, "create")
        .await
    {
        tracing::error!(environment_id = env_id, reason, error = %e, "reconciler: trigger environment create failed");
        return Err(e);
    }
    super::env_log::emit_environment_log(
        &ctx.pool,
        env_id,
        "create_enqueue",
        "completed",
        "Create requested",
        Some(serde_json::json!({ "reason": reason, "recovery": true })),
    )
    .await;
    tracing::info!(
        environment_id = env_id,
        reason,
        "reconciler: trigger environment create"
    );
    Ok(())
}

/// Mirrors `enqueueEnvironmentReconcile`: SignalWithStart the
/// environment workflow (D3 — Temporal is the only trigger path).
///
/// `recovery` distinguishes startup recovery from steady-state
/// reconciles; the old NATS path purged a stale `TENANT_LOCKS` entry on
/// recovery, but per-environment serialization is now structural (one
/// workflow per environment id) so there is nothing to purge.
async fn enqueue_environment_reconcile(
    ctx: &WorkerContext,
    env_id: &str,
    recovery: bool,
    reason: &str,
) -> anyhow::Result<()> {
    if let Err(e) = ctx
        .temporal_trigger
        .trigger_environment(env_id, "reconcile")
        .await
    {
        tracing::error!(environment_id = env_id, reason, recovery, error = %e, "reconciler: trigger environment reconcile failed");
        return Err(e);
    }
    super::env_log::emit_environment_log(
        &ctx.pool,
        env_id,
        "reconcile_enqueue",
        "completed",
        "Reconcile requested",
        Some(serde_json::json!({ "reason": reason, "recovery": recovery })),
    )
    .await;
    tracing::info!(
        environment_id = env_id,
        reason,
        recovery,
        "reconciler: trigger environment reconcile"
    );
    Ok(())
}

// ── Sandbox liveness (port of sandbox_liveness.go) ─────────────────────

#[derive(Clone)]
pub(super) struct LivenessRow {
    pub(super) id: String,
    pub(super) state: String,
    pub(super) desired_state: String,
    pub(super) operation_generation: i64,
    pub(super) state_changed_at: chrono::DateTime<chrono::Utc>,
    pub(super) namespace: String,
    pub(super) pod_name: String,
    pub(super) pod_ip: String,
    /// The bound workspace Pod UID (Program #2238 design §10).
    pub(super) bound_pod_uid: Option<String>,
    pub(super) setup_owner_generation: Option<i64>,
    pub(super) setup_owner_status: String,
}

async fn sandbox_liveness_loop(ctx: Arc<WorkerContext>, is_leader: Arc<AtomicBool>) {
    // Mirrors the Backend==nil early return.
    if ctx.runtime.is_none() {
        return;
    }
    let mut ticker = tokio::time::interval(SANDBOX_LIVENESS_INTERVAL);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            continue;
        }
        reconcile_sandbox_liveness(&ctx).await;
    }
}

async fn reconcile_sandbox_liveness(ctx: &WorkerContext) {
    let rows = match sqlx::query(
        r#"SELECT e.id, e.state, e.desired_state, e.state_changed_at,
                  e.environment_operation_generation,
                  COALESCE(b.namespace, '') AS namespace,
                  COALESCE(b.pod_name, '') AS pod_name,
                  COALESCE(b.pod_ip, '') AS pod_ip,
                  b.pod_uid AS bound_pod_uid,
                  b.setup_owner_generation,
                  COALESCE(b.setup_owner_status, '') AS setup_owner_status
             FROM environments e
             JOIN sandbox_environment_backend b ON b.environment_id = e.id
            WHERE e.type = 'sandbox'
              AND e.desired_state = 'started'
              AND e.state IN ('running', 'creating', 'starting')"#,
    )
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "sandbox liveness: query environments");
            return;
        }
    };

    let now = chrono::Utc::now();
    for row in rows {
        // state_changed_at is timestamp WITHOUT time zone — read naive
        // and interpret as UTC like pgx does.
        let state_changed_at: chrono::NaiveDateTime = match row.try_get("state_changed_at") {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "sandbox liveness: scan row failed");
                continue;
            }
        };
        let parsed = LivenessRow {
            id: row.try_get("id").unwrap_or_default(),
            state: row.try_get("state").unwrap_or_default(),
            desired_state: row.try_get("desired_state").unwrap_or_default(),
            operation_generation: row
                .try_get("environment_operation_generation")
                .unwrap_or_default(),
            state_changed_at: state_changed_at.and_utc(),
            namespace: row.try_get("namespace").unwrap_or_default(),
            pod_name: row.try_get("pod_name").unwrap_or_default(),
            pod_ip: row.try_get("pod_ip").unwrap_or_default(),
            bound_pod_uid: row.try_get("bound_pod_uid").unwrap_or(None),
            setup_owner_generation: row.try_get("setup_owner_generation").unwrap_or(None),
            setup_owner_status: row.try_get("setup_owner_status").unwrap_or_default(),
        };
        reconcile_single_sandbox_liveness(ctx, now, parsed).await;
    }
}

async fn reconcile_single_sandbox_liveness(
    ctx: &WorkerContext,
    now: chrono::DateTime<chrono::Utc>,
    row: LivenessRow,
) {
    let Some(runtime) = &ctx.runtime else { return };
    let Some(reason) = observe_sandbox_liveness(&ctx.pool, runtime.as_ref(), now, &row).await
    else {
        return;
    };
    // Should this fail, the stuck-state sweep still recovers the sandbox.
    if let Err(error) = enqueue_environment_reconcile(ctx, &row.id, true, reason).await {
        tracing::warn!(
            environment_id = row.id,
            reason,
            error = %error,
            "sandbox liveness: enqueue reconcile failed"
        );
    }
}

/// Compares a sandbox with its runtime and records what it finds. Returns why
/// a reconcile is needed now, if one is.
pub(super) async fn observe_sandbox_liveness(
    pool: &PgPool,
    runtime: &dyn RuntimeDriver,
    now: chrono::DateTime<chrono::Utc>,
    row: &LivenessRow,
) -> Option<&'static str> {
    if row.desired_state != "started" {
        tracing::debug!(
            environment_id = row.id,
            state = row.state,
            desired_state = row.desired_state,
            "sandbox liveness: lifecycle transition owns sandbox readiness"
        );
        return None;
    }
    if setup_activity_active(row) {
        tracing::debug!(
            environment_id = row.id,
            operation_generation = row.operation_generation,
            setup_owner_status = row.setup_owner_status,
            "sandbox liveness: current setup activity owns sandbox readiness"
        );
        return None;
    }
    let grace = chrono::Duration::from_std(SANDBOX_TRANSITIONAL_LIVENESS_GRACE).unwrap();
    if row.namespace.is_empty() {
        if row.state != "running" && now - row.state_changed_at < grace {
            return None;
        }
        mark_sandbox_env_error(pool, row, "sandbox backend namespace missing").await;
        return None;
    }

    let probe = match runtime
        .probe(&Placement::new(&row.namespace), &row.id)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(environment_id = row.id, namespace = row.namespace, error = %e, "sandbox liveness: probe failed");
            return None;
        }
    };

    if running_pod_is_leaving(now, row, &probe) {
        tracing::info!(
            environment_id = row.id,
            pod_uid = probe.pod_uid,
            pod_phase = probe.pod_phase,
            "sandbox liveness: a Pod being deleted has not failed"
        );
        return None;
    }

    if running_runtime_recovery_required(row, &probe) {
        return Some("workspace Pod runtime identity is not current");
    }

    if let Some(reason) = sandbox_liveness_reason(now, row, &probe) {
        if sandbox_pod_failed_on_its_node(row, &probe) {
            // The user is told it is restarting, and the volume is still
            // there, so start now rather than at the next sweep.
            if mark_sandbox_stopped(pool, row, &reason).await && crash_recovery_due(now, row) {
                return Some("sandbox stopped unexpectedly");
            }
        } else {
            mark_sandbox_env_error(pool, row, &reason).await;
        }
        return None;
    }

    if !probe.pod_name.is_empty() || !probe.pod_ip.is_empty() {
        sync_sandbox_backend_pod_info(pool, row, &probe).await;
    }
    None
}

/// Whether a sandbox that just stopped had been running long enough to restart
/// at once.
fn crash_recovery_due(now: chrono::DateTime<chrono::Utc>, row: &LivenessRow) -> bool {
    now - row.state_changed_at >= chrono::Duration::from_std(CRASH_RECOVERY_MIN_RUNNING).unwrap()
}

/// A deleted Pod's containers exit as it goes, and it can show `Succeeded` or
/// `Failed` before it is removed. Something asked for that, such as a daemon
/// repair replacing it, so it says nothing about the sandbox (#3944). Kubernetes
/// holds the mark, so this survives a restart and needs no agreement between
/// workers. The grace bounds it: a Pod stuck going counts as failed again.
fn running_pod_is_leaving(
    now: chrono::DateTime<chrono::Utc>,
    row: &LivenessRow,
    probe: &ProbeResult,
) -> bool {
    row.state == "running"
        && matches!(probe.pod_phase.as_str(), "Failed" | "Succeeded")
        && probe.pod_deleting_at.is_some_and(|deleting_at| {
            now.timestamp() - deleting_at.as_second()
                < SANDBOX_TRANSITIONAL_LIVENESS_GRACE.as_secs() as i64
        })
}

fn running_runtime_recovery_required(row: &LivenessRow, probe: &ProbeResult) -> bool {
    if row.state != "running"
        || row.desired_state != "started"
        || !probe.claim_exists
        || (is_terminal_claim_reason(&probe.claim_reason)
            && !claim_failure_is_of_an_earlier_pod(probe))
        || matches!(probe.pod_phase.as_str(), "Failed" | "Succeeded")
    {
        return false;
    }
    // A Pod replaced under the same name, and possibly the same IP, keeps
    // both. Its UID differs from the bound one, so the reconcile records the
    // replacement's binding before any gateway wait; until then its daemon
    // stays unbound and unreachable, never serving the old binding.
    (!probe.claim_ready && !is_transient_claim_reason(&probe.claim_reason))
        || !probe.pod_exists
        || probe.pod_name.is_empty()
        || probe.pod_uid.is_empty()
        || probe.pod_ip.is_empty()
        || probe.pod_name != row.pod_name
        || probe.pod_ip != row.pod_ip
        || row
            .bound_pod_uid
            .as_deref()
            .is_some_and(|bound| bound != probe.pod_uid)
}

/// A terminal phase is final for a Pod, so a live Pod isn't the one a claim's
/// `PodFailed` describes: the claim hasn't caught up with its replacement (#3944).
fn claim_failure_is_of_an_earlier_pod(probe: &ProbeResult) -> bool {
    probe.claim_reason == "PodFailed"
        && probe.pod_exists
        && !matches!(probe.pod_phase.as_str(), "" | "Failed" | "Succeeded")
}

fn setup_activity_active(row: &LivenessRow) -> bool {
    row.state == "running"
        && row.desired_state == "started"
        && row.setup_owner_generation == Some(row.operation_generation)
        && matches!(
            row.setup_owner_status.as_str(),
            "claimed" | "running" | "reaping"
        )
}

/// A claim that is not Ready for a reason that resolves on its own while the
/// Pod keeps running. `SandboxUpdatePending` (agent-sandbox fork, Program
/// #2238 C0): the Sandbox controller has not yet applied the Sandbox's
/// current generation, for example a claim's metadata after a warm adoption,
/// to the Pod. Liveness neither fails nor recovers the runtime for it; the Pod
/// checks still apply.
fn is_transient_claim_reason(reason: &str) -> bool {
    matches!(reason, "SandboxUpdatePending")
}

/// Mirrors `sandbox.IsTerminalClaimReason`.
fn is_terminal_claim_reason(reason: &str) -> bool {
    matches!(
        reason,
        "SandboxExpired"
            | "SandboxDeleted"
            | "SandboxFailed"
            | "PodFailed"
            | "NodeLost"
            | "NodeDeleted"
            | "Evicted"
            | "Failed"
    )
}

/// Mirrors `sandboxLivenessReason`.
fn sandbox_liveness_reason(
    now: chrono::DateTime<chrono::Utc>,
    row: &LivenessRow,
    probe: &ProbeResult,
) -> Option<String> {
    if row.desired_state != "started" {
        return None;
    }
    let grace = chrono::Duration::from_std(SANDBOX_TRANSITIONAL_LIVENESS_GRACE).unwrap();
    match row.state.as_str() {
        "running" => {
            if !probe.claim_exists {
                Some("sandbox claim missing".to_string())
            } else if !probe.claim_ready && !is_transient_claim_reason(&probe.claim_reason) {
                if probe.claim_reason.is_empty() {
                    Some("sandbox claim not ready".to_string())
                } else {
                    Some(format!("sandbox claim not ready: {}", probe.claim_reason))
                }
            } else if !probe.pod_exists {
                Some("sandbox pod missing".to_string())
            } else if probe.pod_uid.is_empty() {
                Some("sandbox pod missing UID".to_string())
            } else if probe.pod_phase == "Failed" || probe.pod_phase == "Succeeded" {
                Some(format!(
                    "sandbox pod entered {} unexpectedly",
                    probe.pod_phase.to_lowercase()
                ))
            } else if probe.pod_ip.is_empty() {
                Some("sandbox pod missing IP".to_string())
            } else {
                None
            }
        }
        state @ ("creating" | "starting") => {
            if now - row.state_changed_at < grace {
                return None;
            }
            if !probe.claim_exists {
                Some(format!("sandbox claim missing during {state}"))
            } else if probe.pod_phase == "Failed" || probe.pod_phase == "Succeeded" {
                Some(format!(
                    "sandbox pod entered {} during {state}",
                    probe.pod_phase.to_lowercase()
                ))
            } else if !probe.claim_ready {
                if !probe.claim_reason.is_empty() && is_terminal_claim_reason(&probe.claim_reason) {
                    Some(format!(
                        "sandbox did not become ready during {state}: {}",
                        probe.claim_reason
                    ))
                } else {
                    None
                }
            } else if !probe.pod_exists {
                Some(format!("sandbox pod missing during {state}"))
            } else if probe.pod_ip.is_empty() {
                Some(format!("sandbox pod missing IP during {state}"))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A running sandbox's Pod failed while its node stayed, which leaves its volume
/// and its way back. Whatever killed it isn't known here (#3772).
fn sandbox_pod_failed_on_its_node(row: &LivenessRow, probe: &ProbeResult) -> bool {
    row.state == "running"
        && !matches!(probe.claim_reason.as_str(), "NodeLost" | "NodeDeleted")
        && (probe.pod_phase == "Failed" || probe.claim_reason == "PodFailed")
}

async fn sync_sandbox_backend_pod_info(pool: &PgPool, row: &LivenessRow, probe: &ProbeResult) {
    if probe.pod_name == row.pod_name && probe.pod_ip == row.pod_ip {
        return;
    }
    let authority = match ActivityAuthority::capture_required(
        pool,
        &row.id,
        &row.desired_state,
        row.operation_generation,
    )
    .await
    {
        Ok(authority) => authority,
        Err(error) if is_authority_lost(&error) => return,
        Err(error) => {
            tracing::warn!(environment_id = row.id, error = %error, "sandbox liveness: capture pod-info authority failed");
            return;
        }
    };
    let result = async {
        let mut tx = pool.begin().await?;
        authority.lock_transaction(&mut tx).await?;
        sqlx::query(
            "UPDATE sandbox_environment_backend
                SET pod_name = $1, pod_ip = $2
              WHERE environment_id = $3",
        )
        .bind(&probe.pod_name)
        .bind(&probe.pod_ip)
        .bind(&row.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(e) = result {
        if is_authority_lost(&e) {
            return;
        }
        tracing::warn!(environment_id = row.id, error = %e, "sandbox liveness: sync pod info failed");
    }
}

/// The internal reason stays in the worker's log; the user gets the plain message.
/// Returns whether this call marked it.
async fn mark_sandbox_stopped(pool: &PgPool, row: &LivenessRow, reason: &str) -> bool {
    let authority = match ActivityAuthority::capture_required(
        pool,
        &row.id,
        &row.desired_state,
        row.operation_generation,
    )
    .await
    {
        Ok(authority) => authority,
        Err(error) if is_authority_lost(&error) => return false,
        Err(error) => {
            tracing::error!(environment_id = row.id, error = %error, "sandbox liveness: capture stopped authority failed");
            return false;
        }
    };
    let svc = Service::<PgLifecycleStore>::for_activity(pool.clone(), authority);
    match svc.mark_sandbox_stopped(&row.id).await {
        Err(e) => {
            tracing::error!(environment_id = row.id, error = %e, "sandbox liveness: mark stopped failed");
            false
        }
        Ok(true) => {
            tracing::warn!(
                environment_id = row.id,
                reason,
                "sandbox liveness: running sandbox stopped unexpectedly"
            );
            true
        }
        Ok(false) => false,
    }
}

async fn mark_sandbox_env_error(pool: &PgPool, row: &LivenessRow, reason: &str) {
    let authority = match ActivityAuthority::capture_required(
        pool,
        &row.id,
        &row.desired_state,
        row.operation_generation,
    )
    .await
    {
        Ok(authority) => authority,
        Err(error) if is_authority_lost(&error) => return,
        Err(error) => {
            tracing::error!(environment_id = row.id, state = row.state, error = %error, "sandbox liveness: capture error authority failed");
            return;
        }
    };
    let svc = Service::<PgLifecycleStore>::for_activity(pool.clone(), authority);
    match svc
        .mark_error_for_states(&row.id, reason, &[row.state.as_str()])
        .await
    {
        Err(e) => {
            tracing::error!(environment_id = row.id, state = row.state, error = %e, "sandbox liveness: mark error failed");
        }
        Ok(true) => {
            tracing::warn!(
                environment_id = row.id,
                from_state = row.state,
                reason,
                "sandbox liveness: environment marked error"
            );
        }
        Ok(false) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::fake::FakeRuntimeDriver;

    #[tokio::test]
    async fn legacy_pool_retirement_completes_only_when_the_runtime_reports_none_left() {
        assert!(!retire_legacy_shared_warm_pools(None, "ns").await);

        let runtime = FakeRuntimeDriver::default();
        runtime
            .retirements
            .lock()
            .unwrap()
            .extend([Ok(2), Err("list refused".to_string()), Ok(0)]);
        let answers = [false, false, true];
        for complete in answers {
            assert_eq!(
                retire_legacy_shared_warm_pools(Some(&runtime), "ns").await,
                complete
            );
        }
        assert_eq!(
            *runtime.placements.lock().unwrap(),
            vec![Placement::new("ns"); answers.len()]
        );
    }

    #[test]
    fn incomplete_external_cleanup_recovery_includes_errored_destroy_intent() {
        assert_eq!(
            INCOMPLETE_EXTERNAL_CLEANUP_STATES,
            ["destroying", "destroyed", "error"]
        );
    }

    fn row(state: &str, age_secs: i64) -> LivenessRow {
        LivenessRow {
            id: "env-1".into(),
            state: state.into(),
            desired_state: "started".into(),
            operation_generation: 1,
            state_changed_at: chrono::Utc::now() - chrono::Duration::seconds(age_secs),
            namespace: "ns".into(),
            pod_name: "p".into(),
            pod_ip: "10.0.0.1".into(),
            bound_pod_uid: None,
            setup_owner_generation: None,
            setup_owner_status: String::new(),
        }
    }

    #[test]
    fn only_a_sandbox_that_stayed_up_restarts_at_once() {
        let running = row("running", 0);
        let minimum = chrono::Duration::from_std(CRASH_RECOVERY_MIN_RUNNING).unwrap();
        let at = running.state_changed_at + minimum;
        assert!(crash_recovery_due(at, &running));
        assert!(!crash_recovery_due(
            at - chrono::Duration::seconds(1),
            &running
        ));
    }

    #[test]
    fn current_generation_setup_lease_suppresses_liveness_interference() {
        let mut active = row("running", 300);
        active.setup_owner_generation = Some(active.operation_generation);
        for status in ["claimed", "running", "reaping"] {
            active.setup_owner_status = status.into();
            assert!(setup_activity_active(&active));
        }

        let mut stale = active;
        stale.setup_owner_generation = Some(stale.operation_generation - 1);
        assert!(!setup_activity_active(&stale));
    }

    fn probe(
        exists: bool,
        ready: bool,
        reason: &str,
        pod: bool,
        phase: &str,
        ip: &str,
    ) -> ProbeResult {
        ProbeResult {
            claim_exists: exists,
            claim_ready: ready,
            claim_reason: reason.into(),
            pod_exists: pod,
            pod_phase: phase.into(),
            pod_uid: if pod { "pod-uid" } else { "" }.into(),
            pod_ip: ip.into(),
            ..Default::default()
        }
    }

    #[test]
    fn running_replacement_recovers_before_liveness_marks_error() {
        let mut running = row("running", 300);
        running.pod_name = "old-pod".into();
        running.pod_ip = "10.1.1.1".into();

        let pending = probe(true, false, "", false, "", "");
        assert!(running_runtime_recovery_required(&running, &pending));

        let mut replacement = probe(true, true, "", true, "Running", "10.1.1.2");
        replacement.pod_name = "new-pod".into();
        replacement.pod_uid = "new-pod-uid".into();
        assert!(running_runtime_recovery_required(&running, &replacement));

        let terminal = probe(true, false, "PodFailed", false, "", "");
        assert!(!running_runtime_recovery_required(&running, &terminal));
    }

    /// A claim waiting for the Sandbox controller to apply its current
    /// generation to a still-running Pod is neither an error nor a reason to
    /// recover the runtime; the Pod checks still apply.
    #[test]
    fn sandbox_update_pending_is_transient() {
        let now = chrono::Utc::now();
        let mut running = row("running", 300);
        running.pod_name = "pod".into();
        running.pod_ip = "10.1.1.1".into();
        let mut pending = probe(
            true,
            false,
            "SandboxUpdatePending",
            true,
            "Running",
            "10.1.1.1",
        );
        pending.pod_name = "pod".into();
        assert!(is_transient_claim_reason("SandboxUpdatePending"));
        assert!(!is_terminal_claim_reason("SandboxUpdatePending"));
        assert!(!running_runtime_recovery_required(&running, &pending));
        assert_eq!(sandbox_liveness_reason(now, &running, &pending), None);

        // The Pod checks still apply while the update is pending.
        let mut lost = pending.clone();
        lost.pod_exists = false;
        lost.pod_uid = String::new();
        assert!(running_runtime_recovery_required(&running, &lost));
        assert_eq!(
            sandbox_liveness_reason(now, &running, &lost),
            Some("sandbox pod missing".into())
        );

        // Other not-ready reasons keep their behavior.
        let mut not_ready = pending.clone();
        not_ready.claim_reason = "SandboxNotReady".into();
        assert!(running_runtime_recovery_required(&running, &not_ready));
        assert_eq!(
            sandbox_liveness_reason(now, &running, &not_ready),
            Some("sandbox claim not ready: SandboxNotReady".into())
        );

        // Transitional states keep waiting on it, as on any non-terminal reason.
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("starting", 120),
                &probe(true, false, "SandboxUpdatePending", true, "Running", "")
            ),
            None
        );
    }

    /// #3944: what a daemon repair's deleted Pod looks like, and what doesn't.
    #[test]
    fn only_a_finished_pod_being_deleted_is_leaving() {
        let now = chrono::Utc::now();
        let seconds_ago = |seconds: i64| {
            k8s_openapi::jiff::Timestamp::from_second(now.timestamp() - seconds).unwrap()
        };
        let observed = |state: &str, phase: &str, deleting: Option<i64>| {
            let mut observed = probe(true, false, "PodSucceeded", true, phase, "");
            observed.pod_deleting_at = deleting.map(seconds_ago);
            running_pod_is_leaving(now, &row(state, 300), &observed)
        };

        assert!(observed("running", "Succeeded", Some(0)));
        assert!(observed("running", "Failed", Some(0)));
        // A mark ahead of now: the time it will be force-killed.
        assert!(observed("running", "Succeeded", Some(-30)));
        assert!(observed("running", "Succeeded", Some(59)));

        assert!(
            !observed("running", "Succeeded", None),
            "finished by itself"
        );
        assert!(!observed("running", "Failed", None), "failed by itself");
        assert!(!observed("running", "Succeeded", Some(60)), "stuck going");
        // Still running while it goes: the identity reconcile decides.
        assert!(!observed("running", "Running", Some(0)));
        // A start or create has its own window and its own checks.
        assert!(!observed("starting", "Succeeded", Some(0)));
        assert!(!observed("creating", "Failed", Some(0)));
    }

    /// Design §10: a Pod replaced under the same name and IP is found by its
    /// UID, and only once the environment is bound.
    #[test]
    fn a_replacement_under_the_same_name_and_ip_is_found_by_pod_uid() {
        let mut running = row("running", 300);
        let mut same = probe(true, true, "", true, "Running", "10.0.0.1");
        same.pod_name = "p".into();
        same.pod_uid = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52".into();
        // Unbound (a legacy Pod the backfill has not bound): name and IP only.
        assert!(!running_runtime_recovery_required(&running, &same));
        running.bound_pod_uid = Some(same.pod_uid.clone());
        assert!(!running_runtime_recovery_required(&running, &same));
        let mut replaced = same.clone();
        replaced.pod_uid = "a1560db3-8899-40c9-b521-500f223b04fb".into();
        assert!(running_runtime_recovery_required(&running, &replaced));
        // Never for a non-running or terminal runtime.
        let mut starting = running.clone();
        starting.state = "starting".into();
        assert!(!running_runtime_recovery_required(&starting, &replaced));
        let mut failed = replaced.clone();
        failed.pod_phase = "Failed".into();
        assert!(!running_runtime_recovery_required(&running, &failed));
    }

    #[test]
    fn only_a_failed_pod_on_a_live_node_counts_as_stopped_unexpectedly() {
        let running = row("running", 300);
        for (probe, expected) in [
            (probe(true, false, "PodFailed", true, "Failed", ""), true),
            (probe(true, false, "PodFailed", false, "", ""), true),
            (probe(true, true, "", true, "Failed", "10.0.0.1"), true),
            // The node went, and the volume may have with it.
            (probe(true, false, "NodeLost", true, "Failed", ""), false),
            (probe(true, false, "NodeDeleted", false, "", ""), false),
            // Not a failed Pod.
            (probe(false, false, "", false, "", ""), false),
            (probe(true, true, "", true, "Succeeded", "10.0.0.1"), false),
        ] {
            assert_eq!(
                sandbox_pod_failed_on_its_node(&running, &probe),
                expected,
                "{probe:?}"
            );
        }
        // A create that never ran has no files or processes to speak of.
        let creating = row("creating", 300);
        let failed = probe(true, false, "PodFailed", true, "Failed", "");
        assert!(!sandbox_pod_failed_on_its_node(&creating, &failed));
    }

    #[test]
    fn liveness_reasons_mirror_go() {
        let now = chrono::Utc::now();
        // Running: every failure branch.
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(false, false, "", false, "", "")
            ),
            Some("sandbox claim missing".into())
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(true, false, "PodFailed", false, "", "")
            ),
            Some("sandbox claim not ready: PodFailed".into())
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(true, true, "", false, "", "")
            ),
            Some("sandbox pod missing".into())
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(true, true, "", true, "Failed", "")
            ),
            Some("sandbox pod entered failed unexpectedly".into())
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(true, true, "", true, "Running", "")
            ),
            Some("sandbox pod missing IP".into())
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("running", 300),
                &probe(true, true, "", true, "Running", "10.1.1.1")
            ),
            None
        );

        // Stop and destroy intent transfer readiness ownership to the
        // lifecycle workflow. A suspended or deleted claim during teardown is
        // expected and must never overwrite that intent with state=error.
        for desired_state in ["stopped", "destroyed"] {
            let mut transitioning = row("running", 300);
            transitioning.desired_state = desired_state.into();
            assert_eq!(
                sandbox_liveness_reason(
                    now,
                    &transitioning,
                    &probe(true, false, "SandboxSuspended", false, "", "")
                ),
                None,
                "liveness interfered with desired_state={desired_state}"
            );
        }

        // Transitional states get the 60s grace window.
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("creating", 10),
                &probe(false, false, "", false, "", "")
            ),
            None
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("creating", 120),
                &probe(false, false, "", false, "", "")
            ),
            Some("sandbox claim missing during creating".into())
        );
        // Non-terminal claim reasons keep waiting; terminal ones fail.
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("starting", 120),
                &probe(true, false, "Pending", false, "", "")
            ),
            None
        );
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("starting", 120),
                &probe(true, false, "SandboxFailed", false, "", "")
            ),
            Some("sandbox did not become ready during starting: SandboxFailed".into())
        );
        // Stopped state never flags.
        assert_eq!(
            sandbox_liveness_reason(
                now,
                &row("stopped", 300),
                &probe(false, false, "", false, "", "")
            ),
            None
        );
    }

    #[test]
    fn terminal_claim_reasons_mirror_go() {
        for r in [
            "SandboxExpired",
            "SandboxDeleted",
            "SandboxFailed",
            "PodFailed",
            "NodeLost",
            "NodeDeleted",
            "Evicted",
            "Failed",
        ] {
            assert!(is_terminal_claim_reason(r), "{r}");
        }
        assert!(!is_terminal_claim_reason("Pending"));
        assert!(!is_terminal_claim_reason(""));
    }
}
