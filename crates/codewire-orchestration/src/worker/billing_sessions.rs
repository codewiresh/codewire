//! Sandbox billing-session lifecycle controller.
//!
//! Opens and closes `sandbox_running_sessions` rows as a Sandbox CR
//! starts (Ready) and stops (terminated / deleted / suspended). The
//! aggregation side (`AggregateMonthlyUsage`) already lives in
//! `codewire-billing::metering`; this is the writer that produces the
//! rows that aggregation reads.
//!
//! ## Informer → poll adaptation
//!
//! The Go controller registers a k8s shared informer over Sandboxes
//! (Add/Update → `reconcile`, Delete → `CloseByName`) and, after the
//! initial cache sync, runs `recoverOpenSessions` to close DB rows whose
//! Sandbox no longer exists. The Rust orchestration substitutes a
//! leader-gated poll for every watch it owns (`wait_for_ready`,
//! `sandbox_liveness_loop`), so this is a poll loop: each tick lists all
//! Sandboxes, reconciles each (open/heartbeat or close), then runs the
//! recovery sweep over the open DB rows. Because the recovery sweep runs
//! every tick (not just at startup), the explicit DeleteFunc branch from
//! Go is unnecessary — a vanished Sandbox is closed by the sweep with
//! reason `controller_lost_track`. (Go closes deletes immediately with
//! reason `deleted`; the steady-state row shape is identical, only the
//! close reason for a hard-deleted CR differs. Documented accepted drift.)
//!
//! ## Billing opens at bind (Program #2238 C3)
//!
//! Owner decision, 2026-10-02: a session opens at the environment's
//! claim-time binding, for every sandbox, cold or pool-born. A Ready Sandbox
//! opens a row only while the environment's live binding names this exact
//! Sandbox (`sandbox_workspace_bindings.sandbox_uid`), and the row starts at
//! that binding's `bound_at`, never before the Sandbox's previous session
//! ended. An unclaimed warm-pool member, and an adopted one that is not bound
//! yet, is never billed: it has no binding. An already open row keeps its
//! heartbeat, so a Pod replaced while running is billed without a gap.
//!
//! ## Gating
//!
//! Runs when `billing-session` is in `WORKER_LOOPS` (the default), under
//! the orchestration leader. The `ON CONFLICT (runtime_type, runtime_uid)
//! WHERE ended_at IS NULL` upsert is idempotent, so a concurrent writer
//! (e.g. the legacy Go controller during a deploy overlap) cannot corrupt
//! a row.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use prometheus::{IntCounterVec, IntGauge, Opts, register_int_counter_vec, register_int_gauge};
use sqlx::{PgPool, Row};

use super::WorkerContext;
use crate::runtime::{MemberPhase as Phase, Placement, Resources, RuntimeDriver, RuntimeMember};

/// Mirrors the retired Go billing-session controller's default
/// `ResyncInterval` of `time.Minute`.
pub const BILLING_SESSION_INTERVAL: Duration = Duration::from_secs(60);

/// Mirrors `sessions.Identity`.
#[derive(Debug, Clone)]
pub(crate) struct Identity {
    pub(crate) environment_id: String,
    pub(crate) org_id: String,
    pub(crate) runtime_tier: String,
    pub(crate) runtime_uid: String,
    pub(crate) runtime_name: String,
    pub(crate) namespace: String,
}

#[derive(Debug)]
enum IdentityResolution {
    NotManaged,
    Resolved(Identity),
    Unresolved(&'static str),
}

static UNRESOLVED_IDENTITIES: OnceLock<IntCounterVec> = OnceLock::new();
static UNBILLABLE_RUNNING: OnceLock<IntGauge> = OnceLock::new();

fn unresolved_identities_metric() -> &'static IntCounterVec {
    UNRESOLVED_IDENTITIES.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_billing_identity_resolution_failures_total",
                "Running Codewire Sandboxes whose billable identity could not be resolved."
            ),
            &["reason"]
        )
        .expect("billing identity metric registration must be unique")
    })
}

static AWAITING_BIND: OnceLock<IntGauge> = OnceLock::new();

fn awaiting_bind_metric() -> &'static IntGauge {
    AWAITING_BIND.get_or_init(|| {
        register_int_gauge!(
            "codewire_billing_awaiting_bind_sandboxes",
            "Ready Codewire Sandboxes whose environment has not bound them yet, so nothing is billed."
        )
        .expect("awaiting-bind billing metric registration must be unique")
    })
}

fn unbillable_running_metric() -> &'static IntGauge {
    UNBILLABLE_RUNNING.get_or_init(|| {
        register_int_gauge!(
            "codewire_billing_unbillable_running_environments",
            "Current running Codewire Sandboxes that lack a resolved billable identity."
        )
        .expect("unbillable billing metric registration must be unique")
    })
}

/// Mirrors `sessions.OpenSession`.
struct OpenSession {
    id: String,
    runtime_uid: String,
    last_observed_at: chrono::DateTime<chrono::Utc>,
}

// ── resources.go ───────────────────────────────────────────────────────

fn replace_workspace_billing_resources(
    workspace: &Resources,
    declared: Resources,
    applied_cpu_millicores: i32,
    applied_memory_mib: i32,
    applied_disk_gib: i32,
) -> Resources {
    Resources {
        cpu_millicores: declared.cpu_millicores - workspace.cpu_millicores + applied_cpu_millicores,
        memory_mib: declared.memory_mib - workspace.memory_mib + applied_memory_mib,
        disk_gib: declared.disk_gib - workspace.disk_gib + applied_disk_gib,
        runtime_class: declared.runtime_class,
    }
}

/// The declared resources with the workspace disk at the environment's
/// applied size, never below the size its volume claim template declares
/// (a PVC never shrinks below it).
fn bill_applied_workspace_disk(
    workspace: &Resources,
    declared: Resources,
    applied_disk_gb: Option<i32>,
) -> Resources {
    let disk_gib = applied_disk_gb.map_or(workspace.disk_gib, |applied| {
        applied.max(workspace.disk_gib)
    });
    replace_workspace_billing_resources(
        workspace,
        declared,
        workspace.cpu_millicores,
        workspace.memory_mib,
        disk_gib,
    )
}

/// Freeze an open billing session while a resize is active. Once a failed
/// operation is terminal, charge the durable last-applied workspace resources
/// even if Kubernetes desired-state rollback is still converging. Only the
/// latest operation counts: a later completed resize supersedes an earlier
/// failure.
///
/// Otherwise the workspace disk is the environment's applied size, the one
/// the dashboard and CLI show. A Sandbox's volume claim template is immutable,
/// so after a disk grows it still names the size the environment was created
/// with, while the PVC has the grown size (#3554).
async fn resize_billing_resources(
    pool: &PgPool,
    environment_id: &str,
    workspace: &Resources,
    declared: Resources,
) -> anyhow::Result<Resources> {
    let operation: Option<(String, i32, i32, i32)> = sqlx::query_as(
        "SELECT state, last_applied_cpu_millicores, last_applied_memory_mb,
                last_applied_disk_gb
           FROM environment_resize_operations
          WHERE environment_id = $1
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    let Some((state, cpu, memory, disk)) = operation.filter(|(state, ..)| {
        matches!(
            state.as_str(),
            "pending" | "applying" | "restarting" | "failed"
        )
    }) else {
        let applied_disk_gb: Option<i32> =
            sqlx::query_scalar("SELECT disk_gb FROM environments WHERE id = $1")
                .bind(environment_id)
                .fetch_optional(pool)
                .await?;
        return Ok(bill_applied_workspace_disk(
            workspace,
            declared,
            applied_disk_gb,
        ));
    };

    if state != "failed" {
        let existing: Option<(i32, i32, i32, Option<String>)> = sqlx::query_as(
            "SELECT cpu_millicores, memory_mib, disk_gib, runtime_class
               FROM sandbox_running_sessions
              WHERE environment_id = $1 AND ended_at IS NULL
              ORDER BY started_at DESC
              LIMIT 1",
        )
        .bind(environment_id)
        .fetch_optional(pool)
        .await?;
        if let Some((cpu_millicores, memory_mib, disk_gib, runtime_class)) = existing {
            return Ok(Resources {
                cpu_millicores,
                memory_mib,
                disk_gib,
                runtime_class,
            });
        }
    }

    Ok(replace_workspace_billing_resources(
        workspace, declared, cpu, memory, disk,
    ))
}

// ── store.go ───────────────────────────────────────────────────────────

/// Mirrors `Store.ResolveIdentity`: derive (env, org, uid, name, ns) from
/// the member, falling back to the `sandbox_environment_backend`
/// claim-uid join and the `environments` org lookup. Returns `Ok(None)`
/// when the Sandbox is not a billable Codewire environment (the Go
/// `(Identity{}, false, nil)` path).
async fn resolve_identity(
    pool: &PgPool,
    member: &RuntimeMember,
) -> anyhow::Result<IdentityResolution> {
    // A snapshot's clearing Sandbox has a claim but no environment, and bills
    // nothing.
    if member.snapshot_clearing {
        return Ok(IdentityResolution::NotManaged);
    }
    let namespace = member.namespace.as_str();
    let runtime_name = member.name.as_str();
    let runtime_uid = member.uid.as_str();
    let mut env_id = member.environment_id.clone();
    let mut org_id = member.organization_id.clone();
    let claim_uid = member.claim_uid.as_str();

    if env_id.is_empty() && !claim_uid.is_empty() {
        let row = sqlx::query(
            "SELECT environment_id
               FROM sandbox_environment_backend
              WHERE sandbox_claim_uid = $1 AND namespace = $2",
        )
        .bind(claim_uid)
        .bind(namespace)
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow::anyhow!("resolve environment by claim uid: {e}"))?;
        match row {
            None => return Ok(IdentityResolution::Unresolved("claim_not_found")),
            Some(r) => env_id = r.try_get::<String, _>(0).unwrap_or_default(),
        }
    }
    if env_id.is_empty() {
        return Ok(IdentityResolution::NotManaged);
    }

    let row = sqlx::query("SELECT org_id, isolation_tier FROM environments WHERE id = $1")
        .bind(&env_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow::anyhow!("resolve environment billing identity: {e}"))?;
    let Some(row) = row else {
        return Ok(IdentityResolution::Unresolved("environment_not_found"));
    };
    let stored_org_id: String = row.try_get(0).unwrap_or_default();
    let runtime_tier: String = row.try_get(1).unwrap_or_default();
    if org_id.is_empty() {
        org_id = stored_org_id;
    } else if org_id != stored_org_id {
        return Ok(IdentityResolution::Unresolved("organization_mismatch"));
    }

    if org_id.is_empty()
        || runtime_uid.is_empty()
        || runtime_name.is_empty()
        || namespace.is_empty()
    {
        return Ok(IdentityResolution::Unresolved("invalid_runtime_identity"));
    }

    Ok(IdentityResolution::Resolved(Identity {
        environment_id: env_id,
        org_id,
        runtime_tier,
        runtime_uid: runtime_uid.to_string(),
        runtime_name: runtime_name.to_string(),
        namespace: namespace.to_string(),
    }))
}

/// What [`open_or_heartbeat`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionWrite {
    /// The open row was refreshed.
    Heartbeat,
    /// A row opened at the binding's `bound_at`.
    Opened,
    /// No open row and no live binding of this Sandbox: nothing is billed.
    AwaitingBind,
}

/// Heartbeat the open row for this runtime UID, or open one at bind.
///
/// An open row (keyed by the partial unique index `(runtime_type,
/// runtime_uid) WHERE ended_at IS NULL`) refreshes its resources and
/// `last_observed_at`. Otherwise a row opens only while the environment's
/// live binding names this Sandbox, starting at that binding's `bound_at`,
/// no earlier than the Sandbox's last closed session and no later than this
/// observation.
pub(crate) async fn open_or_heartbeat(
    pool: &PgPool,
    id: &Identity,
    res: &Resources,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<SessionWrite> {
    let refreshed = sqlx::query(
        r#"UPDATE sandbox_running_sessions SET
               environment_id = $1,
               organization_id = $2,
               runtime_name = $4,
               runtime_namespace = $5,
               cpu_millicores = $6,
               memory_mib = $7,
               disk_gib = $8,
               runtime_class = $9,
               runtime_tier = $10,
               last_observed_at = $11,
               updated_at = $11
           WHERE runtime_type = 'sandbox' AND runtime_uid = $3 AND ended_at IS NULL"#,
    )
    .bind(&id.environment_id)
    .bind(&id.org_id)
    .bind(&id.runtime_uid)
    .bind(&id.runtime_name)
    .bind(&id.namespace)
    .bind(res.cpu_millicores)
    .bind(res.memory_mib)
    .bind(res.disk_gib)
    .bind(&res.runtime_class)
    .bind(&id.runtime_tier)
    .bind(observed_at)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("heartbeat sandbox session: {e}"))?
    .rows_affected();
    if refreshed > 0 {
        return Ok(SessionWrite::Heartbeat);
    }
    let opened = sqlx::query(
        r#"WITH bound AS (
               SELECT w.bound_at
                 FROM sandbox_environment_backend b
                 JOIN sandbox_workspace_bindings w
                   ON w.environment_id = b.environment_id
                  AND w.pod_uid = b.pod_uid
                  AND w.released_at IS NULL
                WHERE b.environment_id = $1
                  AND b.bound_at IS NOT NULL
                  AND w.sandbox_uid = $3
           ), previous AS (
               SELECT max(ended_at) AS ended_at
                 FROM sandbox_running_sessions
                WHERE runtime_type = 'sandbox' AND runtime_uid = $3
           )
           INSERT INTO sandbox_running_sessions (
               environment_id, organization_id, runtime_type, runtime_uid, runtime_name,
               runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_class, runtime_tier,
               started_at, last_observed_at, updated_at
           )
           SELECT $1, $2, 'sandbox', $3, $4, $5, $6, $7, $8, $9, $10,
                  LEAST($11, GREATEST(bound.bound_at, COALESCE(previous.ended_at, bound.bound_at))),
                  $11, $11
             FROM bound CROSS JOIN previous
           ON CONFLICT (runtime_type, runtime_uid) WHERE ended_at IS NULL
           DO UPDATE SET
               environment_id = EXCLUDED.environment_id,
               organization_id = EXCLUDED.organization_id,
               runtime_name = EXCLUDED.runtime_name,
               runtime_namespace = EXCLUDED.runtime_namespace,
               cpu_millicores = EXCLUDED.cpu_millicores,
               memory_mib = EXCLUDED.memory_mib,
               disk_gib = EXCLUDED.disk_gib,
               runtime_class = EXCLUDED.runtime_class,
               runtime_tier = EXCLUDED.runtime_tier,
               last_observed_at = EXCLUDED.last_observed_at,
               updated_at = EXCLUDED.updated_at"#,
    )
    .bind(&id.environment_id)
    .bind(&id.org_id)
    .bind(&id.runtime_uid)
    .bind(&id.runtime_name)
    .bind(&id.namespace)
    .bind(res.cpu_millicores)
    .bind(res.memory_mib)
    .bind(res.disk_gib)
    .bind(&res.runtime_class)
    .bind(&id.runtime_tier)
    .bind(observed_at)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("open sandbox session at bind: {e}"))?
    .rows_affected();
    Ok(if opened > 0 {
        SessionWrite::Opened
    } else {
        SessionWrite::AwaitingBind
    })
}

/// Mirrors `Store.CloseByUID`: set `ended_at`/`end_reason` on the open row
/// for this runtime UID. No-op when the UID is empty or already closed.
/// A row never ends before it was last observed running, so a draw already
/// made up to that observation stays within the session.
async fn close_by_uid(
    pool: &PgPool,
    runtime_uid: &str,
    reason: &str,
    ended_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    if runtime_uid.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"UPDATE sandbox_running_sessions
              SET ended_at = GREATEST(last_observed_at, $1), end_reason = $2,
                  updated_at = NOW()
            WHERE runtime_type = 'sandbox'
              AND runtime_uid = $3
              AND ended_at IS NULL"#,
    )
    .bind(ended_at)
    .bind(reason)
    .bind(runtime_uid)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("close sandbox session by uid: {e}"))?;
    Ok(())
}

/// Mirrors `Store.ListOpen`: open rows in (or across, when `namespace` is
/// empty) the namespace, for the recovery sweep.
async fn list_open(pool: &PgPool, namespace: &str) -> anyhow::Result<Vec<OpenSession>> {
    let rows = sqlx::query(
        r#"SELECT id, runtime_uid, last_observed_at
             FROM sandbox_running_sessions
            WHERE runtime_type = 'sandbox'
              AND ended_at IS NULL
              AND ($1 = '' OR runtime_namespace = $1)"#,
    )
    .bind(namespace)
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow::anyhow!("list open sandbox sessions: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| OpenSession {
            id: r.try_get("id").unwrap_or_default(),
            runtime_uid: r.try_get("runtime_uid").unwrap_or_default(),
            last_observed_at: r
                .try_get("last_observed_at")
                .unwrap_or_else(|_| chrono::Utc::now()),
        })
        .collect())
}

// ── controller.go ──────────────────────────────────────────────────────

/// One Sandbox's billing state this cycle, for the gauges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Reconciled {
    /// Running without a resolved billable identity.
    unbillable: bool,
    /// Running, resolved, but not bound: billing waits for the bind.
    awaiting_bind: bool,
}

/// Mirrors `handler.reconcile`: resolve identity, classify, then open at
/// bind or heartbeat (Running) or close (Terminated). Pending is a no-op.
async fn reconcile(pool: &PgPool, member: &RuntimeMember) -> Reconciled {
    let name = member.name.as_str();
    let uid = member.uid.as_str();
    let phase = member.phase;
    let id = match resolve_identity(pool, member).await {
        Ok(IdentityResolution::Resolved(id)) => id,
        Ok(IdentityResolution::NotManaged) => return Reconciled::default(),
        Ok(IdentityResolution::Unresolved(reason)) => {
            if phase == Phase::Running {
                unresolved_identities_metric()
                    .with_label_values(&[reason])
                    .inc();
                tracing::error!(reason, runtime_uid = %uid, "billing_identity_unresolved");
                return Reconciled {
                    unbillable: true,
                    ..Reconciled::default()
                };
            }
            return Reconciled::default();
        }
        Err(e) => {
            if phase == Phase::Running {
                unresolved_identities_metric()
                    .with_label_values(&["database_error"])
                    .inc();
                tracing::error!(error = %e, runtime_uid = %uid, reason = "database_error", "billing_identity_unresolved");
                return Reconciled {
                    unbillable: true,
                    ..Reconciled::default()
                };
            }
            tracing::error!(error = %e, "billing-session: resolve identity");
            return Reconciled::default();
        }
    };
    let now = chrono::Utc::now();
    match phase {
        Phase::Running => {
            let res = match resize_billing_resources(
                pool,
                &id.environment_id,
                &member.workspace,
                member.declared.clone(),
            )
            .await
            {
                Ok(resources) => resources,
                Err(error) => {
                    tracing::error!(environment_id = id.environment_id, sandbox = name, %error, "billing-session: resolve resize resources");
                    return Reconciled::default();
                }
            };
            match open_or_heartbeat(pool, &id, &res, now).await {
                Ok(SessionWrite::AwaitingBind) => {
                    return Reconciled {
                        awaiting_bind: true,
                        ..Reconciled::default()
                    };
                }
                Ok(SessionWrite::Opened) => {
                    tracing::info!(
                        environment_id = id.environment_id,
                        sandbox = name,
                        "billing-session: session opened at bind"
                    );
                }
                Ok(SessionWrite::Heartbeat) => {}
                Err(e) => {
                    tracing::error!(environment_id = id.environment_id, sandbox = name, error = %e, "billing-session: open/heartbeat session");
                }
            }
        }
        Phase::Terminated => {
            let reason = if member.phase_reason.is_empty() {
                "not_billable"
            } else {
                member.phase_reason.as_str()
            };
            // Charging ends when the Sandbox stopped running, as it records
            // it, not when this poll noticed (owner, 2026-11-10, #3950).
            // Without a record it ends now.
            let ended_at = member.stopped_at.map_or(now, |stopped| stopped.min(now));
            if let Err(e) = close_by_uid(pool, uid, reason, ended_at).await {
                tracing::error!(environment_id = id.environment_id, sandbox = name, reason, error = %e, "billing-session: close session");
            }
        }
        Phase::Pending => {}
    }
    Reconciled::default()
}

/// One reconcile cycle: list every Sandbox, reconcile it, then close DB
/// rows whose Sandbox is gone (mirrors `recoverOpenSessions`, run every
/// tick rather than only at cache sync — see the module note).
async fn run_cycle(pool: &PgPool, runtime: &dyn RuntimeDriver, namespace: &str) {
    let members = match runtime.list_members(&Placement::new(namespace)).await {
        Ok(members) => members,
        Err(e) => {
            tracing::error!(namespace, error = %e, "billing-session: list sandboxes");
            return;
        }
    };

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unbillable_running = 0i64;
    let mut awaiting_bind = 0i64;
    for member in &members {
        if !member.uid.is_empty() {
            seen.insert(member.uid.clone());
        }
        let reconciled = reconcile(pool, member).await;
        unbillable_running += i64::from(reconciled.unbillable);
        awaiting_bind += i64::from(reconciled.awaiting_bind);
    }
    unbillable_running_metric().set(unbillable_running);
    awaiting_bind_metric().set(awaiting_bind);

    let open = match list_open(pool, namespace).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "billing-session: list open sessions for recovery");
            return;
        }
    };
    for row in open {
        if seen.contains(&row.runtime_uid) {
            continue;
        }
        if let Err(e) =
            // A vanished runtime stopped contributing billable usage when it
            // was last observed, not when a later recovery poll noticed it.
            close_by_uid(
                pool,
                &row.runtime_uid,
                "controller_lost_track",
                row.last_observed_at,
            )
            .await
        {
            tracing::error!(session_id = row.id, runtime_uid = row.runtime_uid, error = %e, "billing-session: recover missing session");
        }
    }
}

/// Leader-gated poll loop. Mirrors `StartSandboxController`'s guards (no
/// kube client / no pool → skip) and resync cadence.
pub async fn billing_session_loop(
    ctx: Arc<WorkerContext>,
    is_leader: Arc<AtomicBool>,
    namespace: String,
) {
    let Some(runtime) = ctx.runtime.clone() else {
        tracing::info!("billing-session: sandbox client unavailable, skipping");
        return;
    };
    tracing::info!(namespace, "billing-session controller: started");
    let mut ticker = tokio::time::interval(BILLING_SESSION_INTERVAL);
    ticker.tick().await; // align with Go's NewTicker (first fire after interval)
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            continue;
        }
        run_cycle(&ctx.pool, runtime.as_ref(), &namespace).await;
    }
}

#[cfg(test)]
#[path = "billing_sessions/database_tests.rs"]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(cpu_millicores: i32, memory_mib: i32, disk_gib: i32) -> Resources {
        Resources {
            cpu_millicores,
            memory_mib,
            disk_gib,
            runtime_class: None,
        }
    }

    #[test]
    fn a_shared_workspace_is_billed_for_its_full_vcpus() {
        let workspace = workspace(2000, 8192, 80);
        let declared = Resources {
            cpu_millicores: 2500,
            memory_mib: 9216,
            disk_gib: 80,
            runtime_class: None,
        };

        let resized =
            replace_workspace_billing_resources(&workspace, declared.clone(), 4000, 16384, 80);
        assert_eq!(resized.cpu_millicores, 4500);

        let unchanged = bill_applied_workspace_disk(&workspace, declared, Some(80));
        assert_eq!(unchanged.cpu_millicores, 2500);
    }

    #[test]
    fn resize_billing_replaces_only_workspace_resources() {
        let workspace = workspace(4000, 8192, 40);
        let declared = Resources {
            cpu_millicores: 4250,
            memory_mib: 8704,
            disk_gib: 40,
            runtime_class: Some("commodity".into()),
        };
        let applied = replace_workspace_billing_resources(&workspace, declared, 2000, 4096, 30);

        assert_eq!(applied.cpu_millicores, 2250);
        assert_eq!(applied.memory_mib, 4608);
        assert_eq!(applied.disk_gib, 30);
        assert_eq!(applied.runtime_class.as_deref(), Some("commodity"));
    }

    #[test]
    fn a_grown_disk_is_billed_at_its_applied_size() {
        let workspace = workspace(2000, 8192, 80);
        let declared = Resources {
            cpu_millicores: 2500,
            memory_mib: 9216,
            disk_gib: 80,
            runtime_class: None,
        };

        // The Sandbox still declares 80 Gi after the PVC grew to 120 Gi.
        let grown = bill_applied_workspace_disk(&workspace, declared.clone(), Some(120));
        assert_eq!(grown.disk_gib, 120);
        assert_eq!(grown.cpu_millicores, 2500);
        assert_eq!(grown.memory_mib, 9216);

        let unchanged = bill_applied_workspace_disk(&workspace, declared.clone(), Some(80));
        assert_eq!(unchanged.disk_gib, 80);
        let unknown = bill_applied_workspace_disk(&workspace, declared.clone(), None);
        assert_eq!(unknown.disk_gib, 80);
        let below = bill_applied_workspace_disk(&workspace, declared, Some(10));
        assert_eq!(below.disk_gib, 80);
    }
}
