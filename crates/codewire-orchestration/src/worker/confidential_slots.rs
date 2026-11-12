//! A bound on concurrent confidential activations (#4281).
//!
//! Before a confidential workspace volume's key is made ready, its create or
//! start (or a replacement of its member) takes a slot; the slot is released
//! once the member it activated is ready. Activating the volume inside the SNP
//! guest is slow and contends for the host's disk: four at once on one host
//! overran the Kata agent's create deadline on Dev and none recovered. So the
//! activations that run at once are bounded, and the rest wait.
//!
//! The bound is cluster-wide, and a slot is taken before the scheduler picks
//! the member's node. With one confidential host the bound is `per_host`, a
//! true per-host bound. With several, nothing yet keeps the scheduler from
//! placing two activations on one host, so the bound is 1 until per-host
//! placement exists (#4296): safe by default, not a gate to remember.
//!
//! A slot is a row of `confidential_activation_slots` (0018), written under one
//! transaction-scoped advisory lock so two activations can't both take the last
//! one. Every acquisition first sweeps rows whose environment is no longer
//! active and rows whose lease has passed, so a missed release never holds a
//! slot past the activation's own deadline.

use std::time::Duration;

use sqlx::PgPool;

use super::activity_authority::ActivityAuthority;
use super::env_log::emit_authoritative_environment_log_for_states;
use crate::runtime::{Placement, RuntimeDriver};
use crate::sandbox::template::CONFIDENTIAL_WORKSPACE_READY_TIMEOUT;

/// How many confidential activations may run at once on one host
/// (`CONFIDENTIAL_ACTIVATIONS_PER_HOST`).
pub const ACTIVATIONS_PER_HOST_ENV: &str = "CONFIDENTIAL_ACTIVATIONS_PER_HOST";
/// Until measured otherwise, one at a time per host.
pub const DEFAULT_ACTIVATIONS_PER_HOST: u32 = 1;
const MAX_ACTIVATIONS_PER_HOST: u32 = 16;

/// How long an activation waits for a slot before it fails. Waiting is not
/// readiness: the member's own readiness deadline starts after the slot.
pub(crate) const QUEUE_LIMIT: Duration = Duration::from_secs(30 * 60);
const POLL: Duration = Duration::from_secs(5);
/// A slot outlives the confidential readiness deadline by this much, so a
/// slot is never reclaimed from an activation that can still succeed.
const LEASE_MARGIN: Duration = Duration::from_secs(5 * 60);
/// An environment in any other state holds no slot; its row is swept.
const ACTIVE_STATES: [&str; 4] = ["pending", "creating", "starting", "running"];

/// [`ACTIVATIONS_PER_HOST_ENV`] as configured: unset is the default, and
/// anything but 1 to 16 stops orchestration rather than guessing.
pub fn activations_per_host(value: Option<&str>) -> u32 {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return DEFAULT_ACTIVATIONS_PER_HOST;
    };
    match value.parse::<u32>() {
        Ok(per_host) if (1..=MAX_ACTIVATIONS_PER_HOST).contains(&per_host) => per_host,
        _ => panic!("{ACTIVATIONS_PER_HOST_ENV} must be 1 to {MAX_ACTIVATIONS_PER_HOST}"),
    }
}

/// How many activations may run at once, cluster-wide: `per_host` with one
/// confidential host (or none counted), and 1 with several or an unknown
/// count, until per-host placement exists (#4296). Never zero, so a miscount
/// queues activations and never blocks them all.
pub(crate) fn bound(per_host: u32, hosts: Option<u32>) -> i64 {
    match hosts {
        Some(0 | 1) => i64::from(per_host.max(1)),
        Some(_) | None => 1,
    }
}

fn lease() -> Duration {
    CONFIDENTIAL_WORKSPACE_READY_TIMEOUT + LEASE_MARGIN
}

/// Take a slot for `environment_id` if one is free, in one transaction.
/// `true` when the environment holds a slot afterwards, including one it
/// already held.
pub(crate) async fn try_acquire(
    pool: &PgPool,
    environment_id: &str,
    bound: i64,
    lease: Duration,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('confidential-activation-slots', 0))",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM confidential_activation_slots AS slot USING environments AS env \
         WHERE slot.environment_id = env.id \
           AND (slot.expires_at <= now() OR env.state <> ALL($1))",
    )
    .bind(&ACTIVE_STATES[..])
    .execute(&mut *tx)
    .await?;
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM confidential_activation_slots WHERE environment_id = $1)",
    )
    .bind(environment_id)
    .fetch_one(&mut *tx)
    .await?;
    if !held {
        let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM confidential_activation_slots")
            .fetch_one(&mut *tx)
            .await?;
        if taken >= bound {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO confidential_activation_slots (environment_id, expires_at) \
             VALUES ($1, now() + make_interval(secs => $2))",
        )
        .bind(environment_id)
        .bind(lease.as_secs_f64())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Free the environment's slot, if it holds one.
pub(crate) async fn release(pool: &PgPool, environment_id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM confidential_activation_slots WHERE environment_id = $1")
        .bind(environment_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// The refusal when no slot came free in time.
#[derive(Debug, thiserror::Error)]
#[error("no confidential capacity became free within {} minutes", .0.as_secs() / 60)]
pub(crate) struct QueueTimedOut(pub Duration);

/// Wait until `environment_id` holds a slot, for at most `limit`, polling
/// every `poll`. The activity stops waiting when it loses authority.
pub(crate) async fn wait_for_slot<F, Fut>(
    pool: &PgPool,
    environment_id: &str,
    bound: i64,
    limit: Duration,
    poll: Duration,
    mut still_wanted: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        still_wanted().await?;
        if try_acquire(pool, environment_id, bound, lease()).await? {
            return Ok(());
        }
        if tokio::time::Instant::now() + poll > deadline {
            return Err(QueueTimedOut(limit).into());
        }
        tokio::time::sleep(poll).await;
    }
}

/// Take a slot before a confidential activation at `placement`: sized from
/// the runtime's confidential hosts, logged while it waits, and bounded by
/// [`QUEUE_LIMIT`].
pub(crate) async fn acquire_for_activation(
    pool: &PgPool,
    runtime: &dyn RuntimeDriver,
    per_host: u32,
    placement: &Placement,
    authority: &ActivityAuthority,
    states: &[&str],
    environment_id: &str,
) -> anyhow::Result<()> {
    let hosts = runtime.confidential_hosts(placement).await;
    if hosts.is_some_and(|hosts| hosts > 1) {
        tracing::warn!(
            hosts,
            per_host,
            "several confidential hosts and no per-host placement (#4296): one activation at a time"
        );
    }
    let bound = bound(per_host, hosts);
    if try_acquire(pool, environment_id, bound, lease()).await? {
        return Ok(());
    }
    tracing::info!(
        env = environment_id,
        bound,
        "waiting for confidential capacity"
    );
    emit_authoritative_environment_log_for_states(
        authority,
        states,
        "confidential_capacity",
        "waiting",
        "waiting for confidential capacity on this host",
        None,
    )
    .await?;
    let waited = std::time::Instant::now();
    wait_for_slot(pool, environment_id, bound, QUEUE_LIMIT, POLL, || {
        authority.ensure()
    })
    .await?;
    emit_authoritative_environment_log_for_states(
        authority,
        states,
        "confidential_capacity",
        "completed",
        "",
        Some(serde_json::json!({ "waited_ms": waited.elapsed().as_millis() as u64 })),
    )
    .await?;
    Ok(())
}

/// [`acquire_for_activation`] with the worker's pool, runtime and setting.
pub(crate) async fn acquire(
    ctx: &super::WorkerContext,
    namespace: &str,
    authority: &ActivityAuthority,
    states: &[&str],
    environment_id: &str,
) -> anyhow::Result<()> {
    acquire_for_activation(
        &ctx.pool,
        ctx.require_runtime()?,
        ctx.sandbox_cfg.confidential_activations_per_host,
        &Placement::new(namespace),
        authority,
        states,
        environment_id,
    )
    .await
}

/// Free the slot once the member it activated is ready. A failed release
/// leaves the slot to the sweep and its lease, so it never fails the caller.
pub(crate) async fn release_after_ready(pool: &PgPool, environment_id: &str) {
    if let Err(error) = release(pool, environment_id).await {
        tracing::warn!(env = environment_id, error = %error, "confidential slot not released; its lease will free it");
    }
}

#[cfg(test)]
#[path = "confidential_slots_database_tests.rs"]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_is_per_host_and_never_zero() {
        assert_eq!(bound(1, Some(1)), 1);
        assert_eq!(bound(2, Some(1)), 2);
        // Several hosts and no per-host placement (#4296): one at a time,
        // whatever the per-host setting.
        assert_eq!(bound(2, Some(2)), 1);
        assert_eq!(bound(16, Some(3)), 1);
        // Unknown hosts let one through; none counted is one host.
        assert_eq!(bound(2, None), 1);
        assert_eq!(bound(2, Some(0)), 2);
        // A zero per-host setting (the derived default) is one.
        assert_eq!(bound(0, Some(1)), 1);
    }

    #[test]
    fn activations_per_host_defaults_and_refuses_nonsense() {
        assert_eq!(activations_per_host(None), DEFAULT_ACTIVATIONS_PER_HOST);
        assert_eq!(
            activations_per_host(Some("  ")),
            DEFAULT_ACTIVATIONS_PER_HOST
        );
        assert_eq!(activations_per_host(Some("2")), 2);
        assert_eq!(activations_per_host(Some("16")), 16);
        for bad in ["0", "17", "-1", "two", "1.5"] {
            assert!(
                std::panic::catch_unwind(|| activations_per_host(Some(bad))).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_lease_outlives_the_confidential_readiness_deadline() {
        assert!(lease() > CONFIDENTIAL_WORKSPACE_READY_TIMEOUT);
    }
}
