//! Leader-gated billing loops: usage metering (a port of the Go worker's
//! `StartEnvironmentBilling`), credit metering (#3381) and the Stripe
//! webhook delivery check.
//!
//! These live in the billing service because they are billing-domain
//! crons, not orchestration. `BILLING_LOOPS` is the allow-list of crons
//! to run (`env-usage-metering`, `credit-metering`,
//! `stripe-delivery-check`). The billing service elects its own leader
//! under a distinct pg advisory lock, so its replicas never double-meter.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sqlx::{Connection, PgConnection, PgPool, Row};

use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;

/// "codebill" — distinct from the Go worker's 0x636F646573706163 and
/// orchestration's 0x636F646577697265 (see module docs).
const ADVISORY_LOCK_ID: i64 = 0x636F646562696C6C;

const USAGE_METERING_INTERVAL: Duration = Duration::from_secs(60);

pub struct MeteringDeps {
    pub pool: PgPool,
    pub stripe: Arc<StripeHandle>,
    pub email: Arc<EmailClient>,
    pub database_url: String,
    pub credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    /// Billing's own webhook route on its listener, for the delivery
    /// check's forged event.
    pub webhook_self_url: String,
}

pub fn start_loops(deps: Arc<MeteringDeps>, loops: &[String]) {
    if loops.is_empty() {
        return;
    }
    let dry_run = std::env::var("DRY_RUN").as_deref() == Ok("true");
    let is_leader = Arc::new(AtomicBool::new(false));
    {
        let url = deps.database_url.clone();
        let is_leader = is_leader.clone();
        tokio::spawn(async move { leader_loop(&url, is_leader).await });
    }

    for name in loops {
        match name.as_str() {
            "env-usage-metering" => {
                if dry_run {
                    tracing::info!("env billing: disabled (dry run)");
                    continue;
                }
                if std::env::var("BILLING_SESSION_LEDGER_CANONICAL").as_deref() == Ok("true") {
                    tracing::info!("env billing: disabled (session ledger canonical)");
                    continue;
                }
                let deps = deps.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    interval_loop(USAGE_METERING_INTERVAL, is_leader, move || {
                        let deps = deps.clone();
                        async move {
                            if let Err(e) = report_environment_usage(&deps.pool).await {
                                tracing::error!(error = %e, "env billing: report failed");
                            }
                        }
                    })
                    .await;
                });
                tracing::info!(interval = ?USAGE_METERING_INTERVAL, "env billing: started");
            }
            "credit-metering" => {
                if dry_run {
                    tracing::info!("credit metering: disabled (dry run)");
                    continue;
                }
                // One task draws, settles and sends notices, on the minute's
                // tick and at once on a credit change, so two passes never
                // overlap and no notice is sent twice (#4754).
                tokio::spawn(crate::credit_changes::run(deps.clone(), is_leader.clone()));
                tracing::info!(
                    interval = ?crate::credit::CREDIT_METERING_INTERVAL,
                    channel = crate::credit_changes::CHANNEL,
                    "credit metering: started"
                );
            }
            "stripe-delivery-check" => {
                if deps.stripe.enabled().is_none() {
                    tracing::info!(
                        "Stripe webhook delivery check: disabled (Stripe not configured)"
                    );
                    continue;
                }
                let deps = deps.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    // The first run comes soon after start, so a deploy that
                    // restarts billing daily still gets one; then daily.
                    let mut ticker = tokio::time::interval_at(
                        tokio::time::Instant::now() + crate::stripe_delivery_check::FIRST_RUN_AFTER,
                        crate::stripe_delivery_check::INTERVAL,
                    );
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        ticker.tick().await;
                        if is_leader.load(Ordering::SeqCst) {
                            crate::stripe_delivery_check::run_once(
                                &deps.stripe,
                                &deps.pool,
                                &deps.webhook_self_url,
                            )
                            .await;
                        }
                    }
                });
                tracing::info!("Stripe webhook delivery check: started");
            }
            other => tracing::warn!(name = other, "billing: unknown loop name, ignoring"),
        }
    }
}

async fn interval_loop<F, Fut>(interval: Duration, is_leader: Arc<AtomicBool>, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // first fire after one interval, like time.NewTicker
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            continue;
        }
        f().await;
    }
}

/// Same advisory-lock leader pattern as the Go worker / orchestration.
async fn leader_loop(database_url: &str, is_leader: Arc<AtomicBool>) {
    loop {
        let mut conn = match PgConnection::connect(database_url).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "billing leader: failed to acquire connection");
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
                    tracing::error!(error = %e, "billing leader: failed to acquire advisory lock");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
        if !acquired {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        tracing::info!("billing leader: acquired leadership");
        is_leader.store(true, Ordering::SeqCst);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = conn.ping().await {
                tracing::error!(error = %e, "billing leader: connection health check failed");
                break;
            }
        }
        is_leader.store(false, Ordering::SeqCst);
        tracing::warn!("billing leader: connection lost, will retry");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Mirrors `billing.LogBillingEvent` (warn-only).
pub async fn log_billing_event(
    pool: &PgPool,
    event_type: &str,
    org_id: &str,
    amount_cents: Option<i32>,
    currency: &str,
    stripe_item_id: &str,
    metadata: Option<serde_json::Value>,
) {
    let nil_if_empty = |s: &str| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    if let Err(e) = sqlx::query(
        r#"INSERT INTO billing_events (event_type, org_id, amount_cents, currency, stripe_item_id, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(event_type)
    .bind(nil_if_empty(org_id))
    .bind(amount_cents)
    .bind(currency)
    .bind(nil_if_empty(stripe_item_id))
    .bind(metadata)
    .execute(pool)
    .await
    {
        tracing::warn!(r#type = event_type, error = %e, "billing: failed to log event");
    }
}

// ── Usage metering (port of ReportEnvironmentUsage) ────────────────────

pub async fn report_environment_usage(pool: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        r#"SELECT id, org_id, type, cpu_millicores, memory_mb, disk_gb, started_at, last_billing_event_at
           FROM environments
           WHERE state = 'running'
             AND (last_billing_event_at IS NULL OR last_billing_event_at < NOW() - INTERVAL '55 seconds')"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow::anyhow!("query running environments: {e}"))?;

    let now = chrono::Utc::now().naive_utc();
    let mut metered = 0;

    for row in rows {
        let id: String = row.try_get("id")?;
        let org_id: String = row.try_get("org_id")?;
        let env_type: String = row.try_get("type")?;
        let cpu: i32 = row.try_get("cpu_millicores")?;
        let mem: i32 = row.try_get("memory_mb")?;
        let disk: i32 = row.try_get("disk_gb")?;
        // timestamp WITHOUT time zone columns.
        let started_at: Option<chrono::NaiveDateTime> = row.try_get("started_at")?;
        let last_billing: Option<chrono::NaiveDateTime> = row.try_get("last_billing_event_at")?;

        let Some(ref_time) = last_billing.or(started_at) else {
            tracing::warn!(
                environment_id = id,
                "env billing: no reference time, skipping"
            );
            continue;
        };
        let elapsed_secs = (now - ref_time).num_seconds();
        if elapsed_secs <= 0 {
            continue;
        }

        if let Err(e) = sqlx::query(
            r#"UPDATE environments
               SET last_billing_event_at = NOW(),
                   total_running_seconds = total_running_seconds + $1
               WHERE id = $2"#,
        )
        .bind(elapsed_secs as i32)
        .bind(&id)
        .execute(pool)
        .await
        {
            tracing::error!(environment_id = id, error = %e, "env billing: update tracking");
            continue;
        }

        log_billing_event(
            pool,
            "environment_usage",
            &org_id,
            None,
            "",
            "",
            Some(serde_json::json!({
                "elapsed_seconds": elapsed_secs,
                "cpu_millicores": cpu,
                "memory_mb": mem,
                "disk_gb": disk,
                "type": env_type,
            })),
        )
        .await;
        metered += 1;
    }

    if metered > 0 {
        tracing::info!(count = metered, "env billing: metered environments");
    }
    Ok(())
}

/// Mirrors `billingsessions.AggregateMonthlyUsage`.
pub(crate) async fn aggregate_monthly_usage(
    pool: &PgPool,
    org_id: &str,
    month_start: chrono::DateTime<chrono::Utc>,
    runtime_tier: &str,
) -> anyhow::Result<(f64, f64, f64)> {
    let row: (f64, f64, f64) = sqlx::query_as(
        r#"WITH period AS (
               SELECT $1::timestamptz AS start_at,
                      ($1::timestamptz + interval '1 month') AS end_at
           ),
           bounded AS (
               -- A paused stretch keeps its disk and uses no vCPU or
               -- memory (#5529).
               SELECT CASE WHEN s.rate_kind = 'paused' THEN 0 ELSE s.cpu_millicores END
                          AS cpu_millicores,
                      CASE WHEN s.rate_kind = 'paused' THEN 0 ELSE s.memory_mib END
                          AS memory_mib,
                      s.disk_gib,
                      GREATEST(s.started_at, p.start_at) AS bill_start,
                      LEAST(COALESCE(s.ended_at, NOW()), p.end_at) AS bill_end
               FROM sandbox_running_sessions s
               CROSS JOIN period p
               WHERE s.organization_id = $2
                 AND s.runtime_tier = $3
                 AND s.started_at < p.end_at
                 AND COALESCE(s.ended_at, NOW()) > p.start_at
           )
           SELECT
              COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start)) / 3600.0 * cpu_millicores / 1000.0), 0)::float8,
              COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start)) / 3600.0 * memory_mib / 1024.0), 0)::float8,
              COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start)) / 3600.0 * disk_gib), 0)::float8
           FROM bounded
           WHERE bill_end > bill_start"#,
    )
    .bind(month_start)
    .bind(org_id)
    .bind(runtime_tier)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("aggregate sandbox session usage: {e}"))?;
    Ok(row)
}
