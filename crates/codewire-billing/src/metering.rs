//! Leader-gated billing loops — port of the Go worker's
//! `StartEnvironmentBilling` (usage metering), `StartEnvironmentOverageBilling`
//! (Stripe overage invoicing, `internal/billing/environment_usage.go`), and
//! `billing.CheckExpiredTrials` (`internal/billing/trial.go`).
//!
//! These live in the billing service because they are billing-domain
//! crons, not orchestration. `BILLING_LOOPS` is the allow-list of crons
//! to run (`env-usage-metering`, `env-overage-billing`, `trials`). The
//! billing service elects its own leader under a distinct pg advisory
//! lock, so its replicas never double-meter.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Datelike;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool, Row};

use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;

/// "codebill" — distinct from the Go worker's 0x636F646573706163 and
/// orchestration's 0x636F646577697265 (see module docs).
const ADVISORY_LOCK_ID: i64 = 0x636F646562696C6C;

const USAGE_METERING_INTERVAL: Duration = Duration::from_secs(60);
const TRIALS_INTERVAL: Duration = Duration::from_secs(30); // Go: reconciler tick

pub struct MeteringDeps {
    pub pool: PgPool,
    pub stripe: Arc<StripeHandle>,
    pub email: Arc<EmailClient>,
    pub database_url: String,
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
            "env-overage-billing" => {
                if deps.stripe.enabled().is_none() {
                    tracing::info!("env overage billing: disabled (no billing client)");
                    continue;
                }
                if dry_run {
                    tracing::info!("env overage billing: disabled (dry run)");
                    continue;
                }
                let interval = std::env::var("USAGE_BILLING_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(2 * 3600));
                let deps = deps.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    interval_loop(interval, is_leader, move || {
                        let deps = deps.clone();
                        async move {
                            if let Err(e) = report_environment_overages(&deps).await {
                                tracing::error!(error = %e, "env overage billing: report failed");
                            }
                        }
                    })
                    .await;
                });
                tracing::info!(interval = ?interval, "env overage billing: started");
            }
            "trials" => {
                let deps = deps.clone();
                let is_leader = is_leader.clone();
                tokio::spawn(async move {
                    interval_loop(TRIALS_INTERVAL, is_leader, move || {
                        let deps = deps.clone();
                        async move {
                            if let Err(e) = check_expired_trials(&deps.pool, &deps.email).await {
                                tracing::error!(error = %e, "billing: check expired org trials failed");
                            }
                        }
                    })
                    .await;
                });
                tracing::info!(interval = ?TRIALS_INTERVAL, "trial expiry checker: started");
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

// ── Trial expiry (port of CheckExpiredTrials) ──────────────────────────

/// Selects orgs whose trial has lapsed without a Stripe subscription.
/// Mirrors `CheckExpiredTrials`' SELECT (`internal/billing/trial.go`).
const SELECT_EXPIRED_TRIALS: &str = r#"SELECT os.org_id FROM org_subscriptions os
           WHERE os.status = 'trialing'
             AND os.trial_end < NOW()
             AND os.stripe_subscription_id IS NULL"#;

/// Suspends the lapsed trial subscription. Go's first UPDATE.
const SUSPEND_TRIAL_SUBSCRIPTION: &str =
    "UPDATE org_subscriptions SET status = 'suspended', updated_at = NOW() WHERE org_id = $1";

/// Suspends the denormalized org billing status. Go's second UPDATE.
const SUSPEND_ORG_BILLING_STATUS: &str =
    "UPDATE organizations SET billing_status = 'suspended', updated_at = NOW() WHERE id = $1";

/// Resolves the org owner's email for the trial-expired notice.
const SELECT_OWNER_EMAIL: &str = r#"SELECT u.email FROM org_members m
               JOIN users u ON u.id = m.user_id
               WHERE m.org_id = $1 AND m.role = 'owner'
               ORDER BY m.created_at ASC LIMIT 1"#;

pub async fn check_expired_trials(pool: &PgPool, email: &EmailClient) -> anyhow::Result<()> {
    let org_ids: Vec<(String,)> = sqlx::query_as(SELECT_EXPIRED_TRIALS)
        .fetch_all(pool)
        .await?;

    for (org_id,) in org_ids {
        if let Err(e) = sqlx::query(SUSPEND_TRIAL_SUBSCRIPTION)
            .bind(&org_id)
            .execute(pool)
            .await
        {
            tracing::error!(org_id, error = %e, "billing: failed to suspend trial org subscription");
            continue;
        }

        if let Err(e) = sqlx::query(SUSPEND_ORG_BILLING_STATUS)
            .bind(&org_id)
            .execute(pool)
            .await
        {
            tracing::error!(org_id, error = %e, "billing: failed to update org billing status");
        }

        // Match Go: a missing Resend key disables the email path entirely.
        if email.is_configured() {
            let owner_email: Option<(String,)> = sqlx::query_as(SELECT_OWNER_EMAIL)
                .bind(&org_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);
            if let Some((owner,)) = owner_email
                && !owner.is_empty()
                && let Err(e) = email.send_trial_expired(&owner).await
            {
                tracing::error!(org_id, error = %e, "billing: failed to send trial expired email");
            }
        }

        log_billing_event(pool, "trial_expired", &org_id, None, "usd", "", None).await;
        tracing::info!(org_id, "billing: trial expired, org suspended");
    }
    Ok(())
}

// ── Overage invoicing (port of ReportEnvironmentOverages) ──────────────

/// Mirrors `billing.EffectiveOrgEnvironmentPlan` resolution.
#[derive(Debug, Default, Clone)]
pub struct EffectivePlan {
    pub plan: String,
    pub stripe_subscription: Option<String>,
}

pub async fn resolve_effective_org_environment_plan(pool: &PgPool, org_id: &str) -> EffectivePlan {
    if let Ok(Some((plan, sub))) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"SELECT plan, stripe_subscription_id
           FROM environment_subscriptions
           WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
           ORDER BY updated_at DESC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
        && !plan.is_empty()
    {
        return EffectivePlan {
            plan,
            stripe_subscription: sub,
        };
    }
    if let Ok(Some((plan, sub))) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"SELECT os.plan, os.stripe_subscription_id
           FROM org_subscriptions os
           WHERE os.org_id = $1 AND os.status IN ('active', 'trialing', 'past_due')
           ORDER BY os.updated_at DESC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
        && !plan.is_empty()
    {
        return EffectivePlan {
            plan,
            stripe_subscription: sub,
        };
    }
    if let Ok(Some((plan,))) = sqlx::query_as::<_, (String,)>(
        r#"SELECT billing_plan FROM organizations
           WHERE id = $1 AND billing_plan NOT IN ('', 'none')
             AND billing_status IN ('active', 'trialing', 'past_due')"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    {
        return EffectivePlan {
            plan,
            stripe_subscription: None,
        };
    }
    EffectivePlan::default()
}

/// Mirrors `OrgOwnerIsAdmin`.
pub async fn org_owner_is_admin(pool: &PgPool, org_id: &str) -> bool {
    sqlx::query_as::<_, (bool,)>(
        r#"SELECT u.is_admin FROM org_members m
           JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 AND m.role = 'owner'
           ORDER BY m.created_at ASC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(b,)| b)
    .unwrap_or(false)
}

/// The overage-relevant slice of a sandbox plan, from the DB catalog
/// (Go reads the in-memory catalog loaded from the same rows;
/// archived plans are excluded there too).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OveragePlan {
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
    pub included_disk_gb_hours: i32,
    pub cpu_overage_cents: f64,
    pub mem_overage_cents: f64,
    pub disk_overage_cents: f64,
}

async fn get_sandbox_overage_plan(pool: &PgPool, plan_key: &str) -> Option<OveragePlan> {
    sqlx::query_as(
        r#"SELECT included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours,
                  cpu_overage_cents, mem_overage_cents, disk_overage_cents
           FROM billing_catalog_plans
           WHERE resource_type = 'sandbox' AND plan_key = $1 AND archived_at IS NULL"#,
    )
    .bind(plan_key)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Mirrors `CalculateOverageCents`.
pub fn calculate_overage_cents(
    plan: &OveragePlan,
    cpu_hours: f64,
    mem_gb_hours: f64,
    disk_gb_hours: f64,
) -> i32 {
    let cpu_over = (cpu_hours - f64::from(plan.included_cpu_hours)).max(0.0);
    let mem_over = (mem_gb_hours - f64::from(plan.included_mem_gb_hours)).max(0.0);
    let disk_over = (disk_gb_hours - f64::from(plan.included_disk_gb_hours)).max(0.0);
    let total = cpu_over * plan.cpu_overage_cents
        + mem_over * plan.mem_overage_cents
        + disk_over * plan.disk_overage_cents;
    total.ceil() as i32
}

/// Mirrors `billingsessions.AggregateMonthlyUsage`.
pub(crate) async fn aggregate_monthly_usage(
    pool: &PgPool,
    org_id: &str,
    month_start: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<(f64, f64, f64)> {
    let row: (f64, f64, f64) = sqlx::query_as(
        r#"WITH period AS (
               SELECT $1::timestamptz AS start_at,
                      ($1::timestamptz + interval '1 month') AS end_at
           ),
           bounded AS (
               SELECT s.cpu_millicores,
                      s.memory_mib,
                      s.disk_gib,
                      GREATEST(s.started_at, p.start_at) AS bill_start,
                      LEAST(COALESCE(s.ended_at, NOW()), p.end_at) AS bill_end
               FROM sandbox_running_sessions s
               CROSS JOIN period p
               WHERE s.organization_id = $2
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
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("aggregate sandbox session usage: {e}"))?;
    Ok(row)
}

pub async fn report_environment_overages(deps: &MeteringDeps) -> anyhow::Result<()> {
    let Some(_) = deps.stripe.enabled() else {
        return Ok(());
    };
    let pool = &deps.pool;
    let now = chrono::Utc::now();
    let month_start =
        chrono::NaiveDate::from_ymd_opt(now.date_naive().year(), now.date_naive().month(), 1)
            .expect("first of month")
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc();
    let period_label = month_start.format("%b %Y").to_string();

    let org_ids: Vec<(String,)> = sqlx::query_as(
        r#"SELECT DISTINCT o.id
           FROM organizations o
           WHERE EXISTS (
               SELECT 1 FROM environment_subscriptions es
               WHERE es.org_id = o.id AND es.status IN ('active', 'trialing', 'past_due')
           )
              OR EXISTS (
               SELECT 1 FROM org_subscriptions os
               WHERE os.org_id = o.id AND os.status IN ('active', 'trialing', 'past_due')
           )
              OR (
               o.billing_plan NOT IN ('', 'none')
               AND o.billing_status IN ('active', 'trialing', 'past_due')
           )"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow::anyhow!("query billable orgs: {e}"))?;

    let mut checked = 0;
    let mut updated = 0;

    for (org_id,) in org_ids {
        let effective = resolve_effective_org_environment_plan(pool, &org_id).await;
        let Some(plan) = get_sandbox_overage_plan(pool, &effective.plan).await else {
            continue;
        };
        if plan.cpu_overage_cents == 0.0
            && plan.mem_overage_cents == 0.0
            && plan.disk_overage_cents == 0.0
        {
            continue;
        }

        let owner_is_admin = org_owner_is_admin(pool, &org_id).await;
        checked += 1;

        let (cpu_hours, mem_gb_hours, disk_gb_hours) =
            match aggregate_monthly_usage(pool, &org_id, month_start).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(org_id, error = %e, "env overage: query session usage");
                    continue;
                }
            };

        let overage_cents = calculate_overage_cents(&plan, cpu_hours, mem_gb_hours, disk_gb_hours);

        let existing: Option<(i32, Option<String>)> = match sqlx::query_as(
            r#"SELECT last_overage_cents, stripe_invoice_item_id
               FROM environment_usage_billing
               WHERE org_id = $1 AND billing_period_start = $2"#,
        )
        .bind(&org_id)
        .bind(month_start)
        .fetch_optional(pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(org_id, error = %e, "env overage: query billing record");
                continue;
            }
        };
        let last_overage_cents = existing.as_ref().map(|(c, _)| *c).unwrap_or(0);
        let existing_item_id = existing.as_ref().and_then(|(_, id)| id.clone());

        if existing.is_some() && last_overage_cents == overage_cents {
            continue;
        }

        // Below minimum threshold.
        if overage_cents > 0 && overage_cents < deps.stripe.min_overage_cents() {
            sqlx::query(
                r#"INSERT INTO environment_usage_billing
                   (org_id, billing_period_start, last_cpu_hours, last_mem_gb_hours, last_disk_gb_hours, last_overage_cents, stripe_invoice_item_id, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, NULL, NOW())
                   ON CONFLICT (org_id, billing_period_start)
                   DO UPDATE SET last_cpu_hours = $3, last_mem_gb_hours = $4, last_disk_gb_hours = $5,
                                last_overage_cents = $6, updated_at = NOW()"#,
            )
            .bind(&org_id)
            .bind(month_start)
            .bind(cpu_hours)
            .bind(mem_gb_hours)
            .bind(disk_gb_hours)
            .bind(overage_cents)
            .execute(pool)
            .await
            .map_err(|e| anyhow::anyhow!("record below-threshold environment overage: {e}"))?;
            log_billing_event(
                pool,
                "env_below_threshold",
                &org_id,
                Some(overage_cents),
                "usd",
                "",
                Some(serde_json::json!({ "threshold": deps.stripe.min_overage_cents() })),
            )
            .await;
            updated += 1;
            continue;
        }

        let customer_id: Option<String> = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT stripe_customer_id FROM organizations WHERE id = $1",
        )
        .bind(&org_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|(c,)| c)
        .filter(|c| !c.is_empty());
        let Some(customer_id) = customer_id else {
            tracing::debug!(org_id, "env overage: no stripe customer");
            continue;
        };

        let has_stripe_sub = effective
            .stripe_subscription
            .as_deref()
            .is_some_and(|s| !s.is_empty());

        if has_stripe_sub {
            // Pending items are replaced wholesale; the subscription's
            // billing cycle invoices them.
            if let Some(old_id) = existing_item_id.as_deref().filter(|s| !s.is_empty()) {
                let idempotency_key = metering_idempotency_key("delete-item", &[&org_id, old_id]);
                if let Err(e) = run_organization_billing_mutation(pool, &org_id, async {
                    deps.stripe
                        .delete_invoice_item(old_id, &idempotency_key)
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await
                {
                    tracing::warn!(id = old_id, error = %e, "env overage: delete old invoice item");
                    continue;
                }
            }

            let mut new_item_id: Option<String> = None;
            if overage_cents > 0 {
                let amount = overage_cents.to_string();
                let idempotency_key = metering_idempotency_key(
                    "subscription-overage",
                    &[&org_id, &period_label, &amount],
                );
                match run_organization_billing_mutation(pool, &org_id, async {
                    deps.stripe
                        .create_overage_invoice_item(
                            &customer_id,
                            i64::from(overage_cents),
                            &format!("Environment compute overage ({period_label})"),
                            &idempotency_key,
                        )
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await
                {
                    Err(e) => {
                        tracing::error!(org_id, error = %e, "env overage: create invoice item");
                        continue;
                    }
                    Ok(id) => {
                        log_billing_event(
                            pool,
                            "env_overage_charge",
                            &org_id,
                            Some(overage_cents),
                            "usd",
                            &id,
                            Some(serde_json::json!({
                                "cpu_hours": cpu_hours, "mem_gb_hours": mem_gb_hours, "disk_gb_hours": disk_gb_hours,
                            })),
                        )
                        .await;
                        new_item_id = Some(id);
                    }
                }
            }

            if overage_cents > 0 && owner_is_admin && new_item_id.is_some() {
                let amount = overage_cents.to_string();
                let idempotency_key = metering_idempotency_key(
                    "subscription-overage-admin-credit",
                    &[&org_id, &period_label, &amount],
                );
                match run_organization_billing_mutation(pool, &org_id, async {
                    deps.stripe
                        .create_overage_invoice_item(
                            &customer_id,
                            -i64::from(overage_cents),
                            &format!("Admin credit for billing visibility: environment overage ({period_label})"),
                            &idempotency_key,
                        )
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await
                {
                    Err(e) => tracing::error!(org_id, error = %e, "env overage: create admin credit"),
                    Ok(credit_id) => {
                        log_billing_event(pool, "env_admin_credit", &org_id, Some(-overage_cents), "usd", &credit_id, None).await;
                    }
                }
            }

            sqlx::query(
                r#"INSERT INTO environment_usage_billing
                   (org_id, billing_period_start, last_cpu_hours, last_mem_gb_hours, last_disk_gb_hours, last_overage_cents, stripe_invoice_item_id, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                   ON CONFLICT (org_id, billing_period_start)
                   DO UPDATE SET last_cpu_hours = $3, last_mem_gb_hours = $4, last_disk_gb_hours = $5,
                                last_overage_cents = $6, stripe_invoice_item_id = $7, updated_at = NOW()"#,
            )
            .bind(&org_id)
            .bind(month_start)
            .bind(cpu_hours)
            .bind(mem_gb_hours)
            .bind(disk_gb_hours)
            .bind(overage_cents)
            .bind(&new_item_id)
            .execute(pool)
            .await
            .map_err(|e| anyhow::anyhow!("record subscription environment overage: {e}"))?;
        } else {
            // No Stripe subscription — invoice the incremental
            // difference immediately.
            let diff_cents = overage_cents - last_overage_cents;
            if diff_cents <= 0 {
                continue;
            }

            let diff = diff_cents.to_string();
            let previous = last_overage_cents.to_string();
            let idempotency_key = metering_idempotency_key(
                "incremental-overage",
                &[&org_id, &period_label, &previous, &diff],
            );
            let charge_id = match run_organization_billing_mutation(pool, &org_id, async {
                deps.stripe
                    .create_overage_invoice_item(
                        &customer_id,
                        i64::from(diff_cents),
                        &format!("Environment compute overage ({period_label})"),
                        &idempotency_key,
                    )
                    .await
                    .map_err(OrganizationBillingMutationError::ambiguous)
            })
            .await
            {
                Err(e) => {
                    tracing::error!(org_id, error = %e, "env overage: create invoice item");
                    continue;
                }
                Ok(id) => id,
            };
            log_billing_event(
                pool,
                "env_overage_charge",
                &org_id,
                Some(diff_cents),
                "usd",
                &charge_id,
                Some(serde_json::json!({
                    "cpu_hours": cpu_hours, "mem_gb_hours": mem_gb_hours, "disk_gb_hours": disk_gb_hours,
                    "differential": true, "previous_cents": last_overage_cents,
                })),
            )
            .await;

            if owner_is_admin {
                let idempotency_key = metering_idempotency_key(
                    "incremental-overage-admin-credit",
                    &[&org_id, &period_label, &previous, &diff],
                );
                match run_organization_billing_mutation(pool, &org_id, async {
                    deps.stripe
                        .create_overage_invoice_item(
                            &customer_id,
                            -i64::from(diff_cents),
                            &format!("Admin credit for billing visibility: environment overage ({period_label})"),
                            &idempotency_key,
                        )
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await
                {
                    Err(e) => tracing::error!(org_id, error = %e, "env overage: create admin credit"),
                    Ok(credit_id) => {
                        log_billing_event(pool, "env_admin_credit", &org_id, Some(-diff_cents), "usd", &credit_id, None).await;
                    }
                }
            }

            let invoice_key = metering_idempotency_key(
                "overage-invoice",
                &[&org_id, &period_label, &previous, &diff],
            );
            match run_organization_billing_mutation(pool, &org_id, async {
                deps.stripe
                    .create_auto_advancing_invoice(
                        &customer_id,
                        &format!("Environment compute - {period_label}"),
                        &invoice_key,
                    )
                    .await
                    .map_err(OrganizationBillingMutationError::ambiguous)
            })
            .await
            {
                Err(e) => tracing::error!(org_id, error = %e, "env overage: create invoice"),
                Ok(invoice_id) => {
                    let finalize_key =
                        metering_idempotency_key("finalize-invoice", &[&org_id, &invoice_id]);
                    match run_organization_billing_mutation(pool, &org_id, async {
                        deps.stripe
                            .finalize_invoice(&invoice_id, &finalize_key)
                            .await
                            .map_err(OrganizationBillingMutationError::ambiguous)
                    })
                    .await
                    {
                        Err(e) => {
                            tracing::error!(org_id, invoice = invoice_id, error = %e, "env overage: finalize invoice")
                        }
                        Ok(()) => {
                            tracing::info!(
                                org_id,
                                invoice = invoice_id,
                                amount_cents = diff_cents,
                                "env overage: invoice created"
                            )
                        }
                    }
                }
            }

            sqlx::query(
                r#"INSERT INTO environment_usage_billing
                   (org_id, billing_period_start, last_cpu_hours, last_mem_gb_hours, last_disk_gb_hours, last_overage_cents, stripe_invoice_item_id, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, NULL, NOW())
                   ON CONFLICT (org_id, billing_period_start)
                   DO UPDATE SET last_cpu_hours = $3, last_mem_gb_hours = $4, last_disk_gb_hours = $5,
                                last_overage_cents = $6, stripe_invoice_item_id = NULL, updated_at = NOW()"#,
            )
            .bind(&org_id)
            .bind(month_start)
            .bind(cpu_hours)
            .bind(mem_gb_hours)
            .bind(disk_gb_hours)
            .bind(overage_cents)
            .execute(pool)
            .await
            .map_err(|e| anyhow::anyhow!("record invoiced environment overage: {e}"))?;
        }

        updated += 1;
        if overage_cents > 0 {
            tracing::info!(org_id, overage_cents, "env overage: recorded");
        }
    }

    if checked > 0 {
        tracing::info!(checked, updated, "env overage: report complete");
    }
    Ok(())
}

fn metering_idempotency_key(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("cw-{kind}-{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(inc: (i32, i32, i32), cents: (f64, f64, f64)) -> OveragePlan {
        OveragePlan {
            included_cpu_hours: inc.0,
            included_mem_gb_hours: inc.1,
            included_disk_gb_hours: inc.2,
            cpu_overage_cents: cents.0,
            mem_overage_cents: cents.1,
            disk_overage_cents: cents.2,
        }
    }

    #[test]
    fn overage_cents_mirror_go() {
        // Under the included allowance → 0.
        let p = plan((100, 200, 300), (5.0, 1.0, 0.5));
        assert_eq!(calculate_overage_cents(&p, 50.0, 100.0, 200.0), 0);
        // Mixed: only CPU over; ceil applied to the total.
        assert_eq!(calculate_overage_cents(&p, 100.5, 100.0, 200.0), 3); // 0.5*5 = 2.5 → 3
        // All over.
        assert_eq!(
            calculate_overage_cents(&p, 110.0, 210.0, 310.0),
            (10.0f64 * 5.0 + 10.0 * 1.0 + 10.0 * 0.5).ceil() as i32
        );
        // Zero-rate plan.
        let p0 = plan((0, 0, 0), (0.0, 0.0, 0.0));
        assert_eq!(calculate_overage_cents(&p0, 1000.0, 1000.0, 1000.0), 0);
    }

    // ── Trial expiry: query-shape + transition parity with the Go source.
    // These pin the SQL contract against `internal/billing/trial.go`'s
    // `CheckExpiredTrials` without needing a live DB; the e2e
    // `TestE2E_RustBillingSuspendsExpiredTrial` covers the wired path.

    #[test]
    fn expired_trials_selection_mirrors_go() {
        // Go selects trialing subs past trial_end with no Stripe sub.
        assert!(SELECT_EXPIRED_TRIALS.contains("FROM org_subscriptions os"));
        assert!(SELECT_EXPIRED_TRIALS.contains("os.status = 'trialing'"));
        assert!(SELECT_EXPIRED_TRIALS.contains("os.trial_end < NOW()"));
        assert!(SELECT_EXPIRED_TRIALS.contains("os.stripe_subscription_id IS NULL"));
        // Only the org_id is projected (drives the per-org transition).
        assert!(SELECT_EXPIRED_TRIALS.contains("SELECT os.org_id"));
    }

    #[test]
    fn trial_transition_suspends_both_subscription_and_org() {
        // First UPDATE: the subscription itself → 'suspended'.
        assert!(SUSPEND_TRIAL_SUBSCRIPTION.contains("UPDATE org_subscriptions"));
        assert!(SUSPEND_TRIAL_SUBSCRIPTION.contains("status = 'suspended'"));
        assert!(SUSPEND_TRIAL_SUBSCRIPTION.contains("updated_at = NOW()"));
        assert!(SUSPEND_TRIAL_SUBSCRIPTION.contains("WHERE org_id = $1"));

        // Second UPDATE: the denormalized org billing_status → 'suspended'.
        assert!(SUSPEND_ORG_BILLING_STATUS.contains("UPDATE organizations"));
        assert!(SUSPEND_ORG_BILLING_STATUS.contains("billing_status = 'suspended'"));
        assert!(SUSPEND_ORG_BILLING_STATUS.contains("updated_at = NOW()"));
        assert!(SUSPEND_ORG_BILLING_STATUS.contains("WHERE id = $1"));
    }

    #[test]
    fn owner_email_lookup_mirrors_go() {
        // Oldest owner member's email, matching Go's ORDER BY ... LIMIT 1.
        assert!(SELECT_OWNER_EMAIL.contains("FROM org_members m"));
        assert!(SELECT_OWNER_EMAIL.contains("JOIN users u ON u.id = m.user_id"));
        assert!(SELECT_OWNER_EMAIL.contains("m.role = 'owner'"));
        assert!(SELECT_OWNER_EMAIL.contains("ORDER BY m.created_at ASC LIMIT 1"));
    }
}
