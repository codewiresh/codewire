//! Org billing overview + environment usage for the Connect service.
//!
//! Both require an authenticated org member and hide organization existence
//! from non-members with a 404.
//!
//! The plan catalog lives in `billing_catalog_*`; these queries read it
//! directly. Lookups do not filter `archived_at`; only the public listing does.
//!
//! Stripe `has_payment_method` is a read-only Customers retrieve
//! checking `invoice_settings.default_payment_method`. With no
//! `STRIPE_SECRET_KEY` configured the service reports
//! `billing_enabled:false, has_payment_method:false`.

use chrono::{DateTime, Datelike, Duration, NaiveDateTime, TimeZone, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::require_org_member;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use crate::routes::BillingState;

// ── Response shapes ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct BillingLimitUsage {
    pub used: i32,
    pub max: i32,
}

#[derive(Debug)]
pub struct BillingLimits {
    pub team_members: BillingLimitUsage,
    pub concurrent_workspaces: i32,
    pub storage_gb: i32,
}

#[derive(Debug)]
pub struct UsageSummary {
    pub cpu_hours: f64,
    pub memory_gb_hours: f64,
    pub storage_gb_hours: f64,
}

#[derive(Debug)]
pub struct SubscriptionSummary {
    pub resource_type: String,
    pub plan: String,
    pub plan_display_name: String,
    pub status: String,
    pub monthly_cost_cents: i32,
}

/// A rate card's prices, in nano-euros per unit-hour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CreditRates {
    pub cpu_per_vcpu_hour: i64,
    pub memory_per_gib_hour: i64,
    pub disk_per_gib_hour: i64,
}

/// An organization's prepaid compute credit (#3381). The card's name is never
/// shown; Discounted is not offered publicly.
#[derive(Debug, Clone, Default)]
pub struct CreditOverview {
    pub balance_nano_eur: i64,
    pub rates: CreditRates,
    /// The Unlimited card: no charge and no quota.
    pub unmetered: bool,
    pub auto_top_up_enabled: bool,
    pub auto_top_up_cents: i32,
    pub exhausted_at: Option<String>,
    pub month_usage_nano_eur: i64,
}

#[derive(Debug)]
pub struct BillingOverviewResponse {
    pub credit: CreditOverview,
    pub billing_enabled: bool,
    pub has_payment_method: bool,
    pub plan: String,
    pub plan_display_name: String,
    pub status: String,
    pub trial_end: Option<String>,
    pub trial_days: i32,
    pub seat_count: i32,
    pub included_devs: i32,
    pub extra_seat_price_cents: i32,
    pub limits: BillingLimits,
    pub current_period_end: Option<String>,
    pub active_subscriptions: i32,
    pub total_monthly_cost_cents: i32,
    /// The Go handler never populates this; a Go nil slice marshals as
    /// JSON null, so `None` here is the faithful encoding.
    pub subscriptions: Option<Vec<SubscriptionSummary>>,
    pub current_month_usage: UsageSummary,
}

// ── Catalog lookups (DB-backed, see module docs) ───────────────────

#[derive(Debug, Default, sqlx::FromRow)]
struct CatalogOrgPlan {
    display_name: String,
    included_devs: i32,
    max_team_members: i32,
}

#[derive(Debug, Default, sqlx::FromRow)]
struct CatalogResourcePlan {
    display_name: String,
    price_cents: i32,
    max_concurrent_ws: i32,
    storage_gb: i32,
    included_cpu_hours: i32,
    included_mem_gb_hours: i32,
}

async fn lookup_org_plan(pool: &PgPool, key: &str) -> AppResult<Option<CatalogOrgPlan>> {
    Ok(sqlx::query_as(
        r#"SELECT display_name, included_devs, max_team_members
           FROM billing_catalog_plans WHERE resource_type = 'org' AND plan_key = $1"#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await?)
}

async fn lookup_resource_plan(
    pool: &PgPool,
    resource_type: &str,
    key: &str,
) -> AppResult<Option<CatalogResourcePlan>> {
    Ok(sqlx::query_as(
        r#"SELECT display_name, price_cents, max_concurrent_ws, storage_gb,
                  included_cpu_hours, included_mem_gb_hours
           FROM billing_catalog_plans WHERE resource_type = $1 AND plan_key = $2"#,
    )
    .bind(resource_type)
    .bind(key)
    .fetch_optional(pool)
    .await?)
}

/// `trial_days` / `extra_seat_cents` with the same compile-time
/// fallbacks Go keeps for a not-yet-seeded database.
async fn lookup_settings(pool: &PgPool) -> AppResult<(i32, i32)> {
    let rows: Vec<(String, i32)> =
        sqlx::query_as(r#"SELECT setting_key, int_value FROM billing_catalog_settings"#)
            .fetch_all(pool)
            .await?;
    let (mut trial_days, mut extra_seat) = (14, 1800);
    for (k, v) in rows {
        match k.as_str() {
            "trial_days" => trial_days = v,
            "extra_seat_cents" => extra_seat = v,
            _ => {}
        }
    }
    Ok((trial_days, extra_seat))
}

// ── Effective plan resolution ───────────────────────────────────────

#[derive(Debug, Default)]
struct EffectiveOrgBilling {
    plan: String,
    plan_display_name: String,
    status: String,
    trial_end: Option<NaiveDateTime>,
    current_period_end: Option<NaiveDateTime>,
    seat_count: i32,
}

/// Mirrors `billing.ResolveEffectiveOrgEnvironmentPlan` +
/// `api.loadEffectiveOrgBilling`: environment subscription wins, then
/// org subscription, then the denormalized org columns.
async fn load_effective_org_billing(pool: &PgPool, org_id: &str) -> AppResult<EffectiveOrgBilling> {
    let mut state = EffectiveOrgBilling {
        plan: "none".into(),
        status: "none".into(),
        ..Default::default()
    };

    if let Some((plan, status, trial_end)) = sqlx::query_as::<
        _,
        (String, String, Option<NaiveDateTime>),
    >(
        r#"SELECT billing_plan, billing_status, trial_ends_at FROM organizations WHERE id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    {
        state.plan = plan;
        state.status = status;
        state.trial_end = trial_end;
    }

    if let Some((seats, period_end)) = sqlx::query_as::<_, (i32, Option<NaiveDateTime>)>(
        r#"SELECT seat_count, current_period_end FROM org_subscriptions WHERE org_id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    {
        state.seat_count = seats;
        state.current_period_end = period_end;
    }

    if let Some(p) = lookup_org_plan(pool, &state.plan).await? {
        state.plan_display_name = p.display_name;
    } else if !state.plan.is_empty() && state.plan != "none" {
        state.plan_display_name = state.plan.clone();
    }

    // ResolveEffectiveOrgEnvironmentPlan: env subscription first…
    let effective: Option<(String, String, Option<NaiveDateTime>)> = sqlx::query_as(
        r#"SELECT plan, status, trial_end
           FROM environment_subscriptions
           WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
           ORDER BY updated_at DESC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;

    // …then org subscription…
    let effective = match effective {
        Some(e) if !e.0.is_empty() => Some(e),
        _ => sqlx::query_as(
            r#"SELECT os.plan, os.status, COALESCE(os.trial_end, o.trial_ends_at)
               FROM org_subscriptions os
               JOIN organizations o ON o.id = os.org_id
               WHERE os.org_id = $1 AND os.status IN ('active', 'trialing', 'past_due')
               ORDER BY os.updated_at DESC LIMIT 1"#,
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .filter(|e: &(String, String, Option<NaiveDateTime>)| !e.0.is_empty()),
    };

    // …then the denormalized org columns.
    let effective = match effective {
        Some(e) => Some(e),
        None => sqlx::query_as(
            r#"SELECT billing_plan, billing_status, trial_ends_at
               FROM organizations
               WHERE id = $1
                 AND billing_plan NOT IN ('', 'none')
                 AND billing_status IN ('active', 'trialing', 'past_due')"#,
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .filter(|e: &(String, String, Option<NaiveDateTime>)| !e.0.is_empty()),
    };

    if let Some((plan, status, trial_end)) = effective {
        state.plan_display_name = match lookup_resource_plan(pool, "sandbox", &plan).await? {
            Some(p) => p.display_name,
            None => plan.clone(),
        };
        state.plan = plan;
        state.status = status;
        state.trial_end = trial_end;
    }

    Ok(state)
}

fn fmt_naive_utc_opt(t: Option<NaiveDateTime>) -> Option<String> {
    t.map(|t| {
        DateTime::<Utc>::from_naive_utc_and_offset(t, Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    })
}

fn coalesce_plan_display_name(values: &[&str]) -> String {
    for v in values {
        if !v.is_empty() && *v != "none" {
            return (*v).to_string();
        }
    }
    "No plan".to_string()
}

async fn credit_overview(
    pool: &PgPool,
    org_id: &str,
    month_start: DateTime<Utc>,
) -> AppResult<CreditOverview> {
    type Row = (
        String,
        i64,
        i64,
        i64,
        i64,
        bool,
        i32,
        Option<DateTime<Utc>>,
        i64,
    );
    let row: Row = sqlx::query_as(
        r#"SELECT
               o.rate_card, r.cpu_nano_eur_per_vcpu_hour,
               r.memory_nano_eur_per_gib_hour, r.disk_nano_eur_per_gib_hour,
               COALESCE((SELECT balance_nano_eur FROM billing_credit_balances
                         WHERE organization_id = o.id), 0),
               o.auto_top_up_enabled,
               o.auto_top_up_cents,
               o.credit_exhausted_at,
               COALESCE((SELECT -SUM(amount_nano_eur) FROM billing_credit_ledger
                         WHERE organization_id = o.id AND entry_kind = 'usage'
                           AND usage_ended_at >= $2), 0)::int8
           FROM organizations o
           JOIN billing_rate_cards r ON r.rate_card = o.rate_card
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .bind(month_start)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    let (rate_card, cpu, memory, disk, balance, enabled, cents, exhausted_at, month) = row;
    Ok(CreditOverview {
        balance_nano_eur: balance,
        rates: CreditRates {
            cpu_per_vcpu_hour: cpu,
            memory_per_gib_hour: memory,
            disk_per_gib_hour: disk,
        },
        unmetered: rate_card == crate::credit::UNLIMITED_RATE_CARD,
        auto_top_up_enabled: enabled,
        auto_top_up_cents: cents,
        exhausted_at: exhausted_at.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        month_usage_nano_eur: month,
    })
}

/// The smallest and largest automatic top-up: EUR 5 and EUR 1,000.
pub const AUTO_TOP_UP_CENTS: std::ops::RangeInclusive<i32> = 500..=100_000;

/// Turns automatic top-up on or off and sets its amount, for an organization
/// owner or admin, and audits the change in the same transaction.
pub async fn update_auto_top_up(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    enabled: bool,
    amount_cents: i32,
) -> AppResult<(bool, i32)> {
    crate::checkout_sessions::require_org_billing_admin(pool, user, org_id).await?;
    if !AUTO_TOP_UP_CENTS.contains(&amount_cents) {
        return Err(AppError::Validation {
            errors: vec![codewire_server_core::ValidationIssue {
                path: "/amount_cents".into(),
                message: "must be between 500 and 100000".into(),
            }],
        });
    }
    let mut transaction = pool.begin().await?;
    let previous: (bool, i32) = sqlx::query_as(
        r#"SELECT auto_top_up_enabled, auto_top_up_cents FROM organizations
           WHERE id = $1 FOR UPDATE"#,
    )
    .bind(org_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        r#"UPDATE organizations
           SET auto_top_up_enabled = $2, auto_top_up_cents = $3, updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(org_id)
    .bind(enabled)
    .bind(amount_cents)
    .execute(&mut *transaction)
    .await?;
    if previous != (enabled, amount_cents) {
        sqlx::query(
            r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
               VALUES (gen_random_uuid()::text, NOW(), 'organization.billing.auto_top_up', $1,
                       jsonb_build_object('organization_id', $2::text,
                                          'previous_enabled', $3::bool,
                                          'previous_amount_cents', $4::int,
                                          'enabled', $5::bool, 'amount_cents', $6::int),
                       'info')"#,
        )
        .bind(&user.user_id)
        .bind(org_id)
        .bind(previous.0)
        .bind(previous.1)
        .bind(enabled)
        .bind(amount_cents)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok((enabled, amount_cents))
}

/// Shared billing-overview operation used by the Connect adapter.
pub async fn billing_overview(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<BillingOverviewResponse> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;

    let effective = load_effective_org_billing(pool, org_id).await?;

    let member_count: i64 =
        sqlx::query_scalar(r#"SELECT COUNT(*) FROM org_members WHERE org_id = $1"#)
            .bind(org_id)
            .fetch_one(pool)
            .await?;

    let billing_enabled = state.stripe.is_configured();
    let has_payment_method = state.stripe.org_has_payment_method(pool, org_id).await;

    let org_plan = lookup_org_plan(pool, &effective.plan)
        .await?
        .unwrap_or_default();
    let env_plan = lookup_resource_plan(pool, "sandbox", &effective.plan)
        .await?
        .unwrap_or_default();

    let (active_subs, total_monthly) = if matches!(
        effective.status.as_str(),
        "active" | "trialing" | "past_due"
    ) {
        (1, env_plan.price_cents)
    } else {
        (0, 0)
    };

    let now = Utc::now();
    let month_start = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .expect("first of month is always valid");
    let usage = usage_sums(pool, org_id, month_start).await?;
    let credit = credit_overview(pool, org_id, month_start).await?;

    let (trial_days, extra_seat_cents) = lookup_settings(pool).await?;

    Ok(BillingOverviewResponse {
        credit,
        billing_enabled,
        has_payment_method,
        plan_display_name: coalesce_plan_display_name(&[
            &effective.plan_display_name,
            &org_plan.display_name,
            &effective.plan,
        ]),
        plan: effective.plan,
        status: effective.status,
        trial_end: fmt_naive_utc_opt(effective.trial_end),
        trial_days,
        seat_count: effective.seat_count,
        included_devs: org_plan.included_devs,
        extra_seat_price_cents: extra_seat_cents,
        limits: BillingLimits {
            team_members: BillingLimitUsage {
                used: member_count as i32,
                max: org_plan.max_team_members,
            },
            concurrent_workspaces: env_plan.max_concurrent_ws,
            storage_gb: env_plan.storage_gb,
        },
        current_period_end: fmt_naive_utc_opt(effective.current_period_end),
        active_subscriptions: active_subs,
        total_monthly_cost_cents: total_monthly,
        subscriptions: None,
        current_month_usage: UsageSummary {
            cpu_hours: usage.cpu_hours,
            memory_gb_hours: usage.mem_gb_hours,
            storage_gb_hours: usage.disk_gb_hours,
        },
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct UsageSums {
    cpu_hours: f64,
    mem_gb_hours: f64,
    disk_gb_hours: f64,
}

fn session_ledger_canonical() -> bool {
    !matches!(
        std::env::var("BILLING_SESSION_LEDGER_CANONICAL")
            .unwrap_or_else(|_| "true".to_string())
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

async fn usage_sums(pool: &PgPool, org_id: &str, since: DateTime<Utc>) -> AppResult<UsageSums> {
    if session_ledger_canonical() {
        return session_usage_sums(pool, org_id, since).await;
    }
    legacy_event_usage_sums(pool, org_id, since).await
}

async fn legacy_event_usage_sums(
    pool: &PgPool,
    org_id: &str,
    since: DateTime<Utc>,
) -> AppResult<UsageSums> {
    let (cpu_hours, mem_gb_hours, disk_gb_hours): (f64, f64, f64) = sqlx::query_as(
        r#"
        SELECT
          COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'cpu_millicores')::float / 1000.0), 0),
          COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'memory_mb')::float / 1024.0), 0),
          COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * COALESCE((metadata->>'disk_gb')::float, 0)), 0)
        FROM billing_events
        WHERE event_type = 'environment_usage' AND created_at >= $1 AND org_id = $2
        "#,
    )
    .bind(since)
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    Ok(UsageSums {
        cpu_hours,
        mem_gb_hours,
        disk_gb_hours,
    })
}

async fn session_usage_sums(
    pool: &PgPool,
    org_id: &str,
    month_start: DateTime<Utc>,
) -> AppResult<UsageSums> {
    let (cpu_hours, mem_gb_hours, disk_gb_hours): (f64, f64, f64) = sqlx::query_as(
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
    .await?;
    Ok(UsageSums {
        cpu_hours,
        mem_gb_hours,
        disk_gb_hours,
    })
}

// ── Environment usage ───────────────────────────────────────────────

#[derive(Debug)]
pub struct EnvironmentUsageMonth {
    pub cpu_hours: f64,
    pub mem_gb_hours: f64,
    pub disk_gb_hours: f64,
    pub cost_cents: i32,
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
}

#[derive(Debug)]
pub struct EnvironmentUsageHour {
    pub hour: String,
    pub cpu_hours: f64,
    pub mem_gb_hours: f64,
    pub cost_cents: i32,
}

#[derive(Debug)]
pub struct EnvironmentUsageEntry {
    pub id: String,
    pub name: String,
    pub running_seconds: i32,
    pub cost_cents: i32,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub hourly_cents: i32,
}

#[derive(Debug)]
pub struct EnvironmentUsageResponse {
    pub current_month: EnvironmentUsageMonth,
    /// Go appends to nil slices, so empty marshals as null — `None`
    /// reproduces that exactly.
    pub hourly_breakdown: Option<Vec<EnvironmentUsageHour>>,
    pub per_environment: Option<Vec<EnvironmentUsageEntry>>,
}

/// Shared environment-usage operation used by the Connect adapter.
pub async fn environment_usage(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<EnvironmentUsageResponse> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;

    let now = Utc::now();
    let month_start = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .expect("first of month is always valid");
    let usage = usage_sums(pool, org_id, month_start).await?;

    let plan_name = load_effective_org_billing(pool, org_id).await?.plan;
    let (included_cpu, included_mem) =
        match lookup_resource_plan(pool, "sandbox", &plan_name).await? {
            Some(p) => (p.included_cpu_hours, p.included_mem_gb_hours),
            None => (0, 0),
        };

    // Hourly breakdown, last 72h. Same rounding as Go:
    // int((cpu*5.04 + mem*1.62) + 0.5) — truncation after +0.5.
    let hourly_rows = hourly_usage(pool, org_id, now - Duration::hours(72), now).await?;
    let hourly: Vec<EnvironmentUsageHour> = hourly_rows
        .into_iter()
        .map(|(hour, usage)| EnvironmentUsageHour {
            hour: hour.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            cpu_hours: usage.cpu_hours,
            mem_gb_hours: usage.mem_gb_hours,
            cost_cents: ((usage.cpu_hours * 5.04 + usage.mem_gb_hours * 1.62) + 0.5) as i32,
        })
        .collect();

    let per_env = per_environment_usage(pool, org_id, month_start).await?;

    let total_cost_cents: i32 = per_env.iter().map(|e| e.cost_cents).sum();

    Ok(EnvironmentUsageResponse {
        current_month: EnvironmentUsageMonth {
            cpu_hours: usage.cpu_hours,
            mem_gb_hours: usage.mem_gb_hours,
            disk_gb_hours: usage.disk_gb_hours,
            cost_cents: total_cost_cents,
            included_cpu_hours: included_cpu,
            included_mem_gb_hours: included_mem,
        },
        hourly_breakdown: if hourly.is_empty() {
            None
        } else {
            Some(hourly)
        },
        per_environment: if per_env.is_empty() {
            None
        } else {
            Some(per_env)
        },
    })
}

async fn hourly_usage(
    pool: &PgPool,
    org_id: &str,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<Vec<(DateTime<Utc>, UsageSums)>> {
    if session_ledger_canonical() {
        return session_hourly_usage(pool, org_id, since, now).await;
    }
    legacy_event_hourly_usage(pool, org_id, since).await
}

async fn legacy_event_hourly_usage(
    pool: &PgPool,
    org_id: &str,
    since: DateTime<Utc>,
) -> AppResult<Vec<(DateTime<Utc>, UsageSums)>> {
    let rows: Vec<(DateTime<Utc>, f64, f64)> = sqlx::query_as(
        r#"
        SELECT date_trunc('hour', created_at) AS hour,
          COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'cpu_millicores')::float / 1000.0), 0),
          COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'memory_mb')::float / 1024.0), 0)
        FROM billing_events
        WHERE event_type = 'environment_usage' AND created_at >= $1 AND org_id = $2
        GROUP BY hour ORDER BY hour
        "#,
    )
    .bind(since)
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(hour, cpu_hours, mem_gb_hours)| {
            (
                hour,
                UsageSums {
                    cpu_hours,
                    mem_gb_hours,
                    disk_gb_hours: 0.0,
                },
            )
        })
        .collect())
}

async fn session_hourly_usage(
    pool: &PgPool,
    org_id: &str,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<Vec<(DateTime<Utc>, UsageSums)>> {
    let rows: Vec<(DateTime<Utc>, f64, f64)> = sqlx::query_as(
        r#"WITH bounds AS (
               SELECT date_trunc('hour', $1::timestamptz) AS start_at,
                      date_trunc('hour', $2::timestamptz) AS end_at
           ),
           hours AS (
               SELECT generate_series(start_at, end_at, interval '1 hour') AS hour
               FROM bounds
           ),
           bounded AS (
               SELECT h.hour,
                      s.cpu_millicores,
                      s.memory_mib,
                      GREATEST(s.started_at, h.hour) AS bill_start,
                      LEAST(COALESCE(s.ended_at, $2), h.hour + interval '1 hour') AS bill_end
               FROM hours h
               JOIN sandbox_running_sessions s
                 ON s.organization_id = $3
                AND s.started_at < h.hour + interval '1 hour'
                AND COALESCE(s.ended_at, $2) > h.hour
           )
           SELECT
              hour,
              COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start)) / 3600.0 * cpu_millicores / 1000.0), 0)::float8,
              COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start)) / 3600.0 * memory_mib / 1024.0), 0)::float8
           FROM bounded
           WHERE bill_end > bill_start
           GROUP BY hour
           ORDER BY hour"#,
    )
    .bind(since)
    .bind(now)
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(hour, cpu_hours, mem_gb_hours)| {
            (
                hour,
                UsageSums {
                    cpu_hours,
                    mem_gb_hours,
                    disk_gb_hours: 0.0,
                },
            )
        })
        .collect())
}

async fn per_environment_usage(
    pool: &PgPool,
    org_id: &str,
    month_start: DateTime<Utc>,
) -> AppResult<Vec<EnvironmentUsageEntry>> {
    if session_ledger_canonical() {
        return session_per_environment_usage(pool, org_id, month_start).await;
    }
    legacy_per_environment_usage(pool, org_id).await
}

async fn legacy_per_environment_usage(
    pool: &PgPool,
    org_id: &str,
) -> AppResult<Vec<EnvironmentUsageEntry>> {
    let rows: Vec<(String, String, i32, i32, i32)> = sqlx::query_as(
        r#"
        SELECT e.id, COALESCE(e.name, e.id), e.total_running_seconds, e.cpu_millicores, e.memory_mb
        FROM environments e
        WHERE e.org_id = $1 AND e.state != 'destroyed' AND e.total_running_seconds > 0
        ORDER BY e.total_running_seconds DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, running_seconds, cpu, mem)| {
            environment_usage_entry(id, name, running_seconds, cpu, mem)
        })
        .collect())
}

async fn session_per_environment_usage(
    pool: &PgPool,
    org_id: &str,
    month_start: DateTime<Utc>,
) -> AppResult<Vec<EnvironmentUsageEntry>> {
    let rows: Vec<(String, String, i32, i32, i32, i32, i32)> = sqlx::query_as(
        r#"WITH period AS (
               SELECT $1::timestamptz AS start_at,
                      ($1::timestamptz + interval '1 month') AS end_at
           ),
           bounded AS (
               SELECT s.environment_id,
                      COALESCE(e.name, s.runtime_name, s.environment_id) AS name,
                      s.cpu_millicores,
                      s.memory_mib,
                      GREATEST(s.started_at, p.start_at) AS bill_start,
                      LEAST(COALESCE(s.ended_at, NOW()), p.end_at) AS bill_end
               FROM sandbox_running_sessions s
               CROSS JOIN period p
               LEFT JOIN environments e ON e.id = s.environment_id
               WHERE s.organization_id = $2
                 AND s.started_at < p.end_at
                 AND COALESCE(s.ended_at, NOW()) > p.start_at
           )
           SELECT
              environment_id,
              name,
              floor(COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start))), 0))::int4 AS running_seconds,
              MAX(cpu_millicores)::int4 AS cpu_millicores,
              MAX(memory_mib)::int4 AS memory_mib,
              floor(COALESCE(SUM(
                  EXTRACT(EPOCH FROM (bill_end - bill_start))
                  * (cpu_millicores / 1000.0 * 0.000014 + memory_mib / 1024.0 * 0.0000045)
                  * 100.0
              ), 0))::int4 AS cost_cents,
              floor(((MAX(cpu_millicores) / 1000.0 * 0.000014 + MAX(memory_mib) / 1024.0 * 0.0000045) * 3600.0 * 100.0))::int4 AS hourly_cents
           FROM bounded
           WHERE bill_end > bill_start
           GROUP BY environment_id, name
           HAVING COALESCE(SUM(EXTRACT(EPOCH FROM (bill_end - bill_start))), 0) > 0
           ORDER BY running_seconds DESC"#,
    )
    .bind(month_start)
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, running_seconds, cpu_millicores, memory_mb, cost_cents, hourly_cents)| {
                EnvironmentUsageEntry {
                    id,
                    name,
                    running_seconds,
                    cost_cents,
                    cpu_millicores,
                    memory_mb,
                    hourly_cents,
                }
            },
        )
        .collect())
}

fn environment_usage_entry(
    id: String,
    name: String,
    running_seconds: i32,
    cpu: i32,
    mem: i32,
) -> EnvironmentUsageEntry {
    let rate = f64::from(cpu) / 1000.0 * 0.000014 + f64::from(mem) / 1024.0 * 0.0000045;
    EnvironmentUsageEntry {
        id,
        name,
        running_seconds,
        cost_cents: (f64::from(running_seconds) * rate * 100.0) as i32,
        cpu_millicores: cpu,
        memory_mb: mem,
        hourly_cents: (rate * 3600.0 * 100.0) as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_coalesces_like_go() {
        assert_eq!(
            coalesce_plan_display_name(&["", "none", "Starter"]),
            "Starter"
        );
        assert_eq!(coalesce_plan_display_name(&["", "none", ""]), "No plan");
        assert_eq!(
            coalesce_plan_display_name(&["Custom", "Starter", "x"]),
            "Custom"
        );
    }
}
