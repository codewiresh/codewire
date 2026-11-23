//! Billing-catalog admin write handlers + subscription migrations.
//!
//! The shared operations write `billing_catalog_plans` and
//! `billing_catalog_subscription_migrations`; BillingCatalogService owns the
//! public protobuf mapping and authorization.
//!
//! `#181` removed the legacy max-instance catalog column; it is deliberately
//! not present here.

use std::borrow::Cow;

use codewire_server_core::{AppError, AppResult, ValidationIssue};
use sqlx::PgPool;

use crate::routes::BillingState;
use crate::subscription_migration::{self, MigrationCandidate};

// ── Plan create / update / archive ──────────────────────────────────

/// Connect plan input with database-native numeric widths.
#[derive(Debug)]
pub struct PlanWriteBody {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    pub is_admin_only: bool,
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
    pub included_disk_gb_hours: i32,
    pub cpu_overage_cents: f64,
    pub mem_overage_cents: f64,
    pub disk_overage_cents: f64,
}
// ── Systemd environments opt-in ─────────────────────────────────────

/// An organization as the systemd opt-in calls name it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OrganizationRef {
    pub organization_id: String,
    pub slug: String,
    pub name: String,
}

/// The organizations opted in to systemd environments
/// (docs/dev/SYSTEMD-WORKSPACE.md), by slug.
pub async fn list_systemd_organizations_core(pool: &PgPool) -> AppResult<Vec<OrganizationRef>> {
    sqlx::query_as(
        r#"SELECT id AS organization_id, slug, name FROM organizations
            WHERE systemd_environments_enabled
            ORDER BY slug"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to list systemd organizations".into()))
}

/// Opt one organization in to, or out of, systemd environments. The change
/// and its audit entry, naming the actor, the organization and the new value,
/// commit together.
pub async fn set_organization_systemd_environments_core(
    pool: &PgPool,
    actor_user_id: &str,
    organization_slug: &str,
    enabled: bool,
) -> AppResult<OrganizationRef> {
    let failed = |message: &'static str| AppError::InternalMsg(message.into());
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| failed("failed to start the systemd opt-in update"))?;
    let updated: Option<OrganizationRef> = sqlx::query_as(
        r#"UPDATE organizations
              SET systemd_environments_enabled = $2, updated_at = NOW()
            WHERE slug = $1
          RETURNING id AS organization_id, slug, name"#,
    )
    .bind(organization_slug)
    .bind(enabled)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| failed("failed to update the systemd opt-in"))?;
    let organization =
        updated.ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    sqlx::query(
        r#"INSERT INTO audit_logs
               (id, timestamp, action, user_id, metadata, severity)
           VALUES
               (gen_random_uuid()::text, NOW(),
                'admin.organization.systemd_environments', $1,
                jsonb_build_object('organization_id', $2::text,
                                   'systemd_environments_enabled', $3::bool),
                'warn')"#,
    )
    .bind(actor_user_id)
    .bind(&organization.organization_id)
    .bind(enabled)
    .execute(&mut *transaction)
    .await
    .map_err(|_| failed("failed to audit the systemd opt-in update"))?;
    transaction
        .commit()
        .await
        .map_err(|_| failed("failed to commit the systemd opt-in update"))?;
    Ok(organization)
}

/// Shared catalog-plan create operation used by BillingCatalogService.
pub async fn create_plan_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    plan: &PlanWriteBody,
) -> AppResult<()> {
    let p = plan;
    sqlx::query(
        r#"INSERT INTO billing_catalog_plans
           (resource_type, plan_key, display_name, price_cents,
            included_devs, max_concurrent_ws, max_team_members,
            storage_gb, is_contact_us, is_admin_only,
            included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours,
            cpu_overage_cents, mem_overage_cents, disk_overage_cents,
            created_at, updated_at, archived_at)
           VALUES ($1, $2, $3, $4,
                   $5, $6, $7,
                   $8, $9, $10,
                   $11, $12, $13,
                   $14, $15, $16,
                   NOW(), NOW(), NULL)"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(&p.display_name)
    .bind(p.price_cents)
    .bind(p.included_devs)
    .bind(p.max_concurrent_ws)
    .bind(p.max_team_members)
    .bind(p.storage_gb)
    .bind(p.is_contact_us)
    .bind(p.is_admin_only)
    .bind(p.included_cpu_hours)
    .bind(p.included_mem_gb_hours)
    .bind(p.included_disk_gb_hours)
    .bind(p.cpu_overage_cents)
    .bind(p.mem_overage_cents)
    .bind(p.disk_overage_cents)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to create billing catalog plan".into()))?;
    Ok(())
}

/// Shared catalog-plan update operation used by BillingCatalogService.
pub async fn update_plan_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    p: &PlanWriteBody,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_plans
           SET display_name = $3,
               price_cents = $4,
               included_devs = $5,
               max_concurrent_ws = $6,
               max_team_members = $7,
               storage_gb = $8,
               is_contact_us = $9,
               is_admin_only = $10,
               included_cpu_hours = $11,
               included_mem_gb_hours = $12,
               included_disk_gb_hours = $13,
               cpu_overage_cents = $14,
               mem_overage_cents = $15,
               disk_overage_cents = $16,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(&p.display_name)
    .bind(p.price_cents)
    .bind(p.included_devs)
    .bind(p.max_concurrent_ws)
    .bind(p.max_team_members)
    .bind(p.storage_gb)
    .bind(p.is_contact_us)
    .bind(p.is_admin_only)
    .bind(p.included_cpu_hours)
    .bind(p.included_mem_gb_hours)
    .bind(p.included_disk_gb_hours)
    .bind(p.cpu_overage_cents)
    .bind(p.mem_overage_cents)
    .bind(p.disk_overage_cents)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to update billing catalog plan".into()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog plan not found".into()));
    }
    Ok(())
}

/// Shared catalog-plan archive operation used by BillingCatalogService.
pub async fn set_plan_archived_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    archived: bool,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_plans
           SET archived_at = CASE WHEN $3 THEN NOW() ELSE NULL END,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(archived)
    .execute(pool)
    .await
    .map_err(|_| {
        AppError::InternalMsg("failed to update billing catalog plan archive state".into())
    })?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog plan not found".into()));
    }
    Ok(())
}

// ── Price create / update / archive + settings ─────────────────────

/// Shared catalog-price create operation used by BillingCatalogService.
pub async fn create_price_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    stripe_price_id: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO billing_catalog_prices
           (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id,
            created_at, updated_at, archived_at)
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), NULL)"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(stripe_price_id)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to create billing catalog price".into()))?;
    Ok(())
}

/// Shared catalog-price update operation used by BillingCatalogService.
pub async fn update_price_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    stripe_price_id: &str,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_prices
           SET stripe_price_id = $5, updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2 AND stripe_mode = $3 AND price_kind = $4"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(stripe_price_id)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to update billing catalog price".into()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog price not found".into()));
    }
    Ok(())
}

/// Shared catalog-price archive operation used by BillingCatalogService.
pub async fn set_price_archived_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    archived: bool,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_prices
           SET archived_at = CASE WHEN $5 THEN NOW() ELSE NULL END,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2 AND stripe_mode = $3 AND price_kind = $4"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(archived)
    .execute(pool)
    .await
    .map_err(|_| {
        AppError::InternalMsg("failed to update billing catalog price archive state".into())
    })?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog price not found".into()));
    }
    Ok(())
}

/// The sign-up credit setting: euro cents a new organization is granted once
/// at creation. 0 is off.
pub const SIGNUP_CREDIT_SETTING: &str = "signup_credit_cents";

/// The largest sign-up credit: EUR 1,000, the largest automatic top-up.
pub const MAX_SIGNUP_CREDIT_CENTS: i32 = 100_000;

/// Shared catalog-setting update operation used by BillingCatalogService.
/// The change and its audit entry, naming the actor and the old and new
/// values, commit together.
pub async fn update_setting_core(
    pool: &PgPool,
    actor_user_id: &str,
    setting_key: &str,
    int_value: i32,
) -> AppResult<()> {
    if setting_key == SIGNUP_CREDIT_SETTING && !(0..=MAX_SIGNUP_CREDIT_CENTS).contains(&int_value) {
        return Err(AppError::BadRequest(
            format!("{SIGNUP_CREDIT_SETTING} must be between 0 and {MAX_SIGNUP_CREDIT_CENTS}")
                .into(),
        ));
    }
    let failed = |_| AppError::InternalMsg("failed to update billing catalog setting".into());
    let mut transaction = pool.begin().await.map_err(failed)?;
    let previous: Option<i32> = sqlx::query_scalar(
        r#"SELECT int_value FROM billing_catalog_settings
           WHERE setting_key = $1
           FOR UPDATE"#,
    )
    .bind(setting_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(failed)?;
    let Some(previous) = previous else {
        return Err(AppError::NotFound(
            "billing catalog setting not found".into(),
        ));
    };
    sqlx::query(
        r#"UPDATE billing_catalog_settings
           SET int_value = $2, updated_at = NOW()
           WHERE setting_key = $1"#,
    )
    .bind(setting_key)
    .bind(int_value)
    .execute(&mut *transaction)
    .await
    .map_err(failed)?;
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), 'admin.billing.catalog.setting_updated', $1,
                   jsonb_build_object('setting_key', $2::text, 'previous_value', $3::int4,
                                      'value', $4::int4),
                   'warn')"#,
    )
    .bind(actor_user_id)
    .bind(setting_key)
    .bind(previous)
    .bind(int_value)
    .execute(&mut *transaction)
    .await
    .map_err(failed)?;
    transaction.commit().await.map_err(failed)?;
    Ok(())
}

// ── Rate cards ──────────────────────────────────────────────────────

/// The card that charges nothing: its rates are all 0 and stay 0.
const UNLIMITED_RATE_CARD: &str = "unlimited";

/// A rate card's four rates, in whole nano-euros per unit-hour
/// (docs/dev/BILLING.md "Prices").
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct RateCardRates {
    pub cpu_nano_eur_per_vcpu_hour: i64,
    pub memory_nano_eur_per_gib_hour: i64,
    pub disk_nano_eur_per_gib_hour: i64,
    /// Per GiB-hour of disk while a Sandbox is suspended or hibernated.
    pub parked_storage_nano_eur_per_gib_hour: i64,
}

impl RateCardRates {
    /// Each rate by its column name, which is also its request field.
    fn named(self) -> [(&'static str, i64); 4] {
        [
            (
                "cpu_nano_eur_per_vcpu_hour",
                self.cpu_nano_eur_per_vcpu_hour,
            ),
            (
                "memory_nano_eur_per_gib_hour",
                self.memory_nano_eur_per_gib_hour,
            ),
            (
                "disk_nano_eur_per_gib_hour",
                self.disk_nano_eur_per_gib_hour,
            ),
            (
                "parked_storage_nano_eur_per_gib_hour",
                self.parked_storage_nano_eur_per_gib_hour,
            ),
        ]
    }
}

/// One rate card as stored.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RateCard {
    pub rate_card: String,
    pub display_name: String,
    #[sqlx(flatten)]
    pub rates: RateCardRates,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Every rate card, by key.
pub async fn list_rate_cards_core(pool: &PgPool) -> AppResult<Vec<RateCard>> {
    sqlx::query_as(
        r#"SELECT rate_card, display_name, cpu_nano_eur_per_vcpu_hour,
                  memory_nano_eur_per_gib_hour, disk_nano_eur_per_gib_hour,
                  parked_storage_nano_eur_per_gib_hour, updated_at
             FROM billing_rate_cards
            ORDER BY rate_card"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to list rate cards".into()))
}

/// Regular's rates, which the public pages show. Regular is chosen by its
/// key, never by its display name, and a missing row is an error, never
/// another card's rates.
pub async fn regular_rates_core<'e>(
    executor: impl sqlx::PgExecutor<'e>,
) -> AppResult<RateCardRates> {
    let rates: Option<RateCardRates> = sqlx::query_as(
        r#"SELECT cpu_nano_eur_per_vcpu_hour, memory_nano_eur_per_gib_hour,
                  disk_nano_eur_per_gib_hour, parked_storage_nano_eur_per_gib_hour
             FROM billing_rate_cards
            WHERE rate_card = 'regular'"#,
    )
    .fetch_optional(executor)
    .await
    .map_err(|_| AppError::InternalMsg("failed to read the regular rates".into()))?;
    rates.ok_or_else(|| AppError::InternalMsg("the regular rate card is missing".into()))
}

/// The most a rate may be: EUR 10 per unit-hour, as the database checks
/// (migration 0046), so a mistyped price can't reprice every organization.
pub const MAX_RATE_NANO_EUR_PER_UNIT_HOUR: i64 = 10_000_000_000;

/// A negative rate, one above [`MAX_RATE_NANO_EUR_PER_UNIT_HOUR`], and any
/// rate above 0 on Unlimited, by request field.
fn rate_card_rate_issues(rate_card: &str, rates: RateCardRates) -> Vec<ValidationIssue> {
    rates
        .named()
        .into_iter()
        .filter_map(|(name, value)| {
            let message = if value < 0 {
                "must not be negative"
            } else if value > MAX_RATE_NANO_EUR_PER_UNIT_HOUR {
                "must be at most 10000000000 (EUR 10 per unit-hour)"
            } else if rate_card == UNLIMITED_RATE_CARD && value != 0 {
                "must be 0: unlimited charges nothing"
            } else {
                return None;
            };
            Some(ValidationIssue {
                path: Cow::Owned(format!("/{name}")),
                message: Cow::Borrowed(message),
            })
        })
        .collect()
}

/// Set one rate card's four rates. A card changed since the caller read it at
/// `expected_updated_at` is refused, so a page acting on a stale read never
/// overwrites a newer price. The change and its audit entry, naming the
/// actor, the card and each changed rate's previous and new value, commit
/// together; metering reads the card inside each draw, so the next draw
/// charges the new rates. Rates equal to the stored ones change nothing.
pub async fn update_rate_card_core(
    pool: &PgPool,
    actor_user_id: &str,
    rate_card: &str,
    rates: RateCardRates,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
) -> AppResult<RateCard> {
    let errors = rate_card_rate_issues(rate_card, rates);
    if !errors.is_empty() {
        return Err(AppError::Validation { errors });
    }
    let failed = |_| AppError::InternalMsg("failed to update the rate card".into());
    let mut transaction = pool.begin().await.map_err(failed)?;
    let previous: Option<RateCard> = sqlx::query_as(
        r#"SELECT rate_card, display_name, cpu_nano_eur_per_vcpu_hour,
                  memory_nano_eur_per_gib_hour, disk_nano_eur_per_gib_hour,
                  parked_storage_nano_eur_per_gib_hour, updated_at
             FROM billing_rate_cards
            WHERE rate_card = $1
              FOR UPDATE"#,
    )
    .bind(rate_card)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(failed)?;
    let Some(previous) = previous else {
        return Err(AppError::NotFound("rate card not found".into()));
    };
    if previous.updated_at != expected_updated_at {
        return Err(AppError::Precondition(
            "the rate card changed since it was read; reload it and try again".into(),
        ));
    }
    let changed: serde_json::Map<String, serde_json::Value> = previous
        .rates
        .named()
        .into_iter()
        .zip(rates.named())
        .filter(|((_, previous), (_, value))| previous != value)
        .map(|((name, previous), (_, value))| {
            (
                name.to_owned(),
                serde_json::json!({ "previous_value": previous, "value": value }),
            )
        })
        .collect();
    if changed.is_empty() {
        return Ok(previous);
    }
    let updated: RateCard = sqlx::query_as(
        r#"UPDATE billing_rate_cards
              SET cpu_nano_eur_per_vcpu_hour = $2, memory_nano_eur_per_gib_hour = $3,
                  disk_nano_eur_per_gib_hour = $4, parked_storage_nano_eur_per_gib_hour = $5,
                  updated_at = NOW()
            WHERE rate_card = $1
        RETURNING rate_card, display_name, cpu_nano_eur_per_vcpu_hour,
                  memory_nano_eur_per_gib_hour, disk_nano_eur_per_gib_hour,
                  parked_storage_nano_eur_per_gib_hour, updated_at"#,
    )
    .bind(rate_card)
    .bind(rates.cpu_nano_eur_per_vcpu_hour)
    .bind(rates.memory_nano_eur_per_gib_hour)
    .bind(rates.disk_nano_eur_per_gib_hour)
    .bind(rates.parked_storage_nano_eur_per_gib_hour)
    .fetch_one(&mut *transaction)
    .await
    .map_err(failed)?;
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), 'admin.billing.rate_card_updated', $1, $2,
                   'warn')"#,
    )
    .bind(actor_user_id)
    .bind(serde_json::json!({ "rate_card": rate_card, "rates": changed }))
    .execute(&mut *transaction)
    .await
    .map_err(failed)?;
    transaction.commit().await.map_err(failed)?;
    Ok(updated)
}

// ── Subscription migrations ─────────────────────────────────────────

/// Migration sample mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationSample {
    pub scope: String,
    pub org_id: String,
    pub org_slug: String,
    pub stripe_subscription_id: String,
    pub status: String,
    pub current_plan_key: String,
    pub current_stripe_price_id: String,
}

impl From<MigrationCandidate> for MigrationSample {
    fn from(c: MigrationCandidate) -> Self {
        MigrationSample {
            scope: c.scope,
            org_id: c.org_id,
            org_slug: c.org_slug,
            stripe_subscription_id: c.stripe_subscription_id,
            status: c.status,
            current_plan_key: c.current_plan_key,
            current_stripe_price_id: c.current_stripe_price_id,
        }
    }
}

/// Migration preview mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationPreviewResponse {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub matching_count: i32,
    pub candidate_count: i32,
    pub already_on_target: i32,
    pub samples: Vec<MigrationSample>,
}

/// Migration run mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationRunResponse {
    pub id: String,
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub proration_behavior: String,
    pub migrated_count: i32,
    pub skipped_count: i32,
    pub failed_count: i32,
    pub created_by: String,
    pub created_at: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct PreviewMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub sample_limit: i32,
}

#[derive(Debug)]
pub struct RunMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub proration_behavior: String,
}

/// Validates the Connect field limit with a protobuf field path.
pub fn validate_connect_migration_limit(limit: i64) -> AppResult<i64> {
    validate_migration_limit_at(limit, "/limit")
}

fn validate_migration_limit_at(limit: i64, path: &'static str) -> AppResult<i64> {
    if limit > 100 {
        return Err(AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed(path),
                message: Cow::Borrowed("expected number <= 100"),
            }],
        });
    }
    Ok(limit)
}

/// Shared subscription-migration preview used by BillingCatalogService.
///
/// The caller supplies the required configured Stripe handle. No missing-Stripe
/// response is part of either product contract.
pub async fn preview_migration_core(
    state: &BillingState,
    body: &PreviewMigrationBody,
) -> AppResult<MigrationPreviewResponse> {
    let preview = subscription_migration::preview(
        &state.pool,
        &state.stripe,
        &body.resource_type,
        &body.source_plan_key,
        &body.target_plan_key,
        body.sample_limit,
    )
    .await?;

    Ok(MigrationPreviewResponse {
        resource_type: preview.resource_type,
        source_plan_key: preview.source_plan_key,
        target_plan_key: preview.target_plan_key,
        target_stripe_price_id: preview.target_stripe_price_id,
        matching_count: preview.matching_count,
        candidate_count: preview.candidate_count,
        already_on_target: preview.already_on_target,
        samples: preview
            .samples
            .into_iter()
            .map(MigrationSample::from)
            .collect(),
    })
}

/// Shared subscription-migration command used by BillingCatalogService.
pub async fn run_migration_core(
    state: &BillingState,
    body: &RunMigrationBody,
    user_id: &str,
) -> AppResult<MigrationRunResponse> {
    let proration_behavior = if body.proration_behavior.is_empty() {
        subscription_migration::PRORATION_NONE.to_string()
    } else {
        body.proration_behavior.clone()
    };

    let result = subscription_migration::run(
        &state.pool,
        &state.stripe,
        &body.resource_type,
        &body.source_plan_key,
        &body.target_plan_key,
        &proration_behavior,
        user_id,
    )
    .await?;

    // created_by on the response is the actor's email (Go uses
    // user.Email); audit log uses user.ID. Look the email up — empty if
    // the row is gone, matching the omitempty behavior.
    let email: String =
        sqlx::query_scalar(r#"SELECT COALESCE(email, '') FROM users WHERE id = $1"#)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_default();

    let ip = String::new();
    let ua = String::new();
    log_audit_event(
        &state.pool,
        "admin.billing.catalog.subscription_migration",
        user_id,
        &ip,
        &ua,
        serde_json::json!({
            "resource_type": result.resource_type,
            "source_plan_key": result.source_plan_key,
            "target_plan_key": result.target_plan_key,
            "target_stripe_price_id": result.target_stripe_price_id,
            "proration_behavior": result.proration_behavior,
            "migrated_count": result.migrated_count,
            "skipped_count": result.skipped_count,
            "failed_count": result.failed_count,
            "migration_id": result.id,
            "failures": result.failures,
        }),
        "warn",
    )
    .await;

    Ok(MigrationRunResponse {
        id: result.id,
        resource_type: result.resource_type,
        source_plan_key: result.source_plan_key,
        target_plan_key: result.target_plan_key,
        target_stripe_price_id: result.target_stripe_price_id,
        proration_behavior: result.proration_behavior,
        migrated_count: result.migrated_count,
        skipped_count: result.skipped_count,
        failed_count: result.failed_count,
        created_by: email,
        created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        metadata: Some(serde_json::json!({ "failures": result.failures })),
    })
}

/// Shared subscription-migration listing used by BillingCatalogService.
pub async fn list_migrations_core(
    pool: &PgPool,
    limit: i64,
) -> AppResult<Vec<MigrationRunResponse>> {
    let rows: Vec<MigrationRunRow> = sqlx::query_as(
        r#"SELECT m.id, m.resource_type, m.source_plan_key, m.target_plan_key,
                  m.target_stripe_price_id, m.proration_behavior,
                  m.migrated_count, m.skipped_count, m.failed_count,
                  COALESCE(u.email, '') AS created_by,
                  COALESCE(m.metadata, '{}'::jsonb) AS metadata,
                  m.created_at
             FROM billing_catalog_subscription_migrations m
             LEFT JOIN users u ON u.id = m.created_by
            ORDER BY m.created_at DESC
            LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to query billing subscription migrations".into()))?;

    let runs: Vec<MigrationRunResponse> = rows
        .into_iter()
        .map(|r| MigrationRunResponse {
            id: r.id,
            resource_type: r.resource_type,
            source_plan_key: r.source_plan_key,
            target_plan_key: r.target_plan_key,
            target_stripe_price_id: r.target_stripe_price_id,
            proration_behavior: r.proration_behavior,
            migrated_count: r.migrated_count,
            skipped_count: r.skipped_count,
            failed_count: r.failed_count,
            created_by: r.created_by,
            created_at: r.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            // Go: only set when the row's metadata is valid JSON; the
            // COALESCE guarantees a value, and '{}' parses fine, so this
            // is always Some — matching Go's `omitempty`-but-present
            // behavior for the persisted `{"failures": …}` blob.
            metadata: Some(r.metadata),
        })
        .collect();

    Ok(runs)
}

#[derive(Debug, sqlx::FromRow)]
struct MigrationRunRow {
    id: String,
    resource_type: String,
    source_plan_key: String,
    target_plan_key: String,
    target_stripe_price_id: String,
    proration_behavior: String,
    migrated_count: i32,
    skipped_count: i32,
    failed_count: i32,
    created_by: String,
    metadata: serde_json::Value,
    // `timestamp without time zone`, stored UTC; formatted with a literal
    // Z to match Go's `createdAt.UTC().Format(time.RFC3339)`.
    created_at: chrono::NaiveDateTime,
}

/// Mirrors `auth.LogAuditEvent`: best-effort insert, errors logged not
/// surfaced. Severity is written verbatim (the run handler passes
/// `"warn"`).
async fn log_audit_event(
    pool: &PgPool,
    action: &str,
    user_id: &str,
    ip_address: &str,
    user_agent: &str,
    metadata: serde_json::Value,
    severity: &str,
) {
    // ID generation mirrors the schema default (gen_random_uuid()::text)
    // — the billing crate keeps no uuid dependency, generating IDs in SQL
    // like the webhook handler does.
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, $4, $5, $6)"#,
    )
    .bind(action)
    .bind(user_id)
    .bind(ip_address)
    .bind(user_agent)
    .bind(&metadata)
    .bind(severity)
    .execute(pool)
    .await
    {
        tracing::error!(action, error = %e, "failed to log audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                eprintln!("DATABASE_URL unset; skipping the billing settings database flow");
                return None;
            }
        };
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect billing settings test database"),
        )
    }

    async fn signup_credit(pool: &PgPool) -> i32 {
        sqlx::query_scalar("SELECT int_value FROM billing_catalog_settings WHERE setting_key = $1")
            .bind(SIGNUP_CREDIT_SETTING)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn db_the_systemd_opt_in_is_audited_and_listed() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix: String = sqlx::query_scalar("SELECT replace(gen_random_uuid()::text, '-', '')")
            .fetch_one(&pool)
            .await
            .unwrap();
        let actor = format!("u_systemd_{suffix}");
        let organization_id = format!("org_systemd_{suffix}");
        let slug = format!("systemd-{suffix}");
        sqlx::query("INSERT INTO users (id, email, name, is_admin) VALUES ($1, $1 || '@example.test', 'Admin', true)")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, 'Systemd', $2, $3)",
        )
        .bind(&organization_id)
        .bind(&slug)
        .bind(&actor)
        .execute(&pool)
        .await
        .unwrap();
        let listed = |pool: PgPool, organization_id: String| async move {
            list_systemd_organizations_core(&pool)
                .await
                .unwrap()
                .iter()
                .any(|organization| organization.organization_id == organization_id)
        };
        assert!(!listed(pool.clone(), organization_id.clone()).await);

        for enabled in [true, false] {
            let organization =
                set_organization_systemd_environments_core(&pool, &actor, &slug, enabled)
                    .await
                    .unwrap();
            assert_eq!(
                organization,
                OrganizationRef {
                    organization_id: organization_id.clone(),
                    slug: slug.clone(),
                    name: "Systemd".into(),
                }
            );
            assert_eq!(listed(pool.clone(), organization_id.clone()).await, enabled);
        }
        let audit: Vec<(String, serde_json::Value, String)> = sqlx::query_as(
            "SELECT action, metadata, severity FROM audit_logs WHERE user_id = $1 ORDER BY timestamp",
        )
        .bind(&actor)
        .fetch_all(&pool)
        .await
        .unwrap();
        let expected = |enabled: bool| {
            (
                "admin.organization.systemd_environments".to_string(),
                serde_json::json!({
                    "organization_id": organization_id,
                    "systemd_environments_enabled": enabled,
                }),
                "warn".to_string(),
            )
        };
        assert_eq!(audit, vec![expected(true), expected(false)]);

        // An unknown organization changes nothing and audits nothing.
        assert!(matches!(
            set_organization_systemd_environments_core(&pool, &actor, "no-such-organization", true)
                .await,
            Err(AppError::NotFound(_))
        ));
        let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE user_id = $1")
            .bind(&actor)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audited, 2);

        sqlx::raw_sql(&format!(
            "DELETE FROM audit_logs WHERE user_id = '{actor}'; \
             DELETE FROM organizations WHERE id = '{organization_id}'; \
             DELETE FROM users WHERE id = '{actor}';"
        ))
        .execute(&pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn db_a_setting_change_is_audited_and_the_signup_credit_is_bounded() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let actor: String = sqlx::query_scalar("SELECT 'u_settings_' || gen_random_uuid()")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, email, name, is_admin) VALUES ($1, $1 || '@example.test', 'Admin', true)")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
        let before = signup_credit(&pool).await;

        update_setting_core(&pool, &actor, SIGNUP_CREDIT_SETTING, 1_000)
            .await
            .unwrap();
        assert_eq!(signup_credit(&pool).await, 1_000);
        let audit: (String, serde_json::Value) =
            sqlx::query_as("SELECT action, metadata FROM audit_logs WHERE user_id = $1")
                .bind(&actor)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audit.0, "admin.billing.catalog.setting_updated");
        assert_eq!(
            audit.1,
            serde_json::json!({
                "setting_key": SIGNUP_CREDIT_SETTING,
                "previous_value": before,
                "value": 1_000,
            })
        );

        // Out of range or unknown: nothing changes and nothing is audited.
        for value in [-1, MAX_SIGNUP_CREDIT_CENTS + 1] {
            assert!(matches!(
                update_setting_core(&pool, &actor, SIGNUP_CREDIT_SETTING, value).await,
                Err(AppError::BadRequest(_))
            ));
        }
        assert!(matches!(
            update_setting_core(&pool, &actor, "no_such_setting", 1).await,
            Err(AppError::NotFound(_))
        ));
        assert_eq!(signup_credit(&pool).await, 1_000);
        let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE user_id = $1")
            .bind(&actor)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audited, 1);

        update_setting_core(&pool, &actor, SIGNUP_CREDIT_SETTING, before)
            .await
            .unwrap();
        sqlx::query("DELETE FROM audit_logs WHERE user_id = $1")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn a_rate_card_refuses_negative_rates_and_any_charge_on_unlimited() {
        let rates = RateCardRates {
            cpu_nano_eur_per_vcpu_hour: 1,
            memory_nano_eur_per_gib_hour: 0,
            disk_nano_eur_per_gib_hour: -1,
            parked_storage_nano_eur_per_gib_hour: 0,
        };
        let issues = |rate_card| {
            rate_card_rate_issues(rate_card, rates)
                .into_iter()
                .map(|issue| (issue.path.into_owned(), issue.message.into_owned()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            issues("discounted"),
            [(
                "/disk_nano_eur_per_gib_hour".to_owned(),
                "must not be negative".to_owned()
            )]
        );
        assert_eq!(
            issues("unlimited"),
            [
                (
                    "/cpu_nano_eur_per_vcpu_hour".to_owned(),
                    "must be 0: unlimited charges nothing".to_owned()
                ),
                (
                    "/disk_nano_eur_per_gib_hour".to_owned(),
                    "must not be negative".to_owned()
                ),
            ]
        );
        let free = RateCardRates {
            cpu_nano_eur_per_vcpu_hour: 0,
            disk_nano_eur_per_gib_hour: 0,
            ..rates
        };
        assert!(rate_card_rate_issues("unlimited", free).is_empty());
    }

    async fn rate_card(pool: &PgPool, rate_card: &str) -> RateCard {
        list_rate_cards_core(pool)
            .await
            .unwrap()
            .into_iter()
            .find(|card| card.rate_card == rate_card)
            .unwrap()
    }

    #[tokio::test]
    async fn db_a_rate_card_change_is_audited_and_a_stale_or_invalid_one_writes_nothing() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let actor: String = sqlx::query_scalar("SELECT 'u_rate_cards_' || gen_random_uuid()")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, email, name, is_admin) VALUES ($1, $1 || '@example.test', 'Admin', true)")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
        let before = rate_card(&pool, "discounted").await;
        let audit = |pool: PgPool, actor: String| async move {
            sqlx::query_as::<_, (String, serde_json::Value, String)>(
                "SELECT action, metadata, severity FROM audit_logs WHERE user_id = $1",
            )
            .bind(&actor)
            .fetch_all(&pool)
            .await
            .unwrap()
        };

        // A change writes all four rates and one audit entry naming each
        // changed rate's previous and new value.
        let rates = RateCardRates {
            cpu_nano_eur_per_vcpu_hour: before.rates.cpu_nano_eur_per_vcpu_hour + 1,
            parked_storage_nano_eur_per_gib_hour: before.rates.parked_storage_nano_eur_per_gib_hour
                + 5,
            ..before.rates
        };
        let updated = update_rate_card_core(&pool, &actor, "discounted", rates, before.updated_at)
            .await
            .unwrap();
        assert_eq!(updated.rates, rates);
        assert!(updated.updated_at > before.updated_at);
        assert_eq!(rate_card(&pool, "discounted").await, updated);
        let changed = vec![(
            "admin.billing.rate_card_updated".to_string(),
            serde_json::json!({
                "rate_card": "discounted",
                "rates": {
                    "cpu_nano_eur_per_vcpu_hour": {
                        "previous_value": before.rates.cpu_nano_eur_per_vcpu_hour,
                        "value": rates.cpu_nano_eur_per_vcpu_hour,
                    },
                    "parked_storage_nano_eur_per_gib_hour": {
                        "previous_value": before.rates.parked_storage_nano_eur_per_gib_hour,
                        "value": rates.parked_storage_nano_eur_per_gib_hour,
                    },
                },
            }),
            "warn".to_string(),
        )];
        assert_eq!(audit(pool.clone(), actor.clone()).await, changed);

        // A stale read, a negative rate, a charging Unlimited and an unknown
        // card change nothing and audit nothing; nor do unchanged rates.
        let unlimited = rate_card(&pool, "unlimited").await;
        assert!(matches!(
            update_rate_card_core(&pool, &actor, "discounted", before.rates, before.updated_at)
                .await,
            Err(AppError::Precondition(_))
        ));
        let negative = RateCardRates {
            memory_nano_eur_per_gib_hour: -1,
            ..rates
        };
        assert!(matches!(
            update_rate_card_core(&pool, &actor, "discounted", negative, updated.updated_at).await,
            Err(AppError::Validation { .. })
        ));
        // A rate past the bound, such as a price typed with extra zeros, is
        // refused here, and the database refuses it too.
        let excessive = RateCardRates {
            cpu_nano_eur_per_vcpu_hour: MAX_RATE_NANO_EUR_PER_UNIT_HOUR + 1,
            ..rates
        };
        assert!(matches!(
            update_rate_card_core(&pool, &actor, "discounted", excessive, updated.updated_at).await,
            Err(AppError::Validation { .. })
        ));
        assert!(
            sqlx::query(
                "UPDATE billing_rate_cards SET cpu_nano_eur_per_vcpu_hour = $1 \
                  WHERE rate_card = 'discounted'"
            )
            .bind(MAX_RATE_NANO_EUR_PER_UNIT_HOUR + 1)
            .execute(&pool)
            .await
            .is_err()
        );
        let charging = RateCardRates {
            parked_storage_nano_eur_per_gib_hour: 1,
            ..unlimited.rates
        };
        assert!(matches!(
            update_rate_card_core(&pool, &actor, "unlimited", charging, unlimited.updated_at).await,
            Err(AppError::Validation { .. })
        ));
        assert!(matches!(
            update_rate_card_core(&pool, &actor, "gold", rates, updated.updated_at).await,
            Err(AppError::NotFound(_))
        ));
        assert_eq!(
            update_rate_card_core(&pool, &actor, "discounted", rates, updated.updated_at)
                .await
                .unwrap(),
            updated
        );
        assert_eq!(rate_card(&pool, "discounted").await, updated);
        assert_eq!(rate_card(&pool, "unlimited").await, unlimited);
        assert_eq!(audit(pool.clone(), actor.clone()).await, changed);

        update_rate_card_core(
            &pool,
            &actor,
            "discounted",
            before.rates,
            updated.updated_at,
        )
        .await
        .unwrap();
        sqlx::query("DELETE FROM audit_logs WHERE user_id = $1")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&actor)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn db_the_public_rates_are_regulars_and_never_another_cards() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let cards = list_rate_cards_core(&pool).await.unwrap();
        let rates = |key: &str| {
            cards
                .iter()
                .find(|card| card.rate_card == key)
                .unwrap()
                .rates
        };
        assert_eq!(regular_rates_core(&pool).await.unwrap(), rates("regular"));
        assert_ne!(rates("regular"), rates("discounted"));

        // Every change below is rolled back, so no other test sees it.
        let mut transaction = pool.begin().await.unwrap();
        let changed = RateCardRates {
            cpu_nano_eur_per_vcpu_hour: 1,
            memory_nano_eur_per_gib_hour: 2,
            disk_nano_eur_per_gib_hour: 3,
            parked_storage_nano_eur_per_gib_hour: 4,
        };
        sqlx::query(
            "UPDATE billing_rate_cards SET cpu_nano_eur_per_vcpu_hour = $1, \
                    memory_nano_eur_per_gib_hour = $2, disk_nano_eur_per_gib_hour = $3, \
                    parked_storage_nano_eur_per_gib_hour = $4 \
              WHERE rate_card = 'regular'",
        )
        .bind(changed.cpu_nano_eur_per_vcpu_hour)
        .bind(changed.memory_nano_eur_per_gib_hour)
        .bind(changed.disk_nano_eur_per_gib_hour)
        .bind(changed.parked_storage_nano_eur_per_gib_hour)
        .execute(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(
            regular_rates_core(&mut *transaction).await.unwrap(),
            changed
        );

        // Organizations and ledger rows may name Regular, so its row can't
        // always be deleted. A temporary copy of the cards without it
        // shadows the table for this transaction alone.
        sqlx::query(
            "CREATE TEMPORARY TABLE billing_rate_cards ON COMMIT DROP AS \
             SELECT * FROM public.billing_rate_cards WHERE rate_card <> 'regular'",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM billing_rate_cards")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(remaining, 2);
        assert!(matches!(
            regular_rates_core(&mut *transaction).await,
            Err(AppError::InternalMsg(_))
        ));
        transaction.rollback().await.unwrap();

        assert_eq!(regular_rates_core(&pool).await.unwrap(), rates("regular"));
    }
}
