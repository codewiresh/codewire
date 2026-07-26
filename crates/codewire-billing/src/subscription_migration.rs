//! Subscription-migration engine.
//!
//! Moves org environment subscriptions from a source plan key to a target plan
//! key: validates the plan pair against the catalog, enumerates the
//! matching `environment_subscriptions`, and (for `run`) swaps each
//! live Stripe subscription item's price and updates the local row.
//!
//! Wire-shape parity lives in `catalog_admin.rs`; this module is the
//! reusable logic the preview/run handlers call. Validation order is observable
//! through the 400 error detail and therefore part of the current contract:
//!
//! 1. `bc == nil` → "billing is disabled" (the handler checks this
//!    first, before calling in here).
//! 2. `resource_type != "org"` → only org subscriptions supported.
//! 3. unknown source plan → "unknown source plan …".
//! 4. no current Stripe price for target → "no current Stripe price …".
//! 5. archived target plan → "target plan … is archived".

use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::metering::log_billing_event;
use crate::stripe_client::StripeHandle;

pub const PRORATION_NONE: &str = "none";
pub const PRORATION_CREATE_PRORATIONS: &str = "create_prorations";
pub const PRORATION_ALWAYS_INVOICE: &str = "always_invoice";

pub fn valid_proration_behavior(value: &str) -> bool {
    matches!(
        value,
        PRORATION_NONE | PRORATION_CREATE_PRORATIONS | PRORATION_ALWAYS_INVOICE
    )
}

#[derive(Debug, Clone)]
pub struct MigrationCandidate {
    pub scope: String,
    pub org_id: String,
    pub org_slug: String,
    pub stripe_subscription_id: String,
    pub status: String,
    pub current_plan_key: String,
    pub current_stripe_price_id: String,
}

#[derive(Debug, Default)]
pub struct MigrationPreview {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub matching_count: i32,
    pub candidate_count: i32,
    pub already_on_target: i32,
    pub samples: Vec<MigrationCandidate>,
}

#[derive(Debug, Default)]
pub struct MigrationResult {
    pub id: String,
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub proration_behavior: String,
    pub migrated_count: i32,
    pub skipped_count: i32,
    pub failed_count: i32,
    pub failures: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// Mirrors `BillingClient.validateSubscriptionMigration`. Returns the
/// target plan's current Stripe price ID for the active mode.
async fn validate(
    pool: &PgPool,
    stripe: &StripeHandle,
    resource_type: &str,
    source_plan_key: &str,
    target_plan_key: &str,
) -> Result<String, AppError> {
    if resource_type != "org" {
        return Err(AppError::BadRequest(
            "only organization environment subscriptions are supported".into(),
        ));
    }

    // GetOrgPlan(source) existence + GetOrgPlan(target).Archived — the
    // catalog is canonical, so read both from billing_catalog_plans.
    let source_exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM billing_catalog_plans
               WHERE resource_type = 'org' AND plan_key = $1
           )"#,
    )
    .bind(source_plan_key)
    .fetch_one(pool)
    .await?;

    let target_archived: Option<bool> = sqlx::query_scalar(
        r#"SELECT archived_at IS NOT NULL
           FROM billing_catalog_plans
           WHERE resource_type = 'org' AND plan_key = $1"#,
    )
    .bind(target_plan_key)
    .fetch_optional(pool)
    .await?;

    // bc.PlanPriceIDs[target]: the org subscription price for the current
    // stripe mode (mirrors billing.PriceIDs → orgPlanPriceIDs[mode]).
    let target_price_id: Option<String> = sqlx::query_scalar(
        r#"SELECT stripe_price_id FROM billing_catalog_prices
           WHERE resource_type = 'org' AND plan_key = $1 AND stripe_mode = $2
             AND price_kind = 'subscription' AND archived_at IS NULL
           LIMIT 1"#,
    )
    .bind(target_plan_key)
    .bind(stripe.stripe_mode())
    .fetch_optional(pool)
    .await?;
    let target_price_id = target_price_id.unwrap_or_default();

    if !source_exists {
        return Err(AppError::BadRequest(
            format!("unknown source plan {source_plan_key} for {resource_type}").into(),
        ));
    }
    if target_price_id.is_empty() {
        return Err(AppError::BadRequest(
            format!(
                "no current Stripe price configured for target plan {resource_type}/{target_plan_key}"
            )
            .into(),
        ));
    }
    if target_archived.unwrap_or(false) {
        return Err(AppError::BadRequest(
            format!("target plan {resource_type}/{target_plan_key} is archived").into(),
        ));
    }
    Ok(target_price_id)
}

/// Mirrors `loadSubscriptionMigrationCandidates`.
async fn load_candidates(
    pool: &PgPool,
    resource_type: &str,
    source_plan_key: &str,
) -> Result<Vec<MigrationCandidate>, AppError> {
    if resource_type != "org" {
        return Err(AppError::BadRequest(
            "only organization environment subscriptions are supported".into(),
        ));
    }
    let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        r#"SELECT es.org_id, o.slug, es.stripe_subscription_id, es.status, es.plan,
                  COALESCE(es.stripe_price_id, '')
           FROM environment_subscriptions es
           JOIN organizations o ON o.id = es.org_id
           WHERE es.plan = $1
             AND es.status IN ('active', 'trialing', 'past_due')
             AND es.stripe_subscription_id IS NOT NULL
           ORDER BY o.slug ASC"#,
    )
    .bind(source_plan_key)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(org_id, org_slug, stripe_subscription_id, status, plan, current_price)| {
                MigrationCandidate {
                    scope: "environment".to_string(),
                    org_id,
                    org_slug,
                    stripe_subscription_id,
                    status,
                    current_plan_key: plan,
                    current_stripe_price_id: current_price,
                }
            },
        )
        .collect())
}

/// Mirrors `subscriptionCandidateNeedsMigration`.
fn needs_migration(c: &MigrationCandidate, target_plan_key: &str, target_price_id: &str) -> bool {
    if c.current_plan_key != target_plan_key {
        return true;
    }
    if target_price_id.is_empty() {
        return false;
    }
    c.current_stripe_price_id.trim() != target_price_id.trim()
}

/// Port of `PreviewSubscriptionMigration`.
pub async fn preview(
    pool: &PgPool,
    stripe: &StripeHandle,
    resource_type: &str,
    source_plan_key: &str,
    target_plan_key: &str,
    sample_limit: i32,
) -> Result<MigrationPreview, AppError> {
    let target_price_id = validate(
        pool,
        stripe,
        resource_type,
        source_plan_key,
        target_plan_key,
    )
    .await?;
    let candidates = load_candidates(pool, resource_type, source_plan_key).await?;

    let mut p = MigrationPreview {
        resource_type: resource_type.to_string(),
        source_plan_key: source_plan_key.to_string(),
        target_plan_key: target_plan_key.to_string(),
        target_stripe_price_id: target_price_id.clone(),
        matching_count: candidates.len() as i32,
        ..Default::default()
    };

    let sample_limit = if sample_limit <= 0 { 10 } else { sample_limit } as usize;

    for candidate in candidates {
        if needs_migration(&candidate, target_plan_key, &target_price_id) {
            p.candidate_count += 1;
            if p.samples.len() < sample_limit {
                p.samples.push(candidate);
            }
            continue;
        }
        p.already_on_target += 1;
    }

    Ok(p)
}

/// Port of `RunSubscriptionMigration`.
pub async fn run(
    pool: &PgPool,
    stripe: &StripeHandle,
    resource_type: &str,
    source_plan_key: &str,
    target_plan_key: &str,
    proration_behavior: &str,
    created_by: &str,
) -> Result<MigrationResult, AppError> {
    let target_price_id = validate(
        pool,
        stripe,
        resource_type,
        source_plan_key,
        target_plan_key,
    )
    .await?;
    if !valid_proration_behavior(proration_behavior) {
        return Err(AppError::BadRequest(
            format!("unsupported proration behavior \"{proration_behavior}\"").into(),
        ));
    }

    let candidates = load_candidates(pool, resource_type, source_plan_key).await?;

    let mut result = MigrationResult {
        resource_type: resource_type.to_string(),
        source_plan_key: source_plan_key.to_string(),
        target_plan_key: target_plan_key.to_string(),
        target_stripe_price_id: target_price_id.clone(),
        proration_behavior: proration_behavior.to_string(),
        ..Default::default()
    };

    for candidate in &candidates {
        if !needs_migration(candidate, target_plan_key, &target_price_id) {
            result.skipped_count += 1;
            continue;
        }

        let sub = match stripe
            .retrieve_subscription(&candidate.stripe_subscription_id)
            .await
        {
            Ok(sub) => sub,
            Err(e) => {
                result.failed_count += 1;
                push_failure(
                    &mut result,
                    &candidate.stripe_subscription_id,
                    &format!("load subscription: {e}"),
                );
                continue;
            }
        };

        let item = match resolve_item(&sub, &candidate.current_stripe_price_id) {
            Ok(item) => item,
            Err(msg) => {
                result.failed_count += 1;
                push_failure(&mut result, &candidate.stripe_subscription_id, &msg);
                continue;
            }
        };

        let quantity = item.quantity.unwrap_or(0);
        let idempotency_key = subscription_migration_idempotency_key(
            item.id.as_str(),
            &target_price_id,
            proration_behavior,
            quantity,
        );
        let mutation = run_organization_billing_mutation(pool, &candidate.org_id, async {
            stripe
                .update_subscription_item(
                    item.id.as_str(),
                    &target_price_id,
                    proration_behavior,
                    quantity,
                    &idempotency_key,
                )
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)?;
            apply_local_row(pool, candidate, target_plan_key, &target_price_id)
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await;
        if let Err(e) = mutation {
            result.failed_count += 1;
            push_failure(
                &mut result,
                &candidate.stripe_subscription_id,
                &format!("update subscription item: {e}"),
            );
            continue;
        }

        log_billing_event(
            pool,
            "subscription_migrated",
            &candidate.org_id,
            None,
            "usd",
            &candidate.stripe_subscription_id,
            Some(serde_json::json!({
                "resource_type": resource_type,
                "subscription_scope": candidate.scope,
                "source_plan_key": source_plan_key,
                "target_plan_key": target_plan_key,
                "target_stripe_price_id": target_price_id,
                "proration_behavior": proration_behavior,
            })),
        )
        .await;
        result.migrated_count += 1;
    }

    let metadata = serde_json::json!({ "failures": result.failures });
    let id: String = sqlx::query_scalar(
        r#"INSERT INTO billing_catalog_subscription_migrations
           (resource_type, source_plan_key, target_plan_key, target_stripe_price_id,
            proration_behavior, migrated_count, skipped_count, failed_count, created_by, metadata, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, NOW())
           RETURNING id"#,
    )
    .bind(&result.resource_type)
    .bind(&result.source_plan_key)
    .bind(&result.target_plan_key)
    .bind(&result.target_stripe_price_id)
    .bind(&result.proration_behavior)
    .bind(result.migrated_count)
    .bind(result.skipped_count)
    .bind(result.failed_count)
    .bind(created_by)
    .bind(&metadata)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("insert subscription migration record: {e}")))?;
    result.id = id;

    Ok(result)
}

fn subscription_migration_idempotency_key(
    item_id: &str,
    target_price_id: &str,
    proration_behavior: &str,
    quantity: u64,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        item_id,
        target_price_id,
        proration_behavior,
        &quantity.to_string(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("cw-subscription-migration-{:x}", hasher.finalize())
}

fn push_failure(result: &mut MigrationResult, subscription_id: &str, message: &str) {
    let mut m = serde_json::Map::new();
    m.insert(
        "stripe_subscription_id".to_string(),
        serde_json::Value::String(subscription_id.to_string()),
    );
    m.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    result.failures.push(m);
}

/// Mirrors `resolveSubscriptionMigrationItem`.
fn resolve_item<'a>(
    sub: &'a stripe_shared::Subscription,
    current_price_id: &str,
) -> Result<&'a stripe_shared::SubscriptionItem, String> {
    let items = &sub.items.data;
    if items.is_empty() {
        return Err("subscription has no items".to_string());
    }
    if !current_price_id.is_empty()
        && let Some(item) = items
            .iter()
            .find(|item| item.price.id.as_str() == current_price_id)
    {
        return Ok(item);
    }
    if items.len() == 1 {
        return Ok(&items[0]);
    }
    Err("could not identify base subscription item".to_string())
}

/// Mirrors `applySubscriptionMigrationRow`.
async fn apply_local_row(
    pool: &PgPool,
    candidate: &MigrationCandidate,
    target_plan_key: &str,
    target_price_id: &str,
) -> Result<(), AppError> {
    if candidate.scope == "environment" {
        sqlx::query(
            r#"UPDATE environment_subscriptions
               SET plan = $2, stripe_price_id = $3, updated_at = NOW()
               WHERE org_id = $1"#,
        )
        .bind(&candidate.org_id)
        .bind(target_plan_key)
        .bind(target_price_id)
        .execute(pool)
        .await?;
        return Ok(());
    }
    Err(AppError::Internal(anyhow::anyhow!(
        "unsupported subscription migration scope \"{}\"",
        candidate.scope
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(plan: &str, price: &str) -> MigrationCandidate {
        MigrationCandidate {
            scope: "environment".into(),
            org_id: "org_1".into(),
            org_slug: "acme".into(),
            stripe_subscription_id: "sub_1".into(),
            status: "active".into(),
            current_plan_key: plan.into(),
            current_stripe_price_id: price.into(),
        }
    }

    #[test]
    fn valid_proration_matches_go_constants() {
        assert!(valid_proration_behavior("none"));
        assert!(valid_proration_behavior("create_prorations"));
        assert!(valid_proration_behavior("always_invoice"));
        assert!(!valid_proration_behavior(""));
        assert!(!valid_proration_behavior("bogus"));
    }

    #[test]
    fn needs_migration_mirrors_go() {
        // Different plan key → always needs migration.
        assert!(needs_migration(
            &candidate("starter", "price_a"),
            "pro",
            "price_b"
        ));
        // Same plan, no target price → no migration.
        assert!(!needs_migration(&candidate("pro", "price_a"), "pro", ""));
        // Same plan, same price (trimmed) → no migration.
        assert!(!needs_migration(
            &candidate("pro", " price_b "),
            "pro",
            "price_b"
        ));
        // Same plan, different price → needs migration.
        assert!(needs_migration(
            &candidate("pro", "price_a"),
            "pro",
            "price_b"
        ));
    }
}
