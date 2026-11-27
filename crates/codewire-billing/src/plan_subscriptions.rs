//! Monthly USD billing plan subscriptions, automatic Stripe Product/Price
//! provisioning, synchronous Checkout reconciliation, plan switching, and
//! per-cycle compute allowance grants (#6659).

use chrono::{DateTime, NaiveDateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use crate::checkout_sessions::{
    billing_idempotency_key, org_identity, require_billing_admin, require_org_billing_admin,
};
use crate::routes::BillingState;
use crate::stripe_client::{
    PLAN_SUBSCRIPTION_KIND, PlanCheckout, StripeHandle, SubscriptionPlanUpdate,
};

/// One row from `billing_plan_definitions`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlanDefinition {
    pub plan_key: String,
    pub display_name: String,
    pub monthly_price_cents: i32,
    pub included_compute_nano_usd: i64,
    pub max_concurrent_sandboxes: Option<i32>,
    pub max_vcpu: i32,
    pub max_memory_gib: i32,
    pub max_disk_gib: i32,
    pub max_team_members: Option<i32>,
    pub stripe_price_id_test: Option<String>,
    pub stripe_price_id_live: Option<String>,
}

/// Active monthly allowance state for an organization's current billing cycle.
#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct ActivePlanAllowance {
    pub granted_nano_usd: i64,
    pub drawn_nano_usd: i64,
    pub period_end: Option<DateTime<Utc>>,
}

impl ActivePlanAllowance {
    pub fn remaining_nano_usd(&self) -> i64 {
        (self.granted_nano_usd - self.drawn_nano_usd).max(0)
    }
}

/// Outcome of `ReconcilePlanCheckoutSession`.
#[derive(Debug, Clone)]
pub struct ReconciledPlan {
    pub plan: String,
    pub status: String,
    pub current_period_end: Option<DateTime<Utc>>,
    pub allowance_granted_nano_usd: i64,
}

/// Outcome of `SwitchOrganizationPlan`.
#[derive(Debug, Clone)]
pub struct SwitchedPlan {
    pub plan: String,
    pub status: String,
    pub checkout_url: String,
    pub cancel_at_period_end: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct CurrentOrgSubRow {
    plan: String,
    status: String,
    stripe_subscription_id: Option<String>,
    cancel_at_period_end: bool,
    updated_at: NaiveDateTime,
}

pub async fn lookup_plan_definition(
    pool: &PgPool,
    plan_key: &str,
) -> AppResult<Option<PlanDefinition>> {
    Ok(sqlx::query_as::<_, PlanDefinition>(
        r#"SELECT plan_key, display_name, monthly_price_cents, included_compute_nano_usd,
                  max_concurrent_sandboxes, max_vcpu, max_memory_gib, max_disk_gib,
                  max_team_members, stripe_price_id_test, stripe_price_id_live
           FROM billing_plan_definitions
           WHERE plan_key = $1"#,
    )
    .bind(plan_key)
    .fetch_optional(pool)
    .await?)
}

pub async fn lookup_plan_by_stripe_price(
    pool: &PgPool,
    price_id: &str,
) -> AppResult<Option<PlanDefinition>> {
    Ok(sqlx::query_as::<_, PlanDefinition>(
        r#"SELECT plan_key, display_name, monthly_price_cents, included_compute_nano_usd,
                  max_concurrent_sandboxes, max_vcpu, max_memory_gib, max_disk_gib,
                  max_team_members, stripe_price_id_test, stripe_price_id_live
           FROM billing_plan_definitions
           WHERE stripe_price_id_test = $1 OR stripe_price_id_live = $1
           LIMIT 1"#,
    )
    .bind(price_id)
    .fetch_optional(pool)
    .await?)
}

/// Returns the current cycle's active allowance (or zeros when none is active).
pub async fn active_allowance(pool: &PgPool, org_id: &str) -> AppResult<ActivePlanAllowance> {
    let row: Option<(i64, i64, DateTime<Utc>)> = sqlx::query_as(
        r#"SELECT granted_nano_usd, drawn_nano_usd, period_end
           FROM billing_plan_allowances
           WHERE organization_id = $1
             AND period_start <= now()
             AND period_end > now()
           ORDER BY period_end DESC, id DESC
           LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((granted_nano_usd, drawn_nano_usd, period_end)) => ActivePlanAllowance {
            granted_nano_usd,
            drawn_nano_usd,
            period_end: Some(period_end),
        },
        None => ActivePlanAllowance::default(),
    })
}

/// Ensures a Stripe recurring monthly USD Price ID exists for `plan` in the
/// active Stripe mode (test or live), caching it in `billing_plan_definitions`.
pub async fn ensure_stripe_price_id(
    pool: &PgPool,
    stripe: &StripeHandle,
    plan: &PlanDefinition,
) -> AppResult<String> {
    if plan.monthly_price_cents <= 0 {
        return Err(AppError::BadRequest(
            "payg does not use a recurring Stripe price".into(),
        ));
    }
    let existing = if stripe.is_live() {
        plan.stripe_price_id_live.as_deref()
    } else {
        plan.stripe_price_id_test.as_deref()
    };
    if let Some(price_id) = existing.filter(|id| !id.is_empty()) {
        return Ok(price_id.to_owned());
    }

    let product_id = stripe
        .ensure_plan_product(&plan.plan_key, &plan.display_name)
        .await?;
    let price_id = stripe
        .ensure_plan_price(&product_id, &plan.plan_key, plan.monthly_price_cents)
        .await?;

    let update_sql = if stripe.is_live() {
        "UPDATE billing_plan_definitions
            SET stripe_price_id_live = COALESCE(NULLIF(stripe_price_id_live, ''), $2),
                updated_at = now()
          WHERE plan_key = $1
          RETURNING stripe_price_id_live"
    } else {
        "UPDATE billing_plan_definitions
            SET stripe_price_id_test = COALESCE(NULLIF(stripe_price_id_test, ''), $2),
                updated_at = now()
          WHERE plan_key = $1
          RETURNING stripe_price_id_test"
    };
    let stored: Option<Option<String>> = sqlx::query_scalar(update_sql)
        .bind(&plan.plan_key)
        .bind(&price_id)
        .fetch_optional(pool)
        .await?;
    Ok(stored.flatten().unwrap_or(price_id))
}

/// Opens a Stripe Checkout session in `subscription` mode for `pro` or `max`.
pub async fn create_plan_checkout(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    plan_key: &str,
    success_url: &str,
    cancel_url: &str,
) -> AppResult<String> {
    require_billing_admin(state, user, org_id).await?;
    if !matches!(plan_key, "pro" | "max") {
        return Err(AppError::BadRequest(
            "plan must be \"pro\" or \"max\"".into(),
        ));
    }
    state
        .frontend_origin
        .validate_redirect("success_url", success_url)?;
    state
        .frontend_origin
        .validate_redirect("cancel_url", cancel_url)?;

    let plan = lookup_plan_definition(&state.pool, plan_key)
        .await?
        .ok_or_else(|| AppError::NotFound("plan not found".into()))?;
    let (org_name, owner_email) = org_identity(&state.pool, org_id).await?;
    let customer_key = billing_idempotency_key("customer", &[org_id]);
    let customer_id = run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .ensure_customer(&state.pool, org_id, &org_name, &owner_email, &customer_key)
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;

    let price_id = ensure_stripe_price_id(&state.pool, &state.stripe, &plan).await?;
    let checkout_url = run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .create_plan_checkout_session(&PlanCheckout {
                customer_id: &customer_id,
                organization_id: org_id,
                plan_key,
                price_id: &price_id,
                success_url,
                cancel_url,
            })
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;
    Ok(checkout_url)
}

/// Verifies that `stripe_customer_id` is the customer bound to `org_id`.
pub(crate) async fn org_owns_stripe_customer(
    pool: &PgPool,
    org_id: &str,
    stripe_customer_id: &str,
) -> AppResult<bool> {
    if org_id.is_empty() || stripe_customer_id.is_empty() {
        return Ok(false);
    }
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1 AND stripe_customer_id = $2)",
    )
    .bind(org_id)
    .bind(stripe_customer_id)
    .fetch_one(pool)
    .await?)
}

fn expandable_customer_id(customer: &stripe_types::Expandable<stripe_shared::Customer>) -> String {
    match customer {
        stripe_types::Expandable::Id(id) => id.to_string(),
        stripe_types::Expandable::Object(c) => c.id.to_string(),
    }
}

/// Synchronizes an organization's subscription immediately when Stripe
/// Checkout redirects back, before waiting for webhook delivery.
pub async fn reconcile_plan_checkout(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    session_id: &str,
) -> AppResult<ReconciledPlan> {
    if !state.stripe.is_configured() {
        return Err(AppError::NotFound("billing is not enabled".into()));
    }
    require_org_billing_admin(&state.pool, user, org_id).await?;
    if session_id.trim().is_empty() {
        return Err(AppError::BadRequest("session_id is required".into()));
    }

    let session = state.stripe.retrieve_checkout_session(session_id).await?;
    if session.mode != stripe_shared::CheckoutSessionMode::Subscription {
        return Err(AppError::BadRequest(
            "checkout session is not a subscription session".into(),
        ));
    }
    if session.status != Some(stripe_shared::CheckoutSessionStatus::Complete) {
        return Err(AppError::Precondition(
            "checkout session is not complete".into(),
        ));
    }
    let metadata = session.metadata.as_ref();
    let meta_org = metadata.and_then(|m| m.get("org_id")).map(String::as_str);
    let meta_kind = metadata.and_then(|m| m.get("kind")).map(String::as_str);
    if meta_org != Some(org_id) || meta_kind != Some(PLAN_SUBSCRIPTION_KIND) {
        return Err(AppError::Forbidden);
    }
    let Some(customer_id) = session.customer.as_ref().map(expandable_customer_id) else {
        return Err(AppError::Forbidden);
    };
    if !org_owns_stripe_customer(&state.pool, org_id, &customer_id).await? {
        return Err(AppError::Forbidden);
    }

    let Some(sub_ref) = session.subscription.as_ref() else {
        return Err(AppError::Precondition(
            "checkout session has not created a subscription yet".into(),
        ));
    };
    let sub_id = match sub_ref {
        stripe_types::Expandable::Id(id) => id.to_string(),
        stripe_types::Expandable::Object(sub) => sub.id.to_string(),
    };
    let subscription = state.stripe.retrieve_subscription(&sub_id).await?;
    if expandable_customer_id(&subscription.customer) != customer_id {
        return Err(AppError::Forbidden);
    }
    let synced = sync_subscription_state(&state.pool, org_id, &subscription, None, None)
        .await?
        .ok_or_else(|| {
            AppError::Precondition("subscription price does not match a known billing plan".into())
        })?;

    let mut granted = 0_i64;
    if session.payment_status == stripe_shared::CheckoutSessionPaymentStatus::Paid
        && let Some(invoice_id) = subscription
            .latest_invoice
            .as_ref()
            .and_then(|inv| match inv {
                stripe_types::Expandable::Id(id) => id.as_ref().map(ToString::to_string),
                stripe_types::Expandable::Object(inv) => inv.id.as_ref().map(ToString::to_string),
            })
        && let Some((period_start, period_end)) = subscription_period(&subscription)
        && let Some(def) = lookup_plan_definition(&state.pool, &synced.plan).await?
        && def.included_compute_nano_usd > 0
        && grant_cycle_allowance(
            &state.pool,
            org_id,
            &def.plan_key,
            period_start,
            period_end,
            def.included_compute_nano_usd,
            &invoice_id,
        )
        .await?
    {
        granted = def.included_compute_nano_usd;
    }

    Ok(ReconciledPlan {
        plan: synced.plan,
        status: synced.status,
        current_period_end: synced.current_period_end,
        allowance_granted_nano_usd: granted,
    })
}

/// Activates the Pay as you go ($0/mo) plan once the organization has a
/// default saved payment method (or immediately when billing is unconfigured).
/// Refuses when an existing non-canceled paid Stripe subscription is attached
/// so callers use `SwitchOrganizationPlan` instead of orphaning it.
pub async fn activate_payg_plan(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<(String, String)> {
    require_org_billing_admin(&state.pool, user, org_id).await?;
    if state.stripe.is_configured()
        && !state
            .stripe
            .org_has_payment_method(&state.pool, org_id)
            .await
    {
        return Err(AppError::Precondition(
            "a saved payment method is required to activate Pay as you go".into(),
        ));
    }

    run_organization_billing_mutation(&state.pool, org_id, async {
        activate_payg_plan_db(&state.pool, org_id)
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;

    Ok(("payg".to_owned(), "active".to_owned()))
}

async fn activate_payg_plan_db(pool: &PgPool, org_id: &str) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    let existing: Option<(String, Option<String>)> = sqlx::query_as(
        r#"SELECT status, stripe_subscription_id
           FROM org_subscriptions
           WHERE org_id = $1
           FOR UPDATE"#,
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((status, Some(sub_id))) = existing
        && !sub_id.is_empty()
        && !matches!(status.as_str(), "canceled" | "incomplete_expired")
    {
        return Err(AppError::Precondition(
            "organization already has a paid subscription; switch to Pay as you go via SwitchOrganizationPlan"
                .into(),
        ));
    }

    sqlx::query(
        r#"INSERT INTO org_subscriptions (org_id, plan, status, stripe_subscription_id,
                                          cancel_at_period_end, updated_at)
           VALUES ($1, 'payg', 'active', NULL, false, NOW())
           ON CONFLICT (org_id) DO UPDATE SET
               plan = 'payg',
               status = 'active',
               stripe_subscription_id = NULL,
               cancel_at_period_end = false,
               current_period_start = NULL,
               current_period_end = NULL,
               updated_at = NOW()"#,
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"UPDATE organizations
           SET billing_plan = 'payg', billing_status = 'active', updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Switches an organization between `payg`, `pro`, and `max`.
pub async fn switch_organization_plan(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    target_plan: &str,
    success_url: &str,
    cancel_url: &str,
) -> AppResult<SwitchedPlan> {
    require_billing_admin(state, user, org_id).await?;
    if !matches!(target_plan, "payg" | "pro" | "max") {
        return Err(AppError::BadRequest(
            "plan must be \"payg\", \"pro\", or \"max\"".into(),
        ));
    }

    let current: Option<CurrentOrgSubRow> = sqlx::query_as(
        r#"SELECT plan, status, stripe_subscription_id, cancel_at_period_end, updated_at
           FROM org_subscriptions
           WHERE org_id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?;

    let transition_tag = current
        .as_ref()
        .map(|row| {
            format!(
                "{}:{}:{}:{}",
                row.plan,
                row.status,
                row.cancel_at_period_end,
                row.updated_at.and_utc().timestamp_micros(),
            )
        })
        .unwrap_or_else(|| "none".to_owned());

    let active_sub_id = current.as_ref().and_then(|row| {
        matches!(row.status.as_str(), "active" | "trialing" | "past_due")
            .then_some(row.stripe_subscription_id.as_deref())
            .flatten()
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
    });

    if target_plan == "payg" {
        if let Some(sub_id) = active_sub_id {
            let subscription = state.stripe.retrieve_subscription(&sub_id).await?;
            let updated = if subscription.cancel_at_period_end {
                subscription
            } else {
                let key = billing_idempotency_key(
                    "sub-cancel-period-end",
                    &[org_id, &sub_id, &transition_tag],
                );
                run_organization_billing_mutation(&state.pool, org_id, async {
                    state
                        .stripe
                        .set_subscription_cancel_at_period_end(&sub_id, true, &key)
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await?
            };
            let synced = sync_subscription_state(&state.pool, org_id, &updated, None, None)
                .await?
                .ok_or_else(|| {
                    AppError::Precondition(
                        "subscription price does not match a known billing plan".into(),
                    )
                })?;
            return Ok(SwitchedPlan {
                plan: synced.plan,
                status: synced.status,
                checkout_url: String::new(),
                cancel_at_period_end: updated.cancel_at_period_end,
            });
        }
        let (plan, status) = activate_payg_plan(state, user, org_id).await?;
        return Ok(SwitchedPlan {
            plan,
            status,
            checkout_url: String::new(),
            cancel_at_period_end: false,
        });
    }

    // Target is pro or max.
    let Some(sub_id) = active_sub_id else {
        let checkout_url =
            create_plan_checkout(state, user, org_id, target_plan, success_url, cancel_url).await?;
        return Ok(SwitchedPlan {
            plan: current.map(|c| c.plan).unwrap_or_else(|| "none".to_owned()),
            status: "checkout_required".to_owned(),
            checkout_url,
            cancel_at_period_end: false,
        });
    };

    let target_def = lookup_plan_definition(&state.pool, target_plan)
        .await?
        .ok_or_else(|| AppError::NotFound("plan not found".into()))?;
    let target_price_id = ensure_stripe_price_id(&state.pool, &state.stripe, &target_def).await?;
    let subscription = state.stripe.retrieve_subscription(&sub_id).await?;
    let item = subscription
        .items
        .data
        .first()
        .ok_or_else(|| AppError::InternalMsg("stripe subscription has no items".into()))?;
    let item_id = item.id.to_string();
    let current_price_id = item.price.id.as_str();

    let current_plan_key = resolve_subscription_plan_key(&state.pool, &subscription)
        .await?
        .or_else(|| current.as_ref().map(|c| c.plan.clone()))
        .unwrap_or_default();
    let current_price_cents = match lookup_plan_definition(&state.pool, &current_plan_key).await? {
        Some(def) => def.monthly_price_cents,
        None => 0,
    };
    let is_upgrade = target_def.monthly_price_cents > current_price_cents;

    if is_upgrade && subscription.status != stripe_shared::SubscriptionStatus::Active {
        return Err(AppError::Precondition(
            "subscription must be active before upgrading; update your payment method first".into(),
        ));
    }

    let updated = if current_price_id == target_price_id && !subscription.cancel_at_period_end {
        subscription
    } else {
        let resume_flag = if subscription.cancel_at_period_end {
            "resume"
        } else {
            "keep"
        };
        let key = billing_idempotency_key(
            "sub-switch",
            &[
                org_id,
                &sub_id,
                current_price_id,
                &target_price_id,
                resume_flag,
                &transition_tag,
            ],
        );
        run_organization_billing_mutation(&state.pool, org_id, async {
            state
                .stripe
                .update_subscription_plan(
                    &SubscriptionPlanUpdate {
                        subscription_id: &sub_id,
                        item_id: &item_id,
                        price_id: &target_price_id,
                        plan_key: target_plan,
                        proration_behavior: if is_upgrade {
                            "always_invoice"
                        } else {
                            "create_prorations"
                        },
                        payment_behavior: is_upgrade.then_some("error_if_incomplete"),
                        cancel_at_period_end: false,
                    },
                    &key,
                )
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await?
    };

    let synced = sync_subscription_state(&state.pool, org_id, &updated, None, None)
        .await?
        .ok_or_else(|| {
            AppError::Precondition(
                "updated subscription price does not match a known billing plan".into(),
            )
        })?;

    // Mid-cycle upgrade (e.g. Pro -> Max) uplifts the active cycle's allowance
    // only after Stripe synchronously collected payment and returned Active.
    if is_upgrade
        && updated.status == stripe_shared::SubscriptionStatus::Active
        && synced.plan == target_plan
        && target_def.included_compute_nano_usd > 0
    {
        let mut tx = state.pool.begin().await?;
        let uplifted: Option<i64> = sqlx::query_scalar(
            r#"UPDATE billing_plan_allowances
               SET plan_key = $2,
                   granted_nano_usd = $3,
                   updated_at = NOW()
               WHERE id = (
                   SELECT id FROM billing_plan_allowances
                   WHERE organization_id = $1
                     AND period_start <= NOW()
                     AND period_end > NOW()
                     AND granted_nano_usd < $3
                   ORDER BY period_end DESC, id DESC
                   LIMIT 1
                   FOR UPDATE
               )
               RETURNING id"#,
        )
        .bind(org_id)
        .bind(&target_def.plan_key)
        .bind(target_def.included_compute_nano_usd)
        .fetch_optional(&mut *tx)
        .await?;
        if uplifted.is_some() {
            sqlx::query(
                r#"UPDATE organizations
                   SET credit_exhausted_at = NULL
                   WHERE id = $1 AND credit_exhausted_at IS NOT NULL"#,
            )
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }

    Ok(SwitchedPlan {
        plan: synced.plan,
        status: synced.status,
        checkout_url: String::new(),
        cancel_at_period_end: updated.cancel_at_period_end,
    })
}

/// Synced local subscription summary returned by [`sync_subscription_state`].
#[derive(Debug, Clone)]
pub struct SyncedSubscription {
    pub plan: String,
    pub status: String,
    pub current_period_end: Option<DateTime<Utc>>,
}

/// Extracts `(period_start, period_end)` from a Stripe Subscription's first
/// item (Stripe API `2025-03-31.basil`+ moved period timestamps to items).
pub fn subscription_period(
    sub: &stripe_shared::Subscription,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let item = sub.items.data.first()?;
    let start = DateTime::<Utc>::from_timestamp(item.current_period_start, 0)?;
    let end = DateTime::<Utc>::from_timestamp(item.current_period_end, 0)?;
    (end > start).then_some((start, end))
}

/// Resolves the plan key (`pro` or `max`) authoritatively from the
/// subscription items' Stripe Price IDs. Never trusts mutable subscription
/// metadata over active Stripe prices and never silently defaults an
/// unrecognized price to a paid plan.
pub async fn resolve_subscription_plan_key(
    pool: &PgPool,
    sub: &stripe_shared::Subscription,
) -> AppResult<Option<String>> {
    for item in &sub.items.data {
        if let Some(def) = lookup_plan_by_stripe_price(pool, item.price.id.as_str()).await? {
            return Ok(Some(def.plan_key));
        }
    }
    Ok(None)
}

/// Persists a Stripe Subscription snapshot into `org_subscriptions` and
/// `organizations` with stale-event protection when driven by a webhook.
/// Returns `Ok(None)` without mutating local rows when the subscription's
/// active Stripe Price ID does not match a known billing plan.
pub async fn sync_subscription_state(
    pool: &PgPool,
    org_id: &str,
    sub: &stripe_shared::Subscription,
    event_id: Option<&str>,
    event_created_at: Option<DateTime<Utc>>,
) -> AppResult<Option<SyncedSubscription>> {
    let Some(plan) = resolve_subscription_plan_key(pool, sub).await? else {
        tracing::warn!(
            org_id,
            subscription_id = %sub.id,
            "billing: subscription price does not match a known billing plan; skipping sync"
        );
        return Ok(None);
    };
    let status = sub.status.as_str().to_owned();
    let sub_id = sub.id.as_str();
    let period = subscription_period(sub);
    let period_start_naive = period.map(|(s, _)| s.naive_utc());
    let period_end_naive = period.map(|(_, e)| e.naive_utc());
    let event_created_naive = event_created_at.map(|t| t.naive_utc());

    let mut tx = pool.begin().await?;
    if let Some(event_ts) = event_created_naive {
        let existing_ts: Option<Option<NaiveDateTime>> = sqlx::query_scalar(
            "SELECT stripe_event_created_at FROM org_subscriptions WHERE org_id = $1 FOR UPDATE",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(Some(recorded)) = existing_ts
            && event_ts < recorded
        {
            tx.commit().await?;
            return Ok(Some(SyncedSubscription {
                plan,
                status,
                current_period_end: period.map(|(_, e)| e),
            }));
        }
    }

    sqlx::query(
        r#"INSERT INTO org_subscriptions
               (org_id, plan, status, stripe_subscription_id, current_period_start,
                current_period_end, cancel_at_period_end, stripe_event_created_at,
                stripe_event_id, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
           ON CONFLICT (org_id) DO UPDATE SET
               plan = EXCLUDED.plan,
               status = EXCLUDED.status,
               stripe_subscription_id = EXCLUDED.stripe_subscription_id,
               current_period_start = COALESCE(EXCLUDED.current_period_start, org_subscriptions.current_period_start),
               current_period_end = COALESCE(EXCLUDED.current_period_end, org_subscriptions.current_period_end),
               cancel_at_period_end = EXCLUDED.cancel_at_period_end,
               stripe_event_created_at = COALESCE(EXCLUDED.stripe_event_created_at, org_subscriptions.stripe_event_created_at),
               stripe_event_id = COALESCE(EXCLUDED.stripe_event_id, org_subscriptions.stripe_event_id),
               updated_at = NOW()"#,
    )
    .bind(org_id)
    .bind(&plan)
    .bind(&status)
    .bind(sub_id)
    .bind(period_start_naive)
    .bind(period_end_naive)
    .bind(sub.cancel_at_period_end)
    .bind(event_created_naive)
    .bind(event_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"UPDATE organizations
           SET billing_plan = $2, billing_status = $3, updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(org_id)
    .bind(&plan)
    .bind(&status)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(SyncedSubscription {
        plan,
        status,
        current_period_end: period.map(|(_, e)| e),
    }))
}

/// Grants a non-rolling monthly compute allowance for one paid subscription
/// invoice, idempotently by `stripe_invoice_id` and non-overlapping cycle,
/// clearing `credit_exhausted_at` only when a new row is actually inserted.
pub async fn grant_cycle_allowance(
    pool: &PgPool,
    org_id: &str,
    plan_key: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    granted_nano_usd: i64,
    stripe_invoice_id: &str,
) -> AppResult<bool> {
    if granted_nano_usd <= 0 || period_end <= period_start || stripe_invoice_id.is_empty() {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    // Serialize cycle allowance grants per organization.
    let org_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?;
    if org_exists.is_none() {
        tx.commit().await?;
        return Ok(false);
    }

    // Refuse a second overlapping allowance row for the same billing cycle
    // (e.g. from a distinct proration or duplicate invoice ID).
    let overlapping: Option<i64> = sqlx::query_scalar(
        r#"SELECT id FROM billing_plan_allowances
           WHERE organization_id = $1
             AND period_start < $3
             AND period_end > $2
           LIMIT 1"#,
    )
    .bind(org_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(&mut *tx)
    .await?;
    if overlapping.is_some() {
        tx.commit().await?;
        return Ok(false);
    }

    let inserted: Option<i64> = sqlx::query_scalar(
        r#"INSERT INTO billing_plan_allowances
               (organization_id, plan_key, period_start, period_end,
                granted_nano_usd, stripe_invoice_id)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (stripe_invoice_id) DO NOTHING
           RETURNING id"#,
    )
    .bind(org_id)
    .bind(plan_key)
    .bind(period_start)
    .bind(period_end)
    .bind(granted_nano_usd)
    .bind(stripe_invoice_id)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_some() {
        sqlx::query(
            r#"UPDATE organizations
               SET credit_exhausted_at = NULL
               WHERE id = $1 AND credit_exhausted_at IS NOT NULL"#,
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(inserted.is_some())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, routing::post};
    use chrono::Duration;
    use codewire_server_core::credit_enforcement::CreditEnforcement;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.is_empty())
            .or_else(|| {
                std::env::var("TEST_DATABASE_URL")
                    .ok()
                    .filter(|url| !url.is_empty())
            })?;
        Some(
            PgPoolOptions::new()
                .max_connections(4)
                .connect(&url)
                .await
                .expect("connect test db"),
        )
    }

    async fn seed_org(pool: &PgPool, tag: &str) -> (String, String) {
        let user_id = format!("plan-sub-user-{tag}");
        let org_id = format!("plan-sub-org-{tag}");
        let slug = format!("plan-sub-{tag}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&org_id)
        .bind(format!("Plan Org {tag}"))
        .bind(&slug)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'owner') \
             ON CONFLICT DO NOTHING",
        )
        .bind(format!("mem-{tag}"))
        .bind(&org_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
        (user_id, org_id)
    }

    #[tokio::test]
    async fn db_two_bucket_metering_draws_allowance_before_prepaid_credit() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let (user_id, org_id) = seed_org(&pool, &suffix).await;

        let now = Utc::now();
        // Grant $1.00 allowance for the active billing cycle, idempotently.
        let inv_id = format!("in_allowance_{suffix}");
        assert!(
            grant_cycle_allowance(
                &pool,
                &org_id,
                "pro",
                now - Duration::hours(1),
                now + Duration::days(29),
                1_000_000_000,
                &inv_id,
            )
            .await
            .unwrap()
        );
        // Duplicate invoice delivery is a no-op.
        assert!(
            !grant_cycle_allowance(
                &pool,
                &org_id,
                "pro",
                now - Duration::hours(1),
                now + Duration::days(29),
                1_000_000_000,
                &inv_id,
            )
            .await
            .unwrap()
        );

        // Seed $5.00 prepaid credit as backup.
        sqlx::query(
            "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, idempotency_key) \
             VALUES ($1, 'grant', 5000000000, $2)",
        )
        .bind(&org_id)
        .bind(format!("seed-{suffix}"))
        .execute(&pool)
        .await
        .unwrap();

        // Seed a closed 10-hour session on Regular ($0.050/vCPU + $0.016/GiB + $0.0001/GiB):
        // 2 vCPU ($0.10/h) + 8 GiB ($0.128/h) + 20 GiB ($0.002/h) = $0.230/h -> 10h = $2.30.
        let preset_id = format!("preset-{suffix}");
        let env_id = format!("env-{suffix}");
        let sess_id = format!("sess-{suffix}");
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ($1, $2, 'P', 'p', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(&preset_id)
        .bind(&org_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, preset_id, type, state, desired_state, project_spec) \
             VALUES ($1, $2, $3, $4, 'sandbox', 'stopped', 'stopped', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(&env_id)
        .bind(&org_id)
        .bind(&user_id)
        .bind(&preset_id)
        .execute(&pool)
        .await
        .unwrap();
        let started = now - Duration::hours(10);
        sqlx::query(
            "INSERT INTO sandbox_running_sessions \
               (id, environment_id, organization_id, runtime_type, runtime_uid, runtime_name, \
                runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_class, \
                started_at, last_observed_at, ended_at) \
             VALUES ($1, $2, $3, 'sandbox', 'uid', 'sbx', 'ns', 2000, 8192, 20, 'kata', $4, $5, $5)",
        )
        .bind(&sess_id)
        .bind(&env_id)
        .bind(&org_id)
        .bind(started)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        let drawn = crate::credit::draw_organization(&pool, &org_id)
            .await
            .unwrap();
        assert_eq!(drawn, 2_300_000_000);

        // Allowance drew its full $1.00; prepaid credit drew only the $1.30 overflow -> $3.70 left.
        let allowance = active_allowance(&pool, &org_id).await.unwrap();
        assert_eq!(allowance.granted_nano_usd, 1_000_000_000);
        assert_eq!(allowance.drawn_nano_usd, 1_000_000_000);
        assert_eq!(allowance.remaining_nano_usd(), 0);

        let balance: i64 = sqlx::query_scalar(
            "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(balance, 3_700_000_000);

        // An org with $0 credit but remaining active allowance settles as Funded without top-up.
        let (_, org2) = seed_org(&pool, &format!("{suffix}b")).await;
        grant_cycle_allowance(
            &pool,
            &org2,
            "max",
            now - Duration::hours(1),
            now + Duration::days(29),
            250_000_000_000,
            &format!("in_max_{suffix}"),
        )
        .await
        .unwrap();
        let settlement = crate::credit::settle_organization(
            &pool,
            &StripeHandle::default(),
            CreditEnforcement::On,
            &org2,
            false,
        )
        .await
        .unwrap();
        assert_eq!(settlement, crate::credit::Settlement::Funded);
    }

    #[tokio::test]
    async fn db_ensure_stripe_price_id_auto_creates_and_caches_in_db() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = calls.clone();
        let app = Router::new()
            .route(
                "/v1/products",
                post({
                    let seen = seen.clone();
                    move || {
                        seen.lock().unwrap().push("products".to_owned());
                        async {
                            (
                                [("content-type", "application/json")],
                                json!({"id": "prod_auto_pro"}).to_string(),
                            )
                        }
                    }
                }),
            )
            .route(
                "/v1/prices",
                post({
                    let seen = seen.clone();
                    move || {
                        seen.lock().unwrap().push("prices".to_owned());
                        async {
                            (
                                [("content-type", "application/json")],
                                json!({"id": "price_auto_pro"}).to_string(),
                            )
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let stripe = StripeHandle::for_test(&format!("http://{addr}"));

        // Clear any test price ID on `pro`, then ensure twice.
        sqlx::query("UPDATE billing_plan_definitions SET stripe_price_id_test = NULL WHERE plan_key = 'pro'")
            .execute(&pool)
            .await
            .unwrap();
        let def = lookup_plan_definition(&pool, "pro").await.unwrap().unwrap();
        let first = ensure_stripe_price_id(&pool, &stripe, &def).await.unwrap();
        assert_eq!(first, "price_auto_pro");

        let def_cached = lookup_plan_definition(&pool, "pro").await.unwrap().unwrap();
        let second = ensure_stripe_price_id(&pool, &stripe, &def_cached)
            .await
            .unwrap();
        assert_eq!(second, "price_auto_pro");
        assert_eq!(*calls.lock().unwrap(), vec!["products", "prices"]);

        // Clean up cached synthetic price ID.
        sqlx::query("UPDATE billing_plan_definitions SET stripe_price_id_test = NULL WHERE plan_key = 'pro'")
            .execute(&pool)
            .await
            .unwrap();
        server.abort();
    }

    fn test_billing_state(pool: PgPool, stripe: StripeHandle) -> BillingState {
        BillingState {
            pool,
            stripe,
            email: crate::email::EmailClient::disabled(),
            credit_enforcement: CreditEnforcement::On,
            receipts: Default::default(),
            frontend_origin: crate::checkout_sessions::FrontendOrigin::parse(
                "https://app.codewire.test",
            )
            .unwrap(),
            operator_email: None,
            card_setup_address_key: crate::cards::CardSetupAddressKey::for_test("plan-test"),
        }
    }

    fn test_auth_user(user_id: &str) -> AuthUser {
        AuthUser {
            user_id: user_id.to_owned(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        }
    }

    fn synthetic_subscription_json(
        sub_id: &str,
        customer_id: &str,
        price_id: &str,
        status: &str,
        cancel_at_period_end: bool,
        meta_plan_key: Option<&str>,
        (period_start, period_end): (i64, i64),
    ) -> serde_json::Value {
        let mut metadata = serde_json::Map::new();
        if let Some(plan) = meta_plan_key {
            metadata.insert("plan_key".to_owned(), json!(plan));
        }
        json!({
            "id": sub_id,
            "object": "subscription",
            "automatic_tax": { "enabled": false },
            "billing_cycle_anchor": period_start,
            "billing_mode": { "type": "classic" },
            "cancel_at_period_end": cancel_at_period_end,
            "collection_method": "charge_automatically",
            "created": period_start,
            "currency": "usd",
            "customer": customer_id,
            "discounts": [],
            "invoice_settings": { "issuer": { "type": "self" } },
            "items": {
                "object": "list",
                "data": [{
                    "id": "si_test_item_1",
                    "object": "subscription_item",
                    "created": period_start,
                    "current_period_start": period_start,
                    "current_period_end": period_end,
                    "discounts": [],
                    "metadata": {},
                    "plan": {
                        "id": price_id,
                        "object": "plan",
                        "active": true,
                        "billing_scheme": "per_unit",
                        "created": period_start,
                        "currency": "usd",
                        "interval": "month",
                        "interval_count": 1,
                        "livemode": false,
                        "usage_type": "licensed"
                    },
                    "price": {
                        "id": price_id,
                        "object": "price",
                        "active": true,
                        "billing_scheme": "per_unit",
                        "created": period_start,
                        "currency": "usd",
                        "livemode": false,
                        "metadata": {},
                        "product": "prod_test",
                        "type": "recurring"
                    },
                    "quantity": 1,
                    "subscription": sub_id
                }],
                "has_more": false,
                "url": format!("/v1/subscription_items?subscription={sub_id}")
            },
            "livemode": false,
            "metadata": metadata,
            "start_date": period_start,
            "status": status
        })
    }

    #[tokio::test]
    async fn db_resolve_plan_prefers_price_id_over_stale_metadata_and_rejects_unknown() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let pro_price = format!("price_pro_{suffix}");
        let max_price = format!("price_max_{suffix}");
        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = $1 WHERE plan_key = 'pro'",
        )
        .bind(&pro_price)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = $1 WHERE plan_key = 'max'",
        )
        .bind(&max_price)
        .execute(&pool)
        .await
        .unwrap();

        let now = Utc::now().timestamp();
        // Downgraded to Pro price, but metadata still carries stale "max".
        let sub_json = synthetic_subscription_json(
            "sub_stale_meta",
            "cus_test",
            &pro_price,
            "active",
            false,
            Some("max"),
            (now - 3600, now + 86400),
        );
        let sub: stripe_shared::Subscription =
            miniserde::json::from_str(&sub_json.to_string()).unwrap();
        assert_eq!(sub.items.data.len(), 1);
        assert_eq!(
            resolve_subscription_plan_key(&pool, &sub).await.unwrap(),
            Some("pro".to_owned()),
            "Stripe Price ID must override stale subscription metadata"
        );

        // Unknown price must NOT default to "pro" or trust metadata.
        let unknown_json = synthetic_subscription_json(
            "sub_unknown",
            "cus_test",
            "price_unrelated_legacy",
            "active",
            false,
            Some("max"),
            (now - 3600, now + 86400),
        );
        let unknown_sub: stripe_shared::Subscription =
            miniserde::json::from_str(&unknown_json.to_string()).unwrap();
        assert_eq!(
            resolve_subscription_plan_key(&pool, &unknown_sub)
                .await
                .unwrap(),
            None
        );

        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = NULL WHERE plan_key IN ('pro', 'max')",
        )
        .execute(&pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn db_grant_cycle_allowance_prevents_overlap_and_preserves_exhausted_on_replay() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let (_, org_id) = seed_org(&pool, &suffix).await;
        let now = Utc::now();
        let start = now - Duration::hours(1);
        let end = now + Duration::days(29);

        // First grant inserts the row.
        assert!(
            grant_cycle_allowance(
                &pool,
                &org_id,
                "pro",
                start,
                end,
                100_000_000_000,
                &format!("in_first_{suffix}"),
            )
            .await
            .unwrap()
        );

        // Mark org credit_exhausted_at as set (e.g. after burning through allowance).
        sqlx::query("UPDATE organizations SET credit_exhausted_at = NOW() WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();

        // Replay of the exact same invoice ID must NOT clear credit_exhausted_at.
        assert!(
            !grant_cycle_allowance(
                &pool,
                &org_id,
                "pro",
                start,
                end,
                100_000_000_000,
                &format!("in_first_{suffix}"),
            )
            .await
            .unwrap()
        );
        let exhausted: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT credit_exhausted_at FROM organizations WHERE id = $1")
                .bind(&org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            exhausted.is_some(),
            "replayed invoice grant must not clear credit_exhausted_at"
        );

        // A distinct proration/duplicate invoice covering an overlapping period must also be refused.
        assert!(
            !grant_cycle_allowance(
                &pool,
                &org_id,
                "max",
                start + Duration::days(5),
                end,
                250_000_000_000,
                &format!("in_overlap_{suffix}"),
            )
            .await
            .unwrap()
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_plan_allowances WHERE organization_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn db_activate_payg_plan_refuses_when_paid_subscription_exists() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let (user_id, org_id) = seed_org(&pool, &suffix).await;
        let sub_id = format!("sub_paid_keep_{suffix}");
        sqlx::query(
            r#"INSERT INTO org_subscriptions (org_id, plan, status, stripe_subscription_id)
               VALUES ($1, 'pro', 'active', $2)"#,
        )
        .bind(&org_id)
        .bind(&sub_id)
        .execute(&pool)
        .await
        .unwrap();

        let state = test_billing_state(pool.clone(), StripeHandle::default());
        let user = test_auth_user(&user_id);
        let err = activate_payg_plan(&state, &user, &org_id)
            .await
            .expect_err("must refuse PAYG activation while a paid Stripe subscription is active");
        assert!(matches!(err, AppError::Precondition(_)));

        let stored_sub: Option<String> = sqlx::query_scalar(
            "SELECT stripe_subscription_id FROM org_subscriptions WHERE org_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_sub.as_deref(), Some(sub_id.as_str()));
    }

    #[tokio::test]
    async fn db_switch_plan_refuses_past_due_upgrade_and_uses_distinct_roundtrip_keys() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let (user_id, org_id) = seed_org(&pool, &suffix).await;
        let sub_id = format!("sub_sw_{suffix}");
        let pro_price = format!("price_sw_pro_{suffix}");
        let max_price = format!("price_sw_max_{suffix}");
        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = $1 WHERE plan_key = 'pro'",
        )
        .bind(&pro_price)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = $1 WHERE plan_key = 'max'",
        )
        .bind(&max_price)
        .execute(&pool)
        .await
        .unwrap();

        let now = Utc::now();
        let start_ts = (now - Duration::hours(1)).timestamp();
        let end_ts = (now + Duration::days(29)).timestamp();

        // Shared mutable fake Stripe subscription state.
        #[derive(Clone)]
        struct FakeSub {
            status: String,
            price_id: String,
            plan_key: String,
            cancel_at_period_end: bool,
            post_keys: Vec<String>,
            post_bodies: Vec<String>,
        }
        let fake = Arc::new(Mutex::new(FakeSub {
            status: "past_due".to_owned(),
            price_id: pro_price.clone(),
            plan_key: "pro".to_owned(),
            cancel_at_period_end: false,
            post_keys: Vec::new(),
            post_bodies: Vec::new(),
        }));

        let fake_get = fake.clone();
        let fake_post = fake.clone();
        let sub_id_get = sub_id.clone();
        let sub_id_post = sub_id.clone();
        let app = Router::new().route(
            "/v1/subscriptions/{id}",
            axum::routing::get({
                move || {
                    let s = fake_get.lock().unwrap().clone();
                    let sub_id = sub_id_get.clone();
                    async move {
                        (
                            [("content-type", "application/json")],
                            synthetic_subscription_json(
                                &sub_id,
                                "cus_sw_test",
                                &s.price_id,
                                &s.status,
                                s.cancel_at_period_end,
                                Some(&s.plan_key),
                                (start_ts, end_ts),
                            )
                            .to_string(),
                        )
                    }
                }
            })
            .post({
                move |headers: axum::http::HeaderMap, body: String| {
                    let mut s = fake_post.lock().unwrap();
                    if let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok())
                    {
                        s.post_keys.push(key.to_owned());
                    }
                    s.post_bodies.push(body.clone());
                    for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
                        match k.as_ref() {
                            "items[0][price]" => s.price_id = v.into_owned(),
                            "metadata[plan_key]" => s.plan_key = v.into_owned(),
                            "cancel_at_period_end" => s.cancel_at_period_end = v == "true",
                            _ => {}
                        }
                    }
                    let snapshot = s.clone();
                    drop(s);
                    let sub_id = sub_id_post.clone();
                    async move {
                        (
                            [("content-type", "application/json")],
                            synthetic_subscription_json(
                                &sub_id,
                                "cus_sw_test",
                                &snapshot.price_id,
                                &snapshot.status,
                                snapshot.cancel_at_period_end,
                                Some(&snapshot.plan_key),
                                (start_ts, end_ts),
                            )
                            .to_string(),
                        )
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = test_billing_state(
            pool.clone(),
            StripeHandle::for_test(&format!("http://{addr}")),
        );
        let user = test_auth_user(&user_id);

        // Seed past_due Pro subscription + $100 allowance.
        sqlx::query(
            r#"INSERT INTO org_subscriptions (org_id, plan, status, stripe_subscription_id)
               VALUES ($1, 'pro', 'past_due', $2)"#,
        )
        .bind(&org_id)
        .bind(&sub_id)
        .execute(&pool)
        .await
        .unwrap();
        grant_cycle_allowance(
            &pool,
            &org_id,
            "pro",
            now - Duration::hours(1),
            now + Duration::days(29),
            100_000_000_000,
            &format!("in_sw_{suffix}"),
        )
        .await
        .unwrap();

        // 1. past_due Pro -> Max upgrade MUST be refused without calling POST /subscriptions.
        let err = switch_organization_plan(
            &state,
            &user,
            &org_id,
            "max",
            "https://app.codewire.test/ok",
            "https://app.codewire.test/cancel",
        )
        .await
        .expect_err("past_due upgrade must be rejected");
        assert!(matches!(err, AppError::Precondition(_)));
        assert!(fake.lock().unwrap().post_keys.is_empty());

        // 2. Active Pro -> Max -> Pro -> Max round trip uses distinct idempotency keys and
        //    requires always_invoice + error_if_incomplete on upgrades.
        fake.lock().unwrap().status = "active".to_owned();
        sqlx::query("UPDATE org_subscriptions SET status = 'active' WHERE org_id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();

        let sw1 = switch_organization_plan(
            &state,
            &user,
            &org_id,
            "max",
            "https://app.codewire.test/ok",
            "https://app.codewire.test/cancel",
        )
        .await
        .unwrap();
        assert_eq!(sw1.plan, "max");
        assert_eq!(sw1.status, "active");
        assert_eq!(
            active_allowance(&pool, &org_id)
                .await
                .unwrap()
                .granted_nano_usd,
            250_000_000_000
        );

        let sw2 = switch_organization_plan(
            &state,
            &user,
            &org_id,
            "pro",
            "https://app.codewire.test/ok",
            "https://app.codewire.test/cancel",
        )
        .await
        .unwrap();
        assert_eq!(sw2.plan, "pro");

        let sw3 = switch_organization_plan(
            &state,
            &user,
            &org_id,
            "max",
            "https://app.codewire.test/ok",
            "https://app.codewire.test/cancel",
        )
        .await
        .unwrap();
        assert_eq!(sw3.plan, "max");

        let snapshot = fake.lock().unwrap().clone();
        assert_eq!(snapshot.post_keys.len(), 3);
        assert_ne!(
            snapshot.post_keys[0], snapshot.post_keys[2],
            "round-trip pro -> max -> pro -> max must not reuse the earlier idempotency key"
        );
        assert!(
            snapshot.post_bodies[0].contains("proration_behavior=always_invoice")
                && snapshot.post_bodies[0].contains("payment_behavior=error_if_incomplete")
                && snapshot.post_bodies[0].contains("metadata%5Bplan_key%5D=max"),
            "upgrade request must require immediate collected payment and sync plan_key metadata: {}",
            snapshot.post_bodies[0]
        );
        assert!(
            snapshot.post_bodies[1].contains("proration_behavior=create_prorations")
                && !snapshot.post_bodies[1].contains("payment_behavior"),
            "downgrade request should use create_prorations without error_if_incomplete: {}",
            snapshot.post_bodies[1]
        );

        sqlx::query(
            "UPDATE billing_plan_definitions SET stripe_price_id_test = NULL WHERE plan_key IN ('pro', 'max')",
        )
        .execute(&pool)
        .await
        .unwrap();
        server.abort();
    }
}
