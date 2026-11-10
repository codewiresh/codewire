//! Stripe webhook endpoint: `POST /api/webhooks/stripe`.
//!
//! Wire behavior (this third-party webhook uses its established
//! `{"error": "..."}` shape rather than the product error envelope):
//! - billing disabled → 404 `{"error":"billing is not enabled"}`
//! - no signing secret configured → 401
//!   `{"error":"webhook signing is not configured"}`
//! - bad signature → 400 `{"error":"invalid signature"}`
//! - handler failure → 500 `{"error":"webhook processing failed"}`
//! - success → 200 `{"status":"ok"}`
//!
//! The endpoint accepts a complete body up to 64KiB. Oversized payloads are
//! rejected before parsing; signatures are never calculated over a truncation.
//!
//! Event handling starts with an idempotency check on
//! `stripe_webhook_events` first (duplicates are a silent 200), one
//! handler per event type, unhandled types are recorded no-ops, and the
//! idempotency record itself is best-effort.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use stripe_webhook::{Event, EventObject, Webhook};

use crate::email::{EmailClient, ReceiptData};
use crate::routes::BillingState;

const MAX_BODY: usize = 65536;

fn err_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

pub async fn stripe_webhook(
    State(state): State<BillingState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.stripe.is_configured() {
        return err_response(StatusCode::NOT_FOUND, "billing is not enabled");
    }

    // HMAC accepts an empty key, so with no signing secret any caller could
    // sign its own event. Refuse every delivery until the secret is set.
    if state.stripe.webhook_secret().is_empty() {
        tracing::error!(
            "billing: Stripe webhook rejected because STRIPE_WEBHOOK_SECRET is not set"
        );
        return err_response(
            StatusCode::UNAUTHORIZED,
            "webhook signing is not configured",
        );
    }

    if body.len() > MAX_BODY {
        tracing::warn!(
            body_len = body.len(),
            "billing: oversized Stripe webhook rejected"
        );
        return err_response(StatusCode::PAYLOAD_TOO_LARGE, "webhook payload too large");
    }
    let payload = &body;
    let Ok(payload) = std::str::from_utf8(payload) else {
        return err_response(StatusCode::BAD_REQUEST, "invalid signature");
    };
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let event = match Webhook::construct_event(payload, signature, state.stripe.webhook_secret()) {
        Ok(event) => event,
        Err(e) => {
            tracing::warn!(error = ?e, "billing: webhook signature verification failed");
            return err_response(StatusCode::BAD_REQUEST, "invalid signature");
        }
    };

    if let Err(e) = handle_webhook_event(&state, event).await {
        tracing::error!(error = ?e, "billing: webhook processing failed");
        return err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "webhook processing failed",
        );
    }

    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

/// The Stripe event types `handle_webhook_event` acts on. Billing's Stripe
/// endpoint check requires its endpoint to send each of them and nothing
/// else (#3263), so keep this list and the match in step.
pub const HANDLED_EVENT_TYPES: [&str; 8] = [
    "checkout.session.completed",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.trial_will_end",
    "invoice.created",
    "invoice.paid",
    "invoice.payment_failed",
    "invoice.finalized",
];

/// Mirrors `billing.HandleWebhookEvent`.
pub async fn handle_webhook_event(state: &BillingState, event: Event) -> anyhow::Result<()> {
    let pool = &state.pool;

    // The unique insert is the claim. `SELECT EXISTS` followed by a later
    // best-effort insert races across replicas and can double-apply an event.
    let claimed: Option<String> = sqlx::query_scalar(
        r#"INSERT INTO stripe_webhook_events (id, event_type, stripe_created_at, processed_at)
           VALUES ($1, $2, to_timestamp($3), NOW())
           ON CONFLICT (id) DO NOTHING
           RETURNING id"#,
    )
    .bind(event.id.as_str())
    .bind(event.type_.to_string())
    .bind(event.created)
    .fetch_optional(pool)
    .await?;
    if claimed.is_none() {
        tracing::debug!(event_id = %event.id, "billing: skipping duplicate webhook event");
        return Ok(());
    }

    let result: anyhow::Result<()> = async {
        match &event.data.object {
            EventObject::CheckoutSessionCompleted(session) => {
                handle_checkout_completed(state, session).await?
            }
            EventObject::CustomerSubscriptionUpdated(sub) => {
                handle_subscription_updated(pool, sub, event.created, event.id.as_str()).await?
            }
            EventObject::CustomerSubscriptionDeleted(sub) => {
                handle_subscription_deleted(pool, sub, event.created, event.id.as_str()).await?
            }
            EventObject::CustomerSubscriptionTrialWillEnd(sub) => {
                handle_trial_will_end(pool, &state.email, sub).await?
            }
            EventObject::InvoiceCreated(inv) => handle_invoice_created(state, inv).await?,
            EventObject::InvoicePaid(inv) => handle_invoice_paid(state, inv).await?,
            EventObject::InvoicePaymentFailed(inv) => {
                handle_invoice_payment_failed(state, inv).await?
            }
            EventObject::InvoiceFinalized(inv) => upsert_invoice(pool, inv).await?,
            _ => {
                tracing::debug!(event_type = %event.type_, "billing: unhandled webhook event type");
            }
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        // A failed delivery must be retryable. The receipt is the claim, not
        // an irreversible acknowledgement; Stripe receives a 500 and retries.
        sqlx::query("DELETE FROM stripe_webhook_events WHERE id = $1")
            .bind(event.id.as_str())
            .execute(pool)
            .await?;
    }
    result
}

fn expandable_id<T: stripe_types::Object>(e: &stripe_types::Expandable<T>) -> String
where
    T::Id: ToString,
{
    match e {
        stripe_types::Expandable::Id(id) => id.to_string(),
        stripe_types::Expandable::Object(o) => o.id().to_string(),
    }
}

// ── checkout.session.completed ──────────────────────────────────────

async fn handle_checkout_completed(
    state: &BillingState,
    session: &stripe_shared::CheckoutSession,
) -> anyhow::Result<()> {
    let pool = &state.pool;

    // Setup-mode session: persist the collected payment method.
    if session.mode == stripe_shared::CheckoutSessionMode::Setup {
        if let Some(si) = &session.setup_intent {
            let si = state
                .stripe
                .retrieve_setup_intent(&expandable_id(si))
                .await?;
            let org_id = session
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("org_id"))
                .cloned()
                .unwrap_or_default();
            if let (Some(pm), Some(customer)) = (si.payment_method, &session.customer)
                && !org_id.is_empty()
            {
                let customer_id = expandable_id(customer);
                let payment_method_id = expandable_id(&pm);
                let idempotency_key = provider_idempotency_key(
                    "default-payment-method",
                    &[&org_id, &customer_id, &payment_method_id],
                );
                match run_organization_billing_mutation(pool, &org_id, async {
                    state
                        .stripe
                        .set_default_payment_method(
                            &customer_id,
                            &payment_method_id,
                            &idempotency_key,
                        )
                        .await
                        .map_err(OrganizationBillingMutationError::ambiguous)
                })
                .await
                {
                    Ok(()) => tracing::info!(
                        customer_id,
                        "billing: payment method added via setup checkout"
                    ),
                    Err(e) => {
                        tracing::error!(error = ?e, "billing: failed to set default payment method from setup")
                    }
                }
                settle_after_new_card(state, &org_id).await?;
            }
        }
        return Ok(());
    }

    let Some(sub_ref) = &session.subscription else {
        return Ok(());
    };

    // Fetch the subscription for its metadata.
    let sub = state
        .stripe
        .retrieve_subscription(&expandable_id(sub_ref))
        .await?;
    let org_id = sub.metadata.get("org_id").cloned().unwrap_or_default();
    let plan_name = sub.metadata.get("plan").cloned().unwrap_or_default();
    if org_id.is_empty() || plan_name.is_empty() {
        tracing::warn!(sub_id = %sub.id, "billing: checkout completed but missing metadata");
        return Ok(());
    }

    if sub.metadata.get("entity_type").map(String::as_str) == Some("environment") {
        let status = sub.status.to_string();
        let price_cents: Option<i32> = sqlx::query_scalar(
            r#"SELECT price_cents FROM billing_catalog_plans
               WHERE resource_type = 'sandbox' AND plan_key = $1"#,
        )
        .bind(&plan_name)
        .fetch_optional(pool)
        .await?;
        let price_id: Option<String> = sqlx::query_scalar(
            r#"SELECT stripe_price_id FROM billing_catalog_prices
               WHERE resource_type = 'sandbox' AND plan_key = $1 AND stripe_mode = $2
                 AND price_kind = 'subscription' AND archived_at IS NULL"#,
        )
        .bind(&plan_name)
        .bind(state.stripe.stripe_mode())
        .fetch_optional(pool)
        .await?;

        if let Err(e) = sqlx::query(
            r#"INSERT INTO environment_subscriptions
               (id, org_id, plan, status, stripe_subscription_id, stripe_price_id, created_at, updated_at)
               VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, NOW(), NOW())
               ON CONFLICT (org_id) DO UPDATE SET
                      plan = EXCLUDED.plan, status = EXCLUDED.status,
                      stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                      stripe_price_id = EXCLUDED.stripe_price_id,
                      updated_at = NOW()"#,
        )
        .bind(&org_id)
        .bind(&plan_name)
        .bind(&status)
        .bind(sub.id.as_str())
        .bind(price_id.unwrap_or_default())
        .execute(pool)
        .await
        {
            tracing::error!(error = ?e, "billing: failed to upsert environment subscription");
        }

        if let Some(pm) = &sub.default_payment_method {
            let customer_id = expandable_id(&sub.customer);
            let payment_method_id = expandable_id(pm);
            let idempotency_key = provider_idempotency_key(
                "default-payment-method",
                &[&org_id, &customer_id, &payment_method_id],
            );
            if let Err(e) = run_organization_billing_mutation(pool, &org_id, async {
                state
                    .stripe
                    .set_default_payment_method(&customer_id, &payment_method_id, &idempotency_key)
                    .await
                    .map_err(OrganizationBillingMutationError::ambiguous)
            })
            .await
            {
                tracing::warn!(error = ?e, "billing: failed to set default payment method");
            }
        }

        log_billing_event(
            pool,
            "env_checkout_completed",
            &org_id,
            price_cents,
            "usd",
            sub.id.as_str(),
            serde_json::json!({"plan": plan_name, "entity_type": "environment"}),
        )
        .await;
        tracing::info!(
            org_id,
            plan = plan_name,
            "billing: environment checkout completed"
        );
        return Ok(());
    }

    // Legacy org-level path.
    sqlx::query(
        r#"INSERT INTO org_subscriptions (id, org_id, plan, status, stripe_subscription_id, created_at, updated_at)
           VALUES (gen_random_uuid()::text, $1, $2, 'active', $3, NOW(), NOW())
           ON CONFLICT (org_id) DO UPDATE SET
                  plan = EXCLUDED.plan, status = 'active',
                  stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                  updated_at = NOW()"#,
    )
    .bind(&org_id)
    .bind(&plan_name)
    .bind(sub.id.as_str())
    .execute(pool)
    .await?;

    sqlx::query(
        r#"UPDATE organizations SET billing_plan = $1, billing_status = 'active', updated_at = NOW()
           WHERE id = $2"#,
    )
    .bind(&plan_name)
    .bind(&org_id)
    .execute(pool)
    .await?;

    log_billing_event(
        pool,
        "checkout_completed",
        &org_id,
        None,
        "usd",
        sub.id.as_str(),
        serde_json::json!({"plan": plan_name}),
    )
    .await;
    tracing::info!(org_id, plan = plan_name, sub_id = %sub.id, "billing: checkout completed");
    Ok(())
}

/// A new card tops up a balance that ran out (#3381), where this deployment
/// enforces credit. A card grants no credit (owner, 2026-11-10). An error
/// fails the delivery, so Stripe retries; the top-up is idempotent.
async fn settle_after_new_card(state: &BillingState, org_id: &str) -> anyhow::Result<()> {
    if !state.credit_enforcement.is_on() {
        return Ok(());
    }
    let settlement = crate::credit::settle_organization(
        &state.pool,
        &state.stripe,
        state.credit_enforcement,
        org_id,
        true,
    )
    .await?;
    tracing::info!(
        org_id,
        ?settlement,
        "billing: credit settled after a new card"
    );
    Ok(())
}

// ── customer.subscription.updated / deleted ─────────────────────────

/// Stripe status → DB status, mirroring the Go switch (notably
/// `unpaid` → `suspended`).
fn db_status(status: &stripe_shared::SubscriptionStatus) -> String {
    use stripe_shared::SubscriptionStatus as S;
    match status {
        S::Active => "active".into(),
        S::PastDue => "past_due".into(),
        S::Canceled => "canceled".into(),
        S::Unpaid => "suspended".into(),
        S::Trialing => "trialing".into(),
        other => other.to_string(),
    }
}

async fn handle_subscription_updated(
    pool: &PgPool,
    sub: &stripe_shared::Subscription,
    event_created: i64,
    event_id: &str,
) -> anyhow::Result<()> {
    let status = db_status(&sub.status);
    let plan_name = sub.metadata.get("plan").cloned().unwrap_or_default();

    let env_org: Option<String> = sqlx::query_scalar(
        r#"SELECT org_id FROM environment_subscriptions WHERE stripe_subscription_id = $1"#,
    )
    .bind(sub.id.as_str())
    .fetch_optional(pool)
    .await?;

    if let Some(env_org_id) = env_org.filter(|o| !o.is_empty()) {
        let updated = sqlx::query(
            r#"UPDATE environment_subscriptions
                  SET status = $1,
                      plan = CASE WHEN $2 = '' THEN plan ELSE $2 END,
                      stripe_event_created_at = to_timestamp($3),
                      stripe_event_id = $4,
                      updated_at = NOW()
                WHERE stripe_subscription_id = $5
                  AND (stripe_event_created_at IS NULL
                       OR stripe_event_created_at < to_timestamp($3)
                       OR (stripe_event_created_at = to_timestamp($3)
                           AND COALESCE(stripe_event_id, '') < $4))"#,
        )
        .bind(&status)
        .bind(&plan_name)
        .bind(event_created)
        .bind(event_id)
        .bind(sub.id.as_str())
        .execute(pool)
        .await;
        if updated
            .map(|result| result.rows_affected() == 0)
            .unwrap_or(true)
        {
            return Ok(());
        }
        log_billing_event(
            pool,
            "env_subscription_updated",
            &env_org_id,
            None,
            "usd",
            sub.id.as_str(),
            serde_json::json!({"status": status, "plan": plan_name}),
        )
        .await;
        return Ok(());
    }

    let updated = sqlx::query(
        r#"UPDATE org_subscriptions
              SET status = $1,
                  plan = CASE WHEN $2 = '' THEN plan ELSE $2 END,
                  stripe_event_created_at = to_timestamp($3),
                  stripe_event_id = $4,
                  updated_at = NOW()
            WHERE stripe_subscription_id = $5
              AND (stripe_event_created_at IS NULL
                   OR stripe_event_created_at < to_timestamp($3)
                   OR (stripe_event_created_at = to_timestamp($3)
                       AND COALESCE(stripe_event_id, '') < $4))"#,
    )
    .bind(&status)
    .bind(&plan_name)
    .bind(event_created)
    .bind(event_id)
    .bind(sub.id.as_str())
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }

    let org_id: Option<String> = sqlx::query_scalar(
        r#"SELECT org_id FROM org_subscriptions WHERE stripe_subscription_id = $1"#,
    )
    .bind(sub.id.as_str())
    .fetch_optional(pool)
    .await?;
    if let Some(org_id) = org_id {
        let _ = sqlx::query(
            r#"UPDATE organizations SET billing_status = $1, updated_at = NOW() WHERE id = $2"#,
        )
        .bind(&status)
        .bind(&org_id)
        .execute(pool)
        .await;
        if !plan_name.is_empty() {
            let _ = sqlx::query(
                r#"UPDATE organizations SET billing_plan = $1, updated_at = NOW() WHERE id = $2"#,
            )
            .bind(&plan_name)
            .bind(&org_id)
            .execute(pool)
            .await;
        }
    }

    Ok(())
}

async fn handle_subscription_deleted(
    pool: &PgPool,
    sub: &stripe_shared::Subscription,
    event_created: i64,
    event_id: &str,
) -> anyhow::Result<()> {
    let env_org: Option<String> = sqlx::query_scalar(
        r#"SELECT org_id FROM environment_subscriptions WHERE stripe_subscription_id = $1"#,
    )
    .bind(sub.id.as_str())
    .fetch_optional(pool)
    .await?;

    if let Some(env_org_id) = env_org.filter(|o| !o.is_empty()) {
        let updated = sqlx::query(
            r#"UPDATE environment_subscriptions
                  SET status = 'canceled', stripe_event_created_at = to_timestamp($1),
                      stripe_event_id = $2, updated_at = NOW()
                WHERE stripe_subscription_id = $3
                  AND (stripe_event_created_at IS NULL
                       OR stripe_event_created_at < to_timestamp($1)
                       OR (stripe_event_created_at = to_timestamp($1)
                           AND COALESCE(stripe_event_id, '') < $2))"#,
        )
        .bind(event_created)
        .bind(event_id)
        .bind(sub.id.as_str())
        .execute(pool)
        .await;
        if updated
            .map(|result| result.rows_affected() == 0)
            .unwrap_or(true)
        {
            return Ok(());
        }
        log_billing_event(
            pool,
            "env_subscription_canceled",
            &env_org_id,
            None,
            "usd",
            sub.id.as_str(),
            serde_json::Value::Null,
        )
        .await;
        tracing::info!(
            org_id = env_org_id,
            "billing: environment subscription canceled"
        );
        return Ok(());
    }

    let updated = sqlx::query(
        r#"UPDATE org_subscriptions
              SET status = 'canceled', stripe_event_created_at = to_timestamp($1),
                  stripe_event_id = $2, updated_at = NOW()
            WHERE stripe_subscription_id = $3
              AND (stripe_event_created_at IS NULL
                   OR stripe_event_created_at < to_timestamp($1)
                   OR (stripe_event_created_at = to_timestamp($1)
                       AND COALESCE(stripe_event_id, '') < $2))"#,
    )
    .bind(event_created)
    .bind(event_id)
    .bind(sub.id.as_str())
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }

    let org_id: Option<String> = sqlx::query_scalar(
        r#"SELECT org_id FROM org_subscriptions WHERE stripe_subscription_id = $1"#,
    )
    .bind(sub.id.as_str())
    .fetch_optional(pool)
    .await?;
    if let Some(org_id) = org_id {
        let _ = sqlx::query(
            r#"UPDATE organizations SET billing_status = 'canceled', updated_at = NOW() WHERE id = $1"#,
        )
        .bind(&org_id)
        .execute(pool)
        .await;
        log_billing_event(
            pool,
            "subscription_canceled",
            &org_id,
            None,
            "usd",
            sub.id.as_str(),
            serde_json::Value::Null,
        )
        .await;
    }

    Ok(())
}

async fn handle_trial_will_end(
    pool: &PgPool,
    email: &EmailClient,
    sub: &stripe_shared::Subscription,
) -> anyhow::Result<()> {
    let org_id = sub.metadata.get("org_id").cloned().unwrap_or_default();
    if org_id.is_empty() {
        return Ok(());
    }
    if email.is_configured()
        && let Some(owner_email) = org_owner_email_by_id(pool, &org_id).await
        && let Err(e) = email.send_trial_ending(&owner_email, 3).await
    {
        tracing::error!(error = ?e, "billing: failed to send trial ending email");
    }
    Ok(())
}

// ── invoice.* ────────────────────────────────────────────────────────

async fn handle_invoice_created(
    state: &BillingState,
    inv: &stripe_shared::Invoice,
) -> anyhow::Result<()> {
    let pool = &state.pool;
    upsert_invoice(pool, inv).await?;
    Ok(())
}

fn provider_idempotency_key(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("cw-{kind}-{:x}", hasher.finalize())
}

/// The top-up an invoice charges, when it is an automatic credit top-up.
fn top_up_id(inv: &stripe_shared::Invoice) -> Option<&str> {
    let metadata = inv.metadata.as_ref()?;
    (metadata.get("kind").map(String::as_str) == Some("credit_top_up"))
        .then(|| metadata.get("top_up_id").map(String::as_str))
        .flatten()
        .filter(|id| !id.is_empty())
}

async fn handle_invoice_paid(
    state: &BillingState,
    inv: &stripe_shared::Invoice,
) -> anyhow::Result<()> {
    let pool = &state.pool;
    upsert_invoice(pool, inv).await?;
    if let (Some(top_up_id), Some(invoice_id)) = (top_up_id(inv), inv.id.as_deref()) {
        crate::credit::complete_top_up(pool, top_up_id, invoice_id).await?;
    }

    let invoice_id = inv.id.as_deref().unwrap_or_default();
    let org_id = resolve_invoice_org_id(pool, inv).await;

    if state.email.is_configured() {
        let receipt_sent: bool = sqlx::query_scalar(
            r#"SELECT receipt_sent_at IS NOT NULL FROM stripe_invoices WHERE stripe_invoice_id = $1"#,
        )
        .bind(invoice_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(false);

        if !receipt_sent && let Some(org_email) = org_owner_email_by_customer(pool, inv).await {
            let mut data = ReceiptData {
                invoice_number: inv.number.clone().unwrap_or_default(),
                date: format_go_date(inv.created, "long"),
                amount_paid: inv.amount_paid,
                subtotal: invoice_subtotal(inv),
                net_amount_due: inv.amount_due,
                currency: inv.currency.to_string(),
                hosted_invoice_url: inv.hosted_invoice_url.clone().unwrap_or_default(),
                invoice_pdf: inv.invoice_pdf.clone().unwrap_or_default(),
                charge_reasons: invoice_line_descriptions(inv, false),
                credit_reasons: invoice_line_descriptions(inv, true),
                ..Default::default()
            };
            // A one-off invoice, such as a top-up, covers no period.
            if inv.period_start > 0 && inv.period_end > inv.period_start {
                data.period_start = format_go_date(inv.period_start, "short");
                data.period_end = format_go_date(inv.period_end, "short");
            }
            // A failed send fails the delivery, so Stripe retries it: paying
            // never ends without a receipt. Everything above is idempotent,
            // and the event below is logged once, after the receipt.
            state.email.send_payment_receipt(&org_email, &data).await?;
            let _ = sqlx::query(
                r#"UPDATE stripe_invoices SET receipt_sent_at = NOW() WHERE stripe_invoice_id = $1"#,
            )
            .bind(invoice_id)
            .execute(pool)
            .await;
        }
    }

    log_billing_event(
        pool,
        "invoice_paid",
        &org_id,
        Some(inv.amount_paid as i32),
        &inv.currency.to_string(),
        invoice_id,
        serde_json::json!({"invoice_number": inv.number.clone().unwrap_or_default()}),
    )
    .await;

    Ok(())
}

async fn handle_invoice_payment_failed(
    state: &BillingState,
    inv: &stripe_shared::Invoice,
) -> anyhow::Result<()> {
    let pool = &state.pool;
    upsert_invoice(pool, inv).await?;
    if let Some(top_up_id) = top_up_id(inv) {
        crate::credit::fail_top_up(pool, top_up_id, inv.id.as_deref(), "invoice_payment_failed")
            .await?;
    }

    let invoice_id = inv.id.as_deref().unwrap_or_default();
    let org_id = resolve_invoice_org_id(pool, inv).await;
    log_billing_event(
        pool,
        "invoice_failed",
        &org_id,
        Some(inv.amount_due as i32),
        &inv.currency.to_string(),
        invoice_id,
        serde_json::json!({"invoice_number": inv.number.clone().unwrap_or_default()}),
    )
    .await;

    if state.email.is_configured()
        && let Some(org_email) = org_owner_email_by_customer(pool, inv).await
        && let Err(e) = state
            .email
            .send_payment_failed(&org_email, inv.amount_due, &inv.currency.to_string())
            .await
    {
        tracing::error!(error = ?e, "billing: failed to send payment failed email");
    }

    Ok(())
}

// ── Shared helpers ───────────────────────────────────────────────────

fn invoice_subscription_id(inv: &stripe_shared::Invoice) -> String {
    inv.parent
        .as_ref()
        .and_then(|p| p.subscription_details.as_ref())
        .map(|d| expandable_id(&d.subscription))
        .unwrap_or_default()
}

async fn upsert_invoice(pool: &PgPool, inv: &stripe_shared::Invoice) -> anyhow::Result<()> {
    let invoice_id = inv.id.as_deref().unwrap_or_default();
    let sub_id = invoice_subscription_id(inv);
    let org_id = resolve_invoice_org_id(pool, inv).await;
    if org_id.is_empty() {
        tracing::warn!(
            invoice_id,
            sub_id,
            "billing: upsertInvoice could not find org_id"
        );
        return Ok(()); // Can't link invoice to org.
    }

    let to_naive = |ts: i64| DateTime::<Utc>::from_timestamp(ts, 0).map(|t| t.naive_utc());
    let period_start = (inv.period_start > 0)
        .then(|| to_naive(inv.period_start))
        .flatten();
    let period_end = (inv.period_end > 0)
        .then(|| to_naive(inv.period_end))
        .flatten();

    sqlx::query(
        r#"INSERT INTO stripe_invoices (org_id, stripe_invoice_id, stripe_subscription_id,
                  status, amount_due, amount_paid, currency, hosted_invoice_url, invoice_pdf,
                  period_start, period_end)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (stripe_invoice_id) DO UPDATE SET
                  status = EXCLUDED.status, amount_due = EXCLUDED.amount_due,
                  amount_paid = EXCLUDED.amount_paid, hosted_invoice_url = EXCLUDED.hosted_invoice_url,
                  invoice_pdf = EXCLUDED.invoice_pdf,
                  updated_at = NOW()"#,
    )
    .bind(&org_id)
    .bind(invoice_id)
    .bind((!sub_id.is_empty()).then_some(sub_id.clone()))
    .bind(inv.status.as_ref().map(|s| s.to_string()).unwrap_or_default())
    .bind(inv.amount_due as i32)
    .bind(inv.amount_paid as i32)
    .bind(inv.currency.to_string())
    .bind(&inv.hosted_invoice_url)
    .bind(&inv.invoice_pdf)
    .bind(period_start)
    .bind(period_end)
    .execute(pool)
    .await?;

    Ok(())
}

async fn resolve_invoice_org_id(pool: &PgPool, inv: &stripe_shared::Invoice) -> String {
    let sub_id = invoice_subscription_id(inv);
    if !sub_id.is_empty() {
        if let Ok(Some(org)) = sqlx::query_scalar::<_, String>(
            r#"SELECT org_id FROM org_subscriptions WHERE stripe_subscription_id = $1"#,
        )
        .bind(&sub_id)
        .fetch_optional(pool)
        .await
            && !org.is_empty()
        {
            return org;
        }
        if let Ok(Some(org)) = sqlx::query_scalar::<_, String>(
            r#"SELECT org_id FROM environment_subscriptions WHERE stripe_subscription_id = $1"#,
        )
        .bind(&sub_id)
        .fetch_optional(pool)
        .await
            && !org.is_empty()
        {
            return org;
        }
    }
    if let Some(customer) = &inv.customer
        && let Ok(Some(org)) = sqlx::query_scalar::<_, String>(
            r#"SELECT id FROM organizations WHERE stripe_customer_id = $1"#,
        )
        .bind(expandable_id(customer))
        .fetch_optional(pool)
        .await
    {
        return org;
    }
    String::new()
}

async fn org_owner_email_by_customer(
    pool: &PgPool,
    inv: &stripe_shared::Invoice,
) -> Option<String> {
    let customer = inv.customer.as_ref()?;
    sqlx::query_scalar(
        r#"SELECT u.email FROM organizations o
           JOIN org_members m ON m.org_id = o.id AND m.role = 'owner'
           JOIN users u ON u.id = m.user_id
           WHERE o.stripe_customer_id = $1
           ORDER BY m.created_at ASC LIMIT 1"#,
    )
    .bind(expandable_id(customer))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

pub(crate) async fn org_owner_email_by_id(pool: &PgPool, org_id: &str) -> Option<String> {
    sqlx::query_scalar(
        r#"SELECT u.email FROM org_members m
           JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 AND m.role = 'owner'
           ORDER BY m.created_at ASC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Mirrors `LogBillingEvent` (fire-and-forget; resource columns were
/// dropped from billing_events).
async fn log_billing_event(
    pool: &PgPool,
    event_type: &str,
    org_id: &str,
    amount_cents: Option<i32>,
    currency: &str,
    stripe_item_id: &str,
    metadata: serde_json::Value,
) {
    let metadata = if metadata.is_null() {
        None
    } else {
        Some(metadata)
    };
    if let Err(e) = sqlx::query(
        r#"INSERT INTO billing_events (event_type, org_id, amount_cents, currency, stripe_item_id, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(event_type)
    .bind((!org_id.is_empty()).then_some(org_id))
    .bind(amount_cents)
    .bind(currency)
    .bind((!stripe_item_id.is_empty()).then_some(stripe_item_id))
    .bind(metadata)
    .execute(pool)
    .await
    {
        tracing::warn!(event_type, error = ?e, "billing: failed to log event");
    }
}

fn invoice_subtotal(inv: &stripe_shared::Invoice) -> i64 {
    inv.lines
        .data
        .iter()
        .filter(|l| l.amount > 0)
        .map(|l| l.amount)
        .sum()
}

fn invoice_line_descriptions(inv: &stripe_shared::Invoice, credits: bool) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in &inv.lines.data {
        if credits && line.amount >= 0 {
            continue;
        }
        if !credits && line.amount <= 0 {
            continue;
        }
        let description = line
            .description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| fallback_line_description(line, credits));
        if description.is_empty() || !seen.insert(description.clone()) {
            continue;
        }
        out.push(description);
    }
    out
}

fn fallback_line_description(line: &stripe_shared::InvoiceLineItem, credits: bool) -> String {
    use stripe_shared::BillingBillResourceInvoicingLinesParentsInvoiceLineItemParentType as T;
    match line.parent.as_ref().map(|p| &p.type_) {
        Some(T::SubscriptionItemDetails) => "Subscription charges",
        Some(T::InvoiceItemDetails) => {
            if credits {
                "Credits applied"
            } else {
                "Usage charges"
            }
        }
        _ => {
            if credits {
                "Credits applied"
            } else {
                "Usage and subscription charges"
            }
        }
    }
    .to_string()
}

/// Go time formats: `January 2, 2006` ("long") and `Jan 2, 2006`
/// ("short") — note the non-zero-padded day.
fn format_go_date(ts: i64, style: &str) -> String {
    let Some(t) = DateTime::<Utc>::from_timestamp(ts, 0) else {
        return String::new();
    };
    let fmt = if style == "long" {
        "%B %-d, %Y"
    } else {
        "%b %-d, %Y"
    };
    t.format(fmt).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkout_sessions::FrontendOrigin;
    use crate::stripe_client::StripeHandle;
    use codewire_server_core::credit_enforcement::CreditEnforcement;

    // The event shape async-stripe's own tests construct; Codewire does not
    // handle this type, so an accepted delivery goes on to the idempotency
    // record.
    const EVENT: &str = r#"{"id":"evt_forged","object":"event","api_version":"2017-05-25","created":1492774577,"livemode":false,"pending_webhooks":1,"data":{"object":{"object":"bank_account","country":"us","currency":"usd","id":"ba_test","last4":"6789","status":"verified"}},"type":"account.external_account.created"}"#;

    fn state(stripe: StripeHandle) -> BillingState {
        BillingState {
            // Never connected: every case below answers before any query.
            pool: PgPool::connect_lazy("postgres://codewire@127.0.0.1:1/codewire").unwrap(),
            stripe,
            email: EmailClient::disabled(),
            credit_enforcement: Default::default(),
            frontend_origin: FrontendOrigin::parse("https://app.codewire.test").unwrap(),
        }
    }

    async fn deliver(stripe: StripeHandle, signed_with: &str) -> (StatusCode, serde_json::Value) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Stripe-Signature",
            Webhook::generate_test_header(EVENT, signed_with, None)
                .parse()
                .unwrap(),
        );
        let response = stripe_webhook(
            State(state(stripe)),
            headers,
            axum::body::Bytes::from_static(EVENT.as_bytes()),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), MAX_BODY)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[test]
    fn stripe_accepts_a_signature_made_with_an_empty_key() {
        // Why the guard exists: the library does not refuse an empty secret.
        let header = Webhook::generate_test_header(EVENT, "", None);
        assert!(Webhook::construct_event(EVENT, &header, "").is_ok());
    }

    #[tokio::test]
    async fn webhooks_are_refused_while_the_signing_secret_is_empty() {
        // The attack: with no secret configured, sign with the empty key.
        let (status, body) = deliver(StripeHandle::for_test("http://127.0.0.1:1"), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "webhook signing is not configured");
    }

    #[tokio::test]
    async fn a_configured_secret_rejects_an_empty_key_signature() {
        let stripe = StripeHandle::for_test("http://127.0.0.1:1").with_webhook_secret("whsec_test");
        let (status, body) = deliver(stripe, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid signature");
    }

    #[tokio::test]
    async fn with_enforcement_off_a_new_card_charges_nothing() {
        // Neither the database nor Stripe is reachable, so doing anything
        // at all would fail.
        let mut billing = state(StripeHandle::for_test("http://127.0.0.1:1"));
        settle_after_new_card(&billing, "org_off").await.unwrap();
        billing.credit_enforcement = CreditEnforcement::On;
        settle_after_new_card(&billing, "org_on").await.unwrap_err();
    }

    #[test]
    fn go_date_formats_match() {
        // 2026-06-02 10:30 UTC.
        let ts = 1780396200;
        assert_eq!(format_go_date(ts, "long"), "June 2, 2026");
        assert_eq!(format_go_date(ts, "short"), "Jun 2, 2026");
    }

    #[test]
    fn unpaid_maps_to_suspended() {
        assert_eq!(
            db_status(&stripe_shared::SubscriptionStatus::Unpaid),
            "suspended"
        );
        assert_eq!(
            db_status(&stripe_shared::SubscriptionStatus::Active),
            "active"
        );
        assert_eq!(
            db_status(&stripe_shared::SubscriptionStatus::Incomplete),
            "incomplete"
        );
    }
}
