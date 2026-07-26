//! Rust-owned deploy-shaped billing smoke.
//!
//! Runs against the real billing binary and PostgreSQL database. It proves a
//! valid signed Stripe `invoice.paid` delivery is idempotent and that the
//! Rust-owned trial loop suspends an expired organization. The retired
//! pre-session-ledger usage writer is intentionally not part of this current
//! product contract.

#![recursion_limit = "256"]

use std::time::Duration;

use anyhow::Context as _;
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("BILLING_RUNTIME_BASE_URL")?
        .trim_end_matches('/')
        .to_owned();
    let database_url = required_env("DATABASE_URL")?;
    let webhook_secret = required_env("BILLING_RUNTIME_WEBHOOK_SECRET")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("connect billing runtime database")?;
    let http = Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(0)
        .build()
        .context("build billing runtime HTTP client")?;

    assert_invoice_paid_idempotency(&http, &pool, &base_url, &webhook_secret).await?;
    assert_trial_expiry(&pool).await?;

    println!(
        "billing-runtime-smoke: signed Stripe invoice idempotency and Rust trial expiry green"
    );
    Ok(())
}

async fn assert_invoice_paid_idempotency(
    http: &Client,
    pool: &PgPool,
    base_url: &str,
    webhook_secret: &str,
) -> anyhow::Result<()> {
    let suffix = &Uuid::new_v4().to_string()[..8];
    let org_id = Uuid::new_v4().to_string();
    let customer_id = format!("cus_rust_runtime_{suffix}");
    let subscription_id = format!("sub_rust_runtime_{suffix}");
    let invoice_id = format!("in_rust_runtime_{suffix}");
    let event_id = format!("evt_rust_runtime_{suffix}");

    sqlx::query(
        "INSERT INTO organizations
             (id, name, slug, created_by, stripe_customer_id, created_at, updated_at)
         VALUES ($1, 'Rust Billing Runtime', $2, 'usr_contract_admin', $3, NOW(), NOW())",
    )
    .bind(&org_id)
    .bind(format!("rust-billing-runtime-{suffix}"))
    .bind(&customer_id)
    .execute(pool)
    .await
    .context("seed webhook organization")?;
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
         VALUES ($1, $2, 'usr_contract_admin', 'owner', NOW(), NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&org_id)
    .execute(pool)
    .await
    .context("seed webhook organization owner")?;
    sqlx::query(
        "INSERT INTO environment_subscriptions
             (id, org_id, plan, status, stripe_subscription_id, created_at, updated_at)
         VALUES ($1, $2, 'starter', 'active', $3, NOW(), NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&org_id)
    .bind(&subscription_id)
    .execute(pool)
    .await
    .context("seed webhook subscription")?;

    let payload = invoice_paid_event(&event_id, &invoice_id, &subscription_id, &customer_id);
    let payload = serde_json::to_string(&payload).context("serialize invoice.paid fixture")?;
    let signature = stripe_signature(webhook_secret, &payload);
    for delivery in ["first", "duplicate"] {
        let response = http
            .post(format!("{base_url}/api/webhooks/stripe"))
            .header("content-type", "application/json")
            .header("stripe-signature", &signature)
            .body(payload.clone())
            .send()
            .await
            .with_context(|| format!("post {delivery} invoice.paid webhook"))?;
        let status = response.status();
        let body = response.text().await.context("read webhook response")?;
        anyhow::ensure!(
            status == StatusCode::OK,
            "{delivery} invoice.paid status={status} body={body:?}"
        );
        if delivery == "first" {
            anyhow::ensure!(body.contains("\"ok\""), "webhook body={body:?}");
        }
    }

    let invoice: (i64, Option<String>, Option<String>, Option<i32>) = sqlx::query_as(
        "SELECT COUNT(*), MIN(org_id), MIN(status), MIN(amount_paid)
           FROM stripe_invoices WHERE stripe_invoice_id = $1",
    )
    .bind(&invoice_id)
    .fetch_one(pool)
    .await
    .context("read persisted invoice")?;
    anyhow::ensure!(
        invoice == (1, Some(org_id.clone()), Some("paid".into()), Some(4900)),
        "persisted invoice mismatch: {invoice:?}"
    );
    let webhook_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM stripe_webhook_events WHERE id = $1")
            .bind(&event_id)
            .fetch_one(pool)
            .await?;
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM billing_events
          WHERE event_type = 'invoice_paid' AND stripe_item_id = $1",
    )
    .bind(&invoice_id)
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        webhook_count == 1 && event_count == 1,
        "duplicate webhook rows: idempotency={webhook_count} billing_events={event_count}"
    );

    sqlx::query("DELETE FROM billing_events WHERE stripe_item_id = $1")
        .bind(&invoice_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM stripe_invoices WHERE stripe_invoice_id = $1")
        .bind(&invoice_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM stripe_webhook_events WHERE id = $1")
        .bind(&event_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM environment_subscriptions WHERE org_id = $1")
        .bind(&org_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&org_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_trial_expiry(pool: &PgPool) -> anyhow::Result<()> {
    let suffix = &Uuid::new_v4().to_string()[..8];
    let org_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO organizations
             (id, name, slug, created_by, billing_status, created_at, updated_at)
         VALUES ($1, 'Rust Trial Runtime', $2, 'usr_contract_admin', 'trialing', NOW(), NOW())",
    )
    .bind(&org_id)
    .bind(format!("rust-trial-runtime-{suffix}"))
    .execute(pool)
    .await
    .context("seed trial organization")?;
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
         VALUES ($1, $2, 'usr_contract_admin', 'owner', NOW(), NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&org_id)
    .execute(pool)
    .await
    .context("seed trial owner")?;
    sqlx::query(
        "INSERT INTO org_subscriptions
             (org_id, plan, status, trial_start, trial_end)
         VALUES ($1, 'starter', 'trialing', NOW() - INTERVAL '15 days', NOW() - INTERVAL '1 minute')",
    )
    .bind(&org_id)
    .execute(pool)
    .await
    .context("seed expired trial")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(70);
    loop {
        let state = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT os.status, COALESCE(o.billing_status, ''),
                    (SELECT COUNT(*) FROM billing_events
                      WHERE event_type = 'trial_expired' AND org_id = os.org_id)
               FROM org_subscriptions os
               JOIN organizations o ON o.id = os.org_id
              WHERE os.org_id = $1",
        )
        .bind(&org_id)
        .fetch_one(pool)
        .await?;
        if state == ("suspended".into(), "suspended".into(), 1) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("expired trial was not fully suspended: {state:?}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    sqlx::query("DELETE FROM billing_events WHERE org_id = $1")
        .bind(&org_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&org_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn stripe_signature(secret: &str, payload: &str) -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let signed = format!("{timestamp}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("Stripe HMAC key");
    mac.update(signed.as_bytes());
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("t={timestamp},v1={signature}")
}

fn invoice_paid_event(
    event_id: &str,
    invoice_id: &str,
    subscription_id: &str,
    customer_id: &str,
) -> Value {
    json!({
        "id": event_id,
        "object": "event",
        "api_version": "2025-03-31.basil",
        "created": chrono::Utc::now().timestamp(),
        "livemode": false,
        "pending_webhooks": 1,
        "request": null,
        "type": "invoice.paid",
        "data": {"object": {
            "id": invoice_id,
            "object": "invoice",
            "amount_due": 4900,
            "amount_paid": 4900,
            "amount_overpaid": 0,
            "amount_remaining": 0,
            "amount_shipping": 0,
            "attempt_count": 1,
            "attempted": true,
            "automatic_tax": {"enabled": false, "disabled_reason": null, "liability": null, "provider": null, "status": null},
            "billing_reason": "subscription_cycle",
            "collection_method": "charge_automatically",
            "created": 1781100000,
            "currency": "usd",
            "customer": customer_id,
            "default_tax_rates": [],
            "discounts": [],
            "issuer": {"type": "self", "account": null},
            "hosted_invoice_url": "https://stripe.test/hosted",
            "invoice_pdf": "https://stripe.test/pdf",
            "lines": {"object": "list", "data": [], "has_more": false, "total_count": 0, "url": "/v1/invoices/lines"},
            "livemode": false,
            "metadata": {},
            "number": "INV-RUST-RUNTIME-001",
            "parent": {
                "type": "subscription_details",
                "quote_details": null,
                "subscription_details": {"subscription": subscription_id, "metadata": {}}
            },
            "payment_settings": {"default_mandate": null, "payment_method_options": null, "payment_method_types": null},
            "period_end": 1781100000,
            "period_start": 1778421600,
            "post_payment_credit_notes_amount": 0,
            "pre_payment_credit_notes_amount": 0,
            "starting_balance": 0,
            "status": "paid",
            "status_transitions": {"finalized_at": null, "marked_uncollectible_at": null, "paid_at": 1781100000, "voided_at": null},
            "subtotal": 4900,
            "total": 4900,
            "total_discount_amounts": [],
            "total_taxes": [],
            "webhooks_delivered_at": null
        }}
    })
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
