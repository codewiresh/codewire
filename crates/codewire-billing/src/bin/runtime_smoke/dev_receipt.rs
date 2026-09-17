//! Explicit Dev-only, one-attempt billing receipt proof. No SES credentials
//! belong in this process: the ordinary billing service owns the sender.

use std::time::Duration;

use anyhow::ensure;
use codewire_server_core::config::database_url_from_parts;
use codewire_server_core::organization_slug::valid_organization_slug;
use reqwest::{Client, StatusCode};
use sqlx::PgPool;
use uuid::Uuid;

use super::{invoice_paid_event, required_env, stripe_signature};

const DEV_BILLING_URL: &str = "http://codewire-billing.dev.svc.cluster.local:8081";
const RECEIPT: &str = "billing-dev-receipt: one webhook accepted; receipt_sent_at absent-to-present; recipient and fixture linkage verified";

struct Config {
    database_url: String,
    webhook_secret: String,
    user_id: String,
    email: String,
    attempt: Uuid,
}

impl Config {
    fn from_reader(
        read: impl Fn(&str) -> anyhow::Result<String>,
        database_url_override_present: bool,
    ) -> anyhow::Result<Self> {
        ensure!(
            !database_url_override_present,
            "DATABASE_URL is forbidden in Dev receipt mode"
        );
        ensure!(read("ENVIRONMENT")? == "dev", "Dev required");
        ensure!(
            read("BILLING_RUNTIME_BASE_URL")? == DEV_BILLING_URL,
            "Dev billing endpoint required"
        );
        let database_url = database_url_from_parts(
            &read("DB_HOST")?,
            &read("DB_PORT")?,
            &read("DB_USER")?,
            &read("DB_PASSWORD")?,
            &read("DB_NAME")?,
            &read("DB_SSLMODE")?,
        )?;
        validate_database_url(&database_url)?;
        let webhook_secret = read("BILLING_RUNTIME_WEBHOOK_SECRET")?;
        let user_id = read("BILLING_RECEIPT_EXPECTED_USER_ID")?;
        let email = read("BILLING_RECEIPT_EXPECTED_EMAIL")?;
        ensure!(
            !webhook_secret.is_empty() && !user_id.trim().is_empty(),
            "explicit inputs required"
        );
        ensure!(
            email == email.trim() && email.contains('@') && !email.chars().any(char::is_whitespace),
            "explicit recipient required"
        );
        let raw_attempt = read("BILLING_RECEIPT_ATTEMPT_ID")?;
        let attempt = Uuid::parse_str(&raw_attempt)?;
        ensure!(
            attempt.get_version_num() == 4 && attempt.to_string() == raw_attempt,
            "canonical UUID v4 attempt required"
        );
        Ok(Self {
            database_url,
            webhook_secret,
            user_id,
            email,
            attempt,
        })
    }
}

fn validate_database_url(raw: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(raw)?;
    ensure!(
        url.scheme() == "postgres"
            && url.host_str() == Some("codewire-db-rw.dev.svc.cluster.local.")
            && url.port() == Some(5432)
            && url.username() == "codewire"
            && url.password().is_some_and(|p| !p.is_empty())
            && url.path() == "/codewire"
            && url.fragment().is_none()
            && url.query() == Some("sslmode=require"),
        "exact Dev database required"
    );
    Ok(())
}

struct Fixture {
    org: String,
    slug: String,
    member: String,
    customer: String,
    invoice: String,
    event: String,
}

impl Fixture {
    fn new(attempt: Uuid) -> Self {
        let suffix = attempt.simple();
        Self {
            org: format!("org_dev_receipt_{suffix}"),
            slug: format!("dev-receipt-{suffix}"),
            member: format!("member_dev_receipt_{suffix}"),
            customer: format!("cus_dev_receipt_{suffix}"),
            invoice: format!("in_dev_receipt_{suffix}"),
            event: format!("evt_dev_receipt_{suffix}"),
        }
    }

    fn payload(&self) -> String {
        let mut event = invoice_paid_event(&self.event, &self.invoice, "", &self.customer);
        let invoice = &mut event["data"]["object"];
        // This is a synthetic paid invoice, not a Stripe charge or subscription.
        invoice["parent"] = serde_json::Value::Null;
        invoice["number"] = "DEV-RECEIPT-VERIFICATION".into();
        invoice["hosted_invoice_url"] = serde_json::Value::Null;
        invoice["invoice_pdf"] = serde_json::Value::Null;
        event.to_string()
    }
}

fn http_client() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()?)
}

async fn post_once(http: &Client, base: &str, secret: &str, payload: String) -> anyhow::Result<()> {
    // A timeout, error, redirect, or unexpected status is terminal. Never
    // replay this request: SES acceptance may precede an interrupted response.
    let response = http
        .post(format!("{base}/api/webhooks/stripe"))
        .header("content-type", "application/json")
        .header("stripe-signature", stripe_signature(secret, &payload))
        .body(payload)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK, "webhook not accepted");
    Ok(())
}

pub(super) async fn run() -> anyhow::Result<()> {
    let database_url_override_present =
        std::env::var_os("DATABASE_URL").is_some_and(|value| !value.is_empty());
    let config = Config::from_reader(required_env, database_url_override_present)?;
    let fixture = Fixture::new(config.attempt);
    ensure!(
        valid_organization_slug(&fixture.slug),
        "fixture slug is invalid"
    );
    let http = http_client()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = '10s'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET idle_in_transaction_session_timeout = '90s'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&config.database_url)
        .await?;

    // Hold the recipient's row stable across seeding, delivery, and proof.
    // SHARE blocks email changes/deletion while allowing ordinary reads and
    // FK checks. NOWAIT makes an existing account mutation fail closed.
    let mut recipient_guard = pool.begin().await?;
    // Serialize the entire attempt so a concurrent invocation cannot seed or
    // deliver the same deterministic fixture before its tombstone is visible.
    let owned: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&fixture.event)
            .fetch_one(&mut *recipient_guard)
            .await?;
    ensure!(owned, "attempt already running");
    let recipient: Option<String> = sqlx::query_scalar(
        "SELECT id FROM users WHERE id = $1 AND email = $2
         AND enabled AND email_verified FOR SHARE NOWAIT",
    )
    .bind(&config.user_id)
    .bind(&config.email)
    .fetch_optional(&mut *recipient_guard)
    .await?;
    ensure!(recipient.is_some(), "recipient mismatch");
    seed(&pool, &config, &fixture).await?;
    println!("billing-dev-receipt: owned fixture seeded; one attempt starting");
    post_once(
        &http,
        DEV_BILLING_URL,
        &config.webhook_secret,
        fixture.payload(),
    )
    .await?;

    let proven: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM stripe_invoices i
            JOIN organizations o ON o.id = i.org_id
            JOIN org_members m ON m.org_id = o.id
            JOIN users u ON u.id = m.user_id
            WHERE i.stripe_invoice_id = $1 AND i.org_id = $2
              AND i.receipt_sent_at IS NOT NULL AND i.status = 'paid'
              AND i.amount_paid = 4900 AND i.currency = 'usd'
              AND o.stripe_customer_id = $3 AND o.created_by = $4
              AND m.id = $5 AND m.role = 'owner' AND u.id = $4 AND u.email = $6
              AND (SELECT COUNT(*) FROM org_members WHERE org_id = $2) = 1
              AND (SELECT COUNT(*) FROM stripe_webhook_events
                   WHERE id = $7 AND event_type = 'invoice.paid') = 1
              AND (SELECT COUNT(*) FROM billing_events
                   WHERE org_id = $2 AND stripe_item_id = $1
                     AND event_type = 'invoice_paid') = 1
        )",
    )
    .bind(&fixture.invoice)
    .bind(&fixture.org)
    .bind(&fixture.customer)
    .bind(&config.user_id)
    .bind(&fixture.member)
    .bind(&config.email)
    .bind(&fixture.event)
    .fetch_one(&pool)
    .await?;
    ensure!(proven, "durable receipt proof missing");
    // Ensure the guard survived the bounded HTTP request before emitting proof.
    sqlx::query("SELECT 1")
        .execute(&mut *recipient_guard)
        .await?;
    println!("{RECEIPT}");
    recipient_guard.commit().await?;
    // Retain the complete synthetic fixture. Deleting the parent organization
    // could cascade through a concurrent product write that this harness does
    // not own, and a parent row lock cannot cover the visibility gap between
    // the seed commit and lock acquisition. The attempt UUID is the durable
    // tombstone; any cleanup is a separately reviewed operation.
    println!("billing-dev-receipt: owned fixture retained; attempt tombstone active");
    Ok(())
}

async fn seed(pool: &PgPool, config: &Config, fixture: &Fixture) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let used: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM stripe_webhook_events WHERE id = $1)")
            .bind(&fixture.event)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(!used, "attempt already consumed");
    // Plain INSERTs, no upsert: a retained or concurrent attempt must fail.
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by, stripe_customer_id)
         VALUES ($1, 'Dev receipt verification', $2, $3, $4)",
    )
    .bind(&fixture.org)
    .bind(&fixture.slug)
    .bind(&config.user_id)
    .bind(&fixture.customer)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'owner')")
        .bind(&fixture.member)
        .bind(&fixture.org)
        .bind(&config.user_id)
        .execute(&mut *tx)
        .await?;
    let receipt_absent: bool = sqlx::query_scalar(
        "INSERT INTO stripe_invoices
         (org_id, stripe_invoice_id, status, amount_due, amount_paid, currency, receipt_sent_at)
         VALUES ($1, $2, 'open', 4900, 0, 'usd', NULL)
         RETURNING receipt_sent_at IS NULL",
    )
    .bind(&fixture.org)
    .bind(&fixture.invoice)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(receipt_absent, "receipt already present");
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_slug_is_valid_and_deterministic_without_changing_attempt_identities() {
        let attempt = Uuid::parse_str("877b1810-bcb7-4e68-97df-cda73287ee3d").unwrap();
        let fixture = Fixture::new(attempt);
        let suffix = "877b1810bcb74e6897dfcda73287ee3d";
        assert_eq!(fixture.org, format!("org_dev_receipt_{suffix}"));
        assert!(!valid_organization_slug(&fixture.org));
        assert_eq!(fixture.slug, format!("dev-receipt-{suffix}"));
        assert_eq!(fixture.slug.len(), 44);
        assert!(valid_organization_slug(&fixture.slug));
        assert_eq!(fixture.slug, Fixture::new(attempt).slug);
        assert_eq!(fixture.member, format!("member_dev_receipt_{suffix}"));
        assert_eq!(fixture.customer, format!("cus_dev_receipt_{suffix}"));
        assert_eq!(fixture.invoice, format!("in_dev_receipt_{suffix}"));
        assert_eq!(fixture.event, format!("evt_dev_receipt_{suffix}"));
    }

    #[test]
    fn live_mode_requires_all_explicit_bindings_without_defaults() {
        let inputs = std::collections::HashMap::from([
            ("ENVIRONMENT", "dev"),
            ("BILLING_RUNTIME_BASE_URL", DEV_BILLING_URL),
            ("DB_HOST", "codewire-db-rw.dev.svc.cluster.local."),
            ("DB_PORT", "5432"),
            ("DB_USER", "codewire"),
            ("DB_PASSWORD", "synthetic"),
            ("DB_NAME", "codewire"),
            ("DB_SSLMODE", "require"),
            ("BILLING_RUNTIME_WEBHOOK_SECRET", "synthetic"),
            ("BILLING_RECEIPT_EXPECTED_USER_ID", "synthetic-user"),
            ("BILLING_RECEIPT_EXPECTED_EMAIL", "recipient@example.test"),
            (
                "BILLING_RECEIPT_ATTEMPT_ID",
                "877b1810-bcb7-4e68-97df-cda73287ee3d",
            ),
        ]);
        let parse = |values: &std::collections::HashMap<&str, &str>| {
            Config::from_reader(
                |name| {
                    values
                        .get(name)
                        .map(|v| v.to_string())
                        .ok_or_else(|| anyhow::anyhow!("missing"))
                },
                false,
            )
        };
        assert!(parse(&inputs).is_ok());
        for name in inputs.keys() {
            let mut missing = inputs.clone();
            missing.remove(name);
            assert!(parse(&missing).is_err(), "{name}");
        }
        for (name, value) in [
            ("ENVIRONMENT", "prod"),
            ("BILLING_RUNTIME_BASE_URL", "http://127.0.0.1:8081"),
            (
                "BILLING_RUNTIME_BASE_URL",
                "http://codewire-billing.dev.svc.cluster.local:8081/",
            ),
            ("DB_HOST", "codewire-db-rw.prod.svc.cluster.local."),
            ("DB_PORT", "6432"),
            ("DB_USER", "postgres"),
            ("DB_PASSWORD", ""),
            ("DB_NAME", "postgres"),
            ("DB_SSLMODE", "disable"),
            ("BILLING_RUNTIME_WEBHOOK_SECRET", ""),
            ("BILLING_RECEIPT_EXPECTED_USER_ID", ""),
            ("BILLING_RECEIPT_EXPECTED_EMAIL", "recipient@example.test\n"),
            (
                "BILLING_RECEIPT_ATTEMPT_ID",
                "00000000-0000-0000-0000-000000000000",
            ),
        ] {
            let mut invalid = inputs.clone();
            invalid.insert(name, value);
            assert!(parse(&invalid).is_err(), "{name}");
        }
        assert!(
            Config::from_reader(
                |name| {
                    inputs
                        .get(name)
                        .map(|v| v.to_string())
                        .ok_or_else(|| anyhow::anyhow!("missing"))
                },
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn database_binding_rejects_other_targets_and_overrides() {
        let good = "postgres://codewire:synthetic@codewire-db-rw.dev.svc.cluster.local.:5432/codewire?sslmode=require";
        validate_database_url(good).unwrap();
        for bad in [
            good.replace(".dev.svc.cluster.local.", ".prod.svc.cluster.local."),
            good.replace(".svc.cluster.local.", ".attacker.test"),
            good.replace("5432", "6432"),
            good.replace("/codewire?", "/postgres?"),
            good.replace("require", "disable"),
            good.replace("codewire:synthetic", "postgres:synthetic"),
            format!("{good}&host=other"),
            format!("{good}#ignored"),
        ] {
            assert!(validate_database_url(&bad).is_err());
        }
    }

    #[test]
    fn receipt_fixture_is_bound_synthetic_and_parses_as_ordinary_invoice_paid() {
        let attempt = Uuid::new_v4();
        let fixture = Fixture::new(attempt);
        assert_eq!(fixture.invoice, Fixture::new(attempt).invoice);
        assert_ne!(fixture.invoice, Fixture::new(Uuid::new_v4()).invoice);
        let payload = fixture.payload();
        let event = stripe_webhook::Webhook::construct_event(
            &payload,
            &stripe_signature("synthetic", &payload),
            "synthetic",
        )
        .unwrap();
        let stripe_webhook::EventObject::InvoicePaid(invoice) = event.data.object else {
            panic!("expected ordinary invoice.paid");
        };
        assert_eq!(invoice.id.as_deref(), Some(fixture.invoice.as_str()));
        assert_eq!(invoice.amount_paid, 4900);
        assert!(!invoice.livemode);
        assert!(invoice.parent.is_none());
        assert!(invoice.hosted_invoice_url.is_none());
        assert!(invoice.invoice_pdf.is_none());
    }

    #[tokio::test]
    async fn redirect_is_not_followed_and_failure_is_not_retried() {
        use axum::{Router, routing::post};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::OK,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let app = Router::new().route(
                "/api/webhooks/stripe",
                post(move || {
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        (status, [("location", "/api/webhooks/stripe")])
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = post_once(&http_client().unwrap(), &base, "synthetic", "{}".into()).await;
            assert_eq!(result.is_ok(), status == StatusCode::OK);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            server.abort();
        }
    }
}
