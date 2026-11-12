//! "Add credit" against a fake Stripe. The `db_` tests need `DATABASE_URL`
//! (the "credit purchase matrix" database lane) and skip without it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use codewire_server_core::auth::AuthUser;
use serde_json::{Value, json};
use sqlx::PgPool;
use stripe_webhook::Webhook;

use super::*;
use crate::checkout_sessions::FrontendOrigin;
use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;

const WEBHOOK_SECRET: &str = "whsec_add_credit_synthetic";
const SUCCESS_URL: &str = "https://app.codewire.test/acme/billing/?message=credit-paid";
const CANCEL_URL: &str = "https://app.codewire.test/acme/billing/?error=credit-cancelled";
const NANO_EUR_PER_CENT: i64 = 10_000_000;

#[test]
fn a_purchase_is_named_by_its_organization_request_and_amount() {
    let id = purchase_top_up_id("org-1", "request-0123456789", 10_000);
    assert_eq!(
        id,
        purchase_top_up_id("org-1", "request-0123456789", 10_000)
    );
    assert!(id.starts_with("credit-") && id.len() == 7 + 32, "{id}");
    for other in [
        purchase_top_up_id("org-2", "request-0123456789", 10_000),
        purchase_top_up_id("org-1", "request-0123456780", 10_000),
        purchase_top_up_id("org-1", "request-0123456789", 10_001),
        // The parts are length-prefixed, so moving a boundary changes it.
        purchase_top_up_id("org-1r", "equest-0123456789", 10_000),
    ] {
        assert_ne!(id, other);
    }
}

#[test]
fn a_request_id_is_sixteen_to_sixty_four_safe_characters() {
    for valid in ["0123456789abcdef", "A-b_C-d_0123456789", &"x".repeat(64)] {
        assert!(valid_request_id(valid), "{valid}");
    }
    for invalid in [
        "",
        "short",
        &"x".repeat(65),
        "0123456789abcdef!",
        "0123456789 abcdef",
    ] {
        assert!(!valid_request_id(invalid), "{invalid}");
    }
}

// ── A fake Stripe ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pay {
    Paid,
    Declined,
    AuthenticationRequired,
}

#[derive(Clone, Debug)]
struct Seen {
    method: Method,
    path: String,
    form: BTreeMap<String, String>,
    idempotency_key: Option<String>,
}

struct Fake {
    /// Names this fake's invoices: invoice ids are unique across every test.
    prefix: String,
    card: bool,
    pay: Pay,
    invoice_status: &'static str,
    invoices: u32,
    seen: Vec<Seen>,
}

type Shared = Arc<Mutex<Fake>>;

const CREATED: i64 = 1_781_100_000;

fn hosted_url(invoice_id: &str) -> String {
    format!("https://invoice.stripe.com/i/acct_fake/test_{invoice_id}")
}

fn invoice(id: &str, status: &str, customer: &str, amount: i64, metadata: Value) -> Value {
    json!({
        "id": id,
        "object": "invoice",
        "amount_due": amount,
        "amount_paid": if status == "paid" { amount } else { 0 },
        "amount_overpaid": 0,
        "amount_remaining": if status == "paid" { 0 } else { amount },
        "amount_shipping": 0,
        "attempt_count": 1,
        "attempted": status != "draft",
        "automatic_tax": {"enabled": false, "disabled_reason": null, "liability": null, "provider": null, "status": null},
        "billing_reason": "manual",
        "collection_method": "charge_automatically",
        "created": CREATED,
        "currency": "eur",
        "customer": customer,
        "default_tax_rates": [],
        "discounts": [],
        "issuer": {"type": "self", "account": null},
        "hosted_invoice_url": if status == "draft" { Value::Null } else { Value::String(hosted_url(id)) },
        "invoice_pdf": null,
        "lines": {"object": "list", "data": [], "has_more": false, "total_count": 0, "url": "/v1/invoices/lines"},
        "livemode": false,
        "metadata": metadata,
        "number": null,
        "parent": null,
        "payment_settings": {"default_mandate": null, "payment_method_options": null, "payment_method_types": null},
        "period_end": CREATED,
        "period_start": CREATED,
        "post_payment_credit_notes_amount": 0,
        "pre_payment_credit_notes_amount": 0,
        "starting_balance": 0,
        "status": status,
        "status_transitions": {"finalized_at": null, "marked_uncollectible_at": null, "paid_at": null, "voided_at": null},
        "subtotal": amount,
        "total": amount,
        "total_discount_amounts": [],
        "total_taxes": [],
        "webhooks_delivered_at": null
    })
}

fn customer(id: &str, card: bool) -> Value {
    json!({
        "id": id,
        "object": "customer",
        "created": CREATED,
        "livemode": false,
        "invoice_settings": {
            "custom_fields": null,
            "default_payment_method": if card { Value::String("pm_fake_card".into()) } else { Value::Null },
            "footer": null,
            "rendering_options": null
        }
    })
}

fn checkout_session(id: &str, fields: Value) -> Value {
    let mut session = json!({
        "id": id,
        "object": "checkout.session",
        "automatic_tax": {"enabled": false, "liability": null, "provider": null, "status": null},
        "created": CREATED,
        "custom_fields": [],
        "custom_text": {"after_submit": null, "shipping_address": null, "submit": null, "terms_of_service_acceptance": null},
        "expires_at": CREATED + 86_400,
        "livemode": false,
        "mode": "payment",
        "payment_method_types": ["card"],
        "payment_status": "unpaid",
        "shipping_options": [],
        "status": "open",
        "url": format!("https://checkout.stripe.com/c/pay/{id}")
    });
    for (key, value) in fields.as_object().into_iter().flatten() {
        session[key] = value.clone();
    }
    session
}

fn card_error(code: &str, decline_code: &str) -> (StatusCode, String) {
    let body = json!({"error": {
        "type": "card_error",
        "code": code,
        "decline_code": decline_code,
        "message": "synthetic decline"
    }});
    (StatusCode::PAYMENT_REQUIRED, body.to_string())
}

async fn stripe(
    State(fake): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let mut fake = fake.lock().unwrap();
    fake.seen.push(Seen {
        method: method.clone(),
        path: uri.path().to_owned(),
        form: form.clone(),
        idempotency_key: headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    });
    let segments: Vec<&str> = uri.path().trim_start_matches("/v1/").split('/').collect();
    let ok = |value: Value| (StatusCode::OK, value.to_string());
    let customer_of =
        |form: &BTreeMap<String, String>| form.get("customer").cloned().unwrap_or_default();
    let metadata = |form: &BTreeMap<String, String>| {
        let entries: serde_json::Map<String, Value> = form
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("metadata[")
                    .and_then(|key| key.strip_suffix(']'))
                    .map(|key| (key.to_owned(), Value::String(value.clone())))
            })
            .collect();
        Value::Object(entries)
    };
    match (method, segments.as_slice()) {
        (Method::GET, ["customers", id]) => ok(customer(id, fake.card)),
        (Method::POST, ["customers"]) => ok(customer("cus_fake_new", false)),
        (Method::POST, ["customers", id]) => ok(customer(id, true)),
        (Method::POST, ["invoices"]) => {
            fake.invoices += 1;
            let id = format!("in_{}_{}", fake.prefix, fake.invoices);
            ok(invoice(
                &id,
                "draft",
                &customer_of(&form),
                0,
                metadata(&form),
            ))
        }
        (Method::POST, ["invoiceitems"]) => ok(json!({
            "id": "ii_fake",
            "object": "invoiceitem",
            "amount": form.get("amount").and_then(|amount| amount.parse::<i64>().ok()).unwrap_or(0),
            "currency": "eur",
            "customer": customer_of(&form),
            "date": CREATED,
            "discountable": true,
            "livemode": false,
            "period": {"end": CREATED, "start": CREATED},
            "proration": false,
            "quantity": 1,
            "quantity_decimal": "1"
        })),
        (Method::POST, ["invoices", id, "finalize"]) => {
            ok(invoice(id, "open", "cus_fake", 0, json!({})))
        }
        (Method::POST, ["invoices", id, "pay"]) => match fake.pay {
            Pay::Paid => ok(invoice(id, "paid", "cus_fake", 0, json!({}))),
            Pay::Declined => card_error("card_declined", "insufficient_funds"),
            Pay::AuthenticationRequired => {
                card_error("authentication_required", "authentication_required")
            }
        },
        (Method::GET, ["invoices", id]) => {
            ok(invoice(id, fake.invoice_status, "cus_fake", 0, json!({})))
        }
        (Method::POST, ["checkout", "sessions"]) => ok(checkout_session("cs_test_fake", json!({}))),
        (Method::GET, ["payment_intents", id]) => ok(json!({
            "id": id,
            "object": "payment_intent",
            "payment_method": "pm_fake_card"
        })),
        _ => (
            StatusCode::NOT_FOUND,
            json!({"error": {"type": "invalid_request_error", "message": "unknown fake route"}})
                .to_string(),
        ),
    }
}

struct Harness {
    state: BillingState,
    fake: Shared,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(pool: PgPool, card: bool, pay: Pay) -> Self {
        static HARNESSES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let harness = HARNESSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fake = Arc::new(Mutex::new(Fake {
            prefix: format!("fake{}x{harness}", std::process::id()),
            card,
            pay,
            invoice_status: "open",
            invoices: 0,
            seen: Vec::new(),
        }));
        let app = Router::new().fallback(stripe).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = BillingState {
            pool,
            stripe: StripeHandle::for_test(&format!("http://{address}"))
                .with_webhook_secret(WEBHOOK_SECRET),
            email: EmailClient::disabled(),
            credit_enforcement: Default::default(),
            frontend_origin: FrontendOrigin::parse("https://app.codewire.test").unwrap(),
        };
        Self {
            state,
            fake,
            server,
        }
    }

    /// The id of this fake's `n`th invoice.
    fn invoice_id(&self, n: u32) -> String {
        format!("in_{}_{n}", self.fake.lock().unwrap().prefix)
    }

    fn seen(&self) -> Vec<Seen> {
        self.fake.lock().unwrap().seen.clone()
    }

    fn charges(&self) -> usize {
        self.seen()
            .iter()
            .filter(|seen| seen.method == Method::POST && seen.path.starts_with("/v1/invoices"))
            .count()
    }

    fn only(&self, method: Method, path: &str) -> Seen {
        let matching: Vec<Seen> = self
            .seen()
            .into_iter()
            .filter(|seen| seen.method == method && seen.path == path)
            .collect();
        assert_eq!(matching.len(), 1, "{method} {path}: {:?}", self.seen());
        matching[0].clone()
    }

    async fn deliver(&self, event_id: &str, event_type: &str, object: Value) {
        let event = json!({
            "id": event_id,
            "object": "event",
            "api_version": "2026-04-22.dahlia",
            "created": CREATED,
            "livemode": false,
            "pending_webhooks": 1,
            "request": null,
            "type": event_type,
            "data": {"object": object}
        })
        .to_string();
        let header = Webhook::generate_test_header(&event, WEBHOOK_SECRET, None);
        let event = Webhook::construct_event(&event, &header, WEBHOOK_SECRET).unwrap();
        crate::webhook::handle_webhook_event(&self.state, event)
            .await
            .unwrap();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

// ── Database fixtures ────────────────────────────────────────────────

async fn test_pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset; skipping the add credit database flow");
            return None;
        }
    };
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect add credit test database"),
    )
}

struct Fixture {
    organization_id: String,
    user_id: String,
    customer_id: String,
    events: Vec<String>,
}

impl Fixture {
    fn user(&self) -> AuthUser {
        AuthUser {
            user_id: self.user_id.clone(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        }
    }

    fn event(&mut self, name: &str) -> String {
        let id = format!("evt_{name}_{}", &self.organization_id[14..]);
        self.events.push(id.clone());
        id
    }
}

/// An organization owned by a new user, with a Stripe customer when
/// `with_customer` is set.
async fn seed(pool: &PgPool, role: &str, with_customer: bool) -> Fixture {
    let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(pool)
        .await
        .unwrap();
    let fixture = Fixture {
        organization_id: format!("org_addcredit_{namespace}"),
        user_id: format!("u_addcredit_{namespace}"),
        customer_id: format!("cus_fake_{}", &namespace[..8]),
        events: Vec::new(),
    };
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&fixture.user_id)
        .bind(format!("{namespace}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by, rate_card, stripe_customer_id) \
         VALUES ($1, 'Add credit', $2, $3, 'regular', $4)",
    )
    .bind(&fixture.organization_id)
    .bind(format!("add-credit-{}", &namespace[..8]))
    .bind(&fixture.user_id)
    .bind(with_customer.then_some(&fixture.customer_id))
    .execute(pool)
    .await
    .unwrap();
    if !role.is_empty() {
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) \
             VALUES (gen_random_uuid()::text, $1, $2, $3)",
        )
        .bind(&fixture.organization_id)
        .bind(&fixture.user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }
    fixture
}

async fn cleanup(pool: &PgPool, fixture: Fixture) {
    for event in &fixture.events {
        sqlx::query("DELETE FROM stripe_webhook_events WHERE id = $1")
            .bind(event)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM billing_events WHERE org_id = $1")
        .bind(&fixture.organization_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&fixture.organization_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&fixture.user_id)
        .execute(pool)
        .await
        .unwrap();
}

async fn adjust(pool: &PgPool, fixture: &Fixture, key: &str, cents: i64) {
    sqlx::query(
        "INSERT INTO billing_credit_ledger \
         (organization_id, entry_kind, amount_nano_eur, idempotency_key, actor_user_id, reason) \
         VALUES ($1, 'adjustment', $2, $3, 'test', 'test')",
    )
    .bind(&fixture.organization_id)
    .bind(cents * NANO_EUR_PER_CENT)
    .bind(key)
    .execute(pool)
    .await
    .unwrap();
}

async fn balance_cents(pool: &PgPool, fixture: &Fixture) -> i64 {
    let nano: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT balance_nano_eur FROM billing_credit_balances \
         WHERE organization_id = $1), 0)",
    )
    .bind(&fixture.organization_id)
    .fetch_one(pool)
    .await
    .unwrap();
    nano / NANO_EUR_PER_CENT
}

async fn exhausted(pool: &PgPool, fixture: &Fixture) -> bool {
    sqlx::query_scalar("SELECT credit_exhausted_at IS NOT NULL FROM organizations WHERE id = $1")
        .bind(&fixture.organization_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

type TopUp = (String, i32, Option<String>, Option<String>);

async fn top_ups(pool: &PgPool, fixture: &Fixture) -> Vec<TopUp> {
    sqlx::query_as(
        "SELECT state, amount_cents, stripe_invoice_id, failure_code FROM billing_top_ups \
         WHERE organization_id = $1 ORDER BY created_at",
    )
    .bind(&fixture.organization_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

fn purchase(amount_cents: i32, request_id: &str) -> AddCreditRequest {
    AddCreditRequest {
        amount_cents,
        request_id: request_id.to_owned(),
        success_url: SUCCESS_URL.to_owned(),
        cancel_url: CANCEL_URL.to_owned(),
    }
}

async fn buy(
    harness: &Harness,
    fixture: &Fixture,
    amount_cents: i32,
    request_id: &str,
) -> AppResult<AddCreditOutcome> {
    add_credit(
        &harness.state,
        &fixture.user(),
        &fixture.organization_id,
        purchase(amount_cents, request_id),
    )
    .await
}

// ── Saved card ───────────────────────────────────────────────────────

#[tokio::test]
async fn db_a_saved_card_is_charged_once_and_credited_at_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed(&pool, "owner", true).await;
    let harness = Harness::new(pool.clone(), true, Pay::Paid).await;
    // Out of credit: a purchase is how the owner gets going again.
    sqlx::query("UPDATE organizations SET credit_exhausted_at = now() WHERE id = $1")
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();

    let request = "paid-request-000000000001";
    assert_eq!(
        buy(&harness, &fixture, 10_000, request).await.unwrap(),
        AddCreditOutcome::Paid
    );
    let top_up_id = purchase_top_up_id(&fixture.organization_id, request, 10_000);
    assert_eq!(balance_cents(&pool, &fixture).await, 10_000);
    assert!(!exhausted(&pool, &fixture).await);
    assert_eq!(
        top_ups(&pool, &fixture).await,
        [("paid".to_owned(), 10_000, Some(harness.invoice_id(1)), None)]
    );
    // The same invoice path as an automatic top-up: a EUR invoice naming the
    // purchase, one item for the amount, paid off-session, every step keyed
    // on the top-up.
    let created = harness.only(Method::POST, "/v1/invoices");
    for (key, value) in [
        ("currency", "eur"),
        ("customer", fixture.customer_id.as_str()),
        ("metadata[kind]", "credit_top_up"),
        ("metadata[org_id]", fixture.organization_id.as_str()),
        ("metadata[top_up_id]", top_up_id.as_str()),
    ] {
        assert_eq!(
            created.form.get(key).map(String::as_str),
            Some(value),
            "{key}"
        );
    }
    let item = harness.only(Method::POST, "/v1/invoiceitems");
    assert_eq!(item.form.get("amount").map(String::as_str), Some("10000"));
    assert_eq!(item.form.get("currency").map(String::as_str), Some("eur"));
    let pay = harness.only(
        Method::POST,
        &format!("/v1/invoices/{}/pay", harness.invoice_id(1)),
    );
    assert_eq!(
        pay.form.get("off_session").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        pay.idempotency_key.as_deref(),
        Some(format!("cw-top-up-pay-{top_up_id}").as_str())
    );

    // A retry of the same request answers from the record and charges nothing.
    let charges = harness.charges();
    assert_eq!(
        buy(&harness, &fixture, 10_000, request).await.unwrap(),
        AddCreditOutcome::Paid
    );
    assert_eq!(harness.charges(), charges);
    assert_eq!(balance_cents(&pool, &fixture).await, 10_000);
    cleanup(&pool, fixture).await;
}

#[tokio::test]
async fn db_a_retried_purchase_resumes_its_own_charge() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed(&pool, "admin", true).await;
    let harness = Harness::new(pool.clone(), true, Pay::Paid).await;
    // The first attempt died after creating its top-up, before Stripe said
    // anything: the retry charges that same top-up, with the same keys.
    let request = "resumed-request-0000000001";
    let top_up_id = purchase_top_up_id(&fixture.organization_id, request, 5_000);
    sqlx::query(
        "INSERT INTO billing_top_ups (id, organization_id, amount_cents) VALUES ($1, $2, 5000)",
    )
    .bind(&top_up_id)
    .bind(&fixture.organization_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        buy(&harness, &fixture, 5_000, request).await.unwrap(),
        AddCreditOutcome::Paid
    );
    let created = harness.only(Method::POST, "/v1/invoices");
    assert_eq!(
        created.idempotency_key.as_deref(),
        Some(format!("cw-top-up-invoice-{top_up_id}").as_str())
    );
    assert_eq!(balance_cents(&pool, &fixture).await, 5_000);
    assert_eq!(top_ups(&pool, &fixture).await.len(), 1);
    cleanup(&pool, fixture).await;
}

#[tokio::test]
async fn db_a_charge_the_bank_holds_goes_to_its_invoice_and_its_payment_credits_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let mut fixture = seed(&pool, "owner", true).await;
    let harness = Harness::new(pool.clone(), true, Pay::AuthenticationRequired).await;
    adjust(&pool, &fixture, "funded", 500).await;

    let request = "sca-request-00000000000001";
    let top_up_id = purchase_top_up_id(&fixture.organization_id, request, 10_000);
    assert_eq!(
        buy(&harness, &fixture, 10_000, request).await.unwrap(),
        AddCreditOutcome::ActionRequired {
            payment_url: hosted_url(&harness.invoice_id(1))
        }
    );
    // Recorded and released: nothing credited yet, the pending slot is free
    // for automatic top-up, and a funded organization is not out of credit.
    assert_eq!(
        top_ups(&pool, &fixture).await,
        [(
            "failed".to_owned(),
            10_000,
            Some(harness.invoice_id(1)),
            Some("authentication_required".to_owned())
        )]
    );
    assert_eq!(balance_cents(&pool, &fixture).await, 500);
    assert!(!exhausted(&pool, &fixture).await);

    // A retry while the invoice is still open goes back to the same page,
    // without charging again.
    let charges = harness.charges();
    assert_eq!(
        buy(&harness, &fixture, 10_000, request).await.unwrap(),
        AddCreditOutcome::ActionRequired {
            payment_url: hosted_url(&harness.invoice_id(1))
        }
    );
    assert_eq!(harness.charges(), charges);
    harness.only(
        Method::GET,
        &format!("/v1/invoices/{}", harness.invoice_id(1)),
    );

    // The customer approves on Stripe: `invoice.paid` credits it, once.
    let paid = invoice(
        &harness.invoice_id(1),
        "paid",
        &fixture.customer_id,
        10_000,
        json!({"kind": "credit_top_up", "org_id": fixture.organization_id, "top_up_id": top_up_id}),
    );
    let first = fixture.event("sca_paid");
    harness.deliver(&first, "invoice.paid", paid.clone()).await;
    let again = fixture.event("sca_paid_again");
    harness.deliver(&again, "invoice.paid", paid).await;
    assert_eq!(balance_cents(&pool, &fixture).await, 10_500);
    assert_eq!(top_ups(&pool, &fixture).await[0].0, "paid");
    assert_eq!(
        buy(&harness, &fixture, 10_000, request).await.unwrap(),
        AddCreditOutcome::Paid
    );
    cleanup(&pool, fixture).await;
}

#[tokio::test]
async fn db_a_declined_card_charges_nothing_and_says_why() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed(&pool, "owner", true).await;
    let harness = Harness::new(pool.clone(), true, Pay::Declined).await;
    adjust(&pool, &fixture, "funded", 500).await;

    let request = "declined-request-000000001";
    let declined = AddCreditOutcome::Declined {
        code: "insufficient_funds".to_owned(),
    };
    assert_eq!(
        buy(&harness, &fixture, 2_500, request).await.unwrap(),
        declined
    );
    assert_eq!(
        top_ups(&pool, &fixture).await,
        [(
            "failed".to_owned(),
            2_500,
            Some(harness.invoice_id(1)),
            Some("insufficient_funds".to_owned())
        )]
    );
    assert_eq!(balance_cents(&pool, &fixture).await, 500);
    assert!(!exhausted(&pool, &fixture).await);

    // A retry says the same and charges nothing.
    let charges = harness.charges();
    assert_eq!(
        buy(&harness, &fixture, 2_500, request).await.unwrap(),
        declined
    );
    assert_eq!(harness.charges(), charges);
    cleanup(&pool, fixture).await;
}

#[tokio::test]
async fn db_a_top_up_under_way_refuses_a_purchase() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed(&pool, "owner", true).await;
    sqlx::query("INSERT INTO billing_top_ups (organization_id, amount_cents) VALUES ($1, 2000)")
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    for card in [true, false] {
        let harness = Harness::new(pool.clone(), card, Pay::Paid).await;
        assert_eq!(
            buy(&harness, &fixture, 10_000, "under-way-request-00000001")
                .await
                .unwrap(),
            AddCreditOutcome::InProgress,
            "card {card}"
        );
        assert_eq!(harness.charges(), 0);
        assert!(
            !harness
                .seen()
                .iter()
                .any(|seen| seen.path == "/v1/checkout/sessions")
        );
    }
    assert_eq!(top_ups(&pool, &fixture).await.len(), 1);
    assert_eq!(balance_cents(&pool, &fixture).await, 0);
    cleanup(&pool, fixture).await;
}

// ── No card ──────────────────────────────────────────────────────────

fn completed_session(
    fixture: &Fixture,
    customer: &str,
    top_up_id: &str,
    amount: i64,
    metadata_amount: i64,
) -> Value {
    checkout_session(
        "cs_test_fake",
        json!({
            "status": "complete",
            "payment_status": "paid",
            "amount_total": amount,
            "currency": "eur",
            "customer": customer,
            "payment_intent": "pi_fake",
            "metadata": {
                "kind": "credit_top_up",
                "org_id": fixture.organization_id,
                "top_up_id": top_up_id,
                "amount_cents": metadata_amount.to_string()
            },
            "url": null
        }),
    )
}

#[tokio::test]
async fn db_without_a_card_stripe_takes_the_card_and_the_payment_together() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let mut fixture = seed(&pool, "owner", false).await;
    let harness = Harness::new(pool.clone(), false, Pay::Paid).await;
    sqlx::query("UPDATE organizations SET credit_exhausted_at = now() WHERE id = $1")
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();

    let request = "checkout-request-000000001";
    let top_up_id = purchase_top_up_id(&fixture.organization_id, request, 25_000);
    assert_eq!(
        buy(&harness, &fixture, 25_000, request).await.unwrap(),
        AddCreditOutcome::ActionRequired {
            payment_url: "https://checkout.stripe.com/c/pay/cs_test_fake".to_owned()
        }
    );
    // A customer first, then one payment-mode session for the amount in
    // euros that saves the card for off-session top-ups and names the
    // purchase. Nothing is charged or held pending meanwhile.
    harness.only(Method::POST, "/v1/customers");
    let session = harness.only(Method::POST, "/v1/checkout/sessions");
    assert!(
        session
            .idempotency_key
            .as_deref()
            .is_some_and(|key| key.starts_with("cw-credit-checkout-")),
        "{session:?}"
    );
    for (key, value) in [
        ("mode", "payment"),
        ("customer", "cus_fake_new"),
        ("payment_method_types[0]", "card"),
        ("line_items[0][quantity]", "1"),
        ("line_items[0][price_data][currency]", "eur"),
        ("line_items[0][price_data][unit_amount]", "25000"),
        (
            "line_items[0][price_data][product_data][name]",
            "Codewire compute credit",
        ),
        ("payment_intent_data[setup_future_usage]", "off_session"),
        ("invoice_creation[enabled]", "true"),
        (
            "invoice_creation[invoice_data][metadata][kind]",
            "credit_checkout",
        ),
        ("metadata[kind]", "credit_top_up"),
        ("metadata[org_id]", fixture.organization_id.as_str()),
        ("metadata[top_up_id]", top_up_id.as_str()),
        ("metadata[amount_cents]", "25000"),
        ("success_url", SUCCESS_URL),
        ("cancel_url", CANCEL_URL),
    ] {
        assert_eq!(
            session.form.get(key).map(String::as_str),
            Some(value),
            "{key} in {:?}",
            session.form
        );
    }
    assert!(!session.form.contains_key("payment_method_types[1]"));
    assert_eq!(harness.charges(), 0);
    assert!(top_ups(&pool, &fixture).await.is_empty());

    // Stripe reports the paid session: credited once, the card becomes the
    // default, and the organization is funded again.
    let completed = completed_session(&fixture, "cus_fake_new", &top_up_id, 25_000, 25_000);
    let first = fixture.event("checkout_paid");
    harness
        .deliver(&first, "checkout.session.completed", completed.clone())
        .await;
    let again = fixture.event("checkout_paid_again");
    harness
        .deliver(&again, "checkout.session.completed", completed)
        .await;
    assert_eq!(balance_cents(&pool, &fixture).await, 25_000);
    assert!(!exhausted(&pool, &fixture).await);
    let saved: Vec<Seen> = harness
        .seen()
        .into_iter()
        .filter(|seen| seen.method == Method::POST && seen.path == "/v1/customers/cus_fake_new")
        .collect();
    assert!(!saved.is_empty());
    assert!(saved.iter().all(|seen| {
        seen.form
            .get("invoice_settings[default_payment_method]")
            .map(String::as_str)
            == Some("pm_fake_card")
    }));
    let provider: String = sqlx::query_scalar(
        "SELECT provider_object_id FROM billing_credit_ledger \
         WHERE organization_id = $1 AND entry_kind = 'top_up'",
    )
    .bind(&fixture.organization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(provider, "pi_fake");

    // A retry of the same request is already paid; no new page opens.
    let sessions = |harness: &Harness| {
        harness
            .seen()
            .iter()
            .filter(|seen| seen.path == "/v1/checkout/sessions")
            .count()
    };
    assert_eq!(
        buy(&harness, &fixture, 25_000, request).await.unwrap(),
        AddCreditOutcome::Paid
    );
    assert_eq!(sessions(&harness), 1);

    // A session whose paid amount is not what it was opened for, or that
    // another customer paid, credits nothing.
    let other = purchase_top_up_id(
        &fixture.organization_id,
        "checkout-request-000000002",
        5_000,
    );
    let wrong_amount = fixture.event("checkout_wrong_amount");
    harness
        .deliver(
            &wrong_amount,
            "checkout.session.completed",
            completed_session(&fixture, "cus_fake_new", &other, 500, 5_000),
        )
        .await;
    let wrong_customer = fixture.event("checkout_wrong_customer");
    harness
        .deliver(
            &wrong_customer,
            "checkout.session.completed",
            completed_session(&fixture, "cus_someone_else", &other, 5_000, 5_000),
        )
        .await;
    assert_eq!(balance_cents(&pool, &fixture).await, 25_000);
    cleanup(&pool, fixture).await;
}

// ── Who and what ─────────────────────────────────────────────────────

#[tokio::test]
async fn db_only_owners_and_admins_buy_credit_and_only_valid_amounts() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stranger = seed(&pool, "", true).await;
    let member = seed(&pool, "member", true).await;
    let owner = seed(&pool, "owner", true).await;
    let harness = Harness::new(pool.clone(), true, Pay::Paid).await;
    let request = "validation-request-0000001";

    assert!(matches!(
        buy(&harness, &stranger, 10_000, request).await,
        Err(AppError::NotFound(_))
    ));
    assert!(matches!(
        buy(&harness, &member, 10_000, request).await,
        Err(AppError::Forbidden)
    ));
    for amount in [0, 499, 100_001] {
        assert!(
            matches!(
                buy(&harness, &owner, amount, request).await,
                Err(AppError::Validation { .. })
            ),
            "{amount}"
        );
    }
    assert!(matches!(
        buy(&harness, &owner, 10_000, "short").await,
        Err(AppError::Validation { .. })
    ));
    let mut foreign = purchase(10_000, request);
    foreign.success_url = "https://elsewhere.test/billing".to_owned();
    assert!(matches!(
        add_credit(
            &harness.state,
            &owner.user(),
            &owner.organization_id,
            foreign
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    // The bounds themselves are fine.
    assert_eq!(
        buy(&harness, &owner, 500, "validation-request-0000002")
            .await
            .unwrap(),
        AddCreditOutcome::Paid
    );
    assert_eq!(
        buy(&harness, &owner, 100_000, "validation-request-0000003")
            .await
            .unwrap(),
        AddCreditOutcome::Paid
    );
    assert_eq!(balance_cents(&pool, &owner).await, 100_500);
    for fixture in [stranger, member, owner] {
        cleanup(&pool, fixture).await;
    }
}
