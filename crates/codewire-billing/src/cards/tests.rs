//! Saved cards against a fake Stripe. The `db_` tests need `DATABASE_URL`
//! (the "saved cards" database lane) and skip without it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::credit_enforcement::CreditEnforcement;
use serde_json::{Value, json};
use sqlx::PgPool;

use super::*;
use crate::checkout_sessions::FrontendOrigin;
use crate::credit_purchase::tests::invoice;
use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;

const CREATED: i64 = 1_781_100_000;

/// The client address every setup comes from, unless a test says otherwise.
/// Each harness hashes it under a key of its own fixture's user, so tests
/// sharing a database don't share the address count.
const ADDRESS: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)));

/// A SetupIntent the fake holds: what Begin wrote, and when.
struct Intent {
    metadata: HashMap<String, String>,
    created: i64,
}

/// The fake account: one customer's cards, its default, and its
/// SetupIntents.
struct Fake {
    customer: String,
    cards: Vec<(String, String)>,
    default: Option<String>,
    intents: HashMap<String, Intent>,
    /// Every SetupIntent's status.
    setup_status: &'static str,
    /// The customer the SetupIntents name, when not the organization's.
    setup_customer: Option<String>,
    /// Drops metadata updates, as if each finish read the SetupIntent before
    /// another wrote its mark: two finishes at the same moment.
    marks_lost: bool,
    detached: Vec<String>,
    /// The amount of each invoice item, in cents: one per charge.
    charged: Vec<i64>,
    invoices: u32,
    /// Stripe's answer to each idempotency key: a repeat gets the first
    /// answer and changes nothing.
    replies: HashMap<String, (StatusCode, String)>,
}

type Shared = Arc<Mutex<Fake>>;

fn card(id: &str, last4: &str, customer: &str) -> Value {
    json!({
        "id": id,
        "object": "payment_method",
        "created": CREATED,
        "livemode": false,
        "type": "card",
        "customer": customer,
        "billing_details": {"address": null, "email": null, "name": null, "phone": null, "tax_id": null},
        "card": {"brand": "visa", "exp_month": 8, "exp_year": 2028, "funding": "credit", "last4": last4}
    })
}

fn setup_intent(fake: &Fake, id: &str) -> Value {
    let intent = &fake.intents[id];
    let status = fake.setup_status;
    json!({
        "id": id,
        "object": "setup_intent",
        "created": intent.created,
        "livemode": false,
        "client_secret": format!("{id}_secret_fake"),
        "customer": fake.setup_customer.as_ref().unwrap_or(&fake.customer),
        "metadata": intent.metadata,
        "payment_method": if status == "succeeded" { Value::String("pm_new".into()) } else { Value::Null },
        "payment_method_types": ["card"],
        "status": status,
        "usage": "off_session",
        "automatic_payment_methods": null,
        "excluded_payment_method_types": null,
        "payment_method_configuration_details": null
    })
}

/// The `metadata[key]` fields of a form body.
fn form_metadata(form: &[(String, String)]) -> HashMap<String, String> {
    form.iter()
        .filter_map(|(key, value)| {
            let key = key.strip_prefix("metadata[")?.strip_suffix(']')?;
            Some((key.to_owned(), value.clone()))
        })
        .collect()
}

async fn stripe(
    State(fake): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    let mut fake = fake.lock().unwrap();
    let key = headers
        .get("idempotency-key")
        .and_then(|key| key.to_str().ok())
        .map(str::to_owned);
    if let Some(reply) = key.as_ref().and_then(|key| fake.replies.get(key)) {
        return reply.clone();
    }
    let reply = answer(&mut fake, method, &uri, &body);
    if let Some(key) = key {
        fake.replies.insert(key, reply.clone());
    }
    reply
}

fn answer(fake: &mut Fake, method: Method, uri: &Uri, body: &Bytes) -> (StatusCode, String) {
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
    let customer = fake.customer.clone();
    let parts: Vec<&str> = uri.path().trim_start_matches("/v1/").split('/').collect();
    let ok = |value: Value| (StatusCode::OK, value.to_string());
    let missing = || {
        (
            StatusCode::NOT_FOUND,
            json!({"error": {"type": "invalid_request_error", "code": "resource_missing", "message": "no such object"}})
                .to_string(),
        )
    };
    match (method, parts.as_slice()) {
        (Method::GET, ["customers", id, "payment_methods"]) if *id == customer => ok(json!({
            "object": "list",
            "url": format!("/v1/customers/{customer}/payment_methods"),
            "has_more": false,
            "data": fake.cards.iter().map(|(id, last4)| card(id, last4, &customer)).collect::<Vec<_>>()
        })),
        (Method::GET, ["customers", id]) if *id == customer => ok(json!({
            "id": customer, "object": "customer", "created": CREATED, "livemode": false,
            "invoice_settings": {"custom_fields": null, "default_payment_method": fake.default,
                                 "footer": null, "rendering_options": null}
        })),
        (Method::POST, ["customers", id]) if *id == customer => {
            if let Some((_, default)) = form
                .iter()
                .find(|(key, _)| key == "invoice_settings[default_payment_method]")
            {
                fake.default = Some(default.clone());
            }
            ok(json!({"id": customer, "object": "customer", "created": CREATED, "livemode": false}))
        }
        // Ids as long as Stripe's, so they pass as a purchase's attempt key.
        (Method::POST, ["setup_intents"]) => {
            let id = format!("seti_fake{:020}", fake.intents.len() + 1);
            let intent = Intent {
                metadata: form_metadata(&form),
                created: chrono::Utc::now().timestamp(),
            };
            fake.intents.insert(id.clone(), intent);
            ok(setup_intent(fake, &id))
        }
        (Method::POST, ["setup_intents", id]) if fake.intents.contains_key(*id) => {
            if !fake.marks_lost {
                let update = form_metadata(&form);
                fake.intents.get_mut(*id).unwrap().metadata.extend(update);
            }
            ok(setup_intent(fake, id))
        }
        (Method::GET, ["setup_intents", id]) if fake.intents.contains_key(*id) => {
            if fake.setup_status == "succeeded"
                && !fake.cards.iter().any(|(card, _)| card == "pm_new")
            {
                fake.cards.insert(0, ("pm_new".into(), "4242".into()));
            }
            ok(setup_intent(fake, id))
        }
        (_, ["setup_intents", ..]) => missing(),
        // A top-up or a purchase: an invoice with one item, paid at once.
        // Invoice ids are unique across every test sharing the database,
        // as billing_top_ups requires: named by this fixture's customer.
        (Method::POST, ["invoices"]) => {
            fake.invoices += 1;
            let id = format!(
                "in_{}_{}",
                customer.trim_start_matches("cus_"),
                fake.invoices
            );
            ok(invoice(&id, "draft", &customer, 0, json!({})))
        }
        (Method::POST, ["invoiceitems"]) => {
            let amount = form
                .iter()
                .find(|(key, _)| key == "amount")
                .and_then(|(_, amount)| amount.parse::<i64>().ok())
                .unwrap_or(0);
            fake.charged.push(amount);
            ok(json!({
                "id": "ii_cards", "object": "invoiceitem", "amount": amount, "currency": "usd",
                "customer": customer, "date": CREATED, "discountable": true, "livemode": false,
                "period": {"end": CREATED, "start": CREATED}, "proration": false,
                "quantity": 1, "quantity_decimal": "1"
            }))
        }
        (Method::POST, ["invoices", id, "finalize"]) => {
            ok(invoice(id, "open", &customer, 0, json!({})))
        }
        (Method::POST, ["invoices", id, "pay"]) => ok(invoice(id, "paid", &customer, 0, json!({}))),
        (Method::GET, ["invoices", id]) => ok(invoice(id, "paid", &customer, 0, json!({}))),
        (Method::POST, ["payment_methods", id, "detach"]) => {
            let id = (*id).to_owned();
            fake.cards.retain(|(card, _)| *card != id);
            fake.detached.push(id.clone());
            ok(card(&id, "0000", &customer))
        }
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
    async fn new(pool: PgPool, fixture: &Fixture) -> Self {
        Self::enforcing(pool, fixture, CreditEnforcement::Off).await
    }

    async fn enforcing(pool: PgPool, fixture: &Fixture, enforcement: CreditEnforcement) -> Self {
        let fake = Arc::new(Mutex::new(Fake {
            customer: fixture.customer_id.clone(),
            cards: vec![
                ("pm_old".into(), "1111".into()),
                ("pm_older".into(), "2222".into()),
            ],
            default: Some("pm_old".into()),
            intents: HashMap::new(),
            setup_status: "succeeded",
            setup_customer: None,
            marks_lost: false,
            detached: Vec::new(),
            charged: Vec::new(),
            invoices: 0,
            replies: HashMap::new(),
        }));
        let app = Router::new().fallback(stripe).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = BillingState {
            pool,
            stripe: StripeHandle::for_test(&format!("http://{address}")),
            email: EmailClient::disabled(),
            credit_enforcement: enforcement,
            receipts: Default::default(),
            frontend_origin: FrontendOrigin::parse("https://app.codewire.test").unwrap(),
            operator_email: None,
            card_setup_address_key: CardSetupAddressKey::for_test(&fixture.user_id),
        };
        Self {
            state,
            fake,
            server,
        }
    }

    /// A SetupIntent made by hand rather than by Begin, with `metadata`.
    fn intent(&self, metadata: &[(&str, &str)], created: i64) -> String {
        let mut fake = self.fake.lock().unwrap();
        let id = format!("seti_hand{:020}", fake.intents.len() + 1);
        let metadata = metadata
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        fake.intents
            .insert(id.clone(), Intent { metadata, created });
        id
    }

    /// Whether Finish marked `id` finished.
    fn marked(&self, id: &str) -> bool {
        self.fake.lock().unwrap().intents[id]
            .metadata
            .contains_key("finished_at")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn test_pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset; skipping the saved cards database flow");
            return None;
        }
    };
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect saved cards test database"),
    )
}

struct Fixture {
    organization_id: String,
    user_id: String,
    customer_id: String,
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
}

/// An organization with a Stripe customer, and a user with `role` in it.
async fn seed(pool: &PgPool, role: &str) -> Fixture {
    let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(pool)
        .await
        .unwrap();
    let fixture = Fixture {
        organization_id: format!("org_cards_{namespace}"),
        user_id: format!("u_cards_{namespace}"),
        customer_id: format!("cus_cards_{}", &namespace[..8]),
    };
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&fixture.user_id)
        .bind(format!("{namespace}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by, stripe_customer_id) \
         VALUES ($1, 'Cards', $2, $3, $4)",
    )
    .bind(&fixture.organization_id)
    .bind(format!("cards-{}", &namespace[..8]))
    .bind(&fixture.user_id)
    .bind(&fixture.customer_id)
    .execute(pool)
    .await
    .unwrap();
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
    fixture
}

fn ids(list: &CardList) -> Vec<&str> {
    list.cards.iter().map(|card| card.id.as_str()).collect()
}

/// Top-up on at €20, no credit: "Save card and pay €20".
const TOP_UP: CardChoices = CardChoices {
    auto_top_up_enabled: true,
    auto_top_up_cents: 2000,
    credit_cents: None,
};

/// Top-up off, no credit: "Save card".
const CARD_ONLY: CardChoices = CardChoices {
    auto_top_up_enabled: false,
    auto_top_up_cents: 5000,
    credit_cents: None,
};

/// The SetupIntent a Begin made: the one before `_secret_fake`.
fn begun(setup: &CardSetup) -> String {
    setup
        .client_secret
        .trim_end_matches("_secret_fake")
        .to_owned()
}

async fn top_up_setting(pool: &PgPool, org: &str) -> (bool, i32) {
    sqlx::query_as("SELECT auto_top_up_enabled, auto_top_up_cents FROM organizations WHERE id = $1")
        .bind(org)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[test]
fn a_finish_needs_begins_fields_and_comes_within_the_hour_and_once() {
    let begin = CardChoices {
        credit_cents: Some(10_000),
        ..TOP_UP
    };
    let metadata = begin.metadata("org_x");
    let hour = i64::try_from(CARD_SETUP_FINISH_WINDOW.as_secs()).unwrap();
    assert_eq!(hour, 3600);

    // Within the hour, Begin's choices come back as they were.
    assert_eq!(
        finishable_choices(Some(&metadata), 1_000, 1_000).unwrap(),
        begin
    );
    assert_eq!(
        finishable_choices(Some(&metadata), 1_000, 1_000 + hour).unwrap(),
        begin
    );
    // A second later, or once marked, it can't be finished.
    for (metadata, now) in [
        (metadata.clone(), 1_000 + hour + 1),
        (
            {
                let mut marked = metadata.clone();
                marked.insert("finished_at".into(), "2026-11-15T23:00:00Z".into());
                marked
            },
            1_000,
        ),
    ] {
        let refused = finishable_choices(Some(&metadata), 1_000, now);
        assert!(matches!(refused, Err(AppError::Conflict(_))), "{refused:?}");
    }
    // A field missing or outside what Begin accepts: refused, never guessed.
    let broken: [&[(&str, &str)]; 6] = [
        &[],
        &[("org_id", "org_x")],
        &[("org_id", "org_x"), ("auto_top_up", "true")],
        &[("auto_top_up", "yes"), ("auto_top_up_cents", "2000")],
        &[("auto_top_up", "true"), ("auto_top_up_cents", "499")],
        &[
            ("auto_top_up", "false"),
            ("auto_top_up_cents", "2000"),
            ("credit_cents", "100001"),
        ],
    ];
    for fields in broken {
        let metadata: HashMap<String, String> = fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let refused = finishable_choices(Some(&metadata), 1_000, 1_000);
        assert!(
            matches!(refused, Err(AppError::Conflict(_))),
            "{fields:?}: {refused:?}"
        );
    }
    assert!(finishable_choices(None, 1_000, 1_000).is_err());
}

#[tokio::test]
async fn db_cards_are_listed_a_default_is_chosen_and_removing_it_moves_the_default() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::new(pool.clone(), &owner).await;
    let state = &harness.state;
    let user = owner.user();
    let org = owner.organization_id.as_str();

    let list = list_cards(state, &user, org).await.unwrap();
    assert_eq!(ids(&list), ["pm_old", "pm_older"]);
    assert_eq!(list.default_id.as_deref(), Some("pm_old"));
    assert_eq!(list.cards[0].card.as_ref().unwrap().last4, "1111");
    // The card form mounts with the publishable key, before any SetupIntent.
    assert!(list.publishable_key.unwrap().starts_with("pk_test_"));

    set_default_card(state, &user, org, "pm_older")
        .await
        .unwrap();
    assert_eq!(
        list_cards(state, &user, org)
            .await
            .unwrap()
            .default_id
            .as_deref(),
        Some("pm_older")
    );
    // Switching back works: each switch has its own idempotency key.
    set_default_card(state, &user, org, "pm_old").await.unwrap();
    set_default_card(state, &user, org, "pm_older")
        .await
        .unwrap();
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_older")
    );

    // Removing the default moves it to the newest card left.
    remove_card(state, &user, org, "pm_older").await.unwrap();
    let list = list_cards(state, &user, org).await.unwrap();
    assert_eq!(ids(&list), ["pm_old"]);
    assert_eq!(list.default_id.as_deref(), Some("pm_old"));

    // A card that isn't the organization's is not found, and nothing changes.
    for result in [
        set_default_card(state, &user, org, "pm_someone_elses").await,
        remove_card(state, &user, org, "pm_someone_elses").await,
    ] {
        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }
    assert_eq!(harness.fake.lock().unwrap().detached, ["pm_older"]);
}

#[tokio::test]
async fn db_a_finished_setup_makes_its_card_the_default_and_saves_the_top_up_setting_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::new(pool.clone(), &owner).await;
    let state = &harness.state;
    let user = owner.user();
    let org = owner.organization_id.as_str();

    let setup = begin_card_setup(state, &user, org, CARD_ONLY, ADDRESS)
        .await
        .unwrap();
    let intent = begun(&setup);

    // Not yet confirmed in the form: nothing is saved.
    harness.fake.lock().unwrap().setup_status = "requires_action";
    let refused = finish_card_setup(state, &user, org, &intent).await;
    assert!(matches!(refused, Err(AppError::Conflict(_))), "{refused:?}");
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_old")
    );
    assert!(!harness.marked(&intent));

    // Confirmed: its card is the default and Begin's setting saved. This
    // deployment doesn't enforce credit, so nothing is charged.
    harness.fake.lock().unwrap().setup_status = "succeeded";
    let settled = finish_card_setup(state, &user, org, &intent).await.unwrap();
    assert_eq!(
        settled,
        CardSetupResult {
            settlement: Settlement::NotEnforced,
            credit: None,
            auto_top_up_enabled: false,
        }
    );
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_new")
    );
    assert_eq!(top_up_setting(&pool, org).await, (false, 5000));
    assert!(harness.marked(&intent));

    // Finishing it again, say from a replayed return link, changes nothing:
    // not the default the admin chose since, nor the setting.
    set_default_card(state, &user, org, "pm_old").await.unwrap();
    crate::overview::update_auto_top_up(&pool, &user, org, true, 3000)
        .await
        .unwrap();
    let again = finish_card_setup(state, &user, org, &intent).await;
    assert!(matches!(again, Err(AppError::Conflict(_))), "{again:?}");
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_old")
    );
    assert_eq!(top_up_setting(&pool, org).await, (true, 3000));
}

#[tokio::test]
async fn db_another_organizations_setup_and_a_member_are_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::new(pool.clone(), &owner).await;
    let state = &harness.state;

    // The SetupIntent names another organization: not found, nothing saved.
    let theirs = harness.intent(
        &[
            ("org_id", "org_someone_else"),
            ("auto_top_up", "true"),
            ("auto_top_up_cents", "2000"),
        ],
        chrono::Utc::now().timestamp(),
    );
    let refused = finish_card_setup(state, &owner.user(), &owner.organization_id, &theirs).await;
    assert!(matches!(refused, Err(AppError::NotFound(_))), "{refused:?}");
    // One Stripe doesn't know: not found either.
    let unknown = finish_card_setup(
        state,
        &owner.user(),
        &owner.organization_id,
        "seti_unknown00000000000000000",
    )
    .await;
    assert!(unknown.is_err(), "{unknown:?}");
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_old")
    );

    // A member may see the cards but not change them.
    let member = seed(&pool, "member").await;
    let member_harness = Harness::new(pool.clone(), &member).await;
    let member_state = &member_harness.state;
    assert_eq!(
        ids(
            &list_cards(member_state, &member.user(), &member.organization_id)
                .await
                .unwrap()
        ),
        ["pm_old", "pm_older"]
    );
    for result in [
        set_default_card(
            member_state,
            &member.user(),
            &member.organization_id,
            "pm_older",
        )
        .await,
        remove_card(
            member_state,
            &member.user(),
            &member.organization_id,
            "pm_older",
        )
        .await,
    ] {
        assert!(result.is_err(), "a member changed a card: {result:?}");
    }
    assert!(
        begin_card_setup(
            member_state,
            &member.user(),
            &member.organization_id,
            TOP_UP,
            ADDRESS
        )
        .await
        .is_err()
    );
    assert!(member_harness.fake.lock().unwrap().intents.is_empty());
}

/// The organization's credit balance, in cents.
async fn balance_cents(pool: &PgPool, org: &str) -> i64 {
    let nano: Option<i64> = sqlx::query_scalar(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
    )
    .bind(org)
    .fetch_optional(pool)
    .await
    .unwrap();
    nano.unwrap_or(0) / 10_000_000
}

async fn purchases(pool: &PgPool, org: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM billing_top_ups WHERE organization_id = $1")
        .bind(org)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn db_a_new_card_with_no_credit_and_top_up_on_is_charged_the_top_up_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::enforcing(pool.clone(), &owner, CreditEnforcement::On).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());

    // "Save card and pay €20": the balance is empty and top-up is on.
    let intent = begun(
        &begin_card_setup(state, &user, org, TOP_UP, ADDRESS)
            .await
            .unwrap(),
    );
    let finished = finish_card_setup(state, &user, org, &intent).await.unwrap();
    assert_eq!(finished.settlement, Settlement::ToppedUp);
    assert_eq!(finished.credit, None);
    assert_eq!(harness.fake.lock().unwrap().charged, [2000]);
    assert_eq!(balance_cents(&pool, org).await, 2000);

    // A second finish of the same SetupIntent charges nothing more.
    assert!(finish_card_setup(state, &user, org, &intent).await.is_err());
    assert_eq!(harness.fake.lock().unwrap().charged, [2000]);
}

#[tokio::test]
async fn db_credit_bought_with_a_new_card_comes_first_so_top_up_charges_nothing_more() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::enforcing(pool.clone(), &owner, CreditEnforcement::On).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());

    // Add credit with no card yet: Pay €100, top-up on at €20. Only the
    // €100 is charged, and the organization is funded.
    let choices = CardChoices {
        credit_cents: Some(10_000),
        ..TOP_UP
    };
    let intent = begun(
        &begin_card_setup(state, &user, org, choices, ADDRESS)
            .await
            .unwrap(),
    );
    let finished = finish_card_setup(state, &user, org, &intent).await.unwrap();
    assert_eq!(
        finished.credit,
        Some(NewCardCredit {
            amount_cents: 10_000,
            outcome: AddCreditOutcome::Paid
        })
    );
    assert_eq!(finished.settlement, Settlement::Funded);
    assert_eq!(harness.fake.lock().unwrap().charged, [10_000]);
    assert_eq!(balance_cents(&pool, org).await, 10_000);
    assert_eq!(
        harness.fake.lock().unwrap().default.as_deref(),
        Some("pm_new")
    );
}

#[tokio::test]
async fn db_two_finishes_at_once_make_one_purchase_and_one_charge() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::enforcing(pool.clone(), &owner, CreditEnforcement::On).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());
    let choices = CardChoices {
        credit_cents: Some(10_000),
        ..TOP_UP
    };
    let intent = begun(
        &begin_card_setup(state, &user, org, choices, ADDRESS)
            .await
            .unwrap(),
    );

    // Neither finish sees the other's mark, so the ledger's key is all that
    // stands between them and a second charge.
    harness.fake.lock().unwrap().marks_lost = true;
    let (first, second) = tokio::join!(
        finish_card_setup(state, &user, org, &intent),
        finish_card_setup(state, &user, org, &intent),
    );
    assert!(first.is_ok() || second.is_ok(), "{first:?} {second:?}");
    // And one after both, still unmarked.
    let _third = finish_card_setup(state, &user, org, &intent).await;
    assert_eq!(harness.fake.lock().unwrap().charged, [10_000]);
    assert_eq!(purchases(&pool, org).await, 1);
    assert_eq!(balance_cents(&pool, org).await, 10_000);
}

#[tokio::test]
async fn db_a_crafted_return_buys_nothing_and_changes_no_setting() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::enforcing(pool.clone(), &owner, CreditEnforcement::On).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());
    crate::overview::update_auto_top_up(&pool, &user, org, false, 5000)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp();

    // Succeeded SetupIntents of this organization that a link could name:
    // one with no choices from a Begin, one with choices Begin would
    // refuse, and one past the hour.
    let refused_intents = [
        harness.intent(&[("org_id", org)], now),
        harness.intent(
            &[
                ("org_id", org),
                ("auto_top_up", "true"),
                ("auto_top_up_cents", "2000"),
                ("credit_cents", "999999"),
            ],
            now,
        ),
        harness.intent(
            &[
                ("org_id", org),
                ("auto_top_up", "true"),
                ("auto_top_up_cents", "2000"),
                ("credit_cents", "10000"),
            ],
            now - 3601,
        ),
    ];
    for intent in &refused_intents {
        let refused = finish_card_setup(state, &user, org, intent).await;
        assert!(
            matches!(refused, Err(AppError::Conflict(_))),
            "{intent}: {refused:?}"
        );
    }
    {
        let fake = harness.fake.lock().unwrap();
        assert!(fake.charged.is_empty(), "{:?}", fake.charged);
        assert_eq!(fake.default.as_deref(), Some("pm_old"));
    }
    assert_eq!(top_up_setting(&pool, org).await, (false, 5000));
    assert_eq!(purchases(&pool, org).await, 0);

    // The admin's own card setup, finished in the page, then the same
    // return replayed with a fresh link: it applies once, as chosen.
    let intent = begun(
        &begin_card_setup(state, &user, org, CARD_ONLY, ADDRESS)
            .await
            .unwrap(),
    );
    finish_card_setup(state, &user, org, &intent).await.unwrap();
    assert!(finish_card_setup(state, &user, org, &intent).await.is_err());
    assert!(harness.fake.lock().unwrap().charged.is_empty());
    assert_eq!(top_up_setting(&pool, org).await, (false, 5000));
    assert_eq!(purchases(&pool, org).await, 0);
}

#[tokio::test]
async fn db_bad_choices_are_refused_at_begin_and_another_customers_setup_changes_nothing() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::enforcing(pool.clone(), &owner, CreditEnforcement::On).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());

    // A top-up amount or a credit out of range is refused before any Stripe
    // call: no SetupIntent, no new default, no charge.
    for choices in [0, 499, 100_001]
        .map(|cents| CardChoices {
            auto_top_up_cents: cents,
            ..TOP_UP
        })
        .into_iter()
        .chain([CardChoices {
            credit_cents: Some(499),
            ..TOP_UP
        }])
    {
        let refused = begin_card_setup(state, &user, org, choices, ADDRESS).await;
        assert!(
            matches!(refused, Err(AppError::Validation { .. })),
            "{choices:?}: {refused:?}"
        );
    }
    assert!(harness.fake.lock().unwrap().intents.is_empty());

    // The SetupIntent names this organization but another customer.
    let intent = begun(
        &begin_card_setup(state, &user, org, TOP_UP, ADDRESS)
            .await
            .unwrap(),
    );
    harness.fake.lock().unwrap().setup_customer = Some("cus_someone_else".into());
    let refused = finish_card_setup(state, &user, org, &intent).await;
    assert!(matches!(refused, Err(AppError::NotFound(_))), "{refused:?}");

    {
        let fake = harness.fake.lock().unwrap();
        assert_eq!(fake.default.as_deref(), Some("pm_old"));
        assert!(fake.charged.is_empty(), "{:?}", fake.charged);
    }
    assert_eq!(balance_cents(&pool, org).await, 0);
}

#[tokio::test]
async fn db_an_organization_starts_at_most_ten_card_setups_an_hour() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::new(pool.clone(), &owner).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());
    for attempt in 1..=10 {
        begin_card_setup(state, &user, org, TOP_UP, ADDRESS)
            .await
            .unwrap_or_else(|error| panic!("setup {attempt}: {error:?}"));
    }
    // The eleventh says what was limited and when to try again.
    match begin_card_setup(state, &user, org, TOP_UP, ADDRESS).await {
        Err(AppError::Coded {
            code: "rate_limited",
            detail,
            ..
        }) => {
            assert!(
                detail.starts_with("at most 10 card setups an hour"),
                "{detail}"
            );
        }
        other => panic!("an eleventh setup was not refused: {other:?}"),
    }
}

/// Another organization owned by `owner`'s user, with its own customer.
async fn another_organization(pool: &PgPool, owner: &Fixture, tag: &str) -> Fixture {
    let fixture = Fixture {
        organization_id: format!("{}_{tag}", owner.organization_id),
        user_id: owner.user_id.clone(),
        customer_id: format!("{}{tag}", owner.customer_id),
    };
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by, stripe_customer_id) \
         VALUES ($1, 'Cards', $2, $3, $4)",
    )
    .bind(&fixture.organization_id)
    .bind(format!("cards-{}-{tag}", &owner.customer_id[10..]))
    .bind(&fixture.user_id)
    .bind(&fixture.customer_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role) \
         VALUES (gen_random_uuid()::text, $1, $2, 'owner')",
    )
    .bind(&fixture.organization_id)
    .bind(&fixture.user_id)
    .execute(pool)
    .await
    .unwrap();
    fixture
}

#[tokio::test]
async fn db_a_user_starts_at_most_twenty_card_setups_a_day_across_organizations() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let second = another_organization(&pool, &owner, "b").await;
    let third = another_organization(&pool, &owner, "c").await;
    let user = owner.user();
    // Ten in each of two organizations: each organization's own cap, and the
    // user's twenty a day.
    for fixture in [&owner, &second] {
        let harness = Harness::new(pool.clone(), fixture).await;
        for attempt in 1..=10 {
            begin_card_setup(
                &harness.state,
                &user,
                &fixture.organization_id,
                TOP_UP,
                ADDRESS,
            )
            .await
            .unwrap_or_else(|error| panic!("setup {attempt}: {error:?}"));
        }
    }
    // A third, fresh organization doesn't buy the user more tries.
    let harness = Harness::new(pool.clone(), &third).await;
    match begin_card_setup(
        &harness.state,
        &user,
        &third.organization_id,
        TOP_UP,
        ADDRESS,
    )
    .await
    {
        Err(AppError::Coded {
            code: "rate_limited",
            detail,
            ..
        }) => {
            assert!(
                detail.starts_with("at most 20 card setups a day"),
                "{detail}"
            );
        }
        other => panic!("a twenty-first setup was not refused: {other:?}"),
    }
}

#[tokio::test]
async fn db_a_setup_with_no_client_address_is_refused_before_anything_counts() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed(&pool, "owner").await;
    let harness = Harness::new(pool.clone(), &owner).await;
    let (state, user, org) = (&harness.state, owner.user(), owner.organization_id.as_str());
    match begin_card_setup(state, &user, org, TOP_UP, None).await {
        Err(AppError::Coded {
            code: "client_address_required",
            ..
        }) => {}
        other => panic!("a setup with no address was not refused: {other:?}"),
    }
    assert!(harness.fake.lock().unwrap().intents.is_empty());
    let counted: i64 = sqlx::query_scalar("SELECT count(*) FROM rate_limit WHERE key = ANY($1)")
        .bind(vec![
            CARD_SETUP_ORGANIZATION.key(org),
            CARD_SETUP_USER.key(&owner.user_id),
        ])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        counted, 0,
        "a refused setup spent the organization's or user's tries"
    );
}

#[tokio::test]
async fn db_accounts_on_one_client_address_share_its_sixty_setups_an_hour() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let ada = seed(&pool, "owner").await;
    let grace = seed(&pool, "owner").await;
    let ada_harness = Harness::new(pool.clone(), &ada).await;
    let mut grace_harness = Harness::new(pool.clone(), &grace).await;
    // One billing deployment, so one key, as in production.
    grace_harness.state.card_setup_address_key = ada_harness.state.card_setup_address_key.clone();
    // Fifty-eight setups already started from the address this hour, by
    // other accounts.
    let address = unit_hash(&ada_harness.state.card_setup_address_key.0, ADDRESS).unwrap();
    sqlx::query(
        "INSERT INTO rate_limit (id, key, count, last_request) \
         VALUES (gen_random_uuid()::text, $1, 58, \
                 (extract(epoch FROM clock_timestamp()) * 1000)::bigint)",
    )
    .bind(CARD_SETUP_ADDRESS.key(&address))
    .execute(&pool)
    .await
    .unwrap();

    for (harness, fixture) in [(&ada_harness, &ada), (&grace_harness, &grace)] {
        begin_card_setup(
            &harness.state,
            &fixture.user(),
            &fixture.organization_id,
            TOP_UP,
            ADDRESS,
        )
        .await
        .unwrap();
    }
    // The sixty-first from the address is refused, whoever starts it, while
    // the same account from another address is not.
    match begin_card_setup(
        &ada_harness.state,
        &ada.user(),
        &ada.organization_id,
        TOP_UP,
        ADDRESS,
    )
    .await
    {
        Err(AppError::Coded {
            code: "rate_limited",
            detail,
            ..
        }) => assert!(
            detail.starts_with("at most 60 card setups an hour"),
            "{detail}"
        ),
        other => panic!("a sixty-first setup from one address was not refused: {other:?}"),
    }
    let elsewhere = Some(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9)));
    begin_card_setup(
        &ada_harness.state,
        &ada.user(),
        &ada.organization_id,
        TOP_UP,
        elsewhere,
    )
    .await
    .unwrap();
}
