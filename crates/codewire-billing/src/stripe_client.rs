//! Stripe client handle for the billing service.
//!
//! Wraps `Option<stripe::Client>` with the same nil-safety the Go
//! `*billing.BillingClient` has: every method degrades to a harmless
//! default when Stripe isn't configured (`STRIPE_SECRET_KEY` unset),
//! mirroring `billing: disabled (no STRIPE_SECRET_KEY)` on the Go side.
//!
//! ## Idempotency keys
//!
//! Stripe remembers an idempotency key for 24 hours and refuses it with any
//! other parameters. Every idempotent call here is one of two kinds, named in
//! [`IDEMPOTENT_CALLS`]:
//!
//! - **Operation-keyed:** the key names one business operation (one customer
//!   per organization, one charge per top-up, one invoice item per billing
//!   period). A retry must never act twice, even when a parameter changed
//!   between a failed attempt and its retry, for example across a deploy, so
//!   the key ignores the parameters. A changed parameter then fails loudly
//!   for 24 hours instead of creating a second customer or charging twice.
//!   Every call that moves money or creates an identity is of this kind.
//! - **Parameter-keyed:** the call only opens a hosted Stripe page (checkout,
//!   card setup, billing portal) and moves no money, so a duplicate is
//!   harmless. Its key hashes the exact request sent, so a retry with the same
//!   parameters reuses the session, and any parameter change, by a user or by
//!   a new release, gets a new key rather than 24 hours of refusals (#3381:
//!   adding the currency stopped every add-card that had been tried in the
//!   previous day).

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use stripe::{IdempotencyKey, RequestStrategy, StripeRequest};
use stripe_billing::billing_portal_session::CreateBillingPortalSession;
use stripe_billing::invoice::{
    CreateInvoice, CreateInvoicePendingInvoiceItemsBehavior, FinalizeInvoiceInvoice, PayInvoice,
    RetrieveInvoice, SearchInvoice,
};
use stripe_billing::invoice_item::{CreateInvoiceItem, UpdateInvoiceItem};
use stripe_billing::subscription::{CancelSubscription, ListSubscription, RetrieveSubscription};
use stripe_billing::subscription_item::{
    UpdateSubscriptionItem, UpdateSubscriptionItemProrationBehavior,
};
use stripe_checkout::checkout_session::{
    CreateCheckoutSession, CreateCheckoutSessionInvoiceCreation,
    CreateCheckoutSessionInvoiceCreationInvoiceData, CreateCheckoutSessionLineItems,
    CreateCheckoutSessionLineItemsPriceData, CreateCheckoutSessionPaymentIntentData,
    CreateCheckoutSessionPaymentIntentDataSetupFutureUsage,
    CreateCheckoutSessionPaymentMethodTypes, ExpireCheckoutSession, ListCheckoutSession,
    ProductData,
};
use stripe_client_core::{RequestBuilder, StripeMethod};
use stripe_core::customer::{
    CreateCustomer, DeleteCustomer, ListPaymentMethodsCustomer, ListPaymentMethodsCustomerType,
    RetrieveCustomer, SearchCustomer, UpdateCustomer, UpdateCustomerInvoiceSettings,
};
use stripe_core::setup_intent::{
    CreateSetupIntent, CreateSetupIntentUsage, RetrieveSetupIntent, UpdateSetupIntent,
};

use codewire_server_core::AppError;

/// `on` makes billing refuse to start with anything but a test key, so a
/// test environment can never charge a real card. Unset, empty or `off`
/// accepts any key. Anything else is refused.
pub const REQUIRE_TEST_KEY_ENV: &str = "CODEWIRE_STRIPE_REQUIRE_TEST_KEY";

/// Applies [`REQUIRE_TEST_KEY_ENV`] to the configured key. No key means
/// billing is disabled, which charges nothing. The error never holds the key.
pub fn check_test_key_requirement(required: Option<&str>, key: Option<&str>) -> Result<(), String> {
    match required.map(str::trim) {
        None | Some("" | "off") => Ok(()),
        Some("on") => match key {
            None | Some("") => Ok(()),
            Some(key) if key.starts_with("sk_test_") || key.starts_with("rk_test_") => Ok(()),
            Some(_) => Err(format!(
                "{REQUIRE_TEST_KEY_ENV} is on, but STRIPE_SECRET_KEY is not a test key"
            )),
        },
        Some(value) => Err(format!(
            "{REQUIRE_TEST_KEY_ENV} must be \"on\" or \"off\"; got {value:?}"
        )),
    }
}

/// The one currency every Stripe call that names one uses: prices and credit
/// are in euros, so a charge, an invoice item or a card setup session in any
/// other currency is wrong (#3381).
pub(crate) const BILLING_CURRENCY: stripe_types::Currency = stripe_types::Currency::EUR;

/// How an idempotent Stripe call is keyed; see the module documentation.
/// Only the guard test reads it; outside tests it documents the contract.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdempotencyKind {
    Operation,
    Parameters,
}

/// Every idempotent Stripe call this client makes. A test fails when an
/// idempotent call is missing here or is keyed against its kind.
#[cfg_attr(not(test), allow(dead_code))]
const IDEMPOTENT_CALLS: &[(&str, IdempotencyKind)] = &[
    ("create_overage_invoice_item", IdempotencyKind::Operation),
    ("update_overage_invoice_item", IdempotencyKind::Operation),
    ("delete_invoice_item", IdempotencyKind::Operation),
    ("create_auto_advancing_invoice", IdempotencyKind::Operation),
    ("finalize_invoice", IdempotencyKind::Operation),
    ("ensure_customer", IdempotencyKind::Operation),
    ("expire_checkout_session", IdempotencyKind::Operation),
    ("cancel_subscription", IdempotencyKind::Operation),
    ("update_subscription_item", IdempotencyKind::Operation),
    ("set_default_payment_method", IdempotencyKind::Operation),
    ("charge_top_up", IdempotencyKind::Operation),
    ("create_portal_session", IdempotencyKind::Parameters),
    ("create_setup_session", IdempotencyKind::Parameters),
    (
        "create_credit_checkout_session",
        IdempotencyKind::Parameters,
    ),
];

/// The key of a parameter-keyed call: a hash of the request exactly as it is
/// serialized, with object keys sorted so a map's iteration order cannot
/// change it.
fn parameter_key(kind: &str, request: &impl serde::Serialize) -> Result<IdempotencyKey, AppError> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    fn feed(value: &serde_json::Value, hasher: &mut Sha256) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                hasher.update(b"{");
                for key in keys {
                    hasher.update((key.len() as u64).to_be_bytes());
                    hasher.update(key.as_bytes());
                    feed(&map[key], hasher);
                }
                hasher.update(b"}");
            }
            serde_json::Value::Array(items) => {
                hasher.update(b"[");
                for item in items {
                    feed(item, hasher);
                }
                hasher.update(b"]");
            }
            scalar => {
                let text = scalar.to_string();
                hasher.update((text.len() as u64).to_be_bytes());
                hasher.update(text.as_bytes());
            }
        }
    }

    let value = serde_json::to_value(request).map_err(|e| {
        AppError::InternalMsg(format!("stripe request is not serializable: {e}").into())
    })?;
    let mut hasher = Sha256::new();
    feed(&value, &mut hasher);
    let mut key = format!("cw-{kind}-");
    for byte in hasher.finalize() {
        let _ = write!(key, "{byte:02x}");
    }
    IdempotencyKey::new(key).map_err(stripe_err)
}

/// The publishable key, when it is of the secret key's mode: a test key with
/// a live account, or a live key with a test one, would make the card form
/// save cards into another account, so it is left out and the form refuses.
fn publishable_key_for(live: bool, key: Option<String>) -> Option<String> {
    let prefix = if live { "pk_live_" } else { "pk_test_" };
    match key {
        Some(key) if key.starts_with(prefix) => Some(key),
        Some(key) if !key.is_empty() => {
            tracing::error!(
                live,
                "STRIPE_PUBLISHABLE_KEY is not of the secret key's mode; the card form is off"
            );
            None
        }
        _ => None,
    }
}

#[derive(Clone, Default)]
pub struct StripeHandle {
    client: Option<Arc<stripe::Client>>,
    /// `sk_live_` key → live price rows, else test — mirrors
    /// `billing.stripeMode`.
    live: bool,
    webhook_secret: String,
    /// The publishable key the console's embedded card form uses (#4750),
    /// only when it is of the secret key's mode.
    publishable_key: Option<String>,
}

impl StripeHandle {
    /// Builds the handle from `STRIPE_SECRET_KEY`; unset/empty →
    /// billing disabled, same as the Go service.
    pub fn from_env() -> Self {
        let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
        match std::env::var("STRIPE_SECRET_KEY") {
            Ok(key) if !key.is_empty() => Self {
                publishable_key: publishable_key_for(
                    key.starts_with("sk_live_"),
                    std::env::var("STRIPE_PUBLISHABLE_KEY").ok(),
                ),
                live: key.starts_with("sk_live_"),
                client: Some(Arc::new(
                    stripe::ClientBuilder::new(key)
                        .timeout(Duration::from_secs(30))
                        .build()
                        .expect("valid Stripe client configuration"),
                )),
                webhook_secret,
            },
            _ => Self {
                client: None,
                live: false,
                webhook_secret,
                publishable_key: None,
            },
        }
    }

    /// A handle on a synthetic Stripe API at `api_base`. The production
    /// client keeps its 30 s request bound (`from_env`); no test is about it,
    /// so a test client only guards against a hang. A fixed 1 s bound failed
    /// a loopback request on a busy CI slot (PR run 24503).
    #[cfg(test)]
    pub(crate) fn for_test(api_base: &str) -> Self {
        Self {
            client: Some(Arc::new(
                stripe::ClientBuilder::new("sk_test_codewire")
                    .url(api_base)
                    .timeout(Duration::from_secs(60))
                    .build()
                    .expect("valid Stripe test client configuration"),
            )),
            live: false,
            webhook_secret: String::new(),
            publishable_key: Some("pk_test_codewire".to_owned()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_webhook_secret(mut self, secret: &str) -> Self {
        self.webhook_secret = secret.to_owned();
        self
    }

    pub fn webhook_secret(&self) -> &str {
        &self.webhook_secret
    }

    /// The publishable key for the console's embedded card form, when one of
    /// this account's mode is configured.
    pub fn publishable_key(&self) -> Option<&str> {
        self.publishable_key.as_deref()
    }

    /// `test` or `live`, for billing_catalog_prices lookups.
    pub fn stripe_mode(&self) -> &'static str {
        if self.live { "live" } else { "test" }
    }

    fn client(&self) -> Result<&stripe::Client, AppError> {
        self.client
            .as_deref()
            .ok_or_else(|| AppError::NotFound("billing is not enabled".into()))
    }

    pub fn is_configured(&self) -> bool {
        self.client.is_some()
    }

    /// Some(()) when Stripe is configured — ergonomic gate for the
    /// metering loops (mirrors the Go `bc == nil` checks).
    pub fn enabled(&self) -> Option<()> {
        self.client.as_ref().map(|_| ())
    }

    /// Mirrors `NewBillingClient`'s MinOverageCents: $1.00 in live
    /// mode, 0 in test mode.
    pub fn min_overage_cents(&self) -> i32 {
        if self.live { 100 } else { 0 }
    }

    /// Plain USD InvoiceItem for the overage flows (positive = charge,
    /// negative = admin credit). Returns the item ID.
    pub async fn create_overage_invoice_item(
        &self,
        customer_id: &str,
        amount_cents: i64,
        description: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let item = CreateInvoiceItem::new()
            .customer(customer_id)
            .amount(amount_cents)
            .currency(BILLING_CURRENCY)
            .description(description)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(item.id.to_string())
    }

    /// Reconciles an existing pending overage item to its cumulative
    /// month-to-date amount. This deliberately updates in place: deleting and
    /// recreating a pending Stripe item loses the stable provider identity.
    pub async fn update_overage_invoice_item(
        &self,
        item_id: &str,
        amount_cents: i64,
        description: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let item = UpdateInvoiceItem::new(item_id)
            .amount(amount_cents)
            .description(description)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(item.id.to_string())
    }

    /// Mirrors `bc.Client.V1InvoiceItems.Delete`.
    pub async fn delete_invoice_item(
        &self,
        item_id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        stripe_billing::invoice_item::DeleteInvoiceItem::new(item_id)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(())
    }

    /// Mirrors the overage flow's `V1Invoices.Create` with AutoAdvance.
    pub async fn create_auto_advancing_invoice(
        &self,
        customer_id: &str,
        description: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let inv = stripe_billing::invoice::CreateInvoice::new()
            .customer(customer_id)
            .auto_advance(true)
            .description(description)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        inv.id
            .map(|id| id.to_string())
            .ok_or_else(|| AppError::InternalMsg("stripe invoice create returned no id".into()))
    }

    /// Mirrors `V1Invoices.FinalizeInvoice`.
    pub async fn finalize_invoice(
        &self,
        invoice_id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        stripe_billing::invoice::FinalizeInvoiceInvoice::new(invoice_id)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(())
    }

    /// Mirrors `billing.OrgHasPaymentMethod`: false on any failure
    /// (no client, no customer, Stripe error, deleted customer) —
    /// the overview endpoint must not 500 because Stripe hiccuped.
    pub async fn org_has_payment_method(&self, pool: &PgPool, org_id: &str) -> bool {
        self.org_payment_method(pool, org_id, false).await.is_some()
    }

    /// The organization's default payment method, read with the same one
    /// Customers retrieve as [`Self::org_has_payment_method`], which also
    /// expands it to show the card. `None` on any failure, as there.
    pub async fn org_default_payment_method(
        &self,
        pool: &PgPool,
        org_id: &str,
    ) -> Option<DefaultPaymentMethod> {
        self.org_payment_method(pool, org_id, true).await
    }

    async fn org_payment_method(
        &self,
        pool: &PgPool,
        org_id: &str,
        expand: bool,
    ) -> Option<DefaultPaymentMethod> {
        self.try_org_payment_method(pool, org_id, expand)
            .await
            .ok()
            .flatten()
    }

    /// The organization's default card, for the admin credit question
    /// (#5094). `Ok(None)` only when there truly is none: Stripe not set up,
    /// no customer, no default method, or one that isn't a card. `Err` when
    /// the database or Stripe couldn't answer, so a card that may be charged
    /// is never reported as absent.
    pub async fn org_default_card(
        &self,
        pool: &PgPool,
        org_id: &str,
    ) -> Result<Option<CardSummary>, PaymentMethodUnavailable> {
        Ok(self
            .try_org_payment_method(pool, org_id, true)
            .await?
            .and_then(|method| method.card))
    }

    async fn try_org_payment_method(
        &self,
        pool: &PgPool,
        org_id: &str,
        expand: bool,
    ) -> Result<Option<DefaultPaymentMethod>, PaymentMethodUnavailable> {
        if !self.is_configured() {
            return Ok(None);
        }
        let Some(customer_id) = Self::org_customer_id(pool, org_id).await? else {
            return Ok(None);
        };
        self.try_default_payment_method(&customer_id, expand).await
    }

    /// The organization's Stripe customer ID, if it has one.
    async fn org_customer_id(
        pool: &PgPool,
        org_id: &str,
    ) -> Result<Option<String>, PaymentMethodUnavailable> {
        let customer_id: Option<Option<String>> =
            sqlx::query_scalar(r#"SELECT stripe_customer_id FROM organizations WHERE id = $1"#)
                .bind(org_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| PaymentMethodUnavailable)?;
        Ok(customer_id.flatten().filter(|id| !id.is_empty()))
    }

    /// The customer's `invoice_settings.default_payment_method`, expanded
    /// when `expand` is set. Nothing is logged: the expanded object carries
    /// the card's fingerprint, which only [`CardSummary::from_stripe`] reads
    /// past, keeping brand, last four digits and expiry.
    #[cfg(test)]
    pub(crate) async fn default_payment_method(
        &self,
        customer_id: &str,
        expand: bool,
    ) -> Option<DefaultPaymentMethod> {
        self.try_default_payment_method(customer_id, expand)
            .await
            .ok()
            .flatten()
    }

    /// As [`Self::default_payment_method`], telling a customer Stripe has no
    /// default for (or doesn't know, a 404) from a Stripe that couldn't
    /// answer.
    async fn try_default_payment_method(
        &self,
        customer_id: &str,
        expand: bool,
    ) -> Result<Option<DefaultPaymentMethod>, PaymentMethodUnavailable> {
        let Some(client) = self.client.as_deref() else {
            return Ok(None);
        };
        let mut request = RetrieveCustomer::new(customer_id);
        if expand {
            request = request.expand(["invoice_settings.default_payment_method".to_string()]);
        }
        let customer = match request.send(client).await {
            Ok(stripe_core::customer::RetrieveCustomerReturned::Customer(customer)) => customer,
            Ok(_) => return Ok(None),
            Err(error) if stripe_not_found(&error) => return Ok(None),
            Err(_) => return Err(PaymentMethodUnavailable),
        };
        let Some(method) = customer
            .invoice_settings
            .and_then(|settings| settings.default_payment_method)
        else {
            return Ok(None);
        };
        Ok(Some(DefaultPaymentMethod {
            card: match &method {
                stripe_types::Expandable::Object(method) => {
                    method.card.as_ref().and_then(CardSummary::from_stripe)
                }
                stripe_types::Expandable::Id(_) => None,
            },
        }))
    }
}

/// Stripe or the database couldn't say whether an organization has a card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentMethodUnavailable;

/// An organization's default payment method, as the billing overview shows
/// it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DefaultPaymentMethod {
    /// Set when the method is a card and Stripe expanded it.
    pub card: Option<CardSummary>,
}

/// What a receipt shows of a card. Never the number or the fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardSummary {
    /// Stripe's brand code, such as `visa` or `amex`.
    pub brand: String,
    pub last4: String,
    pub exp_month: i32,
    pub exp_year: i32,
}

impl CardSummary {
    /// `None` when Stripe's values are out of range, so a malformed card
    /// shows as a payment method without details rather than as nonsense.
    fn from_stripe(card: &stripe_shared::PaymentMethodCard) -> Option<Self> {
        let last4_ok = card.last4.len() == 4 && card.last4.bytes().all(|b| b.is_ascii_digit());
        let brand_ok = !card.brand.is_empty()
            && card.brand.len() <= 32
            && card
                .brand
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_');
        let exp_month = i32::try_from(card.exp_month).ok()?;
        let exp_year = i32::try_from(card.exp_year).ok()?;
        (last4_ok && brand_ok && (1..=12).contains(&exp_month) && (1000..=9999).contains(&exp_year))
            .then(|| Self {
                brand: card.brand.clone(),
                last4: card.last4.clone(),
                exp_month,
                exp_year,
            })
    }
}

// ── Session creation (Go: billing/checkout.go, portal.go, customer.go) ──

impl StripeHandle {
    /// Mirrors `billing.EnsureCustomer`: reuse `stripe_customer_id` or
    /// create the customer and persist the ID. A reused customer's email is
    /// set to `owner_email`, the address Stripe sends receipts to.
    pub async fn ensure_customer(
        &self,
        pool: &PgPool,
        org_id: &str,
        org_name: &str,
        owner_email: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;

        let existing: Option<Option<String>> =
            sqlx::query_scalar(r#"SELECT stripe_customer_id FROM organizations WHERE id = $1"#)
                .bind(org_id)
                .fetch_optional(pool)
                .await?;
        if let Some(Some(id)) = existing
            && !id.is_empty()
        {
            self.sync_customer_email(&id, owner_email).await;
            return Ok(id);
        }

        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let customer = CreateCustomer::new()
            .name(org_name)
            .email(owner_email)
            .metadata([("org_id".to_string(), org_id.to_string())])
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;

        sqlx::query(
            r#"UPDATE organizations SET stripe_customer_id = $2, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(org_id)
        .bind(customer.id.as_str())
        .execute(pool)
        .await?;

        Ok(customer.id.to_string())
    }

    /// Mirrors `billing.CreatePortalSession`. Parameter-keyed: see the module
    /// docs.
    pub async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let request = portal_session_request(customer_id, return_url);
        let idempotency_key = parameter_key("portal", &request)?;
        let session = request
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(session.url)
    }

    /// Mirrors `billing.CreateSetupCheckoutSession`: setup-mode session to
    /// collect a payment method without a subscription. Parameter-keyed: see
    /// the module docs.
    pub async fn create_setup_session(
        &self,
        customer_id: &str,
        success_url: &str,
        cancel_url: &str,
        org_id: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let window = setup_window(chrono::Utc::now());
        let request = setup_session_request(customer_id, success_url, cancel_url, org_id, &window);
        let idempotency_key = parameter_key("setup", &request)?;
        let session = request
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(session.url.unwrap_or_default())
    }

    /// Opens a one-time credit payment for an organization with no saved
    /// card: Stripe's page takes the card and the payment together and saves
    /// the card for later top-ups. Parameter-keyed: see the module docs; the
    /// top-up id in the request makes each attempt its own session.
    pub async fn create_credit_checkout_session(
        &self,
        purchase: &CreditCheckout<'_>,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let request = credit_checkout_request(purchase);
        let idempotency_key = parameter_key("credit-checkout", &request)?;
        let session = request
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        session
            .url
            .filter(|url| !url.is_empty())
            .ok_or_else(|| AppError::InternalMsg("stripe checkout session has no url".into()))
    }
}

/// A one-time credit payment through Stripe Checkout.
#[derive(Debug, Clone, Copy)]
pub struct CreditCheckout<'a> {
    pub customer_id: &'a str,
    pub organization_id: &'a str,
    pub top_up_id: &'a str,
    pub amount_cents: i64,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
}

/// The metadata `kind` of a credit purchase, on the Checkout session and the
/// automatic top-up invoice alike.
pub(crate) const CREDIT_TOP_UP_KIND: &str = "credit_top_up";
/// The metadata `kind` of the receipt invoice a credit Checkout creates. It
/// is not [`CREDIT_TOP_UP_KIND`]: the session, not the invoice, credits it.
pub(crate) const CREDIT_CHECKOUT_INVOICE_KIND: &str = "credit_checkout";

// ── Webhook endpoint self-check (#3263) ─────────────────────────────

/// The fields of a Stripe webhook endpoint that billing checks. The SDK's
/// webhook-endpoint types live in a crate billing does not otherwise need,
/// so this reads the list response through the existing client.
#[derive(Clone, Debug, miniserde::Deserialize)]
pub struct WebhookEndpoint {
    pub id: String,
    pub url: String,
    pub status: String,
    pub livemode: bool,
    pub api_version: Option<String>,
    pub enabled_events: Vec<String>,
}

#[derive(miniserde::Deserialize)]
struct WebhookEndpointList {
    data: Vec<WebhookEndpoint>,
    has_more: bool,
}

/// What [`StripeHandle::customer_event_probe`] reads of a `customer.updated`
/// event: its customer's id and metadata.
#[derive(miniserde::Deserialize)]
struct CustomerEvent {
    data: CustomerEventData,
}

#[derive(miniserde::Deserialize)]
struct CustomerEventData {
    object: CustomerEventObject,
}

#[derive(miniserde::Deserialize)]
struct CustomerEventObject {
    id: String,
    metadata: std::collections::BTreeMap<String, String>,
}

#[derive(serde::Serialize)]
struct WebhookEndpointListParams {
    limit: u8,
}

impl StripeHandle {
    /// `true` for an `sk_live_` key: its webhook endpoints must be live too.
    pub fn is_live(&self) -> bool {
        self.live
    }

    /// The customers marked as the webhook delivery sentinel
    /// (`metadata.codewire_sentinel` = `delivery`), at most two: the check
    /// wants exactly one.
    pub async fn delivery_sentinels(&self) -> Result<Vec<String>, AppError> {
        let found = SearchCustomer::new("metadata['codewire_sentinel']:'delivery'")
            .limit(2)
            .send(self.client()?)
            .await
            .map_err(stripe_err)?;
        Ok(found.data.into_iter().map(|c| c.id.to_string()).collect())
    }

    /// Points the customer's email at the organization's current owner
    /// before a purchase. Stripe sends its receipts there (#4816), and the
    /// owner, or their address, may have changed since the customer was
    /// created. It updates only an address that differs, so a purchase adds
    /// no `customer.updated` event the delivery check would count. A failure
    /// is logged, never fatal: a purchase is not refused over where its
    /// receipt goes.
    pub async fn sync_customer_email(&self, customer: &str, owner_email: &str) {
        let result = match self.client() {
            Ok(client) => match RetrieveCustomer::new(customer).send(client).await {
                Ok(stripe_core::customer::RetrieveCustomerReturned::Customer(current))
                    if current.email.as_deref() == Some(owner_email) =>
                {
                    Ok(())
                }
                _ => UpdateCustomer::new(customer)
                    .email(owner_email)
                    .send(client)
                    .await
                    .map(|_| ())
                    .map_err(stripe_err),
            },
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::warn!(customer, %error, "could not update the Stripe customer's email");
        }
    }

    /// Sets the sentinel's `codewire_probe` metadata to `probe`. Stripe
    /// answers a customer update with a `customer.updated` event; nothing is
    /// charged.
    pub async fn touch_delivery_sentinel(
        &self,
        customer: &str,
        probe: &str,
    ) -> Result<(), AppError> {
        UpdateCustomer::new(customer)
            .metadata([("codewire_probe".to_string(), probe.to_string())])
            .send(self.client()?)
            .await
            .map_err(stripe_err)?;
        Ok(())
    }

    /// The customer a `customer.updated` event is about and the
    /// `codewire_probe` it carries, read back from Stripe by the event's id.
    /// The delivery check takes a recorded event as its own touch only when
    /// both match (#4862).
    pub async fn customer_event_probe(
        &self,
        event_id: &str,
    ) -> Result<(String, Option<String>), AppError> {
        // The id comes from a verified delivery; refuse anything that would
        // change the request's path rather than name one event.
        if event_id.is_empty()
            || !event_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(AppError::InternalMsg(
                format!("not a Stripe event id: {event_id:?}").into(),
            ));
        }
        let mut event: CustomerEvent =
            RequestBuilder::new(StripeMethod::Get, format!("/events/{event_id}"))
                .customize()
                .send(self.client()?)
                .await
                .map_err(stripe_err)?;
        Ok((
            event.data.object.id,
            event.data.object.metadata.remove("codewire_probe"),
        ))
    }

    /// Every webhook endpoint of the account. More than one page is an
    /// explicit failure, never silent partial evidence.
    pub async fn list_webhook_endpoints(&self) -> Result<Vec<WebhookEndpoint>, AppError> {
        let client = self.client()?;
        let page: WebhookEndpointList =
            RequestBuilder::new(StripeMethod::Get, "/webhook_endpoints")
                .query(&WebhookEndpointListParams { limit: 100 })
                .customize()
                .send(client)
                .await
                .map_err(stripe_err)?;
        if page.has_more {
            return Err(AppError::InternalMsg(
                "stripe webhook-endpoint enumeration exceeded one page".into(),
            ));
        }
        Ok(page.data)
    }
}

/// The payment-mode session `create_credit_checkout_session` sends.
/// - One EUR line for the amount, so the page shows exactly what is charged.
/// - Card only, saved for off-session use, so later automatic top-ups can
///   charge it; the completion webhook makes it the default.
/// - A receipt invoice, as an automatic top-up has.
/// - The organization, top-up and amount in the metadata, which the
///   completion webhook credits from.
fn credit_checkout_request(purchase: &CreditCheckout<'_>) -> CreateCheckoutSession {
    let metadata = std::collections::HashMap::from([
        ("kind".to_owned(), CREDIT_TOP_UP_KIND.to_owned()),
        ("org_id".to_owned(), purchase.organization_id.to_owned()),
        ("top_up_id".to_owned(), purchase.top_up_id.to_owned()),
        ("amount_cents".to_owned(), purchase.amount_cents.to_string()),
    ]);
    let mut price = CreateCheckoutSessionLineItemsPriceData::new(BILLING_CURRENCY);
    price.unit_amount = Some(purchase.amount_cents);
    price.product_data = Some(ProductData::new("Codewire compute credit"));
    let mut payment_intent = CreateCheckoutSessionPaymentIntentData::new();
    payment_intent.setup_future_usage =
        Some(CreateCheckoutSessionPaymentIntentDataSetupFutureUsage::OffSession);
    payment_intent.description = Some("Codewire compute credit".to_owned());
    payment_intent.metadata = Some(metadata.clone());
    let mut invoice_data = CreateCheckoutSessionInvoiceCreationInvoiceData::new();
    invoice_data.description = Some("Codewire compute credit".to_owned());
    invoice_data.metadata = Some(std::collections::HashMap::from([
        ("kind".to_owned(), CREDIT_CHECKOUT_INVOICE_KIND.to_owned()),
        ("org_id".to_owned(), purchase.organization_id.to_owned()),
        ("top_up_id".to_owned(), purchase.top_up_id.to_owned()),
    ]));
    let mut invoice_creation = CreateCheckoutSessionInvoiceCreation::new(true);
    invoice_creation.invoice_data = Some(invoice_data);
    CreateCheckoutSession::new()
        .customer(purchase.customer_id)
        .mode(stripe_shared::CheckoutSessionMode::Payment)
        .payment_method_types([CreateCheckoutSessionPaymentMethodTypes::Card])
        .line_items(vec![CreateCheckoutSessionLineItems {
            price_data: Some(price),
            quantity: Some(1),
            ..Default::default()
        }])
        .payment_intent_data(payment_intent)
        .invoice_creation(invoice_creation)
        .success_url(purchase.success_url)
        .cancel_url(purchase.cancel_url)
        .metadata(metadata)
}

/// The billing portal session `create_portal_session` sends.
fn portal_session_request(customer_id: &str, return_url: &str) -> CreateBillingPortalSession {
    CreateBillingPortalSession::new()
        .customer(customer_id)
        .return_url(return_url)
}

/// How long a card setup session is reused. Within one window a double click
/// opens one session; a later attempt, after a card was saved or declined,
/// always gets a fresh one (#3381: a replayed, completed session left a user
/// unable to replace a card for a day).
const SETUP_SESSION_WINDOW_SECS: i64 = 300;

/// The window `now` falls in, as the RFC 3339 time it starts.
fn setup_window(now: chrono::DateTime<chrono::Utc>) -> String {
    let start = now.timestamp() - now.timestamp().rem_euclid(SETUP_SESSION_WINDOW_SECS);
    chrono::DateTime::<chrono::Utc>::from_timestamp(start, 0)
        .unwrap_or(now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The card setup session `create_setup_session` sends.
/// - Card only: a saved method has to pay automatic top-ups off-session.
/// - A currency: Stripe refuses a setup-mode session without one ("Missing
///   required param: currency").
/// - The window in the metadata, so the parameter key, and with it the
///   session, changes from one window to the next.
fn setup_session_request(
    customer_id: &str,
    success_url: &str,
    cancel_url: &str,
    org_id: &str,
    requested_window: &str,
) -> CreateCheckoutSession {
    CreateCheckoutSession::new()
        .customer(customer_id)
        .mode(stripe_shared::CheckoutSessionMode::Setup)
        .payment_method_types([CreateCheckoutSessionPaymentMethodTypes::Card])
        .currency(BILLING_CURRENCY)
        .success_url(success_url)
        .cancel_url(cancel_url)
        .metadata([
            ("org_id".to_string(), org_id.to_string()),
            ("requested_window".to_string(), requested_window.to_string()),
        ])
}

/// What a failed Stripe call may say about itself in an error or a log.
trait StripeFailure {
    fn kind(&self) -> String;
}

/// The HTTP status and Stripe's type, code, decline code and parameter name.
/// Stripe's message and the objects its error carries, a payment method's
/// billing details among them, can hold a customer's name, email or address,
/// so neither reaches an error or a log (#6006). Every other variant is fixed
/// text or the transport's own, which names no request.
impl StripeFailure for stripe::StripeError {
    fn kind(&self) -> String {
        match self {
            stripe::StripeError::Stripe(errors, status) => format!(
                "HTTP {status}, type {}, code {:?}, decline code {:?}, param {:?}",
                errors.type_.as_str(),
                errors.code.as_ref().map(|code| code.as_str()),
                errors.decline_code,
                errors.param,
            ),
            other => other.to_string(),
        }
    }
}

/// Empty or too long, with the length: never the key.
impl StripeFailure for stripe::IdempotentKeyError {
    fn kind(&self) -> String {
        self.to_string()
    }
}

impl StripeFailure for std::convert::Infallible {
    fn kind(&self) -> String {
        match *self {}
    }
}

fn stripe_err(error: impl StripeFailure) -> AppError {
    AppError::Internal(anyhow::anyhow!("stripe request failed: {}", error.kind()))
}

fn stripe_not_found(error: &stripe::StripeError) -> bool {
    matches!(error, stripe::StripeError::Stripe(_, 404))
}

// ── Webhook-handler Stripe calls (Go: webhook.go) ───────────────────

impl StripeHandle {
    pub async fn retrieve_subscription(
        &self,
        id: &str,
    ) -> Result<stripe_shared::Subscription, AppError> {
        let client = self.client()?;
        RetrieveSubscription::new(
            id.parse::<stripe_shared::SubscriptionId>()
                .map_err(stripe_err)?,
        )
        .send(client)
        .await
        .map_err(stripe_err)
    }

    /// Enumerate every open Checkout session for one customer. Deletion uses
    /// this to close setup and subscription entrypoints before canceling the
    /// subscriptions themselves. More than one page is an explicit failure,
    /// never silent partial evidence.
    pub async fn list_open_checkout_session_ids(
        &self,
        customer_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let client = self.client()?;
        let sessions = ListCheckoutSession::new()
            .customer(customer_id)
            .status(stripe_shared::CheckoutSessionStatus::Open)
            .limit(100)
            .send(client)
            .await
            .map_err(stripe_err)?;
        if sessions.has_more {
            return Err(AppError::InternalMsg(
                "stripe checkout-session enumeration exceeded one page".into(),
            ));
        }
        Ok(sessions
            .data
            .into_iter()
            .map(|session| session.id.to_string())
            .collect())
    }

    pub async fn expire_checkout_session(
        &self,
        session_id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let session_id = session_id
            .parse::<stripe_shared::CheckoutSessionId>()
            .map_err(stripe_err)?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        match ExpireCheckoutSession::new(session_id)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
        {
            Ok(session)
                if session.status == Some(stripe_shared::CheckoutSessionStatus::Expired) =>
            {
                Ok(())
            }
            Ok(_) => Err(AppError::InternalMsg(
                "stripe checkout session did not become expired".into(),
            )),
            Err(error) if stripe_not_found(&error) => Ok(()),
            Err(error) => Err(stripe_err(error)),
        }
    }

    /// Stripe's default subscription list excludes canceled subscriptions.
    /// An empty result after cancellation is the provider-side absence proof.
    pub async fn list_nonterminal_subscription_ids(
        &self,
        customer_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let client = self.client()?;
        let subscriptions = ListSubscription::new()
            .customer(customer_id)
            .limit(100)
            .send(client)
            .await
            .map_err(stripe_err)?;
        if subscriptions.has_more {
            return Err(AppError::InternalMsg(
                "stripe subscription enumeration exceeded one page".into(),
            ));
        }
        Ok(subscriptions
            .data
            .into_iter()
            .map(|subscription| subscription.id.to_string())
            .collect())
    }

    pub async fn subscription_is_terminal(&self, id: &str) -> Result<bool, AppError> {
        let client = self.client()?;
        let id = id
            .parse::<stripe_shared::SubscriptionId>()
            .map_err(stripe_err)?;
        match RetrieveSubscription::new(id).send(client).await {
            Ok(subscription) => Ok(matches!(
                subscription.status,
                stripe_shared::SubscriptionStatus::Canceled
                    | stripe_shared::SubscriptionStatus::IncompleteExpired
            )),
            Err(error) if stripe_not_found(&error) => Ok(true),
            Err(error) => Err(stripe_err(error)),
        }
    }

    /// Mirrors `bc.Client.V1Subscriptions.Cancel` (webhook.go
    /// `CancelOrgSubscriptions`): cancels the subscription, discarding
    /// the returned object. When Stripe is disabled (`self.client` is
    /// None) this is a no-op `Ok(())`, mirroring the Go `bc == nil` skip
    /// on the delete-org path.
    pub async fn cancel_subscription(
        &self,
        id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let Some(client) = &self.client else {
            return Ok(());
        };
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let result = CancelSubscription::new(
            id.parse::<stripe_shared::SubscriptionId>()
                .map_err(stripe_err)?,
        )
        .invoice_now(true)
        .prorate(false)
        .customize()
        .request_strategy(RequestStrategy::Idempotent(idempotency_key))
        .send(client.as_ref())
        .await;
        let result = match result {
            Ok(result) => result,
            Err(error) if stripe_not_found(&error) => return Ok(()),
            Err(error) => return Err(stripe_err(error)),
        };
        if result.status != stripe_shared::SubscriptionStatus::Canceled {
            return Err(AppError::InternalMsg(
                "stripe subscription cancellation was not terminal".into(),
            ));
        }
        Ok(())
    }

    /// Delete a customer when its account is deleted (#3679). Stripe keeps
    /// the customer's invoices and payments and removes its payment methods.
    /// A customer that is already deleted, or never existed, is a success.
    pub async fn delete_customer(&self, id: &str) -> Result<(), AppError> {
        let Some(client) = &self.client else {
            return Ok(());
        };
        let customer = id
            .parse::<stripe_shared::CustomerId>()
            .map_err(stripe_err)?;
        match DeleteCustomer::new(customer).send(client.as_ref()).await {
            Ok(_) => Ok(()),
            Err(error) if stripe_not_found(&error) => Ok(()),
            Err(error) => Err(stripe_err(error)),
        }
    }

    /// Mirrors `bc.Client.V1SubscriptionItems.Update` in the subscription
    /// migration flow: swap an item's price, carrying the proration
    /// behavior and quantity through verbatim.
    pub async fn update_subscription_item(
        &self,
        item_id: &str,
        price_id: &str,
        proration_behavior: &str,
        quantity: u64,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let item_id = item_id
            .parse::<stripe_shared::SubscriptionItemId>()
            .map_err(stripe_err)?;
        // FromStr is infallible (unknown → Unknown variant), so an
        // already-validated behavior string round-trips, and an
        // unexpected one is forwarded to Stripe exactly like the Go
        // `stripe.String(prorationBehavior)`.
        let behavior: UpdateSubscriptionItemProrationBehavior = proration_behavior
            .parse()
            .unwrap_or(UpdateSubscriptionItemProrationBehavior::None);
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        UpdateSubscriptionItem::new(item_id)
            .price(price_id)
            .proration_behavior(behavior)
            .quantity(quantity)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(())
    }
}

// ── Saved cards (#4750) ─────────────────────────────────────────────────

mod cards;
pub use cards::SavedCard;

/// How an automatic top-up charge ended (#3381).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopUpCharge {
    /// The card was charged; the invoice is paid.
    Paid { invoice_id: String },
    /// Stripe refused the charge for a reason a retry will not fix (a
    /// declined card, no payment method). The code is Stripe's, made safe
    /// for storage.
    Declined {
        invoice_id: Option<String>,
        code: String,
    },
    /// The bank wants the customer to approve the charge (SCA), which an
    /// off-session charge cannot do. The invoice stays open, and paying it on
    /// its Stripe page sends `invoice.paid`.
    ActionRequired {
        invoice_id: String,
        payment_url: String,
    },
}

/// The code a charge that needs the customer is recorded with.
pub const AUTHENTICATION_REQUIRED: &str = "authentication_required";

/// A Stripe error code as a stored failure code: lower-case letters, digits
/// and '_', at most 128 characters, or `card_declined` when there is none.
pub fn failure_code(code: Option<&str>) -> String {
    let code: String = code
        .unwrap_or("card_declined")
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(128)
        .collect();
    if code.is_empty() {
        "card_declined".to_owned()
    } else {
        code
    }
}

/// A charge the bank holds for the customer's approval: Stripe answers an
/// off-session charge that needs authentication with 402
/// `authentication_required`, and an invoice whose payment needs an action
/// with `invoice_payment_intent_requires_action`.
fn needs_customer(error: &stripe::StripeError) -> bool {
    match error {
        stripe::StripeError::Stripe(errors, 402) => [
            errors.decline_code.as_deref(),
            errors.code.as_ref().map(|code| code.as_str()),
        ]
        .into_iter()
        .flatten()
        .any(|code| {
            matches!(
                code,
                AUTHENTICATION_REQUIRED | "invoice_payment_intent_requires_action"
            )
        }),
        _ => false,
    }
}

/// A refusal no retry fixes: Stripe answers a declined card with 402.
fn declined(error: &stripe::StripeError) -> Option<String> {
    match error {
        stripe::StripeError::Stripe(errors, 402) => Some(failure_code(
            errors
                .decline_code
                .as_deref()
                .or(errors.code.as_ref().map(|code| code.as_str())),
        )),
        _ => None,
    }
}

impl StripeHandle {
    /// Charges a top-up, automatic or an Add credit purchase, to the
    /// customer's default payment method as its own EUR invoice, paid at
    /// once. Every call is idempotent on the top-up id, so a retry after a
    /// crash resumes the same charge.
    pub(crate) async fn charge_top_up(
        &self,
        customer_id: &str,
        organization_id: &str,
        top_up_id: &str,
        amount_cents: i64,
    ) -> Result<TopUpCharge, AppError> {
        let client = self.client()?;
        let key = |step: &str| IdempotencyKey::new(format!("cw-top-up-{step}-{top_up_id}"));
        // Both receipts show why the card was charged (#4754, #5775). The
        // words name no balance, so a retried charge sends the same request.
        let (invoice_description, item_description) =
            if top_up_id.starts_with(crate::credit_purchase::PURCHASE_TOP_UP_PREFIX) {
                ("Codewire compute credit", "Codewire compute credit")
            } else {
                (
                    "Codewire automatic top-up: compute credit reached €0",
                    "Compute credit, added by automatic top-up when the balance reached €0",
                )
            };
        let metadata = std::collections::HashMap::from([
            ("kind".to_owned(), CREDIT_TOP_UP_KIND.to_owned()),
            ("org_id".to_owned(), organization_id.to_owned()),
            ("top_up_id".to_owned(), top_up_id.to_owned()),
        ]);
        let invoice = CreateInvoice::new()
            .customer(customer_id)
            .currency(BILLING_CURRENCY)
            .auto_advance(false)
            .collection_method(stripe_shared::InvoiceCollectionMethod::ChargeAutomatically)
            .pending_invoice_items_behavior(CreateInvoicePendingInvoiceItemsBehavior::Exclude)
            .description(invoice_description)
            .metadata(metadata)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(
                key("invoice").map_err(stripe_err)?,
            ))
            .send(client)
            .await
            .map_err(stripe_err)?;
        let invoice_id = invoice
            .id
            .map(|id| id.to_string())
            .ok_or_else(|| AppError::InternalMsg("stripe invoice create returned no id".into()))?;
        CreateInvoiceItem::new()
            .customer(customer_id)
            .invoice(invoice_id.clone())
            .amount(amount_cents)
            .currency(BILLING_CURRENCY)
            .description(item_description)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(
                key("item").map_err(stripe_err)?,
            ))
            .send(client)
            .await
            .map_err(stripe_err)?;
        let finalized = FinalizeInvoiceInvoice::new(invoice_id.as_str())
            .customize()
            .request_strategy(RequestStrategy::Idempotent(
                key("finalize").map_err(stripe_err)?,
            ))
            .send(client)
            .await
            .map_err(stripe_err)?;
        match PayInvoice::new(invoice_id.as_str())
            .off_session(true)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(key("pay").map_err(stripe_err)?))
            .send(client)
            .await
        {
            Ok(paid) if paid.status == Some(stripe_shared::InvoiceStatus::Paid) => {
                Ok(TopUpCharge::Paid { invoice_id })
            }
            Ok(other) => Err(AppError::InternalMsg(
                format!("stripe top-up invoice is {:?}, not paid", other.status).into(),
            )),
            Err(error) if needs_customer(&error) => match finalized.hosted_invoice_url {
                Some(payment_url) if !payment_url.is_empty() => Ok(TopUpCharge::ActionRequired {
                    invoice_id,
                    payment_url,
                }),
                _ => Ok(TopUpCharge::Declined {
                    invoice_id: Some(invoice_id),
                    code: AUTHENTICATION_REQUIRED.to_owned(),
                }),
            },
            Err(error) => match declined(&error) {
                Some(code) => Ok(TopUpCharge::Declined {
                    invoice_id: Some(invoice_id),
                    code,
                }),
                None => Err(stripe_err(error)),
            },
        }
    }

    /// The paid invoice of a top-up, found by the `top_up_id` its metadata
    /// carries. A pending top-up old enough that its idempotency keys may have
    /// expired looks here before it is charged again (#5365).
    pub(crate) async fn paid_top_up_invoice(
        &self,
        top_up_id: &str,
    ) -> Result<Option<String>, AppError> {
        // Top-up ids are UUIDs or derived `credit-…` ids; nothing else is
        // quoted into a search query.
        if top_up_id.is_empty()
            || !top_up_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::InternalMsg(
                "top-up id cannot be searched for".into(),
            ));
        }
        let client = self.client()?;
        let found = SearchInvoice::new(format!("metadata['top_up_id']:'{top_up_id}'"))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(found
            .data
            .into_iter()
            .filter(|invoice| invoice.status == Some(stripe_shared::InvoiceStatus::Paid))
            .filter(|invoice| {
                invoice
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("top_up_id"))
                    .is_some_and(|id| id == top_up_id)
            })
            .find_map(|invoice| invoice.id.map(|id| id.to_string())))
    }

    /// An invoice's state and its Stripe payment page, for a credit request
    /// retried after its charge needed the customer.
    pub(crate) async fn invoice_payment(
        &self,
        invoice_id: &str,
    ) -> Result<InvoicePayment, AppError> {
        let client = self.client()?;
        let invoice = RetrieveInvoice::new(invoice_id)
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(InvoicePayment {
            paid: invoice.status == Some(stripe_shared::InvoiceStatus::Paid),
            open: invoice.status == Some(stripe_shared::InvoiceStatus::Open),
            payment_url: invoice.hosted_invoice_url.filter(|url| !url.is_empty()),
        })
    }

    /// The payment method a payment intent was paid with.
    pub(crate) async fn payment_intent_payment_method(
        &self,
        payment_intent_id: &str,
    ) -> Result<Option<String>, AppError> {
        #[derive(miniserde::Deserialize)]
        struct PaymentIntent {
            payment_method: Option<String>,
        }
        let client = self.client()?;
        let id = payment_intent_id
            .parse::<stripe_shared::PaymentIntentId>()
            .map_err(stripe_err)?;
        let intent: PaymentIntent =
            RequestBuilder::new(StripeMethod::Get, format!("/payment_intents/{id}"))
                .customize()
                .send(client)
                .await
                .map_err(stripe_err)?;
        Ok(intent.payment_method.filter(|id| !id.is_empty()))
    }
}

/// Where an invoice's payment stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvoicePayment {
    pub paid: bool,
    pub open: bool,
    pub payment_url: Option<String>,
}

#[cfg(test)]
mod top_up_tests {
    use super::{REQUIRE_TEST_KEY_ENV, check_test_key_requirement, failure_code};

    #[test]
    fn a_live_key_is_refused_where_a_test_key_is_required() {
        for required in [Some("on"), Some(" on ")] {
            for key in ["sk_live_synthetic", "rk_live_synthetic", "synthetic"] {
                let error = check_test_key_requirement(required, Some(key)).unwrap_err();
                assert!(error.contains(REQUIRE_TEST_KEY_ENV), "{error}");
                assert!(!error.contains(key), "{error}");
            }
            for key in ["sk_test_synthetic", "rk_test_synthetic", ""] {
                check_test_key_requirement(required, Some(key)).unwrap();
            }
            check_test_key_requirement(required, None).unwrap();
        }
        for required in [None, Some(""), Some("off")] {
            check_test_key_requirement(required, Some("sk_live_synthetic")).unwrap();
        }
        check_test_key_requirement(Some("yes"), Some("sk_test_synthetic")).unwrap_err();
    }

    const DECLINE: &str = r#"{
        "type": "card_error", "code": "card_declined", "decline_code": "insufficient_funds",
        "param": "payment_method",
        "message": "Declined for Synthetic Person <synthetic.person@example.test>",
        "request_log_url": "https://dashboard.stripe.com/test/logs/req_synthetic?t=1",
        "payment_method": {
            "id": "pm_synthetic", "object": "payment_method", "created": 1, "livemode": false,
            "type": "card",
            "billing_details": {
                "name": "Synthetic Person", "email": "synthetic.person@example.test",
                "phone": "+15550100",
                "address": {"line1": "1 Synthetic Street", "city": "Testville",
                            "country": "US", "postal_code": "00000"}
            }
        }
    }"#;

    #[tokio::test]
    async fn a_stripe_error_reaches_logs_and_callers_as_its_kind_only() {
        let errors: stripe_shared::ApiErrors = miniserde::json::from_str(DECLINE).unwrap();
        assert!(
            errors.payment_method.is_some(),
            "the fixture carries billing details"
        );
        let kind = "stripe request failed: HTTP 402, type card_error, code Some(\"card_declined\"), \
                    decline code Some(\"insufficient_funds\"), param Some(\"payment_method\")";
        let failure = super::stripe_err(stripe::StripeError::Stripe(Box::new(errors), 402));
        // What the delivery check reports, and what the response logs.
        assert_eq!(failure.to_string(), kind);
        let super::AppError::Internal(error) = &failure else {
            panic!("a Stripe failure is an internal error");
        };
        assert_eq!(format!("{error:?}"), kind);
        let response = axum::response::IntoResponse::into_response(failure);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("internal error"), "{body}");
        for private in [
            "Synthetic",
            "example.test",
            "+15550100",
            "Testville",
            "req_synthetic",
        ] {
            assert!(
                !kind.contains(private) && !body.contains(private),
                "{private}"
            );
        }
    }

    #[test]
    fn every_other_stripe_error_keeps_its_own_fixed_text() {
        for (error, text) in [
            (
                stripe::StripeError::ClientError("client error (Connect)".into()),
                "error communicating with stripe: client error (Connect)",
            ),
            (
                stripe::StripeError::JSONDeserialize("error deserializing request data".into()),
                "error deserializing a request: error deserializing request data",
            ),
            (
                stripe::StripeError::Timeout,
                "timeout communicating with stripe",
            ),
        ] {
            assert_eq!(
                super::stripe_err(error).to_string(),
                format!("stripe request failed: {text}")
            );
        }
    }

    #[test]
    fn stripe_codes_become_safe_failure_codes() {
        assert_eq!(
            failure_code(Some("insufficient_funds")),
            "insufficient_funds"
        );
        assert_eq!(failure_code(Some("Card-Declined!")), "carddeclined");
        assert_eq!(failure_code(Some("")), "card_declined");
        assert_eq!(failure_code(None), "card_declined");
        assert_eq!(failure_code(Some(&"x".repeat(300))).len(), 128);
    }
}

#[cfg(test)]
mod currency_tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{OriginalUri, State};
    use axum::http::StatusCode;
    use axum::routing::post;
    use serde_json::json;

    use super::StripeHandle;

    type Seen = Arc<Mutex<Vec<(String, BTreeMap<String, String>)>>>;

    /// Records the path and form of every request, then refuses it, so a call
    /// stops after its first Stripe request.
    async fn record(
        State(seen): State<Seen>,
        uri: OriginalUri,
        body: String,
    ) -> (StatusCode, String) {
        let form = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        seen.lock().unwrap().push((uri.path().to_owned(), form));
        let error = json!({"error": {"type": "invalid_request_error", "message": "recorded"}});
        (StatusCode::BAD_REQUEST, error.to_string())
    }

    async fn fake_stripe() -> (StripeHandle, Seen, tokio::task::JoinHandle<()>) {
        let seen = Seen::default();
        let app = Router::new()
            .route("/v1/checkout/sessions", post(record))
            .route("/v1/invoiceitems", post(record))
            .route("/v1/invoices", post(record))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            StripeHandle::for_test(&format!("http://{address}")),
            seen,
            server,
        )
    }

    fn only_request(seen: &Seen, path: &str) -> BTreeMap<String, String> {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, path);
        seen[0].1.clone()
    }

    /// Stripe refuses a setup-mode Checkout session without a currency
    /// ("Missing required param: currency"), which failed every add-card on
    /// Dev (#3381).
    #[tokio::test]
    async fn a_setup_session_asks_stripe_for_a_euro_setup_checkout() {
        let (stripe, seen, server) = fake_stripe().await;
        stripe
            .create_setup_session(
                "cus_synthetic",
                "https://codewire.test/billing?setup=done",
                "https://codewire.test/billing?setup=cancelled",
                "org-1",
            )
            .await
            .unwrap_err();
        server.abort();
        let form = only_request(&seen, "/v1/checkout/sessions");
        for (key, value) in [
            ("mode", "setup"),
            ("currency", "eur"),
            ("customer", "cus_synthetic"),
            ("success_url", "https://codewire.test/billing?setup=done"),
            (
                "cancel_url",
                "https://codewire.test/billing?setup=cancelled",
            ),
            ("metadata[org_id]", "org-1"),
        ] {
            assert_eq!(
                form.get(key).map(String::as_str),
                Some(value),
                "{key} in {form:?}"
            );
        }
        // Card only, so the saved method can pay top-ups off-session.
        assert_eq!(
            form.get("payment_method_types[0]").map(String::as_str),
            Some("card"),
            "{form:?}"
        );
        assert!(!form.contains_key("payment_method_types[1]"), "{form:?}");
        let window = form
            .get("metadata[requested_window]")
            .expect("requested_window");
        assert!(window.ends_with(":00Z"), "{window}");
    }

    /// Overage was invoiced in USD although prices are in euros (#3381).
    #[tokio::test]
    async fn an_overage_invoice_item_is_in_euros() {
        let (stripe, seen, server) = fake_stripe().await;
        stripe
            .create_overage_invoice_item("cus_synthetic", 1234, "overage", "cw-overage-synthetic")
            .await
            .unwrap_err();
        server.abort();
        let form = only_request(&seen, "/v1/invoiceitems");
        assert_eq!(
            form.get("currency").map(String::as_str),
            Some("eur"),
            "{form:?}"
        );
        assert_eq!(
            form.get("amount").map(String::as_str),
            Some("1234"),
            "{form:?}"
        );
    }

    #[tokio::test]
    async fn a_top_up_invoice_is_in_euros() {
        let (stripe, seen, server) = fake_stripe().await;
        stripe
            .charge_top_up("cus_synthetic", "org-1", "top-up-1", 2000)
            .await
            .unwrap_err();
        server.abort();
        let form = only_request(&seen, "/v1/invoices");
        assert_eq!(
            form.get("currency").map(String::as_str),
            Some("eur"),
            "{form:?}"
        );
        // An automatic top-up's id isn't a purchase's, so it keeps #4754's words.
        assert_eq!(
            form.get("description").map(String::as_str),
            Some("Codewire automatic top-up: compute credit reached €0"),
            "{form:?}"
        );
    }

    /// Every Stripe call that names a currency names the one constant, the
    /// top-up's invoice item included, which a fake Stripe only reaches with a
    /// full invoice.
    #[test]
    fn every_currency_this_client_sends_is_the_billing_currency() {
        let file = include_str!("stripe_client.rs");
        let source = &file[..file.find("mod currency_tests").expect("this module")];
        let calls = source.matches(".currency(").count();
        let constant = source.matches(".currency(BILLING_CURRENCY)").count();
        assert!(calls >= 4, "{calls}");
        assert_eq!(
            calls, constant,
            "a Stripe call names a currency other than BILLING_CURRENCY"
        );
    }
}

#[cfg(test)]
mod idempotency_key_tests {
    use super::{
        CreditCheckout, IDEMPOTENT_CALLS, IdempotencyKind, credit_checkout_request, parameter_key,
        portal_session_request, setup_session_request, setup_window,
    };

    fn key(kind: &str, request: &impl serde::Serialize) -> String {
        format!("{:?}", parameter_key(kind, request).unwrap())
    }

    /// Asserts the first key is stable and every other one differs from it
    /// and from each other.
    fn all_distinct(base: String, again: String, variants: Vec<String>) {
        assert_eq!(base, again, "the same request must give the same key");
        let mut seen = std::collections::BTreeSet::from([base]);
        for variant in variants {
            assert!(
                seen.insert(variant.clone()),
                "a changed parameter kept a key: {variant}"
            );
        }
    }

    #[test]
    fn a_setup_session_key_changes_with_every_parameter() {
        let w = "2026-11-11T11:00:00Z";
        let k = |c, s, x, o, w| key("setup", &setup_session_request(c, s, x, o, w));
        all_distinct(
            k("cus_1", "https://a/ok", "https://a/no", "org-1", w),
            k("cus_1", "https://a/ok", "https://a/no", "org-1", w),
            vec![
                k("cus_2", "https://a/ok", "https://a/no", "org-1", w),
                k("cus_1", "https://a/ok2", "https://a/no", "org-1", w),
                k("cus_1", "https://a/ok", "https://a/no2", "org-1", w),
                k("cus_1", "https://a/ok", "https://a/no", "org-2", w),
                k(
                    "cus_1",
                    "https://a/ok",
                    "https://a/no",
                    "org-1",
                    "2026-11-11T11:05:00Z",
                ),
            ],
        );
    }

    /// A double click inside one five-minute window reuses one session; a
    /// later attempt, after a card was saved or declined, gets a new one.
    #[test]
    fn a_setup_session_is_reused_within_its_window_and_fresh_after_it() {
        let at = |hms: &str| {
            chrono::DateTime::parse_from_rfc3339(&format!("2026-11-11T{hms}Z"))
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let session = |hms| {
            let window = setup_window(at(hms));
            key(
                "setup",
                &setup_session_request("cus_1", "https://a/ok", "https://a/no", "org-1", &window),
            )
        };
        assert_eq!(setup_window(at("11:03:59")), "2026-11-11T11:00:00Z");
        assert_eq!(session("11:00:00"), session("11:04:59"));
        assert_ne!(session("11:04:59"), session("11:05:00"));
        assert_ne!(session("11:00:00"), session("12:00:00"));
    }

    /// A double click on Add credit reuses one session; any other purchase,
    /// amount or return page opens its own.
    #[test]
    fn a_credit_checkout_key_changes_with_every_parameter() {
        let base = CreditCheckout {
            customer_id: "cus_1",
            organization_id: "org-1",
            top_up_id: "credit-1",
            amount_cents: 10_000,
            success_url: "https://a/ok",
            cancel_url: "https://a/no",
        };
        let k = |purchase: CreditCheckout<'_>| {
            key("credit-checkout", &credit_checkout_request(&purchase))
        };
        all_distinct(
            k(base),
            k(base),
            vec![
                k(CreditCheckout {
                    customer_id: "cus_2",
                    ..base
                }),
                k(CreditCheckout {
                    organization_id: "org-2",
                    ..base
                }),
                k(CreditCheckout {
                    top_up_id: "credit-2",
                    ..base
                }),
                k(CreditCheckout {
                    amount_cents: 25_000,
                    ..base
                }),
                k(CreditCheckout {
                    success_url: "https://a/ok2",
                    ..base
                }),
                k(CreditCheckout {
                    cancel_url: "https://a/no2",
                    ..base
                }),
            ],
        );
    }

    #[test]
    fn a_portal_session_key_changes_with_every_parameter() {
        let k = |c, r| key("portal", &portal_session_request(c, r));
        all_distinct(
            k("cus_1", "https://a/back"),
            k("cus_1", "https://a/back"),
            vec![k("cus_2", "https://a/back"), k("cus_1", "https://a/back2")],
        );
    }

    #[test]
    fn every_idempotent_call_is_named_and_keyed_by_its_kind() {
        let file = include_str!("stripe_client.rs");
        // The card calls live in their own file (#4750).
        let source = [
            &file[..file.find("mod currency_tests").expect("test module")],
            include_str!("stripe_client/cards.rs"),
        ]
        .concat();
        let mut found = Vec::new();
        for (start, _) in source.match_indices("async fn ") {
            let name: String = source[start + 9..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let end = source[start..]
                .find("\n    }\n")
                .map_or(source.len(), |e| start + e);
            let body = &source[start..end];
            if !body.contains("RequestStrategy::Idempotent") {
                continue;
            }
            let kind = IDEMPOTENT_CALLS
                .iter()
                .find(|(call, _)| *call == name)
                .map(|(_, kind)| *kind)
                .unwrap_or_else(|| {
                    panic!("{name} is idempotent but missing from IDEMPOTENT_CALLS")
                });
            assert_eq!(
                body.contains("parameter_key("),
                kind == IdempotencyKind::Parameters,
                "{name} is keyed against its kind {kind:?}"
            );
            found.push(name);
        }
        for (call, _) in IDEMPOTENT_CALLS {
            assert!(
                found.iter().any(|name| name == call),
                "{call} is listed but not found"
            );
        }
    }
}

#[cfg(test)]
mod default_payment_method_tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, extract::RawQuery, routing::get};

    use axum::http::StatusCode;

    use super::{CardSummary, DefaultPaymentMethod, PaymentMethodUnavailable, StripeHandle};

    /// A synthetic Visa test card in Stripe's customer shape, with the
    /// default payment method expanded. Its fingerprint must never come out.
    const VISA: &str = r#"{"id":"cus_synthetic","object":"customer","created":1,"livemode":false,
      "invoice_settings":{"custom_fields":null,"footer":null,"rendering_options":null,
        "default_payment_method":{"id":"pm_synthetic_visa","object":"payment_method","created":1,
          "livemode":false,"type":"card","customer":"cus_synthetic","metadata":{},
          "allow_redisplay":"always",
          "billing_details":{"address":null,"email":null,"name":null,"phone":null,"tax_id":null},
          "card":{"brand":"visa","checks":null,"country":"US","display_brand":"visa",
            "exp_month":11,"exp_year":2026,"fingerprint":"fp_synthetic_secret","funding":"credit",
            "generated_from":null,"last4":"4242","networks":null,"regulated_status":"unregulated",
            "three_d_secure_usage":{"supported":true},"wallet":null}}}}"#;

    /// Serves `body` for the synthetic customer and records each query.
    async fn fake_stripe(body: &'static str) -> (StripeHandle, Arc<Mutex<Vec<String>>>) {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = queries.clone();
        let app = Router::new().route(
            "/v1/customers/cus_synthetic",
            get(move |RawQuery(query): RawQuery| {
                seen.lock().unwrap().push(query.unwrap_or_default());
                async move { ([("content-type", "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            StripeHandle::for_test(&format!("http://{address}")),
            queries,
        )
    }

    #[tokio::test]
    async fn one_retrieve_expands_the_card_and_keeps_only_what_a_receipt_shows() {
        let (stripe, queries) = fake_stripe(VISA).await;
        let method = stripe.default_payment_method("cus_synthetic", true).await;
        assert_eq!(
            method,
            Some(DefaultPaymentMethod {
                card: Some(CardSummary {
                    brand: "visa".into(),
                    last4: "4242".into(),
                    exp_month: 11,
                    exp_year: 2026,
                }),
            })
        );
        assert!(!format!("{method:?}").contains("fp_synthetic"));
        assert_eq!(
            *queries.lock().unwrap(),
            ["expand[0]=invoice_settings.default_payment_method"]
        );

        // The credit check only asks whether there is one: no expansion.
        assert!(
            stripe
                .default_payment_method("cus_synthetic", false)
                .await
                .is_some()
        );
        assert_eq!(queries.lock().unwrap()[1], "");
    }

    #[tokio::test]
    async fn a_method_without_card_details_is_still_a_payment_method() {
        let (stripe, _) = fake_stripe(
            r#"{"id":"cus_synthetic","object":"customer","created":1,"livemode":false,
              "invoice_settings":{"default_payment_method":"pm_synthetic"}}"#,
        )
        .await;
        assert_eq!(
            stripe.default_payment_method("cus_synthetic", true).await,
            Some(DefaultPaymentMethod { card: None })
        );
    }

    /// Serves `body` with `status` for the synthetic customer.
    async fn stripe_answering(status: StatusCode, body: &'static str) -> StripeHandle {
        let app = Router::new().route(
            "/v1/customers/cus_synthetic",
            get(move || async move { (status, [("content-type", "application/json")], body) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        StripeHandle::for_test(&format!("http://{address}"))
    }

    /// The admin card read tells "no card" from "Stripe couldn't say", so a
    /// card that may be charged is never reported as absent (#5094).
    #[tokio::test]
    async fn a_stripe_that_cannot_answer_is_unavailable_not_no_card() {
        let failing = stripe_answering(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":{"type":"api_error","message":"synthetic outage"}}"#,
        )
        .await;
        assert_eq!(
            failing
                .try_default_payment_method("cus_synthetic", true)
                .await,
            Err(PaymentMethodUnavailable)
        );
        assert_eq!(
            StripeHandle::for_test("http://127.0.0.1:1")
                .try_default_payment_method("cus_synthetic", true)
                .await,
            Err(PaymentMethodUnavailable)
        );

        // A real absence is none: Stripe doesn't know the customer, it was
        // deleted, it has no default, or Stripe isn't set up.
        let unknown = stripe_answering(
            StatusCode::NOT_FOUND,
            r#"{"error":{"type":"invalid_request_error","message":"No such customer"}}"#,
        )
        .await;
        assert_eq!(
            unknown
                .try_default_payment_method("cus_synthetic", true)
                .await,
            Ok(None)
        );
        for body in [
            r#"{"id":"cus_synthetic","object":"customer","deleted":true}"#,
            r#"{"id":"cus_synthetic","object":"customer","created":1,"livemode":false,
              "invoice_settings":{"default_payment_method":null}}"#,
        ] {
            let stripe = stripe_answering(StatusCode::OK, body).await;
            assert_eq!(
                stripe
                    .try_default_payment_method("cus_synthetic", true)
                    .await,
                Ok(None),
                "{body}"
            );
        }
        assert_eq!(
            StripeHandle::default()
                .try_default_payment_method("cus_synthetic", true)
                .await,
            Ok(None)
        );

        let (visa, _) = fake_stripe(VISA).await;
        assert_eq!(
            visa.try_default_payment_method("cus_synthetic", true)
                .await
                .map(|method| method.and_then(|method| method.card).map(|card| card.last4)),
            Ok(Some("4242".to_owned()))
        );
    }

    #[tokio::test]
    async fn no_default_a_deleted_customer_or_no_stripe_is_none() {
        for body in [
            r#"{"id":"cus_synthetic","object":"customer","created":1,"livemode":false,
              "invoice_settings":{"default_payment_method":null}}"#,
            r#"{"id":"cus_synthetic","object":"customer","deleted":true}"#,
            r#"{"error":{"type":"invalid_request_error","message":"No such customer"}}"#,
        ] {
            let (stripe, _) = fake_stripe(body).await;
            assert_eq!(
                stripe.default_payment_method("cus_synthetic", true).await,
                None,
                "{body}"
            );
        }
        let unreachable = StripeHandle::for_test("http://127.0.0.1:1");
        assert_eq!(
            unreachable
                .default_payment_method("cus_synthetic", true)
                .await,
            None
        );
        assert_eq!(
            StripeHandle::default()
                .default_payment_method("cus_synthetic", true)
                .await,
            None
        );
    }

    #[test]
    fn out_of_range_card_values_show_no_details() {
        let card = |brand: &str, last4: &str, exp_month: i64, exp_year: i64| {
            let mut card: stripe_shared::PaymentMethodCard = miniserde::json::from_str(
                r#"{"brand":"visa","exp_month":1,"exp_year":2030,"funding":"credit","last4":"4242"}"#,
            )
            .unwrap();
            card.brand = brand.into();
            card.last4 = last4.into();
            card.exp_month = exp_month;
            card.exp_year = exp_year;
            CardSummary::from_stripe(&card)
        };
        assert!(card("amex", "0005", 12, 2030).is_some());
        assert!(card("cartes_bancaires", "0005", 1, 2030).is_some());
        for (brand, last4, month, year) in [
            ("", "4242", 1, 2030),
            ("<b>visa</b>", "4242", 1, 2030),
            ("visa", "424", 1, 2030),
            ("visa", "42a2", 1, 2030),
            ("visa", "4242", 0, 2030),
            ("visa", "4242", 13, 2030),
            ("visa", "4242", 1, 30),
        ] {
            assert_eq!(
                card(brand, last4, month, year),
                None,
                "{brand} {last4} {month} {year}"
            );
        }
    }
}
