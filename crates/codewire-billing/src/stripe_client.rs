//! Stripe client handle for the billing service.
//!
//! Wraps `Option<stripe::Client>` with the same nil-safety the Go
//! `*billing.BillingClient` has: every method degrades to a harmless
//! default when Stripe isn't configured (`STRIPE_SECRET_KEY` unset),
//! mirroring `billing: disabled (no STRIPE_SECRET_KEY)` on the Go side.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use stripe::{IdempotencyKey, RequestStrategy, StripeRequest};
use stripe_billing::billing_portal_session::CreateBillingPortalSession;
use stripe_billing::invoice::{
    CreateInvoice, CreateInvoicePendingInvoiceItemsBehavior, FinalizeInvoiceInvoice, PayInvoice,
};
use stripe_billing::invoice_item::{CreateInvoiceItem, UpdateInvoiceItem};
use stripe_billing::subscription::{CancelSubscription, ListSubscription, RetrieveSubscription};
use stripe_billing::subscription_item::{
    UpdateSubscriptionItem, UpdateSubscriptionItemProrationBehavior,
};
use stripe_checkout::checkout_session::{
    CreateCheckoutSession, CreateCheckoutSessionLineItems,
    CreateCheckoutSessionLineItemsAdjustableQuantity, CreateCheckoutSessionSubscriptionData,
    ExpireCheckoutSession, ListCheckoutSession,
};
use stripe_client_core::{RequestBuilder, StripeMethod};
use stripe_core::customer::{
    CreateCustomer, DeleteCustomer, RetrieveCustomer, UpdateCustomer, UpdateCustomerInvoiceSettings,
};
use stripe_core::setup_intent::RetrieveSetupIntent;

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
const BILLING_CURRENCY: stripe_types::Currency = stripe_types::Currency::EUR;

#[derive(Clone, Default)]
pub struct StripeHandle {
    client: Option<Arc<stripe::Client>>,
    /// `sk_live_` key → live price rows, else test — mirrors
    /// `billing.stripeMode`.
    live: bool,
    webhook_secret: String,
}

impl StripeHandle {
    /// Builds the handle from `STRIPE_SECRET_KEY`; unset/empty →
    /// billing disabled, same as the Go service.
    pub fn from_env() -> Self {
        let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
        match std::env::var("STRIPE_SECRET_KEY") {
            Ok(key) if !key.is_empty() => Self {
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
        let Some(client) = &self.client else {
            return false;
        };
        let customer_id: Option<Option<String>> =
            sqlx::query_scalar(r#"SELECT stripe_customer_id FROM organizations WHERE id = $1"#)
                .bind(org_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);
        let Some(Some(customer_id)) = customer_id else {
            return false;
        };
        if customer_id.is_empty() {
            return false;
        }
        match RetrieveCustomer::new(customer_id)
            .send(client.as_ref())
            .await
        {
            Ok(stripe_core::customer::RetrieveCustomerReturned::Customer(c)) => c
                .invoice_settings
                .map(|s| s.default_payment_method.is_some())
                .unwrap_or(false),
            _ => false,
        }
    }
}

// ── Session creation (Go: billing/checkout.go, portal.go, customer.go) ──

impl StripeHandle {
    /// Mirrors `billing.EnsureCustomer`: reuse `stripe_customer_id` or
    /// create the customer and persist the ID.
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

    /// Mirrors `billing.CreateOrgCheckoutSession`: subscription-mode
    /// checkout with the plan price plus the adjustable seat add-on,
    /// honoring any remaining trial days.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_org_checkout_session(
        &self,
        customer_id: &str,
        org_id: &str,
        plan_name: &str,
        price_id: &str,
        seat_price_id: Option<&str>,
        trial_days_remaining: Option<u32>,
        success_url: &str,
        cancel_url: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;

        let mut line_items = vec![CreateCheckoutSessionLineItems {
            price: Some(price_id.to_string()),
            quantity: Some(1),
            ..Default::default()
        }];
        if let Some(seat) = seat_price_id
            && !seat.is_empty()
        {
            line_items.push(CreateCheckoutSessionLineItems {
                price: Some(seat.to_string()),
                quantity: Some(0),
                adjustable_quantity: Some(CreateCheckoutSessionLineItemsAdjustableQuantity {
                    enabled: true,
                    minimum: Some(0),
                    maximum: Some(1000),
                }),
                ..Default::default()
            });
        }

        let sub_data = CreateCheckoutSessionSubscriptionData {
            metadata: Some(
                [
                    ("org_id".to_string(), org_id.to_string()),
                    ("plan".to_string(), plan_name.to_string()),
                ]
                .into(),
            ),
            trial_period_days: trial_days_remaining,
            ..Default::default()
        };

        let request = CreateCheckoutSession::new()
            .customer(customer_id)
            .mode(stripe_shared::CheckoutSessionMode::Subscription)
            .line_items(line_items)
            .success_url(success_url)
            .cancel_url(cancel_url)
            .allow_promotion_codes(true)
            .subscription_data(sub_data);

        let session = request
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;

        Ok(session.url.unwrap_or_default())
    }

    /// Mirrors `billing.CreatePortalSession`.
    pub async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        let session = CreateBillingPortalSession::new()
            .customer(customer_id)
            .return_url(return_url)
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(session.url)
    }

    /// Mirrors `billing.CreateSetupCheckoutSession`: setup-mode session
    /// to collect a payment method without a subscription.
    pub async fn create_setup_session(
        &self,
        customer_id: &str,
        success_url: &str,
        cancel_url: &str,
        org_id: &str,
        idempotency_key: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        // Stripe refuses a setup-mode session without a currency when it picks
        // the payment methods itself ("Missing required param: currency").
        let session = CreateCheckoutSession::new()
            .customer(customer_id)
            .mode(stripe_shared::CheckoutSessionMode::Setup)
            .currency(BILLING_CURRENCY)
            .success_url(success_url)
            .cancel_url(cancel_url)
            .metadata([("org_id".to_string(), org_id.to_string())])
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(session.url.unwrap_or_default())
    }
}

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

#[derive(serde::Serialize)]
struct WebhookEndpointListParams {
    limit: u8,
}

impl StripeHandle {
    /// `true` for an `sk_live_` key: its webhook endpoints must be live too.
    pub fn is_live(&self) -> bool {
        self.live
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

fn stripe_err<E: std::fmt::Debug>(e: E) -> AppError {
    AppError::Internal(anyhow::anyhow!("stripe request failed: {e:?}"))
}

fn stripe_not_found(error: &stripe::StripeError) -> bool {
    matches!(error, stripe::StripeError::Stripe(_, 404))
}

// ── Webhook-handler Stripe calls (Go: webhook.go) ───────────────────

impl StripeHandle {
    pub async fn retrieve_setup_intent(
        &self,
        id: &str,
    ) -> Result<stripe_shared::SetupIntent, AppError> {
        let client = self.client()?;
        RetrieveSetupIntent::new(
            id.parse::<stripe_shared::SetupIntentId>()
                .map_err(stripe_err)?,
        )
        .send(client)
        .await
        .map_err(stripe_err)
    }

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

    /// Customer update setting invoice_settings.default_payment_method.
    pub async fn set_default_payment_method(
        &self,
        customer_id: &str,
        payment_method_id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let settings = UpdateCustomerInvoiceSettings {
            default_payment_method: Some(payment_method_id.to_string()),
            ..Default::default()
        };
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        UpdateCustomer::new(
            customer_id
                .parse::<stripe_shared::CustomerId>()
                .map_err(stripe_err)?,
        )
        .invoice_settings(settings)
        .customize()
        .request_strategy(RequestStrategy::Idempotent(idempotency_key))
        .send(client)
        .await
        .map_err(stripe_err)?;
        Ok(())
    }
}

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
}

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
    /// Charges an automatic top-up to the customer's default payment method
    /// as its own EUR invoice, paid at once. Every call is idempotent on the
    /// top-up id, so a retry after a crash resumes the same charge.
    pub(crate) async fn charge_top_up(
        &self,
        customer_id: &str,
        organization_id: &str,
        top_up_id: &str,
        amount_cents: i64,
    ) -> Result<TopUpCharge, AppError> {
        let client = self.client()?;
        let key = |step: &str| IdempotencyKey::new(format!("cw-top-up-{step}-{top_up_id}"));
        let metadata = std::collections::HashMap::from([
            ("kind".to_owned(), "credit_top_up".to_owned()),
            ("org_id".to_owned(), organization_id.to_owned()),
            ("top_up_id".to_owned(), top_up_id.to_owned()),
        ]);
        let invoice = CreateInvoice::new()
            .customer(customer_id)
            .currency(BILLING_CURRENCY)
            .auto_advance(false)
            .collection_method(stripe_shared::InvoiceCollectionMethod::ChargeAutomatically)
            .pending_invoice_items_behavior(CreateInvoicePendingInvoiceItemsBehavior::Exclude)
            .description("Codewire compute credit top-up")
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
            .description("Compute credit")
            .customize()
            .request_strategy(RequestStrategy::Idempotent(
                key("item").map_err(stripe_err)?,
            ))
            .send(client)
            .await
            .map_err(stripe_err)?;
        FinalizeInvoiceInvoice::new(invoice_id.as_str())
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
            Err(error) => match declined(&error) {
                Some(code) => Ok(TopUpCharge::Declined {
                    invoice_id: Some(invoice_id),
                    code,
                }),
                None => Err(stripe_err(error)),
            },
        }
    }
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
                "cw-setup-synthetic",
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
