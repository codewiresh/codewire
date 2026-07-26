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
use stripe_billing::invoice_item::CreateInvoiceItem;
use stripe_billing::subscription::{CancelSubscription, ListSubscription, RetrieveSubscription};
use stripe_billing::subscription_item::{
    UpdateSubscriptionItem, UpdateSubscriptionItemProrationBehavior,
};
use stripe_checkout::checkout_session::{
    CreateCheckoutSession, CreateCheckoutSessionLineItems,
    CreateCheckoutSessionLineItemsAdjustableQuantity, CreateCheckoutSessionSubscriptionData,
    ExpireCheckoutSession, ListCheckoutSession,
};
use stripe_core::customer::{
    CreateCustomer, RetrieveCustomer, UpdateCustomer, UpdateCustomerInvoiceSettings,
};
use stripe_core::setup_intent::RetrieveSetupIntent;

use codewire_server_core::AppError;

#[derive(Clone, Default)]
pub struct StripeHandle {
    client: Option<Arc<stripe::Client>>,
    /// `sk_live_` key → live price rows, else test — mirrors
    /// `billing.stripeMode`.
    live: bool,
    webhook_secret: String,
}

pub(crate) struct AdminCreditItemInput<'a> {
    pub customer_id: &'a str,
    pub invoice_id: &'a str,
    pub amount_cents: i64,
    pub currency: &'a str,
    pub description: &'a str,
    pub org_id: &'a str,
    pub idempotency_key: &'a str,
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

    #[cfg(test)]
    pub(crate) fn for_test(api_base: &str) -> Self {
        Self {
            client: Some(Arc::new(
                stripe::ClientBuilder::new("sk_test_codewire")
                    .url(api_base)
                    .timeout(Duration::from_secs(1))
                    .build()
                    .expect("valid Stripe test client configuration"),
            )),
            live: false,
            webhook_secret: String::new(),
        }
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
            .currency(stripe_types::Currency::USD)
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
        let session = CreateCheckoutSession::new()
            .customer(customer_id)
            .mode(stripe_shared::CheckoutSessionMode::Setup)
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

    /// Negative InvoiceItem for the admin-credit flow
    /// (webhook.go::handleInvoiceCreated). Returns the item ID.
    pub(crate) async fn create_admin_credit_item(
        &self,
        input: AdminCreditItemInput<'_>,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let currency: stripe_types::Currency = input.currency.parse().map_err(stripe_err)?;
        let idempotency_key = IdempotencyKey::new(input.idempotency_key).map_err(stripe_err)?;
        let item = CreateInvoiceItem::new()
            .customer(input.customer_id)
            .invoice(input.invoice_id)
            .amount(input.amount_cents)
            .currency(currency)
            .description(input.description)
            .discountable(false)
            .metadata([
                (
                    "admin_credit_kind".to_string(),
                    "subscription_base".to_string(),
                ),
                (
                    "stripe_invoice_id".to_string(),
                    input.invoice_id.to_string(),
                ),
                ("org_id".to_string(), input.org_id.to_string()),
            ])
            .customize()
            .request_strategy(RequestStrategy::Idempotent(idempotency_key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(item.id.to_string())
    }
}
