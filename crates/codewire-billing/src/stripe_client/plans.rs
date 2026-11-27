//! Subscription plan products, recurring prices, Checkout sessions, and
//! subscription updates (#6659).

use std::collections::HashMap;

use stripe_checkout::checkout_session::{
    CreateCheckoutSessionLineItems, CreateCheckoutSessionSubscriptionData, RetrieveCheckoutSession,
};

use super::*;

/// Metadata `kind` on a plan subscription Checkout session.
pub(crate) const PLAN_SUBSCRIPTION_KIND: &str = "plan_subscription";

/// Inputs for opening a Stripe Checkout session in `subscription` mode.
#[derive(Debug, Clone, Copy)]
pub struct PlanCheckout<'a> {
    pub customer_id: &'a str,
    pub organization_id: &'a str,
    pub plan_key: &'a str,
    pub price_id: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
}

#[derive(miniserde::Deserialize)]
struct StripeIdOnly {
    id: String,
}

#[derive(serde::Serialize)]
struct CreateProductParams<'a> {
    name: &'a str,
    #[serde(rename = "metadata[codewire_plan]")]
    plan_key: &'a str,
}

#[derive(serde::Serialize)]
struct CreateRecurringPriceParams<'a> {
    product: &'a str,
    currency: stripe_types::Currency,
    unit_amount: i64,
    #[serde(rename = "recurring[interval]")]
    interval: &'a str,
    #[serde(rename = "metadata[codewire_plan]")]
    plan_key: &'a str,
}

#[derive(serde::Serialize)]
struct UpdateSubscriptionCancelParams {
    cancel_at_period_end: bool,
}

/// Parameters for atomically switching a Stripe Subscription's plan price,
/// updating its `plan_key` metadata, and optionally clearing
/// `cancel_at_period_end`.
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionPlanUpdate<'a> {
    pub subscription_id: &'a str,
    pub item_id: &'a str,
    pub price_id: &'a str,
    pub plan_key: &'a str,
    pub proration_behavior: &'a str,
    pub payment_behavior: Option<&'a str>,
    pub cancel_at_period_end: bool,
}

#[derive(serde::Serialize)]
struct UpdateSubscriptionPlanParams<'a> {
    #[serde(rename = "items[0][id]")]
    item_id: &'a str,
    #[serde(rename = "items[0][price]")]
    price_id: &'a str,
    #[serde(rename = "items[0][quantity]")]
    quantity: u64,
    proration_behavior: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_behavior: Option<&'a str>,
    cancel_at_period_end: bool,
    #[serde(rename = "metadata[plan_key]")]
    plan_key: &'a str,
}

pub(super) fn plan_checkout_request(
    checkout: &PlanCheckout<'_>,
    window: &str,
) -> CreateCheckoutSession {
    let mut metadata = HashMap::new();
    metadata.insert("kind".to_owned(), PLAN_SUBSCRIPTION_KIND.to_owned());
    metadata.insert("org_id".to_owned(), checkout.organization_id.to_owned());
    metadata.insert("plan_key".to_owned(), checkout.plan_key.to_owned());
    metadata.insert("requested_window".to_owned(), window.to_owned());

    let mut sub_metadata = HashMap::new();
    sub_metadata.insert("org_id".to_owned(), checkout.organization_id.to_owned());
    sub_metadata.insert("plan_key".to_owned(), checkout.plan_key.to_owned());

    let mut line_item = CreateCheckoutSessionLineItems::new();
    line_item.price = Some(checkout.price_id.to_owned());
    line_item.quantity = Some(1);

    let mut sub_data = CreateCheckoutSessionSubscriptionData::new();
    sub_data.metadata = Some(sub_metadata);

    CreateCheckoutSession::new()
        .mode(stripe_shared::CheckoutSessionMode::Subscription)
        .customer(checkout.customer_id)
        .payment_method_types(vec![CreateCheckoutSessionPaymentMethodTypes::Card])
        .line_items(vec![line_item])
        .subscription_data(sub_data)
        .success_url(checkout.success_url)
        .cancel_url(checkout.cancel_url)
        .metadata(metadata)
}

impl StripeHandle {
    /// Ensures a Stripe Product exists for `plan_key` using a deterministic
    /// operation idempotency key so retries never create duplicate products.
    pub async fn ensure_plan_product(
        &self,
        plan_key: &str,
        display_name: &str,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let mode = if self.live { "live" } else { "test" };
        let key = IdempotencyKey::new(format!("cw-plan-product-{mode}-{plan_key}"))
            .map_err(stripe_err)?;
        let name = format!("Codewire {display_name}");
        let product: StripeIdOnly = RequestBuilder::new(StripeMethod::Post, "/products")
            .form(&CreateProductParams {
                name: &name,
                plan_key,
            })
            .customize()
            .request_strategy(RequestStrategy::Idempotent(key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(product.id)
    }

    /// Ensures a recurring monthly USD Stripe Price exists for `plan_key` at
    /// `monthly_price_cents` using a deterministic operation idempotency key.
    pub async fn ensure_plan_price(
        &self,
        product_id: &str,
        plan_key: &str,
        monthly_price_cents: i32,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let mode = if self.live { "live" } else { "test" };
        let key = IdempotencyKey::new(format!(
            "cw-plan-price-{mode}-{plan_key}-{monthly_price_cents}-usd-month"
        ))
        .map_err(stripe_err)?;
        let price: StripeIdOnly = RequestBuilder::new(StripeMethod::Post, "/prices")
            .form(&CreateRecurringPriceParams {
                product: product_id,
                currency: BILLING_CURRENCY,
                unit_amount: i64::from(monthly_price_cents),
                interval: "month",
                plan_key,
            })
            .customize()
            .request_strategy(RequestStrategy::Idempotent(key))
            .send(client)
            .await
            .map_err(stripe_err)?;
        Ok(price.id)
    }

    /// Opens a Stripe Checkout session in `subscription` mode for a monthly
    /// plan. Parameter-keyed: see the module docs.
    pub async fn create_plan_checkout_session(
        &self,
        checkout: &PlanCheckout<'_>,
    ) -> Result<String, AppError> {
        let client = self.client()?;
        let window = setup_window(chrono::Utc::now());
        let request = plan_checkout_request(checkout, &window);
        let idempotency_key = parameter_key("plan-checkout", &request)?;
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

    /// Retrieves a Stripe Checkout Session by ID for synchronous plan
    /// reconciliation on return from Checkout.
    pub async fn retrieve_checkout_session(
        &self,
        session_id: &str,
    ) -> Result<stripe_shared::CheckoutSession, AppError> {
        let client = self.client()?;
        let id = session_id
            .parse::<stripe_shared::CheckoutSessionId>()
            .map_err(|_| AppError::BadRequest("invalid checkout session id".into()))?;
        RetrieveCheckoutSession::new(id)
            .send(client)
            .await
            .map_err(stripe_err)
    }

    /// Sets or clears `cancel_at_period_end` on a Stripe Subscription.
    pub async fn set_subscription_cancel_at_period_end(
        &self,
        subscription_id: &str,
        cancel_at_period_end: bool,
        idempotency_key: &str,
    ) -> Result<stripe_shared::Subscription, AppError> {
        let client = self.client()?;
        if subscription_id.is_empty()
            || !subscription_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(AppError::InternalMsg(
                format!("not a Stripe subscription id: {subscription_id:?}").into(),
            ));
        }
        let key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        RequestBuilder::new(
            StripeMethod::Post,
            format!("/subscriptions/{subscription_id}"),
        )
        .form(&UpdateSubscriptionCancelParams {
            cancel_at_period_end,
        })
        .customize()
        .request_strategy(RequestStrategy::Idempotent(key))
        .send(client)
        .await
        .map_err(stripe_err)
    }

    /// Atomically updates a subscription item's price, proration/payment
    /// behavior, `cancel_at_period_end`, and `metadata[plan_key]`.
    pub async fn update_subscription_plan(
        &self,
        update: &SubscriptionPlanUpdate<'_>,
        idempotency_key: &str,
    ) -> Result<stripe_shared::Subscription, AppError> {
        let client = self.client()?;
        if update.subscription_id.is_empty()
            || !update
                .subscription_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(AppError::InternalMsg(
                format!("not a Stripe subscription id: {:?}", update.subscription_id).into(),
            ));
        }
        let key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        RequestBuilder::new(
            StripeMethod::Post,
            format!("/subscriptions/{}", update.subscription_id),
        )
        .form(&UpdateSubscriptionPlanParams {
            item_id: update.item_id,
            price_id: update.price_id,
            quantity: 1,
            proration_behavior: update.proration_behavior,
            payment_behavior: update.payment_behavior,
            cancel_at_period_end: update.cancel_at_period_end,
            plan_key: update.plan_key,
        })
        .customize()
        .request_strategy(RequestStrategy::Idempotent(key))
        .send(client)
        .await
        .map_err(stripe_err)
    }
}
