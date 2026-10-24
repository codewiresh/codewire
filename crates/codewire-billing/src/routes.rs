//! Shared billing state and billing's permanent raw routes: the Stripe webhook
//! and the internal webhook endpoint check status.

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::checkout_sessions::FrontendOrigin;
use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;
use crate::stripe_endpoint_check;
use crate::webhook;

/// Shared Connect handler state. `FromRef` keeps pure-DB handlers able to
/// extract `State<PgPool>` while Stripe-touching handlers take the whole state.
#[derive(Clone, FromRef)]
pub struct BillingState {
    pub pool: PgPool,
    pub stripe: StripeHandle,
    pub email: EmailClient,
    pub frontend_origin: FrontendOrigin,
}

/// Stripe owns webhook delivery and authenticates it by signature rather than
/// an account bearer. It is deliberately retained outside Connect.
pub fn router(state: BillingState) -> Router {
    Router::new()
        .route("/api/webhooks/stripe", post(webhook::stripe_webhook))
        .route(
            "/healthz/stripe-webhook-endpoint",
            get(stripe_endpoint_check::status),
        )
        .with_state(state)
}
