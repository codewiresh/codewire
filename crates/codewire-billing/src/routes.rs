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
    pub credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    /// Who emails the receipt for a paid invoice (#4816).
    pub receipts: crate::receipts::ReceiptSender,
    pub frontend_origin: FrontendOrigin,
    /// `CODEWIRE_OPERATOR_EMAIL`: where paid credit purchases are announced
    /// (#5358), or `None` to send no notice.
    pub operator_email: Option<String>,
    /// Keys the client-address hashes the card-setup limit counts (#4901).
    pub card_setup_address_key: crate::cards::CardSetupAddressKey,
}

/// The builder of billing's API router, which `main` mounts every route on.
/// `/metrics` is served only on its own port, open to every source, so the
/// API port, which only the edge and the dashboard reach, serves none (#4901).
pub fn api_builder() -> codewire_server_core::AppBuilder {
    codewire_server_core::AppBuilder::new("codewire-billing").without_metrics()
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
        .route(
            "/healthz/stripe-webhook-delivery",
            get(crate::stripe_delivery_check::status),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    /// What ships: the API router `main` builds serves no `/metrics`, so a
    /// change that drops `without_metrics` is caught here (#4901).
    #[tokio::test]
    async fn the_api_router_serves_no_metrics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = super::api_builder().into_router();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reqwest::get(format!("http://{address}/metrics")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), 404);
        server.abort();
    }
}
