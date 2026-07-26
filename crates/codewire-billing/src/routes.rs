//! HTTP routes for the billing service.
//!
//! Every endpoint here requires authentication — the Caddy `@billing`
//! matcher and the nginx ingress only *route*, they do not authenticate,
//! so the auth gate must live in this service. Admin endpoints add
//! `require_admin` on top, mirroring the Go route registration
//! (`registerAdminRoutes` wraps `/admin/*` in requireAdminMiddleware).

use axum::Router;
use axum::extract::FromRef;
use axum::middleware;
use axum::routing::{get, post, put};
use codewire_server_core::auth::{AuthState, require_admin, require_auth};
use codewire_server_core::rest_sunset::{
    DeprecatedArea, RestSunsetConfig, observe as observe_rest_sunset,
};
use sqlx::PgPool;

use crate::checkout_sessions::FrontendOrigin;
use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;
use crate::{catalog, catalog_admin, checkout_sessions, org_billing, overview, plans, webhook};

// WS13 WI-2 introduces observation only. Future area-specific sunset WIs add
// their route-template prefixes here after their client-flip prerequisites.
const DEPRECATED_REST_AREAS: &[DeprecatedArea] = &[];

/// Shared handler state. `FromRef` lets the pure-DB handlers keep
/// extracting `State<PgPool>` while the Stripe-touching ones take the
/// whole state.
#[derive(Clone, FromRef)]
pub struct BillingState {
    pub pool: PgPool,
    pub stripe: StripeHandle,
    pub email: EmailClient,
    pub frontend_origin: FrontendOrigin,
}

/// Returns the billing service's `Router` with every endpoint the Rust
/// crate currently serves mounted on it. `auth` carries the pool +
/// bearer decryptor for the auth middleware. The parent `main.rs`
/// supplies everything.
pub fn router(state: BillingState, auth: AuthState) -> Router {
    let rest_sunset = RestSunsetConfig::new(DEPRECATED_REST_AREAS);
    // Admin surface: session/key auth + is_admin, like the Go
    // requireAuthMiddleware → requireAdminMiddleware chain.
    let admin = Router::new()
        .route("/api/v1/admin/billing/catalog", get(catalog::get_catalog))
        // Catalog plan write CRUD (#168).
        .route(
            "/api/v1/admin/billing/catalog/plans",
            post(catalog_admin::create_plan),
        )
        .route(
            "/api/v1/admin/billing/catalog/plans/{resource_type}/{plan_key}",
            put(catalog_admin::update_plan),
        )
        .route(
            "/api/v1/admin/billing/catalog/plans/{resource_type}/{plan_key}/archive",
            put(catalog_admin::set_plan_archive),
        )
        // Catalog price write CRUD + settings write (#38).
        .route(
            "/api/v1/admin/billing/catalog/prices",
            post(catalog_admin::create_price),
        )
        .route(
            "/api/v1/admin/billing/catalog/prices/{resource_type}/{plan_key}/{stripe_mode}/{price_kind}",
            put(catalog_admin::update_price),
        )
        .route(
            "/api/v1/admin/billing/catalog/prices/{resource_type}/{plan_key}/{stripe_mode}/{price_kind}/archive",
            put(catalog_admin::set_price_archive),
        )
        .route(
            "/api/v1/admin/billing/catalog/settings/{setting_key}",
            put(catalog_admin::update_setting),
        )
        // Subscription migrations (#168).
        .route(
            "/api/v1/admin/billing/catalog/subscription-migrations/preview",
            post(catalog_admin::preview_migration),
        )
        .route(
            "/api/v1/admin/billing/catalog/subscription-migrations",
            post(catalog_admin::run_migration).get(catalog_admin::list_migrations),
        )
        .route_layer(middleware::from_fn(require_admin));

    // Authenticated (non-admin) surface. Org-scoped routes do their own
    // membership check (require_org_member) inside the handler, exactly
    // like the Go handlers call getUserOrgRole.
    let authed = Router::new()
        .route(
            "/api/v1/billing/plans/{resource_type}",
            get(plans::get_plans),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing",
            get(overview::get_billing_overview),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing/invoices",
            get(org_billing::list_invoices),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing/events",
            get(org_billing::list_events),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/usage",
            get(overview::get_environment_usage),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing/checkout",
            post(checkout_sessions::create_checkout),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing/portal",
            post(checkout_sessions::create_portal),
        )
        .route(
            "/api/v1/organizations/{org_id}/billing/setup",
            post(checkout_sessions::create_setup),
        );

    // The Stripe webhook authenticates by signature, not session —
    // mounted OUTSIDE the require_auth layer, like the Go router keeps
    // it off the CookieAuth group.
    let public = observe_rest_sunset(
        Router::new().route("/api/webhooks/stripe", post(webhook::stripe_webhook)),
        rest_sunset,
    );

    // `route_layer` runs outermost-last-added, so adding require_auth
    // after merging puts it in front of require_admin.
    observe_rest_sunset(admin.merge(authed), rest_sunset)
        .route_layer(middleware::from_fn_with_state(auth, require_auth))
        .merge(public)
        .with_state(state)
}
