//! `codewire-billing` — entry point.
//!
//! Loads service config, connects Postgres, mounts the catalog routes
//! (see [`codewire_billing::routes`]), and serves on the configured port
//! (defaults to 8081 — see `ServiceConfig::from_env("billing")`).

use std::sync::Arc;

use codewire_billing::checkout_sessions::FrontendOrigin;
use codewire_billing::email::EmailClient;
use codewire_billing::routes::BillingState;
use codewire_billing::stripe_client::StripeHandle;
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::ConnectAuthLayer;
use codewire_server_core::{AppBuilder, ServiceConfig};

const DEFAULT_BILLING_LOOPS: &[&str] = &["env-usage-metering", "env-overage-billing", "trials"];

fn billing_loops_from_env() -> Vec<String> {
    billing_loops_from(std::env::var("BILLING_LOOPS").ok().as_deref())
}

fn billing_loops_from(value: Option<&str>) -> Vec<String> {
    value.map(parse_loop_list).unwrap_or_else(|| {
        DEFAULT_BILLING_LOOPS
            .iter()
            .map(|s| s.to_string())
            .collect()
    })
}

fn parse_loop_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("billing")?;
    codewire_server_core::obs::init(&cfg)?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    let auth = AuthState { pool: pool.clone() };

    let state = BillingState {
        pool: pool.clone(),
        // Stripe configuration is required for a billing deployment. Keep the
        // existing handle fail-closed for a deployment misconfiguration; it is
        // not a BillingCatalogService wire outcome.
        stripe: StripeHandle::from_env(),
        // Emails are disabled without RESEND_API_KEY, same as Go.
        email: EmailClient::new(std::env::var("RESEND_API_KEY").unwrap_or_default()),
        frontend_origin: FrontendOrigin::parse(
            &std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:5173".to_string()),
        )?,
    };

    // Leader-gated billing loops: usage metering, overage invoicing,
    // trial expiry. BILLING_LOOPS remains an explicit override for
    // focused diagnostics; unset means the Rust-owned production set.
    let loops = billing_loops_from_env();
    if !loops.is_empty() {
        let deps = Arc::new(codewire_billing::metering::MeteringDeps {
            pool: pool.clone(),
            stripe: Arc::new(StripeHandle::from_env()),
            email: Arc::new(EmailClient::new(
                std::env::var("RESEND_API_KEY").unwrap_or_default(),
            )),
            database_url: cfg.database_url.clone(),
        });
        codewire_billing::metering::start_loops(deps, &loops);
    }

    // Temporal billing worker (#38): runs OrgTeardownWorkflow on the
    // codewire-billing queue so org deletion can cancel Stripe
    // subscriptions cross-service. Non-fatal: the spawn loop retries
    // internally if Temporal is unreachable at startup.
    match std::env::var("TEMPORAL_HOST_PORT") {
        Ok(host_port) if !host_port.is_empty() => {
            let namespace =
                std::env::var("TEMPORAL_NAMESPACE").unwrap_or_else(|_| "default".to_string());
            codewire_billing::temporal::spawn_org_teardown_worker(
                pool.clone(),
                StripeHandle::from_env(),
                host_port,
                namespace,
            );
        }
        _ => {
            tracing::info!("TEMPORAL_HOST_PORT unset; org-teardown worker disabled");
        }
    }

    let connect_auth = ConnectAuthLayer::authenticated(auth.clone());
    let connect_admin_auth = ConnectAuthLayer::admin(auth.clone());
    let app = AppBuilder::new("codewire-billing")
        .with_health_and_db(pool.clone())
        .with_unary_connect_routes_auth(
            codewire_billing::connect::billing::router(state.clone()),
            connect_auth,
        )
        .with_unary_connect_routes_auth(
            codewire_billing::connect::catalog::router(state.clone()),
            connect_admin_auth,
        )
        // Connect conformance probe (doc 03 D8) — no-op unless
        // CONNECT_TESTING_SURFACE=1 (dev-stack/CI/kind only).
        .with_connect_testing_surface(auth.clone())
        .with_routes(codewire_billing::router(state, auth))
        .into_router();

    codewire_server_core::serve(app, cfg.bind_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_loops_default_to_rust_owned_set() {
        assert_eq!(
            billing_loops_from(None),
            vec!["env-usage-metering", "env-overage-billing", "trials"]
        );
    }

    #[test]
    fn billing_loops_empty_override_disables_loops() {
        assert!(billing_loops_from(Some("")).is_empty());
    }

    #[test]
    fn billing_loops_parse_trimmed_override() {
        assert_eq!(
            billing_loops_from(Some(" env-usage-metering, trials ,, ")),
            vec!["env-usage-metering", "trials"]
        );
    }
}
