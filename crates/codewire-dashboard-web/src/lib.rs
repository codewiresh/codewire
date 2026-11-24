//! Production server-rendered dashboard adapter.
//!
//! The adapter owns presentation and progressive enhancement. Identity stays
//! on the raw IdP session contract and product data stays on generated Connect
//! services. Only the canonical browser session cookie crosses those bounds.

mod account_home;
mod account_sessions;
mod account_sign_in_methods;
mod account_two_factor;
mod admin_account_deletion;
mod admin_connect;
mod admin_sandbox_counts;
mod assets;
mod auth;
mod billing_banner;
mod billing_connect;
mod config;
mod connect;
mod credentials_connect;
mod dependency;
mod docs;
mod environment_connect;
mod environment_drafts;
mod environment_source_forms;
mod environment_sources;
mod error;
mod github_check;
mod hosts_connect;
mod live_connect;
mod mailto;
mod network_policies_connect;
mod organization_connect;
mod personal_api_keys_connect;
mod public_rates;
mod raw_auth;
mod response;
mod routes;
mod secrets_presets_connect;
mod security;
mod server_timing;
mod sse_heartbeat;
mod state;
mod templates;
#[cfg(test)]
mod test_support;
mod time_display;
mod transport;
mod updates_connect;
mod usage_scale;
mod view;

use axum::Router;

pub use config::{Config, RuntimeMode};

/// The targets the dashboard writes logs for, each at its level and above,
/// for `codewire_server_core::obs::init_traces_with_logs_from`. Nothing else
/// in the dashboard, or in a library it uses, writes a log line.
pub const LOG_TARGETS: &[(&str, tracing::Level)] = &[updates_connect::LOG_TARGET];
use state::AppState;

/// Build the dashboard router without starting a listener.
///
/// Keeping construction side-effect free lets route lanes compose and test
/// their own routers while the final runtime remains one Axum application.
pub fn app(config: Config) -> Router {
    let state = AppState::new(config);
    Router::new()
        .merge(
            routes::router()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    security::ensure_page_csrf_cookie,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    routes::remember_organization,
                ))
                .layer(axum::middleware::from_fn(security::keep_responses_private))
                .layer(axum::middleware::from_fn(
                    server_timing::total_for_signed_in_pages,
                )),
        )
        .merge(assets::router())
        .merge(docs::router())
        .with_state(state)
        .layer(axum::middleware::map_response(
            security::mark_unmarked_responses_private,
        ))
        .layer(codewire_server_core::http::request_trace_layer())
}

#[cfg(test)]
mod tests;
