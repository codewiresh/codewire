//! Production server-rendered dashboard adapter.
//!
//! The adapter owns presentation and progressive enhancement. Identity stays
//! on the raw IdP session contract and product data stays on generated Connect
//! services. Only the canonical browser session cookie crosses those bounds.

mod account_sessions;
mod account_two_factor;
mod admin_connect;
mod assets;
mod auth;
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
mod organization_connect;
mod personal_api_keys_connect;
mod raw_auth;
mod response;
mod routes;
mod secrets_presets_connect;
mod security;
mod server_timing;
mod state;
mod templates;
mod time_display;
mod transport;
mod view;

use axum::Router;

pub use config::{Config, RuntimeMode};
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
                )),
        )
        .merge(assets::router())
        .merge(docs::router())
        .with_state(state)
        .layer(codewire_server_core::http::request_trace_layer())
}

#[cfg(test)]
mod tests;
