//! `codewire-coordinator` -- Rust tailnet coordinator entry point.

use codewire_coordinator::{CoordinatorState, router};
use codewire_server_core::auth::AuthState;
use codewire_server_core::{AppBuilder, ServiceConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("coordinator")?;
    codewire_server_core::obs::init(&cfg)?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    let auth = AuthState { pool: pool.clone() };
    let nats =
        codewire_server_core::nats::connect(cfg.nats_url.as_deref(), cfg.nats_token.as_deref())
            .await?;
    let mut state = CoordinatorState::new(pool.clone(), cfg.session_secret.clone());
    if let Some(client) = nats {
        state = state.with_nats_client(client).await?;
    }

    let app = AppBuilder::new("codewire-coordinator")
        .with_health_and_db(pool)
        .with_routes(router(state, auth))
        .into_router();

    codewire_server_core::serve_with_h2_keepalive(
        app,
        cfg.bind_addr,
        codewire_server_core::Http2KeepaliveConfig::new(
            Duration::from_secs(15),
            Duration::from_secs(20),
        ),
    )
    .await
}
