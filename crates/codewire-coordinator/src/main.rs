//! `codewire-coordinator` -- Rust tailnet coordinator entry point.

use codewire_coordinator::{CoordinatorState, DerpMap, derp_verify_router, router};
use codewire_server_core::auth::AuthState;
use codewire_server_core::{AppBuilder, ServiceConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("coordinator")?;
    codewire_server_core::obs::init(&cfg)?;
    let derp_map = DerpMap::from_env()?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    let auth = AuthState { pool: pool.clone() };
    let nats =
        codewire_server_core::nats::connect(cfg.nats_url.as_deref(), cfg.nats_token.as_deref())
            .await?;
    let mut state = CoordinatorState::new(pool.clone(), cfg.session_secret.clone(), derp_map);
    if let Some(client) = nats {
        state = state.with_nats_client(client, cfg.nats_kv_replicas).await?;
    }

    // DERP's client admission lookup (#2844), on its own listener so no
    // ingress route reaches it. Unset in local runs and tests.
    let derp_verify = match std::env::var("COORDINATOR_DERP_VERIFY_ADDR") {
        Ok(raw) if !raw.trim().is_empty() => {
            let addr: std::net::SocketAddr = raw.trim().parse()?;
            Some(tokio::spawn(codewire_server_core::serve(
                derp_verify_router(state.clone()),
                addr,
            )))
        }
        _ => None,
    };

    let app = AppBuilder::new("codewire-coordinator")
        .with_health_and_db(pool)
        .with_routes(router(state, auth))
        .into_router();

    let main = codewire_server_core::serve_with_h2_keepalive(
        app,
        cfg.bind_addr,
        codewire_server_core::Http2KeepaliveConfig::new(
            Duration::from_secs(15),
            Duration::from_secs(20),
        ),
    );
    let Some(derp_verify) = derp_verify else {
        return main.await;
    };
    tokio::pin!(main);
    tokio::select! {
        result = &mut main => result,
        // It ends on its own only at shutdown, or when it cannot bind.
        result = derp_verify => {
            result??;
            main.await
        }
    }
}
