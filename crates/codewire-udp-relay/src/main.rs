use std::time::Duration;

use codewire_udp_relay::{Config, RelayRuntime};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "codewire_udp_relay=info,codewire_tailnet=info".into()),
        )
        .init();

    if cfg.disco_private_key_hex.is_none() {
        tracing::warn!(
            env = codewire_udp_relay::DISCO_PRIVATE_KEY_HEX_ENV,
            "udp relay using ephemeral disco key; configure persistent key before production rollout"
        );
    }
    if cfg.allocator_token.is_none() {
        tracing::warn!(
            env = codewire_udp_relay::ALLOCATOR_TOKEN_ENV,
            "udp relay allocator token unset; rely on local development or network policy only"
        );
    }

    let runtime = RelayRuntime::bind(&cfg).await?;
    let app = runtime.app();
    let server = runtime.into_server();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let udp_task = tokio::spawn(async move {
        server
            .run_until(async move {
                let mut shutdown_rx = shutdown_rx;
                loop {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
    });

    let listener = tokio::net::TcpListener::bind(cfg.http_bind_addr).await?;
    tracing::info!(
        http_addr = %cfg.http_bind_addr,
        udp_addr = %cfg.udp_bind_addr,
        advertise_count = cfg.udp_advertise_addr_ports.len(),
        "codewire udp peer relay started"
    );

    let http = axum::serve(listener, app).with_graceful_shutdown(wait_shutdown());
    let result = http.await;
    let _ = shutdown_tx.send(true);
    match tokio::time::timeout(Duration::from_secs(5), udp_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => return Err(err.into()),
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => tracing::warn!("udp relay socket task did not stop within timeout"),
    }
    result?;
    Ok(())
}

async fn wait_shutdown() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %err, "failed to install ctrl-c handler");
    }
}
