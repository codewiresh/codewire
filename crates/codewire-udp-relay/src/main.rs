use std::time::Duration;

use codewire_tls::{PeerTlsListener, TlsPeer};
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

    // A key that lasts only as long as the process is the intended setup (#3926).
    // Allocations and the challenge secret are in memory, so a restart ends
    // every endpoint whatever the key. Endpoint ids restart too, and a client
    // ignores a lower id from a disco key it knows, until its old endpoint goes
    // stale; a new key lets it take the new endpoint at once.
    if cfg.disco_private_key_hex.is_none() {
        tracing::info!(
            env = codewire_udp_relay::DISCO_PRIVATE_KEY_HEX_ENV,
            "udp relay generated a disco key for this process"
        );
    }
    // Each handshake reads the identity and client roots again, so files
    // that cannot serve one now only close the TLS allocator until they are
    // repaired. They never stop relay data, which needs none of them.
    let allocator_tls = match &cfg.allocator_tls {
        Some(tls) => {
            let files = tls.files()?;
            if let Err(error) = files.validate().await {
                tracing::error!(
                    %error,
                    "udp relay allocator TLS files cannot serve a handshake; the TLS allocator refuses every caller until they can"
                );
            }
            Some((tls.bind_addr, files))
        }
        None => None,
    };

    let runtime = RelayRuntime::bind(&cfg).await?;
    let allocator_app = runtime.allocator_app();
    let allocator_tls_app = runtime.allocator_tls_app();
    let ops_app = runtime.ops_app();
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

    let allocator_listener = tokio::net::TcpListener::bind(cfg.allocator_bind_addr).await?;
    let ops_listener = tokio::net::TcpListener::bind(cfg.ops_bind_addr).await?;
    tracing::info!(
        allocator_addr = %cfg.allocator_bind_addr,
        ops_addr = %cfg.ops_bind_addr,
        udp_addr = %cfg.udp_bind_addr,
        advertise_count = cfg.udp_advertise_addr_ports.len(),
        "codewire udp peer relay started"
    );

    let allocator = axum::serve(allocator_listener, allocator_app)
        .with_graceful_shutdown(wait_shutdown())
        .into_future();
    let ops = axum::serve(ops_listener, ops_app)
        .with_graceful_shutdown(wait_shutdown())
        .into_future();
    let allocator_tls = async {
        let Some((addr, files)) = allocator_tls else {
            return Ok(());
        };
        let listener = PeerTlsListener::new(tokio::net::TcpListener::bind(addr).await?, files)
            .map_err(std::io::Error::other)?;
        tracing::info!(
            allocator_tls_addr = %addr,
            "udp relay allocator TLS listener started"
        );
        axum::serve(
            listener,
            allocator_tls_app.into_make_service_with_connect_info::<TlsPeer>(),
        )
        .with_graceful_shutdown(wait_shutdown())
        .await
    };
    let result = tokio::try_join!(allocator, ops, allocator_tls);
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
