use codewire_udp_relay::Config;

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
    codewire_udp_relay::serve(&cfg, wait_shutdown()).await
}

async fn wait_shutdown() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %err, "failed to install ctrl-c handler");
    }
}
