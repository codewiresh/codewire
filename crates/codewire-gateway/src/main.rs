use std::time::Duration;

use codewire_gateway::config::GatewayConfig;
use codewire_gateway::readiness::readiness_check_with_timeout;
use codewire_gateway::runtime::run_gateway;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = GatewayConfig::from_env()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("readiness") {
        readiness_check_with_timeout(&config.ssh_listen_addr, Duration::from_secs(2)).await?;
        return Ok(());
    }
    run_gateway(config).await
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,codewire_gateway=debug,codewire_tailnet=debug"));

    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_current_span(false)
        .with_env_filter(env_filter)
        .init();
}
