//! Disposable KIND proof for the gateway's production coordinator selector.

use codewire_gateway::config::{CoordinateTransport, GatewayConfig};
use codewire_gateway::tailnet::coordinator_selector_probe;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = GatewayConfig::from_env()?;
    let tailnet = config.tailnet.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "CODEWIRE_COORDINATOR_URL, CODEWIRE_ENVIRONMENT_ID, and CODEWIRE_GATEWAY_TOKEN are required"
        )
    })?;
    let expected = match std::env::var("KIND_EXPECTED_COORDINATE_TRANSPORT")?.as_str() {
        "ws" => CoordinateTransport::Ws,
        "connect" => CoordinateTransport::Connect,
        value => anyhow::bail!(
            "KIND_EXPECTED_COORDINATE_TRANSPORT must be exactly ws or connect; got {value:?}"
        ),
    };
    let selected = coordinator_selector_probe(tailnet).await?;
    anyhow::ensure!(
        selected == expected,
        "gateway selector chose {selected:?}, expected {expected:?}"
    );
    println!("coordinator-selector-smoke: selected {selected:?}: OK");
    Ok(())
}
