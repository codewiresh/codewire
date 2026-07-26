//! Live-cluster smoke for the gateway SSH/SFTP readiness path.
//!
//! Env:
//!   SMOKE_NAMESPACE  Sandbox namespace (default "dev-sandboxes")
//!   SMOKE_ENV_ID     Environment ID to resolve to a SandboxClaim/pod
//!   SMOKE_PORT       Gateway SSH port (default 2222)

use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_orchestration::sandbox::sidecar::DEFAULT_GATEWAY_SSH_PORT;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let namespace =
        std::env::var("SMOKE_NAMESPACE").unwrap_or_else(|_| "dev-sandboxes".to_string());
    let env_id =
        std::env::var("SMOKE_ENV_ID").map_err(|_| anyhow::anyhow!("SMOKE_ENV_ID is required"))?;
    let port = std::env::var("SMOKE_PORT")
        .ok()
        .map(|value| value.parse::<u16>())
        .transpose()?
        .unwrap_or(DEFAULT_GATEWAY_SSH_PORT);

    let client = SandboxClient::from_env(&namespace).await?;
    client.check_sidecar_ready(&env_id, port).await?;

    println!("sidecar-smoke: SSH/SFTP readiness OK for {env_id} in {namespace}");
    Ok(())
}
