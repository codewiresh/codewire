//! Live-cluster smoke for the workspace daemon's SSH/SFTP readiness path.
//!
//! Env:
//!   SMOKE_NAMESPACE  Sandbox namespace (default "dev-sandboxes")
//!   SMOKE_ENV_ID     Environment ID to resolve to a SandboxClaim/pod
//!   SMOKE_PORT       Workspace daemon SSH port (default 2222)
//!   SMOKE_HOST_KEY   The environment's recorded host key, one OpenSSH line

use async_trait::async_trait;
use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_orchestration::sandbox::host_keys::HostKeyStore;
use codewire_orchestration::sandbox::sidecar::WORKSPACE_SSH_PORT;

/// The host key the operator read from `GetEnvironmentHostKey`.
struct GivenHostKey(String);

#[async_trait]
impl HostKeyStore for GivenHostKey {
    async fn current_host_key(
        &self,
        _environment_id: &str,
    ) -> Result<Option<(i64, String)>, sqlx::Error> {
        Ok(Some((0, self.0.clone())))
    }
}

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
        .unwrap_or(WORKSPACE_SSH_PORT);

    let host_key = std::env::var("SMOKE_HOST_KEY")
        .map_err(|_| anyhow::anyhow!("SMOKE_HOST_KEY is required"))?;

    let client = SandboxClient::from_env(&namespace).await?;
    client
        .check_sidecar_ready(&env_id, port, &GivenHostKey(host_key))
        .await?;

    println!("sidecar-smoke: SSH/SFTP readiness OK for {env_id} in {namespace}");
    Ok(())
}
