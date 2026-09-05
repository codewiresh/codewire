pub mod client;
pub mod config;
mod credential_bridge;
mod durable_session;
pub mod env;
pub mod execution;
pub mod files;
pub mod server;
pub mod service;
pub mod session;

pub use config::{
    Config, CredentialBridgeConfig, DEFAULT_HOME_ROOT, DEFAULT_LISTEN_ADDR, DEFAULT_WORKSPACE_ROOT,
    HOME_ROOT_ENV, SHIM_ADDR_ENV, WORKSPACE_ROOT_ENV,
};
pub use server::{run, serve_grpc_with_incoming};

use std::time::Duration;

use tracing_subscriber::EnvFilter;

/// Run the environment-daemon process entrypoint shared by the standalone
/// compatibility binary and the self-contained `cw daemon` mode.
pub async fn run_entrypoint() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    run(Config::from_env(), shutdown_signal()).await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    tokio::time::sleep(Duration::from_millis(10)).await;
}
