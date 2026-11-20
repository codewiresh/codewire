use std::time::Duration;

use codewire_mesh::{Config, serve};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // JSON lines at info unless RUST_LOG says otherwise, as the other services
    // log, so a replica that can't reach its shared registry says so (#5515).
    codewire_server_core::obs::init_logs();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let config = Config::from_sources(&args, |key| std::env::var(key).ok())?;
    serve(config, shutdown_signal()).await
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
