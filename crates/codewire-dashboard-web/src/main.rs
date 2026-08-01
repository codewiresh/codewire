use anyhow::Context as _;
use codewire_dashboard_web::{Config, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    let listen_addr = config.listen_addr;
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind dashboard SSR listener {listen_addr}"))?;

    axum::serve(listener, app(config))
        .await
        .context("serve dashboard SSR")
}
