use anyhow::Context as _;
use codewire_dashboard_web::{Config, RuntimeMode, app};

fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    let mut builder = match config.runtime_mode {
        RuntimeMode::MultiThread => tokio::runtime::Builder::new_multi_thread(),
        RuntimeMode::CurrentThread => tokio::runtime::Builder::new_current_thread(),
    };
    builder.enable_all();
    builder
        .build()
        .context("build dashboard Tokio runtime")?
        .block_on(run(config))
}

async fn run(config: Config) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr;
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind dashboard SSR listener {listen_addr}"))?;

    axum::serve(listener, app(config))
        .await
        .context("serve dashboard SSR")
}
