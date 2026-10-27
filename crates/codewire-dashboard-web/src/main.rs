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
    // Trace export only: the dashboard writes no logs, and without
    // OTEL_EXPORTER_OTLP_ENDPOINT this installs nothing.
    let traces = codewire_server_core::obs::init_traces_only(
        "dashboard",
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().as_deref(),
    )?;
    let listen_addr = config.listen_addr;
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind dashboard SSR listener {listen_addr}"))?;

    let served = axum::serve(listener, app(config))
        .await
        .context("serve dashboard SSR");
    traces.shutdown().await;
    served
}
