use anyhow::Context as _;
use codewire_dashboard_web::{Config, LOG_TARGETS, RuntimeMode, app};

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
    // Trace export when OTEL_EXPORTER_OTLP_ENDPOINT is set, and logs from
    // LOG_TARGETS only.
    let traces = codewire_server_core::obs::init_traces_with_logs_from(
        "dashboard",
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().as_deref(),
        LOG_TARGETS,
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
