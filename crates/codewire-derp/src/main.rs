use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // JSON lines on stdout at info unless RUST_LOG says otherwise, as the
    // other services log: an alert matches the relay's warning that its public
    // certificate didn't load (#4000).
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    codewire_derp::run_from_env().await
}
