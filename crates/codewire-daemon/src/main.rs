#[tokio::main]
async fn main() -> anyhow::Result<()> {
    codewire_daemon::run_entrypoint().await
}
