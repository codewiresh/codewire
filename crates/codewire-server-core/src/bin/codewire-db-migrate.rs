#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = codewire_server_core::config::database_url_from_env()?;
    codewire_server_core::migrate::ensure_schema(&database_url).await
}
