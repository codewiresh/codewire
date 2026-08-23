//! One-shot, value-blind operator for the tenant-secret authority transition.

use codewire_orchestration::worker::tenant_secret_operator::{
    TenantSecretOperatorCommand, run_tenant_secret_operator,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args();
    let _binary = arguments.next();
    let command = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("tenant-secret-operator failure_class=missing-command"))?;
    if arguments.next().is_some() {
        anyhow::bail!("tenant-secret-operator failure_class=unexpected-argument");
    }
    let command = TenantSecretOperatorCommand::parse(&command)?;
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("tenant-secret-operator failure_class=missing-database"))?;
    let pool = codewire_server_core::db::connect(&database_url)
        .await
        .map_err(|_| anyhow::anyhow!("tenant-secret-operator failure_class=database-connect"))?;
    let summary = run_tenant_secret_operator(command, pool.clone()).await?;
    println!("{}", serde_json::to_string(&summary)?);
    pool.close().await;
    Ok(())
}
