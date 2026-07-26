//! Rust-owned deploy-shaped proof for TTL eviction in Kind.
//!
//! Creates a real environment through the Rust Connect service, waits for its
//! SandboxClaim and workspace Pod, expires it in PostgreSQL, then proves the
//! Rust reconciler and Temporal lifecycle delete every Kubernetes runtime and
//! record the authoritative journal trail.

use std::time::Duration;

use anyhow::Context as _;
use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_proto::codewire::v1::{CreateEnvironmentRequest, EnvironmentServiceClient};
use connectrpc::client::{ClientConfig, HttpClient};
use reqwest::header::COOKIE;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_ORCHESTRATION_URL")?;
    let database_url = required_env("DATABASE_URL")?;
    let namespace = required_env("SMOKE_SANDBOX_NAMESPACE")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let image = std::env::var("SMOKE_WORKSPACE_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/codewiresh/workspace:latest".into());
    let repo_url = std::env::var("SMOKE_REPO_URL")
        .unwrap_or_else(|_| "https://github.com/codewiresh/example".into());

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("connect TTL smoke PostgreSQL")?;
    sqlx::query("DELETE FROM rate_limit WHERE key LIKE 'env_create:%'")
        .execute(&pool)
        .await
        .context("clear environment-create rate limit")?;

    let config = ClientConfig::new(base_url.parse().context("parse orchestration URL")?)
        .with_default_timeout(Duration::from_secs(30))
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = EnvironmentServiceClient::new(HttpClient::plaintext(), config);
    let response = client
        .create_environment(CreateEnvironmentRequest {
            org_id: org_id.clone(),
            name: Some(format!(
                "rust-ttl-smoke-{}",
                &Uuid::new_v4().to_string()[..8]
            )),
            image,
            repo_url,
            ..Default::default()
        })
        .await
        .context("CreateEnvironment for TTL smoke")?
        .into_owned();
    let environment_id = response
        .environment
        .into_option()
        .context("CreateEnvironment omitted environment")?
        .id;
    anyhow::ensure!(
        !environment_id.is_empty(),
        "CreateEnvironment returned empty id"
    );

    wait_environment_state(
        &pool,
        &environment_id,
        "running",
        Duration::from_secs(8 * 60),
    )
    .await?;
    let sandbox = SandboxClient::from_env(&namespace)
        .await
        .context("create ambient Kind sandbox client")?;
    sandbox
        .wait_for_ready(&environment_id, Duration::from_secs(2 * 60))
        .await
        .context("wait TTL smoke SandboxClaim Ready")?;
    let pods_before = sandbox
        .list_workspace_pod_identities(&environment_id)
        .await
        .context("list TTL smoke workspace Pods")?;
    anyhow::ensure!(
        !pods_before.is_empty(),
        "running environment had no workspace Pod"
    );

    sqlx::query(
        "UPDATE environments
            SET shutdown_at = NOW() - INTERVAL '1 minute',
                ttl_warning_sent_at = NULL,
                protected = false
          WHERE id = $1",
    )
    .bind(&environment_id)
    .execute(&pool)
    .await
    .context("expire TTL smoke environment")?;

    wait_environment_state(
        &pool,
        &environment_id,
        "destroyed",
        Duration::from_secs(3 * 60),
    )
    .await?;
    sandbox
        .wait_for_deleted(&environment_id, Duration::from_secs(60))
        .await
        .context("wait TTL smoke SandboxClaim deletion")?;
    let pods_after = sandbox
        .list_workspace_pod_identities(&environment_id)
        .await
        .context("list workspace Pods after TTL eviction")?;
    anyhow::ensure!(
        pods_after.is_empty(),
        "TTL eviction left Pods: {pods_after:?}"
    );

    for (predicate, label) in [
        (
            "kind = 'intent' AND to_state = 'destroyed'",
            "destroy intent",
        ),
        (
            "kind = 'reconcile_request' AND actor = 'reconciler'",
            "reconciler request",
        ),
        (
            "kind = 'transition' AND from_state = 'running' AND to_state = 'destroying'",
            "running-to-destroying transition",
        ),
        (
            "kind = 'transition' AND from_state = 'destroying' AND to_state = 'destroyed' AND metadata->>'kind' = 'external_cleanup_complete'",
            "external-cleanup terminal transition",
        ),
    ] {
        let query = format!(
            "SELECT COUNT(*) FROM environment_lifecycle_journal WHERE environment_id = $1 AND {predicate}"
        );
        let count: i64 = sqlx::query_scalar(&query)
            .bind(&environment_id)
            .fetch_one(&pool)
            .await
            .with_context(|| format!("query {label}"))?;
        anyhow::ensure!(count > 0, "TTL eviction omitted {label}");
    }

    let terminal: (
        String,
        String,
        Option<chrono::NaiveDateTime>,
        Option<chrono::NaiveDateTime>,
    ) = sqlx::query_as(
        "SELECT state, desired_state, destroyed_at, external_cleanup_completed_at
               FROM environments WHERE id = $1",
    )
    .bind(&environment_id)
    .fetch_one(&pool)
    .await
    .context("read TTL smoke terminal state")?;
    anyhow::ensure!(
        terminal.0 == "destroyed"
            && terminal.1 == "destroyed"
            && terminal.2.is_some()
            && terminal.3.is_some(),
        "TTL terminal state incomplete: {terminal:?}"
    );

    println!(
        "reconciler-ttl-smoke: Connect create, expiry reconcile, Temporal destroy, journal, SandboxClaim, and Pod cleanup green"
    );
    Ok(())
}

async fn wait_environment_state(
    pool: &PgPool,
    environment_id: &str,
    expected: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT state, desired_state, error_reason FROM environments WHERE id = $1",
        )
        .bind(environment_id)
        .fetch_optional(pool)
        .await?;
        if let Some((ref state, ref desired, ref reason)) = row {
            if state == expected && (expected != "destroyed" || desired == "destroyed") {
                return Ok(());
            }
            if state == "error" {
                anyhow::bail!(
                    "environment {environment_id} entered error before {expected}: {reason:?}"
                );
            }
            if state == "destroyed" && expected != "destroyed" {
                anyhow::bail!("environment {environment_id} was destroyed before {expected}");
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("environment {environment_id} did not reach {expected}: {row:?}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
