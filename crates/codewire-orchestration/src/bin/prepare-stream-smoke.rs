//! Live ingress proof for WS06 WI-2 WatchEnvironmentCreate.
//!
//! Drives the deterministic non-analysis prepare path through the configured
//! edge and proves typed ordering plus the per-response no-buffering marker.

use anyhow::Context as _;
use codewire_proto::codewire::v1::{
    CreateEnvironmentRequest, EnvironmentServiceClient, WatchEnvironmentCreateRequest,
    WatchEnvironmentCreateResponse, watch_environment_create_response::EventView,
};
use connectrpc::client::{ClientConfig, HttpClient};
use reqwest::header::COOKIE;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let direct_base_url = required_env("SMOKE_DIRECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;

    run_prepare(&direct_base_url, &org_id, &session_token, "direct", true).await?;
    run_prepare(&base_url, &org_id, &session_token, "ingress", false).await?;

    println!("prepare-stream-smoke: typed direct and ingress stream ordering green");
    Ok(())
}

async fn run_prepare(
    base_url: &str,
    org_id: &str,
    session_token: &str,
    route: &str,
    assert_no_buffering_header: bool,
) -> anyhow::Result<()> {
    let repo_url = format!("https://example.test/codewire/kind-prepare-stream-{route}");

    let config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = EnvironmentServiceClient::new(HttpClient::plaintext(), config);
    let mut stream = client
        .watch_environment_create(WatchEnvironmentCreateRequest {
            org_id: org_id.to_owned(),
            draft: Some(CreateEnvironmentRequest {
                org_id: org_id.to_owned(),
                repo_url,
                ..Default::default()
            })
            .into(),
            analyze: Some(false),
            ..Default::default()
        })
        .await
        .context("open WatchEnvironmentCreate")?;

    if assert_no_buffering_header {
        anyhow::ensure!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|value| value.to_str().ok())
                == Some("no"),
            "direct WatchEnvironmentCreate response lacks X-Accel-Buffering: no"
        );
    }

    let mut events = Vec::new();
    while let Some(message) = stream
        .message::<WatchEnvironmentCreateResponse>()
        .await
        .context("receive WatchEnvironmentCreate frame")?
    {
        match &message.view().event {
            Some(EventView::Progress(progress)) => events.push(progress.phase.to_owned()),
            Some(EventView::Complete(_)) => events.push("complete".into()),
            Some(EventView::RepoFetched(event)) => {
                anyhow::bail!(
                    "non-analysis prepare emitted repo_fetched for {}",
                    event.repo
                )
            }
            None => anyhow::bail!("WatchEnvironmentCreate emitted an empty event"),
        }
    }

    anyhow::ensure!(
        events == ["repo_config", "resolving", "complete"],
        "{route} WatchEnvironmentCreate events {events:?} did not preserve deterministic ordering"
    );
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
