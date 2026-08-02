//! Live ingress proof for WS06 WI-5 StreamExec.
//!
//! Runs a paced command through Connect and proves ordered events, terminal
//! status, and incremental delivery through ingress-nginx.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use codewire_proto::codewire::v1::{
    ExecServiceClient, StreamExecRequest, StreamExecResponse, stream_exec_response::EventView,
};
use connectrpc::client::{ClientConfig, HttpClient};
use reqwest::header::COOKIE;

const COMMAND: &str = "printf 'stdout-1\\n'; sleep 1; printf 'stderr-1\\n' >&2; sleep 1; printf 'stdout-2\\n'; exit 17";

#[derive(Debug)]
struct Observation {
    kind: &'static str,
    data: Vec<u8>,
    exit_code: Option<i32>,
    arrived: Duration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let direct_base_url = required_env("SMOKE_DIRECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;

    assert_direct_connect_header(&direct_base_url, &org_id, &environment_id, &session_token)
        .await?;
    let connect = run_connect(&base_url, &org_id, &environment_id, &session_token).await?;
    println!("exec-stream-smoke: Connect ordered incremental stream green ({connect:?})");
    Ok(())
}

async fn assert_direct_connect_header(
    base_url: &str,
    org_id: &str,
    environment_id: &str,
    session_token: &str,
) -> anyhow::Result<()> {
    let config = ClientConfig::new(base_url.parse().context("parse direct Connect base URL")?)
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = ExecServiceClient::new(HttpClient::plaintext(), config);
    let mut stream = client
        .stream_exec(StreamExecRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            command: vec!["true".into()],
            ..Default::default()
        })
        .await
        .context("open direct StreamExec header probe")?;
    anyhow::ensure!(
        stream
            .headers()
            .get("x-accel-buffering")
            .and_then(|value| value.to_str().ok())
            == Some("no"),
        "direct StreamExec response lacks X-Accel-Buffering: no"
    );
    while stream
        .message::<StreamExecResponse>()
        .await
        .context("receive direct StreamExec header probe")?
        .is_some()
    {}
    Ok(())
}

async fn run_connect(
    base_url: &str,
    org_id: &str,
    environment_id: &str,
    session_token: &str,
) -> anyhow::Result<Duration> {
    let config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = ExecServiceClient::new(HttpClient::plaintext(), config);
    let mut stream = client
        .stream_exec(StreamExecRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            command: vec!["sh".into(), "-c".into(), COMMAND.into()],
            ..Default::default()
        })
        .await
        .context("open StreamExec")?;

    let started = Instant::now();
    let mut observations = Vec::new();
    while let Some(message) = stream
        .message::<StreamExecResponse>()
        .await
        .context("receive StreamExec frame")?
    {
        let observation = match message.view().event {
            Some(EventView::Stdout(bytes)) => Observation {
                kind: "stdout",
                data: bytes.to_vec(),
                exit_code: None,
                arrived: started.elapsed(),
            },
            Some(EventView::Stderr(bytes)) => Observation {
                kind: "stderr",
                data: bytes.to_vec(),
                exit_code: None,
                arrived: started.elapsed(),
            },
            Some(EventView::ExitCode(exit_code)) => Observation {
                kind: "exit",
                data: Vec::new(),
                exit_code: Some(exit_code),
                arrived: started.elapsed(),
            },
            None => anyhow::bail!("StreamExec emitted an empty event"),
        };
        observations.push(observation);
    }

    validate_observations("Connect", &observations)
}

fn validate_observations(label: &str, observations: &[Observation]) -> anyhow::Result<Duration> {
    let kinds: Vec<_> = observations.iter().map(|event| event.kind).collect();
    anyhow::ensure!(
        kinds == ["stdout", "stderr", "stdout", "exit"],
        "{label} event order = {kinds:?}, want stdout/stderr/stdout/exit"
    );
    anyhow::ensure!(
        observations[0].data == b"stdout-1\n",
        "{label} first stdout = {:?}",
        observations[0].data
    );
    anyhow::ensure!(
        observations[1].data == b"stderr-1\n",
        "{label} stderr = {:?}",
        observations[1].data
    );
    anyhow::ensure!(
        observations[2].data == b"stdout-2\n",
        "{label} second stdout = {:?}",
        observations[2].data
    );
    anyhow::ensure!(
        observations[3].exit_code == Some(17),
        "{label} exit = {:?}, want 17",
        observations[3].exit_code
    );

    let spread = observations[2]
        .arrived
        .saturating_sub(observations[0].arrived);
    anyhow::ensure!(
        spread >= Duration::from_millis(1_200),
        "{label} data frames arrived as one buffered burst ({spread:?})"
    );
    Ok(spread)
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
