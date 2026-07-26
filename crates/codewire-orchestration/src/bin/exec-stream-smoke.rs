//! Live ingress proof for WS06 WI-5 StreamExec dual-serving.
//!
//! Runs the same paced command through Connect and the legacy SSE route and
//! proves both renderers preserve event order, terminal status, and
//! incremental delivery through ingress-nginx.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use codewire_proto::codewire::v1::{
    ExecServiceClient, StreamExecRequest, StreamExecResponse, stream_exec_response::EventView,
};
use connectrpc::client::{ClientConfig, HttpClient};
use futures::StreamExt as _;
use reqwest::header::COOKIE;
use serde::Deserialize;

const COMMAND: &str = "printf 'stdout-1\\n'; sleep 1; printf 'stderr-1\\n' >&2; sleep 1; printf 'stdout-2\\n'; exit 17";

#[derive(Debug)]
struct Observation {
    kind: &'static str,
    data: Vec<u8>,
    exit_code: Option<i32>,
    arrived: Duration,
}

#[derive(Debug, Deserialize)]
struct SseExecFrame {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    data: String,
    exit_code: Option<i32>,
    #[serde(default)]
    error: String,
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
    let sse = run_sse(&base_url, &org_id, &environment_id, &session_token).await?;
    anyhow::ensure!(
        connect + Duration::from_millis(500) >= sse,
        "Connect arrival spread {connect:?} regressed against SSE {sse:?}"
    );

    println!(
        "exec-stream-smoke: Connect and SSE ordered incremental streams green (Connect {connect:?}, SSE {sse:?})"
    );
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

async fn run_sse(
    base_url: &str,
    org_id: &str,
    environment_id: &str,
    session_token: &str,
) -> anyhow::Result<Duration> {
    let response = reqwest::Client::new()
        .post(format!(
            "{base_url}/api/v1/organizations/{org_id}/environments/{environment_id}/exec/stream"
        ))
        .header(COOKIE, format!("codewire.session_token={session_token}"))
        .json(&serde_json::json!({ "command": ["sh", "-c", COMMAND] }))
        .send()
        .await
        .context("open SSE exec stream")?;
    anyhow::ensure!(
        response.status().is_success(),
        "SSE exec stream returned {}",
        response.status()
    );
    let started = Instant::now();
    let mut body = response.bytes_stream();
    let mut buffer = Vec::new();
    let mut observations = Vec::new();
    while let Some(chunk) = body.next().await {
        buffer.extend_from_slice(&chunk.context("read SSE exec chunk")?);
        while let Some(frame) = take_sse_frame(&mut buffer) {
            let Some((event, data)) = parse_sse_frame(&frame)? else {
                continue;
            };
            let payload: SseExecFrame =
                serde_json::from_str(&data).context("decode SSE exec payload")?;
            anyhow::ensure!(
                payload.typ == event,
                "SSE event/payload type diverged: {event}/{:?}",
                payload.typ
            );
            anyhow::ensure!(
                payload.error.is_empty(),
                "SSE exec emitted error: {}",
                payload.error
            );
            let observation = match event.as_str() {
                "stdout" => Observation {
                    kind: "stdout",
                    data: payload.data.into_bytes(),
                    exit_code: None,
                    arrived: started.elapsed(),
                },
                "stderr" => Observation {
                    kind: "stderr",
                    data: payload.data.into_bytes(),
                    exit_code: None,
                    arrived: started.elapsed(),
                },
                "exit" => Observation {
                    kind: "exit",
                    data: Vec::new(),
                    exit_code: payload.exit_code,
                    arrived: started.elapsed(),
                },
                other => anyhow::bail!("unexpected SSE exec event {other}"),
            };
            let terminal = observation.kind == "exit";
            observations.push(observation);
            if terminal {
                return validate_observations("SSE", &observations);
            }
        }
    }
    anyhow::bail!("SSE exec stream ended without an exit event")
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

fn take_sse_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = buffer.windows(2).position(|window| window == b"\n\n")?;
    let frame = buffer.drain(..end).collect();
    buffer.drain(..2);
    Some(frame)
}

fn parse_sse_frame(frame: &[u8]) -> anyhow::Result<Option<(String, String)>> {
    let frame = std::str::from_utf8(frame).context("SSE frame is not UTF-8")?;
    let mut event = None;
    let mut data = None;
    for line in frame.lines() {
        if let Some(value) = line.strip_prefix("event: ") {
            event = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("data: ") {
            data = Some(value.to_string());
        }
    }
    match (event, data) {
        (Some(event), Some(data)) => Ok(Some((event, data))),
        (None, None) if frame.starts_with(':') => Ok(None),
        _ => anyhow::bail!("malformed SSE frame: {frame:?}"),
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_handles_fragment_buffer() {
        let mut buffer =
            b"event: stdout\ndata: {\"type\":\"stdout\",\"data\":\"x\"}\n\nrest".to_vec();
        let frame = take_sse_frame(&mut buffer).expect("complete frame");
        assert_eq!(
            parse_sse_frame(&frame).expect("parse frame"),
            Some(("stdout".into(), r#"{"type":"stdout","data":"x"}"#.into()))
        );
        assert_eq!(buffer, b"rest");
    }
}
