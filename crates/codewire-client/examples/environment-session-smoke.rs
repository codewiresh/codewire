use std::time::Duration;

use anyhow::Context as _;
use codewire_client::{
    AttachSessionOpen, ClientConfig, CodewireClient, EnvironmentSessionState, ErrorCode,
    GetSessionRequest, LaunchSessionRequest, ListSessionsRequest, ReadSessionOutputRequest,
    RestartSessionRequest, SendSessionInputRequest, StaticTokenProvider, StopSessionRequest,
    attach_session_response,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_SESSION_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
    let access_token = required_env("SMOKE_ACCESS_TOKEN")?;
    let config =
        ClientConfig::new(&base_url)?.with_user_agent("codewire-environment-session-smoke/1")?;
    let token = StaticTokenProvider::new(access_token)?;
    let client = if let Ok(path) = std::env::var("SMOKE_CA_CERT_FILE") {
        let pem = std::fs::read(&path).with_context(|| format!("read CA certificate {path}"))?;
        let http = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).context("parse CA PEM")?)
            .build()
            .context("build TLS client")?;
        CodewireClient::with_http(config, token, http)?
    } else {
        // Exercise the client core's h2c prior-knowledge transport for the
        // direct Connect leg instead of silently falling back to HTTP/1.1.
        CodewireClient::new(config, token)?
    };

    prove_terminal_session(&client, &org_id, &environment_id, 0).await?;
    prove_terminal_session(&client, &org_id, &environment_id, 42).await?;
    prove_session_controls(&client, &org_id, &environment_id).await?;
    println!("environment-session-smoke: PASS ({base_url})");
    Ok(())
}

async fn prove_session_controls(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let request = LaunchSessionRequest {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        command: vec![
            "timeout".into(),
            "30".into(),
            "sh".into(),
            "-c".into(),
            "read -r value; printf 'CONTROL:%s' \"$value\"".into(),
        ],
        working_dir: "/workspace".into(),
        name: format!("reader-{suffix}"),
        ..Default::default()
    };
    let parent = client
        .launch_session(request.clone())
        .await?
        .session
        .into_option()
        .context("named launch lacks session")?;
    let duplicate = client
        .launch_session(request)
        .await
        .expect_err("duplicate name was admitted");
    anyhow::ensure!(
        duplicate.code() == ErrorCode::AlreadyExists,
        "duplicate name: {duplicate}"
    );
    let child = client
        .launch_session(LaunchSessionRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            command: vec!["sleep".into(), "30".into()],
            working_dir: "/workspace".into(),
            name: format!("child-{suffix}"),
            parent_session_id: Some(parent.session_id.clone()),
            ..Default::default()
        })
        .await?
        .session
        .into_option()
        .context("child launch lacks session")?;
    let result = async {
        anyhow::ensure!(
            child.parent_session_id.as_deref() == Some(parent.session_id.as_str()),
            "parent was not retained as a canonical session identity"
        );
        let bad_input = client
            .send_session_input(SendSessionInputRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: parent.session_id.clone(),
                data: Vec::new(),
                ..Default::default()
            })
            .await
            .expect_err("empty input was accepted");
        anyhow::ensure!(
            bad_input.code() == ErrorCode::InvalidArgument,
            "empty input: {bad_input}"
        );
        client
            .send_session_input(SendSessionInputRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: parent.session_id.clone(),
                data: b"acknowledged\n".to_vec(),
                ..Default::default()
            })
            .await
            .context("acknowledge named reader input")?;
        let ended = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let view = client
                    .get_session(GetSessionRequest {
                        org_id: org_id.into(),
                        environment_id: environment_id.into(),
                        session_id: parent.session_id.clone(),
                        ..Default::default()
                    })
                    .await?
                    .session
                    .into_option()
                    .context("GetSession lacks session")?;
                if view.state.as_known() == Some(EnvironmentSessionState::Exited) {
                    break Ok::<_, anyhow::Error>(view);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("named reader completion deadline")??;
        anyhow::ensure!(
            ended.name == parent.name && ended.exit_code == Some(0) && !ended.cleanup_unknown,
            "named reader completion is not confirmed"
        );
        let output = client
            .read_session_output(ReadSessionOutputRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: parent.session_id.clone(),
                limit: 1024,
                ..Default::default()
            })
            .await?;
        let bytes: Vec<u8> = output
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.data)
            .collect();
        anyhow::ensure!(
            bytes == b"CONTROL:acknowledged" && output.eof,
            "acknowledged input did not produce retained output and EOF"
        );
        let stopped = client
            .stop_session(StopSessionRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: child.session_id.clone(),
                ..Default::default()
            })
            .await?
            .session
            .into_option()
            .context("StopSession lacks session")?;
        anyhow::ensure!(
            stopped.state.as_known() == Some(EnvironmentSessionState::Stopped)
                && !stopped.cleanup_unknown,
            "child stop is unconfirmed"
        );
        let restarted = client
            .restart_session(RestartSessionRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: child.session_id.clone(),
                ..Default::default()
            })
            .await?
            .session
            .into_option()
            .context("RestartSession lacks session")?;
        anyhow::ensure!(
            restarted.session_id == child.session_id
                && restarted.name == child.name
                && restarted.parent_session_id == child.parent_session_id,
            "restart changed the session identity, name or parent"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Clean up these identified sessions even after a failed control assertion.
    for session in [&child, &parent] {
        client
            .stop_session(StopSessionRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                session_id: session.session_id.clone(),
                ..Default::default()
            })
            .await
            .context("clean up control-smoke session")?;
    }
    result?;
    println!("environment-session-smoke: names/parent/send/negative/stop/restart PASS");
    Ok(())
}

async fn prove_terminal_session(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    expected_exit: i32,
) -> anyhow::Result<()> {
    let marker = format!("session-edge-{expected_exit}-{}", std::process::id());
    eprintln!("environment-session-smoke: launch exit-{expected_exit}");
    let launched = client
        .launch_session(LaunchSessionRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            command: vec![
                "sh".into(),
                "-lc".into(),
                format!("printf %s {marker}; exit {expected_exit}"),
            ],
            working_dir: "/workspace".into(),
            ..Default::default()
        })
        .await
        .with_context(|| format!("launch exit-{expected_exit} session"))?
        .session
        .into_option()
        .context("LaunchSession response lacks session")?;
    anyhow::ensure!(!launched.session_id.is_empty(), "empty session id");

    eprintln!(
        "environment-session-smoke: attach exit-{expected_exit} session {}",
        launched.session_id
    );
    let mut attachment = client
        .attach_session(AttachSessionOpen {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            session_id: launched.session_id.clone(),
            output_offset: 0,
            ..Default::default()
        })
        .await
        .with_context(|| format!("open exit-{expected_exit} attachment"))?;
    let (output, terminal_exit) = tokio::time::timeout(Duration::from_secs(20), async {
        let mut output = Vec::new();
        loop {
            let response = attachment
                .next_output()
                .await?
                .context("attachment ended without terminal status")?;
            match response.event {
                Some(attach_session_response::Event::HistoryGap(_)) => {
                    anyhow::bail!("smoke session unexpectedly lost recent output history");
                }
                Some(attach_session_response::Event::Output(chunk)) => {
                    output.extend(chunk.data);
                }
                Some(attach_session_response::Event::Status(status)) => {
                    let session = status
                        .session
                        .into_option()
                        .context("status lacks session")?;
                    if matches!(
                        session.state.as_known(),
                        Some(
                            EnvironmentSessionState::Stopped
                                | EnvironmentSessionState::Exited
                                | EnvironmentSessionState::Failed
                                | EnvironmentSessionState::Interrupted
                        )
                    ) {
                        break Ok::<_, anyhow::Error>((output, session.exit_code));
                    }
                }
                None => anyhow::bail!("attachment returned an empty event"),
            }
        }
    })
    .await
    .context("attachment timed out")??;
    anyhow::ensure!(
        output == marker.as_bytes(),
        "session {} output mismatch: {:?}",
        launched.session_id,
        String::from_utf8_lossy(&output)
    );
    anyhow::ensure!(
        terminal_exit == Some(expected_exit),
        "session {} exit {:?}, want {expected_exit}",
        launched.session_id,
        terminal_exit
    );

    let listed = client
        .list_sessions(ListSessionsRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            ..Default::default()
        })
        .await
        .with_context(|| format!("list after exit-{expected_exit} session"))?;
    let listed = listed
        .sessions
        .iter()
        .find(|session| session.session_id == launched.session_id)
        .context("launched session absent from ListSessions")?;
    anyhow::ensure!(
        listed.exit_code == Some(expected_exit),
        "listed exit {:?}, want {expected_exit}",
        listed.exit_code
    );

    let retained = client
        .read_session_output(ReadSessionOutputRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            session_id: launched.session_id.clone(),
            offset: 0,
            limit: 1024 * 1024,
            ..Default::default()
        })
        .await
        .with_context(|| format!("read retained output for exit-{expected_exit} session"))?;
    let retained_output: Vec<u8> = retained
        .chunks
        .into_iter()
        .flat_map(|chunk| chunk.data)
        .collect();
    anyhow::ensure!(
        retained_output == marker.as_bytes(),
        "retained output mismatch for {}",
        launched.session_id
    );
    anyhow::ensure!(retained.eof, "retained output did not reach EOF");

    println!("environment-session-smoke: output/list/logs/exit-{expected_exit} PASS");
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .with_context(|| format!("{name} is required"))
        .and_then(|value| {
            anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
            Ok(value)
        })
}
