use std::time::Duration;

use anyhow::Context as _;
use codewire_client::{
    AttachSessionOpen, ClientConfig, CodewireClient, EnvironmentSessionState, LaunchSessionRequest,
    ListSessionsRequest, ReadSessionOutputRequest, StaticTokenProvider, attach_session_response,
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
    println!("environment-session-smoke: PASS ({base_url})");
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
