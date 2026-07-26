use std::time::Duration;

use anyhow::Context as _;
use codewire_client::{
    ClientConfig, CodewireClient, RunRequest, RunResize, RunResponse, RunSession, RunStart,
    StaticTokenProvider, run_request, run_response,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
    let access_token = required_env("SMOKE_ACCESS_TOKEN")?;
    let http = if let Ok(path) = std::env::var("SMOKE_CA_CERT_FILE") {
        let pem = std::fs::read(&path).with_context(|| format!("read CA certificate {path}"))?;
        reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).context("parse CA PEM")?)
            .build()
            .context("build TLS client")?
    } else {
        reqwest::Client::new()
    };
    let client = CodewireClient::with_http(
        ClientConfig::new(&base_url)?.with_user_agent("codewire-platform-run-smoke/1")?,
        StaticTokenProvider::new(access_token)?,
        http,
    )?;

    noninteractive_pipe(&client, &org_id, &environment_id).await?;
    pty_resize_and_interrupt(&client, &org_id, &environment_id).await?;
    pty_transport_loss(&client, &org_id, &environment_id).await?;
    println!("platform-run-smoke: PASS");
    Ok(())
}

async fn noninteractive_pipe(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let mut session = client
        .run(start(
            org_id,
            environment_id,
            false,
            vec![
                "sh".into(),
                "-c".into(),
                "read one; read two; printf 'out:%s:%s' \"$one\" \"$two\"; printf err >&2; exit 17"
                    .into(),
            ],
        ))
        .await?;
    let input = session.input_handle();
    input.send(stdin(b"first\n")).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    input.send(stdin(b"second\n")).await?;
    input.send(close_stdin()).await?;
    let (stdout, stderr, exit) = collect_to_exit(&mut session).await?;
    anyhow::ensure!(stdout == b"out:first:second", "pipe stdout: {stdout:?}");
    anyhow::ensure!(stderr == b"err", "pipe stderr: {stderr:?}");
    anyhow::ensure!(exit == 17, "pipe exit: {exit}");
    println!("platform-run-smoke: noninteractive pipe PASS");
    Ok(())
}

async fn pty_resize_and_interrupt(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let mut run_start = start(
        org_id,
        environment_id,
        true,
        vec![
            "sh".into(),
            "-c".into(),
            "trap 'exit 23' INT; read ready; stty size; printf resized; while :; do sleep 1; done"
                .into(),
        ],
    );
    run_start.term = "xterm-256color".into();
    run_start.columns = 80;
    run_start.rows = 24;
    let mut session = client.run(run_start).await?;
    let input = session.input_handle();
    input
        .send(RunRequest {
            input: Some(run_request::Input::Resize(Box::new(RunResize {
                columns: 111,
                rows: 37,
                ..Default::default()
            }))),
            ..Default::default()
        })
        .await?;
    input.send(stdin(b"go\n")).await?;

    let mut output = Vec::new();
    while !String::from_utf8_lossy(&output).contains("resized") {
        let response = tokio::time::timeout(Duration::from_secs(5), session.next_output())
            .await
            .context("PTY resize output timed out")??
            .context("PTY stream ended before resize output")?;
        match response.event {
            Some(run_response::Event::Stdout(data)) => output.extend(data),
            Some(run_response::Event::Stderr(data)) => output.extend(data),
            Some(run_response::Event::ExitCode(code)) => {
                anyhow::bail!("PTY exited before interrupt with {code}");
            }
            None => anyhow::bail!("PTY returned an empty event"),
        }
    }
    anyhow::ensure!(
        String::from_utf8_lossy(&output).contains("37 111"),
        "PTY resize output: {:?}",
        String::from_utf8_lossy(&output)
    );
    input.send(stdin(&[0x03])).await?;
    let (_, _, exit) = tokio::time::timeout(Duration::from_secs(5), collect_to_exit(&mut session))
        .await
        .context("PTY interrupt timed out")??;
    anyhow::ensure!(exit == 23, "PTY interrupt exit: {exit}");
    println!("platform-run-smoke: PTY resize and interrupt PASS");
    Ok(())
}

async fn pty_transport_loss(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let pid_file = format!("/workspace/.codewire-transport-loss-{}", std::process::id());
    let mut run_start = start(
        org_id,
        environment_id,
        true,
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s' \"$$\" > {pid_file}; printf ready; while :; do sleep 1; done"),
        ],
    );
    run_start.term = "xterm-256color".into();
    run_start.columns = 80;
    run_start.rows = 24;
    let mut session = client.run(run_start).await?;
    loop {
        let response = tokio::time::timeout(Duration::from_secs(5), session.next_output())
            .await
            .context("transport-loss readiness timed out")??
            .context("PTY ended before transport-loss readiness")?;
        if matches!(
            response.event,
            Some(run_response::Event::Stdout(ref data))
                if String::from_utf8_lossy(data).contains("ready")
        ) {
            break;
        }
    }
    session
        .input_handle()
        .send(close_stdin())
        .await
        .context("close PTY stdin before transport loss")?;
    drop(session);

    let mut probe = client
        .run(start(
            org_id,
            environment_id,
            false,
            vec![
                "sh".into(),
                "-c".into(),
                format!(
                    "for i in $(seq 1 100); do test -f {pid_file} || exit 1; pid=$(cat {pid_file}); if ! kill -0 \"$pid\" 2>/dev/null; then printf stopped; rm -f {pid_file}; exit 0; fi; sleep .05; done; rm -f {pid_file}; exit 1"
                ),
            ],
        ))
        .await?;
    probe.input_handle().send(close_stdin()).await?;
    let (stdout, _, exit) =
        tokio::time::timeout(Duration::from_secs(10), collect_to_exit(&mut probe))
            .await
            .context("transport-loss probe timed out")??;
    anyhow::ensure!(exit == 0, "transport-loss probe exit: {exit}");
    anyhow::ensure!(
        stdout == b"stopped",
        "transport-loss remote PID: {stdout:?}"
    );
    println!("platform-run-smoke: transport loss PASS");
    Ok(())
}

fn start(org_id: &str, environment_id: &str, allocate_tty: bool, command: Vec<String>) -> RunStart {
    RunStart {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        command,
        working_dir: "/workspace".into(),
        allocate_tty,
        ..Default::default()
    }
}

fn stdin(data: &[u8]) -> RunRequest {
    RunRequest {
        input: Some(run_request::Input::Stdin(data.to_vec())),
        ..Default::default()
    }
}

fn close_stdin() -> RunRequest {
    RunRequest {
        input: Some(run_request::Input::CloseStdin(Box::default())),
        ..Default::default()
    }
}

async fn collect_to_exit(session: &mut RunSession) -> anyhow::Result<(Vec<u8>, Vec<u8>, i32)> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let RunResponse { event, .. } = session
            .next_output()
            .await?
            .context("run stream ended without an exit status")?;
        match event {
            Some(run_response::Event::Stdout(data)) => stdout.extend(data),
            Some(run_response::Event::Stderr(data)) => stderr.extend(data),
            Some(run_response::Event::ExitCode(code)) => return Ok((stdout, stderr, code)),
            None => anyhow::bail!("run stream returned an empty event"),
        }
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .with_context(|| format!("{name} is required"))
        .and_then(|value| {
            anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
            Ok(value)
        })
}
