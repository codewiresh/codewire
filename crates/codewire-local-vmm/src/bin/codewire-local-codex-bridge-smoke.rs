//! Qualified-host proof that stock Codex uses the private guest bridge.
//!
//! The native product smoke invokes this binary against an already-running
//! disposable environment. It never reads a host Codex home or credential and
//! responds only with a repository-owned synthetic Responses API stream.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("codewire-local-codex-bridge-smoke requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if linux::run().await.is_err() {
        eprintln!("codewire-local-codex-bridge-smoke: ERROR: compatibility proof failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::future::Future;
    use std::io;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::time::Duration;

    use codewire_access::CodexProviderProjection;
    use codewire_daemon::client::{CredentialBridgeConnection, SessionClient, v1};
    use codewire_gateway_proto::{
        CREDENTIAL_BRIDGE_LOOPBACK_PORT, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    };
    use codewire_local_vmm::control::v1 as local_v1;
    use codewire_local_vmm::hybrid_vsock;
    use codewire_local_vmm::supervisor::{NativeRuntimeConfig, NativeSupervisorClient};
    use codewire_vmm_guest_probe::CODEX_GUEST_HOME_PATH;
    use serde_json::Value;
    use tokio::time::Instant;
    use tonic::Streaming;
    use uuid::Uuid;

    type SmokeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    const CODEX_BIN: &str = "/home/codewire/.npm-global/bin/codex";
    const CODEX_VERSION: &str = "codex-cli 0.149.0\n";
    const CODEX_MODEL: &str = "codewire-synthetic";
    const CODEX_PROMPT: &str = "Return the synthetic marker.";
    const CODEX_MARKER: &str = "CWCODEX149 synthetic";
    const EXEC_TIMEOUT: Duration = Duration::from_secs(90);
    const MAX_EXEC_OUTPUT: usize = 1024 * 1024;

    const SYNTHETIC_RESPONSE: &[u8] = concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codewire_smoke\"}}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg_codewire_smoke\",\"content\":[{\"type\":\"output_text\",\"text\":\"CWCODEX149 synthetic\"}]}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codewire_smoke\",\"usage\":{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}\n\n",
    )
    .as_bytes();

    struct Args {
        state_root: PathBuf,
        artifact_root: PathBuf,
        artifact_lock: PathBuf,
        cw_bin: PathBuf,
        target: String,
    }

    struct ExecOutput {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: i32,
    }

    pub(super) async fn run() -> SmokeResult<()> {
        let args = Args::parse(std::env::args().skip(1))?;
        stage("supervisor-connect");
        let mut supervisor = NativeSupervisorClient::connect_or_start(&NativeRuntimeConfig {
            root: args.state_root.clone(),
            artifact_root: args.artifact_root,
            artifact_lock: args.artifact_lock,
            credential_authority_root: args.state_root.join("credential-authority"),
            executable: args.cw_bin,
        })
        .await?;
        let environment = supervisor.get(&args.target).await?;
        require(environment.state == local_v1::EnvironmentState::Running as i32)?;
        let environment_id = Uuid::parse_str(&environment.id)?;
        require(!environment_id.is_nil() && environment.generation > 0)?;
        let working_directory = PathBuf::from(&environment.working_directory);
        require(working_directory.is_absolute())?;

        stage("daemon-connect");
        let access = supervisor.daemon_access(&args.target).await?;
        let daemon = hybrid_vsock::connect_daemon(
            PathBuf::from(access.hybrid_socket).as_path(),
            access.guest_port,
            access.generation_capability,
        )
        .await?;
        let capabilities = daemon
            .get_capabilities(&[DAEMON_CAPABILITY_CREDENTIAL_BRIDGE])
            .await?;
        require(capabilities.state == v1::DaemonState::Ready as i32)?;

        stage("config-check");
        require_codex_projection(&daemon).await?;
        stage("version-check");
        require_codex_version(&daemon, &environment.working_directory).await?;

        stage("bridge-open");
        let mut bridge = daemon
            .open_credential_bridge(environment_id, environment.generation)
            .await?;
        require_bridge_ready(&mut bridge, environment_id, environment.generation).await?;

        stage("codex-exec");
        let command = vec![
            CODEX_BIN.to_owned(),
            "exec".to_owned(),
            "--config".to_owned(),
            "model_context_window=100000".to_owned(),
            "--ephemeral".to_owned(),
            "--skip-git-repo-check".to_owned(),
            "--dangerously-bypass-approvals-and-sandbox".to_owned(),
            "--ignore-rules".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
            "--model".to_owned(),
            CODEX_MODEL.to_owned(),
            CODEX_PROMPT.to_owned(),
        ];
        let stream = daemon
            .exec_transient(v1::ExecStartRequest {
                command,
                working_dir: environment.working_directory.clone(),
                env: smoke_environment(),
            })
            .await?;
        let mut output: Pin<Box<dyn Future<Output = SmokeResult<ExecOutput>> + Send>> =
            Box::pin(collect_exec(stream));
        let request = receive_request(&mut bridge, &mut output).await?;
        stage("request-validate");
        validate_request(&request)?;
        send_synthetic_response(&bridge, request.request_id).await?;

        stage("response-complete");
        let output = await_codex_completion(&mut bridge, &mut output).await?;
        require(output.exit_code == 0)?;
        require(output.stdout == format!("{CODEX_MARKER}\n").as_bytes())?;
        require(
            output
                .stderr
                .windows(b"OpenAI Codex v0.149.0".len())
                .any(|window| window == b"OpenAI Codex v0.149.0"),
        )?;

        println!("codewire-local-codex-bridge-smoke: PASS");
        Ok(())
    }

    async fn await_codex_completion(
        bridge: &mut CredentialBridgeConnection,
        output: &mut Pin<Box<dyn Future<Output = SmokeResult<ExecOutput>> + Send>>,
    ) -> SmokeResult<ExecOutput> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        tokio::select! {
            result = output.as_mut() => result,
            message = bridge.receive() => {
                let message = message?.ok_or_else(|| {
                    stage("bridge-closed-before-exit");
                    failed()
                })?;
                use v1::credential_bridge_guest_message::Payload;
                match message.payload {
                    Some(Payload::Request(_)) => stage("unexpected-second-request"),
                    Some(Payload::Cancel(_)) => stage("unexpected-request-cancel"),
                    Some(Payload::Ready(_)) => stage("unexpected-second-ready"),
                    None => stage("unexpected-empty-bridge-frame"),
                }
                Err(failed())
            }
            _ = tokio::time::sleep_until(deadline) => {
                stage("codex-exit-timeout");
                Err(failed())
            }
        }
    }

    async fn require_codex_projection(client: &SessionClient) -> SmokeResult<()> {
        let expected = CodexProviderProjection::for_loopback_port(CREDENTIAL_BRIDGE_LOOPBACK_PORT)?
            .into_config_toml();
        let command = format!(
            "test \"$CODEX_HOME\" = '{CODEX_GUEST_HOME_PATH}' && test -f \"$CODEX_HOME/config.toml\" && test ! -e \"$CODEX_HOME/auth.json\" && cat -- \"$CODEX_HOME/config.toml\""
        );
        let output = run_transient(
            client,
            vec!["/bin/sh".into(), "-c".into(), command],
            "/",
            Vec::new(),
        )
        .await?;
        require(
            output.exit_code == 0
                && output.stdout == expected.as_bytes()
                && output.stderr.is_empty(),
        )
    }

    async fn require_codex_version(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        let output = run_transient(
            client,
            vec![CODEX_BIN.into(), "--version".into()],
            working_directory,
            Vec::new(),
        )
        .await?;
        if output.exit_code != 0 {
            stage("version-command-failed");
            return Err(failed());
        }
        if output.stdout != CODEX_VERSION.as_bytes() {
            stage("version-output-mismatch");
            return Err(failed());
        }
        Ok(())
    }

    fn smoke_environment() -> Vec<String> {
        vec![
            "TERM=xterm-256color".into(),
            "LC_ALL=C".into(),
            "HTTP_PROXY=http://127.0.0.1:1".into(),
            "HTTPS_PROXY=http://127.0.0.1:1".into(),
            "ALL_PROXY=http://127.0.0.1:1".into(),
            "NO_PROXY=127.0.0.1,localhost".into(),
        ]
    }

    async fn require_bridge_ready(
        bridge: &mut CredentialBridgeConnection,
        environment_id: Uuid,
        generation: u64,
    ) -> SmokeResult<()> {
        let message = tokio::time::timeout(EXEC_TIMEOUT, bridge.receive())
            .await
            .map_err(|_| failed())??
            .ok_or_else(failed)?;
        let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) = message.payload
        else {
            return Err(failed());
        };
        require(
            ready.protocol_version == CREDENTIAL_BRIDGE_PROTOCOL_VERSION
                && ready.environment_id == environment_id.to_string()
                && ready.environment_generation == generation,
        )
    }

    async fn receive_request(
        bridge: &mut CredentialBridgeConnection,
        output: &mut Pin<Box<dyn Future<Output = SmokeResult<ExecOutput>> + Send>>,
    ) -> SmokeResult<v1::CredentialBridgeRequest> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        tokio::select! {
            result = output.as_mut() => {
                let _ = result?;
                Err(failed())
            }
            message = bridge.receive() => {
                let message = message?.ok_or_else(failed)?;
                let Some(v1::credential_bridge_guest_message::Payload::Request(request)) = message.payload else {
                    return Err(failed());
                };
                Ok(request)
            }
            _ = tokio::time::sleep_until(deadline) => Err(failed()),
        }
    }

    fn validate_request(request: &v1::CredentialBridgeRequest) -> SmokeResult<()> {
        require(Uuid::parse_str(&request.request_id).is_ok())?;
        require(
            request.method == "POST" && request.path == "/responses" && request.query.is_empty(),
        )?;
        require(
            request
                .headers
                .iter()
                .any(|header| header.name == "content-type" && header.value == b"application/json"),
        )?;
        for header in &request.headers {
            require(!matches!(
                header.name.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "api-key"
                    | "x-api-key"
                    | "content-encoding"
            ))?;
            require(
                !header
                    .value
                    .windows(b"Bearer ".len())
                    .any(|value| value == b"Bearer ")
                    && !header
                        .value
                        .windows(b"Basic ".len())
                        .any(|value| value == b"Basic "),
            )?;
        }
        let body = serde_json::from_slice::<Value>(&request.body)?;
        require(body.get("model").and_then(Value::as_str) == Some(CODEX_MODEL))?;
        require(body.get("stream").and_then(Value::as_bool) == Some(true))?;
        require(body.to_string().contains(CODEX_PROMPT))
    }

    async fn send_synthetic_response(
        bridge: &CredentialBridgeConnection,
        request_id: String,
    ) -> SmokeResult<()> {
        bridge
            .send_response_start(v1::CredentialBridgeResponseStart {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".into(),
                    value: b"text/event-stream".to_vec(),
                }],
            })
            .await?;
        bridge
            .send_response_body(v1::CredentialBridgeResponseBody {
                request_id: request_id.clone(),
                data: SYNTHETIC_RESPONSE.to_vec(),
            })
            .await?;
        bridge
            .send_response_end(v1::CredentialBridgeResponseEnd { request_id })
            .await?;
        Ok(())
    }

    async fn run_transient(
        client: &SessionClient,
        command: Vec<String>,
        working_dir: &str,
        env: Vec<String>,
    ) -> SmokeResult<ExecOutput> {
        let stream = client
            .exec_transient(v1::ExecStartRequest {
                command,
                working_dir: working_dir.into(),
                env,
            })
            .await?;
        tokio::time::timeout(EXEC_TIMEOUT, collect_exec(stream))
            .await
            .map_err(|_| failed())?
    }

    async fn collect_exec(mut stream: Streaming<v1::ExecMessage>) -> SmokeResult<ExecOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let message = stream.message().await?.ok_or_else(failed)?;
            match message.payload.ok_or_else(failed)? {
                v1::exec_message::Payload::Stdout(data) => append_output(&mut stdout, data)?,
                v1::exec_message::Payload::Stderr(data) => append_output(&mut stderr, data)?,
                v1::exec_message::Payload::Exit(exit) => {
                    return Ok(ExecOutput {
                        stdout,
                        stderr,
                        exit_code: exit.code,
                    });
                }
                v1::exec_message::Payload::Error(_) => return Err(failed()),
                _ => return Err(failed()),
            }
        }
    }

    fn append_output(output: &mut Vec<u8>, data: Vec<u8>) -> SmokeResult<()> {
        require(output.len().saturating_add(data.len()) <= MAX_EXEC_OUTPUT)?;
        output.extend(data);
        Ok(())
    }

    impl Args {
        fn parse(arguments: impl IntoIterator<Item = String>) -> SmokeResult<Self> {
            let mut arguments = arguments.into_iter();
            let mut state_root = None;
            let mut artifact_root = None;
            let mut artifact_lock = None;
            let mut cw_bin = None;
            let mut target = None;
            while let Some(flag) = arguments.next() {
                let value = arguments.next().ok_or_else(failed)?;
                let slot = match flag.as_str() {
                    "--state-root" => &mut state_root,
                    "--artifact-root" => &mut artifact_root,
                    "--artifact-lock" => &mut artifact_lock,
                    "--cw-bin" => &mut cw_bin,
                    "--target" => &mut target,
                    _ => return Err(failed()),
                };
                if slot.replace(value).is_some() {
                    return Err(failed());
                }
            }
            Ok(Self {
                state_root: absolute_path(state_root)?,
                artifact_root: absolute_path(artifact_root)?,
                artifact_lock: absolute_path(artifact_lock)?,
                cw_bin: absolute_path(cw_bin)?,
                target: target
                    .filter(|value| !value.is_empty())
                    .ok_or_else(failed)?,
            })
        }
    }

    fn absolute_path(value: Option<String>) -> SmokeResult<PathBuf> {
        let path = PathBuf::from(value.ok_or_else(failed)?);
        require(path.is_absolute())?;
        Ok(path)
    }

    fn require(condition: bool) -> SmokeResult<()> {
        if condition { Ok(()) } else { Err(failed()) }
    }

    fn stage(value: &str) {
        eprintln!("codewire-local-codex-bridge-smoke: stage={value}");
    }

    fn failed() -> Box<dyn Error + Send + Sync> {
        Box::new(io::Error::other(
            "Codex credential bridge smoke assertion failed",
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn synthetic_response_is_well_formed_sse_with_one_terminal_event() {
            let response = std::str::from_utf8(SYNTHETIC_RESPONSE).unwrap();
            let events = response
                .split("\n\n")
                .filter(|event| !event.is_empty())
                .map(|event| {
                    let mut lines = event.lines();
                    let kind = lines.next().unwrap().strip_prefix("event: ").unwrap();
                    let value = lines.next().unwrap().strip_prefix("data: ").unwrap();
                    assert!(lines.next().is_none());
                    let value: Value = serde_json::from_str(value).unwrap();
                    assert_eq!(value.get("type").and_then(Value::as_str), Some(kind));
                    kind.to_owned()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                events,
                [
                    "response.created",
                    "response.output_item.done",
                    "response.completed",
                ]
            );
        }
    }
}
