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
    use std::ffi::OsString;
    use std::fs;
    use std::future::Future;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::time::Duration;

    use codewire_access::{
        BrokerOperationId, BrokerRouteId, CapabilitySlot, CodexProviderProjection, CredentialId,
        EnvironmentId,
    };
    use codewire_daemon::client::{CredentialBridgeConnection, SessionClient, v1};
    use codewire_gateway_proto::{
        CREDENTIAL_BRIDGE_LOOPBACK_PORT, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    };
    use codewire_local_credentials::{
        AuthorityRuntimeConfig, BrokerLeaseAuditDecision, LocalCredentialClient,
    };
    use codewire_local_vmm::control::v1 as local_v1;
    use codewire_local_vmm::hybrid_vsock;
    use codewire_local_vmm::supervisor::{NativeRuntimeConfig, NativeSupervisorClient};
    use codewire_vmm_guest_probe::CODEX_GUEST_HOME_PATH;
    use serde::Deserialize;
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
    const MANAGED_CODEX_MARKER: &str = "CWCODEX149 broker [REDACTED]";
    const GUEST_CALLER_BEARER: &str = "guest-supplied-bearer-must-not-pass";
    const EXEC_TIMEOUT: Duration = Duration::from_secs(90);
    const MAX_EXEC_OUTPUT: usize = 1024 * 1024;
    const MAX_PROC_CMDLINE: usize = 64 * 1024;
    const GENERAL_EGRESS_MARKER: &[u8] = b"codewire-general-egress-ok\n";
    // Classify only locally observed socket phases, never upstream error text,
    // addresses or certificate data. A post-handshake failure still fails the
    // existing proof; this discriminator does not change socket shutdown.
    const GENERAL_EGRESS_SCRIPT: &str = r#"const tls=require('tls');
let phase='unknown';let timedOut=false;
const socket=tls.connect({host:'ghcr.io',port:443,family:4,servername:'ghcr.io',rejectUnauthorized:true},()=>{phase='post-handshake';process.stdout.write('codewire-general-egress-ok\n');socket.end();});
socket.on('lookup',(error)=>{phase=error?'dns':'tcp';});
socket.on('connect',()=>{phase='tls';});
socket.setTimeout(10000,()=>{timedOut=true;socket.destroy(new Error('timeout'));});
socket.on('error',()=>{const code=phase==='post-handshake'?75:timedOut?74:phase==='dns'?71:phase==='tcp'?72:phase==='tls'?73:76;process.exit(code);});"#;

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
        mesh_data_dir: PathBuf,
        platform_config_dir: PathBuf,
        credential_authority_root: PathBuf,
        cw_bin: PathBuf,
        target: String,
        managed_broker: bool,
        credential_id: Option<String>,
    }

    struct ExecOutput {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: i32,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HttpProbeOutput {
        status: u16,
        request_id: Option<String>,
        body: String,
    }

    pub(super) async fn run() -> SmokeResult<()> {
        let args = Args::parse(std::env::args().skip(1))?;
        stage("supervisor-connect");
        let mut supervisor = NativeSupervisorClient::connect_or_start(&NativeRuntimeConfig {
            root: args.state_root.clone(),
            artifact_root: args.artifact_root.clone(),
            artifact_lock: args.artifact_lock.clone(),
            mesh_data_dir: args.mesh_data_dir.clone(),
            platform_config_dir: args.platform_config_dir.clone(),
            credential_authority_root: args.credential_authority_root.clone(),
            executable: args.cw_bin.clone(),
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

        if args.managed_broker {
            run_managed_broker_smoke(&args, &mut supervisor, &daemon, &environment).await?;
            println!("codewire-local-codex-bridge-smoke: PASS (managed broker)");
            return Ok(());
        }

        stage("bridge-open");
        let mut bridge = daemon
            .open_credential_bridge(environment_id, environment.generation)
            .await?;
        require_bridge_ready(&mut bridge, environment_id, environment.generation).await?;

        stage("codex-exec");
        let command = codex_command();
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

    async fn run_managed_broker_smoke(
        args: &Args,
        supervisor: &mut NativeSupervisorClient,
        daemon: &SessionClient,
        environment: &local_v1::Environment,
    ) -> SmokeResult<()> {
        let credential_root = &args.credential_authority_root;
        let credential_id =
            CredentialId::parse(args.credential_id.as_ref().ok_or_else(failed)?.clone())?;
        let environment_id = EnvironmentId::parse(environment.id.clone())?;
        require(!environment.access_profile.is_empty() && environment.access_profile_revision > 0)?;

        stage("managed-broker-ready");
        let runtime = supervisor.ensure_credential_broker(&args.target).await?;
        require(
            runtime.environment_id == environment.id
                && runtime.environment_generation == environment.generation
                && runtime.running,
        )?;
        let mut credentials = LocalCredentialClient::connect(&AuthorityRuntimeConfig {
            root: credential_root.clone(),
            executable: args.cw_bin.clone(),
        })
        .await?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[],
        )
        .await?;

        stage("managed-policy-denial");
        let denied = run_http_probe(
            daemon,
            &environment.working_directory,
            "/v1/responses?exfiltrate=true",
        )
        .await?;
        require(denied.status == 403)?;
        require(!denied.body.contains(GUEST_CALLER_BEARER))?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[],
        )
        .await?;

        stage("managed-injection-redaction");
        let admitted =
            run_http_probe(daemon, &environment.working_directory, "/v1/responses").await?;
        require(
            admitted.status == 200
                && admitted.request_id.as_deref() == Some("[REDACTED]")
                && admitted.body.contains(MANAGED_CODEX_MARKER)
                && !admitted.body.contains(GUEST_CALLER_BEARER),
        )?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[BrokerLeaseAuditDecision::Admitted],
        )
        .await?;

        stage("managed-codex-exec");
        require_managed_codex(daemon, &environment.working_directory).await?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[
                BrokerLeaseAuditDecision::Admitted,
                BrokerLeaseAuditDecision::Admitted,
            ],
        )
        .await?;

        stage("managed-broker-crash");
        let broker_pid = wait_for_exact_broker(args, environment, None).await?;
        stage("managed-broker-identified");
        kill_exact_broker(broker_pid, args, environment)?;
        stage("managed-broker-killed");
        let replacement_pid = wait_for_exact_broker(args, environment, Some(broker_pid)).await?;
        stage("managed-broker-replaced");
        require(replacement_pid != broker_pid)?;
        wait_for_broker_ready(
            supervisor,
            &args.target,
            &environment.id,
            environment.generation,
        )
        .await?;

        stage("managed-codex-after-restart");
        require_managed_codex(daemon, &environment.working_directory).await?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[
                BrokerLeaseAuditDecision::Admitted,
                BrokerLeaseAuditDecision::Admitted,
                BrokerLeaseAuditDecision::Admitted,
            ],
        )
        .await?;

        stage("managed-revocation");
        credentials.revoke_credential(&credential_id).await?;
        let revoked =
            run_http_probe(daemon, &environment.working_directory, "/v1/responses").await?;
        require(revoked.status == 403 && !revoked.body.contains(GUEST_CALLER_BEARER))?;
        require_audit(
            &mut credentials,
            &environment_id,
            environment.generation,
            &credential_id,
            &[
                BrokerLeaseAuditDecision::Denied,
                BrokerLeaseAuditDecision::Admitted,
                BrokerLeaseAuditDecision::Admitted,
                BrokerLeaseAuditDecision::Admitted,
            ],
        )
        .await?;

        stage("managed-authority-loss");
        let broker_pid = wait_for_exact_broker(args, environment, None).await?;
        let authority_pid = exact_broker_parent(broker_pid, args, environment)?;
        kill_exact_authority(authority_pid, args)?;
        wait_for_credential_stack_exit(args, environment).await?;

        stage("managed-route-unavailable");
        let unavailable =
            run_http_probe(daemon, &environment.working_directory, "/v1/responses").await?;
        require(
            unavailable.status == 503
                && unavailable.body == "credential route unavailable\n"
                && !unavailable.body.contains(GUEST_CALLER_BEARER),
        )?;

        stage("managed-general-egress-independent");
        require_general_egress(daemon, &environment.working_directory).await?;
        let current = supervisor.get(&args.target).await?;
        require(
            current.id == environment.id
                && current.generation == environment.generation
                && current.state == local_v1::EnvironmentState::Running as i32,
        )
    }

    async fn require_audit(
        client: &mut LocalCredentialClient,
        environment_id: &EnvironmentId,
        generation: u64,
        credential_id: &CredentialId,
        decisions: &[BrokerLeaseAuditDecision],
    ) -> SmokeResult<()> {
        let events = client.list_recent_broker_lease_audit_events(16).await?;
        require(events.len() == decisions.len())?;
        for (event, decision) in events.iter().zip(decisions) {
            require(
                event.environment_id == *environment_id
                    && event.environment_generation == generation
                    && event.capability_slot == CapabilitySlot::codex()
                    && event.operation == BrokerOperationId::parse("responses")?
                    && event.route == BrokerRouteId::parse("openai-api")?
                    && event.decision == *decision,
            )?;
            match decision {
                BrokerLeaseAuditDecision::Admitted => {
                    require(event.credential_id.as_ref() == Some(credential_id))?;
                    require(
                        event.profile_id.is_some()
                            && event.profile_revision.is_some_and(|value| value > 0)
                            && event
                                .credential_revocation_generation
                                .is_some_and(|value| value > 0),
                    )?;
                }
                BrokerLeaseAuditDecision::Denied | BrokerLeaseAuditDecision::Unavailable => {
                    require(
                        event.credential_id.is_none()
                            && event.profile_id.is_none()
                            && event.profile_revision.is_none()
                            && event.credential_revocation_generation.is_none(),
                    )?;
                }
            }
        }
        Ok(())
    }

    async fn run_http_probe(
        client: &SessionClient,
        working_directory: &str,
        path: &str,
    ) -> SmokeResult<HttpProbeOutput> {
        const SCRIPT: &str = r#"const http=require('http');
const body=JSON.stringify({model:'codewire-synthetic',input:'hello',stream:true});
const request=http.request({host:'127.0.0.1',port:38081,path:process.argv[1],method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(body),'authorization':'Bearer guest-supplied-bearer-must-not-pass'}},response=>{const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>process.stdout.write(JSON.stringify({status:response.statusCode,request_id:response.headers['x-request-id']??null,body:Buffer.concat(chunks).toString('utf8')})));});
request.setTimeout(10000,()=>request.destroy(new Error('timeout')));request.on('error',()=>process.exit(1));request.end(body);"#;
        let output = run_transient(
            client,
            vec!["node".into(), "-e".into(), SCRIPT.into(), path.into()],
            working_directory,
            Vec::new(),
        )
        .await?;
        require(output.exit_code == 0 && output.stderr.is_empty())?;
        serde_json::from_slice(&output.stdout).map_err(Into::into)
    }

    async fn require_managed_codex(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        let output = run_transient(
            client,
            codex_command(),
            working_directory,
            smoke_environment(),
        )
        .await?;
        require(
            output.exit_code == 0
                && output.stdout == format!("{MANAGED_CODEX_MARKER}\n").as_bytes()
                && output
                    .stderr
                    .windows(b"OpenAI Codex v0.149.0".len())
                    .any(|window| window == b"OpenAI Codex v0.149.0"),
        )
    }

    async fn require_general_egress(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        let output = run_transient(
            client,
            vec!["node".into(), "-e".into(), GENERAL_EGRESS_SCRIPT.into()],
            working_directory,
            smoke_environment(),
        )
        .await?;
        eprintln!("{}", general_egress_diagnostic(&output));
        if output.exit_code != 0 {
            stage("managed-general-egress-exec-failed");
            return Err(failed());
        }
        if output.stdout != GENERAL_EGRESS_MARKER {
            stage("managed-general-egress-output-invalid");
            return Err(failed());
        }
        if !output.stderr.is_empty() {
            stage("managed-general-egress-stderr-present");
            return Err(failed());
        }
        Ok(())
    }

    fn general_egress_failure_class(exit_code: i32) -> &'static str {
        match exit_code {
            0 => "none",
            71 => "dns",
            72 => "tcp",
            73 => "tls",
            74 => "timeout",
            75 => "post-handshake",
            _ => "unknown",
        }
    }

    fn general_egress_diagnostic(output: &ExecOutput) -> String {
        format!(
            "codewire-local-codex-bridge-smoke: stage=managed-general-egress-result exit_code={} failure_class={} success_marker={} stderr_present={}",
            output.exit_code,
            general_egress_failure_class(output.exit_code),
            output.stdout == GENERAL_EGRESS_MARKER,
            !output.stderr.is_empty(),
        )
    }

    fn codex_command() -> Vec<String> {
        vec![
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
        ]
    }

    async fn wait_for_broker_ready(
        supervisor: &mut NativeSupervisorClient,
        target: &str,
        environment_id: &str,
        generation: u64,
    ) -> SmokeResult<()> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        loop {
            let runtime = supervisor.ensure_credential_broker(target).await?;
            require(
                runtime.environment_id == environment_id
                    && runtime.environment_generation == generation,
            )?;
            if runtime.running {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_exact_broker(
        args: &Args,
        environment: &local_v1::Environment,
        excluded_pid: Option<i32>,
    ) -> SmokeResult<i32> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        loop {
            let mut pids = exact_broker_pids(args, environment)?;
            pids.retain(|pid| Some(*pid) != excluded_pid);
            if pids.len() == 1 {
                return Ok(pids[0]);
            }
            require(pids.is_empty())?;
            if Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn exact_broker_pids(
        args: &Args,
        environment: &local_v1::Environment,
    ) -> SmokeResult<Vec<i32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
            else {
                continue;
            };
            if exact_broker_process(pid, args, environment) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        Ok(pids)
    }

    fn exact_broker_process(pid: i32, args: &Args, environment: &local_v1::Environment) -> bool {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let Ok(metadata) = fs::metadata(&process) else {
            return false;
        };
        if metadata.uid() != unsafe { libc::geteuid() } {
            return false;
        }
        let Some(parent_pid) = process_parent_pid(&process) else {
            return false;
        };
        exact_process_argv(&process, &expected_broker_argv(args, environment))
            && exact_authority_process(parent_pid, args)
    }

    fn exact_broker_parent(
        pid: i32,
        args: &Args,
        environment: &local_v1::Environment,
    ) -> SmokeResult<i32> {
        let process = PathBuf::from(format!("/proc/{pid}"));
        require(exact_broker_process(pid, args, environment))?;
        let parent = process_parent_pid(&process).ok_or_else(failed)?;
        require(exact_authority_process(parent, args))?;
        Ok(parent)
    }

    fn exact_authority_process(pid: i32, args: &Args) -> bool {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let Ok(metadata) = fs::metadata(&process) else {
            return false;
        };
        let expected_argv = expected_authority_argv(args);
        metadata.uid() == unsafe { libc::geteuid() }
            && fs::read_link(process.join("exe")).ok().as_deref() == Some(args.cw_bin.as_path())
            && exact_process_argv(&process, &expected_argv)
    }

    fn exact_process_argv(process: &Path, expected: &[OsString]) -> bool {
        let Ok(command) = fs::read(process.join("cmdline")) else {
            return false;
        };
        if command.is_empty() || command.len() > MAX_PROC_CMDLINE || command.last() != Some(&0) {
            return false;
        }
        let actual = command[..command.len() - 1]
            .split(|byte| *byte == 0)
            .collect::<Vec<_>>();
        actual.len() == expected.len()
            && actual
                .iter()
                .zip(expected.iter())
                .all(|(actual, expected)| *actual == expected.as_os_str().as_bytes())
    }

    fn process_parent_pid(process: &Path) -> Option<i32> {
        let status = fs::read_to_string(process.join("status")).ok()?;
        let mut parents = status.lines().filter_map(|line| {
            line.strip_prefix("PPid:")
                .map(str::trim)
                .and_then(|value| value.parse::<i32>().ok())
                .filter(|value| *value > 0)
        });
        let parent = parents.next()?;
        parents.next().is_none().then_some(parent)
    }

    fn expected_authority_argv(args: &Args) -> Vec<OsString> {
        vec![
            args.cw_bin.as_os_str().to_owned(),
            "__local-credential-authority".into(),
            "--root".into(),
            args.credential_authority_root.as_os_str().to_owned(),
        ]
    }

    fn expected_broker_argv(args: &Args, environment: &local_v1::Environment) -> Vec<OsString> {
        vec![
            args.cw_bin.as_os_str().to_owned(),
            "__local-credential-broker".into(),
            "--authority-fd".into(),
            "3".into(),
            "--environment-id".into(),
            environment.id.clone().into(),
            "--environment-generation".into(),
            environment.generation.to_string().into(),
            "--environment-name".into(),
            environment.name.clone().into(),
            "--supervisor-socket".into(),
            args.state_root.join("supervisor.sock").into_os_string(),
            "--credential-authentication-kind".into(),
            "oauth".into(),
        ]
    }

    fn kill_exact_broker(
        pid: i32,
        args: &Args,
        environment: &local_v1::Environment,
    ) -> SmokeResult<()> {
        // SAFETY: pidfd_open returns a new descriptor for the numeric process.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: ownership of the newly returned descriptor is transferred once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        require(exact_broker_process(pid, args, environment))?;
        // SAFETY: the pidfd still identifies the revalidated broker process and
        // the null siginfo pointer requests an ordinary SIGKILL delivery.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                descriptor.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn kill_exact_authority(pid: i32, args: &Args) -> SmokeResult<()> {
        // SAFETY: pidfd_open returns a new descriptor for the numeric process.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: ownership of the newly returned descriptor is transferred once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        require(exact_authority_process(pid, args))?;
        // SAFETY: the pidfd still identifies the revalidated authority process.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                descriptor.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    async fn wait_for_credential_stack_exit(
        args: &Args,
        environment: &local_v1::Environment,
    ) -> SmokeResult<()> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        loop {
            let authority_running = fs::read_dir("/proc")?.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|value| value.parse::<i32>().ok())
                    .is_some_and(|pid| exact_authority_process(pid, args))
            });
            if !authority_running && exact_broker_pids(args, environment)?.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
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
            let mut mesh_data_dir = None;
            let mut platform_config_dir = None;
            let mut credential_authority_root = None;
            let mut cw_bin = None;
            let mut target = None;
            let mut managed_broker = false;
            let mut credential_id = None;
            while let Some(flag) = arguments.next() {
                if flag == "--managed-broker" {
                    if managed_broker {
                        return Err(failed());
                    }
                    managed_broker = true;
                    continue;
                }
                let value = arguments.next().ok_or_else(failed)?;
                let slot = match flag.as_str() {
                    "--state-root" => &mut state_root,
                    "--artifact-root" => &mut artifact_root,
                    "--artifact-lock" => &mut artifact_lock,
                    "--mesh-data-dir" => &mut mesh_data_dir,
                    "--platform-config-dir" => &mut platform_config_dir,
                    "--credential-authority-root" => &mut credential_authority_root,
                    "--cw-bin" => &mut cw_bin,
                    "--target" => &mut target,
                    "--credential-id" => &mut credential_id,
                    _ => return Err(failed()),
                };
                if slot.replace(value).is_some() {
                    return Err(failed());
                }
            }
            let credential_id = credential_id.filter(|value| !value.is_empty());
            require(managed_broker == credential_id.is_some())?;
            Ok(Self {
                state_root: absolute_path(state_root)?,
                artifact_root: absolute_path(artifact_root)?,
                artifact_lock: absolute_path(artifact_lock)?,
                mesh_data_dir: absolute_path(mesh_data_dir)?,
                platform_config_dir: absolute_path(platform_config_dir)?,
                credential_authority_root: absolute_path(credential_authority_root)?,
                cw_bin: absolute_path(cw_bin)?,
                target: target
                    .filter(|value| !value.is_empty())
                    .ok_or_else(failed)?,
                managed_broker,
                credential_id,
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

        // Execute the production script, but expose only a socket double to its
        // require('tls'). Neither the fixture nor the VM can open a connection.
        const EGRESS_EVENT_FIXTURE: &str = r#"const vm=require('vm');
const handlers=new Map();let secureConnect;let timeout;let options;let timeoutMs;
let ended=false;let destroyed=false;let stdout='';let exitCode=0;
const opaque=new Error('CANARY-PRIVATE-CERTIFICATE-ADDRESS-ERROR');
opaque.code='CANARY-UNKNOWN-UPSTREAM-CODE';
const socket={on:(name,callback)=>{handlers.set(name,callback);return socket;},
setTimeout:(duration,callback)=>{timeoutMs=duration;timeout=callback;return socket;},
end:()=>{ended=true;},destroy:()=>{destroyed=true;handlers.get('error')(opaque);}};
vm.runInNewContext(process.argv[1],{
require:(name)=>{if(name!=='tls')throw new Error('unexpected module');return {
connect:(value,callback)=>{options=value;secureConnect=callback;return socket;}};},
process:{stdout:{write:(value)=>{stdout+=value;}},exit:(code)=>{exitCode=code;}}
},{timeout:1000});
switch(process.argv[2]){
case 'dns':handlers.get('lookup')(opaque);handlers.get('error')(opaque);break;
case 'tcp':handlers.get('lookup')(null);handlers.get('error')(opaque);break;
case 'tls':handlers.get('lookup')(null);handlers.get('connect')();handlers.get('error')(opaque);break;
case 'timeout':handlers.get('lookup')(null);timeout();break;
case 'post-handshake':handlers.get('lookup')(null);handlers.get('connect')();secureConnect();handlers.get('error')(opaque);break;
case 'post-handshake-timeout':handlers.get('lookup')(null);handlers.get('connect')();secureConnect();timeout();break;
case 'unknown':handlers.get('error')(opaque);break;
case 'success':handlers.get('lookup')(null);handlers.get('connect')();secureConnect();break;
default:throw new Error('invalid fixture case');
}
process.stdout.write(JSON.stringify({exit_code:exitCode,stdout,ended,destroyed,timeout_ms:timeoutMs,options}));"#;

        async fn general_egress_events(scenario: &str) -> Value {
            let mut command = tokio::process::Command::new("node");
            command
                .env_clear()
                .env(
                    "PATH",
                    std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
                )
                .current_dir("/")
                .args(["-e", EGRESS_EVENT_FIXTURE, GENERAL_EGRESS_SCRIPT, scenario])
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(5), command.output())
                .await
                .expect("synthetic Node events exceeded their deadline")
                .expect("Node is required for the native smoke probe fixture");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            assert!(output.stdout.len() < 1024);
            assert!(
                !output
                    .stdout
                    .windows(b"CANARY".len())
                    .any(|part| part == b"CANARY")
            );
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["timeout_ms"], 10000);
            assert_eq!(
                result["options"],
                serde_json::json!({"host":"ghcr.io","port":443,"family":4,
                    "servername":"ghcr.io","rejectUnauthorized":true})
            );
            result
        }

        #[tokio::test]
        async fn general_egress_pre_handshake_failures_are_closed() {
            for (scenario, code) in [("dns", 71), ("tcp", 72), ("tls", 73)] {
                let result = general_egress_events(scenario).await;
                assert_eq!(result["exit_code"], code);
                assert_eq!(general_egress_failure_class(code), scenario);
                assert_eq!(result["stdout"], "");
                assert_eq!(result["ended"], false);
                assert_eq!(result["destroyed"], false);
            }
        }

        #[tokio::test]
        async fn general_egress_timeout_keeps_existing_destroy_behavior() {
            let result = general_egress_events("timeout").await;
            assert_eq!(result["exit_code"], 74);
            assert_eq!(general_egress_failure_class(74), "timeout");
            assert_eq!(result["stdout"], "");
            assert_eq!(result["ended"], false);
            assert_eq!(result["destroyed"], true);
        }

        #[tokio::test]
        async fn general_egress_post_handshake_errors_still_fail_with_success_marker() {
            for scenario in ["post-handshake", "post-handshake-timeout"] {
                let result = general_egress_events(scenario).await;
                assert_eq!(result["exit_code"], 75);
                assert_eq!(general_egress_failure_class(75), "post-handshake");
                assert_eq!(result["stdout"], "codewire-general-egress-ok\n");
                assert_eq!(result["ended"], true);
                assert_eq!(result["destroyed"], scenario == "post-handshake-timeout");
            }
        }

        #[tokio::test]
        async fn general_egress_unknown_error_does_not_expose_upstream_values() {
            let result = general_egress_events("unknown").await;
            assert_eq!(result["exit_code"], 76);
            assert_eq!(general_egress_failure_class(76), "unknown");
            assert_eq!(result["stdout"], "");
            assert_eq!(result["ended"], false);
            assert_eq!(result["destroyed"], false);
        }

        #[tokio::test]
        async fn general_egress_success_keeps_existing_marker_and_socket_end() {
            let result = general_egress_events("success").await;
            assert_eq!(result["exit_code"], 0);
            assert_eq!(general_egress_failure_class(0), "none");
            assert_eq!(result["stdout"], "codewire-general-egress-ok\n");
            assert_eq!(result["ended"], true);
            assert_eq!(result["destroyed"], false);
        }

        #[test]
        fn general_egress_diagnostic_only_reports_numeric_exit_and_closed_booleans() {
            let mut output = ExecOutput {
                exit_code: 137,
                stdout: b"CANARY-PRIVATE-STDOUT".to_vec(),
                stderr: b"CANARY-PRIVATE-STDERR".to_vec(),
            };
            assert_eq!(
                general_egress_diagnostic(&output),
                "codewire-local-codex-bridge-smoke: stage=managed-general-egress-result exit_code=137 failure_class=unknown success_marker=false stderr_present=true"
            );
            output.exit_code = 75;
            output.stdout = GENERAL_EGRESS_MARKER.to_vec();
            output.stderr.clear();
            assert_eq!(
                general_egress_diagnostic(&output),
                "codewire-local-codex-bridge-smoke: stage=managed-general-egress-result exit_code=75 failure_class=post-handshake success_marker=true stderr_present=false"
            );
            output.stdout.push(b' ');
            assert!(general_egress_diagnostic(&output).contains("success_marker=false"));
        }

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

        fn required_arguments() -> Vec<String> {
            [
                "--state-root",
                "/state",
                "--artifact-root",
                "/artifacts",
                "--artifact-lock",
                "/artifacts.lock.json",
                "--mesh-data-dir",
                "/mesh",
                "--platform-config-dir",
                "/platform",
                "--credential-authority-root",
                "/credentials",
                "--cw-bin",
                "/bin/cw",
                "--target",
                "environment",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        }

        #[test]
        fn direct_mode_rejects_managed_arguments() {
            let direct = Args::parse(required_arguments()).unwrap();
            assert!(!direct.managed_broker);
            assert_eq!(
                direct.credential_authority_root,
                std::path::Path::new("/credentials")
            );
            assert!(direct.credential_id.is_none());

            let mut incomplete = required_arguments();
            incomplete.extend(["--credential-id".to_owned(), "credential-id".to_owned()]);
            assert!(Args::parse(incomplete).is_err());
        }

        #[test]
        fn managed_mode_requires_one_complete_selection() {
            let mut managed = required_arguments();
            managed.extend([
                "--managed-broker".to_owned(),
                "--credential-id".to_owned(),
                "credential-id".to_owned(),
            ]);
            let parsed = Args::parse(managed.clone()).unwrap();
            assert!(parsed.managed_broker);
            assert_eq!(
                parsed.credential_authority_root,
                std::path::Path::new("/credentials")
            );
            assert_eq!(parsed.credential_id.as_deref(), Some("credential-id"));

            managed.push("--managed-broker".to_owned());
            assert!(Args::parse(managed).is_err());
        }

        #[test]
        fn parent_pid_parser_requires_one_positive_kernel_status_field() {
            let temp = tempfile::tempdir().unwrap();
            fs::write(temp.path().join("status"), "Name:\ttest\nPPid:\t42\n").unwrap();
            assert_eq!(process_parent_pid(temp.path()), Some(42));

            for invalid in [
                "Name:\ttest\n",
                "PPid:\t0\n",
                "PPid:\tinvalid\n",
                "PPid:\t42\nPPid:\t43\n",
            ] {
                fs::write(temp.path().join("status"), invalid).unwrap();
                assert_eq!(process_parent_pid(temp.path()), None);
            }
        }
    }
}
