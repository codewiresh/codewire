//! Qualified-host proof of selected HTTP clients and SSH identity/signing routes.
//!
//! The native product smoke invokes this binary against an already-running
//! disposable environment. It never reads a host Codex home or credential and
//! uses only repository-owned synthetic upstream responses. OpenAI is a Node
//! HTTP/API configuration proof, not an OpenAI SDK compatibility claim.

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
    use std::collections::BTreeSet;
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
        BrokerOperationId, BrokerRouteId, CapabilitySlot, CodexProviderProjection,
        CredentialAuthKind, CredentialId, CredentialStatus, EnvironmentId,
    };
    use codewire_daemon::client::{CredentialBridgeConnection, SessionClient, v1};
    use codewire_daemon_bridge::client::{
        DaemonClient, DaemonClientError, DaemonRunInput, DaemonRunOutput, DaemonRunReceiver,
        DaemonRunSender, DaemonRunStart,
    };
    use codewire_gateway_proto::codewire::bridge::v1 as bridge_v1;
    use codewire_gateway_proto::{
        CREDENTIAL_BRIDGE_LOOPBACK_PORT, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    };
    use codewire_local_credentials::{
        AuthorityRuntimeConfig, BrokerLeaseAuditDecision, BrokerLeaseAuditEvent,
        LocalCredentialClient,
    };
    use codewire_local_vmm::control::v1 as local_v1;
    use codewire_local_vmm::hybrid_vsock;
    use codewire_local_vmm::linux::path::SocketIdentity;
    use codewire_local_vmm::supervisor::{NativeRuntimeConfig, NativeSupervisorClient};
    use codewire_vmm_guest_probe::CODEX_GUEST_HOME_PATH;
    use futures::{Stream, StreamExt as _};
    use hyper_util::rt::TokioIo;
    use serde::Deserialize;
    use serde_json::Value;
    use tokio::time::Instant;
    use tonic::Streaming;
    use uuid::Uuid;

    type SmokeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    const CODEX_BIN: &str = "codex";
    const CODEX_VERSION: &str = "codex-cli 0.149.0\n";
    const CODEX_MODEL: &str = "codewire-synthetic";
    const CODEX_PROMPT: &str = "Return the synthetic marker.";
    const CODEX_MARKER: &str = "CWCODEX149 synthetic";
    const MANAGED_CODEX_MARKER: &str = "CWCODEX149 broker [REDACTED]";
    const MANAGED_OPENAI_MARKER: &str = "CWOPENAI broker [REDACTED]";
    const MANAGED_CLAUDE_MARKER: &str = "CWCLAUDE21238 broker [REDACTED]";
    const SSH_PUBLIC_KEY_PATH: &str = "/workspace/fixtures/native-ssh-public-key.pub";
    const STOCK_SSH_WORKLOAD_PATH: &str = "/workspace/fixtures/stock-ssh-workload.sh";
    const CLAUDE_VERSION: &str = "2.1.238 (Claude Code)\n";
    const CLAUDE_MODEL: &str = "claude-sonnet-4-6";
    const CLAUDE_PATHS: [&str; 2] = [
        "/opt/codewire/agents/npm/bin/claude",
        "/home/codewire/.npm-global/bin/claude",
    ];
    const MANAGED_PROFILE_REVISION: u64 = 5;
    const MAX_AUDIT_EVENTS: usize = 32;
    const GUEST_CALLER_BEARER: &str = "guest-supplied-bearer-must-not-pass";
    const EXEC_TIMEOUT: Duration = Duration::from_secs(90);
    const MAX_EXEC_OUTPUT: usize = 1024 * 1024;
    const MAX_PROC_CMDLINE: usize = 64 * 1024;
    const GENERAL_EGRESS_MARKER: &[u8] = b"codewire-general-egress-ok\n";
    const AUTHORITY_LOSS_READY: &[u8] = b"codewire-authority-loss-ready\n";
    const AUTHORITY_LOSS_TRIGGER: &[u8] = b"go\n";
    const DENIED_LAUNCH_MARKER: &str = "codewire-denied-launch-ran";
    const HOSTNAME_MARKER: &[u8] = b"codewire-local-hostname-ok\n";
    const HOSTNAME_SCRIPT: &str = r#"const fs=require('fs');const dns=require('dns');const os=require('os');
const hosts=fs.lstatSync('/etc/hosts');
if(!hosts.isFile()||hosts.uid!==0||hosts.gid!==0||hosts.nlink!==1||(hosts.mode&0o777)!==0o444||os.hostname()!=='codewire')process.exit(81);
try{const fd=fs.openSync('/etc/hosts','r+');fs.closeSync(fd);process.exit(81);}catch(error){if(error.code!=='EROFS'&&error.code!=='EACCES')process.exit(81);}
dns.lookup(os.hostname(),{family:4},(error,address)=>{if(error||address!=='192.0.2.2'){process.exit(81);return;}process.stdout.write('codewire-local-hostname-ok\n');});"#;
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
        openai_credential_id: Option<String>,
        anthropic_credential_id: Option<String>,
        ssh_credential_id: Option<String>,
    }

    struct ManagedCredentials {
        codex: CredentialId,
        openai: CredentialId,
        anthropic: CredentialId,
        ssh: CredentialId,
    }

    #[derive(Clone, Copy)]
    enum ExpectedAudit {
        CodexAdmitted,
        CodexDenied,
        OpenAi,
        AnthropicMessages,
        AnthropicCountTokens,
        SshIdentities,
        SshIdentitiesDenied,
        SshSignAdmitted,
        SshSignDenied,
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

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SelectedHttpProbeOutput {
        status: u16,
        request_id: Option<String>,
        content_type: Option<String>,
        opaque_header_present: bool,
        body: String,
    }

    // Only public generated routing inputs enter these requests. No endpoint
    // override is supplied by the fixture, and no upstream key enters argv.
    const SELECTED_HTTP_SCRIPT: &str = r#"const http=require('http');
const mode=process.argv[1];let url;let headers;let input;
if(mode==='openai'){
if(process.env.OPENAI_BASE_URL!=='http://127.0.0.1:38081/_codewire/openai/v1'||process.env.OPENAI_API_KEY!=='codewire-managed')process.exit(81);
url=new URL(process.env.OPENAI_BASE_URL+'/responses');
headers={'content-type':'application/json','authorization':'Bearer '+process.env.OPENAI_API_KEY};
input={model:'codewire-synthetic',input:'Return the synthetic marker.',stream:true};
}else if(mode==='count-tokens'){
if(process.env.ANTHROPIC_BASE_URL!=='http://127.0.0.1:38081'||process.env.ANTHROPIC_AUTH_TOKEN!=='codewire-managed'||process.env.ANTHROPIC_API_KEY!==''||process.env.CLAUDE_CODE_OAUTH_TOKEN!=='')process.exit(82);
url=new URL(process.env.ANTHROPIC_BASE_URL+'/v1/messages/count_tokens');
headers={'content-type':'application/json','anthropic-version':'2023-06-01','authorization':'Bearer '+process.env.ANTHROPIC_AUTH_TOKEN};
input={model:'claude-sonnet-4-6',messages:[{role:'user',content:'Return the synthetic marker.'}]};
}else process.exit(83);
const body=JSON.stringify(input);headers['content-length']=Buffer.byteLength(body);
const request=http.request(url,{method:'POST',headers},response=>{const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>262144){request.destroy();process.exit(84);}chunks.push(chunk);});response.on('error',()=>process.exit(85));response.on('end',()=>process.stdout.write(JSON.stringify({status:response.statusCode,request_id:response.headers[mode==='openai'?'x-request-id':'request-id']??null,content_type:response.headers['content-type']??null,opaque_header_present:response.headers['x-error-json']!==undefined,body:Buffer.concat(chunks).toString('utf8')})));});
request.setTimeout(10000,()=>request.destroy());request.on('error',()=>process.exit(86));request.end(body);"#;

    const CLAUDE_RESOLVER_SCRIPT: &str = "PATH=/opt/codewire/agents/npm/bin:/home/codewire/.npm-global/bin:/usr/bin:/bin; export PATH; command -v claude";
    const CLAUDE_ENV_EXEC_SCRIPT: &str = concat!(
        "test \"${ANTHROPIC_BASE_URL-}\" = 'http://127.0.0.1:38081' && ",
        "test \"${ANTHROPIC_AUTH_TOKEN-}\" = codewire-managed && ",
        "test \"${ANTHROPIC_API_KEY+x}\" = x && test -z \"$ANTHROPIC_API_KEY\" && ",
        "test \"${CLAUDE_CODE_OAUTH_TOKEN+x}\" = x && test -z \"$CLAUDE_CODE_OAUTH_TOKEN\" && ",
        "exec \"$@\"",
    );

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
            PathBuf::from(&access.hybrid_socket).as_path(),
            access.guest_port,
            &access.generation_capability,
        )
        .await?;
        let capabilities = daemon
            .get_capabilities(&[DAEMON_CAPABILITY_CREDENTIAL_BRIDGE])
            .await?;
        require(capabilities.state == v1::DaemonState::Ready as i32)?;

        stage("hostname-check");
        let hostname = run_transient(
            &daemon,
            vec!["node".into(), "-e".into(), HOSTNAME_SCRIPT.into()],
            &environment.working_directory,
            Vec::new(),
        )
        .await?;
        require(
            hostname.exit_code == 0
                && hostname.stdout == HOSTNAME_MARKER
                && hostname.stderr.is_empty(),
        )?;

        stage("config-check");
        if args.managed_broker {
            require_codex_projection(&daemon).await?;
        } else {
            require(environment.access_profile_id.is_empty())?;
            require_unselected_codex_home(&daemon).await?;
        }
        stage("version-check");
        require_codex_version(&daemon, &environment.working_directory).await?;

        if args.managed_broker {
            let probe_client = connect_probe_client(
                PathBuf::from(access.hybrid_socket),
                access.guest_port,
                &access.generation_capability,
            )
            .await?;
            run_managed_broker_smoke(&args, &mut supervisor, &daemon, &probe_client, &environment)
                .await?;
            println!("codewire-local-codex-bridge-smoke: PASS (managed broker)");
            return Ok(());
        }

        stage("bridge-open");
        let mut bridge = daemon
            .open_credential_bridge(environment_id, environment.generation)
            .await?;
        require_bridge_ready(&mut bridge, environment_id, environment.generation).await?;

        stage("codex-exec");
        let command = standalone_codex_command();
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
        probe_client: &DaemonClient,
        environment: &local_v1::Environment,
    ) -> SmokeResult<()> {
        let credential_root = &args.credential_authority_root;
        let selected = ManagedCredentials {
            codex: CredentialId::parse(args.credential_id.as_ref().ok_or_else(failed)?.clone())?,
            openai: CredentialId::parse(
                args.openai_credential_id
                    .as_ref()
                    .ok_or_else(failed)?
                    .clone(),
            )?,
            anthropic: CredentialId::parse(
                args.anthropic_credential_id
                    .as_ref()
                    .ok_or_else(failed)?
                    .clone(),
            )?,
            ssh: CredentialId::parse(args.ssh_credential_id.as_ref().ok_or_else(failed)?.clone())?,
        };
        require(
            !environment.access_profile.is_empty()
                && !environment.access_profile_id.is_empty()
                && environment.access_profile_revision == MANAGED_PROFILE_REVISION
                && selected.codex != selected.openai
                && selected.codex != selected.anthropic
                && selected.codex != selected.ssh
                && selected.openai != selected.anthropic
                && selected.openai != selected.ssh
                && selected.anthropic != selected.ssh,
        )?;
        let mut expected_audit = Vec::new();

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
        let ssh = credentials.get_credential(&selected.ssh).await?;
        require(
            ssh.metadata.provider.as_str() == "ssh"
                && ssh.metadata.authentication_kind == CredentialAuthKind::SshKey
                && ssh.metadata.status == CredentialStatus::Active
                && ssh.metadata.revocation_generation == 1,
        )?;
        let ssh_public_key = ssh
            .metadata
            .ssh_public_key
            .as_ref()
            .map(|key| key.openssh.clone())
            .filter(|key| !key.is_empty())
            .ok_or_else(failed)?;
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-policy-denial");
        let denied = run_http_probe(
            daemon,
            &environment.working_directory,
            "/v1/responses?exfiltrate=true",
        )
        .await?;
        require(denied.status == 403)?;
        require(!denied.body.contains(GUEST_CALLER_BEARER))?;
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-injection-redaction");
        let admitted =
            run_http_probe(daemon, &environment.working_directory, "/v1/responses").await?;
        require(
            admitted.status == 200
                && admitted.request_id.as_deref() == Some("[REDACTED]")
                && admitted.body.contains(MANAGED_CODEX_MARKER)
                && !admitted.body.contains(GUEST_CALLER_BEARER),
        )?;
        expected_audit.insert(0, ExpectedAudit::CodexAdmitted);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-codex-exec");
        require_managed_codex(daemon, &environment.working_directory).await?;
        expected_audit.insert(0, ExpectedAudit::CodexAdmitted);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-openai-api-responses");
        require_managed_openai(daemon, &environment.working_directory).await?;
        expected_audit.insert(0, ExpectedAudit::OpenAi);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-anthropic-count-tokens");
        require_managed_count_tokens(daemon, &environment.working_directory).await?;
        expected_audit.insert(0, ExpectedAudit::AnthropicCountTokens);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-claude-streaming");
        require_managed_claude(daemon, &environment.working_directory).await?;
        expected_audit.insert(0, ExpectedAudit::AnthropicMessages);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-ssh-identities");
        require_managed_ssh_identities(daemon, &environment.working_directory, &ssh_public_key)
            .await?;
        expected_audit.insert(0, ExpectedAudit::SshIdentities);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-ssh-sign");
        require_managed_ssh_sign(
            daemon,
            &environment.working_directory,
            &ssh_public_key,
            true,
        )
        .await?;
        expected_audit.insert(0, ExpectedAudit::SshSignAdmitted);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-stock-ssh-workload");
        let stock_ssh_host_key =
            require_stock_ssh_workload(daemon, &environment.working_directory, "prove", None)
                .await?;
        record_stock_ssh_audit(&mut expected_audit);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

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
        expected_audit.insert(0, ExpectedAudit::CodexAdmitted);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-ssh-after-restart");
        require_managed_ssh_sign(
            daemon,
            &environment.working_directory,
            &ssh_public_key,
            true,
        )
        .await?;
        expected_audit.insert(0, ExpectedAudit::SshSignAdmitted);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-ssh-revocation");
        credentials.revoke_credential(&selected.ssh).await?;
        require_managed_ssh_sign(
            daemon,
            &environment.working_directory,
            &ssh_public_key,
            false,
        )
        .await?;
        expected_audit.insert(0, ExpectedAudit::SshSignDenied);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-stock-ssh-revocation");
        require_stock_ssh_workload(
            daemon,
            &environment.working_directory,
            "revoked",
            Some(&stock_ssh_host_key),
        )
        .await?;
        expected_audit.insert(0, ExpectedAudit::SshIdentitiesDenied);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-revocation");
        credentials.revoke_credential(&selected.codex).await?;
        let revoked =
            run_http_probe(daemon, &environment.working_directory, "/v1/responses").await?;
        require(revoked.status == 403 && !revoked.body.contains(GUEST_CALLER_BEARER))?;
        expected_audit.insert(0, ExpectedAudit::CodexDenied);
        require_audit(&mut credentials, environment, &selected, &expected_audit).await?;

        stage("managed-authority-loss-probe-ready");
        let mut probe =
            AuthorityLossProbe::start(probe_client, &environment.working_directory).await?;
        let outcome = async {
            let broker_pid = wait_for_exact_broker(args, environment, None).await?;
            let authority_pid = exact_broker_parent(broker_pid, args, environment)?;
            let broker = open_pidfd(broker_pid)?;
            let authority = open_pidfd(authority_pid)?;
            // Pin both original identities before the kill and revalidate the
            // full live parent/UID/executable/argv relationship after pinning.
            require(exact_broker_parent(broker_pid, args, environment)? == authority_pid)?;
            require(exact_authority_process(authority_pid, args))?;
            require(!pidfd_exited(&authority)? && !pidfd_exited(&broker)?)?;
            require(Instant::now() < probe.deadline)?;
            stage("managed-authority-loss");
            signal_pidfd(&authority)?;
            wait_for_credential_stack_exit(&authority, &broker, probe.deadline).await?;

            stage("managed-route-unavailable");
            let output = probe.trigger_and_collect().await?;
            let (unavailable, egress) = authority_loss_output(output)?;
            require(
                unavailable.status == 503
                    && unavailable.body == "credential route unavailable\n"
                    && !unavailable.body.contains(GUEST_CALLER_BEARER),
            )?;
            stage("managed-general-egress-independent");
            require_general_egress_output(egress)?;
            stage("managed-fresh-launch-denied");
            require_fresh_launch_denied(daemon, &environment.working_directory).await
        }
        .await;
        // Failure still drops the sole request owner and retains the response
        // while the daemon cancels/reaps. Never leave a READY child detached.
        let drained = probe.cancel_and_drain().await;
        outcome?;
        drained?;
        let current = supervisor.get(&args.target).await?;
        require(
            current.id == environment.id
                && current.generation == environment.generation
                && current.state == local_v1::EnvironmentState::Running as i32,
        )
    }

    async fn require_audit(
        client: &mut LocalCredentialClient,
        environment: &local_v1::Environment,
        selected: &ManagedCredentials,
        expected: &[ExpectedAudit],
    ) -> SmokeResult<()> {
        let events = client
            .list_recent_broker_lease_audit_events(MAX_AUDIT_EVENTS)
            .await?;
        validate_audit_events(&events, environment, selected, expected)
    }

    fn validate_audit_events(
        events: &[BrokerLeaseAuditEvent],
        environment: &local_v1::Environment,
        selected: &ManagedCredentials,
        expected: &[ExpectedAudit],
    ) -> SmokeResult<()> {
        // Examine the complete newest-first ring response. Never filter by
        // slot/environment or accept a truncated list as complete evidence.
        require(expected.len() < MAX_AUDIT_EVENTS && events.len() == expected.len())?;
        let environment_id = EnvironmentId::parse(environment.id.clone())?;
        let mut request_ids = BTreeSet::new();
        for (index, (event, expected)) in events.iter().zip(expected).enumerate() {
            let (slot, operation, route, credential_id, decision) = match expected {
                ExpectedAudit::CodexAdmitted => (
                    "codex",
                    "responses",
                    "openai-api",
                    &selected.codex,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::CodexDenied => (
                    "codex",
                    "responses",
                    "openai-api",
                    &selected.codex,
                    BrokerLeaseAuditDecision::Denied,
                ),
                ExpectedAudit::OpenAi => (
                    "openai",
                    "responses",
                    "openai-api",
                    &selected.openai,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::AnthropicMessages => (
                    "anthropic",
                    "messages",
                    "anthropic-api",
                    &selected.anthropic,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::AnthropicCountTokens => (
                    "anthropic",
                    "count-tokens",
                    "anthropic-api",
                    &selected.anthropic,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::SshIdentities => (
                    "ssh",
                    "ssh-identities",
                    "ssh-agent",
                    &selected.ssh,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::SshIdentitiesDenied => (
                    "ssh",
                    "ssh-identities",
                    "ssh-agent",
                    &selected.ssh,
                    BrokerLeaseAuditDecision::Denied,
                ),
                ExpectedAudit::SshSignAdmitted => (
                    "ssh",
                    "ssh-sign",
                    "ssh-agent",
                    &selected.ssh,
                    BrokerLeaseAuditDecision::Admitted,
                ),
                ExpectedAudit::SshSignDenied => (
                    "ssh",
                    "ssh-sign",
                    "ssh-agent",
                    &selected.ssh,
                    BrokerLeaseAuditDecision::Denied,
                ),
            };
            require(
                event.sequence == (events.len() - index) as u64
                    && event.environment_id == environment_id
                    && event.environment_generation == environment.generation
                    && !event.request_id.is_nil()
                    && request_ids.insert(event.request_id)
                    && event.capability_slot == CapabilitySlot::parse(slot)?
                    && event.operation == BrokerOperationId::parse(operation)?
                    && event.route == BrokerRouteId::parse(route)?
                    && event.decision == decision,
            )?;
            match decision {
                BrokerLeaseAuditDecision::Admitted => {
                    require(event.credential_id.as_ref() == Some(credential_id))?;
                    require(
                        event.profile_id.as_ref().map(|id| id.as_str())
                            == Some(environment.access_profile_id.as_str())
                            && environment.access_profile_revision == MANAGED_PROFILE_REVISION
                            && event.profile_revision == Some(MANAGED_PROFILE_REVISION)
                            && event.credential_revocation_generation == Some(1),
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

    async fn require_managed_ssh_identities(
        client: &SessionClient,
        working_directory: &str,
        expected_public_key: &str,
    ) -> SmokeResult<()> {
        let output = run_transient(
            client,
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "test -n \"${SSH_AUTH_SOCK-}\" && test -S \"$SSH_AUTH_SOCK\" && exec ssh-add -L"
                    .into(),
            ],
            working_directory,
            smoke_environment(),
        )
        .await?;
        require(output.exit_code == 0 && output.stderr.is_empty())?;
        validate_ssh_identity_output(&output.stdout, expected_public_key)
    }

    fn valid_public_host_key_line(output: &[u8]) -> SmokeResult<String> {
        require(output.len() <= 256)?;
        let line = std::str::from_utf8(output)?;
        let line = line.strip_suffix('\n').ok_or_else(failed)?;
        require(!line.contains(['\r', '\n']))?;
        let fields: Vec<_> = line.split(' ').collect();
        require(
            fields.len() == 3
                && fields[0] == "[127.0.0.1]:22222"
                && fields[1] == "ssh-ed25519"
                && fields[2].len() >= 16
                && fields[2].len() % 4 == 0
                && fields[2]
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| match byte {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => true,
                        b'=' => index + 2 >= fields[2].len(),
                        _ => false,
                    }),
        )?;
        Ok(line.to_owned())
    }

    async fn run_stock_ssh_workload(
        client: &SessionClient,
        working_directory: &str,
        arguments: Vec<String>,
    ) -> SmokeResult<ExecOutput> {
        let mut command = vec!["/bin/bash".into(), STOCK_SSH_WORKLOAD_PATH.into()];
        command.extend(arguments);
        run_transient(client, command, working_directory, smoke_environment()).await
    }

    async fn require_stock_ssh_workload(
        client: &SessionClient,
        working_directory: &str,
        mode: &str,
        admitted_host_key: Option<&str>,
    ) -> SmokeResult<String> {
        let host_key = match admitted_host_key {
            Some(host_key) => host_key.to_owned(),
            None => {
                stage("managed-stock-ssh-public-host-key");
                let output = run_stock_ssh_workload(
                    client,
                    working_directory,
                    vec!["public-host-key".into()],
                )
                .await?;
                if output.exit_code != 0 || !output.stderr.is_empty() {
                    eprintln!(
                        "codewire-local-codex-bridge-smoke: stock SSH host-key command exit={} stdout_bytes={} stderr_bytes={}",
                        output.exit_code,
                        output.stdout.len(),
                        output.stderr.len()
                    );
                }
                require(output.exit_code == 0 && output.stderr.is_empty())?;
                stage("managed-stock-ssh-validate-host-key");
                valid_public_host_key_line(&output.stdout)?
            }
        };
        require(matches!(mode, "prove" | "revoked"))?;
        stage("managed-stock-ssh-client-command");
        let output = run_stock_ssh_workload(
            client,
            working_directory,
            vec![mode.into(), host_key.clone()],
        )
        .await?;
        let expected = match mode {
            "prove" => b"stock-ssh-workload-proved\n".as_slice(),
            "revoked" => b"stock-ssh-workload-revoked\n".as_slice(),
            _ => return Err(failed()),
        };
        if output.exit_code != 0 || output.stdout != expected || !output.stderr.is_empty() {
            eprintln!(
                "codewire-local-codex-bridge-smoke: stock SSH client command exit={} stdout_bytes={} stderr_bytes={}",
                output.exit_code,
                output.stdout.len(),
                output.stderr.len()
            );
        }
        require(output.exit_code == 0 && output.stdout == expected && output.stderr.is_empty())?;
        Ok(host_key)
    }

    fn record_stock_ssh_audit(expected: &mut Vec<ExpectedAudit>) {
        // Each of SSH, two SCP transfers, SFTP and Git performs one identity
        // lookup followed by one signature with the sole selected key.
        for _ in 0..5 {
            expected.insert(0, ExpectedAudit::SshIdentities);
            expected.insert(0, ExpectedAudit::SshSignAdmitted);
        }
    }

    async fn require_managed_ssh_sign(
        client: &SessionClient,
        working_directory: &str,
        expected_public_key: &str,
        admitted: bool,
    ) -> SmokeResult<()> {
        let output = run_transient(
            client,
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "test -n \"${{SSH_AUTH_SOCK-}}\" && test -S \"$SSH_AUTH_SOCK\" && test \"$(cat {SSH_PUBLIC_KEY_PATH})\" = \"$1\" && if ssh-add -T {SSH_PUBLIC_KEY_PATH}; then printf 'ssh-sign-admitted\\n'; else printf 'ssh-sign-denied\\n'; fi"
                ),
                "codewire-ssh-sign".into(),
                expected_public_key.into(),
            ],
            working_directory,
            smoke_environment(),
        )
        .await?;
        require(output.exit_code == 0)?;
        let expected = if admitted {
            b"ssh-sign-admitted\n".as_slice()
        } else {
            b"ssh-sign-denied\n".as_slice()
        };
        require(output.stdout == expected)?;
        if admitted {
            require(output.stderr.is_empty())?;
        }
        Ok(())
    }

    fn validate_ssh_identity_output(output: &[u8], expected_public_key: &str) -> SmokeResult<()> {
        let output = std::str::from_utf8(output)?;
        let lines = output.lines().collect::<Vec<_>>();
        require(lines.len() == 1)?;
        let actual = lines[0].split_ascii_whitespace().collect::<Vec<_>>();
        let expected = expected_public_key
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        require(
            actual.len() >= 2
                && expected.len() >= 2
                && actual[0] == expected[0]
                && actual[1] == expected[1],
        )
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

    async fn connect_probe_client(
        socket: PathBuf,
        guest_port: u32,
        token: &str,
    ) -> SmokeResult<DaemonClient> {
        let identity = SocketIdentity::capture(&socket)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let endpoint = tonic::transport::Endpoint::from_static("http://codewire-guest-daemon")
            .connect_timeout(Duration::from_secs(10));
        let channel = endpoint.connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            let identity = identity.clone();
            async move {
                tokio::time::timeout_at(deadline, async {
                    identity.revalidate(&socket).map_err(io::Error::other)?;
                    let stream = hybrid_vsock::connect_hybrid_vsock(&socket, guest_port)
                        .await
                        .map_err(io::Error::other)?;
                    identity.revalidate(&socket).map_err(io::Error::other)?;
                    Ok::<_, io::Error>(TokioIo::new(stream))
                })
                .await
                .map_err(io::Error::other)?
            }
        }));
        let channel = tokio::time::timeout_at(deadline, channel).await??;
        Ok(DaemonClient::from_channel(channel, token)?)
    }

    // Only this synthetic probe's lifetime changes. Its HTTP request and the
    // original TLS/egress check still run in the normally projected workload.
    // There is no auxiliary socket, file trigger or launch-policy exception.
    fn authority_loss_script() -> String {
        let before_egress = r#"const http=require('http');
let trigger=Buffer.alloc(0);let started=false;
const timer=setTimeout(()=>process.exit(80),90000);
process.stdin.on('data',chunk=>{if(started||trigger.length+chunk.length>3){process.exit(80);return;}trigger=Buffer.concat([trigger,chunk]);if(trigger.length===3){if(!trigger.equals(Buffer.from('go\n'))){process.exit(80);return;}started=true;clearTimeout(timer);process.stdin.destroy();checkRoute();}});
process.stdin.on('end',()=>{if(!started)process.exit(80);});
process.stdin.on('error',()=>process.exit(80));
process.stdout.write('codewire-authority-loss-ready\n');
function checkRoute(){
const body=JSON.stringify({model:'codewire-synthetic',input:'hello',stream:true});
const request=http.request({host:'127.0.0.1',port:38081,path:'/v1/responses',method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(body),'authorization':'Bearer guest-supplied-bearer-must-not-pass'}},response=>{const chunks=[];let length=0;response.on('data',chunk=>{length+=chunk.length;if(length>65536){process.exit(80);return;}chunks.push(chunk);});response.on('end',()=>{process.stdout.write(JSON.stringify({status:response.statusCode,request_id:response.headers['x-request-id']??null,body:Buffer.concat(chunks).toString('utf8')})+'\n');generalEgress();});response.on('error',()=>process.exit(80));});
request.setTimeout(10000,()=>request.destroy(new Error('timeout')));request.on('error',()=>process.exit(80));request.end(body);
}
function generalEgress(){
"#;
        format!("{before_egress}{GENERAL_EGRESS_SCRIPT}\n}}\n")
    }

    type ProbeOutput =
        Pin<Box<dyn Stream<Item = Result<DaemonRunOutput, DaemonClientError>> + Send>>;

    fn probe_output(receiver: DaemonRunReceiver) -> ProbeOutput {
        futures::stream::unfold(receiver, |mut receiver| async {
            match receiver.next_output().await {
                Ok(Some(frame)) => Some((Ok(frame), receiver)),
                Ok(None) => None,
                Err(error) => Some((Err(error), receiver)),
            }
        })
        .boxed()
    }

    struct AuthorityLossProbe {
        input: Option<DaemonRunSender>,
        output: ProbeOutput,
        deadline: Instant,
        exit: Option<i32>,
        finished: bool,
    }

    impl AuthorityLossProbe {
        async fn start(client: &DaemonClient, working_directory: &str) -> SmokeResult<Self> {
            let deadline = Instant::now() + EXEC_TIMEOUT;
            let session = tokio::time::timeout_at(
                deadline,
                client.start_run(DaemonRunStart {
                    command: vec!["node".into(), "-e".into(), authority_loss_script()],
                    working_dir: working_directory.into(),
                    env: smoke_environment(),
                    allocate_tty: false,
                    term: String::new(),
                    columns: 0,
                    rows: 0,
                }),
            )
            .await??;
            let (input, output) = session.into_split();
            let mut probe = Self {
                input: Some(input),
                output: probe_output(output),
                deadline,
                exit: None,
                finished: false,
            };
            let ready =
                tokio::time::timeout_at(deadline, require_probe_ready(&mut probe.output)).await;
            if !matches!(ready, Ok(Ok(()))) {
                let _ = probe.cancel_and_drain().await;
                return Err(failed());
            }
            Ok(probe)
        }

        async fn trigger_and_collect(&mut self) -> SmokeResult<ExecOutput> {
            tokio::time::timeout_at(self.deadline, async {
                require(Instant::now() < self.deadline)?;
                self.input
                    .as_ref()
                    .ok_or_else(failed)?
                    .send_input(DaemonRunInput::Stdin(AUTHORITY_LOSS_TRIGGER.to_vec()))
                    .await?;
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                while let Some(frame) = self.output.next().await {
                    require(self.exit.is_none())?;
                    match frame.map_err(|_| failed())? {
                        DaemonRunOutput::Stdout(data) => append_output(&mut stdout, data)?,
                        DaemonRunOutput::Stderr(data) => append_output(&mut stderr, data)?,
                        DaemonRunOutput::Exit(code) => {
                            require((0..=255).contains(&code))?;
                            self.exit = Some(code);
                            self.input.take();
                        }
                    }
                }
                let exit_code = self.exit.ok_or_else(failed)?;
                self.finished = true;
                Ok(ExecOutput {
                    stdout,
                    stderr,
                    exit_code,
                })
            })
            .await
            .map_err(|_| failed())?
        }

        async fn cancel_and_drain(&mut self) -> SmokeResult<()> {
            self.input.take(); // Full cancellation, never stdin half-close.
            if self.finished {
                return Ok(());
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(frame) = self.output.next().await {
                    require(self.exit.is_none())?;
                    match frame {
                        Ok(DaemonRunOutput::Exit(code)) => {
                            require((0..=255).contains(&code))?;
                            self.exit = Some(code);
                        }
                        Ok(DaemonRunOutput::Stdout(_) | DaemonRunOutput::Stderr(_))
                        | Err(DaemonClientError::Remote(_)) => {}
                        Err(_) => return Err(failed()),
                    }
                }
                require(self.exit.is_some())?;
                self.finished = true;
                Ok(())
            })
            .await
            .map_err(|_| failed())?
        }
    }

    async fn require_probe_ready(output: &mut ProbeOutput) -> SmokeResult<()> {
        let mut ready = Vec::new();
        loop {
            let Some(Ok(DaemonRunOutput::Stdout(bytes))) = output.next().await else {
                return Err(failed());
            };
            require(!bytes.is_empty() && ready.len() + bytes.len() <= AUTHORITY_LOSS_READY.len())?;
            ready.extend(bytes);
            require(AUTHORITY_LOSS_READY.starts_with(&ready))?;
            if ready == AUTHORITY_LOSS_READY {
                return Ok(());
            }
        }
    }

    fn authority_loss_output(output: ExecOutput) -> SmokeResult<(HttpProbeOutput, ExecOutput)> {
        let newline = output
            .stdout
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(failed)?;
        let unavailable =
            serde_json::from_slice(&output.stdout[..newline]).map_err(|_| failed())?;
        Ok((
            unavailable,
            ExecOutput {
                stdout: output.stdout[newline + 1..].to_vec(),
                stderr: output.stderr,
                exit_code: output.exit_code,
            },
        ))
    }

    async fn require_fresh_launch_denied(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        tokio::time::timeout(EXEC_TIMEOUT, async {
            let mut stream = client
                .exec_transient(v1::ExecStartRequest {
                    command: vec![
                        "node".into(),
                        "-e".into(),
                        format!("process.stdout.write('{DENIED_LAUNCH_MARKER}\\n')"),
                    ],
                    working_dir: working_directory.into(),
                    env: Vec::new(),
                })
                .await?;
            require_denied_launch_frames(&mut stream).await
        })
        .await
        .map_err(|_| failed())?
    }

    async fn require_denied_launch_frames(
        stream: &mut (impl Stream<Item = Result<v1::ExecMessage, tonic::Status>> + Unpin),
    ) -> SmokeResult<()> {
        use v1::exec_message::Payload;
        let mut state = 0;
        while let Some(frame) = stream.next().await {
            match (state, frame.map_err(|_| failed())?.payload) {
                (0, Some(Payload::Error(error)))
                    if error == "environment launch denied or expired" =>
                {
                    state = 1
                }
                (1, Some(Payload::Exit(exit))) if exit.code == 1 => state = 2,
                _ => return Err(failed()),
            }
        }
        require(state == 2)
    }

    async fn selected_http_probe(
        client: &SessionClient,
        working_directory: &str,
        mode: &str,
    ) -> SmokeResult<SelectedHttpProbeOutput> {
        require(matches!(mode, "openai" | "count-tokens"))?;
        let output = run_transient(
            client,
            vec![
                "node".into(),
                "-e".into(),
                SELECTED_HTTP_SCRIPT.into(),
                mode.into(),
            ],
            working_directory,
            smoke_environment(),
        )
        .await?;
        require(output.exit_code == 0 && output.stderr.is_empty())?;
        serde_json::from_slice(&output.stdout).map_err(Into::into)
    }

    fn require_selected_response_headers(
        response: &SelectedHttpProbeOutput,
        content_type: &str,
    ) -> SmokeResult<()> {
        require(
            response.status == 200
                && response.request_id.as_deref() == Some("[REDACTED]")
                && response.content_type.as_deref() == Some(content_type)
                && !response.opaque_header_present,
        )
    }

    async fn require_managed_openai(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        let response = selected_http_probe(client, working_directory, "openai").await?;
        validate_openai_response(&response)
    }

    fn validate_openai_response(response: &SelectedHttpProbeOutput) -> SmokeResult<()> {
        require_selected_response_headers(response, "text/event-stream")?;
        require(response.body.ends_with("\n\n"))?;
        let events = response
            .body
            .trim_end_matches('\n')
            .split("\n\n")
            .map(|block| {
                let (name, data) = block.split_once('\n').ok_or_else(failed)?;
                let name = name.strip_prefix("event: ").ok_or_else(failed)?;
                let data: Value =
                    serde_json::from_str(data.strip_prefix("data: ").ok_or_else(failed)?)?;
                require(data["type"].as_str() == Some(name))?;
                Ok(data)
            })
            .collect::<SmokeResult<Vec<_>>>()?;
        require(events.len() == 3)?;
        require(
            events[0]["type"] == "response.created"
                && events[1]["type"] == "response.output_item.done"
                && events[2]["type"] == "response.completed"
                && events[0]["response"]["id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty())
                && events[0]["response"]["id"] == events[2]["response"]["id"]
                && events[1]["item"]["role"] == "assistant"
                && events[1]["item"]["content"]
                    == serde_json::json!([{"type":"output_text","text":MANAGED_OPENAI_MARKER}]),
        )
    }

    async fn require_managed_count_tokens(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        let response = selected_http_probe(client, working_directory, "count-tokens").await?;
        validate_count_tokens_response(&response)
    }

    fn validate_count_tokens_response(response: &SelectedHttpProbeOutput) -> SmokeResult<()> {
        require_selected_response_headers(response, "application/json")?;
        require(
            serde_json::from_str::<Value>(&response.body)?
                == serde_json::json!({"input_tokens":42}),
        )
    }

    fn selected_claude_path(output: ExecOutput) -> SmokeResult<String> {
        require(output.exit_code == 0 && output.stderr.is_empty())?;
        let path = std::str::from_utf8(&output.stdout)?;
        let path = path.strip_suffix('\n').ok_or_else(failed)?;
        require(CLAUDE_PATHS.contains(&path))?;
        Ok(path.to_owned())
    }

    fn claude_command(executable: &str) -> SmokeResult<Vec<String>> {
        require(CLAUDE_PATHS.contains(&executable))?;
        // Check the actual process's generated variables immediately before
        // exec, without replacing them or selecting a special auth mode.
        Ok([
            "/bin/sh",
            "-c",
            CLAUDE_ENV_EXEC_SCRIPT,
            "codewire-claude-smoke",
            executable,
            "-p",
            "--model",
            CLAUDE_MODEL,
            "--max-turns",
            "1",
            "--tools",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--setting-sources",
            "",
            "--disable-slash-commands",
            "--no-session-persistence",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            CODEX_PROMPT,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect())
    }

    async fn require_managed_claude(
        client: &SessionClient,
        working_directory: &str,
    ) -> SmokeResult<()> {
        stage("managed-claude-resolve");
        let executable = selected_claude_path(
            run_transient(
                client,
                vec!["/bin/sh".into(), "-c".into(), CLAUDE_RESOLVER_SCRIPT.into()],
                working_directory,
                Vec::new(),
            )
            .await?,
        )?;
        stage("managed-claude-version");
        let version = run_transient(
            client,
            vec![executable.clone(), "--version".into()],
            working_directory,
            smoke_environment(),
        )
        .await?;
        require(
            version.exit_code == 0
                && version.stderr.is_empty()
                && version.stdout == CLAUDE_VERSION.as_bytes(),
        )?;
        let mut environment = smoke_environment();
        environment.extend([
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1".into(),
            "CLAUDE_CODE_MAX_RETRIES=0".into(),
        ]);
        stage("managed-claude-exec");
        let output = run_transient(
            client,
            claude_command(&executable)?,
            working_directory,
            environment,
        )
        .await?;
        stage("managed-claude-output");
        validate_claude_output(&output)
    }

    fn validate_claude_output(output: &ExecOutput) -> SmokeResult<()> {
        require(
            output.exit_code == 0
                && output.stderr.is_empty()
                && output.stdout.len() <= MAX_EXEC_OUTPUT,
        )?;
        let text = std::str::from_utf8(&output.stdout)?;
        require(text.ends_with('\n'))?;
        let mut initialized = false;
        let mut requesting = false;
        let mut stream_state = 0;
        let mut streamed_text = String::new();
        let mut assistant = false;
        let mut completed = false;
        for line in text.lines() {
            require(!completed && !line.is_empty())?;
            let frame: Value = serde_json::from_str(line)?;
            match frame["type"].as_str() {
                Some("system") => match frame["subtype"].as_str() {
                    Some("init") => {
                        require(!initialized && stream_state == 0)?;
                        initialized = true;
                    }
                    Some("status") => {
                        // The pinned client announces a request before its
                        // first partial event. This never substitutes for the
                        // complete stream and successful final result below.
                        require(
                            initialized
                                && !requesting
                                && stream_state == 0
                                && frame["status"] == "requesting",
                        )?;
                        requesting = true;
                    }
                    _ => return Err(failed()),
                },
                Some("rate_limit_event") => require(initialized)?,
                Some("stream_event") => {
                    require(initialized)?;
                    let event = &frame["event"];
                    match (stream_state, event["type"].as_str()) {
                        (0, Some("message_start")) => {
                            require(
                                event["message"]["role"] == "assistant"
                                    && event["message"]["model"] == CLAUDE_MODEL,
                            )?;
                            stream_state = 1;
                        }
                        (1, Some("content_block_start")) => {
                            require(
                                event["index"] == 0
                                    && event["content_block"]
                                        == serde_json::json!({"type":"text","text":""}),
                            )?;
                            stream_state = 2;
                        }
                        (2, Some("content_block_delta")) => {
                            require(
                                !assistant
                                    && event["index"] == 0
                                    && event["delta"]["type"] == "text_delta",
                            )?;
                            let delta = event["delta"]["text"].as_str().ok_or_else(failed)?;
                            require(
                                streamed_text.len().saturating_add(delta.len())
                                    <= MANAGED_CLAUDE_MARKER.len(),
                            )?;
                            streamed_text.push_str(delta);
                        }
                        (2, Some("content_block_stop")) => {
                            require(event["index"] == 0 && streamed_text == MANAGED_CLAUDE_MARKER)?;
                            stream_state = 3;
                        }
                        (3, Some("message_delta")) => {
                            require(event["delta"]["stop_reason"] == "end_turn")?;
                            stream_state = 4;
                        }
                        (4, Some("message_stop")) => stream_state = 5,
                        _ => return Err(failed()),
                    }
                }
                Some("assistant") => {
                    require(
                        initialized
                            && !assistant
                            // The pinned client emits its assembled assistant
                            // immediately before forwarding content_block_stop.
                            // The complete streamed marker must already exist;
                            // all remaining stop/result events are still required.
                            && stream_state >= 2
                            && streamed_text == MANAGED_CLAUDE_MARKER
                            && frame["message"]["role"] == "assistant"
                            && frame["message"]["content"]
                                == serde_json::json!([{"type":"text","text":MANAGED_CLAUDE_MARKER}]),
                    )?;
                    assistant = true;
                }
                Some("result") => {
                    require(
                        initialized
                            && assistant
                            && stream_state == 5
                            && frame["subtype"] == "success"
                            && frame["is_error"] == false
                            && frame["num_turns"] == 1
                            && frame["result"] == MANAGED_CLAUDE_MARKER,
                    )?;
                    completed = true;
                }
                _ => return Err(failed()),
            }
        }
        require(completed)
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

    fn require_general_egress_output(output: ExecOutput) -> SmokeResult<()> {
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

    fn standalone_codex_command() -> Vec<String> {
        // This transport-only fixture has no credential profile. Supply its
        // synthetic provider only for this invocation; managed proof below
        // must continue using unmodified stock-client bootstrap.
        let mut command = codex_command();
        command.splice(2..2, [
            "--config".to_owned(),
            "model_provider=\"codewire_smoke\"".to_owned(),
            "--config".to_owned(),
            format!("model_providers.codewire_smoke={{name=\"Codewire synthetic\",base_url=\"http://127.0.0.1:{CREDENTIAL_BRIDGE_LOOPBACK_PORT}/v1\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}}"),
            "--config".to_owned(),
            "features.enable_request_compression=false".to_owned(),
        ]);
        command
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
        // The confined broker is deliberately non-dumpable: Linux denies this
        // same-user observer /proc/PID/exe even though cmdline and PPid remain
        // readable. Retain the exact argv, UID and validated authority-parent
        // discriminator; the authority's own executable is checked below.
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
        // The checked-in managed smoke pins exactly OpenAI API key, Codex
        // OAuth, Anthropic API key, and GitHub OAuth. Match the spawner's complete
        // argv, including its ordered provider set; never discover a broader
        // selection from an arbitrary candidate process.
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
            "--runner-socket".into(),
            args.state_root
                .join("runners")
                .join(format!("{}.sock", environment.id))
                .into_os_string(),
            "--http-provider".into(),
            "openai-api-key".into(),
            "--http-provider".into(),
            "codex-oauth".into(),
            "--http-provider".into(),
            "anthropic-api-key".into(),
            "--http-provider".into(),
            "github-oauth".into(),
        ]
    }

    fn kill_exact_broker(
        pid: i32,
        args: &Args,
        environment: &local_v1::Environment,
    ) -> SmokeResult<()> {
        let descriptor = open_pidfd(pid)?;
        require(exact_broker_process(pid, args, environment))?;
        signal_pidfd(&descriptor)
    }

    fn open_pidfd(pid: i32) -> SmokeResult<OwnedFd> {
        require(pid > 0)?;
        // SAFETY: pidfd_open returns a new descriptor for the numeric process.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: ownership of the newly returned descriptor is transferred once.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
    }

    fn signal_pidfd(descriptor: &OwnedFd) -> SmokeResult<()> {
        // SAFETY: callers retain a pidfd for one revalidated synthetic process;
        // the null siginfo pointer requests ordinary SIGKILL delivery.
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

    fn pidfd_exited(descriptor: &OwnedFd) -> SmokeResult<bool> {
        let mut poll = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized descriptor and does not block.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        require(poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0)?;
        Ok(poll.revents & libc::POLLIN != 0)
    }

    async fn wait_for_credential_stack_exit(
        authority: &OwnedFd,
        broker: &OwnedFd,
        deadline: Instant,
    ) -> SmokeResult<()> {
        loop {
            // A dead/reparented broker no longer matches the live-parent
            // discovery predicate. Only its original pidfd proves exit here.
            if pidfd_exited(authority)? && pidfd_exited(broker)? {
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
                use bridge_v1::credential_bridge_guest_message::Payload;
                match message.payload {
                    Some(Payload::Request(_)) => stage("unexpected-second-request"),
                    Some(Payload::Cancel(_)) => stage("unexpected-request-cancel"),
                    Some(Payload::Ready(_)) => stage("unexpected-second-ready"),
                    Some(Payload::EnvironmentProjection(_)) => stage("unexpected-environment-projection"),
                    Some(Payload::Ssh(_)) => stage("unexpected-ssh-request"),
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

    async fn require_unselected_codex_home(client: &SessionClient) -> SmokeResult<()> {
        let output = run_transient(
            client,
            vec!["/bin/sh".into(), "-c".into(), format!(
                "test \"$CODEX_HOME\" = '{CODEX_GUEST_HOME_PATH}' && test ! -e \"$CODEX_HOME/config.toml\" && test ! -e \"$CODEX_HOME/auth.json\""
            )],
            "/", Vec::new(),
        ).await?;
        require(output.exit_code == 0 && output.stdout.is_empty() && output.stderr.is_empty())
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
        let Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(ready)) =
            message.payload
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
    ) -> SmokeResult<bridge_v1::CredentialBridgeRequest> {
        let deadline = Instant::now() + EXEC_TIMEOUT;
        tokio::select! {
            result = output.as_mut() => {
                let _ = result?;
                Err(failed())
            }
            message = bridge.receive() => {
                let message = message?.ok_or_else(failed)?;
                let Some(bridge_v1::credential_bridge_guest_message::Payload::Request(request)) = message.payload else {
                    return Err(failed());
                };
                Ok(request)
            }
            _ = tokio::time::sleep_until(deadline) => Err(failed()),
        }
    }

    fn validate_request(request: &bridge_v1::CredentialBridgeRequest) -> SmokeResult<()> {
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
            .send_response_start(bridge_v1::CredentialBridgeResponseStart {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![bridge_v1::CredentialHttpHeader {
                    name: "content-type".into(),
                    value: b"text/event-stream".to_vec(),
                }],
            })
            .await?;
        bridge
            .send_response_body(bridge_v1::CredentialBridgeResponseBody {
                request_id: request_id.clone(),
                data: SYNTHETIC_RESPONSE.to_vec(),
            })
            .await?;
        bridge
            .send_response_end(bridge_v1::CredentialBridgeResponseEnd { request_id })
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
                v1::exec_message::Payload::Error(error) => {
                    stage(if error == "environment launch denied or expired" {
                        "transient-exec-launch-denied"
                    } else {
                        "transient-exec-startup-error"
                    });
                    return Err(failed());
                }
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
            let mut openai_credential_id = None;
            let mut anthropic_credential_id = None;
            let mut ssh_credential_id = None;
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
                    "--openai-credential-id" => &mut openai_credential_id,
                    "--anthropic-credential-id" => &mut anthropic_credential_id,
                    "--ssh-credential-id" => &mut ssh_credential_id,
                    _ => return Err(failed()),
                };
                if slot.replace(value).is_some() {
                    return Err(failed());
                }
            }
            for id in [
                &credential_id,
                &openai_credential_id,
                &anthropic_credential_id,
                &ssh_credential_id,
            ] {
                require(managed_broker == id.is_some())?;
                if let Some(id) = id {
                    let parsed = Uuid::parse_str(id)?;
                    require(!parsed.is_nil() && parsed.to_string() == *id)?;
                }
            }
            if managed_broker {
                require(
                    credential_id != openai_credential_id
                        && credential_id != anthropic_credential_id
                        && credential_id != ssh_credential_id
                        && openai_credential_id != anthropic_credential_id
                        && openai_credential_id != ssh_credential_id
                        && anthropic_credential_id != ssh_credential_id,
                )?;
            }
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
                openai_credential_id,
                anthropic_credential_id,
                ssh_credential_id,
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
        fn hostname_probe_requires_owned_read_only_mapping_and_exact_local_resolution() {
            const FIXTURE: &str = r#"const vm=require('vm');const scenario=process.argv[2];
const stop={};let exit=0;let output='';let lookups=0;
const fs={lstatSync:path=>{if(path!=='/etc/hosts')throw Error('path');return {isFile:()=>scenario!=='not-file',uid:scenario==='wrong-owner'?1000:0,gid:scenario==='wrong-group'?1000:0,nlink:scenario==='hardlink'?2:1,mode:scenario==='writable'?0o644:0o444};},
openSync:(path,mode)=>{if(path!=='/etc/hosts'||mode!=='r+')throw Error('open');if(scenario==='write-open')return 9;throw Object.assign(Error(),{code:scenario==='other-error'?'EIO':scenario==='permission'?'EACCES':'EROFS'});},closeSync:()=>{}};
const os={hostname:()=>scenario==='wrong-name'?'other':'codewire'};
const dns={lookup:(name,options,callback)=>{if(name!=='codewire'||options.family!==4)throw Error('lookup');lookups++;callback(scenario==='dns-error'?Error():null,scenario==='wrong-address'?'203.0.113.1':'192.0.2.2');}};
try{vm.runInNewContext(process.argv[1],{require:name=>{if(name==='fs')return fs;if(name==='os')return os;if(name==='dns')return dns;throw Error('module');},process:{exit:code=>{exit=code;throw stop;},stdout:{write:value=>{output+=value;}}}},{timeout:1000});}catch(error){if(error!==stop)throw error;}
process.stdout.write(JSON.stringify({exit,output,lookups}));"#;
            for scenario in [
                "valid",
                "permission",
                "not-file",
                "wrong-owner",
                "wrong-group",
                "hardlink",
                "writable",
                "write-open",
                "other-error",
                "wrong-name",
                "dns-error",
                "wrong-address",
            ] {
                let output = std::process::Command::new("node")
                    .env_clear()
                    .args(["-e", FIXTURE, HOSTNAME_SCRIPT, scenario])
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                if matches!(scenario, "valid" | "permission") {
                    assert_eq!(result["exit"], 0);
                    assert_eq!(result["output"], "codewire-local-hostname-ok\n");
                    assert_eq!(result["lookups"], 1);
                } else {
                    assert_eq!(result["exit"], 81, "{scenario}");
                    assert_eq!(result["output"], "", "{scenario}");
                }
            }
        }

        fn selected_response(content_type: &str, body: String) -> SelectedHttpProbeOutput {
            SelectedHttpProbeOutput {
                status: 200,
                request_id: Some("[REDACTED]".into()),
                content_type: Some(content_type.into()),
                opaque_header_present: false,
                body,
            }
        }

        #[test]
        fn selected_responses_require_exact_markers_framing_and_filtered_headers() {
            let body = String::from_utf8(SYNTHETIC_RESPONSE.to_vec())
                .unwrap()
                .replace(CODEX_MARKER, MANAGED_OPENAI_MARKER);
            assert!(
                validate_openai_response(&selected_response("text/event-stream", body.clone()))
                    .is_ok()
            );
            for invalid in [
                body.replace(MANAGED_OPENAI_MARKER, MANAGED_CODEX_MARKER),
                body.replace(
                    MANAGED_OPENAI_MARKER,
                    "CWOPENAI broker synthetic-unredacted",
                ),
                body.replace("response.completed", "response.failed"),
                body.trim_end().to_owned(),
                format!("{body}{body}"),
            ] {
                assert!(
                    validate_openai_response(&selected_response("text/event-stream", invalid))
                        .is_err()
                );
            }
            let count = "{\"input_tokens\":42}".to_owned();
            assert!(
                validate_count_tokens_response(&selected_response(
                    "application/json",
                    count.clone()
                ))
                .is_ok()
            );
            for invalid in [
                "{\"input_tokens\":41}",
                "{\"input_tokens\":42,\"unexpected\":true}",
                "not-json",
            ] {
                assert!(
                    validate_count_tokens_response(&selected_response(
                        "application/json",
                        invalid.into()
                    ))
                    .is_err()
                );
            }
            for mode in 0..4 {
                let mut response = selected_response("application/json", count.clone());
                match mode {
                    0 => response.request_id = Some("synthetic-unredacted".into()),
                    1 => response.opaque_header_present = true,
                    2 => response.content_type = Some("text/event-stream".into()),
                    3 => response.status = 403,
                    _ => unreachable!(),
                }
                assert!(validate_count_tokens_response(&response).is_err());
            }
        }

        #[test]
        fn selected_ssh_identity_output_requires_one_exact_public_key() {
            let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKey";
            assert!(
                validate_ssh_identity_output(format!("{key} generated-comment\n").as_bytes(), key,)
                    .is_ok()
            );
            for invalid in [
                String::new(),
                "The agent has no identities.\n".into(),
                format!("{key}\n{key}\n"),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKey\n".into(),
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKey\n".into(),
            ] {
                assert!(validate_ssh_identity_output(invalid.as_bytes(), key).is_err());
            }
        }

        #[test]
        fn stock_ssh_host_trust_requires_one_bounded_exact_loopback_line() {
            let key = "[127.0.0.1]:22222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            assert_eq!(
                valid_public_host_key_line(format!("{key}\n").as_bytes()).unwrap(),
                key
            );
            for invalid in [
                key.to_owned(),
                format!("{key}\r\n"),
                format!("{key}\n{key}\n"),
                format!("{key} comment\n"),
                format!("{}\n", key.replace("127.0.0.1", "localhost")),
                format!("{}\n", key.replace("22222", "22")),
                format!("{}\n", key.replace("ssh-ed25519", "ssh-rsa")),
                format!("[127.0.0.1]:22222 ssh-ed25519 {}\n", "A".repeat(256)),
            ] {
                assert!(valid_public_host_key_line(invalid.as_bytes()).is_err());
            }
        }

        #[test]
        fn stock_ssh_audit_preserves_five_identity_signature_pairs_and_prior_events() {
            let mut events = vec![ExpectedAudit::CodexAdmitted];
            record_stock_ssh_audit(&mut events);
            assert_eq!(events.len(), 11);
            for pair in events[..10].chunks_exact(2) {
                assert!(matches!(pair[0], ExpectedAudit::SshSignAdmitted));
                assert!(matches!(pair[1], ExpectedAudit::SshIdentities));
            }
            assert!(matches!(events[10], ExpectedAudit::CodexAdmitted));
        }

        fn claude_frames() -> Vec<Value> {
            let event = |value| serde_json::json!({"type":"stream_event","event":value});
            vec![
                serde_json::json!({"type":"system","subtype":"init"}),
                event(
                    serde_json::json!({"type":"message_start","message":{"role":"assistant","model":CLAUDE_MODEL}}),
                ),
                event(
                    serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
                ),
                event(
                    serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"CWCLAUDE21238 broker "}}),
                ),
                event(
                    serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"[REDACTED]"}}),
                ),
                event(serde_json::json!({"type":"content_block_stop","index":0})),
                event(
                    serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}}),
                ),
                event(serde_json::json!({"type":"message_stop"})),
                serde_json::json!({"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":MANAGED_CLAUDE_MARKER}]}}),
                serde_json::json!({"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":MANAGED_CLAUDE_MARKER}),
            ]
        }

        fn claude_output(frames: &[Value]) -> ExecOutput {
            ExecOutput {
                stdout: frames
                    .iter()
                    .map(|frame| format!("{frame}\n"))
                    .collect::<String>()
                    .into_bytes(),
                stderr: Vec::new(),
                exit_code: 0,
            }
        }

        #[test]
        fn claude_requires_startup_partial_stream_exact_redaction_and_terminal_success() {
            let frames = claude_frames();
            assert!(validate_claude_output(&claude_output(&frames)).is_ok());
            for missing in 0..frames.len() {
                let mut invalid = frames.clone();
                invalid.remove(missing);
                assert!(
                    validate_claude_output(&claude_output(&invalid)).is_err(),
                    "missing {missing}"
                );
            }
            for index in 0..8 {
                let mut invalid = frames.clone();
                match index {
                    0 => invalid[4]["event"]["delta"]["text"] = "synthetic-unredacted".into(),
                    1 => invalid[1]["event"]["message"]["model"] = "other-model".into(),
                    2 => invalid[9]["is_error"] = true.into(),
                    3 => invalid[9]["num_turns"] = 2.into(),
                    4 => invalid[9]["result"] = "other-result".into(),
                    5 => invalid.push(serde_json::json!({"type":"result"})),
                    6 => invalid.swap(6, 7),
                    7 => invalid[2]["event"]["index"] = 1.into(),
                    _ => unreachable!(),
                }
                assert!(
                    validate_claude_output(&claude_output(&invalid)).is_err(),
                    "corruption {index}"
                );
            }
            let mut failed = claude_output(&frames);
            failed.exit_code = 1;
            assert!(validate_claude_output(&failed).is_err());
        }

        #[test]
        fn claude_accepts_observed_assistant_before_block_stop_only_after_complete_text() {
            let mut frames = claude_frames();
            let assistant = frames.remove(8);
            frames.insert(5, assistant.clone());
            assert!(validate_claude_output(&claude_output(&frames)).is_ok());
            for missing in 0..frames.len() {
                let mut invalid = frames.clone();
                invalid.remove(missing);
                assert!(validate_claude_output(&claude_output(&invalid)).is_err());
            }
            let mut early = claude_frames();
            early.remove(8);
            early.insert(4, assistant.clone());
            assert!(validate_claude_output(&claude_output(&early)).is_err());
            let mut duplicate = frames.clone();
            duplicate.insert(6, assistant);
            assert!(validate_claude_output(&claude_output(&duplicate)).is_err());
            let mut late_delta = frames;
            late_delta.insert(
                6,
                serde_json::json!({
                    "type":"stream_event", "event":{
                        "type":"content_block_delta", "index":0,
                        "delta":{"type":"text_delta", "text":""}
                    }
                }),
            );
            assert!(validate_claude_output(&claude_output(&late_delta)).is_err());
        }

        #[test]
        fn claude_accepts_observed_requesting_status_without_weakening_stream_proof() {
            // Observed from the exact pinned workspace's Claude 2.1.238 with
            // the managed arguments and public auth placeholders. A progress
            // event is not another startup, response, or successful result.
            let requesting = serde_json::json!({
                "type":"system", "subtype":"status", "status":"requesting"
            });
            let mut frames = claude_frames();
            frames.insert(1, requesting.clone());
            assert!(validate_claude_output(&claude_output(&frames)).is_ok());
            for missing in [0, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
                let mut invalid = frames.clone();
                invalid.remove(missing);
                assert!(validate_claude_output(&claude_output(&invalid)).is_err());
            }
            for status in [
                Value::Null,
                Value::Bool(true),
                "thinking".into(),
                "unknown".into(),
            ] {
                let mut invalid = frames.clone();
                invalid[1]["status"] = status;
                assert!(validate_claude_output(&claude_output(&invalid)).is_err());
            }
            for position in [0, 2, 4, frames.len()] {
                let mut invalid = frames.clone();
                invalid.insert(position, requesting.clone());
                assert!(validate_claude_output(&claude_output(&invalid)).is_err());
            }
            for position in [0, 2, 4, claude_frames().len()] {
                let mut invalid = claude_frames();
                invalid.insert(position, requesting.clone());
                assert!(validate_claude_output(&claude_output(&invalid)).is_err());
            }
        }

        // This is the synthetic transport's *post-redaction* Messages stream,
        // not a second broker or an alternative production response policy.
        const CLAUDE_CLIENT_FORMAT_SSE: &str = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_codewire_claude_smoke\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":42,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"CWCLAUDE21238 broker [REDACTED]\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":8}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );

        #[derive(Default)]
        struct ClaudeClientFormatRequests {
            count: std::sync::atomic::AtomicUsize,
            facts: std::sync::Mutex<Vec<Value>>,
        }

        async fn claude_client_format_response(
            axum::extract::State(requests): axum::extract::State<
                std::sync::Arc<ClaudeClientFormatRequests>,
            >,
            request: axum::extract::Request,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            use std::sync::atomic::Ordering;

            let count = requests.count.fetch_add(1, Ordering::SeqCst) + 1;
            if count > 8 {
                return (
                    http::StatusCode::TOO_MANY_REQUESTS,
                    "fixture request bound\n",
                )
                    .into_response();
            }
            let (parts, body) = request.into_parts();
            let path = parts
                .uri
                .path_and_query()
                .map_or("", |value| value.as_str());
            let mut header_names: Vec<_> = parts.headers.keys().map(|name| name.as_str()).collect();
            header_names.sort_unstable();
            let single_header = |name: &str, expected: &[u8]| {
                parts.headers.get_all(name).iter().count() == 1
                    && parts.headers.get(name).map(http::HeaderValue::as_bytes) == Some(expected)
            };
            let headers_valid = single_header("authorization", b"Bearer codewire-managed")
                && single_header("host", b"127.0.0.1:38081")
                && single_header("content-type", b"application/json")
                && single_header("anthropic-version", b"2023-06-01")
                && !parts.headers.contains_key("x-api-key")
                && !parts.headers.contains_key("cookie")
                && !parts.headers.contains_key("proxy-authorization");
            let payload = match tokio::time::timeout(
                Duration::from_secs(5),
                axum::body::to_bytes(body, 4 * 1024 * 1024),
            )
            .await
            {
                Ok(Ok(body)) => serde_json::from_slice::<Value>(&body).ok(),
                _ => None,
            };
            let payload = payload.unwrap_or(Value::Null);
            let messages = payload["messages"].as_array().map(Vec::len);
            let valid = parts.method == http::Method::POST
                && matches!(path, "/v1/messages" | "/v1/messages?beta=true")
                && headers_valid
                && payload["model"] == CLAUDE_MODEL
                && payload["stream"] == true
                && messages.is_some_and(|count| count > 0)
                && payload["max_tokens"]
                    .as_u64()
                    .is_some_and(|count| count > 0);
            // Only finite, public request facts: never prompt/body text or
            // arbitrary header values (even in this isolated synthetic test).
            requests.facts.lock().unwrap().push(serde_json::json!({
                "method": parts.method.as_str().chars().take(32).collect::<String>(),
                "path": path.chars().take(256).collect::<String>(),
                "header_names": header_names.into_iter().take(64).collect::<Vec<_>>(),
                "headers_valid": headers_valid,
                "public_bearer": single_header("authorization", b"Bearer codewire-managed"),
                "expected_host": single_header("host", b"127.0.0.1:38081"),
                "json_content_type": single_header("content-type", b"application/json"),
                "expected_version": single_header("anthropic-version", b"2023-06-01"),
                "api_key_header_present": parts.headers.contains_key("x-api-key"),
                "model": payload["model"].as_str().map(|model| model.chars().take(128).collect::<String>()),
                "stream": payload["stream"].as_bool(),
                "max_tokens": payload["max_tokens"].as_u64(),
                "message_count": messages,
                "valid": valid,
            }));
            if !valid {
                return (http::StatusCode::BAD_REQUEST, "fixture request contract\n")
                    .into_response();
            }
            (
                [
                    ("content-type", "text/event-stream"),
                    ("request-id", "[REDACTED]"),
                    ("connection", "close"),
                ],
                CLAUDE_CLIENT_FORMAT_SSE,
            )
                .into_response()
        }

        struct ClaudeClientFormatChild(tokio::process::Child);

        impl Drop for ClaudeClientFormatChild {
            fn drop(&mut self) {
                // Until wait has completed, this unreaped child pins its exact
                // process-group ID. No ambient PID/process-name matching.
                if let Some(pid) = self
                    .0
                    .id()
                    .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
            }
        }

        async fn run_claude_client_format_child(
            home: &Path,
            command: &[String],
            label: &str,
        ) -> Result<ExecOutput, String> {
            use std::process::Stdio;
            use tokio::io::AsyncReadExt;

            let mut child_command = tokio::process::Command::new(&command[0]);
            child_command
                .args(&command[1..])
                .env_clear()
                .env("HOME", home)
                .env("TMPDIR", home)
                .env("PATH", "/usr/bin:/bin")
                .env("ANTHROPIC_BASE_URL", "http://127.0.0.1:38081")
                .env("ANTHROPIC_AUTH_TOKEN", "codewire-managed")
                .env("ANTHROPIC_API_KEY", "")
                .env("CLAUDE_CODE_OAUTH_TOKEN", "")
                .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
                .env("CLAUDE_CODE_MAX_RETRIES", "0")
                .current_dir(home)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .kill_on_drop(true);
            for variable in smoke_environment() {
                let (name, value) = variable.split_once('=').unwrap();
                child_command.env(name, value);
            }
            let mut child = ClaudeClientFormatChild(
                child_command
                    .spawn()
                    .map_err(|error| format!("{label} spawn: {error}"))?,
            );
            let mut stdout = child
                .0
                .stdout
                .take()
                .unwrap()
                .take(MAX_EXEC_OUTPUT as u64 + 1);
            let mut stderr = child
                .0
                .stderr
                .take()
                .unwrap()
                .take(MAX_EXEC_OUTPUT as u64 + 1);
            let mut output = ExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: -1,
            };
            let result = tokio::time::timeout(EXEC_TIMEOUT, async {
                tokio::try_join!(
                    stdout.read_to_end(&mut output.stdout),
                    stderr.read_to_end(&mut output.stderr),
                )?;
                if output.stdout.len() > MAX_EXEC_OUTPUT || output.stderr.len() > MAX_EXEC_OUTPUT {
                    return Err(io::Error::other("fixture output bound"));
                }
                child.0.wait().await
            })
            .await;
            let failure = match result {
                Ok(Ok(status)) => {
                    output.exit_code = status.code().unwrap_or(-1);
                    None
                }
                Ok(Err(error)) => Some(format!("{label}: {error}")),
                Err(_) => Some(format!("{label}: fixture deadline")),
            };
            if failure.is_some() {
                if let Some(pid) = child
                    .0
                    .id()
                    .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let killed = child.0.start_kill();
                let reaped = tokio::time::timeout(Duration::from_secs(5), child.0.wait())
                    .await
                    .map_err(|_| format!("{label} reap deadline"))?
                    .map_err(|error| format!("{label} reap: {error}"));
                killed.map_err(|error| format!("{label} kill: {error}"))?;
                reaped?;
            }
            // Only this explicitly isolated test emits synthetic CLI output.
            // Production smoke diagnostics remain value-blind.
            eprintln!(
                "{label}: exit={} failure={failure:?} stdout_bytes={} stderr_bytes={}\nstdout:\n{}\nstderr:\n{}",
                output.exit_code,
                output.stdout.len(),
                output.stderr.len(),
                String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(64 * 1024)]),
                String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(64 * 1024)])
            );
            match failure {
                Some(error) => Err(error),
                None => Ok(output),
            }
        }

        #[tokio::test]
        #[ignore = "explicit pinned Claude client-format diagnosis; requires isolated bwrap /fixture/test and /fixture/claude, private /tmp and network namespace"]
        async fn pinned_claude_2_1_238_client_format() {
            use std::sync::{Arc, atomic::Ordering};

            assert_eq!(std::env::current_exe().unwrap(), Path::new("/fixture/test"));
            assert_eq!(
                fs::canonicalize("/fixture/claude").unwrap(),
                Path::new("/fixture/claude")
            );
            let home = tempfile::Builder::new()
                .prefix("claude-client-format-")
                .tempdir_in("/tmp")
                .unwrap();
            let version = run_claude_client_format_child(
                home.path(),
                &["/fixture/claude".into(), "--version".into()],
                "claude-version",
            )
            .await
            .unwrap();
            assert_eq!(version.exit_code, 0);
            assert_eq!(version.stdout, CLAUDE_VERSION.as_bytes());
            assert!(version.stderr.is_empty());

            let listener = tokio::net::TcpListener::bind("127.0.0.1:38081")
                .await
                .unwrap();
            let requests = Arc::new(ClaudeClientFormatRequests::default());
            let router = axum::Router::new()
                .fallback(claude_client_format_response)
                .with_state(requests.clone());
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let mut server = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
            });
            let mut command = claude_command(CLAUDE_PATHS[0]).unwrap();
            // Only the accepted-image executable's mount location changes;
            // flags, public auth checks, model and prompt are production-exact.
            command[4] = "/fixture/claude".into();
            let output =
                run_claude_client_format_child(home.path(), &command, "claude-stream").await;
            let _ = stop.send(());
            let drain = tokio::time::timeout(Duration::from_secs(10), &mut server).await;
            if drain.is_err() {
                server.abort();
                let _ = server.await;
            }
            eprintln!(
                "claude-requests: count={} facts={}",
                requests.count.load(Ordering::SeqCst),
                serde_json::to_string(&*requests.facts.lock().unwrap()).unwrap()
            );
            drain
                .expect("fixture listener drain deadline")
                .expect("fixture listener worker")
                .expect("fixture listener");
            let output = output.expect("bounded pinned client execution");
            assert_eq!(
                requests.count.load(Ordering::SeqCst),
                1,
                "unexpected client request count"
            );
            let facts = requests.facts.lock().unwrap();
            assert_eq!(facts.len(), 1);
            assert_eq!(
                facts[0]["valid"], true,
                "unexpected client request contract"
            );
            assert!(
                validate_claude_output(&output).is_ok(),
                "pinned Claude output disagrees with smoke parser; see bounded synthetic output above"
            );
        }

        #[test]
        fn claude_resolver_and_command_accept_only_pinned_guest_layout_without_auth_override() {
            for path in CLAUDE_PATHS {
                assert_eq!(
                    selected_claude_path(ExecOutput {
                        stdout: format!("{path}\n").into_bytes(),
                        stderr: vec![],
                        exit_code: 0,
                    })
                    .unwrap(),
                    path
                );
                let command = claude_command(path).unwrap();
                assert_eq!(&command[..3], &["/bin/sh", "-c", CLAUDE_ENV_EXEC_SCRIPT]);
                assert_eq!(command[4], path);
                assert!(
                    command
                        .windows(2)
                        .any(|args| args == ["--model", CLAUDE_MODEL])
                );
                for unsupported in [
                    "--bare",
                    "--dangerously-skip-permissions",
                    "--debug",
                    "--debug-file",
                ] {
                    assert!(!command.iter().any(|arg| arg == unsupported));
                }
                assert!(
                    !command[4..]
                        .iter()
                        .any(|arg| arg.contains("ANTHROPIC_") || arg.contains("OAUTH_TOKEN"))
                );
            }
            for path in [
                "/usr/local/bin/claude",
                "/tmp/claude",
                "claude",
                "",
                "/opt/codewire/agents/npm/bin/../bin/claude",
            ] {
                assert!(claude_command(path).is_err());
                assert!(
                    selected_claude_path(ExecOutput {
                        stdout: format!("{path}\n").into_bytes(),
                        stderr: vec![],
                        exit_code: 0,
                    })
                    .is_err()
                );
            }
        }

        #[test]
        fn selected_audit_is_complete_ordered_exact_identity_and_revision_not_filtered() {
            let environment = local_v1::Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                generation: 7,
                access_profile_id: "00000000-0000-4000-8000-000000000002".into(),
                access_profile_revision: MANAGED_PROFILE_REVISION,
                ..Default::default()
            };
            let selected = ManagedCredentials {
                codex: CredentialId::parse("credential-codex").unwrap(),
                openai: CredentialId::parse("credential-openai").unwrap(),
                anthropic: CredentialId::parse("credential-anthropic").unwrap(),
                ssh: CredentialId::parse("credential-ssh").unwrap(),
            };
            let expected = [
                ExpectedAudit::SshSignAdmitted,
                ExpectedAudit::SshIdentities,
                ExpectedAudit::AnthropicMessages,
                ExpectedAudit::AnthropicCountTokens,
                ExpectedAudit::OpenAi,
                ExpectedAudit::CodexAdmitted,
            ];
            let events: Vec<_> = [
                ("ssh", "ssh-sign", "ssh-agent", &selected.ssh),
                ("ssh", "ssh-identities", "ssh-agent", &selected.ssh),
                (
                    "anthropic",
                    "messages",
                    "anthropic-api",
                    &selected.anthropic,
                ),
                (
                    "anthropic",
                    "count-tokens",
                    "anthropic-api",
                    &selected.anthropic,
                ),
                ("openai", "responses", "openai-api", &selected.openai),
                ("codex", "responses", "openai-api", &selected.codex),
            ]
            .into_iter()
            .enumerate()
            .map(
                |(index, (slot, operation, route, credential))| BrokerLeaseAuditEvent {
                    sequence: (6 - index) as u64,
                    observed_at_unix_ms: 1,
                    environment_id: EnvironmentId::parse(environment.id.clone()).unwrap(),
                    environment_generation: 7,
                    request_id: Uuid::from_u128(index as u128 + 1),
                    capability_slot: CapabilitySlot::parse(slot).unwrap(),
                    operation: BrokerOperationId::parse(operation).unwrap(),
                    route: BrokerRouteId::parse(route).unwrap(),
                    decision: BrokerLeaseAuditDecision::Admitted,
                    credential_id: Some(credential.clone()),
                    profile_id: Some(
                        codewire_access::AccessProfileId::parse(
                            environment.access_profile_id.clone(),
                        )
                        .unwrap(),
                    ),
                    profile_revision: Some(MANAGED_PROFILE_REVISION),
                    credential_revocation_generation: Some(1),
                },
            )
            .collect();
            assert!(validate_audit_events(&events, &environment, &selected, &expected).is_ok());
            let mut denied = events.clone();
            denied[0].decision = BrokerLeaseAuditDecision::Denied;
            denied[0].credential_id = None;
            denied[0].profile_id = None;
            denied[0].profile_revision = None;
            denied[0].credential_revocation_generation = None;
            let mut denied_expected = expected;
            denied_expected[0] = ExpectedAudit::SshSignDenied;
            assert!(
                validate_audit_events(&denied, &environment, &selected, &denied_expected).is_ok()
            );
            for corruption in 0..10 {
                let mut invalid = events.clone();
                match corruption {
                    0 => invalid[2].capability_slot = CapabilitySlot::codex(),
                    1 => invalid[2].credential_id = Some(selected.codex.clone()),
                    2 => invalid[0].profile_revision = Some(3),
                    3 => invalid[0].environment_generation = 6,
                    4 => invalid[0].decision = BrokerLeaseAuditDecision::Denied,
                    5 => invalid[0].sequence += 1,
                    6 => invalid[0].request_id = invalid[1].request_id,
                    7 => invalid.push(invalid[0].clone()),
                    8 => {
                        invalid.remove(0);
                    }
                    9 => invalid[0].profile_id = None,
                    _ => unreachable!(),
                }
                assert!(
                    validate_audit_events(&invalid, &environment, &selected, &expected).is_err(),
                    "corruption {corruption}"
                );
            }
        }

        const SELECTED_HTTP_FIXTURE: &str = r#"const vm=require('vm');
const env={OPENAI_BASE_URL:'http://127.0.0.1:38081/_codewire/openai/v1',OPENAI_API_KEY:'codewire-managed',ANTHROPIC_BASE_URL:'http://127.0.0.1:38081',ANTHROPIC_AUTH_TOKEN:'codewire-managed',ANTHROPIC_API_KEY:'',CLAUDE_CODE_OAUTH_TOKEN:''};
const mode=process.argv[2];const change=process.argv[3];if(change==='missing-api')delete env.ANTHROPIC_API_KEY;else if(change==='oauth')env.CLAUDE_CODE_OAUTH_TOKEN='synthetic-competing';else if(change==='base')env.OPENAI_BASE_URL='https://unselected.invalid/v1';else if(change==='key')env.OPENAI_API_KEY='synthetic-competing';
let calls=0;let exitCode=0;let captured=null;let output='';let timeoutMs=0;const handlers=new Map();
const response={statusCode:200,headers:{'content-type':mode==='openai'?'text/event-stream':'application/json','x-request-id':'[REDACTED]','request-id':'[REDACTED]'},on:(name,callback)=>{handlers.set(name,callback);return response;}};
const request={setTimeout:(ms)=>{timeoutMs=ms;return request;},on:()=>request,destroy:()=>{},end:(body)=>{captured.body=JSON.parse(body);}};
try{vm.runInNewContext(process.argv[1],{Buffer,URL,require:(name)=>{if(name!=='http')throw new Error('unexpected module');return {request:(url,options,callback)=>{calls++;captured={url:url.href,...options};callback(response);return request;}};},process:{argv:['node',mode],env,exit:(code)=>{throw {fixture_exit:code};},stdout:{write:(value)=>{output+=value;}}}},{timeout:1000});
handlers.get('data')(Buffer.from('fixture-response'));handlers.get('end')();
}catch(error){if(!Number.isInteger(error.fixture_exit))throw error;exitCode=error.fixture_exit;}
process.stdout.write(JSON.stringify({calls,exit_code:exitCode,captured,output,timeout_ms:timeoutMs}));"#;

        async fn selected_http_fixture(mode: &str, change: &str) -> Value {
            let mut command = tokio::process::Command::new("node");
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .arg("-e")
                .arg(SELECTED_HTTP_FIXTURE)
                .arg(SELECTED_HTTP_SCRIPT)
                .arg(mode)
                .arg(change)
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(5), command.output())
                .await
                .expect("bounded synthetic Node HTTP fixture")
                .unwrap();
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            serde_json::from_slice(&output.stdout).unwrap()
        }

        #[tokio::test]
        async fn selected_http_probe_uses_generated_route_and_public_placeholder_only() {
            for (mode, url, model) in [
                (
                    "openai",
                    "http://127.0.0.1:38081/_codewire/openai/v1/responses",
                    CODEX_MODEL,
                ),
                (
                    "count-tokens",
                    "http://127.0.0.1:38081/v1/messages/count_tokens",
                    CLAUDE_MODEL,
                ),
            ] {
                let result = selected_http_fixture(mode, "unchanged").await;
                assert_eq!(result["calls"], 1);
                assert_eq!(result["exit_code"], 0);
                assert_eq!(result["timeout_ms"], 10_000);
                let request = &result["captured"];
                assert_eq!(request["url"], url);
                assert_eq!(request["method"], "POST");
                assert_eq!(
                    request["headers"]["authorization"],
                    "Bearer codewire-managed"
                );
                assert_eq!(request["headers"]["content-type"], "application/json");
                assert!(request["headers"].get("x-api-key").is_none());
                assert_eq!(request["body"]["model"], model);
                if mode == "openai" {
                    assert_eq!(request["body"]["stream"], true);
                    assert_eq!(request["body"]["input"], CODEX_PROMPT);
                } else {
                    assert!(request["body"].get("stream").is_none());
                    assert_eq!(request["headers"]["anthropic-version"], "2023-06-01");
                    assert_eq!(
                        request["body"]["messages"],
                        serde_json::json!([{"role":"user","content":CODEX_PROMPT}])
                    );
                }
                let response: SelectedHttpProbeOutput =
                    serde_json::from_str(result["output"].as_str().unwrap()).unwrap();
                assert!(!response.opaque_header_present);
                assert_eq!(response.request_id.as_deref(), Some("[REDACTED]"));
            }
        }

        #[tokio::test]
        async fn selected_http_probe_rejects_changed_or_missing_generated_inputs_before_http() {
            for (mode, change) in [
                ("openai", "base"),
                ("openai", "key"),
                ("count-tokens", "missing-api"),
                ("count-tokens", "oauth"),
                ("other", "unchanged"),
            ] {
                let result = selected_http_fixture(mode, change).await;
                assert_eq!(result["calls"], 0);
                assert!(result["exit_code"].as_u64().unwrap() > 0);
                assert_eq!(result["output"], "");
            }
        }

        #[test]
        fn standalone_transport_config_is_invocation_only_and_managed_command_is_unmodified() {
            let managed = codex_command();
            // Resolve the installed command through the workload's image PATH,
            // including when its persistent home starts empty.
            assert_eq!(&managed[..2], &["codex", "exec"]);
            assert!(!managed.iter().any(|arg| arg.contains("model_provider")));
            let standalone = standalone_codex_command();
            assert_eq!(&standalone[..2], &managed[..2]);
            assert_eq!(&standalone[8..], &managed[2..]);
            assert_eq!(standalone[2], "--config");
            assert_eq!(standalone[3], "model_provider=\"codewire_smoke\"");
            assert!(standalone[5].contains("base_url=\"http://127.0.0.1:38081/v1\""));
            assert!(standalone[5].contains("requires_openai_auth=false"));
            assert!(standalone[5].contains("supports_websockets=false"));
            assert_eq!(standalone[7], "features.enable_request_compression=false");
        }

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

        const AUTHORITY_LOSS_EVENT_FIXTURE: &str = r#"const vm=require('vm');
const stdinHandlers=new Map();const responseHandlers=new Map();let timer;let secureConnect;
let httpCount=0;let tlsCount=0;let stdout='';let exitCode=null;let destroyed=false;let cleared=false;let httpOptions;let tlsOptions;let requestBody;
const stopped=Symbol('fixture exit');
const response={statusCode:503,headers:{},on:(name,callback)=>{responseHandlers.set(name,callback);return response;}};
const request={setTimeout:(duration)=>{if(duration!==10000)throw new Error('timeout changed');return request;},on:()=>request,end:(body)=>{requestBody=JSON.parse(body);responseHandlers.get('data')(Buffer.from('credential route unavailable\n'));responseHandlers.get('end')();}};
const socket={on:()=>socket,setTimeout:(duration)=>{if(duration!==10000)throw new Error('TLS timeout changed');return socket;},end:()=>{},destroy:()=>{throw new Error('unexpected TLS failure');}};
vm.runInNewContext(process.argv[1],{Buffer,
setTimeout:(callback,duration)=>{if(duration!==90000)throw new Error('READY timeout changed');timer=callback;return 1;},clearTimeout:()=>{cleared=true;},
require:(name)=>{if(name==='http')return {request:(options,callback)=>{httpCount++;httpOptions=options;callback(response);return request;}};if(name==='tls')return {connect:(options,callback)=>{tlsCount++;tlsOptions=options;secureConnect=callback;return socket;}};throw new Error('unexpected module');},
process:{stdin:{on:(name,callback)=>{stdinHandlers.set(name,callback);},destroy:()=>{destroyed=true;}},stdout:{write:(value)=>{stdout+=value;}},exit:(code)=>{exitCode=code;throw stopped;}}
},{timeout:1000});
const before={http:httpCount,tls:tlsCount,stdout};let partialHttp;
try{switch(process.argv[2]){
case 'valid':stdinHandlers.get('data')(Buffer.from('g'));partialHttp=httpCount;stdinHandlers.get('data')(Buffer.from('o\n'));secureConnect();break;
case 'oversize':stdinHandlers.get('data')(Buffer.from('go\nx'));break;
case 'wrong':stdinHandlers.get('data')(Buffer.from('bad'));break;
case 'eof':stdinHandlers.get('end')();break;
case 'timeout':timer();break;
default:throw new Error('invalid fixture case');
}}catch(error){if(error!==stopped)throw error;}
process.stdout.write(JSON.stringify({before,http:httpCount,tls:tlsCount,stdout,exit_code:exitCode,destroyed,cleared,http_options:httpOptions,tls_options:tlsOptions,request_body:requestBody,partial_http:partialHttp}));"#;

        async fn authority_loss_events(scenario: &str) -> Value {
            let script = authority_loss_script();
            assert!(script.contains(GENERAL_EGRESS_SCRIPT));
            let output = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new("node")
                    .env_clear()
                    .env(
                        "PATH",
                        std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
                    )
                    .current_dir("/")
                    .args(["-e", AUTHORITY_LOSS_EVENT_FIXTURE, &script, scenario])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("bounded synthetic trigger fixture")
            .expect("Node fixture");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            assert!(output.stdout.len() < 4096);
            serde_json::from_slice(&output.stdout).unwrap()
        }

        #[tokio::test]
        async fn authority_loss_probe_waits_for_exact_trigger_before_http_and_unchanged_tls() {
            let result = authority_loss_events("valid").await;
            assert_eq!(
                result["before"],
                serde_json::json!({"http":0,"tls":0,"stdout":"codewire-authority-loss-ready\n"})
            );
            assert_eq!(result["partial_http"], 0);
            assert_eq!(result["http"], 1);
            assert_eq!(result["tls"], 1);
            assert_eq!(result["destroyed"], true);
            assert_eq!(result["cleared"], true);
            assert!(result["exit_code"].is_null());
            assert_eq!(result["http_options"]["host"], "127.0.0.1");
            assert_eq!(result["http_options"]["port"], 38081);
            assert_eq!(result["http_options"]["method"], "POST");
            assert_eq!(result["http_options"]["path"], "/v1/responses");
            assert_eq!(
                result["http_options"]["headers"]["authorization"],
                format!("Bearer {GUEST_CALLER_BEARER}")
            );
            assert_eq!(
                result["request_body"],
                serde_json::json!({"model":"codewire-synthetic","input":"hello","stream":true})
            );
            assert_eq!(
                result["tls_options"],
                serde_json::json!({"host":"ghcr.io","port":443,"family":4,"servername":"ghcr.io","rejectUnauthorized":true})
            );
            let stdout = result["stdout"]
                .as_str()
                .unwrap()
                .strip_prefix(std::str::from_utf8(AUTHORITY_LOSS_READY).unwrap())
                .unwrap();
            let (route, egress) = authority_loss_output(ExecOutput {
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            })
            .unwrap();
            assert_eq!(route.status, 503);
            assert_eq!(route.body, "credential route unavailable\n");
            require_general_egress_output(egress).unwrap();
        }

        #[tokio::test]
        async fn authority_loss_probe_rejects_extra_wrong_eof_and_timed_out_triggers_without_network()
         {
            for scenario in ["oversize", "wrong", "eof", "timeout"] {
                let result = authority_loss_events(scenario).await;
                assert_eq!(result["http"], 0);
                assert_eq!(result["tls"], 0);
                assert_eq!(result["stdout"], "codewire-authority-loss-ready\n");
                assert_eq!(result["exit_code"], 80);
            }
        }

        fn fake_probe_output(
            frames: Vec<Result<DaemonRunOutput, DaemonClientError>>,
        ) -> ProbeOutput {
            futures::stream::iter(frames).boxed()
        }

        #[tokio::test]
        async fn authority_loss_ready_requires_complete_exact_marker_without_early_exit_or_output()
        {
            for split in 1..AUTHORITY_LOSS_READY.len() {
                let mut output = fake_probe_output(vec![
                    Ok(DaemonRunOutput::Stdout(
                        AUTHORITY_LOSS_READY[..split].to_vec(),
                    )),
                    Ok(DaemonRunOutput::Stdout(
                        AUTHORITY_LOSS_READY[split..].to_vec(),
                    )),
                ]);
                require_probe_ready(&mut output).await.unwrap();
            }
            for frames in [
                vec![],
                vec![Ok(DaemonRunOutput::Stdout(b"codewire-".to_vec()))],
                vec![Ok(DaemonRunOutput::Stdout(
                    [AUTHORITY_LOSS_READY, b"extra"].concat(),
                ))],
                vec![Ok(DaemonRunOutput::Stdout(b"CANARY-WRONG-READY".to_vec()))],
                vec![Ok(DaemonRunOutput::Exit(0))],
                vec![Err(DaemonClientError::Remote(
                    "CANARY-PRIVATE-ERROR".into(),
                ))],
            ] {
                assert!(
                    require_probe_ready(&mut fake_probe_output(frames))
                        .await
                        .is_err()
                );
            }
        }

        #[tokio::test]
        async fn authority_loss_cleanup_requires_exit_then_clean_eof() {
            let cases = [
                (vec![Ok(DaemonRunOutput::Exit(137))], true),
                (
                    vec![
                        Err(DaemonClientError::Remote("diagnostic".into())),
                        Ok(DaemonRunOutput::Exit(1)),
                    ],
                    true,
                ),
                (vec![], false),
                (
                    vec![Err(DaemonClientError::Remote("diagnostic".into()))],
                    false,
                ),
                (vec![Ok(DaemonRunOutput::Exit(-1))], false),
                (
                    vec![Ok(DaemonRunOutput::Exit(0)), Ok(DaemonRunOutput::Exit(0))],
                    false,
                ),
                (
                    vec![
                        Ok(DaemonRunOutput::Exit(0)),
                        Ok(DaemonRunOutput::Stdout(vec![1])),
                    ],
                    false,
                ),
                (
                    vec![
                        Ok(DaemonRunOutput::Exit(0)),
                        Err(DaemonClientError::Status(tonic::Status::unavailable(
                            "synthetic",
                        ))),
                    ],
                    false,
                ),
            ];
            for (frames, valid) in cases {
                let mut probe = AuthorityLossProbe {
                    input: None,
                    output: fake_probe_output(frames),
                    deadline: Instant::now() + EXEC_TIMEOUT,
                    exit: None,
                    finished: false,
                };
                assert_eq!(probe.cancel_and_drain().await.is_ok(), valid);
                assert_eq!(probe.finished, valid);
            }
        }

        #[tokio::test]
        async fn fresh_launch_denial_requires_exact_startup_error_exit_one_and_eof() {
            use v1::exec_message::Payload;
            let denied = || v1::ExecMessage {
                payload: Some(Payload::Error(
                    "environment launch denied or expired".into(),
                )),
            };
            let exit = |code| v1::ExecMessage {
                payload: Some(Payload::Exit(v1::ExitStatus { code })),
            };
            let valid = vec![Ok(denied()), Ok(exit(1))];
            require_denied_launch_frames(&mut futures::stream::iter(valid))
                .await
                .unwrap();
            for frames in [
                vec![],
                vec![Ok(denied())],
                vec![Ok(exit(1))],
                vec![Ok(denied()), Ok(exit(0))],
                vec![Ok(denied()), Ok(exit(1)), Ok(exit(1))],
                vec![
                    Ok(v1::ExecMessage {
                        payload: Some(Payload::Error("unrelated failure".into())),
                    }),
                    Ok(exit(1)),
                ],
                vec![
                    Ok(v1::ExecMessage {
                        payload: Some(Payload::Stdout(DENIED_LAUNCH_MARKER.as_bytes().to_vec())),
                    }),
                    Ok(denied()),
                    Ok(exit(1)),
                ],
                vec![
                    Ok(denied()),
                    Ok(exit(1)),
                    Err(tonic::Status::unavailable("synthetic")),
                ],
            ] {
                assert!(
                    require_denied_launch_frames(&mut futures::stream::iter(frames))
                        .await
                        .is_err()
                );
            }
        }

        #[test]
        fn authority_loss_output_preserves_all_general_egress_failure_assertions() {
            let route = b"{\"status\":503,\"request_id\":null,\"body\":\"credential route unavailable\\n\"}\n";
            for (exit_code, stdout, stderr, valid) in [
                (0, GENERAL_EGRESS_MARKER.to_vec(), vec![], true),
                (75, GENERAL_EGRESS_MARKER.to_vec(), vec![], false),
                (0, vec![], vec![], false),
                (
                    0,
                    GENERAL_EGRESS_MARKER.to_vec(),
                    b"CANARY-PRIVATE-STDERR".to_vec(),
                    false,
                ),
            ] {
                let (_, egress) = authority_loss_output(ExecOutput {
                    stdout: [route.as_slice(), stdout.as_slice()].concat(),
                    stderr,
                    exit_code,
                })
                .unwrap();
                assert_eq!(require_general_egress_output(egress).is_ok(), valid);
            }
        }

        #[tokio::test]
        async fn stack_death_requires_both_original_pidfds_after_authority_is_gone() {
            fn child() -> tokio::process::Child {
                tokio::process::Command::new("/bin/sh")
                    .env_clear()
                    .current_dir("/")
                    .args(["-c", "read -r synthetic"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap()
            }
            let mut authority = child();
            let mut broker = child();
            let authority_fd = open_pidfd(authority.id().unwrap() as i32).unwrap();
            let broker_fd = open_pidfd(broker.id().unwrap() as i32).unwrap();
            drop(authority.stdin.take());
            authority.wait().await.unwrap();
            let authority_dead = pidfd_exited(&authority_fd).unwrap();
            let broker_dead = pidfd_exited(&broker_fd).unwrap();
            let premature = wait_for_credential_stack_exit(
                &authority_fd,
                &broker_fd,
                Instant::now() + Duration::from_millis(10),
            )
            .await;
            signal_pidfd(&broker_fd).unwrap();
            let final_death = wait_for_credential_stack_exit(
                &authority_fd,
                &broker_fd,
                Instant::now() + Duration::from_secs(2),
            )
            .await;
            broker.wait().await.unwrap();
            assert!(authority_dead);
            assert!(!broker_dead);
            assert!(
                premature.is_err(),
                "a vanished authority does not prove broker exit"
            );
            final_death.unwrap();
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
            assert!(direct.ssh_credential_id.is_none());

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
                "00000000-0000-4000-8000-000000000011".to_owned(),
                "--openai-credential-id".to_owned(),
                "00000000-0000-4000-8000-000000000012".to_owned(),
                "--anthropic-credential-id".to_owned(),
                "00000000-0000-4000-8000-000000000013".to_owned(),
                "--ssh-credential-id".to_owned(),
                "00000000-0000-4000-8000-000000000014".to_owned(),
            ]);
            let parsed = Args::parse(managed.clone()).unwrap();
            assert!(parsed.managed_broker);
            assert_eq!(
                parsed.credential_authority_root,
                std::path::Path::new("/credentials")
            );
            assert_eq!(
                parsed.credential_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000011")
            );
            assert_eq!(
                parsed.openai_credential_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000012")
            );
            assert_eq!(
                parsed.anthropic_credential_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000013")
            );
            assert_eq!(
                parsed.ssh_credential_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000014")
            );

            for offset in [2, 4, 6, 8] {
                let index = required_arguments().len() + offset;
                for invalid in ["", "credential-id", "00000000-0000-0000-0000-000000000000"] {
                    let mut invalid_arguments = managed.clone();
                    invalid_arguments[index] = invalid.into();
                    assert!(Args::parse(invalid_arguments).is_err());
                }
                let mut missing = managed.clone();
                missing.drain(index - 1..=index);
                assert!(Args::parse(missing).is_err());
            }
            let mut duplicate = managed.clone();
            let first = required_arguments().len() + 2;
            duplicate[first + 2] = duplicate[first].clone();
            assert!(Args::parse(duplicate).is_err());

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

        fn broker_argv_fixture() -> (Args, local_v1::Environment, Vec<OsString>) {
            let args = Args::parse(required_arguments()).unwrap();
            let environment = local_v1::Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                generation: 3,
                name: "environment".into(),
                ..Default::default()
            };
            // Independent fixed vector for the current authority-spawned argv,
            // not an encoding of expected_broker_argv's result.
            let actual = [
                "/bin/cw",
                "__local-credential-broker",
                "--authority-fd",
                "3",
                "--environment-id",
                "00000000-0000-4000-8000-000000000001",
                "--environment-generation",
                "3",
                "--environment-name",
                "environment",
                "--runner-socket",
                "/state/runners/00000000-0000-4000-8000-000000000001.sock",
                "--http-provider",
                "openai-api-key",
                "--http-provider",
                "codex-oauth",
                "--http-provider",
                "anthropic-api-key",
                "--http-provider",
                "github-oauth",
            ]
            .into_iter()
            .map(OsString::from)
            .collect();
            (args, environment, actual)
        }

        fn proc_cmdline_fixture(argv: &[OsString]) -> Vec<u8> {
            argv.iter()
                .flat_map(|arg| arg.as_os_str().as_bytes().iter().copied().chain([0]))
                .collect()
        }

        #[test]
        fn managed_broker_argv_accepts_exact_current_runner_and_provider_selection() {
            let (args, environment, actual) = broker_argv_fixture();
            let expected = expected_broker_argv(&args, &environment);
            assert_eq!(expected, actual);
            let process = tempfile::tempdir().unwrap();
            fs::write(
                process.path().join("cmdline"),
                proc_cmdline_fixture(&actual),
            )
            .unwrap();
            assert!(exact_process_argv(process.path(), &expected));
        }

        #[test]
        fn managed_broker_argv_rejects_retired_contract_and_current_near_misses() {
            let (args, environment, actual) = broker_argv_fixture();
            let expected = expected_broker_argv(&args, &environment);
            let process = tempfile::tempdir().unwrap();
            let rejects = |candidate: &[OsString]| {
                fs::write(
                    process.path().join("cmdline"),
                    proc_cmdline_fixture(candidate),
                )
                .unwrap();
                assert!(!exact_process_argv(process.path(), &expected));
            };
            let mut retired = actual[..10].to_vec();
            retired.extend(
                [
                    "--supervisor-socket",
                    "/state/supervisor.sock",
                    "--credential-authentication-kind",
                    "oauth",
                ]
                .map(OsString::from),
            );
            rejects(&retired);
            for (index, replacement) in [
                (0, "/bin/other-cw"),
                (1, "__local-credential-authority"),
                (3, "4"),
                (5, "00000000-0000-4000-8000-000000000002"),
                (7, "4"),
                (9, "other-environment"),
                (10, "--supervisor-socket"),
                (11, "/state/supervisor.sock"),
                (
                    11,
                    "/state/runners/00000000-0000-4000-8000-000000000002.sock",
                ),
                (
                    11,
                    "/other-state/runners/00000000-0000-4000-8000-000000000001.sock",
                ),
                (12, "--credential-authentication-kind"),
                (13, "codex-oauth"),
                (15, "openai-api-key"),
                (17, "github-oauth"),
                (19, "anthropic-api-key"),
            ] {
                let mut candidate = actual.clone();
                candidate[index] = replacement.into();
                rejects(&candidate);
            }
            let mut reordered = actual.clone();
            reordered.swap(13, 15);
            rejects(&reordered);
            rejects(&actual[..18]); // Missing selected GitHub provider.
            let mut additional = actual.clone();
            additional.extend(["--http-provider", "anthropic-api-key"].map(OsString::from));
            rejects(&additional);
            additional = actual;
            additional.push(OsString::new());
            rejects(&additional);
        }

        #[test]
        fn managed_broker_argv_rejects_malformed_or_oversized_proc_cmdline() {
            let (args, environment, actual) = broker_argv_fixture();
            let expected = expected_broker_argv(&args, &environment);
            let process = tempfile::tempdir().unwrap();
            let mut unterminated = proc_cmdline_fixture(&actual);
            unterminated.pop();
            for invalid in [Vec::new(), unterminated, vec![0; MAX_PROC_CMDLINE + 1]] {
                fs::write(process.path().join("cmdline"), invalid).unwrap();
                assert!(!exact_process_argv(process.path(), &expected));
            }
        }
    }
}
