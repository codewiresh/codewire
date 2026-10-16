use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::Path;

use anyhow::Context as _;
use codewire_access::{EnvironmentId, HttpProvider};
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use codewire_credential_broker::ProviderHttpsTransport;
#[cfg(feature = "local-broker-synthetic-smoke")]
use codewire_credential_broker::SyntheticOpenAiSmokeTransport;
use codewire_credential_broker::{
    BrokerBridgeError, CredentialBridgeRelayOutput, OpenAiBroker, admit_credential_bridge,
    run_admitted_credential_bridge, run_admitted_credential_bridge_relay,
};
#[cfg(target_os = "linux")]
use codewire_local_credentials::AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
use codewire_local_credentials::{
    LocalCredentialBrokerLeaseClient, LocalCredentialDelegationClient,
};
use codewire_local_vmm::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use codewire_local_vmm::runner_service::RunnerClient;
#[cfg(target_os = "linux")]
use codewire_protected_store::ConnectedOsProtectedStore;
use futures::StreamExt as _;
use uuid::Uuid;

use super::LocalCredentialBrokerArgs;
#[cfg(target_os = "linux")]
use super::credential_broker_confinement::{
    apply_broker_landlock_confinement, apply_broker_seccomp_confinement,
};

#[cfg(target_os = "macos")]
mod darwin;

/// The broker's error output, for its authority's broker log (#2763): on
/// failure it writes exactly one line, `CW_BROKER_EXIT stage=<stage>
/// kind=<kind>`, both fixed names. No error message, path, status text or
/// value is written, so the log can be shared.
pub(crate) const BROKER_EXIT_MARKER: &str = "CW_BROKER_EXIT";

/// The step the broker is in, named for its exit line.
struct BrokerStage(std::sync::Mutex<&'static str>);

impl BrokerStage {
    fn set(&self, stage: &'static str) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = stage;
    }

    fn get(&self) -> &'static str {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(crate) async fn run_local_credential_broker(
    args: LocalCredentialBrokerArgs,
) -> anyhow::Result<()> {
    let stage = BrokerStage(std::sync::Mutex::new("process.verify"));
    let result = run_broker(args, &stage).await;
    if let Err(error) = &result {
        eprintln!(
            "{BROKER_EXIT_MARKER} stage={} kind={}",
            stage.get(),
            exit_kind(error)
        );
    }
    result
}

/// A fixed name for the first typed error in the chain; never its message.
fn exit_kind(error: &anyhow::Error) -> &'static str {
    use codewire_local_credentials::BrokerLeaseChannelError as Lease;
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<BrokerBridgeError>() {
            return match error {
                BrokerBridgeError::InvalidIdentity => "bridge.invalid_identity",
                BrokerBridgeError::InvalidProtocol => "bridge.invalid_protocol",
                BrokerBridgeError::Unavailable => "bridge.unavailable",
            };
        }
        if let Some(error) = cause.downcast_ref::<Lease>() {
            return match error {
                Lease::InvalidRequest => "lease.invalid_request",
                Lease::Denied => "lease.denied",
                Lease::Unavailable => "lease.unavailable",
                Lease::InvalidResponse => "lease.invalid_response",
                Lease::RefreshInProgress => "lease.refresh_in_progress",
                Lease::StaleRefresh => "lease.stale_refresh",
            };
        }
        if cause.is::<tokio::time::error::Elapsed>() {
            return "timeout";
        }
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            return status_kind(status.code());
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            return match error.kind() {
                std::io::ErrorKind::NotFound => "io.not_found",
                std::io::ErrorKind::PermissionDenied => "io.permission_denied",
                std::io::ErrorKind::ConnectionRefused => "io.connection_refused",
                std::io::ErrorKind::ConnectionReset => "io.connection_reset",
                std::io::ErrorKind::BrokenPipe => "io.broken_pipe",
                std::io::ErrorKind::TimedOut => "io.timed_out",
                std::io::ErrorKind::UnexpectedEof => "io.unexpected_eof",
                _ => "io.other",
            };
        }
    }
    "other"
}

fn status_kind(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "status.ok",
        tonic::Code::Cancelled => "status.cancelled",
        tonic::Code::Unknown => "status.unknown",
        tonic::Code::InvalidArgument => "status.invalid_argument",
        tonic::Code::DeadlineExceeded => "status.deadline_exceeded",
        tonic::Code::NotFound => "status.not_found",
        tonic::Code::AlreadyExists => "status.already_exists",
        tonic::Code::PermissionDenied => "status.permission_denied",
        tonic::Code::ResourceExhausted => "status.resource_exhausted",
        tonic::Code::FailedPrecondition => "status.failed_precondition",
        tonic::Code::Aborted => "status.aborted",
        tonic::Code::OutOfRange => "status.out_of_range",
        tonic::Code::Unimplemented => "status.unimplemented",
        tonic::Code::Internal => "status.internal",
        tonic::Code::Unavailable => "status.unavailable",
        tonic::Code::DataLoss => "status.data_loss",
        tonic::Code::Unauthenticated => "status.unauthenticated",
    }
}

async fn run_broker(args: LocalCredentialBrokerArgs, stage: &BrokerStage) -> anyhow::Result<()> {
    verify_broker_process_confinement()?;
    stage.set("arguments.parse");
    // Validate the store selection before any channel or provider effect.
    #[cfg(target_os = "macos")]
    let store = super::credential_darwin::ChildStore::from_args(&args.store)?;
    anyhow::ensure!(args.authority_fd == 3, "invalid broker authority channel");
    let environment_id = EnvironmentId::parse(args.environment_id.clone())
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    let environment_uuid = Uuid::parse_str(&args.environment_id)
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    anyhow::ensure!(
        !environment_uuid.is_nil() && args.environment_generation > 0,
        "invalid broker environment identity"
    );
    let mut http_providers = BTreeSet::new();
    for name in &args.http_providers {
        let provider = HttpProvider::parse(name).context("invalid broker HTTP provider")?;
        anyhow::ensure!(
            http_providers.insert(provider),
            "duplicate broker HTTP provider"
        );
    }
    anyhow::ensure!(
        !args.platform_delegated || http_providers.is_empty(),
        "platform relay cannot select local provider transport"
    );
    anyhow::ensure!(
        args.runner_socket.is_absolute()
            && args.runner_socket.file_name().and_then(OsStr::to_str)
                == Some(format!("{environment_uuid}.sock").as_str()),
        "invalid broker runner endpoint"
    );

    stage.set("authority.channel");
    // SAFETY: FD 3 is created by the authority immediately before exec and is
    // the only descriptor deliberately retained across that exec. Ownership is
    // transferred exactly once into this process.
    let authority_fd = unsafe { OwnedFd::from_raw_fd(args.authority_fd) };
    // The macOS broker runs Apple's security tool for keychain reads; that
    // child must not inherit the authority channel.
    #[cfg(target_os = "macos")]
    rustix::io::fcntl_setfd(&authority_fd, rustix::io::FdFlags::CLOEXEC)
        .context("prepare broker authority channel")?;
    let authority_stream = std::os::unix::net::UnixStream::from(authority_fd);
    authority_stream
        .set_nonblocking(true)
        .context("prepare broker authority channel")?;
    let authority_stream = tokio::net::UnixStream::from_std(authority_stream)
        .context("admit broker authority channel")?;
    stage.set("provider.resolve");
    // Provider addresses are resolved once, here, before confinement and
    // before the guest bridge opens: a successor that cannot resolve them
    // never takes new work from the epoch it would replace. The authority
    // replaces this child with an overlapping successor before it has run
    // 600 seconds, and that successor resolves them again. A platform relay
    // selects no provider and resolves nothing.
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let upstream = if http_providers.is_empty() {
        None
    } else {
        Some(
            ProviderHttpsTransport::resolve(&http_providers)
                .await
                .context("resolve credential broker provider endpoint")?,
        )
    };
    #[cfg(feature = "local-broker-synthetic-smoke")]
    let upstream = (!http_providers.is_empty()).then_some(SyntheticOpenAiSmokeTransport);
    // A selected GitHub connection may be an expiring App login. Its refresh
    // uses the App's own family with the public client ID only; resolve it
    // with the other provider addresses, before confinement.
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let github_app = if http_providers.contains(&HttpProvider::GitHubOAuth) {
        Some(std::sync::Arc::new(
            codewire_credential_broker::GitHubAppAuthorizationOwner::public_client(
                codewire_credential_broker::provider_oauth::github::codewire_github_app(),
                std::sync::Arc::new(
                    ProviderHttpsTransport::resolve(&BTreeSet::from([
                        HttpProvider::GitHubAppAuthorization,
                    ]))
                    .await
                    .context("resolve the GitHub App refresh endpoint")?,
                ),
            ),
        ))
    } else {
        None
    };
    stage.set("runner.connect");
    let mut runner = RunnerClient::connect(&args.runner_socket)
        .await
        .context("connect broker to private runner")?;
    stage.set("daemon.transport");
    let access = runner
        .generation_daemon_access(environment_uuid, args.environment_generation)
        .await
        .context("resolve broker daemon transport")?;
    // The supervisor observed authenticated runc-launching progress, which
    // follows spawning the early daemon. Its listener may still be binding.
    // Keep one exact socket identity and one deadline across transport-only
    // retries; no provider material or authenticated Open has been used yet.
    stage.set("daemon.connect");
    let target = HybridVsockTarget::new(
        Path::new(&access.hybrid_socket).to_owned(),
        access.guest_port,
    )
    .context("admit broker daemon endpoint")?;
    let daemon = tokio::time::timeout(std::time::Duration::from_secs(7), async {
        loop {
            match target.connect_daemon(&access.generation_capability).await {
                Ok(daemon) => break Ok(daemon),
                Err(HybridVsockError::Channel) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await
    .context("broker daemon transport readiness timed out")?
    .context("connect broker to guest daemon")?;
    stage.set("bridge.open");
    // Both brokers serve the Codex and Claude logins, the listed direct
    // delivery exceptions (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct
    // delivery exceptions"). The local broker serves the owner's own Codex
    // sign-in; a local profile has no Claude sign-in. For a platform profile
    // the relay passes each request through the host authority's delegation,
    // which admits the login and its answer both ways, to the platform broker,
    // which decides it for the delegation's creator. A refusal answers DENIED or UNAVAILABLE without ending the
    // epoch; only the local broker's authority fault ends its epoch, because
    // a refresh owner it holds is released only when its lease channel
    // closes.
    let bridge = daemon
        .open_credential_bridge_with_capabilities(
            environment_uuid,
            args.environment_generation,
            &[
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
            ],
        )
        .await
        .context("open guest credential bridge")?;
    stage.set("bridge.admit");
    let bridge = admit_credential_bridge(bridge, environment_uuid, args.environment_generation)
        .await
        .context("authenticate guest credential bridge")?;
    // The broker needs only the admitted bridge from this point onward. Do not
    // retain general runner or daemon clients inside the credential-bearing
    // runtime domain.
    drop(daemon);
    drop(runner);
    stage.set("relay.confine");
    if args.platform_delegated {
        // The original guest Ready is retained in `bridge`. This branch has
        // no provider DNS, protected-store connection, or raw lease provider.
        // The only authority endpoint is the parent's inherited FD3 channel.
        #[cfg(target_os = "linux")]
        apply_broker_landlock_confinement().context("confine platform credential relay")?;
        // One deny-all Seatbelt profile replaces Landlock and seccomp: the
        // relay keeps only the bridge and authority descriptors it holds.
        #[cfg(target_os = "macos")]
        darwin::confine_relay().context("confine platform credential relay")?;
        stage.set("relay.authority");
        let mut delegation = LocalCredentialDelegationClient::connect(
            authority_stream,
            environment_id,
            args.environment_generation,
        )
        .await
        .context("connect platform credential relay authority")?;
        #[cfg(target_os = "linux")]
        apply_broker_seccomp_confinement().context("seal platform credential relay")?;
        stage.set("relay.run");
        return run_admitted_credential_bridge_relay(bridge, move |ready, input| async move {
            let output = delegation
                .delegate_credentials(ready, input)
                .await
                .map_err(|_| BrokerBridgeError::Unavailable)?;
            // The exact private admission was consumed only after the parent
            // verified the exact public selection echo. HTTP headers alone
            // never make this native broker ready.
            delegation
                .report_ready()
                .await
                .map_err(|_| BrokerBridgeError::Unavailable)?;
            Ok(
                Box::pin(output.map(|frame| frame.map_err(|_| BrokerBridgeError::Unavailable)))
                    as CredentialBridgeRelayOutput,
            )
        })
        .await
        .context("run platform credential relay");
    }
    stage.set("broker.confine");
    #[cfg(target_os = "linux")]
    let protected_store = {
        apply_broker_landlock_confinement().context("confine credential broker filesystem")?;
        ConnectedOsProtectedStore::connect().context("connect broker protected store")?
    };
    // One Seatbelt profile replaces Landlock and seccomp: provider HTTPS to
    // the addresses resolved above, and reads of exactly the selected store.
    #[cfg(target_os = "macos")]
    let protected_store = {
        darwin::confine(&store, !http_providers.is_empty()).context("confine credential broker")?;
        store.open().context("open broker protected store")?
    };
    stage.set("lease.connect");
    let mut leases = LocalCredentialBrokerLeaseClient::connect(
        authority_stream,
        protected_store,
        environment_id,
        args.environment_generation,
    )
    .await
    .context("connect broker lease authority")?;
    #[cfg(target_os = "linux")]
    apply_broker_seccomp_confinement().context("seal credential broker runtime")?;
    stage.set("lease.ready");
    leases
        .report_ready(bridge.ready().clone())
        .await
        .context("complete broker launch handshake")?;
    stage.set("provider.policy");
    let broker = OpenAiBroker::new(leases, upstream)
        .map_err(|_| anyhow::anyhow!("initialize broker provider policy"))?;
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let broker = match github_app {
        Some(owner) => broker.with_github_app_authorization_owner(owner),
        None => broker,
    };
    stage.set("bridge.run");
    run_admitted_credential_bridge(broker, bridge)
        .await
        .context("run guest credential bridge")
}

#[cfg(target_os = "macos")]
fn verify_broker_process_confinement() -> anyhow::Result<()> {
    darwin::verify_process()
}

#[cfg(target_os = "linux")]
fn verify_broker_process_confinement() -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::thread::no_new_privs().unwrap_or(false),
        "local credential broker is not confined"
    );
    let capabilities = rustix::thread::capabilities(None)
        .map_err(|_| anyhow::anyhow!("local credential broker is not confined"))?;
    anyhow::ensure!(
        capabilities.effective.is_empty()
            && capabilities.permitted.is_empty()
            && capabilities.inheritable.is_empty(),
        "local credential broker is not confined"
    );
    let pid = rustix::process::getpid();
    anyhow::ensure!(
        rustix::process::getsid(None).ok() == Some(pid),
        "local credential broker is not confined"
    );
    for (name, _) in std::env::vars_os() {
        anyhow::ensure!(
            AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
                .iter()
                .any(|allowed| name == OsStr::new(allowed)),
            "local credential broker inherited an ambient environment"
        );
    }
    let mut parent_death_signal = 0_i32;
    // SAFETY: both operations use scalar arguments except PR_GET_PDEATHSIG,
    // which writes exactly one initialized i32 owned by this stack frame.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    let death_signal_result = unsafe {
        libc::prctl(
            libc::PR_GET_PDEATHSIG,
            std::ptr::addr_of_mut!(parent_death_signal),
            0,
            0,
            0,
        )
    };
    anyhow::ensure!(
        dumpable == 0 && death_signal_result == 0 && parent_death_signal == libc::SIGKILL,
        "local credential broker is not confined"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn broker_environment_allowlist_excludes_provider_and_platform_values() {
        let ambient = BTreeMap::from([
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("OPENAI_API_KEY", "synthetic-provider-value"),
            ("CODEWIRE_API_KEY", "synthetic-platform-value"),
            ("SSH_AUTH_SOCK", "/tmp/synthetic-agent"),
        ]);
        let inherited = AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
            .into_iter()
            .filter_map(|name| ambient.get(name).map(|value| (name, *value)))
            .collect::<Vec<_>>();
        assert_eq!(
            inherited,
            vec![
                ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]
        );
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;

    /// The exit line names the first typed error in the chain by a fixed
    /// name, never its message or any context text.
    #[test]
    fn exit_kind_names_the_first_typed_error_and_never_its_message() {
        let bridge = anyhow::Error::new(BrokerBridgeError::Unavailable)
            .context("run guest credential bridge");
        assert_eq!(exit_kind(&bridge), "bridge.unavailable");
        let status = anyhow::Error::new(tonic::Status::deadline_exceeded("ghu_secret_detail"))
            .context("open guest credential bridge");
        assert_eq!(exit_kind(&status), "status.deadline_exceeded");
        let io = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context("connect broker to private runner");
        assert_eq!(exit_kind(&io), "io.connection_refused");
        let lease = anyhow::Error::new(codewire_local_credentials::BrokerLeaseChannelError::Denied)
            .context("complete broker launch handshake");
        assert_eq!(exit_kind(&lease), "lease.denied");
        assert_eq!(exit_kind(&anyhow::anyhow!("sk-0123456789abcdef")), "other");
    }
}
