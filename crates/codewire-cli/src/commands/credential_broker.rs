use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use codewire_access::{EnvironmentId, HttpProvider};
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use codewire_credential_broker::ProviderHttpsTransport;
#[cfg(feature = "local-broker-synthetic-smoke")]
use codewire_credential_broker::SyntheticOpenAiSmokeTransport;
use codewire_credential_broker::{
    AdmittedCredentialBridge, BrokerBridgeError, CredentialBridgeRelayOutput, FrontDoorTransport,
    OpenAiBroker, RelayNetworkPolicy, admit_credential_bridge, run_admitted_credential_bridge,
    run_admitted_credential_bridge_relay, run_admitted_credential_bridges,
};
#[cfg(target_os = "linux")]
use codewire_local_credentials::AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
use codewire_local_credentials::{
    BootSecretPurpose, BrokerBootSecrets, MAX_BOOT_SECRET_RECORDS_BYTES,
};
use codewire_local_credentials::{
    LocalCredentialBrokerLeaseClient, LocalCredentialDelegationClient,
};
use codewire_local_vmm::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use codewire_local_vmm::runner_service::RunnerClient;
use futures::StreamExt as _;
use uuid::Uuid;

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
    // Each refused agent login, as one line the authority keeps in its
    // broker log: two closed words, nothing from the request.
    codewire_credential_broker::timing::set_login_refusal_sink(|agent, reason| {
        eprintln!(
            "{} agent={agent} reason={reason}",
            codewire_local_credentials::AGENT_LOGIN_REFUSED_MARKER
        );
    });
    let result = run_broker(args, &stage).await;
    if let Err(error) = &result {
        eprintln!("{}", exit_line(stage.get(), error));
    }
    result
}

/// The broker's last line on stderr, which the authority keeps in its broker
/// log: the stage it had reached and [`exit_word`].
fn exit_line(stage: &str, error: &anyhow::Error) -> String {
    format!(
        "{BROKER_EXIT_MARKER} stage={stage} kind={}",
        exit_word(error)
    )
}

/// What the broker says of `error` as it ends: [`exit_kind`], and for a
/// runner that speaks another protocol the two numbers, which are the whole
/// cause (#5238). The authority keeps the line in its broker log, where a run
/// of 20 or more token characters is redacted, so each word stays shorter.
fn exit_word(error: &anyhow::Error) -> String {
    use codewire_local_vmm::runner_service::RunnerServiceError;
    for cause in error.chain() {
        match cause.downcast_ref::<RunnerServiceError>() {
            Some(RunnerServiceError::RunnerProtocolMismatch { expected, actual }) => {
                return format!("runner.protocol_mismatch broker={expected} runner={actual}");
            }
            Some(RunnerServiceError::RunnerProtocolInfoUnavailable) => {
                return "runner.no_protocol".to_owned();
            }
            _ => {}
        }
    }
    exit_kind(error).to_owned()
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
                // The reason stays out: the kind is the same for every one.
                Lease::Withheld(_) => "lease.withheld",
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

/// What the local credential authority starts each broker child with.
#[derive(Debug, clap::Args)]
pub(crate) struct LocalCredentialBrokerArgs {
    #[arg(long)]
    pub(crate) authority_fd: i32,
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) environment_generation: u64,
    #[arg(long)]
    pub(crate) environment_name: String,
    #[arg(long)]
    pub(crate) runner_socket: PathBuf,
    #[arg(long = "http-provider")]
    pub(crate) http_providers: Vec<String>,
    #[arg(long)]
    pub(crate) platform_delegated: bool,
    /// The inherited descriptor carrying the boot's secrets (#3999), only
    /// for a boot that has any.
    #[arg(long)]
    pub(crate) boot_secrets_fd: Option<i32>,
    /// The environment's network policy allows GitHub's hosts by rule, so
    /// the managed GitHub credential is served (#4926). Absent, it is not.
    #[arg(long)]
    pub(crate) network_policy_allows_github: bool,
    /// A bound host the environment's network policy allows by rule on 443,
    /// once each: a front-door request carrying none of this environment's
    /// placeholders is forwarded untouched only to one of these (#5555).
    #[arg(long = "network-policy-allows-host")]
    pub(crate) network_policy_allowed_hosts: Vec<String>,
    /// No broker serves this generation: start whatever resolves, leaving a
    /// provider host with no address unserved (#5286).
    #[arg(long, conflicts_with = "may_not_resolve")]
    pub(crate) start_whatever_resolves: bool,
    /// A provider host this broker may leave unresolved, because the broker
    /// it replaces does not serve it either. Every other host must resolve.
    #[arg(long)]
    pub(crate) may_not_resolve: Vec<String>,
    /// An early replacement, started to get a provider back: at least one
    /// of the hosts it may leave unresolved must resolve.
    #[arg(long, requires = "may_not_resolve")]
    pub(crate) must_resolve_more: bool,
    /// The authority's store: brokers read the selected backend.
    #[command(flatten)]
    pub(crate) store: super::credential_child_store::ChildStoreArgs,
}

/// The broker's provider transport, its GitHub App refresh owner when GitHub
/// is selected, and the hosts left unresolved. A selected GitHub connection
/// may be an expiring App login, whose refresh uses the App's own family
/// with the public client ID only. Both transports are built from one
/// lookup of every host, so a start waits one resolver timeout at most.
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
async fn resolve_providers(
    http_providers: &BTreeSet<HttpProvider>,
) -> anyhow::Result<(
    Option<ProviderHttpsTransport>,
    Option<std::sync::Arc<codewire_credential_broker::GitHubAppAuthorizationOwner>>,
    BTreeSet<&'static str>,
)> {
    if http_providers.is_empty() {
        return Ok((None, None, BTreeSet::new()));
    }
    let app_refresh = BTreeSet::from([HttpProvider::GitHubAppAuthorization]);
    let mut selections = vec![http_providers];
    if http_providers.contains(&HttpProvider::GitHubOAuth) {
        selections.push(&app_refresh);
    }
    let looked_up = ProviderHttpsTransport::look_up(&selections)
        .await
        .context("resolve credential broker provider endpoint")?;
    let upstream = ProviderHttpsTransport::available(http_providers, &looked_up)
        .context("resolve credential broker provider endpoint")?;
    let mut unresolved: BTreeSet<&'static str> = upstream.unresolved_hosts().collect();
    let github_app = if selections.len() > 1 {
        let refresh = ProviderHttpsTransport::available(&app_refresh, &looked_up)
            .context("resolve the GitHub App refresh endpoint")?;
        unresolved.extend(refresh.unresolved_hosts());
        Some(std::sync::Arc::new(
            codewire_credential_broker::GitHubAppAuthorizationOwner::public_client(
                codewire_credential_broker::provider_oauth::github::codewire_github_app(),
                std::sync::Arc::new(refresh),
            ),
        ))
    } else {
        None
    };
    Ok((Some(upstream), github_app, unresolved))
}

/// Whether this broker may start with `unresolved` provider hosts, by the
/// rule its authority started it with.
fn lookup_allows(args: &LocalCredentialBrokerArgs, unresolved: &BTreeSet<&'static str>) -> bool {
    if args.start_whatever_resolves {
        return true;
    }
    unresolved
        .iter()
        .all(|host| args.may_not_resolve.iter().any(|allowed| allowed == host))
        && !(args.must_resolve_more && unresolved.len() >= args.may_not_resolve.len())
}

async fn run_broker(args: LocalCredentialBrokerArgs, stage: &BrokerStage) -> anyhow::Result<()> {
    verify_broker_process_confinement()?;
    // Before anything else, so nothing this broker starts inherits them.
    stage.set("boot_secrets.read");
    let boot_secrets = match args.boot_secrets_fd {
        Some(descriptor) => read_boot_secrets(descriptor)?,
        None => BrokerBootSecrets::default(),
    };
    stage.set("arguments.parse");
    // Validate the store selection before any channel or provider effect.
    let store = super::credential_child_store::ChildStore::from_args(&args.store)?;
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
    // before the guest bridge opens. A host with no address is left unserved
    // (#5286) when the authority's rule allows it: any host for a generation
    // with no broker serving, and for a successor only a host the broker it
    // replaces does not serve either, so a successor that resolves fewer
    // never takes new work from that epoch. The authority replaces this
    // child with an overlapping successor before it has run 600 seconds, and
    // that successor resolves them again. A platform relay selects no
    // provider and resolves nothing.
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let (upstream, github_app, unresolved) = resolve_providers(&http_providers).await?;
    #[cfg(feature = "local-broker-synthetic-smoke")]
    let unresolved = BTreeSet::<&'static str>::new();
    #[cfg(feature = "local-broker-synthetic-smoke")]
    let upstream = (!http_providers.is_empty()).then_some(SyntheticOpenAiSmokeTransport);
    anyhow::ensure!(
        lookup_allows(&args, &unresolved),
        "resolve credential broker provider endpoint"
    );
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
    // sign-in and Claude sign-in from a local profile. For a platform profile
    // the relay passes each request through the host authority's delegation,
    // which admits the login and its answer both ways, to the platform broker,
    // which decides it for the delegation's creator. A refusal answers DENIED or UNAVAILABLE without ending the
    // epoch; only the local broker's authority fault ends its epoch, because
    // a refresh owner it holds is released only when its lease channel
    // closes.
    //
    // Only this broker's own runner serves streamed Git request bodies
    // (#4280). A platform-delegated broker relays frames to an authority that
    // may be older, so it leaves them out and its guest sends whole bodies.
    let mut capabilities = vec![
        codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
        codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
    ];
    if !args.platform_delegated {
        capabilities.push(codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM);
    }
    let bridge = daemon
        .open_credential_bridge_with_capabilities(
            environment_uuid,
            args.environment_generation,
            &capabilities,
        )
        .await
        .context("open guest credential bridge")?;
    stage.set("bridge.admit");
    let bridge = admit_credential_bridge(bridge, environment_uuid, args.environment_generation)
        .await
        .context("authenticate guest credential bridge")?;
    // The environment's front door (#3999), when the boot binds interception.
    // It pairs before confinement, as the daemon connection does. A relay to
    // the platform broker (#4909) writes the session's Open only once the
    // platform has admitted what it serves, so here it only connects.
    stage.set("front_door.pair");
    let intercepted = !access.front_door_socket.is_empty();
    let paired = if !intercepted {
        None
    } else {
        // Only the boot's own pairing secret pairs; never the daemon token,
        // which the guest knows (#3999).
        let pairing = boot_secrets
            .get(BootSecretPurpose::FrontDoorPairing)
            .context("the boot's pairing secret is missing")?;
        connect_front_door(Path::new(&access.front_door_socket), pairing)
            .await
            .context("pair with the environment's front door")?
    };
    let (front_door, delegated_front_door) = match paired {
        Some(stream) if args.platform_delegated => {
            (None, Some((stream, tokio::time::Instant::now())))
        }
        Some(stream) => (
            Some(
                open_front_door(stream, environment_uuid, args.environment_generation)
                    .await
                    .context("open the environment's front-door session")?,
            ),
            None,
        ),
        None => (None, None),
    };
    drop(boot_secrets);
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
        apply_broker_landlock_confinement(None).context("confine platform credential relay")?;
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
        // The front door's session starts now and holds its Open until the
        // relay's first join, which waits for the delegation's admission.
        let hand_over = delegated_front_door.map(|(stream, paired_at)| {
            let (hand_over, joiner) = tokio::sync::oneshot::channel();
            let identity = codewire_credential_broker::BridgeIdentity {
                environment_id: environment_uuid,
                environment_generation: args.environment_generation,
            };
            tokio::spawn(async move {
                let end = codewire_credential_broker::serve_delegated_front_door(
                    stream, identity, joiner, paired_at,
                )
                .await;
                tracing::info!(?end, "the platform front-door session ended");
            });
            hand_over
        });
        stage.set("relay.run");
        let relay_policy = if args.network_policy_allows_github {
            RelayNetworkPolicy::AllowsGitHub
        } else {
            RelayNetworkPolicy::RefusesGitHub
        };
        return run_admitted_credential_bridge_relay(
            bridge,
            relay_policy,
            move |ready, input| async move {
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
                if let Some(hand_over) = hand_over {
                    // Joins go through the authority, which keeps the
                    // platform's epoch handle; the loopback session never
                    // waits for them.
                    let joiner = FrontDoorJoiner {
                        delegation,
                        environment_id: environment_uuid,
                        environment_generation: args.environment_generation,
                    };
                    let _ = hand_over.send(joiner); // Fails only once the session has ended.
                }
                Ok(
                    Box::pin(output.map(|frame| frame.map_err(|_| BrokerBridgeError::Unavailable)))
                        as CredentialBridgeRelayOutput,
                )
            },
        )
        .await
        .context("run platform credential relay");
    }
    stage.set("broker.confine");
    // Landlock first: it admits reads of a file store's directory only, and
    // Secret Service is connected once afterwards over the session bus.
    #[cfg(target_os = "linux")]
    let protected_store = {
        apply_broker_landlock_confinement(store.file_directory())
            .context("confine credential broker filesystem")?;
        store.open().context("open broker protected store")?
    };
    // One Seatbelt profile replaces Landlock and seccomp: provider HTTPS to
    // the addresses resolved above, and reads of exactly the selected store.
    // The store is opened first: opening the login keychain asks the user
    // database for the account's home through `id`, and the profile lets the
    // broker run only `security`. Opening reads no value.
    #[cfg(target_os = "macos")]
    let protected_store = {
        let protected_store = store.open().context("open broker protected store")?;
        darwin::confine(
            &store,
            protected_store.selected(),
            !http_providers.is_empty(),
        )
        .context("confine credential broker")?;
        protected_store
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
        .report_ready(
            bridge.ready().clone(),
            unresolved.iter().map(|host| (*host).to_owned()).collect(),
        )
        .await
        .context("complete broker launch handshake")?;
    stage.set("provider.policy");
    let broker = OpenAiBroker::new(leases, upstream)
        .map_err(|_| anyhow::anyhow!("initialize broker provider policy"))?
        .with_network_policy_allowing_github(args.network_policy_allows_github)
        .with_network_policy_allowing_hosts(&args.network_policy_allowed_hosts);
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let broker = match github_app {
        Some(owner) => broker.with_github_app_authorization_owner(owner),
        None => broker,
    };
    let broker = if refuses_agent_logins(intercepted, front_door.is_some()) {
        broker.with_agent_logins_refused()
    } else {
        broker
    };
    stage.set("bridge.run");
    match front_door {
        Some(front_door) => run_admitted_credential_bridges(broker, bridge, front_door)
            .await
            .context("run guest and front-door credential bridges"),
        None => run_admitted_credential_bridge(broker, bridge)
            .await
            .context("run guest credential bridge"),
    }
}

/// Whether a broker seals no agent login: one started with a front door it
/// could not pair with. The guest's seed says intercepted, so the sign-in's
/// tokens would reach agents that expect only placeholders (#3999).
fn refuses_agent_logins(intercepted: bool, paired: bool) -> bool {
    intercepted && !paired
}

/// A boot's secrets from the descriptor the authority passed (#3999). It is
/// made close-on-exec before it is read, so no helper this broker starts can
/// inherit it, read once to its end, and closed.
fn read_boot_secrets(descriptor: i32) -> anyhow::Result<BrokerBootSecrets> {
    anyhow::ensure!(descriptor == 4, "invalid broker boot secrets");
    // SAFETY: FD 4 is created by the authority immediately before exec, only
    // for a boot with secrets; ownership moves here exactly once.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    read_boot_secret_descriptor(&descriptor)
}

/// Seal `descriptor` close-on-exec, then read it to its end. The caller
/// closes it.
fn read_boot_secret_descriptor(descriptor: &OwnedFd) -> anyhow::Result<BrokerBootSecrets> {
    use std::io::Read as _;
    rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::CLOEXEC)
        .context("seal broker boot secrets")?;
    let mut records = zeroize::Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_BOOT_SECRET_RECORDS_BYTES + 1).unwrap_or(u64::MAX);
    std::os::unix::net::UnixStream::from(
        descriptor.try_clone().context("read broker boot secrets")?,
    )
    .take(limit)
    .read_to_end(&mut records)
    .context("read broker boot secrets")?;
    BrokerBootSecrets::from_records(&records)
        .map_err(|_| anyhow::anyhow!("invalid broker boot secrets"))
}

/// Connect to the runner's pairing socket, present the boot's pairing
/// secret, and open the front-door session the runner then hands the front
/// door.
///
/// The front-door session, or none when the generation's pairing socket is
/// gone. The runner keeps it for the generation's life, so every broker the
/// authority starts, each renewal's successor included, pairs and takes the
/// new work (#3999). Gone means the runner or its front door has ended: this
/// broker serves its loopback session alone, and intercepted dials stay
/// refused.
async fn connect_front_door(
    socket: &Path,
    capability: &[u8],
) -> anyhow::Result<Option<tokio::net::UnixStream>> {
    use tokio::io::AsyncWriteExt as _;
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::UnixStream::connect(socket),
    )
    .await
    .context("front door pairing timed out")?;
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let length = u16::try_from(capability.len()).context("pairing secret is too long")?;
    stream.write_u16(length).await?;
    stream.write_all(capability).await?;
    // The runner reads the capability; the front door reads this role tag
    // before anything else, so a swapped socket is refused at once.
    stream
        .write_all(&[codewire_credential_broker::FRONT_DOOR_SESSION_ROLE_TAG])
        .await?;
    Ok(Some(stream))
}

/// Open the local broker's front-door session on a paired `stream` and admit
/// the front door's Ready.
async fn open_front_door(
    stream: tokio::net::UnixStream,
    environment_id: Uuid,
    environment_generation: u64,
) -> anyhow::Result<AdmittedCredentialBridge<FrontDoorTransport>> {
    let session = FrontDoorTransport::open(stream, environment_id, environment_generation).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        admit_credential_bridge(session, environment_id, environment_generation),
    )
    .await
    .context("front door session readiness timed out")?
    .map_err(Into::into)
}

/// Joins the admitted delegation's front-door session (#4909) with this
/// relay's own binding Ready, through the authority on the relay's channel.
/// The platform's epoch handle stays with the authority.
struct FrontDoorJoiner {
    delegation: LocalCredentialDelegationClient,
    environment_id: Uuid,
    environment_generation: u64,
}

impl codewire_credential_broker::DelegatedFrontDoorJoiner for FrontDoorJoiner {
    fn join(
        &mut self,
    ) -> futures::future::BoxFuture<
        '_,
        Option<codewire_credential_broker::DelegatedFrontDoorUpstream>,
    > {
        Box::pin(async move {
            let ready = codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady {
                protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: self.environment_id.to_string(),
                environment_generation: self.environment_generation,
            };
            let (guest, guest_frames) = tokio::sync::mpsc::channel(FRONT_DOOR_GUEST_BUFFER);
            let (host, capabilities) = self
                .delegation
                .delegate_front_door(
                    ready,
                    tokio_stream::wrappers::ReceiverStream::new(guest_frames),
                )
                .await
                .ok()?;
            Some(codewire_credential_broker::DelegatedFrontDoorUpstream {
                capabilities,
                guest,
                host: host.map(|frame| frame.map_err(|_| ())).boxed(),
            })
        })
    }
}

/// Guest frames queued toward the platform's front-door session.
const FRONT_DOOR_GUEST_BUFFER: usize = 32;

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

    /// The boot's secrets arrive whole on their descriptor, which is made
    /// close-on-exec before anything reads it; a short or unknown record
    /// fails the broker before it pairs (#3999).
    #[test]
    fn boot_secrets_are_read_whole_from_a_sealed_descriptor() {
        use std::io::Write as _;
        let secrets = BrokerBootSecrets::new([(
            BootSecretPurpose::FrontDoorPairing,
            vec![0x5a; codewire_local_credentials::BOOT_SECRET_BYTES],
        )])
        .unwrap();
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let reader = OwnedFd::from(reader);
        // As inherited: not close-on-exec until the broker seals it.
        rustix::io::fcntl_setfd(&reader, rustix::io::FdFlags::empty()).unwrap();
        writer.write_all(&secrets.records()).unwrap();
        drop(writer);
        assert_eq!(read_boot_secret_descriptor(&reader).unwrap(), secrets);
        assert!(
            rustix::io::fcntl_getfd(&reader)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );

        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.write_all(&secrets.records()[..10]).unwrap();
        drop(writer);
        assert!(read_boot_secret_descriptor(&OwnedFd::from(reader)).is_err());
        assert!(read_boot_secrets(5).is_err());
    }

    /// Only a broker that intercepts but could not pair refuses agent logins;
    /// paired, its logins carry placeholders, and without interception they
    /// are delivered as before.
    #[test]
    fn a_broker_that_intercepts_unpaired_refuses_agent_logins() {
        assert!(refuses_agent_logins(true, false));
        assert!(!refuses_agent_logins(true, true));
        assert!(!refuses_agent_logins(false, false));
    }

    /// A broker that finds this generation's pairing socket gone, its runner
    /// or front door ended, serves without the front door.
    #[tokio::test]
    async fn a_pairing_socket_already_gone_means_no_front_door_session() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("front-door.sock");
        let paired = connect_front_door(&socket, b"capability").await;
        assert!(paired.unwrap().is_none());
    }

    /// The first broker's pairing is bounded: a front door that never
    /// answers fails the broker, and so the boot, rather than hanging it.
    #[tokio::test(start_paused = true)]
    async fn a_front_door_that_never_answers_fails_the_pairing() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("front-door.sock");
        let _silent = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let stream = connect_front_door(&socket, b"capability")
            .await
            .unwrap()
            .unwrap();
        assert!(open_front_door(stream, Uuid::new_v4(), 1).await.is_err());
    }

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

    /// A broker whose runner speaks another protocol says so as it ends,
    /// with both numbers, in words the authority's log keeps whole (#5238);
    /// a runner that never said its protocol has its own word.
    #[test]
    fn the_exit_word_names_a_runner_protocol_mismatch_with_both_numbers() {
        use codewire_local_vmm::runner_service::RunnerServiceError;
        let mismatch = anyhow::Error::new(RunnerServiceError::RunnerProtocolMismatch {
            expected: 14,
            actual: 13,
        })
        .context("connect broker to private runner");
        assert_eq!(
            exit_line("runner.connect", &mismatch),
            format!(
                "{BROKER_EXIT_MARKER} stage=runner.connect kind=runner.protocol_mismatch broker=14 runner=13"
            )
        );
        let silent = anyhow::Error::new(RunnerServiceError::RunnerProtocolInfoUnavailable)
            .context("connect broker to private runner");
        assert_eq!(exit_word(&silent), "runner.no_protocol");
        let other = anyhow::Error::new(BrokerBridgeError::Unavailable).context("bridge");
        assert_eq!(exit_word(&other), exit_kind(&other));
        // No word is long enough for the log to take it for a token.
        for word in [exit_word(&mismatch), exit_word(&silent)] {
            let longest = word
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || "_-".contains(character))
                })
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(longest < 20, "{word}");
        }
    }

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
        let withheld = anyhow::Error::new(
            codewire_local_credentials::BrokerLeaseChannelError::Withheld(
                codewire_access::WithheldReason::Revoked,
            ),
        );
        assert_eq!(exit_kind(&withheld), "lease.withheld");
        assert_eq!(exit_kind(&anyhow::anyhow!("sk-0123456789abcdef")), "other");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lookup_tests {
    use codewire_local_credentials::ProviderLookup;

    use super::*;

    #[derive(clap::Parser)]
    struct Broker {
        #[command(flatten)]
        args: LocalCredentialBrokerArgs,
    }

    /// A broker's arguments as the authority's spawner writes them for
    /// `lookup`.
    fn started_with(lookup: &ProviderLookup) -> LocalCredentialBrokerArgs {
        let mut line: Vec<String> = [
            "broker",
            "--authority-fd=3",
            "--environment-id=environment",
            "--environment-generation=1",
            "--environment-name=name",
            "--runner-socket=/runner.sock",
            "--protected-store=file",
            "--protected-store-directory=/root/protected-v1",
        ]
        .map(str::to_owned)
        .into();
        line.extend(lookup.arguments());
        <Broker as clap::Parser>::try_parse_from(line).unwrap().args
    }

    /// The authority's rule, as the broker it starts reads it (#5286): with
    /// no broker serving, any host may stay unresolved; a replacement may
    /// leave only what the serving broker left, and with nothing left it
    /// must resolve every host, as every broker had to before.
    #[test]
    fn a_broker_may_leave_unresolved_exactly_what_its_authority_allows() {
        let hosts = |hosts: &[&'static str]| hosts.iter().copied().collect::<BTreeSet<_>>();
        let replacing = |left: &[&str]| {
            started_with(&ProviderLookup::NoFewerThan(
                left.iter().map(|host| (*host).to_owned()).collect(),
            ))
        };

        let fresh = started_with(&ProviderLookup::Available);
        assert!(lookup_allows(&fresh, &hosts(&[])));
        assert!(lookup_allows(
            &fresh,
            &hosts(&["api.anthropic.com", "github.com"])
        ));

        let beside = replacing(&["api.anthropic.com"]);
        assert!(lookup_allows(&beside, &hosts(&[])));
        assert!(lookup_allows(&beside, &hosts(&["api.anthropic.com"])));
        assert!(!lookup_allows(&beside, &hosts(&["github.com"])));
        assert!(!lookup_allows(
            &beside,
            &hosts(&["api.anthropic.com", "github.com"])
        ));

        let strict = replacing(&[]);
        assert!(lookup_allows(&strict, &hosts(&[])));
        assert!(!lookup_allows(&strict, &hosts(&["api.anthropic.com"])));

        // An early replacement must get at least one host back.
        let early = started_with(&ProviderLookup::FewerThan(
            ["api.anthropic.com", "github.com"]
                .map(str::to_owned)
                .into(),
        ));
        assert!(lookup_allows(&early, &hosts(&[])));
        assert!(lookup_allows(&early, &hosts(&["github.com"])));
        assert!(!lookup_allows(
            &early,
            &hosts(&["api.anthropic.com", "github.com"])
        ));
        assert!(!lookup_allows(&early, &hosts(&["api.openai.com"])));
    }
}
