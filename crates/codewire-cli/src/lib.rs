pub mod config;
mod console_client;
mod environment_client;
#[cfg(target_os = "linux")]
mod hosted_access;
#[cfg(unix)]
mod hosted_binding;
mod hosted_exec;
mod mesh;
mod organization_client;
mod presentation;
mod secret_client;
mod tailnet_ssh;
mod terminal_attach;
mod update;

pub use hosted_exec::run_hosted_exec_from;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use codewire_client::{
    ApiKey, AuthUser as PlatformUser, CreateApiKeyRequest, OAuthClient, OAuthCredentials,
    OAuthUserInfo,
};
use config::{OsEnv, ResolvePaths};
use console_client::{BillingOverview, ConsoleClient};
use environment_client::{CreateEnvironmentPortRequest, EnvironmentClient, EnvironmentPort};
use mesh::{Invite, MeshClient, Network, Node, NodeEnrollment, RedeemedNodeEnrollment};
use organization_client::{
    CreateInvitationRequest, CreateOrgRequest, CreatePresetRequest, OrgWithRole,
    OrganizationClient, OrganizationDeletionOutcome, OrganizationDeletionStart, Preset,
};
#[cfg(target_os = "linux")]
use presentation::EnvironmentDaemonRepair;
use presentation::{
    CreateEnvironmentRequest, Environment, EnvironmentAccessGrant, EnvironmentDaemonStatus,
    EnvironmentLog, EnvironmentResizeResources, EnvironmentTrustReport, ExtendTtlRequest,
    GrantEnvironmentAccessRequest, PrepareEnvironmentRequest, StatusResponse,
};
use secret_client::{CreateSecretProjectRequest, SecretClient, SecretMetadata, SecretProject};

const CLI_VERSION: &str = match option_env!("CODEWIRE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// Reassert a credential-bearing child's non-dumpable state immediately after
/// `execve`, which resets this flag for an ordinary executable. The selected
/// hidden entrypoint performs its remaining confinement checks.
#[cfg(target_os = "linux")]
pub fn prepare_local_credential_broker_process() -> std::io::Result<()> {
    // SAFETY: this scalar prctl affects only the current broker process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The repository executor gives Git this private symlink to the current cw
/// binary, allowing a shell-free SSH trampoline before normal CLI startup.
#[cfg(target_os = "linux")]
pub fn is_local_git_ssh_helper(program: &std::ffi::OsStr) -> bool {
    std::path::Path::new(program).file_name()
        == Some(std::ffi::OsStr::new(
            codewire_local_credentials::SSH_HELPER_BASENAME,
        ))
}

/// Execute fixed stock SSH under the isolated repository's captured parent,
/// pinned public host trust and selected agent. No normal configuration loads.
#[cfg(target_os = "linux")]
pub fn run_local_git_ssh_helper(arguments: Vec<std::ffi::OsString>) -> std::io::Result<()> {
    commands::run_git_ssh_helper(arguments)
        .map_err(|_| std::io::Error::other("repository SSH failed"))
}
const LOCAL_WORKSPACE_PATH: &str = "/workspace";
const DEFAULT_LOCAL_MESH_URL: &str = "http://127.0.0.1:18090";
const DEFAULT_LOCAL_MESH_LISTEN_ADDR: &str = "127.0.0.1:18090";
const DEFAULT_LOCAL_DERP_URL: &str = "http://127.0.0.1:18091";
const DEFAULT_LOCAL_DERP_LISTEN_ADDR: &str = "127.0.0.1:18091";
const LOCAL_MESH_RUNTIME_FILE: &str = "mesh_runtime.json";
const LOCAL_MESH_OWNER_CONTEXT_FILE: &str = "mesh_owner.json";
const LOCAL_MESH_LOG_FILE: &str = "codewire-mesh.log";
const LOCAL_DERP_LOG_FILE: &str = "codewire-derp.log";

#[derive(Debug, Parser)]
#[command(name = "cw", version = CLI_VERSION, about = "Codewire CLI")]
struct Cli {
    #[arg(short, long, global = true, help = "Platform server URL override")]
    server: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug)]
struct Globals {
    server: Option<String>,
}

mod commands;

use commands::*;

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Inspect Codewire CLI configuration")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    #[command(about = "Generate or install shell completion scripts")]
    Completion(CompletionArgs),
    #[command(
        name = "config-ssh",
        about = "Write OpenSSH config for Codewire environments",
        long_about = "Adds or updates the managed Codewire section in your SSH config so OpenSSH, scp, sftp, rsync, and Remote-SSH can use `cw shell --stdio` as ProxyCommand."
    )]
    ConfigSsh(ConfigSshArgs),
    #[command(about = "Check Codewire CLI and environment setup")]
    Doctor(DoctorArgs),
    #[command(about = "Show how to update cw during the private preview")]
    Update,
    #[command(about = "Sign in to Codewire")]
    Login(LoginArgs),
    #[command(
        about = "Run the Codewire first-time setup wizard",
        long_about = "Connect to a Codewire server, sign in, choose or create a default organization, and optionally configure OpenSSH integration."
    )]
    Setup(SetupArgs),
    #[command(about = "Sign out of Codewire")]
    Logout,
    #[command(about = "Show current user and server")]
    Whoami(WhoamiArgs),
    #[command(about = "Set the current execution target")]
    Use(UseTargetArgs),
    #[command(about = "Show the current execution target")]
    Current(CurrentTargetArgs),
    #[command(
        about = "Write a codewire.yaml project file",
        long_about = "Initialize codewire.yaml from direct environment flags.\n\nExamples:\n  cw init\n  cw init --image workspace --install \"pnpm install\" --startup \"pnpm dev\""
    )]
    Init(InitArgs),
    #[command(
        about = "Open a running environment in VS Code",
        long_about = "Open VS Code connected to a running environment via Remote-SSH. Ensures your SSH config is up to date before launching VS Code with the vscode:// URI scheme."
    )]
    Vscode(VscodeArgs),
    #[command(about = "Open a shell session in the selected or named environment")]
    Shell(EnvironmentShellArgs),
    #[command(about = "Run a durable session in the selected or named environment")]
    Run(EnvironmentRunArgs),
    #[command(about = "Manage environments")]
    Env(EnvArgs),
    #[command(about = "Show usage and billing overview")]
    Cost(CostArgs),
    #[command(alias = "orgs", about = "Manage organizations")]
    Org {
        #[command(subcommand)]
        command: Option<OrgCommand>,
    },
    #[command(alias = "keys", about = "Manage API keys")]
    ApiKeys {
        #[command(subcommand)]
        command: ApiKeyCommand,
    },
    #[command(alias = "presets", about = "Manage environment presets")]
    Preset {
        #[command(subcommand)]
        command: PresetCommand,
    },
    #[command(about = "Manage secrets and secret projects")]
    Secrets(SecretsArgs),
    #[command(about = "Manage protected credentials and access profiles")]
    Credentials(CredentialsArgs),
    #[command(
        alias = "networks",
        about = "Manage Mesh networks for environments and nodes"
    )]
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    #[command(about = "Manage local Codewire Mesh configuration")]
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },
    #[command(name = "__hosted-daemon", hide = true)]
    HostedDaemon,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-supervisor", hide = true)]
    NativeSupervisor(NativeSupervisorArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__native-runner", hide = true)]
    NativeRunner(NativeRunnerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__native-network-worker", hide = true)]
    NativeNetworkWorker(NativeNetworkWorkerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__native-egress-broker", hide = true)]
    NativeEgressBroker(NativeEgressBrokerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__native-mesh-transport", hide = true)]
    NativeMeshTransport(NativeMeshTransportArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__native-mesh-enrollment-broker", hide = true)]
    NativeMeshEnrollmentBroker(NativeMeshEnrollmentBrokerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-credential-authority", hide = true)]
    LocalCredentialAuthority(LocalCredentialAuthorityArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-credential-authority-probe", hide = true)]
    LocalCredentialAuthorityProbe(LocalCredentialAuthorityProbeArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-credential-broker", hide = true)]
    LocalCredentialBroker(LocalCredentialBrokerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__environment-launch", hide = true)]
    EnvironmentLaunch(EnvironmentLaunchArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-credential-broker-confinement-probe", hide = true)]
    LocalCredentialBrokerConfinementProbe,
    #[cfg(target_os = "linux")]
    #[command(name = "__local-git-repository-executor", hide = true)]
    LocalGitRepositoryExecutor(LocalGitRepositoryExecutorArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-git-credential-helper", hide = true)]
    LocalGitCredentialHelper(LocalGitCredentialHelperArgs),
    #[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
    #[command(name = "__local-credential-broker-synthetic-smoke-check", hide = true)]
    LocalCredentialBrokerSyntheticSmokeCheck,
    #[command(about = "List sessions for the selected or explicit environment")]
    List(ListArgs),
    #[command(
        about = "Attach to a session in the selected or explicit environment",
        long_about = "Attach to a durable environment session. A single positional is always an environment. Detach without stopping the session with Ctrl+B d."
    )]
    Attach(AttachArgs),
    #[command(about = "Show saved output for an environment session")]
    Logs(LogsArgs),
}

pub async fn run() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
    require_local_broker_smoke_executable()?;
    let mut args = std::env::args().collect::<Vec<_>>();
    if let Some(program) = args.first_mut() {
        *program = "cw".to_string();
    }
    run_from(args).await
}

/// One-shot launch trampoline. The thin binary calls this before creating an
/// async runtime or loading normal CLI configuration. Errors are deliberately
/// finite: neither command arguments nor child-visible values are diagnostics.
#[cfg(target_os = "linux")]
pub fn run_environment_launcher_from<I, T>(args: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let invalid = || std::io::Error::other("environment launch failed");
    let cli = Cli::try_parse_from(args).map_err(|_| invalid())?;
    let Command::EnvironmentLaunch(args) = cli.command else {
        return Err(invalid());
    };
    if cli.server.is_some() {
        return Err(invalid());
    }
    codewire_daemon::execution::run_environment_launcher(&args.projection_socket, &args.command)
        .map_err(|_| invalid())
}

/// Preserve the fixed private worker failure taxonomy across the thin binary
/// wrapper. Ordinary CLI failures continue to use the generic exit status.
#[cfg(target_os = "linux")]
pub fn native_network_worker_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::network_worker::NetworkWorkerError>()
        .map(codewire_local_vmm::network_worker::NetworkWorkerError::exit_code)
}

/// Preserve the fixed private broker failure taxonomy across the thin binary
/// wrapper without printing process-internal detail to ambient stderr.
#[cfg(target_os = "linux")]
pub fn native_egress_broker_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::egress_broker::EgressBrokerProcessError>()
        .map(codewire_local_vmm::egress_broker::EgressBrokerProcessError::exit_code)
}

/// Preserve the fixed private Mesh-process failure taxonomy without printing
/// credential-adjacent process detail to ambient stderr.
#[cfg(target_os = "linux")]
pub fn native_mesh_transport_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::mesh_process::MeshTransportProcessError>()
        .map(codewire_local_vmm::mesh_process::MeshTransportProcessError::exit_code)
}

/// Preserve the fixed one-shot enrollment-issuer failure taxonomy without
/// exposing credential-adjacent detail on ambient stderr.
#[cfg(target_os = "linux")]
pub fn native_mesh_enrollment_broker_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::mesh_enrollment::MeshEnrollmentProcessError>()
        .map(codewire_local_vmm::mesh_enrollment::MeshEnrollmentProcessError::exit_code)
}

#[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
fn require_local_broker_smoke_executable() -> anyhow::Result<()> {
    let executable =
        std::env::current_exe().context("resolve synthetic broker smoke executable")?;
    anyhow::ensure!(
        executable.file_name().and_then(std::ffi::OsStr::to_str)
            == Some("cw-local-credential-broker-smoke"),
        "synthetic local credential broker build must be named cw-local-credential-broker-smoke"
    );
    Ok(())
}

pub async fn run_from<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    let globals = Globals {
        server: cli.server.clone(),
    };
    match cli.command {
        Command::Config {
            command: ConfigCommand::Inspect { output },
        } => inspect_config(output),
        Command::Completion(args) => handle_completion_command(args),
        Command::ConfigSsh(args) => handle_config_ssh_command(args),
        Command::Doctor(args) => handle_doctor_command(&globals, args).await,
        Command::Update => update::run_current().await,
        Command::Login(args) => handle_login_command(&globals, args).await,
        Command::Setup(args) => handle_setup_command(&globals, args).await,
        Command::Logout => handle_logout_command(&globals).await,
        Command::Whoami(args) => handle_whoami_command(&globals, args).await,
        Command::Use(args) => handle_use_command(&globals, args).await,
        Command::Current(args) => handle_current_command(&globals, args).await,
        Command::Init(args) => handle_init_command(&globals, args).await,
        Command::Vscode(args) => handle_vscode_command(&globals, args).await,
        Command::Shell(args) => handle_environment_shell_command(&globals, args).await,
        Command::Run(args) => handle_environment_run_command(&globals, args).await,
        Command::Env(args) => handle_env_command(&globals, args).await,
        Command::Cost(args) => handle_cost_command(&globals, args).await,
        Command::Org { command } => handle_org_command(&globals, command).await,
        Command::ApiKeys { command } => handle_api_keys_command(&globals, command).await,
        Command::Preset { command } => handle_preset_command(&globals, command).await,
        Command::Secrets(args) => handle_secrets_command(&globals, args).await,
        Command::Credentials(args) => handle_credentials_command(&globals, args).await,
        Command::Network { command } => handle_network_command(&globals, command).await,
        Command::Mesh { command } => handle_mesh_command(&globals, command).await,
        Command::HostedDaemon => run_hosted_daemon().await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeSupervisor(args) => run_native_supervisor(args).await,
        #[cfg(target_os = "linux")]
        Command::NativeRunner(args) => run_native_runner(args).await,
        #[cfg(target_os = "linux")]
        Command::NativeNetworkWorker(args) => run_native_network_worker(args).await,
        #[cfg(target_os = "linux")]
        Command::NativeEgressBroker(args) => run_native_egress_broker(args).await,
        #[cfg(target_os = "linux")]
        Command::NativeMeshTransport(args) => run_native_mesh_transport(args).await,
        #[cfg(target_os = "linux")]
        Command::NativeMeshEnrollmentBroker(args) => run_native_mesh_enrollment_broker(args).await,
        #[cfg(target_os = "linux")]
        Command::LocalCredentialAuthority(args) => run_local_credential_authority(args).await,
        #[cfg(target_os = "linux")]
        Command::LocalCredentialAuthorityProbe(args) => {
            run_local_credential_authority_probe(args).await
        }
        #[cfg(target_os = "linux")]
        Command::LocalCredentialBroker(args) => run_local_credential_broker(args).await,
        #[cfg(target_os = "linux")]
        Command::EnvironmentLaunch(args) => codewire_daemon::execution::run_environment_launcher(
            &args.projection_socket,
            &args.command,
        )
        .map_err(|_| anyhow::anyhow!("environment launch failed")),
        #[cfg(target_os = "linux")]
        Command::LocalCredentialBrokerConfinementProbe => {
            run_local_credential_broker_confinement_probe().await
        }
        #[cfg(target_os = "linux")]
        Command::LocalGitRepositoryExecutor(args) => run_local_git_repository_executor(args).await,
        #[cfg(target_os = "linux")]
        Command::LocalGitCredentialHelper(args) => run_local_git_credential_helper(args),
        #[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
        Command::LocalCredentialBrokerSyntheticSmokeCheck => {
            println!("codewire-local-credential-broker-synthetic-smoke:v1");
            Ok(())
        }
        Command::List(args) => handle_list_command(&globals, args).await,
        Command::Attach(args) => handle_attach_command(&globals, args).await,
        Command::Logs(args) => handle_logs_command(&globals, args).await,
    }
}

async fn run_hosted_daemon() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
    match codewire_daemon::HostedDaemonMode::from_env()? {
        codewire_daemon::HostedDaemonMode::EnvironmentToken(config) => {
            serve_hosted_daemon(*config, false, None).await
        }
        codewire_daemon::HostedDaemonMode::Binding(config) => run_bound_hosted_daemon(config).await,
    }
}

/// Identity-free Pod (Program #2238 B2): mark local readiness, bind, install
/// the bound credential, then prepare Codex's home and listen. Nothing listens
/// before an accepted binding.
#[cfg(unix)]
async fn run_bound_hosted_daemon(
    config: codewire_daemon::WorkspaceBindingConfig,
) -> anyhow::Result<()> {
    let paths = codewire_daemon::hosted_state::HostedStatePaths::default();
    paths
        .mark_ready()
        .context("write hosted daemon readiness marker")?;
    tracing::info!("hosted environment daemon waiting for its workspace binding");
    let client = std::sync::Arc::new(
        hosted_binding::BindingClient::new(
            config.binding_url(),
            config.tls_roots_file(),
            config.token_path(),
            hosted_binding::BindTiming::default(),
        )
        .context("configure workspace binding client")?,
    );
    let bound = hosted_binding::bind_until_accepted(&client, &config).await;
    paths
        .install_binding(&bound.binding)
        .context("install hosted daemon binding")?;
    // Workspace access (#2460): the daemon serves SSH itself, reaching its
    // own gRPC service in-process.
    let (connector, local) = codewire_daemon::local_transport::local_transport();
    #[cfg(target_os = "linux")]
    {
        let (_access_shutdown, access_shutdown_rx) = tokio::sync::watch::channel(false);
        let access = hosted_access::serve(
            paths.clone(),
            hosted_access::BoundAccess {
                environment_id: bound.binding.environment_id(),
                generation: bound.binding.operation_generation(),
                daemon_credential: bound.binding.daemon_credential().clone(),
                grant: bound.access.clone(),
            },
            connector,
            client.clone(),
            access_shutdown_rx,
        );
        tokio::spawn(async move {
            // The sender lives as long as the access task, which ends with
            // the daemon process.
            let _keep = _access_shutdown;
            if let Err(error) = access.await {
                tracing::error!(error = %format!("{error:#}"), "workspace access stopped");
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    drop(connector);
    serve_hosted_daemon(config.into_config(&bound.binding), true, Some(local)).await
}

#[cfg(not(unix))]
async fn run_bound_hosted_daemon(
    _config: codewire_daemon::WorkspaceBindingConfig,
) -> anyhow::Result<()> {
    anyhow::bail!("workspace binding requires a Unix hosted daemon")
}

async fn serve_hosted_daemon(
    config: codewire_daemon::Config,
    bound: bool,
    local: Option<codewire_daemon::local_transport::LocalDaemonIncoming>,
) -> anyhow::Result<()> {
    use tokio_stream::wrappers::TcpListenerStream;

    config
        .prepare_native_launch_directory()
        .context("prepare hosted launch process directory")?;
    // Both identity modes: the daemon is the one writer of Codewire's
    // `~/.codex/config.toml`, before it listens, from the served clients.
    #[cfg(unix)]
    codewire_daemon::codex_home::CodexHome::default().prepare(config.managed_credential_clients);
    // Claude Code runs its first-run onboarding, including a login picker,
    // unless `~/.claude.json` records it complete, and asks whether you trust
    // each folder; while the Anthropic client is selected the daemon marks
    // onboarding complete and the workspace root trusted, so Claude Code uses
    // the managed credential at once in any checked-out repository. A
    // selection change restarts the Sandbox.
    #[cfg(target_os = "linux")]
    codewire_daemon::claude_home::ClaudeHome::new(&config.home_root, &config.workspace_root)
        .prepare(config.managed_credential_clients);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("listen hosted daemon {}", config.listen_addr))?;
    let local_addr = listener
        .local_addr()
        .context("read hosted daemon listener address")?;
    tracing::info!(daemon_listen_addr = %local_addr, bound, "hosted environment daemon listening");
    // An environment-token Pod also writes the marker once it listens, so one
    // readiness probe shape serves both modes. It is advisory there.
    #[cfg(unix)]
    if !bound
        && let Err(error) = codewire_daemon::hosted_state::HostedStatePaths::default().mark_ready()
    {
        tracing::warn!(error = %error, "hosted daemon readiness marker unavailable");
    }
    // One server, one session engine: the network listener and, for a bound
    // daemon, its own in-process workspace access connections.
    let local = local.unwrap_or_else(|| codewire_daemon::local_transport::local_transport().1);
    let incoming = codewire_daemon::local_transport::with_local_connections(
        TcpListenerStream::new(listener),
        local,
    );
    // Once listening, the hosted daemon also keeps Codex's own ChatGPT login
    // while the broker delivers one, in the same home.
    #[cfg(target_os = "linux")]
    return codewire_daemon::serve_hosted_grpc_with_incoming(
        config,
        codewire_daemon::codex_home::CodexHome::default(),
        incoming,
        hosted_daemon_shutdown_signal(),
    )
    .await;
    #[cfg(not(target_os = "linux"))]
    codewire_daemon::serve_grpc_with_incoming(config, incoming, hosted_daemon_shutdown_signal())
        .await
}

async fn hosted_daemon_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    tokio::time::sleep(Duration::from_millis(10)).await;
}
