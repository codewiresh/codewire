//! Command handler/module map for the Wave 4 CLI client flips.
//!
//! - `core`: hook, gateway, target selection, init, VS Code, shell, and CLI utilities.
//! - `environment`: environment lifecycle, files, access, ports, logs, and list views.
//! - `native`: Codewire-owned native local environment lifecycle and public clients.
//! - `platform_commands`: doctor, billing, login/setup, GitHub, organizations, API keys,
//!   presets, and secrets.
//! - `mesh_commands`: network, node, and local Mesh management.
//! - `sessions`: local and remote session lifecycle, output, and messaging.
//! - `collaboration`: remote access grants and Mesh groups.
//!
//! WS10 WI-2 through WI-7 change these handler families in place; the former
//! `lib.rs` line positions are historical anchors only.

use super::*;

#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
pub(crate) use native::*;
#[cfg(target_os = "linux")]
mod credential_authority;
#[cfg(target_os = "linux")]
pub(crate) use credential_authority::*;
#[cfg(target_os = "linux")]
mod credential_broker;
#[cfg(target_os = "linux")]
pub(crate) use credential_broker::*;
#[cfg(target_os = "linux")]
mod credential_broker_confinement;
#[cfg(target_os = "linux")]
pub(crate) use credential_broker_confinement::run_local_credential_broker_confinement_probe;
#[cfg(target_os = "linux")]
mod credential_repository;
#[cfg(target_os = "linux")]
pub(crate) use credential_repository::*;
#[cfg(target_os = "linux")]
mod credentials;
#[cfg(target_os = "linux")]
pub(crate) use credentials::*;

#[derive(Debug, Args)]
pub(crate) struct CompletionArgs {
    #[arg(value_enum, value_name = "SHELL")]
    shell: Option<CompletionShell>,
    #[arg(long, help = "Install completion for the current shell automatically")]
    install: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigSshArgs {
    #[arg(long, value_name = "PATH", help = "Path to the SSH config file")]
    ssh_config_file: Option<PathBuf>,
    #[arg(
        short = 'o',
        long = "ssh-option",
        help = "Additional SSH option to add to the managed Codewire host block"
    )]
    ssh_options: Vec<String>,
    #[arg(
        short = 'n',
        long,
        help = "Print the resulting SSH config instead of writing it"
    )]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
    #[command(subcommand)]
    command: Option<DoctorCommand>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DoctorCommand {
    #[cfg(target_os = "linux")]
    #[command(about = "Inspect native local VM orphans without mutating them")]
    Local(DoctorLocalArgs),
    #[command(about = "Probe environment tailnet transport paths")]
    Tailnet(DoctorTailnetArgs),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct DoctorLocalArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorTailnetArgs {
    #[arg(value_name = "ENV")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
    #[arg(
        long,
        default_value = "15s",
        help = "How long to wait for direct UDP before reporting fallback"
    )]
    direct_wait: String,
    #[arg(
        long,
        default_value = "10s",
        help = "How long to wait for coordinator peer and DERP readiness"
    )]
    peer_timeout: String,
    #[arg(
        long,
        default_value = "any",
        help = "Required transport (any|direct_udp|udp_relay|derp)"
    )]
    expect: String,
    #[arg(long, help = "Skip the forced DERP fallback probe")]
    skip_forced_derp: bool,
}

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    #[arg(long, value_name = "ID_OR_SLUG", help = "Default organization to save")]
    org: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SetupArgs {
    #[arg(long, value_name = "ID_OR_SLUG", help = "Default organization to save")]
    org: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Create this organization when selecting the default org"
    )]
    create_org: Option<String>,
    #[arg(
        long,
        value_name = "SLUG",
        requires = "create_org",
        help = "Slug for --create-org"
    )]
    org_slug: Option<String>,
    #[arg(long, help = "Connect GitHub during setup")]
    github: bool,
    #[arg(long, help = "Skip GitHub connection prompts")]
    skip_github: bool,
    #[arg(long, help = "Skip OpenSSH config update")]
    skip_ssh: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

#[derive(Debug, Args)]
pub(crate) struct WhoamiArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct UseTargetArgs {
    #[arg(
        long,
        conflicts_with = "platform",
        help = "Select a local environment explicitly"
    )]
    pub(crate) local: bool,
    #[arg(
        long,
        conflicts_with = "local",
        help = "Select a platform environment explicitly"
    )]
    pub(crate) platform: bool,
    #[arg(value_name = "TARGET")]
    pub(crate) target: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvironmentPlacement {
    Local,
    Platform,
}

#[derive(Debug, Args)]
pub(crate) struct EnvArgs {
    #[arg(
        long,
        global = true,
        conflicts_with = "platform",
        help = "Operate on local environments only"
    )]
    pub(crate) local: bool,
    #[arg(
        long,
        global = true,
        conflicts_with = "local",
        help = "Operate on current-organization platform environments only"
    )]
    pub(crate) platform: bool,
    #[command(subcommand)]
    pub(crate) command: EnvCommand,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeSupervisorArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_lock: PathBuf,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
    #[arg(long)]
    pub(crate) credential_authority_root: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeRunnerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) socket: PathBuf,
    #[arg(long)]
    pub(crate) engine_state_root: PathBuf,
    #[arg(long)]
    pub(crate) artifact_generation: String,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeNetworkWorkerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeEgressBrokerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeMeshTransportArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct NativeMeshEnrollmentBrokerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
    #[arg(long)]
    pub(crate) mesh_data_dir: PathBuf,
    #[arg(long)]
    pub(crate) platform_config_dir: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct LocalCredentialAuthorityArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct LocalCredentialAuthorityProbeArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    #[arg(long)]
    pub(crate) shutdown: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
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
    pub(crate) supervisor_socket: PathBuf,
    #[arg(long)]
    pub(crate) credential_authentication_kind: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct LocalGitRepositoryExecutorArgs {
    #[arg(long)]
    pub(crate) authority_fd: i32,
    #[arg(long)]
    pub(crate) request_id: String,
    #[arg(long)]
    pub(crate) staging_directory: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct LocalGitCredentialHelperArgs {
    #[arg(long)]
    pub(crate) credential_socket: PathBuf,
    pub(crate) operation: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialsArgs {
    #[arg(long, conflicts_with = "platform")]
    pub(crate) local: bool,
    #[arg(long, conflicts_with = "local")]
    pub(crate) platform: bool,
    #[command(subcommand)]
    pub(crate) command: CredentialsCommand,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
pub(crate) enum CredentialsCommand {
    #[command(about = "Connect an explicitly selected provider identity")]
    Connect(CredentialConnectArgs),
    #[command(about = "Add an explicitly supplied credential")]
    Add(CredentialAddArgs),
    #[command(about = "List credential metadata")]
    List(CredentialListArgs),
    #[command(about = "Show credential metadata")]
    Get(CredentialSelectorArgs),
    #[command(about = "Rename a credential")]
    Rename(CredentialRenameArgs),
    #[command(about = "Replace credential material")]
    Rotate(CredentialRotateArgs),
    #[command(about = "Revoke a credential immediately")]
    Revoke(CredentialSelectorArgs),
    #[command(alias = "rm", about = "Delete a credential")]
    Delete(CredentialDeleteArgs),
    #[command(about = "Manage access profiles")]
    Profile {
        #[command(subcommand)]
        command: CredentialProfileCommand,
    },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialConnectArgs {
    #[arg(value_enum, value_name = "PROVIDER")]
    pub(crate) provider: CredentialConnectProviderArg,
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CredentialConnectProviderArg {
    Codex,
    Github,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CredentialAuthenticationKindArg {
    Oauth,
    ApiKey,
    AccessToken,
    GithubApp,
    SshPrivateKey,
    SshAgent,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialAddArgs {
    #[arg(value_name = "PROVIDER")]
    pub(crate) provider: String,
    #[arg(long, value_enum, value_name = "KIND")]
    pub(crate) kind: CredentialAuthenticationKindArg,
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
    #[arg(long, value_name = "HINT")]
    pub(crate) account_hint: Option<String>,
    #[arg(long, value_name = "UNIX_SECONDS")]
    pub(crate) expires_at: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialSelectorArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) credential: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialRenameArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) credential: String,
    #[arg(value_name = "NEW_NAME")]
    pub(crate) name: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialRotateArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) credential: String,
    #[arg(long, value_name = "UNIX_SECONDS")]
    pub(crate) expires_at: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialDeleteArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) credential: String,
    #[arg(long)]
    pub(crate) yes: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
pub(crate) enum CredentialProfileCommand {
    #[command(about = "Create an empty access profile")]
    Create(CredentialProfileNameArgs),
    #[command(about = "List access profiles")]
    List(CredentialListArgs),
    #[command(about = "Show an access profile")]
    Get(CredentialProfileSelectorArgs),
    #[command(about = "Select a credential for one capability slot")]
    Set(CredentialProfileSetArgs),
    #[command(about = "Remove one capability slot from a profile")]
    Unset(CredentialProfileSlotArgs),
    #[command(about = "List immutable profile revisions")]
    Revisions(CredentialProfileSelectorArgs),
    #[command(alias = "rm", about = "Delete an access profile")]
    Delete(CredentialProfileDeleteArgs),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialProfileNameArgs {
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSelectorArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) profile: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSetArgs {
    #[arg(value_name = "PROFILE")]
    pub(crate) profile: String,
    #[arg(value_name = "SLOT")]
    pub(crate) slot: String,
    #[arg(value_name = "CREDENTIAL")]
    pub(crate) credential: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSlotArgs {
    #[arg(value_name = "PROFILE")]
    pub(crate) profile: String,
    #[arg(value_name = "SLOT")]
    pub(crate) slot: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct CredentialProfileDeleteArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) profile: String,
    #[arg(long)]
    pub(crate) yes: bool,
}

impl EnvArgs {
    pub(crate) fn placement(&self) -> Option<EnvironmentPlacement> {
        if self.local {
            Some(EnvironmentPlacement::Local)
        } else if self.platform {
            Some(EnvironmentPlacement::Platform)
        } else {
            None
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct CurrentTargetArgs {
    #[arg(short, long, help = "Show full target details")]
    verbose: bool,
}

#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    #[arg(value_name = "REPO_URL")]
    repo_urls: Vec<String>,
    #[arg(long = "preset", help = "Preset slug (e.g. go, node, python)")]
    preset_slug: Option<String>,
    #[arg(long = "preset-id", help = "Preset ID (exact)")]
    preset_id: Option<String>,
    #[arg(long, help = "Environment name hint for server-side resolution")]
    name: Option<String>,
    #[arg(
        long,
        help = "Time to live for server-side resolution or saved presets"
    )]
    ttl: Option<String>,
    #[arg(long, help = "CPU in millicores")]
    cpu: Option<i32>,
    #[arg(long, help = "Memory in MB")]
    memory: Option<i32>,
    #[arg(long, help = "Disk in GB")]
    disk: Option<i32>,
    #[arg(long, value_parser = ["standard", "confidential"], help = "Product isolation tier")]
    isolation: Option<String>,
    #[arg(
        long = "repo",
        help = "Git repo (repeatable, URL[@branch][::/workspace/path])"
    )]
    repo_flags: Vec<String>,
    #[arg(long, help = "Branch to checkout")]
    branch: Option<String>,
    #[arg(
        long,
        help = "Container image (shorthand: workspace -> ghcr.io/codewiresh/workspace)"
    )]
    image: Option<String>,
    #[arg(long, help = "Install command")]
    install: Option<String>,
    #[arg(long, help = "Startup script")]
    startup: Option<String>,
    #[arg(
        long = "coding-agent",
        help = "Coding agent (claude-code, codex, gemini-cli, aider)"
    )]
    coding_agent: Option<String>,
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    #[arg(long = "secrets", help = "Secret project to bind")]
    secret_project: Option<String>,
    #[arg(long, help = "Do not inject org-level secrets")]
    no_org_secrets: bool,
    #[arg(long, help = "Do not inject user-level secrets")]
    no_user_secrets: bool,
    #[arg(long, default_value = "codewire.yaml", help = "Path to write")]
    file: PathBuf,
    #[arg(long, help = "Overwrite the target file if it exists")]
    force: bool,
    #[arg(long = "save-preset", help = "Save the resolved preset to the server")]
    save_preset: Option<String>,
    #[arg(short, long, help = "Skip confirmation prompts")]
    yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct VscodeArgs {
    #[arg(value_name = "ENV")]
    environment: Option<String>,
    #[arg(long, default_value = "/workspace", help = "Remote folder to open")]
    folder: String,
    #[arg(long, help = "Organization ID or slug")]
    org: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentShellArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: Option<String>,
    #[arg(long, help = "Pipe stdin/stdout for OpenSSH ProxyCommand")]
    stdio: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentRunArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: Option<String>,
    #[arg(short = 'w', long = "workdir", alias = "dir", value_name = "DIR")]
    pub(crate) workdir: Option<String>,
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    #[arg(
        short = 't',
        long,
        conflicts_with = "no_tty",
        help = "Allocate a terminal for this session"
    )]
    pub(crate) tty: bool,
    #[arg(long, conflicts_with = "tty", help = "Do not allocate a terminal")]
    pub(crate) no_tty: bool,
    #[arg(short = 'd', long, help = "Launch the session without attaching")]
    pub(crate) detach: bool,
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvCommand {
    #[command(
        about = "Create a new environment",
        long_about = "Create a new environment from direct CLI flags.\n\nMultiple repos can be specified as positional args or with --repo flags.\nUse URL[@branch][::/workspace/path] to set a branch and optional checkout path per repo."
    )]
    Create(Box<EnvCreateArgs>),
    #[command(about = "List environments")]
    List(EnvListArgs),
    #[command(about = "Show environment details")]
    Info(EnvInfoArgs),
    #[command(about = "Resize a local or platform environment")]
    Resize(EnvResizeArgs),
    #[command(
        name = "report",
        about = "Show isolation, runtime, and trust evidence for an environment"
    )]
    Report(EnvReportArgs),
    #[command(about = "Stop an environment")]
    Stop(EnvTargetArgs),
    #[command(about = "Start an environment")]
    Start(EnvTargetArgs),
    #[command(about = "Restart a native local environment")]
    Restart(EnvTargetArgs),
    #[command(
        name = "refresh-skills",
        about = "Refresh immutable skills for a native local environment"
    )]
    RefreshSkills(EnvTargetArgs),
    #[command(about = "Delete an environment")]
    Rm(EnvDeleteArgs),
    #[command(
        about = "Bulk delete stale environments",
        long_about = "Delete environments stuck in error, creating, or pending states."
    )]
    Prune(EnvPruneArgs),
    #[command(
        about = "Delete ALL environments",
        long_about = "Delete every environment in the current org. Requires typed confirmation unless --yes is passed."
    )]
    Nuke(EnvNukeArgs),
    #[command(
        about = "Copy files to or from an environment",
        long_about = "Copy files between the local filesystem and a sandbox environment.\n\nUse <env_id>:<path> syntax for remote paths:\n  cw env cp local.txt <env_id>:/workspace/local.txt\n  cw env cp <env_id>:/workspace/file.txt ./file.txt"
    )]
    Cp(EnvCpArgs),
    #[command(about = "Protect an environment from deletion")]
    Protect(EnvTargetArgs),
    #[command(about = "Remove deletion protection from an environment")]
    Unprotect(EnvTargetArgs),
    #[command(
        name = "cancel-delete",
        about = "Cancel a pending environment deletion"
    )]
    CancelDelete(EnvTargetArgs),
    #[command(about = "Extend the TTL of an environment")]
    Extend(EnvExtendArgs),
    #[command(about = "Manage environment access")]
    Access(EnvAccessArgs),
    #[command(about = "Manage environment ports")]
    Port(EnvPortArgs),
    #[command(about = "Show environment setup logs")]
    Logs(EnvLogsArgs),
    #[command(about = "Inspect or repair the managed environment daemon")]
    Daemon(EnvDaemonArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvCreateArgs {
    #[arg(value_name = "REPO_URL")]
    repo_urls: Vec<String>,
    #[arg(long = "preset", help = "Preset slug (e.g. go, node, python)")]
    preset_slug: Option<String>,
    #[arg(long = "preset-id", help = "Preset ID (exact)")]
    preset_id: Option<String>,
    #[arg(long, help = "Environment name")]
    name: Option<String>,
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = ["native", "cloud-hypervisor"],
        help = "Local runtime backend (native by default); requires --local"
    )]
    backend: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Local project directory; used with --local"
    )]
    path: Option<PathBuf>,
    #[arg(
        long = "path-mode",
        value_enum,
        value_name = "MODE",
        help = "Prepare the implicit --path source as auto, clone, or copy; requires --local"
    )]
    path_mode: Option<PathModeArg>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Local preset file, relative to --path; used with --local"
    )]
    file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "SPEC",
        help = "Local JSON spec file or '-' for stdin; requires --local"
    )]
    spec: Option<String>,
    #[arg(long, help = "Time to live (e.g. 1h, 30m)")]
    ttl: Option<String>,
    #[arg(long, value_name = "QUANTITY", help = "CPU resource quantity")]
    cpu: Option<String>,
    #[arg(long, value_name = "QUANTITY", help = "Memory (for example 8GB)")]
    memory: Option<String>,
    #[arg(long, value_name = "QUANTITY", help = "Disk size (for example 40GB)")]
    disk: Option<String>,
    #[arg(
        long,
        value_name = "QUANTITY",
        conflicts_with = "no_docker",
        help = "Dedicated guest Docker data disk (default 8Gi); requires the native local backend"
    )]
    docker_disk: Option<String>,
    #[arg(
        long,
        conflicts_with = "docker_disk",
        help = "Disable the guest-local Docker daemon; requires the native local backend"
    )]
    no_docker: bool,
    #[arg(long, value_parser = ["standard", "confidential"], help = "Product isolation tier")]
    isolation: Option<String>,
    #[arg(
        long = "repo",
        help = "Git repo (repeatable, URL[@branch][::/workspace/path])"
    )]
    repo_flags: Vec<String>,
    #[arg(long, help = "Branch to checkout")]
    branch: Option<String>,
    #[arg(
        long,
        help = "Container image (shorthand: workspace -> ghcr.io/codewiresh/workspace)"
    )]
    image: Option<String>,
    #[arg(long, help = "Install command")]
    install: Option<String>,
    #[arg(long, help = "Startup script")]
    startup: Option<String>,
    #[arg(
        long = "coding-agent",
        help = "Coding agent (claude-code, codex, gemini-cli, aider)"
    )]
    coding_agent: Option<String>,
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    #[arg(long = "secrets", help = "Secret project to bind")]
    secret_project: Option<String>,
    #[arg(
        long,
        value_name = "SCOPE/NAME",
        help = "Local access profile, for example user/work"
    )]
    access_profile: Option<String>,
    #[arg(long, help = "Do not inject org-level secrets")]
    no_org_secrets: bool,
    #[arg(long, help = "Do not inject user-level secrets")]
    no_user_secrets: bool,
    #[arg(long, help = "Join a specific mesh network on boot")]
    network: Option<String>,
    #[arg(long, help = "Do not join the selected private mesh network")]
    no_network: bool,
    #[arg(short, long, default_value_t = true, help = "Watch startup progress")]
    follow: bool,
    #[arg(
        long,
        help = "Return immediately after creation instead of waiting for startup"
    )]
    no_wait: bool,
    #[arg(short, long, help = "Skip confirmation prompts")]
    yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
    #[arg(
        long,
        help = "Write the resolved preset to ./codewire.yaml after creation"
    )]
    write_preset: bool,
    #[arg(long = "save-preset", help = "Save the resolved preset to the server")]
    save_preset: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PathModeArg {
    Auto,
    Clone,
    Copy,
}

#[derive(Debug, Args)]
pub(crate) struct EnvListArgs {
    #[arg(long = "type", help = "Filter by type, for example sandbox")]
    environment_type: Option<String>,
    #[arg(long, help = "Filter by state")]
    state: Option<String>,
    #[arg(short, long, help = "Include destroyed environments")]
    all: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvInfoArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvResizeArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: String,
    #[arg(long, value_name = "CPU", help = "CPU (for example 500m, 0.5, or 4)")]
    pub(crate) cpu: Option<String>,
    #[arg(
        long,
        value_name = "MEMORY",
        help = "Memory (for example 512MB or 8GB)"
    )]
    pub(crate) memory: Option<String>,
    #[arg(long, value_name = "DISK", help = "Disk size (for example 40GB)")]
    pub(crate) disk: Option<String>,
    #[arg(
        long,
        help = "Terminate active platform sessions before the required restart"
    )]
    pub(crate) force: bool,
    #[arg(
        long,
        help = "Allow workspace Pod replacement when Kubernetes cannot apply the resize live"
    )]
    pub(crate) allow_restart: bool,
    #[arg(
        short,
        long,
        help = "Apply a validated resize without the default-no prompt"
    )]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvReportArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvTargetArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvDeleteArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(short, long, help = "Skip confirmation prompt")]
    yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvPruneArgs {
    #[arg(short, long, help = "Skip confirmation prompt")]
    yes: bool,
    #[arg(
        long,
        default_value = "error,creating,pending",
        help = "Comma-separated states to prune"
    )]
    state: String,
    #[arg(long, help = "Show what would be pruned without deleting")]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvNukeArgs {
    #[arg(short, long, help = "Skip typed confirmation")]
    yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvCpArgs {
    #[arg(value_name = "SRC")]
    src: String,
    #[arg(value_name = "DST")]
    dst: String,
}

#[derive(Debug, Args)]
pub(crate) struct EnvExtendArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, default_value_t = 1, help = "Hours to extend TTL by")]
    hours: i32,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct EnvAccessArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
    #[command(subcommand)]
    command: Option<EnvAccessCommand>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvAccessCommand {
    #[command(about = "Apply an access-profile revision to an environment")]
    Apply(EnvAccessApplyArgs),
    #[command(about = "List access grants for an environment")]
    List(EnvAccessTargetArgs),
    #[command(about = "Grant a user access to an environment")]
    Grant(EnvAccessGrantArgs),
    #[command(about = "Revoke a user's access to an environment")]
    Revoke(EnvAccessRevokeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvAccessApplyArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(
        long,
        value_name = "SCOPE/NAME",
        required_unless_present = "clear",
        conflicts_with = "clear",
        help = "Access profile to bind, for example user/work"
    )]
    profile: Option<String>,
    #[arg(
        long,
        required_unless_present = "profile",
        conflicts_with = "profile",
        help = "Remove the environment access profile"
    )]
    clear: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvAccessTargetArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvAccessGrantArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, required = true, help = "User ID to grant access to")]
    user: String,
    #[arg(
        long,
        default_value = "viewer",
        help = "Permission level: owner, operator, or viewer"
    )]
    permission: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvAccessRevokeArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, required = true, help = "User ID to revoke access from")]
    user: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvPortArgs {
    #[command(subcommand)]
    command: EnvPortCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvPortCommand {
    #[command(about = "Register a port and get a preview URL")]
    Add(EnvPortAddArgs),
    #[command(alias = "ls", about = "List registered ports")]
    List(EnvPortListArgs),
    #[command(about = "Remove a registered port")]
    Rm(EnvPortRmArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvPortAddArgs {
    #[arg(value_name = "PORT")]
    port: String,
    #[arg(
        short,
        long,
        required = true,
        help = "DNS-safe label for the preview URL"
    )]
    label: String,
    #[arg(
        short,
        long,
        default_value = "creator",
        help = "Access level: public, org_members, or creator"
    )]
    access: String,
    #[arg(short, long, help = "Environment ID or name (default: current)")]
    env: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvPortListArgs {
    #[arg(short, long, help = "Environment ID or name (default: current)")]
    env: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvPortRmArgs {
    #[arg(value_name = "PORT_NUMBER_OR_LABEL")]
    port: String,
    #[arg(short, long, help = "Environment ID or name (default: current)")]
    env: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvLogsArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(
        short,
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        help = "Follow live logs"
    )]
    follow: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvDaemonArgs {
    #[command(subcommand)]
    command: EnvDaemonCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvDaemonCommand {
    #[command(about = "Show daemon version, capabilities, health, and diagnostics")]
    Status(EnvDaemonTargetArgs),
    #[command(about = "Show recent managed daemon logs")]
    Logs(EnvDaemonLogsArgs),
    #[command(about = "Reconcile the managed daemon without recreating the environment")]
    Repair(EnvDaemonTargetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvDaemonTargetArgs {
    #[arg(value_name = "ENV")]
    environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvDaemonLogsArgs {
    #[arg(value_name = "ENV")]
    environment: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LocalFilesUploadArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(value_name = "REMOTE_PATH")]
    remote_path: String,
}

#[derive(Debug, Args)]
pub(crate) struct LocalFilesPathArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(value_name = "REMOTE_PATH")]
    remote_path: String,
}

#[derive(Debug, Args)]
pub(crate) struct LocalFilesListArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(value_name = "REMOTE_PATH")]
    remote_path: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CostArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
    #[arg(long, help = "Filter to a specific organization (slug or ID)")]
    org: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GithubCommand {
    #[command(about = "Connect GitHub account via device flow")]
    Login,
    #[command(about = "Disconnect GitHub account")]
    Logout,
    #[command(about = "Show GitHub connection status")]
    Status,
}

#[derive(Debug, Subcommand)]
pub(crate) enum OrgCommand {
    #[command(about = "List organizations")]
    List(OrgListArgs),
    #[command(about = "Show the current organization")]
    Current,
    #[command(about = "Set the current organization")]
    Set(OrgSetArgs),
    #[command(about = "Create a new organization")]
    Create(OrgCreateArgs),
    #[command(about = "Delete an organization")]
    Delete(OrgDeleteArgs),
    #[command(about = "Invite a member to an organization")]
    Invite(OrgInviteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct OrgListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct OrgSetArgs {
    #[arg(value_name = "ID_OR_SLUG")]
    id_or_slug: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OrgCreateArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long, help = "URL-safe slug (default: auto-generated from name)")]
    slug: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OrgDeleteArgs {
    #[arg(value_name = "ID_OR_SLUG")]
    id_or_slug: String,
    #[arg(long, help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OrgInviteArgs {
    #[arg(value_name = "EMAIL")]
    email: String,
    #[arg(
        long,
        default_value = "member",
        help = "Role to assign (owner, admin, member)"
    )]
    role: String,
    #[arg(long, value_name = "ID_OR_SLUG", help = "Organization ID or slug")]
    org: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApiKeyCommand {
    #[command(about = "Create an API key")]
    Create(ApiKeyCreateArgs),
    #[command(about = "List API keys")]
    List,
    #[command(alias = "rm", about = "Delete an API key")]
    Delete(ApiKeyDeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ApiKeyCreateArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long, default_value_t = 0, help = "Expire after N days (0 = never)")]
    expires: i32,
}

#[derive(Debug, Args)]
pub(crate) struct ApiKeyDeleteArgs {
    #[arg(value_name = "KEY_ID")]
    key_id: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PresetCommand {
    #[command(alias = "ls", about = "List environment presets")]
    List,
    #[command(about = "Create an environment preset")]
    Create(PresetCreateArgs),
    #[command(about = "Show preset details")]
    Info(PresetInfoArgs),
    #[command(alias = "delete", about = "Delete an environment preset")]
    Rm(PresetRmArgs),
}

#[derive(Debug, Args)]
pub(crate) struct PresetCreateArgs {
    #[arg(value_name = "SLUG")]
    slug: String,
    #[arg(long, help = "Display name (defaults to slug)")]
    name: Option<String>,
    #[arg(long, help = "Container image (shorthand: go, node, python)")]
    image: String,
    #[arg(long, help = "Default install command")]
    install: Option<String>,
    #[arg(long, help = "Default startup script")]
    startup: Option<String>,
    #[arg(long, help = "Default CPU in millicores")]
    cpu: Option<i32>,
    #[arg(long, help = "Default memory in MB")]
    memory: Option<i32>,
    #[arg(long, help = "Default disk in GB")]
    disk: Option<i32>,
    #[arg(long, help = "Default TTL (e.g. 1h, 30m)")]
    ttl: Option<String>,
    #[arg(long, help = "Preset description")]
    description: Option<String>,
    #[arg(long = "secrets", help = "Default secret project to bind")]
    secret_project: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct PresetInfoArgs {
    #[arg(value_name = "SLUG_OR_ID")]
    slug_or_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PresetRmArgs {
    #[arg(value_name = "ID")]
    id: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretsCommand {
    #[command(about = "List workload-secret metadata")]
    List(SecretInventoryListArgs),
    #[command(about = "Preview key/source resolution from codewire.yaml")]
    Preview(SecretPreviewArgs),
    #[command(about = "Manage user-scoped secrets")]
    User {
        #[command(subcommand)]
        command: ScopedSecretCommand,
    },
    #[command(about = "Manage organization-scoped secrets")]
    Organization {
        #[command(subcommand)]
        command: ScopedSecretCommand,
    },
    #[command(about = "Manage named secret projects")]
    Project {
        #[command(subcommand)]
        command: SecretProjectCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
    #[arg(long, conflicts_with_all = ["platform", "all_placements"])]
    pub(crate) local: bool,
    #[arg(long, conflicts_with_all = ["local", "all_placements"])]
    pub(crate) platform: bool,
    #[arg(long, conflicts_with_all = ["local", "platform"])]
    pub(crate) all_placements: bool,
    #[command(subcommand)]
    pub(crate) command: SecretsCommand,
}

#[derive(Debug, Args)]
pub(crate) struct SecretInventoryListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SecretPreviewArgs {
    #[arg(
        long,
        default_value = "codewire.yaml",
        help = "Project document to preview"
    )]
    pub(crate) file: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretProjectCommand {
    #[command(about = "Create a secret project")]
    Create(SecretProjectCreateArgs),
    #[command(about = "List secret projects, or keys in one project")]
    List(SecretsListArgs),
    #[command(about = "Set a secret in a project")]
    Set(ProjectSecretSetArgs),
    #[command(about = "Delete a secret or an entire project")]
    Delete(ProjectSecretDeleteArgs),
    #[command(about = "Rename a secret key in a project")]
    Rename(ProjectSecretRenameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SecretProjectCreateArgs {
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct SecretsListArgs {
    #[arg(value_name = "PROJECT_NAME")]
    pub(crate) project_name: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct ProjectSecretSetArgs {
    #[arg(value_name = "PROJECT")]
    pub(crate) project: String,
    #[arg(value_name = "KEY")]
    pub(crate) key: String,
}

#[derive(Debug, Args)]
pub(crate) struct ProjectSecretDeleteArgs {
    #[arg(value_name = "PROJECT")]
    pub(crate) project: String,
    #[arg(value_name = "KEY")]
    pub(crate) key: Option<String>,
    #[arg(long, help = "Skip project delete confirmation")]
    pub(crate) yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ProjectSecretRenameArgs {
    #[arg(value_name = "PROJECT")]
    pub(crate) project: String,
    #[arg(value_name = "OLD_KEY")]
    pub(crate) old_key: String,
    #[arg(value_name = "NEW_KEY")]
    pub(crate) new_key: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ScopedSecretCommand {
    #[command(about = "List secrets")]
    List(ScopedSecretListArgs),
    #[command(about = "Set a secret")]
    Set(ScopedSecretKeyArgs),
    #[command(alias = "rm", about = "Delete a secret")]
    Delete(ScopedSecretKeyArgs),
    #[command(about = "Rename a secret key")]
    Rename(ScopedSecretRenameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretKeyArgs {
    #[arg(value_name = "KEY")]
    pub(crate) key: String,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretRenameArgs {
    #[arg(value_name = "OLD_KEY")]
    pub(crate) old_key: String,
    #[arg(value_name = "NEW_KEY")]
    pub(crate) new_key: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    #[command(about = "Show resolved non-secret CLI configuration")]
    Inspect {
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum NetworkCommand {
    #[command(alias = "networks", about = "List Mesh networks you can use")]
    List(NetworkListArgs),
    #[command(about = "Create a Mesh network")]
    Create(NetworkCreateArgs),
    #[command(about = "Show the selected Mesh network")]
    Current,
    #[command(about = "Select the default Mesh network")]
    Use(NetworkUseArgs),
    #[command(about = "Clear the selected Mesh network")]
    Clear,
    #[command(about = "List registered nodes in Mesh networks")]
    Nodes(NetworkNodesArgs),
    #[command(about = "Create an invite for the selected Mesh network")]
    Invite(NetworkInviteArgs),
    #[command(about = "Join a Mesh network with a one-use invitation code")]
    Join(NetworkJoinArgs),
    #[command(about = "Revoke a node from the selected Mesh network")]
    Revoke(NetworkRevokeArgs),
    #[command(about = "Create or redeem node enrollment grants")]
    Enroll {
        #[command(subcommand)]
        command: NetworkEnrollCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum NetworkEnrollCommand {
    #[command(about = "Create a short-lived node enrollment code")]
    Create(NetworkEnrollCreateArgs),
    #[command(about = "Redeem a node enrollment code and store node credentials")]
    Redeem(NetworkEnrollRedeemArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum MeshCommand {
    #[command(about = "Start a local Codewire Mesh process")]
    Up(MeshUpArgs),
    #[command(about = "Show local Mesh configuration status")]
    Status(MeshStatusArgs),
    #[command(about = "Stop the managed local Codewire Mesh process")]
    Down(MeshDownArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MeshUpArgs {
    #[arg(long, value_name = "PATH", help = "codewire-mesh binary path")]
    binary: Option<PathBuf>,
    #[arg(
        long = "derp-binary",
        value_name = "PATH",
        help = "codewire-derp binary path"
    )]
    derp_binary: Option<PathBuf>,
    #[arg(
        long = "base-url",
        default_value = DEFAULT_LOCAL_MESH_URL,
        help = "Public base URL saved for local Mesh clients"
    )]
    base_url: String,
    #[arg(
        long,
        default_value = DEFAULT_LOCAL_MESH_LISTEN_ADDR,
        help = "HTTP listen address for the local Mesh process"
    )]
    listen: String,
    #[arg(
        long = "derp-url",
        default_value = DEFAULT_LOCAL_DERP_URL,
        help = "Public DERP URL advertised by the local Mesh process"
    )]
    derp_url: String,
    #[arg(
        long = "derp-listen",
        default_value = DEFAULT_LOCAL_DERP_LISTEN_ADDR,
        help = "TLS listen address for the managed local DERP process"
    )]
    derp_listen: String,
    #[arg(long = "no-derp", help = "Do not start a managed local DERP process")]
    no_derp: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct MeshStatusArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct MeshDownArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkListArgs {
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(long, value_name = "ORG_ID", help = "Exact organization ID to list")]
    org: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkCreateArgs {
    #[arg(help = "Network name to create")]
    name: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(
        long,
        value_name = "ORG_ID",
        help = "Exact organization ID to own the network"
    )]
    org: String,
    #[arg(long, help = "Create without selecting the network locally")]
    no_use: bool,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkUseArgs {
    #[arg(help = "Network name to select")]
    name: String,
    #[arg(
        long = "auto-connect",
        help = "Automatically attach new environments to this network without prompting"
    )]
    auto_connect: bool,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkNodesArgs {
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(long, value_name = "ORG_ID", help = "Exact organization ID to inspect")]
    org: String,
    #[arg(long, help = "Network to list")]
    network: Option<String>,
    #[arg(long, help = "List nodes across all visible networks")]
    all: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkInviteArgs {
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(
        long,
        value_name = "ORG_ID",
        help = "Exact organization ID that owns the network"
    )]
    org: String,
    #[arg(long, help = "Network to create the invite in")]
    network: Option<String>,
    #[arg(long, default_value = "1h", help = "Time-to-live for the invite")]
    ttl: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkJoinArgs {
    #[arg(value_name = "INVITE_CODE", help = "One-use invitation code to redeem")]
    invite_code: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkRevokeArgs {
    #[arg(help = "Node name to revoke")]
    node_name: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(
        long,
        value_name = "ORG_ID",
        help = "Exact organization ID that owns the network"
    )]
    org: String,
    #[arg(long, help = "Network for the target node")]
    network: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkEnrollCreateArgs {
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(
        long,
        value_name = "ORG_ID",
        help = "Exact organization ID that owns the network"
    )]
    org: String,
    #[arg(long, help = "Network to create the enrollment in")]
    network: Option<String>,
    #[arg(long, help = "Optional node name to bind the enrollment to")]
    node_name: Option<String>,
    #[arg(long, default_value = "10m", help = "Time-to-live for the enrollment")]
    ttl: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkEnrollRedeemArgs {
    #[arg(
        value_name = "ENROLLMENT_CODE",
        help = "One-use enrollment code to redeem"
    )]
    enrollment_code: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(long, help = "Node name to redeem as")]
    node_name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct AttachArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: Option<String>,
    #[arg(value_name = "SESSION")]
    pub(crate) session: Option<String>,
    #[arg(long = "session", conflicts_with = "session", value_name = "SESSION")]
    pub(crate) selected_session: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LogsArgs {
    #[arg(value_name = "ENV")]
    pub(crate) environment: Option<String>,
    #[arg(value_name = "SESSION")]
    pub(crate) session: Option<String>,
    #[arg(short, long, help = "Follow log output")]
    follow: bool,
    #[arg(short, long, help = "Number of lines to show from end")]
    tail: Option<u32>,
    #[arg(long, help = "Output raw log data without stripping ANSI escape codes")]
    raw: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Text,
}

mod collaboration;
mod core;
mod environment;
mod mesh_commands;
mod platform_commands;
mod secrets;
mod sessions;

pub(crate) use collaboration::*;
pub(crate) use core::*;
pub(crate) use environment::*;
pub(crate) use mesh_commands::*;
pub(crate) use platform_commands::*;
pub(crate) use secrets::*;
pub(crate) use sessions::*;

#[cfg(test)]
mod tests {
    use super::*;
    include!("tests/core.rs");
    include!("tests/environment.rs");
    include!("tests/run.rs");
    include!("tests/platform.rs");
    include!("tests/sessions.rs");
    include!("tests/collaboration.rs");
}
