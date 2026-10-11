//! Command handler/module map for the Wave 4 CLI client flips.
//!
//! - `core`: hook, gateway, target selection, init, VS Code, shell, and CLI utilities.
//! - `environment`: environment lifecycle, files, access, ports, logs, and list views.
//! - `native`: Codewire-owned native local environment lifecycle and public clients.
//! - `platform_commands`: doctor, billing, login/setup, organizations, API keys,
//!   presets, and secrets.
//! - `mesh_commands`: network, node, and local Mesh management.
//! - `sessions`: local and remote session lifecycle, output, and messaging.
//! - `host_control`: trusted Mesh grants and local host control.
//! - `collaboration`: remote access grants and Mesh groups.
//!
//! WS10 WI-2 through WI-7 change these handler families in place; the former
//! `lib.rs` line positions are historical anchors only.

use super::*;
#[cfg(unix)]
pub(crate) use sessions::agents::*;

#[cfg(unix)]
mod host;
#[cfg(unix)]
pub(crate) use host::*;

#[cfg(target_os = "linux")]
mod host_control;
#[cfg(target_os = "linux")]
pub(crate) use host_control::*;

#[cfg(target_os = "linux")]
mod member_control;
#[cfg(target_os = "linux")]
pub(crate) use member_control::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use native::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credential_authority;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native_progress;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use credential_authority::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credential_broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use credential_broker::*;
#[cfg(target_os = "linux")]
mod credential_broker_confinement;
#[cfg(target_os = "linux")]
pub(crate) use credential_broker_confinement::run_local_credential_broker_confinement_probe;
#[cfg(target_os = "macos")]
mod credential_darwin;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credential_repository;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use credential_repository::*;
mod credential_input;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credentials;
mod platform_credentials;
mod platform_profiles;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod provider_login;
pub(crate) use credential_input::*;

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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(about = "Inspect native local VM orphans without mutating them")]
    Local(DoctorLocalArgs),
    #[command(about = "Probe environment tailnet transport paths")]
    Tailnet(DoctorTailnetArgs),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct DoctorLocalArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorTailnetArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
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
    #[arg(long, help = "Skip OpenSSH config update")]
    skip_ssh: bool,
    /// Install and verify the local VM runtime instead of signing in.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        conflicts_with_all = ["org", "create_org", "org_slug", "skip_ssh"],
        help = "Install and verify the local VM runtime instead of signing in"
    )]
    pub(crate) local: bool,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        value_name = "DIR",
        requires = "local",
        help = "Install the local VM runtime from this release directory"
    )]
    pub(crate) from: Option<std::path::PathBuf>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        requires = "local",
        help = "Replace a different installed local VM runtime"
    )]
    pub(crate) replace: bool,
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct NativeNetworkWorkerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct NativeEgressBrokerArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct NativeMeshTransportArgs {
    #[arg(long)]
    pub(crate) environment_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct LocalCredentialAuthorityArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    /// Present only for a backend other than the platform default.
    #[arg(long)]
    pub(crate) protected_store: Option<String>,
    /// Test-only explicit keychain file for the keychain backend.
    #[cfg(target_os = "macos")]
    #[arg(long)]
    pub(crate) keychain: Option<PathBuf>,
    /// The installed local VM runtime whose git a repository executor may
    /// run; the authority admits it against this lock (macOS).
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "runtime_artifact_lock")]
    pub(crate) runtime_artifact_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "runtime_artifact_root")]
    pub(crate) runtime_artifact_lock: Option<PathBuf>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct LocalCredentialAuthorityProbeArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    #[arg(long)]
    pub(crate) shutdown: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    pub(crate) runner_socket: PathBuf,
    #[arg(long = "http-provider")]
    pub(crate) http_providers: Vec<String>,
    #[arg(long)]
    pub(crate) platform_delegated: bool,
    /// The authority's store: macOS brokers read the selected backend.
    #[cfg(target_os = "macos")]
    #[command(flatten)]
    pub(crate) store: credential_darwin::ChildStoreArgs,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Args)]
pub(crate) struct EnvironmentLaunchArgs {
    #[arg(long)]
    pub(crate) projection_socket: PathBuf,
    #[arg(last = true, required = true)]
    pub(crate) command: Vec<std::ffi::OsString>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct LocalGitRepositoryExecutorArgs {
    #[arg(long)]
    pub(crate) platform_delegated: bool,
    #[arg(long, value_parser = ["github-oauth", "ssh"])]
    pub(crate) transport: String,
    #[arg(long)]
    pub(crate) ssh_runtime_directory: Option<PathBuf>,
    #[arg(long)]
    pub(crate) authority_fd: i32,
    #[arg(long)]
    pub(crate) request_id: String,
    #[arg(long)]
    pub(crate) staging_directory: PathBuf,
    /// The admitted runtime's git and its helper directory (macOS); Linux
    /// runs the system git.
    #[arg(long, requires = "git_exec_path")]
    pub(crate) git: Option<PathBuf>,
    #[arg(long, requires = "git")]
    pub(crate) git_exec_path: Option<PathBuf>,
    /// The runtime the git belongs to; re-admitted before every git spawn.
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "runtime_artifact_lock")]
    pub(crate) runtime_artifact_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "runtime_artifact_root")]
    pub(crate) runtime_artifact_lock: Option<PathBuf>,
    /// The authority's store: a macOS GitHub executor reads the selected
    /// backend, as a Linux one reads Secret Service.
    #[cfg(target_os = "macos")]
    #[command(flatten)]
    pub(crate) store: credential_darwin::ChildStoreArgs,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
pub(crate) struct LocalGitCredentialHelperArgs {
    #[arg(long)]
    pub(crate) brokered_endpoint: Option<String>,
    #[arg(long)]
    pub(crate) credential_socket: PathBuf,
    pub(crate) operation: String,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialsArgs {
    #[arg(
        long,
        conflicts_with = "platform",
        help = "Use local protected storage (prompts when omitted interactively)"
    )]
    pub(crate) local: bool,
    #[arg(
        long,
        conflicts_with = "local",
        help = "Use platform protected storage (prompts when omitted interactively)"
    )]
    pub(crate) platform: bool,
    #[arg(
        long,
        value_name = "PROFILE",
        help = "Select a named credential profile; accepts user/NAME and storage-qualified references"
    )]
    pub(crate) profile: Option<String>,
    #[command(subcommand)]
    pub(crate) command: CredentialsCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CredentialsCommand {
    #[command(about = "Connect an explicitly selected provider identity")]
    Connect(CredentialConnectArgs),
    #[command(about = "Add an explicitly supplied credential")]
    Add(CredentialAddArgs),
    #[command(about = "Generate a protected SSH identity and show its public key")]
    Generate(CredentialGenerateArgs),
    #[command(visible_alias = "ls", about = "List credential metadata")]
    List(CredentialListArgs),
    #[command(about = "Show credential metadata")]
    Get(CredentialGetArgs),
    #[command(about = "Rename a credential")]
    Rename(CredentialRenameArgs),
    #[command(about = "Replace credential material")]
    Rotate(CredentialRotateArgs),
    #[command(about = "Revoke a credential immediately")]
    Revoke(CredentialSelectorArgs),
    #[command(about = "Delete a credential, or the explicitly selected profile")]
    Delete(CredentialDeleteArgs),
    #[command(about = "Set one provider identity in --profile; creates the profile on first set")]
    Set(CredentialProfileSetArgs),
    #[command(about = "Remove one provider identity from --profile")]
    Unset(CredentialProfileSlotArgs),
    #[command(about = "List immutable revisions of --profile (local storage)")]
    Revisions(CredentialListArgs),
    #[command(about = "List credential profiles")]
    Profiles {
        #[command(subcommand)]
        command: CredentialProfilesCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct CredentialConnectArgs {
    #[arg(value_enum, value_name = "PROVIDER")]
    pub(crate) provider: CredentialConnectProviderArg,
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
    #[arg(
        short,
        long,
        help = "Confirm reconnecting an existing named credential"
    )]
    pub(crate) yes: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CredentialConnectProviderArg {
    #[value(help = credential_input::CODEX_DEVICE_AUTHORIZATION_GUIDANCE)]
    Codex,
    Github,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialAddArgs {
    #[arg(
        value_name = "PROVIDER",
        help = "openai or anthropic (API key read from stdin), claude-subscription (token from `claude setup-token`, read from stdin; platform only), or ssh"
    )]
    pub(crate) provider: String,
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
    #[arg(long, value_name = "HINT")]
    pub(crate) account_hint: Option<String>,
    #[arg(long, value_name = "UNIX_SECONDS")]
    pub(crate) expires_at: Option<u64>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Explicit OpenSSH private-key file; required only for add ssh"
    )]
    pub(crate) key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialGenerateArgs {
    #[arg(value_name = "PROVIDER", value_parser = ["ssh"])]
    pub(crate) provider: String,
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
    #[arg(long, value_name = "UNIX_SECONDS")]
    pub(crate) expires_at: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialGetArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name or id:UUID; omit when --profile is selected"
    )]
    pub(crate) credential: Option<String>,
    #[arg(long, help = "Inspect one exact immutable profile revision")]
    pub(crate) revision: Option<u64>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialSelectorArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialRenameArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: String,
    #[arg(value_name = "NEW_NAME")]
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialRotateArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: String,
    #[arg(
        long,
        value_name = "UNIX_SECONDS",
        help = "New hard expiry; omission clears it. Explicit API-key rotation sets status Active, including if revoked. Not accepted for a Claude subscription token, whose replacement restarts its one-year expiry"
    )]
    pub(crate) expires_at: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialDeleteArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: Option<String>,
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Debug)]
pub(crate) enum CredentialProfileCommand {
    List(CredentialListArgs),
    Get(CredentialProfileSelectorArgs),
    Set(CredentialProfileSetArgs),
    Unset(CredentialProfileSlotArgs),
    Revisions(CredentialProfileSelectorArgs),
    Delete(CredentialProfileDeleteArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum CredentialProfilesCommand {
    #[command(visible_alias = "ls", about = "List credential profile metadata")]
    List(CredentialListArgs),
}

#[derive(Debug)]
pub(crate) struct CredentialProfileSelectorArgs {
    pub(crate) profile: String,
    pub(crate) revision: Option<u64>,
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSetArgs {
    #[arg(skip)]
    pub(crate) profile: String,
    #[arg(value_name = "PROVIDER", value_parser = ["codex", "openai", "github", "anthropic", "ssh"])]
    pub(crate) slot: String,
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSlotArgs {
    #[arg(skip)]
    pub(crate) profile: String,
    #[arg(value_name = "PROVIDER", value_parser = ["codex", "openai", "github", "anthropic", "ssh"])]
    pub(crate) slot: String,
}

#[derive(Debug)]
pub(crate) struct CredentialProfileDeleteArgs {
    pub(crate) profile: String,
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
    #[arg(
        long = "preset",
        conflicts_with = "preset_id",
        help = "Preset slug (e.g. go, node, python)"
    )]
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
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    environment: Option<String>,
    #[arg(long, default_value = "/workspace", help = "Remote folder to open")]
    folder: String,
    #[arg(long, help = "Organization ID or slug")]
    org: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentShellArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(long, help = "Pipe stdin/stdout for OpenSSH ProxyCommand")]
    stdio: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentRunArgs {
    #[arg(long, help = "Durable request UUID for a member launch")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Unique session name within this environment")]
    pub(crate) name: Option<String>,
    #[arg(long, help = "Parent session name or ID within this environment")]
    pub(crate) parent: Option<String>,
    #[arg(
        long,
        value_parser = ["codex", "claude", "kimi"],
        conflicts_with = "command",
        help = "Launch a managed agent conversation instead of a command"
    )]
    pub(crate) agent: Option<String>,
    #[arg(
        long,
        requires = "agent",
        help = "Agent model; defaults to the agent's own default"
    )]
    pub(crate) model: Option<String>,
    #[arg(
        long,
        requires = "agent",
        value_parser = ["low", "medium", "high", "xhigh", "max", "ultra"],
        help = "Agent reasoning effort"
    )]
    pub(crate) effort: Option<String>,
    #[arg(
        long,
        requires = "agent",
        help = "Initial task for the managed conversation"
    )]
    pub(crate) prompt: Option<String>,
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(
        short = 'w',
        long = "workdir",
        alias = "dir",
        value_name = "DIR",
        help = "Working directory inside the environment"
    )]
    pub(crate) workdir: Option<String>,
    #[arg(
        short = 'e',
        long = "env",
        value_name = "KEY=VALUE",
        help = "Set a variable for this session; repeatable"
    )]
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
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(
        last = true,
        required_unless_present = "agent",
        value_name = "COMMAND",
        help = "Command and arguments to run, after --"
    )]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvCommand {
    #[command(about = "Inspect platform managed agent support and saved requests")]
    Agent(EnvAgentArgs),
    #[command(about = "Inspect or change cw defaults in a running environment")]
    Runtime(EnvRuntimeArgs),
    #[command(
        about = "Create a new environment",
        long_about = "Create a new environment from direct CLI flags.\n\nMultiple repos can be specified as positional args or with --repo flags.\nUse URL[@branch][::/workspace/path] to set a branch and optional checkout path per repo."
    )]
    Create(Box<EnvCreateArgs>),
    #[command(visible_alias = "ls", about = "List environments")]
    List(EnvListArgs),
    #[command(about = "Show environment details")]
    Info(EnvInfoArgs),
    #[command(about = "Change selected application secrets and credential profile")]
    Update(EnvUpdateArgs),
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
    #[command(about = "Inspect or apply an environment access profile")]
    Access(EnvAccessArgs),
    #[command(about = "Manage platform environment collaborators")]
    Share(EnvShareArgs),
    #[command(about = "Manage environment ports")]
    Port(EnvPortArgs),
    #[command(about = "Show environment setup logs")]
    Logs(EnvLogsArgs),
    #[command(about = "Inspect or repair the managed environment daemon")]
    Daemon(EnvDaemonArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvAgentArgs {
    #[command(subcommand)]
    pub(crate) command: EnvAgentCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvAgentCommand {
    #[command(about = "Show qualified managed agents in a running platform environment")]
    Info(EnvAgentInfoArgs),
    #[command(about = "Observe the original managed request without replaying it")]
    Observe(EnvAgentObserveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvAgentInfoArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: String,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvAgentObserveArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: String,
    #[arg(long, value_name = "UUID")]
    pub(crate) request_id: uuid::Uuid,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvRuntimeArgs {
    #[command(subcommand)]
    command: EnvRuntimeCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvRuntimeCommand {
    #[command(
        alias = "status",
        about = "Show the bootstrap and current cw selection"
    )]
    Info(EnvRuntimeQueryArgs),
    #[command(
        about = "Select a pinned cw without restarting the environment or existing processes"
    )]
    Update(EnvRuntimeUpdateArgs),
    #[command(about = "Select the retained previous cw without restarting existing processes")]
    Rollback(EnvRuntimeRollbackArgs),
    #[command(about = "Observe the same runtime request after an interrupted reply")]
    Observe(EnvRuntimeOperationArgs),
    #[command(about = "Cancel the same request or report its already committed effect")]
    Cancel(EnvRuntimeOperationArgs),
}
#[derive(Debug, Args)]
pub(crate) struct EnvRuntimeQueryArgs {
    #[arg(value_name = "ENV", help = "Explicit environment name or UUID")]
    environment: String,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}
#[derive(Debug, Args)]
pub(crate) struct EnvRuntimeUpdateArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    environment: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "Native: already admitted image-derived cw-runtime.lock.json",
        required_unless_present = "from",
        requires_all = ["image_sha256", "expected_revision"],
        conflicts_with = "from"
    )]
    source: Option<PathBuf>,
    #[arg(long = "from", value_name = "DIR", help = "Platform: admitted cw and cw-runtime.json release directory",
        required_unless_present = "source", requires = "expected_generation", conflicts_with_all = ["source", "image_sha256", "expected_revision"])]
    from: Option<PathBuf>,
    #[arg(
        long,
        value_name = "SHA256",
        help = "Exact lowercase cw image index SHA256",
        value_parser = parse_runtime_sha256,
        requires = "source"
    )]
    image_sha256: Option<String>,
    #[arg(
        long,
        value_name = "SHA256",
        help = "Exact lowercase cw executable SHA256",
        value_parser = parse_runtime_sha256
    )]
    target_sha256: String,
    #[arg(long, help = "Native: observed live selector revision", value_parser = parse_runtime_revision, requires = "source", conflicts_with = "expected_generation")]
    expected_revision: Option<u64>,
    #[arg(long, help = "Platform: observed Store generation (zero for first bootstrap)", value_parser = parse_runtime_generation, requires = "from", conflicts_with = "expected_revision")]
    expected_generation: Option<u64>,
    #[arg(
        long,
        value_name = "UUID",
        help = "Stable request UUID; an existing request is observation only",
        value_parser = parse_runtime_request_id
    )]
    request_id: Option<uuid::Uuid>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}
#[derive(Debug, Args)]
pub(crate) struct EnvRuntimeRollbackArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    environment: String,
    #[arg(long, help = "Native: observed live selector revision", value_parser = parse_runtime_revision, required_unless_present = "expected_generation", conflicts_with = "expected_generation")]
    expected_revision: Option<u64>,
    #[arg(long, help = "Platform: observed Store generation", value_parser = parse_runtime_generation, required_unless_present = "expected_revision", conflicts_with = "expected_revision")]
    expected_generation: Option<u64>,
    #[arg(long, value_name = "UUID", value_parser = parse_runtime_request_id)]
    request_id: Option<uuid::Uuid>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}
#[derive(Debug, Args)]
pub(crate) struct EnvRuntimeOperationArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    environment: String,
    #[arg(long, value_name = "UUID", value_parser = parse_runtime_request_id)]
    request_id: uuid::Uuid,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

fn parse_runtime_sha256(value: &str) -> Result<String, String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err("runtime SHA256 must be exactly 64 lowercase hexadecimal characters".into())
    }
}
fn parse_runtime_revision(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| "runtime selection revision must be a nonzero integer".into())
}
fn parse_runtime_generation(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == value)
        .ok_or_else(|| "runtime Store generation must be a canonical unsigned integer".into())
}
fn parse_runtime_request_id(value: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| "runtime request ID must be a non-nil UUID".into())
}

#[derive(Debug, Args)]
pub(crate) struct EnvCreateArgs {
    #[arg(long = "type", value_enum, default_value_t = EnvironmentTypeArg::Sandbox,
        help = "Sandbox or explicitly trusted host execution")]
    environment_type: EnvironmentTypeArg,
    #[arg(value_name = "REPO_URL")]
    repo_urls: Vec<String>,
    #[arg(
        long = "preset",
        conflicts_with = "preset_id",
        help = "Preset slug (e.g. go, node, python)"
    )]
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
        help = "How --path becomes the workspace: mount (default, live), snapshot, clone, copy, or empty; requires --local"
    )]
    path_mode: Option<PathModeArg>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Project YAML file (relative to --path for local creation)"
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
    #[arg(
        long,
        value_name = "PROFILE",
        help = "Credential profile, for example local:work or platform:work"
    )]
    profile: Option<String>,
    #[arg(long, value_name = "PROJECT", help = "Application-secret project")]
    secrets: Option<String>,
    #[arg(
        long,
        value_enum,
        help = "Include personal application secrets from this store"
    )]
    user_secrets: Option<StoragePlacementArg>,
    #[arg(
        long,
        help = "Include the current platform organization's application secrets"
    )]
    org_secrets: bool,
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

/// How `cw env create --local` turns the `--path` directory into the
/// workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PathModeArg {
    /// Mount the directory live, read-write, at /workspace/<name> (default).
    Mount,
    /// Copy it once: clone a Git repository's committed state, otherwise copy.
    Snapshot,
    /// Clone the Git repository's committed state once.
    Clone,
    /// Copy the directory once.
    Copy,
    /// Start with an empty /workspace.
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum EnvironmentTypeArg {
    Sandbox,
    Host,
}

#[derive(Debug, Args)]
pub(crate) struct HostDaemonArgs {
    #[arg(long)]
    pub(crate) environment: String,
    #[arg(long)]
    pub(crate) registry_root: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum StoragePlacementArg {
    Local,
    Platform,
}

#[derive(Debug, Args)]
pub(crate) struct EnvUpdateArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    environment: String,
    #[arg(long, value_name = "PROJECT")]
    secrets: Option<String>,
    #[arg(long, value_enum)]
    user_secrets: Option<StoragePlacementArg>,
    #[arg(long)]
    org_secrets: bool,
    #[arg(long, conflicts_with_all = ["secrets", "user_secrets", "org_secrets"])]
    clear_secrets: bool,
    #[arg(long, conflicts_with = "clear_profile")]
    profile: Option<String>,
    #[arg(long)]
    clear_profile: bool,
    #[arg(short, long)]
    yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
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
    #[arg(value_name = "ENV", help = "Environment name or ID")]
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
pub(crate) struct EnvAccessArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvShareArgs {
    #[command(subcommand)]
    command: EnvShareCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EnvShareCommand {
    #[command(visible_alias = "ls", about = "List collaborators for an environment")]
    List(EnvShareTargetArgs),
    #[command(about = "Share an environment with a user")]
    Grant(EnvShareGrantArgs),
    #[command(about = "Remove a user's access to an environment")]
    Revoke(EnvShareRevokeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvShareTargetArgs {
    #[arg(value_name = "ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvShareGrantArgs {
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
pub(crate) struct EnvShareRevokeArgs {
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
    #[command(
        about = "Publish a port: a preview URL on the platform, 127.0.0.1 on this host for a local environment"
    )]
    Add(EnvPortAddArgs),
    #[command(visible_alias = "ls", about = "List published ports")]
    List(EnvPortListArgs),
    #[command(about = "Withdraw a published port (local: by host port)")]
    Rm(EnvPortRmArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnvPortAddArgs {
    #[arg(value_name = "PORT", help = "Port inside the environment")]
    port: String,
    #[arg(
        short,
        long,
        help = "DNS-safe label for the preview URL (platform; required there)"
    )]
    label: Option<String>,
    #[arg(
        short,
        long,
        help = "Access level: public, org_members, or creator (platform; default creator)"
    )]
    access: Option<String>,
    #[arg(
        long,
        value_name = "HOST_PORT",
        value_parser = clap::value_parser!(u16).range(1..),
        help = "Port on this host's 127.0.0.1 (local; default: PORT)"
    )]
    host_port: Option<u16>,
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
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct EnvDaemonLogsArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
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
pub(crate) enum OrgCommand {
    #[command(visible_alias = "ls", about = "List organizations")]
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
    #[command(visible_alias = "ls", about = "List API keys")]
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
    #[command(visible_alias = "ls", about = "List environment presets")]
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
}

#[derive(Debug, Args)]
pub(crate) struct PresetInfoArgs {
    #[arg(
        value_name = "SLUG_OR_EXACT_REFERENCE",
        help = "Preset slug, slug:<slug>, or id:<id>"
    )]
    selector: String,
}

#[derive(Debug, Args)]
pub(crate) struct PresetRmArgs {
    #[arg(value_name = "ID")]
    id: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretsCommand {
    #[command(
        visible_alias = "ls",
        about = "List key metadata in the explicitly selected scope"
    )]
    List(ScopedSecretListArgs),
    #[command(about = "Set one key using a hidden prompt or standard input")]
    Set(ScopedSecretKeyArgs),
    #[command(about = "Delete one key from the explicitly selected scope")]
    Delete(ScopedSecretKeyArgs),
    #[command(about = "Rename one key in the explicitly selected scope")]
    Rename(ScopedSecretRenameArgs),
    #[command(about = "Preview key/source resolution from codewire.yaml")]
    Preview(SecretPreviewArgs),
    #[command(about = "Manage named secret projects")]
    Projects {
        #[command(subcommand)]
        command: SecretProjectCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
    #[arg(
        long,
        conflicts_with = "platform",
        help = "Use local protected storage (prompts when omitted interactively)"
    )]
    pub(crate) local: bool,
    #[arg(
        long,
        conflicts_with = "local",
        help = "Use platform protected storage (prompts when omitted interactively)"
    )]
    pub(crate) platform: bool,
    #[arg(long, value_name = "NAME", conflicts_with_all = ["user", "organization"], value_parser = parse_secret_project_reference, help = "Explicit named project for key operations; never inferred from cw use or YAML")]
    pub(crate) project: Option<String>,
    #[arg(long, conflicts_with_all = ["project", "organization"], help = "Operate on user-scoped keys")]
    pub(crate) user: bool,
    #[arg(long, conflicts_with_all = ["project", "user"], help = "Operate on organization-scoped keys (platform only)")]
    pub(crate) organization: bool,
    #[command(subcommand)]
    pub(crate) command: SecretsCommand,
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
    #[command(visible_alias = "ls", about = "List named secret projects")]
    List(ScopedSecretListArgs),
    #[command(about = "Delete an explicitly named project and all its keys")]
    Delete(SecretProjectDeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SecretProjectCreateArgs {
    #[arg(value_name = "NAME", value_parser = parse_secret_project_name)]
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct SecretProjectDeleteArgs {
    #[arg(value_name = "NAME", value_parser = parse_secret_project_reference)]
    pub(crate) name: String,
    #[arg(long, help = "Confirm deletion of this project and all its keys")]
    pub(crate) yes: bool,
}

#[derive(Debug)]
pub(crate) enum ScopedSecretCommand {
    List(ScopedSecretListArgs),
    Set(ScopedSecretKeyArgs),
    Delete(ScopedSecretKeyArgs),
    Rename(ScopedSecretRenameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretKeyArgs {
    #[arg(value_name = "KEY", value_parser = parse_secret_key)]
    pub(crate) key: String,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretRenameArgs {
    #[arg(value_name = "OLD_KEY", value_parser = parse_secret_key)]
    pub(crate) old_key: String,
    #[arg(value_name = "NEW_KEY", value_parser = parse_secret_key)]
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
    #[command(
        alias = "networks",
        visible_alias = "ls",
        about = "List Mesh networks you can use"
    )]
    List(NetworkListArgs),
    #[command(about = "Create a Mesh network")]
    Create(NetworkCreateArgs),
    #[command(about = "Delete an empty Mesh network and permanently retire its name")]
    Delete(NetworkDeleteArgs),
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
pub(crate) struct NetworkDeleteArgs {
    #[arg(help = "Exact network name to delete (cannot be reused)")]
    name: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
    #[arg(
        long,
        value_name = "ORG_ID",
        help = "Exact organization ID owning the network"
    )]
    org: String,
    #[arg(long, help = "Confirm permanent deletion without prompting")]
    yes: bool,
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

#[derive(Args)]
pub(crate) struct NetworkJoinArgs {
    #[arg(value_name = "INVITE_CODE", help = "One-use invitation code to redeem")]
    invite_code: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
}

impl std::fmt::Debug for NetworkJoinArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkJoinArgs")
            .field("invite_code", &"[REDACTED]")
            .field("mesh_url", &self.mesh_url)
            .finish()
    }
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

#[derive(Args)]
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

impl std::fmt::Debug for NetworkEnrollRedeemArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkEnrollRedeemArgs")
            .field("enrollment_code", &"[REDACTED]")
            .field("mesh_url", &self.mesh_url)
            .field("node_name", &self.node_name)
            .finish()
    }
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    #[arg(
        long,
        conflicts_with = "environment",
        help = "List every accessible environment (the default without ENV)"
    )]
    pub(crate) all: bool,
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; omit to list every environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct StopArgs {
    #[command(flatten)]
    pub(crate) session: SessionTargetArgs,
    #[arg(
        long,
        help = "Also stop every running descendant session without asking"
    )]
    pub(crate) all: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SessionTargetArgs {
    #[arg(long, help = "Durable request UUID for a member mutation")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Exact positive member session generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(long, value_name = "UUID", value_parser = parse_runtime_request_id,
        help = "Platform Stop: original uncertain operation to clean up")]
    pub(crate) cleanup_request_id: Option<uuid::Uuid>,
    #[arg(value_name = "TARGET", help = "SESSION, or ENV SESSION", num_args = 1..=2)]
    pub(crate) target: Vec<String>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SendArgs {
    #[arg(long, help = "Durable request UUID for member input")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Exact positive member session generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(value_name = "TARGET_AND_TEXT", help = "SESSION TEXT, or ENV SESSION TEXT; --key omits TEXT", num_args = 1..=3)]
    pub(crate) target_and_text: Vec<String>,
    #[arg(
        long,
        conflicts_with = "key",
        help = "Write text without a trailing newline"
    )]
    pub(crate) no_newline: bool,
    #[arg(long, value_parser = ["ctrl-c", "ctrl-d", "enter", "escape", "tab"])]
    pub(crate) key: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WaitArgs {
    #[arg(value_name = "TARGET", help = "SESSION, or ENV SESSION", num_args = 1..=2, required_unless_present = "message")]
    pub(crate) target: Vec<String>,
    #[arg(
        long,
        help = "Wait for a managed message's terminal result; the ID alone names its session"
    )]
    pub(crate) message: Option<String>,
    #[arg(
        long,
        default_value = "30m",
        help = "Maximum wait; timeout reports unknown, never success"
    )]
    pub(crate) timeout: String,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct AgentMessageArgs {
    #[arg(value_name = "TARGET_AND_TEXT", help = "SESSION TEXT, or ENV SESSION TEXT", num_args = 2..=3)]
    pub(crate) target_and_text: Vec<String>,
    #[arg(long, help = "Reply to a prior message ID")]
    pub(crate) reply_to: Option<String>,
    #[arg(long, help = "Expected active turn ID for steering")]
    pub(crate) turn_id: Option<String>,
    #[arg(long, help = "Saved request UUID for a member-managed message")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Expected member session launch generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct AttachArgs {
    #[arg(
        value_name = "ENV_OR_SESSION",
        help = "Environment, or session in the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(value_name = "SESSION")]
    pub(crate) session: Option<String>,
    #[arg(long = "session", conflicts_with = "session", value_name = "SESSION")]
    pub(crate) selected_session: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LogsArgs {
    #[arg(
        value_name = "ENV_OR_SESSION",
        help = "Environment, or session in the selected environment"
    )]
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
mod ssh_trust;
mod storage_placement;

pub(crate) use collaboration::*;
pub(crate) use core::*;
pub(crate) use environment::*;
#[cfg(target_os = "linux")]
pub(crate) use mesh_commands::retained::StateDir as MeshStateDir;
pub(crate) use mesh_commands::*;
pub(crate) use platform_commands::*;
pub(crate) use secrets::*;
pub(crate) use sessions::*;
pub(crate) use ssh_trust::*;

#[cfg(test)]
mod tests {
    use super::*;
    include!("tests/core.rs");
    include!("tests/network_delete.rs");
    include!("tests/environment.rs");
    include!("tests/runtime.rs");
    include!("tests/run.rs");
    include!("tests/platform.rs");
    include!("tests/sessions.rs");
    include!("tests/collaboration.rs");
    include!("tests/ssh_trust.rs");
}
