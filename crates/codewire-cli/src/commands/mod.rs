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
mod login_screen;
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
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct SshSetupArgs {
    #[command(subcommand)]
    command: Option<SshSetupCommand>,
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
        help = "Show the change to the managed Codewire section without writing it"
    )]
    dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SshSetupCommand {
    #[command(
        about = "Remove the managed Codewire section from your SSH config",
        long_about = "Removes only the managed Codewire section, from its start marker through its end marker. Your own SSH entries and your environments are kept."
    )]
    Remove(SshRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SshRemoveArgs {
    #[arg(long, value_name = "PATH", help = "Path to the SSH config file")]
    ssh_config_file: Option<PathBuf>,
    #[arg(
        short = 'n',
        long,
        help = "Show the section that would be removed without writing"
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
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct SetupArgs {
    #[command(subcommand)]
    pub(crate) command: Option<SetupCommand>,
    #[arg(long, value_name = "ID_OR_SLUG", help = "Default organization to save")]
    pub(crate) org: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Create this organization when selecting the default org"
    )]
    pub(crate) create_org: Option<String>,
    #[arg(
        long,
        value_name = "SLUG",
        requires = "create_org",
        help = "Slug for --create-org"
    )]
    pub(crate) org_slug: Option<String>,
    #[arg(long, help = "Skip OpenSSH config update")]
    pub(crate) skip_ssh: bool,
    /// With --local: install the local VM runtime from this release directory.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        value_name = "DIR",
        help = "With --local: install the local VM runtime from this release directory"
    )]
    pub(crate) from: Option<std::path::PathBuf>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        help = "With --local: replace a different installed local VM runtime"
    )]
    pub(crate) replace: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SetupCommand {
    #[command(
        about = "Write the OpenSSH integration for Codewire environments",
        long_about = "Adds or updates the managed Codewire section in your SSH config so OpenSSH, scp, sftp, rsync, and Remote-SSH can use `cw shell --stdio` as ProxyCommand. `cw setup ssh remove` takes it out again.\n\nThe section passes the host name to ProxyCommand (`%n`) for every `cw-*` host, so it needs OpenSSH 9.6 or later, or a distribution build that includes the CVE-2023-51385 fix. Without that fix, a host name from an untrusted source, such as a git submodule URL, can run commands."
    )]
    Ssh(SshSetupArgs),
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
        value_name = "ENV",
        help = "Environment name or ID; omit to choose from a list in an interactive terminal"
    )]
    pub(crate) target: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvironmentPlacement {
    Local,
    Platform,
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

/// `--local` or `--cloud` (global) selects the protected storage; without
/// one an interactive call prompts.
#[derive(Debug, Args)]
pub(crate) struct CredentialsArgs {
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
    #[value(help = credential_input::CLAUDE_SIGN_IN_GUIDANCE)]
    Claude,
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

#[derive(Debug, Args)]
pub(crate) struct CurrentTargetArgs {
    #[arg(short, long, help = "Also show the environment's ID and organization")]
    pub(crate) verbose: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
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
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(long, default_value = "/workspace", help = "Remote folder to open")]
    pub(crate) folder: String,
    #[arg(long, help = "Organization ID or slug")]
    pub(crate) org: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentShellArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(long, help = "Pipe stdin/stdout for OpenSSH ProxyCommand")]
    pub(crate) stdio: bool,
}

/// The agent `cw run AGENT` opens in its own terminal UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAgent {
    Claude,
    Codex,
}

impl NativeAgent {
    pub(crate) const ALL: [NativeAgent; 2] = [NativeAgent::Claude, NativeAgent::Codex];

    /// The agent's command, which is also its default session name.
    pub(crate) fn command(self) -> &'static str {
        match self {
            NativeAgent::Claude => "claude",
            NativeAgent::Codex => "codex",
        }
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            NativeAgent::Claude => "Claude Code",
            NativeAgent::Codex => "Codex",
        }
    }
}

/// `cw run`'s positional names an agent and never an environment, so an
/// environment that happens to be called `claude` cannot change its meaning.
pub(crate) fn parse_native_agent(value: &str) -> Result<NativeAgent, String> {
    match value {
        "claude" => Ok(NativeAgent::Claude),
        "codex" => Ok(NativeAgent::Codex),
        other => Err(format!(
            "`cw run` opens claude or codex; to run in an environment named {other}, use `cw run --in {other} -- COMMAND` or `cw run claude --in {other}`"
        )),
    }
}

#[derive(Debug, Args)]
pub(crate) struct EnvironmentRunArgs {
    #[arg(long, help = "Durable request UUID for a member launch")]
    pub(crate) request_id: Option<String>,
    #[arg(
        value_name = "AGENT",
        value_parser = parse_native_agent,
        help = "claude or codex: open that agent's own terminal UI in a new session"
    )]
    pub(crate) native_agent: Option<NativeAgent>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Name the new session (unique in its environment); defaults to the agent or command name"
    )]
    pub(crate) name: Option<String>,
    #[arg(long, help = "Parent session name or ID within this environment")]
    pub(crate) parent: Option<String>,
    #[arg(
        long,
        value_parser = ["codex", "claude", "kimi", "noel"],
        conflicts_with_all = ["native_agent", "command", "tty"],
        help = "Start a managed agent conversation (queued messages, recorded results) instead of a terminal UI"
    )]
    pub(crate) agent: Option<String>,
    #[arg(
        long,
        requires = "agent",
        help = "Managed agent model; Codex and Claude default to their own, noel requires PROVIDER/ID"
    )]
    pub(crate) model: Option<String>,
    #[arg(
        long,
        requires = "agent",
        value_parser = ["low", "medium", "high", "xhigh", "max", "ultra"],
        help = "Managed agent reasoning effort; default: medium (Codex)"
    )]
    pub(crate) effort: Option<String>,
    #[arg(
        long,
        requires = "agent",
        help = "Initial task for the managed conversation"
    )]
    pub(crate) prompt: Option<String>,
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
        value_name = "ARGS",
        help = "After --: the command to run, or the agent's own arguments with AGENT"
    )]
    pub(crate) command: Vec<String>,
}

/// One environment operation, built by the flat top-level commands
/// (`commands/flat.rs`) and dispatched by `handle_env_command` with the
/// global placement. Not a parser: the public grammar has no `env` namespace.
#[derive(Debug)]
pub(crate) enum EnvCommand {
    Agent(EnvAgentArgs),
    Runtime(EnvRuntimeArgs),
    Create(Box<EnvCreateArgs>),
    Info(EnvInfoArgs),
    Update(EnvUpdateArgs),
    Resize(EnvResizeArgs),
    Report(EnvReportArgs),
    Stop(EnvTargetArgs),
    Start(EnvTargetArgs),
    Restart(EnvTargetArgs),
    RefreshSkills(EnvTargetArgs),
    Rm(EnvDeleteArgs),
    Prune(EnvPruneArgs),
    Nuke(EnvNukeArgs),
    Cp(EnvCpArgs),
    Protect(EnvTargetArgs),
    Unprotect(EnvTargetArgs),
    CancelDelete(EnvTargetArgs),
    Extend(EnvExtendArgs),
    Access(EnvAccessArgs),
    Share(EnvShareArgs),
    Port(EnvPortTarget),
    Logs(EnvLogsArgs),
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
        help = "Local project directory, where the codewire.yaml search starts; used with --local"
    )]
    path: Option<PathBuf>,
    #[arg(
        long = "path-mode",
        value_enum,
        value_name = "MODE",
        help = "How --path becomes the workspace: mount (default, live), copy (a one-time copy of the folder as it is now), clone (a one-time clone of the Git repository's committed state), or empty; requires --local"
    )]
    path_mode: Option<PathModeArg>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Project YAML file to use instead of the nearest codewire.yaml (relative to --path for a local create)"
    )]
    file: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "file",
        help = "Use only the flags: do not read the nearest codewire.yaml"
    )]
    no_file: bool,
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
        help = "Git repository to clone (repeatable, URL[@branch][::/workspace/path]); replaces the file's repositories"
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
    #[arg(
        long,
        value_name = "NETWORK",
        help = "Join a Mesh network: cloud:NAME, local:NAME, or NAME on the selected Mesh"
    )]
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

/// How `cw create --local` turns the `--path` directory into the
/// workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PathModeArg {
    /// Mount the directory live, read-write, at /workspace/<name> (default).
    Mount,
    /// Copy the folder once, as it is now, uncommitted work included.
    Copy,
    /// Clone the Git repository's committed state once.
    Clone,
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
    /// Filled from the `cw update` ENV positional or `--in ENV`.
    #[arg(skip)]
    environment: String,
    #[arg(
        long,
        value_name = "PROJECT",
        help = "Select this application-secret project"
    )]
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
    #[arg(long, conflicts_with_all = ["secrets", "user_secrets", "org_secrets"], help = "Clear every selected application-secret source")]
    clear_secrets: bool,
    #[arg(
        long,
        conflicts_with = "clear_profile",
        help = "Select this credential profile"
    )]
    profile: Option<String>,
    #[arg(long, help = "Clear the selected credential profile")]
    clear_profile: bool,
    #[arg(short, long, help = "Apply without the confirmation prompt")]
    yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

/// `cw update ENV`: the environment and its selection changes. The CLI
/// updater's flags are accepted only to refuse them with the `cw upgrade`
/// spelling before any effect.
#[derive(Debug, Args)]
pub(crate) struct UpdateEnvironmentArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[command(flatten)]
    pub(crate) update: EnvUpdateArgs,
    #[command(flatten)]
    pub(crate) upgrade_flags: RetiredUpdaterFlags,
}

/// The CLI updater's flags, refused by `cw update` with a `cw upgrade` pointer.
#[derive(Debug, Default, Args)]
pub(crate) struct RetiredUpdaterFlags {
    #[arg(long, hide = true)]
    pub(crate) cli: bool,
    #[arg(long, hide = true)]
    pub(crate) vms: bool,
    #[arg(long, hide = true)]
    pub(crate) restart_vms: bool,
    #[arg(long, hide = true, value_name = "VERSION")]
    pub(crate) to: Option<String>,
    #[arg(long, hide = true, value_name = "CHANNEL")]
    pub(crate) channel: Option<String>,
    #[arg(long, hide = true, value_name = "VERSION")]
    pub(crate) version: Option<String>,
    #[arg(long, hide = true, value_name = "DIR")]
    pub(crate) from: Option<PathBuf>,
    #[arg(long, hide = true, value_name = "HEX")]
    pub(crate) sha256: Option<String>,
    #[arg(long, hide = true, value_name = "N")]
    pub(crate) expect_generation: Option<u64>,
    #[arg(long, hide = true, value_name = "DIR")]
    pub(crate) store: Option<PathBuf>,
}

impl RetiredUpdaterFlags {
    pub(crate) fn names(&self) -> Vec<&'static str> {
        [
            (self.cli, "--cli"),
            (self.vms, "--vms"),
            (self.restart_vms, "--restart-vms"),
            (self.to.is_some(), "--to"),
            (self.channel.is_some(), "--channel"),
            (self.version.is_some(), "--version"),
            (self.from.is_some(), "--from"),
            (self.sha256.is_some(), "--sha256"),
            (self.expect_generation.is_some(), "--expect-generation"),
            (self.store.is_some(), "--store"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect()
    }
}

/// Inventory filters shared by `cw ls` and the attach workspace chooser.
#[derive(Debug)]
pub(crate) struct EnvListArgs {
    pub(crate) environment_type: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) all: bool,
    pub(crate) output: OutputFormat,
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

/// `cw ports [ENV]`: list, or change one mapping with --publish or
/// --unpublish. Listing never starts a VM.
#[derive(Debug, Args)]
pub(crate) struct PortsArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "PORT",
        value_parser = clap::value_parser!(u16).range(1..),
        conflicts_with = "unpublish",
        help = "Publish this guest port: 127.0.0.1 on this host (local) or a preview URL (cloud)"
    )]
    pub(crate) publish: Option<u16>,
    #[arg(
        long,
        value_name = "PORT",
        value_parser = clap::value_parser!(u16).range(1..),
        help = "Withdraw the mapping of this guest port"
    )]
    pub(crate) unpublish: Option<u16>,
    #[arg(
        long,
        value_name = "HOST_PORT",
        value_parser = clap::value_parser!(u16).range(1..),
        help = "Local only: the port on this host's 127.0.0.1 (default: the guest port); selects the binding to unpublish"
    )]
    pub(crate) host_port: Option<u16>,
    #[arg(
        short,
        long,
        help = "Cloud only: DNS-safe preview label (default: port-PORT); selects the preview to unpublish"
    )]
    pub(crate) label: Option<String>,
    #[arg(
        short,
        long,
        help = "Cloud only: preview access, public, org_members or creator (default: creator)"
    )]
    pub(crate) access: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

/// `cw export [ENV]`: write an environment's saved configuration as
/// codewire.yaml without changing the environment.
#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "stdout",
        help = "Write to PATH instead of ./codewire.yaml"
    )]
    pub(crate) file: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "force",
        help = "Print the YAML instead of writing a file"
    )]
    pub(crate) stdout: bool,
    #[arg(long, help = "Overwrite an existing file")]
    pub(crate) force: bool,
}

/// A `cw ports` request after its environment selector was resolved.
#[derive(Debug)]
pub(crate) struct EnvPortTarget {
    pub(crate) environment: Option<String>,
    pub(crate) operation: PortOperation,
    pub(crate) output: OutputFormat,
}

#[derive(Debug)]
pub(crate) enum PortOperation {
    List,
    Publish {
        port: u16,
        host_port: Option<u16>,
        label: Option<String>,
        access: Option<String>,
    },
    Unpublish {
        port: u16,
        host_port: Option<u16>,
        label: Option<String>,
    },
}

/// Setup logs of a cloud environment (`cw logs ENV --setup`).
#[derive(Debug)]
pub(crate) struct EnvLogsArgs {
    pub(crate) environment: String,
    pub(crate) follow: bool,
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

/// `--local` or `--cloud` (global) selects the protected storage; without
/// one an interactive call prompts.
#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
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

/// Network commands choose their Mesh with the global `--cloud` (the
/// platform's hosted Mesh) or `--local` (the local Mesh service), or with
/// `--mesh-url`; otherwise the selected network's Mesh, else the one Mesh
/// available.
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
    #[command(about = "Show the network selected for new environments")]
    Current(NetworkCurrentArgs),
    #[command(
        about = "Select the network new environments join",
        long_about = "Select the network new environments join, on the Mesh --cloud or --local names:\n  cw --cloud network use work\n  cw --local network use dev\n\nThe selection records the Mesh endpoint, the organization that owns new environments there, and the network. It attaches nothing: existing environments keep their attachments."
    )]
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
pub(crate) struct NetworkCurrentArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct NetworkUseArgs {
    #[arg(help = "Network name to select")]
    name: String,
    #[arg(long = "mesh-url", help = "Mesh base URL override")]
    mesh_url: Option<String>,
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
        value_name = "ENV",
        help = "List this environment's sessions; omit to list every environment"
    )]
    pub(crate) environment: Option<String>,
    #[arg(long = "type", help = "Inventory filter by type: sandbox or host")]
    pub(crate) environment_type: Option<String>,
    #[arg(long, help = "Inventory filter by state")]
    pub(crate) state: Option<String>,
    #[arg(
        short,
        long,
        help = "Include destroyed cloud environments in the inventory"
    )]
    pub(crate) all: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

/// The environment and optional session that `stop` and `restart` act on.
/// Without `--session` they act on the whole environment, which must be
/// named; with it, on one session, in the current environment by default.
#[derive(Debug, Args)]
pub(crate) struct SessionScopeArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Act on this session only; without ENV, in the selected environment"
    )]
    pub(crate) session: Option<String>,
    #[arg(
        long,
        help = "Durable request UUID for a member mutation (with --session)"
    )]
    pub(crate) request_id: Option<String>,
    #[arg(
        long,
        help = "Exact positive member session generation (with --session)"
    )]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(long, value_name = "UUID", value_parser = parse_runtime_request_id,
        help = "Platform session stop: original uncertain operation to clean up")]
    pub(crate) cleanup_request_id: Option<uuid::Uuid>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct StopArgs {
    #[command(flatten)]
    pub(crate) scope: SessionScopeArgs,
    #[arg(
        long,
        help = "With --session: also stop every running descendant session without asking"
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

/// One existing session, named by flags: `[ENV | --in ENV] --session S`.
/// Without ENV, the session is in the selected environment. Used by
/// `cw interrupt`; built into [`SessionTargetArgs`] for its handler.
#[derive(Debug, Args)]
pub(crate) struct SessionSelectorArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Session name or ID; without ENV, in the selected environment"
    )]
    pub(crate) session: Option<String>,
    #[arg(long, help = "Durable request UUID for a member mutation")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Exact positive member session generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SendArgs {
    #[arg(long, help = "Durable request UUID for member input")]
    pub(crate) request_id: Option<String>,
    #[arg(long, help = "Exact positive member session generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    /// `[ENV] TEXT`, or `[ENV]` with `--key`: the count alone decides each
    /// value's role, never a lookup. A third value is the retired
    /// `ENV SESSION TEXT` form, refused with its replacement.
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; omit to use the selected environment"
    )]
    pub(crate) first: Option<String>,
    #[arg(
        value_name = "TEXT",
        help = "Text to write; a newline follows unless --no-newline"
    )]
    pub(crate) second: Option<String>,
    #[arg(hide = true, value_name = "RETIRED")]
    pub(crate) retired: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(long, value_name = "SESSION", help = "Session name or ID to write to")]
    pub(crate) session: Option<String>,
    #[arg(
        long,
        conflicts_with = "key",
        help = "Write text without a trailing newline"
    )]
    pub(crate) no_newline: bool,
    #[arg(long, value_parser = ["ctrl-c", "ctrl-d", "enter", "escape", "tab"], help = "Send one terminal key instead of TEXT")]
    pub(crate) key: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WaitArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Wait for this session to finish; without ENV, in the selected environment"
    )]
    pub(crate) session: Option<String>,
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

/// `cw msg` and `cw steer`: `[ENV|--in ENV] --session SESSION TEXT`.
#[derive(Debug, Args)]
pub(crate) struct AgentMessageArgs {
    /// `[ENV] TEXT`. A third positional once named the session; it is
    /// refused with the `--session` spelling before any lookup.
    #[arg(
        value_name = "ENV_AND_TEXT",
        help = "[ENV] TEXT: the environment (default: the selected one), then the text",
        num_args = 1..=3,
        required = true
    )]
    pub(crate) positionals: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(long, value_name = "SESSION", help = "The session to send to")]
    pub(crate) session: Option<String>,
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

impl AgentMessageArgs {
    /// The environment, session and text, checked before any lookup.
    pub(crate) fn target(&self, command: &str) -> anyhow::Result<(Option<&str>, &str, &str)> {
        let usage = format!("`cw {command} [ENV] --session SESSION TEXT`");
        let Some(session) = self.session.as_deref().and_then(trimmed_str) else {
            anyhow::bail!(
                "name the session with --session: {usage}; a positional no longer selects a session"
            );
        };
        match self.positionals.as_slice() {
            [text] => Ok((self.in_environment.as_deref(), session, text)),
            [environment, text] => {
                anyhow::ensure!(
                    self.in_environment.is_none(),
                    "name the environment once: `cw {command} ENV` or `cw {command} --in ENV`, not both"
                );
                Ok((Some(environment), session, text))
            }
            _ => anyhow::bail!(
                "`cw {command} ENV SESSION TEXT` no longer selects a session; use {usage}"
            ),
        }
    }
}

/// `cw inbox [ENV|--in ENV] --session SESSION`.
#[derive(Debug, Args)]
pub(crate) struct InboxArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(long, value_name = "SESSION", help = "The session whose inbox to show")]
    pub(crate) session: Option<String>,
    #[arg(long, help = "Exact positive member session generation")]
    pub(crate) expected_launch_generation: Option<u64>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct AttachArgs {
    #[arg(value_name = "ENV", help = "Environment name or ID")]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Session name or ID; without ENV, in the selected environment"
    )]
    pub(crate) session: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LogsArgs {
    #[arg(
        value_name = "ENV",
        help = "Environment name or ID; defaults to the selected environment"
    )]
    pub(crate) environment: Option<String>,
    /// A second positional, refused with the `--session` spelling.
    #[arg(hide = true, value_name = "SESSION")]
    pub(crate) retired_session: Vec<String>,
    #[arg(
        long = "in",
        value_name = "ENV",
        help = "Environment name or ID (same as ENV)"
    )]
    pub(crate) in_environment: Option<String>,
    #[arg(
        long,
        value_name = "SESSION",
        help = "Show this session's saved output"
    )]
    pub(crate) session: Option<String>,
    #[arg(
        long,
        conflicts_with = "session",
        help = "Show how the environment was set up: provisioning, repository clones, install and startup steps (cloud)"
    )]
    pub(crate) setup: bool,
    #[arg(short, long, help = "Follow new output")]
    pub(crate) follow: bool,
    #[arg(
        short,
        long,
        help = "Session output: number of lines to show from the end"
    )]
    pub(crate) tail: Option<u32>,
    #[arg(long, help = "Session output: keep ANSI escape codes")]
    pub(crate) raw: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Text,
}

mod collaboration;
mod core;
mod current_environment;
mod environment;
mod export;
pub(crate) mod flat;
pub(crate) mod inventory;
pub(crate) mod lifecycle_output;
mod mesh_commands;
mod platform_commands;
pub(crate) mod project_file;
mod secrets;
mod sessions;
mod ssh_trust;
mod storage_placement;

pub(crate) use collaboration::*;
pub(crate) use core::*;
pub(crate) use current_environment::{handle_current_command, handle_use_command};
pub(crate) use environment::*;
pub(crate) use export::handle_export;
#[cfg(test)]
pub(crate) use flat::env_operation;
pub(crate) use flat::{HelpArgs, RetiredEnvArgs};
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
