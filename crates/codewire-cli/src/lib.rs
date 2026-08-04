pub mod config;
mod console_client;
mod environment_client;
mod github_device;
mod mesh;
mod organization_client;
mod presentation;
mod secret_client;
mod tailnet_ssh;
mod terminal_attach;
mod update;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use codewire_client::{
    ApiKey, AuthUser as PlatformUser, CreateApiKeyRequest, OAuthClient, OAuthCredentials,
    OAuthUserInfo,
};
use config::{OsEnv, ResolvePaths};
use console_client::{BillingOverview, ConsoleClient, GitHubStatus, SaveGitHubToken};
use environment_client::{CreateEnvironmentPortRequest, EnvironmentClient, EnvironmentPort};
use mesh::{Invite, MeshClient, Network, Node, NodeEnrollment, RedeemedNodeEnrollment};
use organization_client::{
    CreateInvitationRequest, CreateOrgRequest, CreatePresetRequest, OrgWithRole,
    OrganizationClient, OrganizationDeletionOutcome, OrganizationDeletionStart, Preset,
};
use presentation::{
    CreateEnvironmentRequest, Environment, EnvironmentAccessGrant, EnvironmentDaemonDiagnostic,
    EnvironmentDaemonRepair, EnvironmentDaemonStatus, EnvironmentLog, EnvironmentResizeResources,
    EnvironmentTrustReport, ExtendTtlRequest, GrantEnvironmentAccessRequest,
    PrepareEnvironmentRequest, RepoEntry, SetupAgent, StatusResponse,
};
use rand::{RngCore, rngs::OsRng};
use secret_client::{CreateSecretProjectRequest, SecretClient, SecretMetadata, SecretProject};

const CLI_VERSION: &str = match option_env!("CODEWIRE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
const LOCAL_WORKSPACE_PATH: &str = "/workspace";
const LIMA_CONTAINER_NAME: &str = "cw-workspace";
const LIMA_DOCKER_SOCK_PATH: &str = "/var/run/docker.sock";
const LIMA_DOCKER_HOST_VALUE: &str = "unix:///var/run/docker.sock";
const DEFAULT_LOCAL_MESH_URL: &str = "http://127.0.0.1:18090";
const DEFAULT_LOCAL_MESH_LISTEN_ADDR: &str = "127.0.0.1:18090";
const DEFAULT_LOCAL_DERP_URL: &str = "http://127.0.0.1:18091";
const DEFAULT_LOCAL_DERP_LISTEN_ADDR: &str = "127.0.0.1:18091";
const LOCAL_RUNTIME_CLI_PATH: &str = "/usr/local/bin/cw";
const LIMA_RUNTIME_CLI_COPY_PATH: &str = "/tmp/codewire-cw-stage";
const LIMA_RUNTIME_CLI_STAGE_DIR: &str = "/var/lib/codewire";
const LIMA_RUNTIME_CLI_STAGE_PATH: &str = "/var/lib/codewire/cw";
const LOCAL_MESH_RUNTIME_FILE: &str = "mesh_runtime.json";
const LOCAL_MESH_LOG_FILE: &str = "codewire-mesh.log";
const LOCAL_DERP_LOG_FILE: &str = "codewire-derp.log";

#[derive(Debug, Parser)]
#[command(name = "cw", version = CLI_VERSION, about = "Codewire CLI")]
struct Cli {
    #[arg(short, long, global = true, help = "Platform server URL override")]
    server: Option<String>,
    #[arg(long, global = true, help = "Auth token override")]
    token: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug)]
struct Globals {
    server: Option<String>,
    token: Option<String>,
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
        long_about = "Connect to a Codewire server, sign in, choose or create a default organization, and optionally configure GitHub and SSH integration."
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
    #[command(about = "Manage GitHub connection for private repo access")]
    Github {
        #[command(subcommand)]
        command: GithubCommand,
    },
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
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },
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
    #[command(
        hide = true,
        about = "Run the managed environment daemon inside an environment"
    )]
    Daemon,
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
    let mut args = std::env::args().collect::<Vec<_>>();
    let invoked_as_daemon = args
        .first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(|program| program.to_str())
        .is_some_and(|program| matches!(program, "daemon" | "codewire-daemon"));
    if invoked_as_daemon {
        return codewire_daemon::run_entrypoint().await;
    }
    if let Some(program) = args.first_mut() {
        *program = "cw".to_string();
    }
    run_from(args).await
}

pub async fn run_from<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = args
        .into_iter()
        .map(Into::into)
        .collect::<Vec<std::ffi::OsString>>();
    if let Some(message) = legacy_cli_migration_error(&args) {
        anyhow::bail!("{message}");
    }
    let cli = Cli::parse_from(args);
    let globals = Globals {
        server: cli.server.clone(),
        token: cli.token.clone(),
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
        Command::Github { command } => handle_github_command(&globals, command).await,
        Command::Org { command } => handle_org_command(&globals, command).await,
        Command::ApiKeys { command } => handle_api_keys_command(&globals, command).await,
        Command::Preset { command } => handle_preset_command(&globals, command).await,
        Command::Secrets { command } => handle_secrets_command(&globals, command).await,
        Command::Network { command } => handle_network_command(&globals, command).await,
        Command::Mesh { command } => handle_mesh_command(&globals, command),
        Command::Daemon => codewire_daemon::run_entrypoint().await,
        Command::List(args) => handle_list_command(&globals, args).await,
        Command::Attach(args) => handle_attach_command(&globals, args).await,
        Command::Logs(args) => handle_logs_command(&globals, args).await,
    }
}

fn legacy_cli_migration_error(args: &[std::ffi::OsString]) -> Option<String> {
    let args = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>();
    let command_index = root_command_index(&args)?;
    let command = args[command_index].as_ref();

    let guidance = match command {
        "local" => "`cw local` was removed; use `cw env --local ...`",
        "exec" => "`cw exec` was removed; use `cw run [ENV] -- COMMAND`",
        "node" => {
            "`cw node` was removed; use `cw env daemon ...` for environment-daemon diagnostics or `cw network nodes` for Mesh inventory"
        }
        "hook" | "gateway" | "mcp-server" | "tasks" | "msg" | "request" | "reply" | "listen"
        | "subscribe" | "status" | "wait" | "kill" | "send" | "watch" | "inbox" | "access"
        | "group" => {
            "the host-owned session command was removed; use `cw run`, `cw list`, `cw attach`, and `cw logs` with an environment"
        }
        "run" => {
            let command_args = args[command_index + 1..]
                .iter()
                .take_while(|arg| arg.as_ref() != "--");
            if command_args.clone().any(|arg| arg.as_ref() == "--local") {
                "`cw run --local` was removed; use `cw run ENV -- COMMAND`"
            } else if command_args
                .clone()
                .any(|arg| arg.as_ref() == "--node" || arg.starts_with("--node="))
            {
                "`cw run --node` was removed; use `cw run ENV -- COMMAND`"
            } else {
                return None;
            }
        }
        "init" | "env" => {
            if args[command_index + 1..]
                .iter()
                .take_while(|arg| arg.as_ref() != "--")
                .any(|arg| arg.as_ref() == "--agent" || arg.starts_with("--agent="))
            {
                "`--agent` was renamed; use `--coding-agent`"
            } else {
                return None;
            }
        }
        "attach" | "list" | "logs"
            if args[command_index + 1..]
                .iter()
                .take_while(|arg| arg.as_ref() != "--")
                .filter(|arg| !arg.starts_with('-'))
                .any(|arg| arg.contains(':')) =>
        {
            "`node:session` locators were removed; pass `ENV SESSION`"
        }
        "attach" | "list" | "logs" => return None,
        _ => return None,
    };
    Some(guidance.to_string())
}

fn root_command_index(args: &[std::borrow::Cow<'_, str>]) -> Option<usize> {
    let mut index = 1;
    while index < args.len() {
        match args[index].as_ref() {
            "--server" | "--token" => index += 2,
            value if value.starts_with("--server=") || value.starts_with("--token=") => index += 1,
            value if value.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }
    None
}
