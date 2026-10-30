mod build_record;
pub mod config;
mod console_client;
mod environment_client;
#[cfg(target_os = "linux")]
mod hosted_access;
#[cfg(unix)]
mod hosted_binding;
mod hosted_exec;
mod local_runtime_pin;
mod mesh;
mod organization_client;
mod output;
#[cfg(target_os = "linux")]
mod platform_cw_runtime;
mod presentation;
mod public_fetch;
mod secret_client;
mod tailnet_ssh;
mod terminal_attach;
mod update;

pub use hosted_exec::run_hosted_exec_from;
#[cfg(target_os = "linux")]
pub use platform_cw_runtime::redirect_from as redirect_platform_cw_default_from;
#[cfg(target_os = "linux")]
pub use platform_cw_runtime::run_from as run_platform_cw_runtime_from;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use codewire_client::{
    ApiKey, AuthUser as PlatformUser, CreateApiKeyRequest, OAuthClient, OAuthCredentials,
    OAuthUserInfo,
};
use config::{OsEnv, ResolvePaths};
use console_client::{BillingOverview, ConsoleClient};
use environment_client::{CreateEnvironmentPortRequest, EnvironmentClient, EnvironmentPort};
use mesh::{MeshClient, Node, RedeemedNodeEnrollment};
use organization_client::{
    CreateInvitationRequest, CreateOrgRequest, CreatePresetRequest, OrgWithRole,
    OrganizationClient, OrganizationDeletionOutcome, OrganizationDeletionStart, Preset,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use presentation::EnvironmentDaemonRepair;
use presentation::{
    CreateEnvironmentRequest, Environment, EnvironmentAccessGrant, EnvironmentDaemonStatus,
    EnvironmentLog, EnvironmentResizeResources, EnvironmentTrustReport, ExtendTtlRequest,
    GrantEnvironmentAccessRequest, PrepareEnvironmentRequest, StatusResponse,
};
use secret_client::{CreateSecretProjectRequest, SecretClient, SecretMetadata, SecretProject};

// The effective compiled version: `CODEWIRE_VERSION` when the build set it,
// otherwise the workspace version, read from this cw's embedded build record.
use build_record::CLI_VERSION;

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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn is_local_git_ssh_helper(program: &std::ffi::OsStr) -> bool {
    std::path::Path::new(program).file_name()
        == Some(std::ffi::OsStr::new(
            codewire_local_credentials::SSH_HELPER_BASENAME,
        ))
}

/// Execute fixed stock SSH under the isolated repository's captured parent,
/// pinned public host trust and selected agent. No normal configuration loads.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
#[command(
    name = "cw",
    version = CLI_VERSION,
    about = "Codewire CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(short, long, global = true, help = "Platform server URL override")]
    server: Option<String>,
    #[arg(
        long,
        global = true,
        conflicts_with = "server",
        help = "Pinned trusted host member"
    )]
    member: Option<String>,
    /// The one placement source every command reads (`Globals::placement`).
    /// Accepted before or after the command; never declared again by a
    /// subcommand, so no second `--local` exists to collide with it.
    #[arg(
        long,
        global = true,
        help = "Target local environments (credentials and secrets: local storage)"
    )]
    local: bool,
    #[arg(
        long,
        global = true,
        help = "Target cloud environments (credentials and secrets: cloud storage)"
    )]
    cloud: bool,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    /// The explicit placement. Clap checks conflicts only within one parse
    /// level, while a global's values reach the root from any level, so
    /// `cw --local ls --cloud` is refused here.
    fn placement(&self) -> anyhow::Result<Option<EnvironmentPlacement>> {
        match (self.local, self.cloud) {
            (true, true) => {
                anyhow::bail!("--local and --cloud select different placements; pass only one")
            }
            (true, false) => Ok(Some(EnvironmentPlacement::Local)),
            (false, true) => Ok(Some(EnvironmentPlacement::Platform)),
            (false, false) => Ok(None),
        }
    }
}

/// Help sections in display order. Each visible command belongs to exactly
/// one section. `cw --help` shows the everyday sections; `cw help --all`
/// shows every section. A command missing here still appears under "Other".
const HELP_SECTIONS: &[HelpSection] = &[
    HelpSection::everyday("Get started", &["setup", "run", "login"]),
    HelpSection::everyday(
        "Environments",
        &[
            "ls", "info", "create", "start", "stop", "restart", "rm", "use", "current", "snapshot",
        ],
    ),
    HelpSection::everyday(
        "Work and return",
        &["attach", "shell", "vscode", "logs", "msg", "inbox", "ports"],
    ),
    HelpSection::everyday(
        "Configuration and transfer",
        &[
            "init",
            "update",
            "export",
            "cp",
            "credentials",
            "secrets",
            "policy",
        ],
    ),
    HelpSection::everyday("Codewire", &["upgrade", "doctor", "help"]),
    HelpSection::full(
        "Account and organization",
        &["logout", "whoami", "org", "api-keys", "cost"],
    ),
    HelpSection::full("Session controls", &["send", "wait", "interrupt", "steer"]),
    HelpSection::full(
        "Environment administration",
        &[
            "resize",
            "extend",
            "report",
            "access",
            "share",
            "protect",
            "unprotect",
            "cancel-delete",
            "prune",
            "nuke",
            "refresh-skills",
        ],
    ),
    HelpSection::full("Reusable setup", &["preset"]),
    HelpSection::full("Environment runtime", &["runtime", "daemon", "agent"]),
    HelpSection::full(
        "Mesh and host delegation",
        &["network", "mesh", "control", "member"],
    ),
    HelpSection::full("CLI administration", &["install", "config", "completion"]),
];

struct HelpSection {
    heading: &'static str,
    commands: &'static [&'static str],
    /// Shown by `cw --help`; otherwise only by `cw help --all`.
    everyday: bool,
}

impl HelpSection {
    const fn everyday(heading: &'static str, commands: &'static [&'static str]) -> Self {
        Self {
            heading,
            commands,
            everyday: true,
        }
    }

    const fn full(heading: &'static str, commands: &'static [&'static str]) -> Self {
        Self {
            heading,
            commands,
            everyday: false,
        }
    }
}

/// The top-level command with its commands grouped into [`HELP_SECTIONS`]:
/// the everyday sections, or every section for `cw help --all`. Descriptions
/// come from the commands themselves, so the help cannot drift.
fn cli_command() -> clap::Command {
    cli_command_with(false)
}

fn cli_command_with(all: bool) -> clap::Command {
    let command = Cli::command();
    let visible: Vec<(String, String, String)> = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| {
            let about = subcommand
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            let name = subcommand.get_name().to_owned();
            let label = std::iter::once(name.as_str())
                .chain(subcommand.get_visible_aliases())
                .collect::<Vec<_>>()
                .join(", ");
            (name, label, about)
        })
        .collect();
    let width = visible
        .iter()
        .map(|(_, label, _)| label.len())
        .max()
        .unwrap_or(0);
    let mut sections = String::new();
    let mut listed = std::collections::HashSet::new();
    let mut section =
        |heading: &str, names: &mut dyn Iterator<Item = &(String, String, String)>| {
            let mut body = String::new();
            for (_, label, about) in names {
                body.push_str(&format!("  {label:<width$}  {about}\n"));
            }
            if !body.is_empty() {
                sections.push_str(&format!("{heading}:\n{body}\n"));
            }
        };
    for help_section in HELP_SECTIONS {
        listed.extend(help_section.commands.iter().copied());
        if !all && !help_section.everyday {
            continue;
        }
        let mut members = help_section
            .commands
            .iter()
            .filter_map(|name| visible.iter().find(|(candidate, _, _)| candidate == name));
        section(help_section.heading, &mut members);
    }
    let mut other = visible
        .iter()
        .filter(|(name, _, _)| !listed.contains(name.as_str()));
    section("Other", &mut other);
    let more = if all {
        ""
    } else {
        "`cw help --all` lists every command; `cw help COMMAND` shows one command.\n\n"
    };
    command.help_template(format!(
        "{{before-help}}{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{sections}{more}Options:\n{{options}}{{after-help}}"
    ))
}

#[derive(Clone, Debug)]
struct Globals {
    server: Option<String>,
    member: Option<String>,
    /// `--local` or `--cloud`, read by every command that accepts one.
    placement: Option<EnvironmentPlacement>,
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
    #[command(about = "Diagnose installation and environment problems")]
    Doctor(DoctorArgs),
    #[command(about = "Upgrade the CLI, inspect versions, or roll back")]
    Upgrade(update::UpgradeArgs),
    #[command(about = "Install this cw as a managed, versioned installation")]
    Install(update::InstallArgs),
    #[command(about = "Sign in to Codewire")]
    Login(LoginArgs),
    #[command(
        about = "Set up Codewire, the local runtime, and SSH integration",
        long_about = "Connect to a Codewire server, sign in, choose or create a default organization, and configure OpenSSH integration.\n\nWith --local, install and verify the local VM runtime instead of signing in. `cw setup ssh` writes only the OpenSSH integration."
    )]
    Setup(SetupArgs),
    #[command(about = "Sign out of Codewire")]
    Logout,
    #[command(about = "Show current user and server")]
    Whoami(WhoamiArgs),
    #[command(
        about = "Select the current environment; without ENV, choose from a list",
        long_about = "Select the current environment, which commands use when no environment is named.\n\nWith ENV, select it by name or ID; --local or --cloud says where to look when a name exists in both. Without ENV, choose from a searchable list of local and cloud environments (--local or --cloud filters it): arrow keys move, typing filters, Enter selects, Escape cancels without changing the selection. Selecting a stopped environment does not start it. Outside an interactive terminal, ENV is required."
    )]
    Use(UseTargetArgs),
    #[command(about = "Show the current environment")]
    Current(CurrentTargetArgs),
    #[command(
        about = "Write a codewire.yaml project file",
        long_about = "Initialize codewire.yaml from direct environment flags.\n\nExamples:\n  cw init\n  cw init --image workspace --install \"pnpm install\" --startup \"pnpm dev\""
    )]
    Init(InitArgs),
    #[command(
        about = "Open a running environment in VS Code",
        long_about = "Open VS Code connected to a running environment via Remote-SSH, through its `cw-cloud-<id>` alias, or `cw-local-<id>` for a local VM. Ensures your SSH config is up to date before launching VS Code with the vscode:// URI scheme.\n\nExamples:\n  cw vscode app\n  cw --local vscode my-vm --folder /workspace/my-repo\n\nA local VM must be running, and created by this cw: Remote-SSH reaches its server through port forwarding, which an older VM runtime refuses."
    )]
    Vscode(VscodeArgs),
    #[command(
        about = "Open a shell session in the selected or named environment",
        long_about = "Open a login shell in a new session:\n  cw shell ENV\n  cw shell --in ENV\n  cw shell                         (in the selected environment)\n\nDetach with Ctrl-B, then D; the shell keeps running. Reconnect with `cw attach ENV --session SESSION`."
    )]
    Shell(EnvironmentShellArgs),
    #[command(name = "ssh", hide = true, about = "OpenSSH integration helpers")]
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    #[command(
        about = "Open claude or codex in an environment, or run a command",
        long_about = "Open an agent's own terminal UI in a new session:\n  cw run claude --in ENV [--name SESSION] [-- AGENT_ARGS]\n  cw run codex                     (in the selected environment)\n  cw run                           (asks which agent)\n\nRun a command in a new session:\n  cw run --in ENV [--env KEY=VALUE] -- npm test\n\nStart a managed conversation (queued messages and recorded results):\n  cw run --in ENV --agent claude --name review --detach [--prompt TEXT]\n\nAGENT is only claude or codex; an environment is named with --in, so one called claude is `--in claude`. --name names the new session and never reuses one. Detach with Ctrl-B, then D; reconnect with `cw attach ENV --session SESSION`."
    )]
    Run(EnvironmentRunArgs),
    #[cfg(unix)]
    #[command(name = "_host-daemon", hide = true)]
    HostDaemon(HostDaemonArgs),
    #[command(
        about = "Write acknowledged input to a terminal or command session",
        long_about = "Write text, then a newline, to a session's terminal:\n  cw send ENV --session SESSION TEXT [--no-newline]\n  cw send --session SESSION TEXT   (in the selected environment)\n\nSend one key instead of text:\n  cw send ENV --session SESSION --key ctrl-c"
    )]
    Send(SendArgs),
    #[command(
        about = "Wait for a session or managed message to finish",
        long_about = "Wait for a session to finish, printing its output:\n  cw wait ENV --session SESSION\n  cw wait --session SESSION        (in the selected environment)\n\nWait for a managed message's result; its ID names its session:\n  cw wait --message MESSAGE_ID"
    )]
    Wait(WaitArgs),
    #[command(
        about = "Stop an environment; --session stops one session",
        long_about = "Stop a whole environment:\n  cw stop ENV\n\nStop one session, asking before stopping its running children:\n  cw stop ENV --session SESSION\n  cw stop --session SESSION        (in the selected environment)\n\n--all, with --session, also stops every running descendant without asking."
    )]
    Stop(StopArgs),
    #[command(
        about = "Restart a local environment, or one session with --session",
        long_about = "Restart a whole local environment (cloud environments restart sessions only):\n  cw restart ENV\n\nRestart one retained session with its canonical identity:\n  cw restart ENV --session SESSION\n  cw restart --session SESSION     (in the selected environment)"
    )]
    Restart(SessionScopeArgs),
    #[cfg(unix)]
    #[command(
        about = "Send text to a session: typed into its terminal, or a managed message",
        long_about = "Send text to a session:\n  cw msg ENV --session SESSION TEXT\n  cw msg --session SESSION TEXT      (in the selected environment)\n\nA terminal session receives the text and Enter through its terminal input, and cw reports the write, not what the program did with it. A managed agent conversation (started with `cw run --agent`) receives a durable message; cw prints its ID and state, and `cw wait --message ID` waits for its result."
    )]
    Msg(AgentMessageArgs),
    #[cfg(unix)]
    #[command(about = "Steer the current turn of a managed agent")]
    Steer(AgentMessageArgs),
    #[cfg(unix)]
    #[command(
        about = "Interrupt the current managed agent turn",
        long_about = "Interrupt a managed conversation's running task:\n  cw interrupt ENV --session SESSION\n  cw interrupt --session SESSION   (in the selected environment)"
    )]
    Interrupt(SessionSelectorArgs),
    #[cfg(unix)]
    #[command(
        about = "Show a managed conversation's messages and results",
        long_about = "Show a managed agent conversation's messages and results:\n  cw inbox ENV --session SESSION\n\nA terminal session has no structured inbox; read it with `cw logs ENV --session SESSION` or `cw attach ENV --session SESSION`."
    )]
    Inbox(InboxArgs),
    #[cfg(unix)]
    #[command(name = "_agent-driver", hide = true)]
    AgentDriver(AgentDriverArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "_agent-control", hide = true)]
    AgentControl(AgentControlArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "_agent-peer", hide = true)]
    AgentPeer(AgentPeerArgs),
    /// Retired `env` namespace: only the updater hand-off is accepted;
    /// anything else is refused with its flat spelling (`commands/flat.rs`).
    #[command(name = "env", hide = true, disable_help_flag = true)]
    Env(RetiredEnvArgs),
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
        about = "Manage network policies: which destinations an environment may reach",
        long_about = "Manage network policies: which destinations an environment may reach.\n\nA network policy is named and reusable, and every edit makes a new revision. `open` (every public destination on TCP 22, 80 and 443) and `locked` (nothing) are built in. This is not `cw network`, which manages Mesh networks."
    )]
    Policy(PolicyArgs),
    #[command(
        about = "Save, list and remove local disk snapshots of stopped VMs",
        long_about = "Save, list and remove local disk snapshots.\n\nA disk snapshot is a reusable copy of a stopped local VM's disks on this host (Linux), made in about a second where the filesystem shares blocks between files. Start environments from one with `cw create --local --snapshot NAME [--count N]`; each gets fresh identity.\n\n  cw stop app\n  cw snapshot create app --name good-toolchain\n  cw create --local --snapshot good-toolchain --count 3\n  cw snapshot ls\n  cw snapshot rm good-toolchain"
    )]
    Snapshot(SnapshotArgs),
    #[command(
        hide = true,
        about = "Save, list and remove VM checkpoints of running local VMs",
        long_about = "Save, list and remove VM checkpoints.\n\nA VM checkpoint saves a running local VM's memory, device state and disks at one instant, on this host (Linux). It holds everything the VM's memory held and is never exported.\n\n  cw checkpoint create app --name before-refactor\n  cw checkpoint ls\n  cw checkpoint inspect before-refactor\n  cw checkpoint rm before-refactor"
    )]
    Checkpoint(CheckpointArgs),
    #[command(
        alias = "networks",
        about = "Manage Mesh networks for environments and nodes",
        long_about = "Manage Mesh networks for environments and nodes.\n\nChoose the Mesh with the global --cloud (Codewire Cloud Mesh, your platform's hosted Mesh) or --local (the local Mesh service from `cw mesh up`), or one endpoint with --mesh-url. Without them, the selected network's Mesh is used, else the one Mesh available. Every result names the Mesh, its endpoint and the organization."
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
    #[cfg(target_os = "linux")]
    #[command(about = "Manage trusted Mesh access to a local host (Linux only)")]
    Control(HostControlArgs),
    #[cfg(target_os = "linux")]
    #[command(about = "Manage pinned trusted host members (Linux only)")]
    Member(MemberArgs),
    #[cfg(not(target_os = "linux"))]
    #[command(about = "Manage trusted Mesh access to a local host (Linux only)")]
    Control(UnavailableMemberControlArgs),
    #[cfg(not(target_os = "linux"))]
    #[command(about = "Manage pinned trusted host members (Linux only)")]
    Member(UnavailableMemberControlArgs),
    #[command(name = "__hosted-daemon", hide = true)]
    HostedDaemon,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-supervisor", hide = true)]
    NativeSupervisor(NativeSupervisorArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-runner", hide = true)]
    NativeRunner(NativeRunnerArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-network-worker", hide = true)]
    NativeNetworkWorker(NativeNetworkWorkerArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-egress-broker", hide = true)]
    NativeEgressBroker(NativeEgressBrokerArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-mesh-transport", hide = true)]
    NativeMeshTransport(NativeMeshTransportArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__native-mesh-enrollment-broker", hide = true)]
    NativeMeshEnrollmentBroker(NativeMeshEnrollmentBrokerArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__local-credential-authority", hide = true)]
    LocalCredentialAuthority(LocalCredentialAuthorityArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__local-credential-authority-probe", hide = true)]
    LocalCredentialAuthorityProbe(LocalCredentialAuthorityProbeArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__local-credential-broker", hide = true)]
    LocalCredentialBroker(LocalCredentialBrokerArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__environment-launch", hide = true)]
    EnvironmentLaunch(EnvironmentLaunchArgs),
    #[cfg(target_os = "linux")]
    #[command(name = "__local-credential-broker-confinement-probe", hide = true)]
    LocalCredentialBrokerConfinementProbe,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__local-git-repository-executor", hide = true)]
    LocalGitRepositoryExecutor(LocalGitRepositoryExecutorArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(name = "__local-git-credential-helper", hide = true)]
    LocalGitCredentialHelper(LocalGitCredentialHelperArgs),
    #[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
    #[command(name = "__local-credential-broker-synthetic-smoke-check", hide = true)]
    LocalCredentialBrokerSyntheticSmokeCheck,
    #[command(
        name = "ls",
        visible_alias = "list",
        about = "List environments, or sessions in one environment"
    )]
    Ls(ListArgs),
    #[command(
        about = "Attach to a session in an environment",
        long_about = "Attach to a running session's terminal:\n  cw attach ENV --session SESSION\n  cw attach --session SESSION      (in the selected environment)\n  cw attach ENV                    (its only session, or a choice; scripts name --session)\n\nDetach with Ctrl-B, then D; the session keeps running."
    )]
    Attach(AttachArgs),
    #[command(
        about = "Show session output with --session, or setup logs with --setup",
        long_about = "Show a session's saved output, or how an environment was set up:\n  cw logs ENV --session SESSION [--follow]\n  cw logs --session SESSION        (in the selected environment)\n  cw logs ENV --setup [--follow]   (cloud environments)\n\n--setup shows how the environment was set up: provisioning, repository clones, and the install and startup steps.\n\nWithout --session or --setup, an interactive call selects the environment's only session or offers a choice; scripts must name one."
    )]
    Logs(LogsArgs),
    #[command(about = "Show configuration, state, and connection details")]
    Info(EnvInfoArgs),
    #[command(
        about = "Write an environment's saved configuration as codewire.yaml",
        long_about = "Write an environment's saved configuration as codewire.yaml:\n  cw export ENV                    (writes ./codewire.yaml)\n  cw export ENV --file PATH\n  cw export --in ENV --stdout\n\nThe file names repositories, setup commands, resources, ports, agents, and secret and credential references; it never holds their values or declared environment values. An existing file is kept unless --force. Export never starts or changes the environment, and reports what the file leaves out or applies only to this placement."
    )]
    Export(ExportArgs),
    #[command(
        about = "Create an environment without launching an agent",
        long_about = "Create a new environment from the nearest codewire.yaml and direct CLI flags; flags win over the file.\n\nThe search starts in the current directory (--path for --local) and goes up to the root of its Git repository; outside a Git repository only that directory is checked. --file selects another file. The create shows which configuration it uses before it starts.\n\nMultiple repos can be specified as positional args or with --repo flags, on both placements; each is cloned into its own path, and they replace the file's repositories.\nUse URL[@branch][::/workspace/path] to set a branch and optional checkout path per repo.\n\nWith --local, create a local VM; with --cloud, a cloud environment. Starting an existing environment uses its saved configuration, never a changed file."
    )]
    Create(Box<EnvCreateArgs>),
    #[command(about = "Start an environment")]
    Start(EnvTargetArgs),
    #[command(about = "Remove an environment")]
    Rm(EnvDeleteArgs),
    #[command(
        about = "Change an environment's application secrets and credential profile",
        long_about = "Change the application secrets and credential profile selected for an environment:\n  cw update ENV --profile local:work\n  cw update --in ENV --clear-secrets\n\nTo upgrade the CLI itself, use `cw upgrade`."
    )]
    Update(UpdateEnvironmentArgs),
    #[command(
        about = "Copy a file to or from an environment",
        long_about = "Copy files between the local filesystem and an environment.\n\nUse ENV:PATH for the environment side:\n  cw cp local.txt ENV:/workspace/local.txt\n  cw cp ENV:/workspace/file.txt ./file.txt"
    )]
    Cp(EnvCpArgs),
    #[command(
        about = "List ports; --publish or --unpublish changes a mapping",
        long_about = "List an environment's published ports, or change one mapping:\n  cw ports ENV\n  cw ports ENV --publish 3000 [--host-port 3001]          (local: 127.0.0.1 on this host)\n  cw ports ENV --publish 3000 [--label web] [--access creator]   (cloud: a preview URL)\n  cw ports ENV --unpublish 3000\n\nListing never starts an environment; publishing needs a running one."
    )]
    Ports(PortsArgs),
    #[command(about = "Inspect or change the cw defaults in a running environment")]
    Runtime(EnvRuntimeArgs),
    #[command(about = "Inspect cloud managed agent support and saved requests")]
    Agent(EnvAgentArgs),
    #[command(about = "Inspect or repair an environment's managed daemon")]
    Daemon(EnvDaemonArgs),
    #[command(about = "Resize a local or cloud environment")]
    Resize(EnvResizeArgs),
    #[command(about = "Show isolation, runtime, and trust evidence (cloud)")]
    Report(EnvReportArgs),
    #[command(about = "Extend a cloud environment's TTL")]
    Extend(EnvExtendArgs),
    #[command(about = "Inspect or apply an environment access profile")]
    Access(EnvAccessArgs),
    #[command(about = "Manage cloud environment collaborators")]
    Share(EnvShareArgs),
    #[command(about = "Protect a cloud environment from deletion")]
    Protect(EnvTargetArgs),
    #[command(about = "Remove deletion protection from a cloud environment")]
    Unprotect(EnvTargetArgs),
    #[command(
        name = "cancel-delete",
        about = "Cancel a pending cloud environment deletion"
    )]
    CancelDelete(EnvTargetArgs),
    #[command(
        about = "Delete stale cloud environments",
        long_about = "Delete cloud environments stuck in error, creating, or pending states."
    )]
    Prune(EnvPruneArgs),
    #[command(
        about = "Delete ALL cloud environments",
        long_about = "Delete every environment in the current org. Requires typed confirmation unless --yes is passed."
    )]
    Nuke(EnvNukeArgs),
    #[command(
        name = "refresh-skills",
        about = "Refresh immutable skills for a local environment"
    )]
    RefreshSkills(EnvTargetArgs),
    #[command(about = "Show help for cw or one of its commands; --all lists every command")]
    Help(HelpArgs),
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
    if cli.server.is_some() || cli.member.is_some() || cli.local || cli.cloud {
        return Err(invalid());
    }
    codewire_daemon::execution::run_environment_launcher(&args.projection_socket, &args.command)
        .map_err(|_| invalid())
}

#[cfg(target_os = "linux")]
pub async fn run_host_member_helper_from(arguments: Vec<std::ffi::OsString>) -> anyhow::Result<()> {
    commands::run_host_member_helper(arguments).await
}

/// Fixed platform record helper. The binary dispatches it before ordinary
/// configuration, credential resolution, Mesh paths or mutable CW selection.
#[cfg(target_os = "linux")]
pub async fn run_platform_agent_control_from(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 1000 && unsafe { libc::getegid() } == 1000,
        "platform agent helper requires its ordinary owner"
    );
    anyhow::ensure!(
        arguments.len() == 2 && arguments[0] == "--environment",
        "invalid fixed platform agent arguments"
    );
    let environment = arguments[1]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid platform environment"))?;
    let id = uuid::Uuid::parse_str(environment)?;
    anyhow::ensure!(
        !id.is_nil() && id.to_string() == environment,
        "invalid platform environment"
    );
    // No registry, caller-selected root, command, URL, environment or token.
    commands::run_platform_agent_control(id.to_string()).await
}
#[cfg(target_os = "linux")]
pub async fn run_platform_agent_driver_from(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        arguments.len() == 4 && arguments[0] == "--environment" && arguments[2] == "--driver-id",
        "invalid fixed platform driver arguments"
    );
    let environment = arguments[1]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid platform environment"))?;
    let driver = arguments[3]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid platform driver"))?;
    commands::run_platform_agent_driver(environment.into(), driver.into()).await
}
#[cfg(target_os = "linux")]
pub async fn run_platform_agent_peer_from(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    commands::run_platform_agent_peer(arguments).await
}

#[cfg(target_os = "linux")]
pub async fn run_host_agent_control_from(arguments: Vec<std::ffi::OsString>) -> anyhow::Result<()> {
    commands::run_host_agent_control(arguments).await
}

/// A local credential authority that refused to take over its recorded
/// protected store exits with a status its starting client decodes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn local_credential_authority_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_credentials::AuthorityRuntimeError>()
        .and_then(codewire_local_credentials::authority_exit_code)
}

/// Preserve the fixed private worker failure taxonomy across the thin binary
/// wrapper. Ordinary CLI failures continue to use the generic exit status.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn native_network_worker_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::network_worker::NetworkWorkerError>()
        .map(codewire_local_vmm::network_worker::NetworkWorkerError::exit_code)
}

/// 130 when Ctrl-C ended a lifecycle wait (`cw start`, `cw create` and the
/// like): the error's text already says what continues in the background.
pub fn interrupted_exit_code(error: &anyhow::Error) -> Option<i32> {
    commands::lifecycle_output::interrupted_exit_code(error)
}

/// Preserve the fixed private broker failure taxonomy across the thin binary
/// wrapper without printing process-internal detail to ambient stderr.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn native_egress_broker_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::egress_broker::EgressBrokerProcessError>()
        .map(codewire_local_vmm::egress_broker::EgressBrokerProcessError::exit_code)
}

/// Preserve the fixed private Mesh-process failure taxonomy without printing
/// credential-adjacent process detail to ambient stderr.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn native_mesh_transport_exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<codewire_local_vmm::mesh_process::MeshTransportProcessError>()
        .map(codewire_local_vmm::mesh_process::MeshTransportProcessError::exit_code)
}

/// Preserve the fixed one-shot enrollment-issuer failure taxonomy without
/// exposing credential-adjacent detail on ambient stderr.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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

/// Delegated member control keeps custody of every process a member session
/// starts, including descendants whose parent has exited. Linux tracks that
/// family with pidfds and a subreaper. On macOS only a private libproc
/// record (the original parent's unique ID) survives reparenting to launchd,
/// and Codewire uses no private API, so a Mac host cannot be a member.
#[cfg(not(target_os = "linux"))]
const MEMBER_CONTROL_REQUIRES_LINUX: &str = "delegated member control (cw control, cw member, --member) requires Linux: macOS offers no public way to find a session's processes after their parent exits, which member control needs to stop them all; on a Mac, run sessions in a local VM (cw create --local) instead";

/// `cw control` and `cw member` are refused before their arguments are read.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, clap::Args)]
pub(crate) struct UnavailableMemberControlArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    _arguments: Vec<std::ffi::OsString>,
}

fn validate_member_mutation_flags(cli: &Cli) -> anyhow::Result<()> {
    if cli.member.is_none() {
        match &cli.command {
            Command::Stop(StopArgs { scope: args, .. }) | Command::Restart(args) => {
                anyhow::ensure!(
                    args.request_id.is_none() && args.expected_launch_generation.is_none(),
                    "member mutation flags require --member"
                )
            }
            Command::Interrupt(args) => anyhow::ensure!(
                args.request_id.is_none() && args.expected_launch_generation.is_none(),
                "member mutation flags require --member"
            ),
            Command::Inbox(args) => anyhow::ensure!(
                args.expected_launch_generation.is_none(),
                "member mutation flags require --member"
            ),
            Command::Msg(args) | Command::Steer(args) => anyhow::ensure!(
                args.request_id.is_none() && args.expected_launch_generation.is_none(),
                "member mutation flags require --member"
            ),
            _ => {}
        }
    }
    Ok(())
}

pub async fn run_from<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let mut command = cli_command();
    let matches = command.clone().get_matches_from(args.iter().cloned());
    let cli =
        Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.format(&mut command).exit());
    let placement = cli.placement()?;
    validate_placement_scope(
        &cli.command,
        matches.subcommand_name().unwrap_or_default(),
        placement,
        cli.member.is_some(),
    )?;
    validate_member_mutation_flags(&cli)?;
    if cli.member.is_some() {
        #[cfg(target_os = "linux")]
        anyhow::ensure!(
            matches!(
                &cli.command,
                Command::Run(_)
                    | Command::Ls(_)
                    | Command::Send(_)
                    | Command::Logs(_)
                    | Command::Wait(_)
                    | Command::Stop(_)
                    | Command::Restart(_)
                    | Command::Msg(_)
                    | Command::Steer(_)
                    | Command::Interrupt(_)
                    | Command::Inbox(_)
                    | Command::Member(_)
            ),
            "--member supports run, ls, send, logs, wait, stop, restart, msg, steer, interrupt, inbox and member commands"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!(MEMBER_CONTROL_REQUIRES_LINUX);
    }
    // Validate an explicitly selected Mesh state root before any ordinary
    // command effects, including routes that otherwise need only platform state.
    ResolvePaths::from_env(&OsEnv)?;
    let globals = Globals {
        server: cli.server.clone(),
        member: cli.member.clone(),
        placement,
    };
    match cli.command {
        Command::Config {
            command: ConfigCommand::Inspect { output },
        } => inspect_config(output),
        Command::Completion(args) => handle_completion_command(args),
        Command::Doctor(args) => handle_doctor_command(&globals, args).await,
        Command::Upgrade(args) => update::run(args).await,
        Command::Install(args) => update::install(args),
        Command::Login(args) => handle_login_command(&globals, args).await,
        Command::Setup(args) => handle_setup_command(&globals, args).await,
        Command::Logout => handle_logout_command(&globals).await,
        Command::Whoami(args) => handle_whoami_command(&globals, args).await,
        Command::Use(args) => handle_use_command(&globals, args).await,
        Command::Current(args) => handle_current_command(&globals, args).await,
        Command::Init(args) => handle_init_command(&globals, args).await,
        Command::Vscode(args) => handle_vscode_command(&globals, args).await,
        Command::Shell(args) => handle_environment_shell_command(&globals, args).await,
        Command::Ssh { command } => handle_ssh_command(&globals, command).await,
        Command::Run(args) => handle_environment_run_command(&globals, args).await,
        #[cfg(unix)]
        Command::HostDaemon(args) => run_host_daemon(args).await,
        Command::Send(args) => handle_send_command(&globals, args).await,
        Command::Wait(args) => handle_wait_command(&globals, args).await,
        Command::Stop(args) => flat::handle_stop(&globals, args).await,
        Command::Restart(args) => flat::handle_restart(&globals, args).await,
        #[cfg(unix)]
        Command::Msg(args) => handle_message_command(&globals, args, false).await,
        #[cfg(unix)]
        Command::Steer(args) => handle_message_command(&globals, args, true).await,
        #[cfg(unix)]
        Command::Interrupt(args) => handle_agent_interrupt_command(&globals, args).await,
        #[cfg(unix)]
        Command::Inbox(args) => handle_inbox_command(&globals, args).await,
        #[cfg(unix)]
        Command::AgentDriver(args) => run_agent_driver(args).await,
        #[cfg(target_os = "linux")]
        Command::AgentControl(args) => run_agent_control(args).await,
        #[cfg(target_os = "linux")]
        Command::AgentPeer(args) => run_agent_peer(args).await,
        Command::Env(retired) => flat::handle_retired_env(&args, placement, retired).await,
        Command::Cost(args) => handle_cost_command(&globals, args).await,
        Command::Org { command } => handle_org_command(&globals, command).await,
        Command::ApiKeys { command } => handle_api_keys_command(&globals, command).await,
        Command::Preset { command } => handle_preset_command(&globals, command).await,
        Command::Secrets(args) => handle_secrets_command(&globals, args).await,
        Command::Credentials(args) => handle_credentials_command(&globals, args).await,
        Command::Policy(args) => handle_policy_command(&globals, args).await,
        Command::Snapshot(args) => handle_snapshot_command(&globals, args).await,
        Command::Checkpoint(args) => handle_checkpoint_command(&globals, args).await,
        Command::Network { command } => handle_network_command(&globals, command).await,
        Command::Mesh { command } => handle_mesh_command(&globals, command).await,
        #[cfg(target_os = "linux")]
        Command::Control(args) => handle_host_control_command(&globals, args).await,
        #[cfg(target_os = "linux")]
        Command::Member(args) => handle_member_command(&globals, args).await,
        #[cfg(not(target_os = "linux"))]
        Command::Control(_) | Command::Member(_) => anyhow::bail!(MEMBER_CONTROL_REQUIRES_LINUX),
        Command::HostedDaemon => run_hosted_daemon().await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeSupervisor(args) => run_native_supervisor(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeRunner(args) => run_native_runner(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeNetworkWorker(args) => run_native_network_worker(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeEgressBroker(args) => run_native_egress_broker(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeMeshTransport(args) => run_native_mesh_transport(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::NativeMeshEnrollmentBroker(args) => run_native_mesh_enrollment_broker(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::LocalCredentialAuthority(args) => run_local_credential_authority(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::LocalCredentialAuthorityProbe(args) => {
            run_local_credential_authority_probe(args).await
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::LocalGitRepositoryExecutor(args) => run_local_git_repository_executor(args).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::LocalGitCredentialHelper(args) => run_local_git_credential_helper(args),
        #[cfg(all(target_os = "linux", feature = "local-broker-synthetic-smoke"))]
        Command::LocalCredentialBrokerSyntheticSmokeCheck => {
            println!("codewire-local-credential-broker-synthetic-smoke:v1");
            Ok(())
        }
        Command::Ls(args) => flat::handle_ls(&globals, args).await,
        Command::Attach(args) => handle_attach_command(&globals, args).await,
        Command::Logs(args) => flat::handle_logs(&globals, args).await,
        Command::Update(args) => flat::handle_update(&globals, args).await,
        Command::Ports(args) => flat::handle_ports(&globals, args).await,
        Command::Export(args) => handle_export(&globals, args).await,
        command @ (Command::Info(_)
        | Command::Create(_)
        | Command::Start(_)
        | Command::Rm(_)
        | Command::Cp(_)
        | Command::Runtime(_)
        | Command::Agent(_)
        | Command::Daemon(_)
        | Command::Resize(_)
        | Command::Report(_)
        | Command::Extend(_)
        | Command::Access(_)
        | Command::Share(_)
        | Command::Protect(_)
        | Command::Unprotect(_)
        | Command::CancelDelete(_)
        | Command::Prune(_)
        | Command::Nuke(_)
        | Command::RefreshSkills(_)) => {
            let operation = flat::direct_environment_command(command)
                .map_err(|_| anyhow::anyhow!("not an environment operation"))?;
            flat::operation(&globals, operation).await
        }
        Command::Help(args) => flat::handle_help(args),
    }
}

/// `--local` / `--cloud` reach every command through the one global pair.
/// A command that does not read a placement refuses it before any effect,
/// so an explicit placement is never ignored or reinterpreted.
fn validate_placement_scope(
    command: &Command,
    name: &str,
    placement: Option<EnvironmentPlacement>,
    member: bool,
) -> anyhow::Result<()> {
    let Some(placement) = placement else {
        return Ok(());
    };
    let flag = match placement {
        EnvironmentPlacement::Local => "--local",
        EnvironmentPlacement::Platform => "--cloud",
    };
    anyhow::ensure!(
        !member,
        "{flag} cannot be combined with --member, which names its pinned host target"
    );
    if let Command::Setup(SetupArgs {
        command: Some(SetupCommand::Ssh(_)),
        ..
    }) = command
    {
        anyhow::bail!("{flag} does not apply to `cw setup ssh`");
    }
    let reads = matches!(
        command,
        Command::Setup(_)
            | Command::Use(_)
            | Command::Credentials(_)
            | Command::Policy(_)
            | Command::Snapshot(_)
            | Command::Checkpoint(_)
            | Command::Secrets(_)
            | Command::Env(_)
            | Command::Run(_)
            | Command::Attach(_)
            | Command::Send(_)
            | Command::Wait(_)
            | Command::Shell(_)
            | Command::Vscode(_)
            | Command::Ls(_)
            | Command::Logs(_)
            | Command::Stop(_)
            | Command::Restart(_)
            | Command::Info(_)
            | Command::Export(_)
            | Command::Create(_)
            | Command::Start(_)
            | Command::Rm(_)
            | Command::Update(_)
            | Command::Cp(_)
            | Command::Ports(_)
            | Command::Runtime(_)
            | Command::Agent(_)
            | Command::Daemon(_)
            | Command::Resize(_)
            | Command::Report(_)
            | Command::Extend(_)
            | Command::Access(_)
            | Command::Share(_)
            | Command::Protect(_)
            | Command::Unprotect(_)
            | Command::CancelDelete(_)
            | Command::Prune(_)
            | Command::Nuke(_)
            | Command::RefreshSkills(_)
            // `cw --cloud ssh known-hosts`, as the `cw-cloud-*` block runs it.
            | Command::Ssh { .. }
            // --cloud: the platform's hosted Mesh; --local: the local Mesh service.
            | Command::Network { .. }
    );
    // The managed session controls and the environment a message or inbox
    // addresses exist only on Unix.
    #[cfg(unix)]
    let reads = reads
        || matches!(
            command,
            Command::Interrupt(_) | Command::Steer(_) | Command::Msg(_) | Command::Inbox(_)
        );
    anyhow::ensure!(reads, "{flag} does not apply to `cw {name}`");
    Ok(())
}

async fn run_hosted_daemon() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    // Info by default: binding, host-key and access failures must be visible
    // without RUST_LOG. Every daemon log line is value-blind.
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
    match codewire_daemon::HostedDaemonMode::from_env()? {
        codewire_daemon::HostedDaemonMode::EnvironmentToken(config) => {
            serve_hosted_daemon(*config, false, None, None, None, None).await
        }
        codewire_daemon::HostedDaemonMode::Binding(config) => run_bound_hosted_daemon(config).await,
    }
}

/// Identity-free Pod (Program #2238 B2): mark local readiness, bind, install
/// the bound credential, then prepare Codex's home and listen.
///
/// Nothing listens before an accepted binding: no TCP listener (the daemon's
/// 7777, SSH's 2222, the bridge's loopback 38081) and no UDP socket (the
/// tailnet's 31000). SSH on 2222 has `none` auth, so its NetworkPolicy is its
/// only authorization. The warm-pool template's NetworkPolicy admits
/// orchestration's identity to unbound members on TCP 7777 and 2222 from
/// birth (#3626). A listener there before the bind would hand a shell to
/// anyone holding that identity. `hosted_binding`'s `nothing_listens` tests
/// pin this.
#[cfg(unix)]
async fn run_bound_hosted_daemon(
    config: codewire_daemon::WorkspaceBindingConfig,
) -> anyhow::Result<()> {
    run_bound_hosted_daemon_with(
        config,
        codewire_daemon::hosted_state::HostedStatePaths::default(),
        hosted_binding::BindTiming::default(),
    )
    .await
}

/// [`run_bound_hosted_daemon`] with its state paths and binding pacing given,
/// so a test runs it unprivileged and fast. Production passes the defaults.
#[cfg(unix)]
async fn run_bound_hosted_daemon_with(
    config: codewire_daemon::WorkspaceBindingConfig,
    paths: codewire_daemon::hosted_state::HostedStatePaths,
    timing: hosted_binding::BindTiming,
) -> anyhow::Result<()> {
    paths
        .mark_ready()
        .context("write hosted daemon readiness marker")?;
    // A confidential workspace (B2c) trusts only its measured roots for the
    // binding listener, never the host-supplied mounted ones.
    let roots = match config.measured() {
        Some(measured) => hosted_binding::BindingRoots::Measured(measured.binding_roots_pem()),
        None => hosted_binding::BindingRoots::Mounted(config.tls_roots_file()),
    };
    tracing::info!(
        measured = config.measured().is_some(),
        "hosted environment daemon waiting for its workspace binding"
    );
    let client = std::sync::Arc::new(
        hosted_binding::BindingClient::new(
            config.binding_url(),
            roots,
            config.token_path(),
            timing,
        )
        .context("configure workspace binding client")?,
    );
    // Only the Linux access server distinguishes a measured daemon.
    #[cfg(target_os = "linux")]
    let measured = config.measured().is_some();
    let bound = hosted_binding::bind_until_accepted(&client, &config).await;
    paths
        .install_binding(&bound.binding)
        .context("install hosted daemon binding")?;
    // The binding was accepted for exactly this Pod.
    let pod_uid = config.pod_uid().to_owned();
    let daemon_config = config.into_config(&bound.binding);
    // The saved project defaults and Git author (#3684), before the access
    // task can record the host key: orchestration's access proof therefore
    // comes after this write. No defaults, as from an older server, reports
    // nothing, and setup writes them itself.
    let defaults = match &bound.defaults {
        Some(defaults) => Some(
            codewire_daemon::workspace_defaults::apply(
                &daemon_config,
                bound.binding.operation_generation(),
                defaults,
            )
            .await,
        ),
        None => None,
    };
    // Workspace access (#2460): the daemon serves SSH itself, reaching its
    // own gRPC service in-process, and the environment's application ports
    // on its tailnet address.
    let (connector, local) = codewire_daemon::local_transport::local_transport();
    let (app_ports, _) = tokio::sync::watch::channel(
        bound
            .access
            .as_ref()
            .map(|grant| grant.app_ports().clone())
            .unwrap_or_default(),
    );
    #[cfg(target_os = "linux")]
    {
        let (_access_shutdown, access_shutdown_rx) = tokio::sync::watch::channel(false);
        let daemon_port = daemon_config
            .listen_addr
            .parse::<std::net::SocketAddr>()
            .map(|address| address.port())
            .ok();
        let access = hosted_access::serve(
            paths.clone(),
            hosted_access::BoundAccess {
                environment_id: bound.binding.environment_id(),
                generation: bound.binding.operation_generation(),
                daemon_credential: bound.binding.daemon_credential().clone(),
                grant: bound.access.clone(),
                daemon_port,
                exec_shell: codewire_daemon::env::default_shell_for(&daemon_config),
                measured,
            },
            connector,
            client.clone(),
            app_ports.clone(),
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
    serve_hosted_daemon(
        daemon_config,
        true,
        Some(local),
        Some(app_ports),
        Some(pod_uid),
        defaults,
    )
    .await
}

/// Binding mode needs a Unix daemon. This one refuses before any effect, so
/// it never listens, bound or not (#3626).
#[cfg(not(unix))]
async fn run_bound_hosted_daemon(
    _config: codewire_daemon::WorkspaceBindingConfig,
) -> anyhow::Result<()> {
    anyhow::bail!("workspace binding requires a Unix hosted daemon")
}

/// What a bound daemon wrote before it served; no such thing without Unix.
#[cfg(unix)]
type HostedDefaultsOutcome = codewire_daemon::workspace_defaults::DefaultsOutcome;
#[cfg(not(unix))]
type HostedDefaultsOutcome = std::convert::Infallible;

async fn serve_hosted_daemon(
    config: codewire_daemon::Config,
    bound: bool,
    local: Option<codewire_daemon::local_transport::LocalDaemonIncoming>,
    app_ports: Option<codewire_daemon::app_ports::AppPortsSender>,
    pod_uid: Option<String>,
    defaults: Option<HostedDefaultsOutcome>,
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
    // the managed credential at once in any checked-out repository. Unless
    // the sign-in form is selected, it also removes Codewire's Claude login
    // from `~/.claude/.credentials.json`. A selection change restarts the
    // Sandbox.
    #[cfg(target_os = "linux")]
    codewire_daemon::claude_home::ClaudeHome::new(&config.home_root, &config.workspace_root)
        .prepare(config.managed_credential_clients);
    // Stock `gh` reaches the GitHub API route only through this daemon's Unix
    // ingress socket. While the GitHub client is selected, sessions are given
    // Codewire's own `gh` configuration directory; its one file is written
    // here, beside the sockets, and removed when GitHub is not selected.
    #[cfg(target_os = "linux")]
    codewire_daemon::gh_config::GhConfig::default().prepare(config.managed_credential_clients);
    // While the SSH key is selected, `~/.ssh/known_hosts` lists GitHub's
    // published host keys, so no `git@github.com` connection (Codewire's own
    // `git://` rewrite included) trusts a host key on first use.
    #[cfg(target_os = "linux")]
    codewire_daemon::ssh_known_hosts::SshKnownHosts::new(&config.home_root)
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
    // and Claude Code's own claude.ai login while the broker delivers them.
    #[cfg(target_os = "linux")]
    return match app_ports.zip(pod_uid) {
        // A bound daemon also accepts orchestration's application-port pushes.
        Some((app_ports, pod_uid)) => {
            codewire_daemon::serve_bound_hosted_grpc_with_incoming(
                config,
                &pod_uid,
                codewire_daemon::codex_home::CodexHome::default(),
                app_ports,
                defaults,
                incoming,
                hosted_daemon_shutdown_signal(),
            )
            .await
        }
        None => {
            codewire_daemon::serve_hosted_grpc_with_incoming(
                config,
                codewire_daemon::codex_home::CodexHome::default(),
                incoming,
                hosted_daemon_shutdown_signal(),
            )
            .await
        }
    };
    #[cfg(not(target_os = "linux"))]
    let _ = (app_ports, pod_uid, defaults);
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
