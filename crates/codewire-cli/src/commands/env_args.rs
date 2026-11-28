//! The arguments of `cw create` and of the commands that name one environment.

use super::*;

#[derive(Clone, Debug, Args)]
pub(crate) struct EnvCreateArgs {
    #[arg(skip)]
    pub(crate) guided: bool,
    #[arg(long = "type", value_enum, default_value_t = EnvironmentTypeArg::Sandbox,
        help = "Sandbox or explicitly trusted host execution")]
    pub(crate) environment_type: EnvironmentTypeArg,
    #[arg(value_name = "REPO_URL")]
    pub(crate) repo_urls: Vec<String>,
    #[arg(
        long = "preset",
        conflicts_with = "preset_id",
        help = "Preset slug (e.g. go, node, python)"
    )]
    pub(crate) preset_slug: Option<String>,
    #[arg(long = "preset-id", help = "Preset ID (exact)")]
    pub(crate) preset_id: Option<String>,
    #[arg(long, help = "Environment name")]
    pub(crate) name: Option<String>,
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = ["native", "cloud-hypervisor"],
        help = "Local runtime backend (native by default); requires --local"
    )]
    pub(crate) backend: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Local project directory, where the codewire.yaml search starts; used with --local"
    )]
    pub(crate) path: Option<PathBuf>,
    #[arg(
        long = "path-mode",
        value_enum,
        value_name = "MODE",
        help = "How --path becomes the workspace: mount (default, live and read-write: the VM can change anything in the folder, including Git hooks and settings that git on this machine later runs; use clone for untrusted code), copy (a one-time copy of the folder as it is now), clone (a one-time clone of the Git repository's committed state), or empty; requires --local. Overrides workspace.path_mode. With repositories in codewire.yaml, mount uses the checkouts already in the folder and clone (the default) clones them"
    )]
    pub(crate) path_mode: Option<PathModeArg>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Project YAML file to use instead of the nearest codewire.yaml; repeat to merge files in order (relative to --path for a local create)"
    )]
    pub(crate) file: Vec<PathBuf>,
    #[arg(
        long,
        conflicts_with = "file",
        help = "Use only the flags: do not read the nearest codewire.yaml"
    )]
    pub(crate) no_file: bool,
    #[arg(
        long,
        conflicts_with_all = ["file", "no_file"],
        help = "Do not merge the codewire.local.yaml beside the nearest codewire.yaml (a local create reads it by default)"
    )]
    pub(crate) no_local_file: bool,
    #[arg(
        long,
        value_name = "SPEC",
        help = "Local JSON spec file or '-' for stdin; requires --local"
    )]
    pub(crate) spec: Option<String>,
    #[arg(long, help = "Time to live (e.g. 1h, 30m)")]
    pub(crate) ttl: Option<String>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Stop the cloud sandbox, keeping its disk, after this long with no activity: 5m to 7d, on (6h) or off; overrides codewire.yaml idle_stop (default off)"
    )]
    pub(crate) idle_stop: Option<String>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Pause a standard cloud sandbox, keeping its processes, after this long with no activity: 5m to 7d, on (15m) or off; any use wakes it; overrides codewire.yaml idle_suspend (default off)"
    )]
    pub(crate) idle_suspend: Option<String>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Hibernate a standard cloud sandbox to its encrypted volume after this long with no activity: 5m to 7d, on (6h) or off; overrides codewire.yaml idle_hibernate (default off)"
    )]
    pub(crate) idle_hibernate: Option<String>,
    #[arg(
        long,
        value_name = "CPU",
        help = "CPU cores (for example 2, 0.5, or 500m; a local VM rounds up to whole cores)"
    )]
    pub(crate) cpu: Option<String>,
    #[arg(long, value_name = "QUANTITY", help = "Memory (for example 8GB)")]
    pub(crate) memory: Option<String>,
    #[arg(
        long,
        value_name = "QUANTITY",
        help = "Disk size (for example 160GB); cloud default 120GB, at most 200GB"
    )]
    pub(crate) disk: Option<String>,
    #[arg(
        long,
        value_name = "QUANTITY",
        conflicts_with = "no_docker",
        help = "Dedicated guest Docker data disk (default 8Gi); requires the native local backend"
    )]
    pub(crate) docker_disk: Option<String>,
    #[arg(
        long,
        conflicts_with = "docker_disk",
        help = "Disable the guest-local Docker daemon; requires the native local backend"
    )]
    pub(crate) no_docker: bool,
    #[arg(long, value_parser = ["standard", "confidential"], help = "Product isolation tier")]
    pub(crate) isolation: Option<String>,
    #[arg(
        long = "repo",
        help = "Git repository to clone (repeatable, URL[@branch][::/workspace/path]); replaces the file's repositories"
    )]
    pub(crate) repo_flags: Vec<String>,
    #[arg(long, help = "Branch to checkout")]
    pub(crate) branch: Option<String>,
    #[arg(
        long,
        help = "Container image (shorthand: workspace -> ghcr.io/codewiresh/workspace)"
    )]
    pub(crate) image: Option<String>,
    #[arg(long, help = "Install command")]
    pub(crate) install: Option<String>,
    #[arg(long, help = "Startup script")]
    pub(crate) startup: Option<String>,
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    #[arg(
        long,
        value_name = "PROFILE",
        help = "Credential profile, for example local:work or platform:work; otherwise uses codewire.yaml's profile, then your default profile"
    )]
    pub(crate) profile: Option<String>,
    #[arg(
        long,
        alias = "no-credentials",
        conflicts_with = "profile",
        help = "Create without a credential profile, even when codewire.yaml names one or you have a default"
    )]
    pub(crate) no_profile: bool,
    #[arg(long, value_name = "PROJECT", help = "Application-secret project")]
    pub(crate) secrets: Option<String>,
    #[arg(
        long,
        value_enum,
        help = "Include personal application secrets from this store"
    )]
    pub(crate) user_secrets: Option<StoragePlacementArg>,
    #[arg(
        long,
        help = "Include the current platform organization's application secrets"
    )]
    pub(crate) org_secrets: bool,
    #[arg(
        long,
        value_name = "NETWORK",
        help = "Join a Mesh network: cloud:NAME, local:NAME, or NAME on the selected Mesh"
    )]
    pub(crate) network: Option<String>,
    #[arg(long, help = "Do not join the selected private mesh network")]
    pub(crate) no_network: bool,
    #[arg(
        long,
        value_name = "POLICY",
        help = "Network policy for outbound connections: open (the default, any TCP port), web (TCP 22, 80 and 443), locked, or a policy from `cw policy`; a cloud deployment enforces it only where its hosted egress is on. Unrelated to --network, which joins a Mesh network"
    )]
    pub(crate) policy: Option<policy::PolicyName>,
    #[arg(short, long, default_value_t = true, help = "Watch startup progress")]
    pub(crate) follow: bool,
    #[arg(
        long,
        help = "Return immediately after creation instead of waiting for startup"
    )]
    pub(crate) no_wait: bool,
    #[arg(short, long, help = "Skip confirmation prompts")]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(
        long,
        help = "Write the resolved preset to ./codewire.yaml after creation"
    )]
    pub(crate) write_preset: bool,
    #[arg(long = "save-preset", help = "Save the resolved preset to the server")]
    pub(crate) save_preset: Option<String>,
    #[arg(
        long,
        value_name = "SNAPSHOT",
        group = "restore_source",
        help = "Start from a disk snapshot (`cw snapshot`; with --cloud, a hosted one and its disk only) instead of provisioning: its image, workspace and disks, with fresh identity"
    )]
    pub(crate) snapshot: Option<String>,
    #[arg(
        long = "on",
        value_name = "host:NAME",
        conflicts_with_all = ["snapshot", "checkpoint"],
        help = "Run the environment on an enrolled host of your organization (`cw hosts`) instead of the platform; hosts are a preview"
    )]
    pub(crate) on: Option<String>,
    #[arg(
        long,
        value_name = "CHECKPOINT",
        group = "restore_source",
        help = "Fork a local VM checkpoint (`cw checkpoint`): a running copy of the VM at its instant, processes included, with fresh identity; local VMs only"
    )]
    pub(crate) checkpoint: Option<String>,
    #[arg(
        long,
        requires = "checkpoint",
        help = "With --checkpoint, fork it once although its disk may hold a sign-in from before its VM's disk was cleared (sign the provider out first); not for a VM on a platform profile"
    )]
    pub(crate) start_with_uncleared_disk: bool,
    #[arg(
        long,
        value_name = "N",
        requires = "restore_source",
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=16),
        help = "With --snapshot or --checkpoint, how many environments to create (named NAME-1, NAME-2, ... unless --name-prefix)"
    )]
    pub(crate) count: u32,
    #[arg(
        long,
        value_name = "PREFIX",
        requires = "restore_source",
        conflicts_with = "name",
        help = "With --snapshot, name the environments PREFIX-1, PREFIX-2, ..."
    )]
    pub(crate) name_prefix: Option<String>,
    #[arg(
        long,
        requires = "restore_source",
        help = "With --snapshot, mount the snapshot source's direct host folders again, shared live with it"
    )]
    pub(crate) share_mounts: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnvTargetArgs {
    #[arg(value_name = "ID_OR_NAME")]
    pub(crate) environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

/// `cw start`'s arguments: one environment, and for a local VM the one-start
/// override of an uncleared state disk (#6277).
#[derive(Debug, Args)]
pub(crate) struct EnvStartArgs {
    #[command(flatten)]
    pub(crate) target: EnvTargetArgs,
    #[arg(
        long,
        help = "A local VM only: start it once although its disk could not be cleared of a sign-in from a boot without agent interception (sign the provider out first); not for a VM on a platform profile"
    )]
    pub(crate) start_with_uncleared_disk: bool,
}

impl EnvStartArgs {
    /// The same start of `environment`.
    pub(crate) fn of(self, environment: String) -> Self {
        Self {
            target: EnvTargetArgs {
                environment,
                ..self.target
            },
            ..self
        }
    }
}

impl From<EnvTargetArgs> for EnvStartArgs {
    fn from(target: EnvTargetArgs) -> Self {
        Self {
            target,
            start_with_uncleared_disk: false,
        }
    }
}

impl std::ops::Deref for EnvStartArgs {
    type Target = EnvTargetArgs;

    fn deref(&self) -> &EnvTargetArgs {
        &self.target
    }
}
