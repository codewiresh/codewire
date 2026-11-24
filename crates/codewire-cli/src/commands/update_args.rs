//! The arguments of `cw update ENV`.

use std::path::PathBuf;

use clap::Args;

use super::{OutputFormat, StoragePlacementArg, policy};

#[derive(Debug, Args)]
pub(crate) struct EnvUpdateArgs {
    /// Filled from the `cw update` ENV positional or `--in ENV`.
    #[arg(skip)]
    pub(crate) environment: String,
    #[arg(
        long,
        value_name = "PROJECT",
        help = "Select this application-secret project"
    )]
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
    #[arg(long, conflicts_with_all = ["secrets", "user_secrets", "org_secrets"], help = "Clear every selected application-secret source")]
    pub(crate) clear_secrets: bool,
    #[arg(
        long,
        conflicts_with = "clear_profile",
        help = "Select this credential profile"
    )]
    pub(crate) profile: Option<String>,
    #[arg(long, help = "Clear the selected credential profile")]
    pub(crate) clear_profile: bool,
    #[arg(
        long,
        value_name = "POLICY",
        help = "Select the network policy for outbound connections: open, web, locked, or a policy from `cw policy`. Unrelated to Mesh networks"
    )]
    pub(crate) policy: Option<policy::PolicyName>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Stop the cloud sandbox, keeping its disk, after this long with no activity: 5m to 7d, on (6h) or off; takes effect without a restart"
    )]
    pub(crate) idle_stop: Option<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Give a cloud Sandbox this codewire.yaml's startup_script, which runs at its next start; every other setting must already match. Repeat to merge files in order, as `cw create` does"
    )]
    pub(crate) file: Vec<PathBuf>,
    #[arg(short, long, help = "Apply without the confirmation prompt")]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
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
