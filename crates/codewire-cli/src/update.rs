//! `cw upgrade` and `cw install --managed`.
//!
//! A managed installation keeps every admitted cw at an immutable digest path
//! in an ordinary-user store and points one entry, normally `~/.local/bin/cw`,
//! at the selected version. New invocations follow the selection; running
//! processes and the commands they saved keep their original bytes and path.
//! Source resolution is separate from installation. Public sources are always
//! explicit and must pass compiled-key verification before Store admission.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Args, Subcommand};
use codewire_cw_release::identity::{CwPayloadIdentity, MAX_IDENTITY_BYTES, Platform};
use codewire_cw_release::store::{
    self, Admission, Candidate, DEFAULT_LOCK_TIMEOUT, EntryState, Status, Store, StoreError,
    VersionRecord,
};
use rustix::fs::{self as rfs, Mode, OFlags};
use serde::Serialize;

use crate::build_record::{BUILD_RECORD, embedded, executable_identity};
use crate::public_fetch;

/// Identity file beside `cw` in a pinned local release directory; the same
/// schema-2 document the cw image carries as `cw-runtime.json`.
const LOCAL_RELEASE_IDENTITY: &str = "cw-runtime.json";
const LOCAL_RELEASE_EXECUTABLE: &str = "cw";

/// `cw upgrade`: with no flags, ask what to upgrade at a terminal; `--cli`
/// and `--vms` say it for scripts. A source flag implies `--cli`.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct UpgradeArgs {
    #[command(subcommand)]
    command: Option<UpgradeCommand>,
    /// Select the newer CLI from the source [default source: the signed stable channel].
    #[arg(long)]
    cli: bool,
    /// Pinned local release directory containing `cw` and `cw-runtime.json`.
    #[arg(long, value_name = "DIR", requires = "sha256", conflicts_with_all = ["version", "channel"])]
    from: Option<PathBuf>,
    /// SHA-256 of the release `cw`; required with --from.
    #[arg(long, value_name = "HEX", requires = "from", conflicts_with_all = ["version", "channel"])]
    sha256: Option<String>,
    /// Explicit signed public release; an intentional downgrade is permitted.
    #[arg(long, value_name = "vMAJOR.MINOR.PATCH", value_parser = release_version, conflicts_with = "channel")]
    version: Option<String>,
    /// Signed public channel; stable refuses installed-version regressions.
    #[arg(long, value_parser = ["stable"])]
    channel: Option<String>,
    #[command(flatten)]
    selection: SelectionArgs,
}

#[derive(Debug, Subcommand)]
enum UpgradeCommand {
    /// Show the managed installation, its selection and retained versions.
    Status(StoreArgs),
    /// Select the previous, or a named retained, version for new invocations.
    Rollback(RollbackArgs),
}

#[derive(Debug, Args)]
struct StoreArgs {
    /// Managed version store [default: the store containing this cw, then
    /// $XDG_DATA_HOME/codewire/cli]
    #[arg(long, value_name = "DIR")]
    store: Option<PathBuf>,
    #[arg(long, help = "Print JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct SelectionArgs {
    /// Refuse unless the selection generation is still N.
    #[arg(long, value_name = "N")]
    expect_generation: Option<u64>,
    /// Restart the local VMs still running on an older cw onto the selected
    /// cw; the flag is the consent, and a restart ends the work running in
    /// them. Alone, it restarts them without selecting a CLI version.
    #[arg(long)]
    vms: bool,
    #[command(flatten)]
    store: StoreArgs,
}

#[derive(Debug, Args)]
struct RollbackArgs {
    /// Retained version: SHA-256, a unique prefix of 8+ hex digits, or a unique
    /// package version [default: the previous version]
    #[arg(long, value_name = "VERSION")]
    to: Option<String>,
    #[command(flatten)]
    selection: SelectionArgs,
}

/// Where a CLI selection comes from.
#[derive(Debug, PartialEq, Eq)]
enum CliSource {
    Local { directory: PathBuf, sha256: String },
    Public(PublicSource),
}

#[derive(Debug, PartialEq, Eq)]
enum PublicSource {
    Version(String),
    Stable,
}

/// What a bare or flagged `cw upgrade` does.
#[derive(Debug, PartialEq, Eq)]
enum UpgradePlan {
    /// At a terminal with no flags: check, then ask item by item.
    Ask,
    /// Select the CLI, then restart stale VMs only with `vms` consent.
    Cli { source: CliSource, vms: bool },
    /// `--vms` alone: restart stale local VMs; no CLI is fetched or selected.
    Vms,
}

/// Decide from the flags alone, before any effect. `interactive` is a text
/// run with stdin and stderr on a terminal; `local_vms` says whether this
/// platform runs local VMs.
fn upgrade_plan(
    args: &UpgradeArgs,
    interactive: bool,
    local_vms: bool,
) -> anyhow::Result<UpgradePlan> {
    let vms = args.selection.vms;
    anyhow::ensure!(
        !vms || local_vms,
        "--vms restarts local VMs, which this platform does not run"
    );
    anyhow::ensure!(
        !vms || args.selection.store.store.is_none(),
        "--vms restarts the local VMs of your installed cw; it cannot follow an explicit --store"
    );
    let source = match (&args.from, &args.sha256, &args.version, &args.channel) {
        (Some(directory), Some(sha256), None, None) => Some(CliSource::Local {
            directory: directory.clone(),
            sha256: sha256.clone(),
        }),
        (None, None, Some(version), None) => {
            Some(CliSource::Public(PublicSource::Version(version.clone())))
        }
        (None, None, None, Some(channel)) if channel == "stable" => {
            Some(CliSource::Public(PublicSource::Stable))
        }
        (None, None, None, None) => None,
        _ => anyhow::bail!(
            "cw upgrade takes one source: --version vMAJOR.MINOR.PATCH, --channel stable, \
             or --from DIR --sha256 HEX"
        ),
    };
    Ok(match (source, args.cli, vms) {
        // A source names the CLI to select: it implies --cli.
        (Some(source), _, vms) => UpgradePlan::Cli { source, vms },
        (None, true, vms) => UpgradePlan::Cli {
            source: CliSource::Public(PublicSource::Stable),
            vms,
        },
        (None, false, true) => {
            anyhow::ensure!(
                args.selection.expect_generation.is_none() && !args.selection.store.json,
                "--expect-generation and --json describe a CLI selection; `cw upgrade --vms` alone selects none"
            );
            UpgradePlan::Vms
        }
        (None, false, false) if interactive => UpgradePlan::Ask,
        // Scripts keep the stable CLI upgrade; stale VMs are only listed.
        (None, false, false) => UpgradePlan::Cli {
            source: CliSource::Public(PublicSource::Stable),
            vms: false,
        },
    })
}

#[derive(Debug, Args)]
pub(crate) struct InstallArgs {
    /// Install this cw into the managed version store and select it.
    #[arg(long, required = true)]
    managed: bool,
    /// Directory for the managed `cw` entry [default: $XDG_BIN_HOME, then ~/.local/bin]
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<PathBuf>,
    /// Managed version store [default: $XDG_DATA_HOME/codewire/cli]
    #[arg(long, value_name = "DIR")]
    store: Option<PathBuf>,
    #[arg(long, help = "Print JSON")]
    json: bool,
}

#[derive(Debug, Serialize)]
struct SelectionReport<'a> {
    entry: &'a Path,
    store: &'a Path,
    sha256: &'a str,
    package_version: &'a str,
    published: bool,
    changed: bool,
    generation: u64,
    previous: Option<&'a str>,
    /// Complete identity of a self-installed cw, from its build record and bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<&'a CwPayloadIdentity>,
}

pub(crate) async fn run(args: UpgradeArgs) -> anyhow::Result<()> {
    use std::io::IsTerminal as _;
    let rollback = match args.command {
        Some(UpgradeCommand::Status(store)) => return status(store),
        Some(UpgradeCommand::Rollback(rollback)) => rollback,
        None => {
            let interactive = !args.selection.store.json
                && io::stdin().is_terminal()
                && io::stderr().is_terminal();
            let local_vms = cfg!(any(target_os = "linux", target_os = "macos"));
            return match upgrade_plan(&args, interactive, local_vms)? {
                UpgradePlan::Vms => restart_local_vms().await,
                UpgradePlan::Cli { source, vms } => select_cli(source, args.selection, vms).await,
                UpgradePlan::Ask => ask_and_upgrade(args.selection).await,
            };
        }
    };
    anyhow::ensure!(
        !rollback.selection.vms || rollback.selection.store.store.is_none(),
        "--vms restarts the local VMs of your installed cw; it cannot follow an explicit --store"
    );
    let store = open_store(rollback.selection.store.store.as_deref())?;
    let selected = store
        .rollback(rollback.to.as_deref(), rollback.selection.expect_generation)
        .map_err(with_hint)?;
    let record = store.verify(&selected.current)?;
    print_selection(
        &store,
        &SelectionReport {
            entry: store.entry(),
            store: store.root(),
            sha256: &selected.current,
            package_version: &record.package_version,
            published: false,
            changed: selected.changed,
            generation: selected.generation,
            previous: selected.previous.as_deref(),
            identity: None,
        },
        rollback.selection.store.json,
    )?;
    hand_off_local_vms(
        &store,
        &selected.current,
        &rollback.selection,
        rollback.selection.vms,
    )
    .await;
    Ok(())
}

/// Select the CLI from `source`; then the selected cw restarts stale local
/// VMs with `vms` consent, or only lists them.
async fn select_cli(source: CliSource, options: SelectionArgs, vms: bool) -> anyhow::Result<()> {
    match source {
        CliSource::Public(source) => {
            let source = match source {
                PublicSource::Version(version) => public_fetch::Selection::Version(version),
                PublicSource::Stable => public_fetch::Selection::Stable,
            };
            public_release(source, options, vms).await
        }
        CliSource::Local { directory, sha256 } => {
            let store = open_store(options.store.store.as_deref())?;
            let candidate = local_release(&directory, &sha256)?;
            let (published, selected) = store
                .publish_and_select(&candidate, options.expect_generation)
                .map_err(with_hint)?;
            print_selection(
                &store,
                &SelectionReport {
                    entry: store.entry(),
                    store: store.root(),
                    sha256: &published.sha256,
                    package_version: &published.record.package_version,
                    published: published.created,
                    changed: selected.changed,
                    generation: selected.generation,
                    previous: selected.previous.as_deref(),
                    identity: None,
                },
                options.store.json,
            )?;
            hand_off_local_vms(&store, &published.sha256, &options, vms).await;
            Ok(())
        }
    }
}

/// `cw upgrade --vms` alone: move the local VMs a previous cw still runs
/// onto this cw. The flag is the consent; nothing is fetched or selected.
async fn restart_local_vms() -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        crate::commands::upgrade_native_environments(true, false).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("--vms restarts local VMs, which this platform does not run")
    }
}

/// Bare `cw upgrade` at a terminal: check the stable channel and the local
/// VMs, then ask about each applicable item; nothing changes until every
/// answer is in, and a cancelled question changes nothing.
async fn ask_and_upgrade(options: SelectionArgs) -> anyhow::Result<()> {
    let host = Platform::host().ok_or(StoreError::UnsupportedHost)?;
    let store = open_store(options.store.store.as_deref())?;
    let (expected, current) = admit_public_selection(&store, options.expect_generation)?;
    let installed = current
        .as_ref()
        .map_or(crate::CLI_VERSION, |record| record.package_version.as_str())
        .to_owned();
    eprintln!("Checking the stable channel for a newer cw...");
    let fetched = public_fetch::fetch(public_fetch::Selection::Stable, host).await?;
    let newer = current
        .as_ref()
        .is_none_or(|record| record.sha256 != fetched.identity.sha256)
        && codewire_cw_release::release::guard_stable(
            current
                .as_ref()
                .map(|record| (record.package_version.as_str(), record.sha256.as_str())),
            &fetched.identity,
        )
        .is_ok();
    let offered = fetched.identity.package_version.clone();
    let decided = ask_upgrade_items(&installed, newer.then_some(offered.as_str()), &options).await;
    let (select, restart, stale) = match decided {
        Ok((Items::Decided { select, restart }, stale)) => (select, restart, stale),
        Ok((Items::Nothing, _)) => {
            fetched.cleanup()?;
            eprintln!("The CLI (v{installed}) and local VMs are current.");
            return Ok(());
        }
        Ok((Items::Canceled, _)) => {
            fetched.cleanup()?;
            anyhow::bail!("upgrade canceled; nothing changed")
        }
        Err(error) => {
            let cleanup = fetched.cleanup();
            return Err(match cleanup {
                Ok(()) => error,
                Err(_) => error.context("public release scratch cleanup failed; scratch retained"),
            });
        }
    };
    if !select {
        fetched.cleanup()?;
        if restart {
            return restart_local_vms().await;
        }
        // With the CLI unchanged, only VMs on an older cw than this one are
        // stale.
        let stale = if newer && !stale.is_empty() {
            stale_local_vms(false).await?
        } else {
            stale
        };
        if !stale.is_empty() {
            eprintln!(
                "cw: local VMs {} run on an older cw; restart them with `cw upgrade --vms`",
                stale.join(", ")
            );
        }
        eprintln!("Nothing changed.");
        return Ok(());
    }
    let operation = commit_public(&store, expected, current.as_ref(), true, &fetched);
    let identity = fetched.identity.clone();
    let cleanup = fetched.cleanup();
    let (published, selected) = match operation {
        Ok(value) => {
            cleanup.context("selection committed, but public release scratch cleanup failed")?;
            value
        }
        Err(error) => {
            if cleanup.is_err() {
                return Err(
                    error.context("public release scratch cleanup failed; scratch retained")
                );
            }
            return Err(error);
        }
    };
    print_selection(
        &store,
        &SelectionReport {
            entry: store.entry(),
            store: store.root(),
            sha256: &published.sha256,
            package_version: &published.record.package_version,
            published: published.created,
            changed: selected.changed,
            generation: selected.generation,
            previous: selected.previous.as_deref(),
            identity: Some(&identity),
        },
        options.store.json,
    )?;
    hand_off_local_vms(&store, &published.sha256, &options, restart).await;
    Ok(())
}

/// What `cw upgrade`'s question decided.
#[derive(Debug, PartialEq, Eq)]
enum Items {
    /// The CLI and the local VMs are current: nothing to ask.
    Nothing,
    Decided {
        select: bool,
        restart: bool,
    },
    /// Escape, Ctrl-C or closed input: nothing applies.
    Canceled,
}

/// Offer the applicable items in one checklist: the newer CLI (checked) and
/// the local VMs that would run on an older cw (unchecked, since a restart
/// ends their work). Without a usable terminal it answers as a script would:
/// the CLI alone, VMs only listed afterwards.
async fn ask_upgrade_items(
    installed: &str,
    offered: Option<&str>,
    options: &SelectionArgs,
) -> anyhow::Result<(Items, Vec<String>)> {
    use crate::output::{Capabilities, Checklist, ChecklistItem, OutputMode, run_checklist};
    // The hand-off cannot follow an explicit --store, so neither can this.
    let stale = if options.store.store.is_none() {
        stale_local_vms(offered.is_some()).await?
    } else {
        Vec::new()
    };
    let mut items = Vec::new();
    let cli = offered.map(|offered| {
        items.push(ChecklistItem::new(
            format!("Codewire CLI v{installed} → v{offered}"),
            true,
        ));
        items.len() - 1
    });
    let vms = (!stale.is_empty()).then(|| {
        let noun = if stale.len() == 1 { "VM" } else { "VMs" };
        let target = offered.unwrap_or(installed);
        items.push(
            ChecklistItem::new(
                format!("Restart {} local {noun} onto v{target}", stale.len()),
                false,
            )
            .with_detail(format!(
                "ends the work running in them: {}",
                stale.join(", ")
            )),
        );
        items.len() - 1
    });
    if items.is_empty() {
        return Ok((Items::Nothing, stale));
    }
    let checklist = Checklist::new("Upgrade Codewire", items);
    let caps = Capabilities::from_process(OutputMode::Text);
    let outcome = tokio::task::spawn_blocking(move || run_checklist(checklist, &caps))
        .await
        .context("ask what to upgrade")??;
    Ok((decide_items(outcome, cli, vms), stale))
}

/// The checklist's answer as the items to apply.
fn decide_items(
    outcome: crate::output::ChecklistOutcome,
    cli: Option<usize>,
    vms: Option<usize>,
) -> Items {
    use crate::output::ChecklistOutcome;
    match outcome {
        ChecklistOutcome::Applied(checked) => Items::Decided {
            select: cli.is_some_and(|index| checked.contains(&index)),
            restart: vms.is_some_and(|index| checked.contains(&index)),
        },
        ChecklistOutcome::Canceled => Items::Canceled,
        ChecklistOutcome::Unavailable => Items::Decided {
            select: cli.is_some(),
            restart: false,
        },
    }
}

/// The local VMs that run on an older cw than the one this upgrade leaves
/// selected. Starts nothing.
async fn stale_local_vms(cli_changes: bool) -> anyhow::Result<Vec<String>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        crate::commands::local_vms_on_an_older_cw(cli_changes).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = cli_changes;
        Ok(Vec::new())
    }
}

fn release_version(value: &str) -> Result<String, String> {
    if codewire_cw_release::release::valid_release_tag(value) {
        Ok(value.to_owned())
    } else {
        Err("version must be a bounded vMAJOR.MINOR.PATCH release tag".into())
    }
}

async fn public_release(
    source: public_fetch::Selection,
    options: SelectionArgs,
    vms: bool,
) -> anyhow::Result<()> {
    let host = Platform::host().ok_or(StoreError::UnsupportedHost)?;
    let stable = matches!(source, public_fetch::Selection::Stable);
    let store = open_store(options.store.store.as_deref())?;
    let (expected, current) = admit_public_selection(&store, options.expect_generation)?;
    let fetched = public_fetch::fetch(source, host).await?;
    let identity = fetched.identity.clone();
    let operation = commit_public(&store, expected, current.as_ref(), stable, &fetched);
    let cleanup = fetched.cleanup();
    let (published, selected) = match operation {
        Ok(value) => {
            cleanup.context("selection committed, but public release scratch cleanup failed")?;
            value
        }
        Err(error) => {
            if cleanup.is_err() {
                return Err(
                    error.context("public release scratch cleanup failed; scratch retained")
                );
            }
            return Err(error);
        }
    };
    print_selection(
        &store,
        &SelectionReport {
            entry: store.entry(),
            store: store.root(),
            sha256: &published.sha256,
            package_version: &published.record.package_version,
            published: published.created,
            changed: selected.changed,
            generation: selected.generation,
            previous: selected.previous.as_deref(),
            identity: Some(&identity),
        },
        options.store.json,
    )?;
    hand_off_local_vms(&store, &published.sha256, &options, vms).await;
    Ok(())
}

/// After a selection, let the selected cw restart the local VMs still
/// running on the previous one: it runs that version's own `env --local
/// upgrade --after-update`, since this cw's code may be the older. That argv
/// is the hand-off protocol every cw since #2870 accepts, including those
/// without `cw upgrade`, so a rollback to one still restarts its VMs; later
/// cw keep it as a hidden route (`commands/flat.rs`). With `restart` the
/// consent passes as `--yes`. Without it the hand-off must not ask again:
/// its stdin is not a terminal, so every version only lists the VMs and the
/// repair. A version without the hand-off is asked silently first and
/// skipped. Never for an explicit --store, which the user's `cw` may not
/// resolve to. It never fails the update, which has already succeeded.
async fn hand_off_local_vms(store: &Store, sha256: &str, options: &SelectionArgs, restart: bool) {
    use std::process::{Command, Stdio};
    if !cfg!(any(target_os = "linux", target_os = "macos")) || options.store.store.is_some() {
        return;
    }
    let Ok(record) = store.verify(sha256) else {
        return;
    };
    let executable = store.version_executable(sha256);
    let supported = Command::new(&executable)
        .args(["env", "--local", "upgrade", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !supported {
        // An older cw, from before #2870: it refuses this cw's local VM
        // supervisor and cannot retire it, so hand the root back now.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        crate::commands::release_local_vms_for_older_cw(&record.package_version).await;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = record;
        return;
    }
    let mut command = Command::new(&executable);
    command.args(["env", "--local", "upgrade", "--after-update"]);
    if restart {
        command.arg("--yes");
    } else {
        command.stdin(Stdio::null());
    }
    if options.store.json {
        // stdout carries the JSON report alone.
        match std::os::fd::AsFd::as_fd(&io::stderr()).try_clone_to_owned() {
            Ok(stderr) => {
                command.stdout(Stdio::from(stderr));
            }
            Err(_) => return,
        }
    }
    if !command.status().is_ok_and(|status| status.success()) {
        eprintln!("cw: restart local VMs still on the previous cw with `cw upgrade --vms`");
    }
}

/// Whether this cw is the version its store selects now. The hand-off acts
/// only then, so a later update or rollback is never undone by an older one.
pub(crate) fn this_cw_is_selected() -> bool {
    let Ok(executable) = std::env::current_exe().and_then(fs::canonicalize) else {
        return false;
    };
    let Some(store) =
        Store::locate(&executable).and_then(|root| Store::open(&root, DEFAULT_LOCK_TIMEOUT).ok())
    else {
        return false;
    };
    store.status().is_ok_and(|status| {
        status
            .current
            .is_some_and(|current| store.version_executable(&current) == executable)
    })
}

fn admit_public_selection(
    store: &Store,
    requested: Option<u64>,
) -> anyhow::Result<(u64, Option<VersionRecord>)> {
    let status = store.status()?;
    anyhow::ensure!(
        status.consistent && status.pending.is_none(),
        "public update refuses an uncertain or inconsistent Store selection; observe cw upgrade status and resolve the owning operation first"
    );
    let expected = requested.unwrap_or(status.generation);
    anyhow::ensure!(
        expected == status.generation,
        "managed cw selection generation changed before public fetch"
    );
    let current = status
        .current
        .as_deref()
        .map(|digest| store.verify(digest))
        .transpose()?;
    Ok((expected, current))
}

pub(crate) fn commit_public(
    store: &Store,
    expected: u64,
    current: Option<&VersionRecord>,
    stable: bool,
    fetched: &public_fetch::FetchedRelease,
) -> anyhow::Result<(store::Published, store::Selected)> {
    if stable {
        codewire_cw_release::release::guard_stable(
            current.map(|record| (record.package_version.as_str(), record.sha256.as_str())),
            &fetched.identity,
        )?;
    }
    store
        .publish_and_select(fetched.candidate(), Some(expected))
        .map_err(with_hint)
}

pub(crate) fn install(args: InstallArgs) -> anyhow::Result<()> {
    // The complete identity comes from this cw's build record and its exact
    // running bytes, before any store or entry change.
    let host = Platform::host().ok_or(StoreError::UnsupportedHost)?;
    let executable = running_executable()?;
    let identity = executable_identity(&embedded()?, &BUILD_RECORD, &executable, host)
        .context("admit this cw for managed installation")?;
    install_identified(args, executable, &identity)
}

fn install_identified(
    args: InstallArgs,
    executable: PathBuf,
    identity: &CwPayloadIdentity,
) -> anyhow::Result<()> {
    debug_assert!(args.managed);
    let root = match args.store {
        Some(root) => absolute(root)?,
        None => default_store_root()?,
    };
    let bin_dir = match args.bin_dir {
        Some(directory) => absolute(directory)?,
        None => default_bin_dir()?,
    };
    refuse_contradiction(&root, identity)?;
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("create managed entry directory {}", bin_dir.display()))?;
    let candidate = Candidate {
        executable,
        admission: Admission::SelfInstall {
            package_version: identity.package_version.clone(),
        },
    };
    let installed = store::install(&root, &bin_dir.join("cw"), &candidate, DEFAULT_LOCK_TIMEOUT)
        .map_err(with_hint)?;
    anyhow::ensure!(
        installed.published.sha256 == identity.sha256,
        "the running cw changed while it was installed: stored {} instead of {}; select the \
         intended version with `cw upgrade rollback`",
        installed.published.sha256,
        identity.sha256
    );
    consistent(&installed.published.record, identity)?;
    print_selection(
        &installed.store,
        &SelectionReport {
            entry: installed.store.entry(),
            store: installed.store.root(),
            sha256: &installed.published.sha256,
            package_version: &installed.published.record.package_version,
            published: installed.published.created,
            changed: installed.selected.changed,
            generation: installed.selected.generation,
            previous: installed.selected.previous.as_deref(),
            identity: Some(identity),
        },
        args.json,
    )
}

/// Refuse before any change when the store already holds these bytes under
/// a different identity.
fn refuse_contradiction(root: &Path, identity: &CwPayloadIdentity) -> anyhow::Result<()> {
    let store = match Store::open(root, DEFAULT_LOCK_TIMEOUT) {
        Ok(store) => store,
        Err(StoreError::NotAStore { .. }) => return Ok(()),
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("open managed cw store {}", root.display()));
        }
    };
    match store.verify(&identity.sha256) {
        Ok(record) => consistent(&record, identity),
        Err(StoreError::UnknownVersion(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn consistent(record: &VersionRecord, identity: &CwPayloadIdentity) -> anyhow::Result<()> {
    let agrees = record.sha256 == identity.sha256
        && record.size == identity.size
        && record.package_version == identity.package_version
        && record
            .payload
            .as_ref()
            .is_none_or(|payload| payload == identity);
    anyhow::ensure!(
        agrees,
        "stored cw version {} records an identity that contradicts this cw's build record",
        identity.sha256
    );
    Ok(())
}

fn status(args: StoreArgs) -> anyhow::Result<()> {
    let store = open_store(args.store.as_deref())?;
    let status = store.status()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print!("{}", render_status(&status));
    }
    Ok(())
}

fn render_status(status: &Status) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "Managed cw installation");
    let _ = writeln!(text, "  entry:      {}", status.entry.display());
    let _ = writeln!(text, "  store:      {}", status.root.display());
    let _ = writeln!(text, "  platform:   {}", status.platform);
    let _ = writeln!(text, "  generation: {}", status.generation);
    let describe = |sha256: &Option<String>| match sha256 {
        Some(sha256) => {
            let version = status
                .versions
                .iter()
                .find(|version| &version.sha256 == sha256)
                .and_then(|version| version.package_version.as_deref())
                .unwrap_or("unrecorded");
            format!("{version} ({sha256})")
        }
        None => "none".into(),
    };
    let _ = writeln!(text, "  current:    {}", describe(&status.current));
    let _ = writeln!(text, "  previous:   {}", describe(&status.previous));
    if let Some(pending) = &status.pending {
        let _ = writeln!(
            text,
            "  pending:    interrupted selection of {}; the next upgrade or rollback resolves it from the entry",
            pending.to
        );
    } else if !status.consistent {
        let entry = match &status.entry_state {
            EntryState::Absent => "missing".to_owned(),
            EntryState::Managed { sha256 } => format!("version {sha256}"),
            EntryState::ForeignLink { target } => format!("a link to {}", target.display()),
            EntryState::Unmanaged { kind } => format!("an unmanaged {kind}"),
        };
        let _ = writeln!(
            text,
            "  warning:    the entry is {entry}, not the recorded selection; updates are refused \
             until it is restored"
        );
    }
    let _ = writeln!(text, "  retained:   {} version(s)", status.versions.len());
    for version in &status.versions {
        let marker = if status.current.as_ref() == Some(&version.sha256) {
            '*'
        } else {
            ' '
        };
        let origin = match version.origin {
            Some(store::Origin::PinnedRelease) => "pinned release",
            Some(store::Origin::SelfInstall) => "self-install",
            None => "unreadable identity",
        };
        let _ = writeln!(
            text,
            "  {marker} {} {} ({origin})",
            version.sha256,
            version.package_version.as_deref().unwrap_or("-")
        );
    }
    text
}

fn print_selection(store: &Store, report: &SelectionReport<'_>, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    let action = if report.changed {
        "Selected"
    } else {
        "Already selected"
    };
    println!(
        "{action} cw {} ({}) for new invocations of {} at generation {}.",
        report.package_version,
        report.sha256,
        store.entry().display(),
        report.generation
    );
    if let Some(identity) = report.identity {
        println!(
            "Identity: {} source {} (tree {}), {}.",
            identity.target, identity.source_revision, identity.source_tree_sha256, identity.rustc
        );
    }
    if report.changed && report.previous.is_some() {
        println!("Running cw processes keep their current version.");
    }
    if let Some(previous) = report.previous {
        println!("Previous version {previous} is retained; `cw upgrade rollback` selects it.");
    }
    Ok(())
}

/// Read a pinned local release: `cw` plus its schema-2 identity. The digest
/// pin is supplied separately by the caller and must match both.
fn local_release(directory: &Path, sha256: &str) -> anyhow::Result<Candidate> {
    let identity_path = directory.join(LOCAL_RELEASE_IDENTITY);
    let fd = rfs::open(
        &identity_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("open release identity {}", identity_path.display()))?;
    let mut file = fs::File::from(fd);
    let before = file
        .metadata()
        .with_context(|| format!("inspect release identity {}", identity_path.display()))?;
    anyhow::ensure!(
        before.is_file() && before.len() <= MAX_IDENTITY_BYTES as u64,
        "release identity must be a bounded regular file: {}",
        identity_path.display()
    );
    let mut bytes = Vec::new();
    io::Read::read_to_end(
        &mut io::Read::take(&mut file, MAX_IDENTITY_BYTES as u64 + 1),
        &mut bytes,
    )
    .with_context(|| format!("read release identity {}", identity_path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("recheck release identity {}", identity_path.display()))?;
    anyhow::ensure!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.mode(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ) && bytes.len() as u64 == before.len(),
        "release identity changed while it was read: {}",
        identity_path.display()
    );
    let identity = CwPayloadIdentity::decode(&bytes)
        .with_context(|| format!("admit release identity {}", identity_path.display()))?;
    Ok(Candidate {
        executable: directory.join(LOCAL_RELEASE_EXECUTABLE),
        admission: Admission::Pinned {
            identity,
            sha256: sha256.to_owned(),
        },
    })
}

fn open_store(explicit: Option<&Path>) -> anyhow::Result<Store> {
    if let Some(root) = explicit {
        return Store::open(root, DEFAULT_LOCK_TIMEOUT)
            .with_context(|| format!("open managed cw store {}", root.display()));
    }
    let executable = std::env::current_exe().and_then(fs::canonicalize).ok();
    if let Some(root) = executable.as_deref().and_then(Store::locate) {
        return Store::open(&root, DEFAULT_LOCK_TIMEOUT)
            .with_context(|| format!("open managed cw store {}", root.display()));
    }
    let root = default_store_root()?;
    match Store::open(&root, DEFAULT_LOCK_TIMEOUT) {
        Ok(store) => Ok(store),
        Err(StoreError::NotAStore { .. }) => Err(unmanaged(executable.as_deref(), &root)),
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Err(unmanaged(executable.as_deref(), &root))
        }
        Err(error) => {
            Err(error).with_context(|| format!("open managed cw store {}", root.display()))
        }
    }
}

fn unmanaged(executable: Option<&Path>, root: &Path) -> anyhow::Error {
    let running = executable.map_or_else(
        || "this cw".to_owned(),
        |path| format!("this cw ({})", path.display()),
    );
    anyhow::anyhow!(
        "{running} is not a managed installation and no managed store exists at {}; reinstall \
         with `curl -fsSL https://codewire.sh/install.sh | sh`, which installs a managed cw, or \
         use `make cli-install` from an authorized source checkout. An existing regular-file cw \
         is never replaced automatically.",
        root.display()
    )
}

fn with_hint(error: StoreError) -> anyhow::Error {
    let hint = match &error {
        StoreError::UnmanagedEntry { .. } => Some(
            "Stop processes that use it and move it aside yourself, or keep the previous \
             overwrite behavior with `make -C apps/cli install-user-unmanaged`.",
        ),
        StoreError::NotWritable { .. } => Some(
            "System locations need their owner; install for this user with the default \
             --bin-dir instead.",
        ),
        StoreError::ExternallyChanged { .. } => Some(
            "Restore the entry to the selected version shown by `cw upgrade status`, or remove \
             it if nothing uses it, before updating.",
        ),
        _ => None,
    };
    match hint {
        Some(hint) => anyhow::anyhow!("{error}. {hint}"),
        None => error.into(),
    }
}

/// The exact bytes of the running executable: on Linux the open image itself,
/// even if its path has since been replaced.
fn running_executable() -> anyhow::Result<PathBuf> {
    if cfg!(target_os = "linux") {
        Ok(PathBuf::from("/proc/self/exe"))
    } else {
        std::env::current_exe().context("resolve the running cw executable")
    }
}

fn absolute(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolve the current directory")?
            .join(path))
    }
}

fn env_directory(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn home() -> anyhow::Result<PathBuf> {
    env_directory("HOME").context("HOME must be an absolute path to locate the managed cw store")
}

fn default_store_root() -> anyhow::Result<PathBuf> {
    let data = match env_directory("XDG_DATA_HOME") {
        Some(data) => data,
        None => home()?.join(".local/share"),
    };
    Ok(data.join("codewire/cli"))
}

fn default_bin_dir() -> anyhow::Result<PathBuf> {
    match env_directory("XDG_BIN_HOME") {
        Some(bin) => Ok(bin),
        None => Ok(home()?.join(".local/bin")),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::build_record::tests::{decoded, executable, framed, host, host_target, json, write};
    use crate::{Cli, Command};

    /// Immutable Store versions are 0555; make them writable before the
    /// temporary directory is removed so no test leaves an undeletable tree.
    struct Scratch(tempfile::TempDir);

    impl Scratch {
        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            make_removable(self.0.path());
        }
    }

    fn tempdir() -> Scratch {
        Scratch(tempfile::tempdir().unwrap())
    }

    fn make_removable(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    make_removable(&entry.path());
                }
            }
        }
    }

    fn parse(arguments: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(arguments).map(|cli| cli.command)
    }

    #[test]
    fn upgrade_and_install_grammar() {
        let sha256 = "a".repeat(64);
        assert!(matches!(
            parse(&["cw", "upgrade"]),
            Ok(Command::Upgrade(UpgradeArgs {
                command: None,
                from: None,
                ..
            }))
        ));
        assert!(matches!(
            parse(&["cw", "upgrade", "status", "--json"]),
            Ok(Command::Upgrade(UpgradeArgs {
                command: Some(UpgradeCommand::Status(StoreArgs { json: true, .. })),
                ..
            }))
        ));
        let Ok(Command::Upgrade(UpgradeArgs {
            command: Some(UpgradeCommand::Rollback(rollback)),
            ..
        })) = parse(&[
            "cw",
            "upgrade",
            "rollback",
            "--to",
            "1.2.3",
            "--expect-generation",
            "4",
        ])
        else {
            panic!("rollback");
        };
        assert_eq!(rollback.to.as_deref(), Some("1.2.3"));
        assert_eq!(rollback.selection.expect_generation, Some(4));
        let Ok(Command::Upgrade(update)) = parse(&[
            "cw",
            "upgrade",
            "--from",
            "/releases/1.2.3",
            "--sha256",
            &sha256,
        ]) else {
            panic!("update --from");
        };
        assert_eq!(update.from.as_deref(), Some(Path::new("/releases/1.2.3")));
        assert!(parse(&["cw", "upgrade", "--from", "/releases/1.2.3"]).is_err());
        assert!(parse(&["cw", "upgrade", "--sha256", &sha256]).is_err());
        assert!(
            parse(&[
                "cw", "upgrade", "--from", "/r", "--sha256", &sha256, "status"
            ])
            .is_err()
        );
        // No subcommand or flag restarts VMs except --vms.
        assert!(parse(&["cw", "upgrade", "restart-vms"]).is_err());
        assert!(parse(&["cw", "upgrade", "--restart-vms"]).is_err());
        assert!(parse(&["cw", "upgrade", "--vms", "status"]).is_err());
        // `cw update` now changes an environment; it is no updater route.
        assert!(matches!(
            parse(&["cw", "update", "status"]),
            Ok(Command::Update(_))
        ));
        let Ok(Command::Install(install)) =
            parse(&["cw", "install", "--managed", "--bin-dir", "/opt/bin"])
        else {
            panic!("install");
        };
        assert!(install.managed);
        assert_eq!(install.bin_dir.as_deref(), Some(Path::new("/opt/bin")));
        assert!(parse(&["cw", "install"]).is_err());
    }

    #[test]
    fn public_update_sources_are_explicit_exclusive_bounded_and_closed() {
        let Ok(Command::Upgrade(version)) = parse(&["cw", "upgrade", "--version", "v1.2.3"]) else {
            panic!("version");
        };
        assert_eq!(version.version.as_deref(), Some("v1.2.3"));
        assert!(version.channel.is_none() && version.from.is_none());
        let Ok(Command::Upgrade(channel)) = parse(&[
            "cw",
            "upgrade",
            "--channel",
            "stable",
            "--expect-generation",
            "7",
        ]) else {
            panic!("channel");
        };
        assert_eq!(channel.channel.as_deref(), Some("stable"));
        assert_eq!(channel.selection.expect_generation, Some(7));
        let sha = "a".repeat(64);
        for args in [
            vec!["cw", "upgrade", "--version", ""],
            vec!["cw", "upgrade", "--version", "1.2.3"],
            vec!["cw", "upgrade", "--version", "v1.2.3/../../x"],
            vec![
                "cw",
                "upgrade",
                "--version",
                "v1.2.3",
                "--version",
                "v1.2.4",
            ],
            vec![
                "cw",
                "upgrade",
                "--channel",
                "stable",
                "--channel",
                "stable",
            ],
            vec!["cw", "upgrade", "--channel", "dev"],
            vec![
                "cw",
                "upgrade",
                "--version",
                "v1.2.3",
                "--channel",
                "stable",
            ],
            vec![
                "cw",
                "upgrade",
                "--from",
                "/r",
                "--sha256",
                &sha,
                "--version",
                "v1.2.3",
            ],
            vec![
                "cw",
                "upgrade",
                "--from",
                "/r",
                "--sha256",
                &sha,
                "--channel",
                "stable",
            ],
            vec!["cw", "upgrade", "--channel", "stable", "status"],
            vec!["cw", "upgrade", "--version", "v1.2.3", "rollback"],
            vec![
                "cw",
                "upgrade",
                "--channel",
                "stable",
                "--url",
                "https://example.invalid",
            ],
            vec!["cw", "upgrade", "--channel", "stable", "--key", "/tmp/key"],
            vec![
                "cw",
                "upgrade",
                "--channel",
                "stable",
                "--proxy",
                "http://127.0.0.1:1",
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }

    fn plan(arguments: &[&str], interactive: bool, local_vms: bool) -> anyhow::Result<UpgradePlan> {
        let Ok(Command::Upgrade(args)) = parse(arguments) else {
            panic!("upgrade {arguments:?}");
        };
        upgrade_plan(&args, interactive, local_vms)
    }

    #[test]
    fn upgrade_flags_choose_what_to_upgrade_before_any_effect() {
        let stable = || CliSource::Public(PublicSource::Stable);
        // Bare: a question at a terminal, the stable CLI alone for scripts.
        assert_eq!(
            plan(&["cw", "upgrade"], true, true).unwrap(),
            UpgradePlan::Ask
        );
        // --json is never a terminal conversation (`run` passes false).
        assert_eq!(
            plan(&["cw", "upgrade", "--json"], false, true).unwrap(),
            UpgradePlan::Cli {
                source: stable(),
                vms: false
            }
        );
        assert_eq!(
            plan(&["cw", "upgrade"], false, true).unwrap(),
            UpgradePlan::Cli {
                source: stable(),
                vms: false
            }
        );
        // Explicit flags never ask.
        for (arguments, expected) in [
            (
                vec!["cw", "upgrade", "--cli"],
                UpgradePlan::Cli {
                    source: stable(),
                    vms: false,
                },
            ),
            (vec!["cw", "upgrade", "--vms"], UpgradePlan::Vms),
            (
                vec!["cw", "upgrade", "--cli", "--vms"],
                UpgradePlan::Cli {
                    source: stable(),
                    vms: true,
                },
            ),
            (
                vec!["cw", "upgrade", "--version", "v1.2.3"],
                UpgradePlan::Cli {
                    source: CliSource::Public(PublicSource::Version("v1.2.3".into())),
                    vms: false,
                },
            ),
            (
                vec!["cw", "upgrade", "--channel", "stable", "--vms"],
                UpgradePlan::Cli {
                    source: stable(),
                    vms: true,
                },
            ),
        ] {
            assert_eq!(
                plan(&arguments, true, true).unwrap(),
                expected,
                "{arguments:?}"
            );
            assert_eq!(
                plan(&arguments, false, true).unwrap(),
                expected,
                "{arguments:?}"
            );
        }
        let sha256 = "a".repeat(64);
        assert_eq!(
            plan(
                &["cw", "upgrade", "--from", "/r", "--sha256", &sha256],
                true,
                true
            )
            .unwrap(),
            UpgradePlan::Cli {
                source: CliSource::Local {
                    directory: PathBuf::from("/r"),
                    sha256: sha256.clone(),
                },
                vms: false,
            }
        );
        // --vms is refused where no local VM runtime exists, or for a store
        // the installed cw may not follow, before anything is fetched.
        for arguments in [
            vec!["cw", "upgrade", "--vms"],
            vec!["cw", "upgrade", "--cli", "--vms"],
            vec!["cw", "upgrade", "rollback", "--vms"],
        ] {
            let Ok(Command::Upgrade(args)) = parse(&arguments) else {
                panic!("upgrade {arguments:?}");
            };
            if args.command.is_none() {
                assert_eq!(
                    upgrade_plan(&args, true, false).unwrap_err().to_string(),
                    "--vms restarts local VMs, which this platform does not run",
                    "{arguments:?}"
                );
            }
        }
        assert!(plan(&["cw", "upgrade", "--vms", "--store", "/s"], false, true).is_err());
        assert!(plan(&["cw", "upgrade", "--vms", "--json"], false, true).is_err());
        assert!(
            plan(
                &["cw", "upgrade", "--vms", "--expect-generation", "3"],
                false,
                true
            )
            .is_err()
        );
        assert!(parse(&["cw", "upgrade", "rollback", "--to", "v1.2.3", "--vms"]).is_ok());
    }

    #[test]
    fn the_upgrade_checklist_applies_only_checked_items_and_falls_back_to_scripts() {
        use crate::output::ChecklistOutcome;
        let both = (Some(0), Some(1));
        assert_eq!(
            decide_items(ChecklistOutcome::Applied(vec![0]), both.0, both.1),
            Items::Decided {
                select: true,
                restart: false
            }
        );
        assert_eq!(
            decide_items(ChecklistOutcome::Applied(vec![0, 1]), both.0, both.1),
            Items::Decided {
                select: true,
                restart: true
            }
        );
        assert_eq!(
            decide_items(ChecklistOutcome::Applied(vec![1]), both.0, both.1),
            Items::Decided {
                select: false,
                restart: true
            }
        );
        assert_eq!(
            decide_items(ChecklistOutcome::Applied(vec![]), both.0, both.1),
            Items::Decided {
                select: false,
                restart: false
            }
        );
        // Only the VM item applies: index 0 is the restart.
        assert_eq!(
            decide_items(ChecklistOutcome::Applied(vec![0]), None, Some(0)),
            Items::Decided {
                select: false,
                restart: true
            }
        );
        assert_eq!(
            decide_items(ChecklistOutcome::Canceled, both.0, both.1),
            Items::Canceled
        );
        // No usable terminal: what a script gets, the CLI alone.
        assert_eq!(
            decide_items(ChecklistOutcome::Unavailable, both.0, both.1),
            Items::Decided {
                select: true,
                restart: false
            }
        );
        assert_eq!(
            decide_items(ChecklistOutcome::Unavailable, None, Some(0)),
            Items::Decided {
                select: false,
                restart: false
            }
        );
    }

    #[tokio::test]
    async fn upgrade_without_a_source_follows_the_stable_channel() {
        // The stable channel opens the managed store before any fetch, so a
        // missing store proves the selection without touching the network.
        let directory = tempdir();
        let store = directory.path().join("missing-store");
        let error = run(UpgradeArgs {
            command: None,
            from: None,
            sha256: None,
            version: None,
            channel: None,
            cli: false,
            selection: SelectionArgs {
                expect_generation: None,
                vms: false,
                store: StoreArgs {
                    store: Some(store.clone()),
                    json: false,
                },
            },
        })
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("open managed cw store {}", store.display())),
            "{message}"
        );
        assert!(!message.contains("takes one source"), "{message}");
    }

    #[test]
    fn public_prefetch_admission_captures_verified_state_and_refuses_stale_or_corrupt_state() {
        let directory = tempdir();
        let bin = directory.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let store = Store::create(
            &directory.path().join("store"),
            &bin.join("cw"),
            DEFAULT_LOCK_TIMEOUT,
        )
        .unwrap();
        assert_eq!(admit_public_selection(&store, None).unwrap(), (0, None));
        let (executable, identity) =
            identified(directory.path(), crate::build_record::tests::host_target());
        store
            .publish_and_select(
                &Candidate {
                    executable,
                    admission: Admission::SelfInstall {
                        package_version: identity.package_version,
                    },
                },
                Some(0),
            )
            .unwrap();
        let before = store.status().unwrap();
        let (generation, current) = admit_public_selection(&store, None).unwrap();
        assert_eq!(generation, before.generation);
        assert_eq!(
            current.unwrap(),
            store.verify(before.current.as_deref().unwrap()).unwrap()
        );
        assert!(admit_public_selection(&store, Some(0)).is_err());
        assert_eq!(store.status().unwrap(), before);
        let path = store.version_executable(before.current.as_deref().unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&path, b"corrupted retained bytes").unwrap();
        assert!(admit_public_selection(&store, None).is_err());
        let version = path.parent().unwrap();
        fs::set_permissions(version, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn local_release_requires_a_valid_bounded_identity() {
        let directory = tempdir();
        let missing = local_release(directory.path(), &"a".repeat(64)).unwrap_err();
        assert!(format!("{missing:#}").contains(LOCAL_RELEASE_IDENTITY));
        fs::write(directory.path().join(LOCAL_RELEASE_IDENTITY), b"{}").unwrap();
        assert!(local_release(directory.path(), &"a".repeat(64)).is_err());
        fs::write(
            directory.path().join(LOCAL_RELEASE_IDENTITY),
            vec![b' '; MAX_IDENTITY_BYTES + 1],
        )
        .unwrap();
        assert!(local_release(directory.path(), &"a".repeat(64)).is_err());
    }

    #[test]
    fn local_release_refuses_fifo_and_symlink_identities_promptly() {
        let directory = tempdir();
        let path = directory.path().join(LOCAL_RELEASE_IDENTITY);
        let fifo_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live, NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(local_release(directory.path(), &"a".repeat(64)).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(
            &fs::symlink_metadata(&path).unwrap().file_type()
        ));
        fs::remove_file(&path).unwrap();
        let target = directory.path().join("identity-target");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let error = local_release(directory.path(), &"a".repeat(64)).unwrap_err();
        assert!(format!("{error:#}").contains("open release identity"));
        assert_eq!(fs::read(target).unwrap(), b"{}");
    }

    fn install_args(directory: &Path) -> InstallArgs {
        InstallArgs {
            managed: true,
            bin_dir: Some(directory.join("bin")),
            store: Some(directory.join("store")),
            json: false,
        }
    }

    /// A synthetic executable holding one build record for `target`, and the
    /// identity self-install derives from it.
    fn identified(directory: &Path, target: &str) -> (PathBuf, CwPayloadIdentity) {
        let record = framed(&json("v1.2.30", target, true));
        let decoded = decoded(&record);
        let path = write(
            directory,
            "candidate-cw",
            &executable(&[b"v1.2.3", &record]),
        );
        let identity = executable_identity(&decoded, &record, &path, host()).unwrap();
        (path, identity)
    }

    #[test]
    fn managed_install_refuses_an_unmanaged_entry_and_explains_migration() {
        let directory = tempdir();
        let bin = directory.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join("cw"), b"legacy cw").unwrap();
        let store = directory.path().join("store");
        let (executable, identity) = identified(directory.path(), host_target());
        let error =
            install_identified(install_args(directory.path()), executable, &identity).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("unmanaged regular file"), "{message}");
        assert!(message.contains("install-user-unmanaged"), "{message}");
        assert_eq!(fs::read(bin.join("cw")).unwrap(), b"legacy cw");
        assert!(!store.exists());
    }

    #[test]
    fn self_install_without_source_provenance_changes_nothing() {
        let record = embedded().unwrap();
        if record.source_revision.is_some() {
            // This test binary was built with explicit provenance.
            return;
        }
        let directory = tempdir();
        let error = install(install_args(directory.path())).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("without source provenance"), "{message}");
        assert!(message.contains("make cli-install"), "{message}");
        assert!(!directory.path().join("bin").exists());
        assert!(!directory.path().join("store").exists());
    }

    #[test]
    fn self_install_admits_the_identity_of_its_exact_bytes() {
        let directory = tempdir();
        let (executable, identity) = identified(directory.path(), host_target());
        assert_eq!(identity.package_version, "v1.2.30");
        install_identified(
            install_args(directory.path()),
            executable.clone(),
            &identity,
        )
        .unwrap();
        let store = Store::open(&directory.path().join("store"), DEFAULT_LOCK_TIMEOUT).unwrap();
        let record = store.verify(&identity.sha256).unwrap();
        assert_eq!(record.origin, store::Origin::SelfInstall);
        assert_eq!(record.package_version, "v1.2.30");
        assert_eq!(record.size, identity.size);
        assert_eq!(record.payload, None);
        assert_eq!(
            fs::read_link(directory.path().join("bin/cw")).unwrap(),
            store.version_executable(&identity.sha256)
        );
        // Reinstalling the same bytes is idempotent.
        install_identified(install_args(directory.path()), executable, &identity).unwrap();
        assert_eq!(store.status().unwrap().versions.len(), 1);
    }

    #[test]
    fn self_install_refuses_stored_bytes_with_a_contradicting_identity() {
        let directory = tempdir();
        let release = host().release_target().as_str();
        let (executable, identity) = identified(directory.path(), release);
        let mut pinned = identity.clone();
        pinned.source_revision = "f".repeat(40);
        let entry = directory.path().join("bin");
        fs::create_dir(&entry).unwrap();
        let installed = store::install(
            &directory.path().join("store"),
            &entry.join("cw"),
            &Candidate {
                executable: executable.clone(),
                admission: Admission::Pinned {
                    identity: pinned,
                    sha256: identity.sha256.clone(),
                },
            },
            DEFAULT_LOCK_TIMEOUT,
        )
        .unwrap();
        let generation = installed.selected.generation;
        let error = install_identified(
            install_args(directory.path()),
            executable.clone(),
            &identity,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("contradicts"), "{error:#}");
        assert_eq!(installed.store.status().unwrap().generation, generation);

        // The same bytes pinned under the identical identity are consistent.
        let agreeing = tempdir();
        let entry = agreeing.path().join("bin");
        fs::create_dir(&entry).unwrap();
        store::install(
            &agreeing.path().join("store"),
            &entry.join("cw"),
            &Candidate {
                executable: executable.clone(),
                admission: Admission::Pinned {
                    identity: identity.clone(),
                    sha256: identity.sha256.clone(),
                },
            },
            DEFAULT_LOCK_TIMEOUT,
        )
        .unwrap();
        install_identified(install_args(agreeing.path()), executable, &identity).unwrap();
    }

    #[test]
    fn self_install_refuses_bytes_other_than_its_identity() {
        let directory = tempdir();
        let (executable, mut identity) = identified(directory.path(), host_target());
        identity.sha256 = "e".repeat(64);
        let error =
            install_identified(install_args(directory.path()), executable, &identity).unwrap_err();
        assert!(
            format!("{error:#}").contains("changed while it was installed"),
            "{error:#}"
        );
    }

    #[test]
    fn status_text_marks_the_current_version_and_an_inconsistent_entry() {
        let sha256 = "b".repeat(64);
        let status = Status {
            root: "/home/u/.local/share/codewire/cli".into(),
            entry: "/home/u/.local/bin/cw".into(),
            platform: "linux-x86_64",
            generation: 2,
            current: Some(sha256.clone()),
            previous: None,
            pending: None,
            entry_state: EntryState::ForeignLink {
                target: "/usr/bin/true".into(),
            },
            consistent: false,
            versions: vec![store::VersionSummary {
                sha256: sha256.clone(),
                package_version: Some("v0.3.0".into()),
                origin: Some(store::Origin::SelfInstall),
                size: Some(1024),
                recorded: true,
            }],
        };
        let text = render_status(&status);
        assert!(text.contains(&format!("current:    v0.3.0 ({sha256})")));
        assert!(text.contains("warning:    the entry is a link to /usr/bin/true"));
        assert!(text.contains(&format!("* {sha256} v0.3.0 (self-install)")));
    }
}
