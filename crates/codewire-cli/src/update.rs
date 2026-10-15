//! `cw update` and `cw install --managed`.
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

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct UpdateArgs {
    #[command(subcommand)]
    command: Option<UpdateCommand>,
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
enum UpdateCommand {
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
    /// Restart local VMs still running on the previous cw without asking;
    /// a restart ends the work running in them.
    #[arg(long)]
    restart_vms: bool,
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

pub(crate) async fn run(args: UpdateArgs) -> anyhow::Result<()> {
    match (
        args.command,
        args.from,
        args.sha256,
        args.version,
        args.channel,
    ) {
        (Some(UpdateCommand::Status(store)), _, _, _, _) => status(store),
        (Some(UpdateCommand::Rollback(rollback)), _, _, _, _) => {
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
            hand_off_local_vms(&store, &selected.current, &rollback.selection);
            Ok(())
        }
        (None, Some(directory), Some(sha256), None, None) => {
            let store = open_store(args.selection.store.store.as_deref())?;
            let candidate = local_release(&directory, &sha256)?;
            let (published, selected) = store
                .publish_and_select(&candidate, args.selection.expect_generation)
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
                args.selection.store.json,
            )?;
            hand_off_local_vms(&store, &published.sha256, &args.selection);
            Ok(())
        }
        (None, None, None, Some(version), None) => {
            public_release(public_fetch::Selection::Version(version), args.selection).await
        }
        // Without a source, cw follows the signed stable channel.
        (None, None, None, None, channel) if channel.as_deref().is_none_or(|c| c == "stable") => {
            public_release(public_fetch::Selection::Stable, args.selection).await
        }
        _ => anyhow::bail!(
            "cw update takes one source: --version vMAJOR.MINOR.PATCH, --channel stable, \
             or --from DIR --sha256 HEX"
        ),
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
    hand_off_local_vms(&store, &published.sha256, &options);
    Ok(())
}

/// After a selection, let the selected cw offer to restart local VMs still
/// running on the previous one: it runs that version's own `env --local
/// upgrade --after-update`, since this cw's code may be the older. A version
/// without that command is asked silently first and skipped. Never for an
/// explicit --store, which the user's `cw` may not resolve to. It never fails
/// the update, which has already succeeded.
fn hand_off_local_vms(store: &Store, sha256: &str, options: &SelectionArgs) {
    use std::process::{Command, Stdio};
    if !cfg!(any(target_os = "linux", target_os = "macos"))
        || options.store.store.is_some()
        || store.verify(sha256).is_err()
    {
        return;
    }
    let executable = store.version_executable(sha256);
    let supported = Command::new(&executable)
        .args(["env", "--local", "upgrade", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !supported {
        return;
    }
    let mut command = Command::new(&executable);
    command.args(["env", "--local", "upgrade", "--after-update"]);
    if options.restart_vms {
        command.arg("--yes");
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
        eprintln!("cw: restart local VMs still on the previous cw with `cw env --local upgrade`");
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
        "public update refuses an uncertain or inconsistent Store selection; observe cw update status and resolve the owning operation first"
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
         intended version with `cw update rollback`",
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
            "  pending:    interrupted selection of {}; the next update or rollback resolves it from the entry",
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
        println!("Previous version {previous} is retained; `cw update rollback` selects it.");
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
            "Restore the entry to the selected version shown by `cw update status`, or remove \
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
    fn update_and_install_grammar() {
        let sha256 = "a".repeat(64);
        assert!(matches!(
            parse(&["cw", "update"]),
            Ok(Command::Update(UpdateArgs {
                command: None,
                from: None,
                ..
            }))
        ));
        assert!(matches!(
            parse(&["cw", "update", "status", "--json"]),
            Ok(Command::Update(UpdateArgs {
                command: Some(UpdateCommand::Status(StoreArgs { json: true, .. })),
                ..
            }))
        ));
        let Ok(Command::Update(UpdateArgs {
            command: Some(UpdateCommand::Rollback(rollback)),
            ..
        })) = parse(&[
            "cw",
            "update",
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
        let Ok(Command::Update(update)) = parse(&[
            "cw",
            "update",
            "--from",
            "/releases/1.2.3",
            "--sha256",
            &sha256,
        ]) else {
            panic!("update --from");
        };
        assert_eq!(update.from.as_deref(), Some(Path::new("/releases/1.2.3")));
        assert!(parse(&["cw", "update", "--from", "/releases/1.2.3"]).is_err());
        assert!(parse(&["cw", "update", "--sha256", &sha256]).is_err());
        assert!(
            parse(&[
                "cw", "update", "--from", "/r", "--sha256", &sha256, "status"
            ])
            .is_err()
        );
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
        let Ok(Command::Update(version)) = parse(&["cw", "update", "--version", "v1.2.3"]) else {
            panic!("version");
        };
        assert_eq!(version.version.as_deref(), Some("v1.2.3"));
        assert!(version.channel.is_none() && version.from.is_none());
        let Ok(Command::Update(channel)) = parse(&[
            "cw",
            "update",
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
            vec!["cw", "update", "--version", ""],
            vec!["cw", "update", "--version", "1.2.3"],
            vec!["cw", "update", "--version", "v1.2.3/../../x"],
            vec!["cw", "update", "--version", "v1.2.3", "--version", "v1.2.4"],
            vec!["cw", "update", "--channel", "stable", "--channel", "stable"],
            vec!["cw", "update", "--channel", "dev"],
            vec!["cw", "update", "--version", "v1.2.3", "--channel", "stable"],
            vec![
                "cw",
                "update",
                "--from",
                "/r",
                "--sha256",
                &sha,
                "--version",
                "v1.2.3",
            ],
            vec![
                "cw",
                "update",
                "--from",
                "/r",
                "--sha256",
                &sha,
                "--channel",
                "stable",
            ],
            vec!["cw", "update", "--channel", "stable", "status"],
            vec!["cw", "update", "--version", "v1.2.3", "rollback"],
            vec![
                "cw",
                "update",
                "--channel",
                "stable",
                "--url",
                "https://example.invalid",
            ],
            vec!["cw", "update", "--channel", "stable", "--key", "/tmp/key"],
            vec![
                "cw",
                "update",
                "--channel",
                "stable",
                "--proxy",
                "http://127.0.0.1:1",
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }

    #[tokio::test]
    async fn update_without_a_source_follows_the_stable_channel() {
        // The stable channel opens the managed store before any fetch, so a
        // missing store proves the selection without touching the network.
        let directory = tempdir();
        let store = directory.path().join("missing-store");
        let error = run(UpdateArgs {
            command: None,
            from: None,
            sha256: None,
            version: None,
            channel: None,
            selection: SelectionArgs {
                expect_generation: None,
                restart_vms: false,
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
