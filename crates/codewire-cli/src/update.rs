//! `cw update` and `cw install --managed`.
//!
//! A managed installation keeps every admitted cw at an immutable digest path
//! in an ordinary-user store and points one entry, normally `~/.local/bin/cw`,
//! at the selected version. New invocations follow the selection; running
//! processes and the commands they saved keep their original bytes and path.
//! Source resolution is separate from installation: today the only source is
//! an explicitly pinned local release directory. Public release fetching stays
//! disabled until a release signing key is admitted.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Args, Subcommand};
use codewire_cw_release::identity::{CwPayloadIdentity, MAX_IDENTITY_BYTES};
use codewire_cw_release::store::{
    self, Admission, Candidate, DEFAULT_LOCK_TIMEOUT, EntryState, Status, Store, StoreError,
};
use rustix::fs::{self as rfs, Mode, OFlags};
use serde::Serialize;

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
    #[arg(long, value_name = "DIR", requires = "sha256")]
    from: Option<PathBuf>,
    /// SHA-256 of the release `cw`; required with --from.
    #[arg(long, value_name = "HEX", requires = "from")]
    sha256: Option<String>,
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
}

pub(crate) fn run(args: UpdateArgs) -> anyhow::Result<()> {
    match (args.command, args.from, args.sha256) {
        (Some(UpdateCommand::Status(store)), _, _) => status(store),
        (Some(UpdateCommand::Rollback(rollback)), _, _) => {
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
                },
                rollback.selection.store.json,
            )
        }
        (None, Some(directory), Some(sha256)) => {
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
                },
                args.selection.store.json,
            )
        }
        (None, _, _) => anyhow::bail!(
            "public cw releases are not available yet, so automatic updates are unavailable \
             during the private preview; update your authorized source checkout and run \
             `make cli-install` from its root, or select a pinned local release with \
             `cw update --from DIR --sha256 HEX`"
        ),
    }
}

pub(crate) fn install(args: InstallArgs) -> anyhow::Result<()> {
    debug_assert!(args.managed);
    let root = match args.store {
        Some(root) => absolute(root)?,
        None => default_store_root()?,
    };
    let bin_dir = match args.bin_dir {
        Some(directory) => absolute(directory)?,
        None => default_bin_dir()?,
    };
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("create managed entry directory {}", bin_dir.display()))?;
    let candidate = Candidate {
        executable: running_executable()?,
        admission: Admission::SelfInstall {
            package_version: crate::CLI_VERSION.to_owned(),
        },
    };
    let installed = store::install(&root, &bin_dir.join("cw"), &candidate, DEFAULT_LOCK_TIMEOUT)
        .map_err(with_hint)?;
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
        },
        args.json,
    )
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
        "{running} is not a managed installation and no managed store exists at {}; install one \
         with `make cli-install` from an authorized source checkout or `cw install --managed`. \
         An existing regular-file cw is never replaced automatically.",
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

    use super::*;
    use crate::{Cli, Command};

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
    fn public_update_stays_disabled_and_explains_source_install() {
        let error = run(UpdateArgs {
            command: None,
            from: None,
            sha256: None,
            selection: SelectionArgs {
                expect_generation: None,
                store: StoreArgs {
                    store: None,
                    json: false,
                },
            },
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("private preview"));
        assert!(error.contains("make cli-install"));
        assert!(error.contains("cw update --from DIR --sha256 HEX"));
    }

    #[test]
    fn local_release_requires_a_valid_bounded_identity() {
        let directory = tempfile::tempdir().unwrap();
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
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCAL_RELEASE_IDENTITY);
        rfs::mkfifoat(rfs::CWD, &path, Mode::from_raw_mode(0o600)).unwrap();
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

    #[test]
    fn managed_install_refuses_an_unmanaged_entry_and_explains_migration() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join("cw"), b"legacy cw").unwrap();
        let store = directory.path().join("store");
        let error = install(InstallArgs {
            managed: true,
            bin_dir: Some(bin.clone()),
            store: Some(store.clone()),
            json: false,
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("unmanaged regular file"), "{message}");
        assert!(message.contains("install-user-unmanaged"), "{message}");
        assert_eq!(fs::read(bin.join("cw")).unwrap(), b"legacy cw");
        assert!(!store.exists());
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
