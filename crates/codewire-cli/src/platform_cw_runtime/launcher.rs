//! Ordinary invocations through supported immutable image aliases only.
//!
//! An image must contain this dispatcher before the Pod is created. Updating
//! the UID1000 Store cannot change a legacy immutable alias without it. Private
//! roles and explicit version paths remain pinned to their original executable.
//! Same-UID Store writes are not an OS tamper or trusted-helper boundary.
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::fs::{HeldFile, Paths, Stamp, Tree};
use super::wire::Code;
use super::{Result, host, open_store, store_error, user};
use codewire_cw_release::store::{EntryState, Status};

/// The current release's cw, which every hosted workspace mounts or copies
/// root-owned and re-pins on each start (docs/dev/SANDBOX-DAEMON.md).
const RELEASE_CW: &str = "/codewire/bin/cw";
/// The workspace image's own cw, which lags every release.
const IMAGE_CW: &str = "/usr/local/bin/cw";
const IMAGE_ALIASES: [&str; 2] = [RELEASE_CW, IMAGE_CW];
const LAUNCH_BUDGET: Duration = Duration::from_secs(120);

enum Launch {
    Store(HeldFile),
    Release(Release),
}

/// Called before ordinary CLI configuration/runtime initialization. Returning
/// success means the caller is not an eligible image alias, or runs itself.
/// An ordinary invocation runs the Store's selection, else, invoked as the
/// image's cw, the release's cw (#5202). It replaces only this new
/// invocation, never an already-running daemon, helper or session. A
/// refusal says what it refused and carries its next step (#6315).
pub fn redirect_from<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<_> = args.into_iter().map(Into::into).collect();
    let launch = admit_arguments(&args, || {
        let home = std::env::var_os("HOME");
        admit_context(user(), home.as_deref(), || {
            let path = fs::read_link("/proc/self/exe").map_err(|_| Code::Io)?;
            if !image_alias(&path) {
                return Ok(None);
            }
            // GNU host installs are not the platform image baseline. No fixed
            // user paths or Store data are read for them.
            let decoded = crate::build_record::embedded().map_err(|_| Code::UnsupportedImage)?;
            if decoded.target != "x86_64-unknown-linux-musl"
                || decoded.target != host()?.release_target().as_str()
            {
                return Ok(None);
            }
            let deadline = Instant::now() + LAUNCH_BUDGET;
            let defers = defers_to_release(&path);
            let image = Image::open(path, &decoded)?;
            let selected = select(&Paths::fixed(), deadline)?;
            image.check()?;
            if Instant::now() >= deadline {
                return Err(Code::Deadline);
            }
            Ok(match selected {
                Some(selected) => Some(Launch::Store(selected)),
                None if defers => Release::open_at(Path::new(RELEASE_CW)).map(Launch::Release),
                None => None,
            })
        })
    })
    .map_err(refusal)?;
    match launch {
        Some(Launch::Store(mut selected)) => {
            selected.check().map_err(refusal)?;
            execute(selected.file_mut(), &args).map_err(refusal)?;
        }
        Some(Launch::Release(mut release)) => {
            release.check().map_err(refusal)?;
            execute(&mut release.file, &args).map_err(refusal)?;
        }
        None => {}
    }
    Ok(())
}

/// Only the image's cw defers to the release's; the release's cw invoked
/// directly runs itself, so the two never redirect to each other.
pub(super) fn defers_to_release(invoked: &Path) -> bool {
    invoked.as_os_str() == std::ffi::OsStr::new(IMAGE_CW)
}

/// The release's cw, held open. It is admitted on the same terms as the
/// image's own: a root-owned, read-only regular file under root-owned
/// directories nobody else can write. Anything else, including its absence,
/// leaves the image's cw to run itself, as it did before.
pub(super) struct Release {
    path: PathBuf,
    file: File,
    before: Stamp,
}

impl Release {
    pub(super) fn open_at(path: &Path) -> Option<Self> {
        image_parents(path).ok()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        if !image_metadata(&metadata) {
            return None;
        }
        let before = Stamp::of(&file).ok()?;
        let release = Self {
            path: path.to_owned(),
            file,
            before,
        };
        release.check().ok()?;
        Some(release)
    }

    fn check(&self) -> Result<()> {
        held_unchanged(&self.path, &self.file, &self.before)
    }
}

/// The refusal's sentence and next step, as docs/dev/SANDBOX-DAEMON.md
/// "Which `cw` a sandbox runs" lists them.
pub(super) fn refusal(code: Code) -> anyhow::Error {
    let (refused, step) = match code {
        Code::UnsafeState => (
            "your cw version store under ~/.local is not private: its directories must be yours, not links, and writable by no one else",
            "ls -ld ~/.local ~/.local/bin ~/.local/share ~/.local/share/codewire",
        ),
        Code::UnmanagedEntry => (
            "~/.local/bin/cw is not the cw this sandbox's version store selected",
            "move ~/.local/bin/cw aside",
        ),
        Code::PendingSelection => (
            "a cw update or rollback in this sandbox did not finish",
            "cw --cloud runtime update ENV, again, from your computer",
        ),
        Code::CandidateRefused => (
            "the cw selected for this sandbox failed its check",
            "cw --cloud runtime rollback ENV, from your computer",
        ),
        Code::UnsupportedImage => (
            "this sandbox's cw is not the root-owned copy its image shipped",
            "cw --cloud stop ENV, then cw --cloud start ENV, from your computer",
        ),
        Code::StaleSelection => (
            "the cw selected for this sandbox changed while it was checked",
            "run the command again",
        ),
        Code::Deadline => (
            "checking which cw this sandbox runs took over 2 minutes",
            "run the command again",
        ),
        Code::Io
        | Code::ReadOnly
        | Code::InvalidFrame
        | Code::StageExists
        | Code::MissingStage
        | Code::InputIncomplete => (
            "could not read which cw version this sandbox runs",
            "run the command again",
        ),
    };
    crate::error_report::with_next_step(anyhow::anyhow!(refused), step)
}

pub(super) fn image_alias(path: &Path) -> bool {
    IMAGE_ALIASES
        .iter()
        .any(|alias| path.as_os_str() == std::ffi::OsStr::new(alias))
}

pub(super) fn admit_arguments<T>(
    args: &[OsString],
    admit: impl FnOnce() -> Result<Option<T>>,
) -> Result<Option<T>> {
    if args.is_empty()
        || crate::is_local_git_ssh_helper(&args[0])
        || args
            .get(1)
            .is_some_and(|role| role.as_bytes().starts_with(b"_"))
    {
        return Ok(None);
    }
    admit()
}

// This existing user context distinguishes the supported image invocation
// from a normal UID1000 public-musl host install at /usr/local/bin/cw. It is
// not an authority or secret boundary; fixed path/file admission still applies.
pub(super) fn admit_context<T>(
    owner: (u32, u32),
    home: Option<&std::ffi::OsStr>,
    admit: impl FnOnce() -> Result<Option<T>>,
) -> Result<Option<T>> {
    if owner != (1000, 1000) || home != Some(std::ffi::OsStr::new("/home/codewire")) {
        return Ok(None);
    }
    admit()
}

struct Image {
    path: PathBuf,
    file: File,
    before: Stamp,
}

impl Image {
    fn open(
        path: PathBuf,
        decoded: &codewire_cw_release::build_record::BuildRecord,
    ) -> Result<Self> {
        if !image_alias(&path) {
            return Err(Code::UnsupportedImage);
        }
        image_parents(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| Code::UnsupportedImage)?;
        let metadata = file.metadata().map_err(|_| Code::UnsupportedImage)?;
        if !image_metadata(&metadata) {
            return Err(Code::UnsupportedImage);
        }
        let running = fs::metadata("/proc/self/exe").map_err(|_| Code::UnsupportedImage)?;
        if metadata.dev() != running.dev() || metadata.ino() != running.ino() {
            return Err(Code::UnsupportedImage);
        }
        let before = Stamp::of(&file)?;
        let identity = crate::build_record::executable_identity(
            decoded,
            &crate::build_record::BUILD_RECORD,
            Path::new("/proc/self/exe"),
            host()?,
        )
        .map_err(|_| Code::UnsupportedImage)?;
        super::wire::identity(&identity).map_err(|_| Code::UnsupportedImage)?;
        crate::build_record::admit_incoming(&mut file, &path, &identity, host()?)
            .map_err(|_| Code::UnsupportedImage)?;
        let image = Self { path, file, before };
        image.check()?;
        Ok(image)
    }

    fn check(&self) -> Result<()> {
        held_unchanged(&self.path, &self.file, &self.before)
    }
}

/// The held file and the file its path names now are still the one admitted.
fn held_unchanged(path: &Path, file: &File, before: &Stamp) -> Result<()> {
    image_parents(path)?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Code::UnsupportedImage)?;
    if Stamp::of(file)? != *before || Stamp::of(&named)? != *before {
        return Err(Code::UnsupportedImage);
    }
    Ok(())
}

fn image_metadata(m: &fs::Metadata) -> bool {
    m.is_file()
        && m.uid() == 0
        && m.gid() == 0
        && m.nlink() == 1
        && (1..=codewire_cw_release::identity::MAX_EXECUTABLE_BYTES).contains(&m.len())
        && matches!(m.mode() & 0o7777, 0o555 | 0o755)
}

fn image_parents(path: &Path) -> Result<()> {
    for parent in path
        .parent()
        .ok_or(Code::UnsupportedImage)?
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let m = fs::symlink_metadata(parent).map_err(|_| Code::UnsupportedImage)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o7022 != 0
            || m.mode() & 0o555 != 0o555
        {
            return Err(Code::UnsupportedImage);
        }
    }
    Ok(())
}

fn selected_status(status: &Status) -> Result<&str> {
    if status.pending.is_some() {
        return Err(Code::PendingSelection);
    }
    let sha = status.current.as_deref().ok_or(Code::StaleSelection)?;
    if !status.consistent
        || !matches!(&status.entry_state, EntryState::Managed { sha256 } if sha256 == sha)
    {
        return Err(Code::UnmanagedEntry);
    }
    Ok(sha)
}

fn same_selection(before: &Status, after: &Status) -> bool {
    before.generation == after.generation
        && before.current == after.current
        && before.previous == after.previous
        && before.pending == after.pending
        && before.entry_state == after.entry_state
        && before.consistent == after.consistent
}

/// Existing held ancestry and read-only Store APIs; this never creates a lock,
/// parent, entry or recovery intent. A read linearizes at one verified tuple;
/// an ordinary concurrent Store writer may select again after that observation.
pub(super) fn select(paths: &Paths, deadline: Instant) -> Result<Option<HeldFile>> {
    select_before_recheck(paths, deadline, || {})
}

pub(super) fn select_before_recheck(
    paths: &Paths,
    deadline: Instant,
    before_recheck: impl FnOnce(),
) -> Result<Option<HeldFile>> {
    let tree = Tree::open(paths, false)?;
    let _lock = tree.read_lock(deadline)?;
    let Some(store) = open_store(&tree, paths)? else {
        if tree.entry_present()? {
            return Err(Code::UnmanagedEntry);
        }
        tree.check()?;
        return Ok(None);
    };
    let before = store.status().map_err(store_error)?;
    let sha = selected_status(&before)?;
    let record = store.verify(sha).map_err(store_error)?;
    let identity = record.payload.ok_or(Code::UnsupportedImage)?;
    super::wire::identity(&identity)?;
    let path = store.version_executable(sha);
    let mut held = HeldFile::open(&path, identity.size, 0o555)?;
    crate::build_record::admit_incoming(held.file_mut(), &path, &identity, host()?)
        .map_err(|_| Code::CandidateRefused)?;
    held.check()?;
    before_recheck();
    let after = store.status().map_err(store_error)?;
    selected_status(&after)?;
    if !same_selection(&before, &after) || Instant::now() >= deadline {
        return Err(Code::StaleSelection);
    }
    tree.check()?;
    held.check()?;
    Ok(Some(held))
}

pub(super) fn execute(file: &mut File, args: &[OsString]) -> Result<()> {
    let argv_strings = args
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Code::Io)?;
    let environment_strings = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.as_bytes());
            CString::new(entry)
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Code::Io)?;
    let mut argv: Vec<_> = argv_strings.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut environment: Vec<_> = environment_strings.iter().map(|e| e.as_ptr()).collect();
    environment.push(std::ptr::null());
    // SAFETY: the admitted regular static ELF FD and all C strings/arrays stay
    // live through fexecve. No pathname is reopened for execution. CLOEXEC is
    // correct for this ELF-only boundary; successful exec never returns.
    unsafe { libc::fexecve(file.as_raw_fd(), argv.as_ptr(), environment.as_ptr()) };
    Err(Code::Io)
}
