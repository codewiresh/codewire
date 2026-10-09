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

const IMAGE_ALIASES: [&str; 2] = ["/codewire/bin/cw", "/usr/local/bin/cw"];
const LAUNCH_BUDGET: Duration = Duration::from_secs(120);

/// Called before ordinary CLI configuration/runtime initialization. Returning
/// success means the caller is not an eligible image alias, or has no Store.
/// A selected payload replaces only this new ordinary invocation, never an
/// already-running daemon, helper or session.
pub fn redirect_from<I, T>(args: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<_> = args.into_iter().map(Into::into).collect();
    let selected = admit_arguments(&args, || {
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
            let image = Image::open(path, &decoded)?;
            let selected = select(&Paths::fixed(), deadline)?;
            image.check()?;
            if Instant::now() >= deadline {
                return Err(Code::Deadline);
            }
            Ok(selected)
        })
    })
    .map_err(refusal)?;
    if let Some(mut selected) = selected {
        selected.check().map_err(refusal)?;
        execute(selected.file_mut(), &args).map_err(refusal)?;
    }
    Ok(())
}

fn refusal(_: Code) -> std::io::Error {
    std::io::Error::other("platform CW default selection refused")
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
        image_parents(&self.path)?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|_| Code::UnsupportedImage)?;
        if Stamp::of(&self.file)? != self.before || Stamp::of(&named)? != self.before {
            return Err(Code::UnsupportedImage);
        }
        Ok(())
    }
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
