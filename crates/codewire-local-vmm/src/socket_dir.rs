//! Short private per-user socket directories (#2735).
//!
//! A Unix socket path holds at most 107 bytes on Linux and 103 on macOS, and
//! HOME has no bound, so no native socket lives under HOME. Every supervisor,
//! runner and VM socket lives in one short private directory per user,
//! `/tmp/cw-<uid>` (`/private/tmp/cw-<uid>` on macOS, never the long
//! `$TMPDIR`), in a subdirectory named by a digest of the state root it
//! serves: `/tmp/cw-<uid>/<16 hex>/`. State, disks, locks and logs stay under
//! the state root.
//!
//! Safety. Cloud Hypervisor, virtiofsd and the VZ helper bind and connect by
//! pathname, so the argument is the temporary directory's sticky bit: `/tmp`
//! must be root-owned and sticky (or owned by this user and writable by no
//! one else), so no other user can rename or replace `cw-<uid>` or anything
//! beneath it. That directory is opened without following links and checked
//! through the held descriptor: owned by this user, mode exactly 0700. An
//! existing directory is never repaired. When another user holds the name, cw
//! falls back as ssh-agent does: a private `mkdtemp` directory whose name is
//! recorded in the state root ([`RECORD`], 0600), so every process serving
//! that root finds it. Directories are created on demand, since tmpfiles and
//! periodic cleaning remove them. A per-root directory carries a marker
//! naming its state root, so a digest collision fails instead of sharing.

use std::ffi::OsStr;
use std::io::{self, Read, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use codewire_cw_release::sha256::Sha256;
use rustix::fs::{Mode, OFlags};

use crate::host::path::{PrivateRoot, current_uid};

/// The longest socket path the kernel accepts, excluding the NUL.
#[cfg(target_os = "linux")]
pub const MAXIMUM_SOCKET_PATH_BYTES: usize = 107;
#[cfg(target_os = "macos")]
pub const MAXIMUM_SOCKET_PATH_BYTES: usize = 103;

/// The shared temporary directory; on macOS `/tmp` is a link to it.
#[cfg(target_os = "linux")]
const TEMPORARY: &str = "/tmp";
#[cfg(target_os = "macos")]
const TEMPORARY: &str = "/private/tmp";

/// The fallback directory's name, recorded in the state root.
pub const RECORD: &str = "socket-dir";
/// The marker naming the state root a per-root directory serves.
const MARKER: &str = "root";
const ROOT_ID_HEX: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum SocketDirError {
    #[error(
        "{path} is not safe for private sockets: it must be owned by root with the sticky bit set, or owned by you and writable by no one else (owner uid {owner}, mode {mode:o})"
    )]
    UnsafeTemporary {
        path: PathBuf,
        owner: u32,
        mode: u32,
    },
    #[error(
        "{path} belongs to uid {owner} with mode {mode:o}, not to you (uid {uid}) with mode 700, and no private fallback could be made: {source}"
    )]
    Unusable {
        path: PathBuf,
        owner: u32,
        mode: u32,
        uid: u32,
        source: io::Error,
    },
    #[error(
        "the socket directory {directory} already serves another state root ({other}); remove it and retry"
    )]
    Collision { directory: PathBuf, other: String },
    #[error("the local VM socket path {path} would be {length} bytes, over the {limit}-byte limit")]
    PathTooLong {
        path: PathBuf,
        length: usize,
        limit: usize,
    },
    #[error(transparent)]
    Path(#[from] crate::host::path::PathError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

fn io_error(context: impl Into<String>) -> impl FnOnce(io::Error) -> SocketDirError {
    let context = context.into();
    move |source| SocketDirError::Io { context, source }
}

/// Permission bits of a `st_mode`, which is `u32` on Linux and `u16` on
/// macOS.
fn permission_bits(mode: impl Into<u32>) -> u32 {
    mode.into() & 0o7777
}

/// The per-user default, `/tmp/cw-<uid>`.
fn default_base(temporary: &Path, uid: u32) -> PathBuf {
    temporary.join(format!("cw-{uid}"))
}

/// The name a state root's directory takes under the base.
fn root_id(state_root: &Path) -> String {
    let digest = format!("{:x}", Sha256::digest(state_root.as_os_str().as_bytes()));
    digest[..ROOT_ID_HEX].to_owned()
}

/// A recorded fallback is only ever `<temporary>/cw-<uid>.<suffix>`.
fn valid_fallback(temporary: &Path, path: &Path, uid: u32) -> bool {
    let prefix = format!("cw-{uid}.");
    path.parent() == Some(temporary)
        && path
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix(&prefix))
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
}

fn read_record(
    temporary: &Path,
    state_root: &Path,
    uid: u32,
) -> Result<Option<PathBuf>, SocketDirError> {
    let path = state_root.join(RECORD);
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(format!("read {}", path.display()))(source)),
    };
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(256)
        .read_to_string(&mut text)
        .map_err(io_error(format!("read {}", path.display())))?;
    let recorded = PathBuf::from(text.trim_end_matches('\n'));
    Ok(valid_fallback(temporary, &recorded, uid).then_some(recorded))
}

/// Where the sockets of `state_root` live, without creating anything: what a
/// client connects to. [`prepare`] creates and checks it.
pub fn predicted(state_root: &Path) -> PathBuf {
    predicted_in(Path::new(TEMPORARY), state_root, current_uid())
}

fn predicted_in(temporary: &Path, state_root: &Path, uid: u32) -> PathBuf {
    let base = read_record(temporary, state_root, uid)
        .ok()
        .flatten()
        .unwrap_or_else(|| default_base(temporary, uid));
    base.join(root_id(state_root))
}

/// Opens the temporary directory and checks it can hold private names.
fn open_temporary(path: &Path, uid: u32) -> Result<OwnedFd, SocketDirError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| io_error(format!("open {}", path.display()))(errno.into()))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|errno| io_error(format!("inspect {}", path.display()))(errno.into()))?;
    let mode = permission_bits(stat.st_mode);
    let owner = stat.st_uid;
    let sticky_root = owner == 0 && mode & 0o1000 != 0;
    let private = owner == uid && mode & 0o022 == 0;
    if !(sticky_root || private) {
        return Err(SocketDirError::UnsafeTemporary {
            path: path.to_owned(),
            owner,
            mode,
        });
    }
    Ok(fd)
}

/// Owner and mode of `name` in `parent`, after creating it 0700 if absent.
/// `Ok(None)` means it is ours and private; `Ok(Some(..))` that it is not.
fn ensure_private_in(
    parent: &OwnedFd,
    name: &Path,
    uid: u32,
) -> Result<Option<(u32, u32)>, SocketDirError> {
    match rustix::fs::mkdirat(parent.as_fd(), name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(errno) => {
            return Err(io_error(format!("create {}", name.display()))(errno.into()));
        }
    }
    let fd = match rustix::fs::openat(
        parent.as_fd(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // A link or a non-directory under the name: not ours.
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
            let stat =
                rustix::fs::statat(parent.as_fd(), name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|errno| {
                        io_error(format!("inspect {}", name.display()))(errno.into())
                    })?;
            return Ok(Some((stat.st_uid, permission_bits(stat.st_mode))));
        }
        Err(errno) => {
            return Err(io_error(format!("open {}", name.display()))(errno.into()));
        }
    };
    let stat = rustix::fs::fstat(&fd)
        .map_err(|errno| io_error(format!("inspect {}", name.display()))(errno.into()))?;
    let mode = permission_bits(stat.st_mode);
    if stat.st_uid == uid && mode == 0o700 {
        Ok(None)
    } else {
        Ok(Some((stat.st_uid, mode)))
    }
}

/// Makes a fresh private fallback and records it in the state root.
fn make_fallback(temporary: &Path, state_root: &Path, uid: u32) -> io::Result<PathBuf> {
    let template = temporary.join(format!("cw-{uid}.XXXXXXXX"));
    let mut bytes = template.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: `bytes` is a NUL-terminated, writable buffer that mkdtemp
    // fills in place; it creates the directory 0700.
    let created = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) };
    if created.is_null() {
        return Err(io::Error::last_os_error());
    }
    bytes.pop();
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    let record = state_root.join(RECORD);
    let staging = state_root.join(format!(".{RECORD}.tmp"));
    let _ = std::fs::remove_file(&staging);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staging)?;
    file.write_all(path.as_os_str().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&staging, &record)?;
    Ok(path)
}

/// The per-user base for `state_root`: the default, a recorded fallback, or
/// a new fallback when another user holds the default name.
fn prepare_base(
    temporary_path: &Path,
    state_root: &Path,
    uid: u32,
) -> Result<PathBuf, SocketDirError> {
    let temporary = open_temporary(temporary_path, uid)?;
    if let Some(recorded) = read_record(temporary_path, state_root, uid)? {
        let name = recorded.file_name().map(Path::new).unwrap_or(Path::new(""));
        // A recorded fallback that tmpfiles removed is made again under the
        // same name; one another user took is replaced below.
        if ensure_private_in(&temporary, name, uid)?.is_none() {
            return Ok(recorded);
        }
    }
    let default = default_base(temporary_path, uid);
    let name = default.file_name().map(Path::new).unwrap_or(Path::new(""));
    match ensure_private_in(&temporary, name, uid)? {
        None => {
            match std::fs::remove_file(state_root.join(RECORD)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(io_error(format!(
                        "remove {}",
                        state_root.join(RECORD).display()
                    ))(source));
                }
            }
            Ok(default)
        }
        Some((owner, mode)) => make_fallback(temporary_path, state_root, uid).map_err(|source| {
            SocketDirError::Unusable {
                path: default,
                owner,
                mode,
                uid,
                source,
            }
        }),
    }
}

/// Creates and checks the socket directory of `state_root`, which must be
/// the canonical absolute path every process uses, and returns it.
pub fn prepare(state_root: &Path) -> Result<PathBuf, SocketDirError> {
    prepare_in(Path::new(TEMPORARY), state_root, current_uid())
}

fn prepare_in(temporary: &Path, state_root: &Path, uid: u32) -> Result<PathBuf, SocketDirError> {
    let base = PrivateRoot::open(&prepare_base(temporary, state_root, uid)?)?;
    let id = root_id(state_root);
    let directory = base.ensure_dir(Path::new(&id), 0o700)?;
    let dir = PrivateRoot::open(&directory)?;
    let marker = state_root.as_os_str().as_bytes();
    // The first process to serve this root writes the marker; every later
    // one, and a racing one whose exclusive create lost, reads it.
    if let Ok(created) = dir.create_regular(Path::new(MARKER), 0o600, true) {
        let mut file = created.into_file();
        file.write_all(marker)
            .and_then(|()| file.sync_all())
            .map_err(io_error(format!(
                "write {}",
                directory.join(MARKER).display()
            )))?;
        return Ok(directory);
    }
    let opened = dir.open_regular(Path::new(MARKER), false, None, false, Some(0o600))?;
    let mut existing = Vec::new();
    opened
        .into_file()
        .take(4097)
        .read_to_end(&mut existing)
        .map_err(io_error(format!(
            "read {}",
            directory.join(MARKER).display()
        )))?;
    if existing != marker {
        return Err(SocketDirError::Collision {
            directory,
            other: String::from_utf8_lossy(&existing).into_owned(),
        });
    }
    Ok(directory)
}

/// Creates `relative` (single components, each 0700) under a prepared
/// socket directory and returns it.
pub fn ensure_subdirectory(directory: &Path, relative: &[&str]) -> Result<PathBuf, SocketDirError> {
    let mut current = directory.to_owned();
    for component in relative {
        let root = PrivateRoot::open(&current)?;
        current = root.ensure_dir(Path::new(component), 0o700)?;
    }
    Ok(current)
}

/// How often a supervisor refreshes its sockets' timestamps.
pub const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Marks every entry under `directory` as just used. systemd-tmpfiles ages
/// entries of `/tmp` by their timestamps (ten days on Fedora), and a live
/// socket's never change; a supervisor calls this every
/// [`REFRESH_INTERVAL`] so a long-running VM keeps its sockets. Errors are
/// ignored: a missing entry is recreated on demand.
pub fn refresh(directory: &Path) {
    fn walk(path: &Path, depth: usize) {
        let now = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_NOW,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_NOW,
            },
        };
        let _ = rustix::fs::utimensat(
            rustix::fs::CWD,
            path,
            &now,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| !kind.is_symlink()) {
                walk(&entry.path(), depth - 1);
            }
        }
    }
    // <root id>/vms/<vm>/{api,vsock,fs}/<socket>
    walk(directory, 4);
}

/// Refuses a socket path the kernel cannot bind, naming it and the limit.
pub fn check_length(path: &Path) -> Result<(), SocketDirError> {
    let length = path.as_os_str().len();
    if length > MAXIMUM_SOCKET_PATH_BYTES {
        return Err(SocketDirError::PathTooLong {
            path: path.to_owned(),
            length,
            limit: MAXIMUM_SOCKET_PATH_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
