//! One connection to a Unix socket in the workload, for a Unix-socket
//! forward over SSH (`direct-streamlocal@openssh.com`, #5608; `SPEC.md`,
//! "Port forwarding over SSH").
//!
//! [`target`] admits a path's shape: absolute, at most [`MAX_PATH_BYTES`],
//! no NUL. [`connect`] then opens the path with `O_PATH`, following links as
//! `connect` would, checks what it opened (a socket, not one of the
//! platform's [`crate::platform_sockets`], not in the platform's own
//! directories), and connects through `/proc/self/fd/N`, so the socket it
//! checked is the socket it connects to, with no link or rename in between.
//!
//! Both the lookup and the connect run as the calling thread's identity.
//! A hosted Sandbox's daemon already runs as the workload user in the
//! workload's filesystem, so it calls [`connect`] directly.

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::{io, os::fd::AsRawFd as _, os::unix::net::UnixStream, path::Path};

#[cfg(target_os = "linux")]
use rustix::fs::{FileType, Mode, OFlags};
use thiserror::Error;

use crate::platform_sockets;

/// The longest path a Unix socket address holds (`sun_path`, less its NUL).
pub const MAX_PATH_BYTES: usize = 107;

/// The longest target a refusal or a log line repeats; a longer one is cut.
const SHOWN_PATH_CHARS: usize = 160;

/// Why a forward did not connect. The client sees the message.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum UnixForwardError {
    /// The target is one a forward may never reach, or not a path at all.
    #[error("{0}")]
    Refused(String),
    /// The target may be reached, but nothing accepted the connection.
    #[error("{0}")]
    Failed(String),
}

/// `path` as a log line or a refusal shows it: escaped, and cut short.
pub fn shown(path: &str) -> String {
    let escaped: String = path.escape_debug().collect();
    if escaped.chars().count() <= SHOWN_PATH_CHARS {
        return format!("\"{escaped}\"");
    }
    let cut: String = escaped.chars().take(SHOWN_PATH_CHARS).collect();
    format!("\"{cut}\"…")
}

/// The socket path a forward names, if its shape is one a forward takes.
pub fn target(path: &str) -> Result<PathBuf, UnixForwardError> {
    if path.contains('\0') {
        return Err(UnixForwardError::Refused(format!(
            "a socket forward names a path, and {} holds a NUL",
            shown(path)
        )));
    }
    if !path.starts_with('/') {
        return Err(UnixForwardError::Refused(format!(
            "a socket forward names an absolute path, not {} (relative paths and \
             abstract names are refused)",
            shown(path)
        )));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(UnixForwardError::Refused(format!(
            "{} is {} bytes, longer than a Unix socket path can be ({MAX_PATH_BYTES})",
            shown(path),
            path.len()
        )));
    }
    Ok(PathBuf::from(path))
}

/// Why a connect did not happen, as a fixed code: what a forward helper in
/// the workload reports, and all the daemon takes from it. The daemon gives
/// the client its own words ([`Refusal::describe`]), never the helper's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotSocket,
    /// The platform socket at this index of the list the check was given.
    PlatformSocket(usize),
    /// The platform directory at this index of [`platform_sockets::PLATFORM_DIRECTORIES`].
    PlatformDirectory(usize),
    NotFound,
    PermissionDenied,
    NotListening,
    Failed,
}

/// The status line a helper prints once it has connected.
pub const CONNECTED: &str = "connected";

/// The longest status line a daemon reads from a helper, newline included.
pub const MAX_STATUS_BYTES: usize = 40;

impl Refusal {
    /// The status line for this refusal, without its newline.
    pub fn code(self) -> String {
        match self {
            Self::NotSocket => "not-a-socket".into(),
            Self::PlatformSocket(index) => format!("platform-socket {index}"),
            Self::PlatformDirectory(index) => format!("platform-directory {index}"),
            Self::NotFound => "not-found".into(),
            Self::PermissionDenied => "permission-denied".into(),
            Self::NotListening => "not-listening".into(),
            Self::Failed => "failed".into(),
        }
    }

    /// A status line a helper printed: `Ok(())` for [`CONNECTED`], the
    /// refusal it names, or `None` for anything else. `platform` is how many
    /// platform sockets the helper was given.
    pub fn parse(line: &str, platform: usize) -> Option<Result<(), Self>> {
        let index = |rest: &str, bound: usize| {
            rest.parse::<usize>()
                .ok()
                .filter(|index| *index < bound && rest == index.to_string())
        };
        Some(Err(match line {
            CONNECTED => return Some(Ok(())),
            "not-a-socket" => Self::NotSocket,
            "not-found" => Self::NotFound,
            "permission-denied" => Self::PermissionDenied,
            "not-listening" => Self::NotListening,
            "failed" => Self::Failed,
            _ => {
                if let Some(rest) = line.strip_prefix("platform-socket ") {
                    Self::PlatformSocket(index(rest, platform)?)
                } else {
                    let rest = line.strip_prefix("platform-directory ")?;
                    Self::PlatformDirectory(index(
                        rest,
                        platform_sockets::PLATFORM_DIRECTORIES.len(),
                    )?)
                }
            }
        }))
    }

    /// The daemon's own words for this refusal of `shown`, the target as
    /// [`shown`] wrote it; `names` are the platform sockets' names, in the
    /// order the check was given them.
    pub fn describe(self, shown: &str, names: &[&str]) -> UnixForwardError {
        const PLATFORM: &str = "which belongs to the platform; forwarding cannot reach it";
        match self {
            Self::NotSocket => UnixForwardError::Refused(format!("{shown} is not a socket")),
            Self::PlatformSocket(index) => UnixForwardError::Refused(format!(
                "{shown} is {}, {}",
                names
                    .get(index)
                    .copied()
                    .unwrap_or("one of the platform's sockets"),
                PLATFORM
            )),
            Self::PlatformDirectory(index) => UnixForwardError::Refused(format!(
                "{shown} is in {}, the platform's own directory; forwarding cannot reach it",
                platform_sockets::PLATFORM_DIRECTORIES
                    .get(index)
                    .copied()
                    .unwrap_or("a platform directory")
            )),
            Self::NotFound => {
                UnixForwardError::Failed(format!("nothing in the environment is at {shown}"))
            }
            Self::PermissionDenied => UnixForwardError::Failed(format!(
                "the environment's user may not connect to {shown}"
            )),
            Self::NotListening => {
                UnixForwardError::Failed(format!("nothing is listening on {shown}"))
            }
            Self::Failed => {
                UnixForwardError::Failed(format!("connecting to {shown} in the environment failed"))
            }
        }
    }
}

/// Connect to the socket at `path`, as this thread's identity, unless it is
/// one of this process's platform sockets (see the module docs).
#[cfg(target_os = "linux")]
pub fn connect(path: &Path) -> Result<UnixStream, UnixForwardError> {
    let platform = platform_sockets::snapshot();
    let identities: Vec<(u64, u64)> = platform
        .iter()
        .map(|(device, inode, _)| (*device, *inode))
        .collect();
    let names: Vec<&str> = platform.iter().map(|(_, _, name)| *name).collect();
    connect_among(path, &identities)
        .map_err(|refusal| refusal.describe(&shown(&path.to_string_lossy()), &names))
}

/// Connect to the socket at `path`, as this thread's identity, unless it is
/// not a socket, is one of `platform` (each a device and inode), or resolves
/// under one of the platform's directories.
#[cfg(target_os = "linux")]
pub fn connect_among(path: &Path, platform: &[(u64, u64)]) -> Result<UnixStream, Refusal> {
    let opened = rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| refusal(error.into()))?;
    let status = rustix::fs::fstat(&opened).map_err(|error| refusal(error.into()))?;
    if FileType::from_raw_mode(status.st_mode) != FileType::Socket {
        return Err(Refusal::NotSocket);
    }
    let link = format!("/proc/self/fd/{}", opened.as_raw_fd());
    let resolved = std::fs::read_link(&link).map_err(refusal)?;
    let identity = platform
        .iter()
        .position(|identity| *identity == (status.st_dev, status.st_ino));
    admit(identity, &resolved)?;
    UnixStream::connect(&link).map_err(refusal)
}

/// Whether a socket at `resolved`, which is the platform socket at index
/// `identity` of the check's list if it is one, may be reached. Its identity
/// comes first, so the one directory the backstop exempts never admits a
/// platform socket (#5608).
#[cfg(target_os = "linux")]
pub fn admit(identity: Option<usize>, resolved: &Path) -> Result<(), Refusal> {
    if let Some(index) = identity {
        return Err(Refusal::PlatformSocket(index));
    }
    match platform_sockets::platform_directory_index(resolved) {
        Some(index) => Err(Refusal::PlatformDirectory(index)),
        None => Ok(()),
    }
}

/// A local VM's forward helper, `init workspace-unix-connect PATH
/// [DEVICE:INODE]...`, run as a workload process (#5608): check and connect
/// as [`connect_among`] does, print one status line on `status`, and once
/// connected relay `input` to the socket and the socket to `output` until
/// both directions end. The daemon trusts none of it; see
/// [`Refusal::parse`].
#[cfg(target_os = "linux")]
pub fn relay(
    arguments: &[String],
    status: &mut impl io::Write,
    mut input: impl io::Read + Send,
    mut output: impl io::Write,
) -> io::Result<()> {
    let platform: Option<Vec<(u64, u64)>> = arguments
        .iter()
        .skip(1)
        .map(|identity| {
            let (device, inode) = identity.split_once(':')?;
            Some((device.parse().ok()?, inode.parse().ok()?))
        })
        .collect();
    let connected = match (arguments.first(), platform) {
        (Some(path), Some(platform)) => target(path)
            .map_err(|_| Refusal::Failed)
            .and_then(|path| connect_among(&path, &platform)),
        _ => Err(Refusal::Failed),
    };
    let stream = match connected {
        Ok(stream) => {
            writeln!(status, "{CONNECTED}")?;
            status.flush()?;
            stream
        }
        Err(refusal) => {
            writeln!(status, "{}", refusal.code())?;
            return status.flush();
        }
    };
    let mut to_socket = stream.try_clone()?;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            // Either end failing ends this direction like its end of stream:
            // the socket is half-closed so its server sees the end, and the
            // other direction runs on. Nobody is left to tell of an error.
            let _ = io::copy(&mut input, &mut to_socket);
            let _ = to_socket.shutdown(std::net::Shutdown::Write);
        });
        copy_flushing(&stream, &mut output)
    })
}

/// Copies until end of stream, flushing after every write: the helper's
/// `output` is its stdout, which would otherwise hold back everything after
/// the last newline, such as a WebSocket frame, while the connection stays
/// open.
#[cfg(target_os = "linux")]
fn copy_flushing(mut from: impl io::Read, output: &mut impl io::Write) -> io::Result<()> {
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = match from.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        output.write_all(&buffer[..read])?;
        output.flush()?;
    }
}

#[cfg(target_os = "linux")]
fn refusal(error: io::Error) -> Refusal {
    match error.kind() {
        io::ErrorKind::NotFound => Refusal::NotFound,
        io::ErrorKind::PermissionDenied => Refusal::PermissionDenied,
        io::ErrorKind::ConnectionRefused => Refusal::NotListening,
        _ => Refusal::Failed,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
