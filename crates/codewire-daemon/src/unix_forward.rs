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

#[cfg(target_os = "linux")]
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

/// Connect to the socket at `path`, as this thread's identity, unless it is
/// one the platform keeps (see the module docs).
#[cfg(target_os = "linux")]
pub fn connect(path: &Path) -> Result<UnixStream, UnixForwardError> {
    let named = shown(&path.to_string_lossy());
    let opened = rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| failure(&named, error.into()))?;
    let status = rustix::fs::fstat(&opened).map_err(|error| failure(&named, error.into()))?;
    if FileType::from_raw_mode(status.st_mode) != FileType::Socket {
        return Err(UnixForwardError::Refused(format!(
            "{named} is not a socket"
        )));
    }
    if let Some(name) = platform_sockets::named(status.st_dev, status.st_ino) {
        return Err(UnixForwardError::Refused(format!(
            "{named} is {name}, which belongs to the platform; forwarding cannot reach it"
        )));
    }
    let link = format!("/proc/self/fd/{}", opened.as_raw_fd());
    let resolved = std::fs::read_link(&link).map_err(|error| failure(&named, error))?;
    if let Some(directory) = platform_sockets::platform_directory(&resolved) {
        return Err(UnixForwardError::Refused(format!(
            "{named} is in {directory}, the platform's own directory; forwarding cannot \
             reach it"
        )));
    }
    UnixStream::connect(&link).map_err(|error| failure(&named, error))
}

#[cfg(target_os = "linux")]
fn failure(named: &str, error: io::Error) -> UnixForwardError {
    UnixForwardError::Failed(match error.kind() {
        io::ErrorKind::NotFound => format!("nothing in the environment is at {named}"),
        io::ErrorKind::PermissionDenied => {
            format!("the environment's user may not connect to {named}")
        }
        io::ErrorKind::ConnectionRefused => format!("nothing is listening on {named}"),
        _ => format!("connecting to {named} in the environment failed: {error}"),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
