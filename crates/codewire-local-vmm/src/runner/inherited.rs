//! Descriptors and limits a runner child inherits (#2638), moved out of
//! `runner.rs` unchanged.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::egress_broker::{EGRESS_BROKER_FIRST_SESSION_FD, EGRESS_BROKER_INHERITED_SESSIONS};

/// Inherited sources are duplicated at or above this descriptor, above every
/// fixed target a child uses, so placing one never overwrites another.
pub(super) const INHERITED_SOURCE_FLOOR: RawFd = 64;
const _: () = assert!(
    EGRESS_BROKER_FIRST_SESSION_FD + EGRESS_BROKER_INHERITED_SESSIONS as RawFd
        <= INHERITED_SOURCE_FLOOR
);

/// The soft open-file limit of the network worker and egress broker (#2638).
/// The worker holds up to 256 guest connections, 64 inbound streams and every
/// broker session; macOS starts processes at 256. Never above the hard limit.
pub(super) const NETWORK_ROLE_OPEN_FILE_LIMIT: libc::rlim_t = 1024;

/// Raise the soft open-file limit to [`NETWORK_ROLE_OPEN_FILE_LIMIT`], or to
/// the hard limit if that is lower. Runs in the child before exec.
pub(super) fn raise_open_file_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let wanted = NETWORK_ROLE_OPEN_FILE_LIMIT.min(limit.rlim_max);
    if limit.rlim_cur < wanted {
        limit.rlim_cur = wanted;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn duplicate_inherited_descriptor(descriptor: i32) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC reads no memory; the result is checked below.
    let duplicated =
        unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, INHERITED_SOURCE_FLOOR) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicated` is a new descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}
