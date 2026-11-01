//! What a long-lived owner process and its controllers need from the kernel,
//! on Linux and macOS alike (#3797).
//!
//! A controller that did not spawn the owner never adopts it: macOS has no
//! handle for a process this process did not start, and the shared model must
//! not depend on Linux's pidfds. Instead the controller connects to the owner's
//! socket and admits the peer as exactly the recorded process birth
//! ([`admit_process_socket`]), then asks it to stop over the protocol. A child
//! the owner starts ends with it ([`exit_with_parent`]). Whether a recorded
//! birth still lives can be asked without adopting it ([`recorded_birth_alive`]).

use std::io;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::time::Duration;

use crate::host::process::{self, ProcessIdentity, RecoveryError};

/// Why a stream's peer was not admitted as the recorded process.
#[derive(Debug, thiserror::Error)]
pub enum PeerAdmissionError {
    #[error("the socket peer's process identity is unavailable from the kernel")]
    Kernel,
    #[error("the socket peer is not the recorded process")]
    Identity,
}

/// The admitted peer's exit: a descriptor that polls readable once it exits,
/// a pidfd on Linux and a kqueue on macOS.
#[derive(Debug)]
pub struct PeerExit(OwnedFd);

impl PeerExit {
    pub fn has_exited(&self) -> io::Result<bool> {
        let mut entry = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized entry and a zero timeout, which never blocks.
        let result = unsafe { libc::poll(&mut entry, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if entry.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("process exit descriptor became invalid"));
        }
        Ok(entry.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    /// Whether the peer exited within `timeout`.
    pub async fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.has_exited()? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Admit a connected Unix socket whose peer must be exactly `expected`: the
/// owning user and that PID and birth. Its executable file is not consulted, so
/// an in-place rebuild or update of it does not hide the process. It never
/// adopts or signals the peer.
pub fn admit_process_socket(
    socket: &impl AsFd,
    expected: &ProcessIdentity,
) -> Result<PeerExit, PeerAdmissionError> {
    crate::host::supervisor_peer::admit_known_birth_socket(socket.as_fd(), expected)
        .map(PeerExit)
        .map_err(|error| match error {
            crate::host::supervisor_peer::PeerError::Kernel => PeerAdmissionError::Kernel,
            _ => PeerAdmissionError::Identity,
        })
}

/// Whether the recorded birth still runs. Its PID being absent, held by
/// another birth, or an exit not yet reaped means it ended; it is never
/// adopted.
pub fn recorded_birth_alive(expected: &ProcessIdentity) -> Result<bool, RecoveryError> {
    match process::birth_if_present(expected.pid)? {
        Some((boot_id, start))
            if boot_id == expected.boot_id && start == expected.start_time_ticks =>
        {
            Ok(!process::exited_unreaped(expected.pid)?)
        }
        _ => Ok(false),
    }
}

/// End this process when its parent exits; call it first thing in a child.
/// Linux uses the parent-death signal, which fires when the thread that
/// spawned the child exits, so a parent must spawn from a thread that lives as
/// long as it does. macOS has no parent-death signal and watches the parent
/// from a thread instead. A parent that exited before this call is caught by
/// both.
pub fn exit_with_parent() -> io::Result<()> {
    process::exit_with_parent()
}
