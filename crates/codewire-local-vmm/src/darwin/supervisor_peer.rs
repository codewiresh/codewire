//! Supervisor admission by owner-only socket and the peer's process birth.
//!
//! Darwin exposes no socket-derived process handle, but the kernel names the
//! peer's PID (`LOCAL_PEERPID`). This pin keeps the socket's identity and
//! requires every connection's peer to be the owning user. A
//! configuration-aware caller also pins the peer's birth and executable, and
//! then requires the expected configuration digest over the protocol. It never
//! adopts the peer process; it signals one only to end an older supervisor in
//! a handoff (`terminate`).
//!
//! A cw update leaves a running supervisor on the managed version that started
//! it, and on macOS the VMs stop with their supervisor. As on Linux, a peer
//! whose executable is not this cw is admitted under that executable only when
//! the managed store retains it as a version with the same digest.

use std::ffi::OsString;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixStream;

use super::path::{SocketIdentity, current_uid};
use super::process::{ProcessIdentity, WatchedProcess};
use crate::process_birth::{AdmissionError, ProcessBirth, admit_retained_version, in_a_store};
use crate::supervisor_config::NativeRuntimeConfig;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerError {
    #[error("kernel socket peer credentials are unavailable")]
    Kernel,
    #[error("native supervisor socket or owner identity changed")]
    Identity,
    #[error("native supervisor role or configuration arguments do not match")]
    Role,
    #[error("retained native supervisor executable provenance is unavailable or changed")]
    Provenance,
    #[error("native supervisor runs an executable no managed cw store holds")]
    Unverified { pid: u32, executable: PathBuf },
}

impl From<AdmissionError> for PeerError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Identity => Self::Identity,
            AdmissionError::Provenance => Self::Provenance,
        }
    }
}

/// Opaque and shared: reconnects cannot replace its socket identity or peer.
///
/// The peer is pinned by its process birth and executable file. Only a peer
/// running another cw version has its executable hashed, once, to admit its
/// provenance; a reconnect re-observes the birth and file and never reads
/// the executable again (#2549).
#[derive(Debug)]
pub(crate) struct SupervisorPeerPin {
    socket: PathBuf,
    socket_identity: SocketIdentity,
    peer: Option<ProcessBirth>,
    configuration_digest: Option<[u8; 32]>,
    /// The arguments a supervisor for the requested configuration runs with.
    /// Only a handoff requires them (`require_role`, `terminate`).
    role: Option<Vec<OsString>>,
}

impl SupervisorPeerPin {
    pub(crate) fn capture(
        stream: &UnixStream,
        socket: &Path,
        socket_identity: SocketIdentity,
        requested: Option<&NativeRuntimeConfig>,
    ) -> Result<Arc<Self>, PeerError> {
        let (peer, configuration_digest, role) = match requested {
            None => (None, None, None),
            Some(requested) => {
                let peer = ProcessBirth::observe(peer_pid(stream.as_fd())?)
                    .map_err(|_| PeerError::Identity)?;
                let config = if peer.executable() == requested.executable {
                    requested.clone()
                } else {
                    if !in_a_store(&peer) {
                        return Err(PeerError::Unverified {
                            pid: peer.pid(),
                            executable: peer.executable().to_owned(),
                        });
                    }
                    let identity =
                        ProcessIdentity::capture(peer.pid()).map_err(|_| PeerError::Identity)?;
                    admit_retained_version(&peer, &identity)?;
                    requested
                        .with_supervisor_executable(peer.executable().to_owned())
                        .map_err(|_| PeerError::Identity)?
                };
                (
                    Some(peer),
                    Some(config.configuration_digest()),
                    Some(config.supervisor_argv()),
                )
            }
        };
        let pin = Self {
            socket: socket.to_owned(),
            socket_identity,
            peer,
            configuration_digest,
            role,
        };
        pin.revalidate_stream(stream)?;
        Ok(Arc::new(pin))
    }

    /// The admitted peer's PID and executable, for messages that name it.
    pub(crate) fn peer_process(&self) -> Option<(u32, &Path)> {
        self.peer
            .as_ref()
            .map(|peer| (peer.pid(), peer.executable()))
    }

    /// Remove the socket an ended supervisor left (a SIGTERM skips its own
    /// cleanup), only while it is still the socket this pin admitted.
    pub(crate) fn remove_stale_socket(&self) -> Result<(), crate::uds::UdsError> {
        crate::uds::remove_bound_socket(&self.socket, &self.socket_identity)
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn configuration_digest(&self) -> Option<[u8; 32]> {
        self.configuration_digest
    }

    /// Watch this supervisor's exit for a handoff (supervisor_handoff). The
    /// watch is registered before its socket, arguments and birth are checked
    /// again, so an exit or PID reuse after the check still shows on it. Only
    /// a peer admitted for this state root's configuration may be watched.
    pub(crate) fn watch_exit(&self) -> Result<SupervisorExit, PeerError> {
        let peer = self.peer.as_ref().ok_or(PeerError::Identity)?;
        self.require_role()?;
        self.socket_identity
            .revalidate(&self.socket)
            .map_err(|_| PeerError::Identity)?;
        let identity = ProcessIdentity::capture(peer.pid()).map_err(|_| PeerError::Identity)?;
        if !peer.is(&identity) {
            return Err(PeerError::Identity);
        }
        let watched = WatchedProcess::watch(&identity).map_err(|_| PeerError::Identity)?;
        if watched.is_exited().map_err(|_| PeerError::Kernel)?
            || ProcessBirth::observe(peer.pid()).map_err(|_| PeerError::Identity)? != *peer
        {
            return Err(PeerError::Identity);
        }
        Ok(SupervisorExit(watched))
    }

    /// End this supervisor for a handoff: SIGTERM once `watch_exit` holds.
    /// Darwin has no process descriptor to signal through; the watch shows an
    /// exit after the check, and then no signal is sent.
    pub(crate) fn terminate(&self) -> Result<SupervisorExit, PeerError> {
        let exit = self.watch_exit()?;
        if exit.exited()? {
            return Err(PeerError::Identity);
        }
        let peer = self.peer.as_ref().ok_or(PeerError::Identity)?;
        let pid = rustix::process::Pid::from_raw(
            i32::try_from(peer.pid()).map_err(|_| PeerError::Identity)?,
        )
        .ok_or(PeerError::Identity)?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)
            .map_err(|_| PeerError::Kernel)?;
        Ok(exit)
    }

    /// Require the peer to run exactly as the supervisor for the requested
    /// configuration, as the Linux pin does at every admission. Darwin
    /// connections check it only for a handoff, before any effect on the peer.
    pub(crate) fn require_role(&self) -> Result<(), PeerError> {
        let (Some(peer), Some(role)) = (&self.peer, &self.role) else {
            return Err(PeerError::Role);
        };
        if &process_argv(peer.pid())? != role {
            return Err(PeerError::Role);
        }
        Ok(())
    }

    pub(crate) fn revalidate_stream(&self, stream: &UnixStream) -> Result<(), PeerError> {
        let credential = stream.peer_cred().map_err(|_| PeerError::Kernel)?;
        if credential.uid() != current_uid() {
            return Err(PeerError::Identity);
        }
        self.socket_identity
            .revalidate(&self.socket)
            .map_err(|_| PeerError::Identity)?;
        if let Some(peer) = &self.peer
            && (peer_pid(stream.as_fd())? != peer.pid()
                || ProcessBirth::observe(peer.pid()).map_err(|_| PeerError::Identity)? != *peer)
        {
            return Err(PeerError::Identity);
        }
        Ok(())
    }
}

/// The ended supervisor's exit watch.
#[derive(Debug)]
pub(crate) struct SupervisorExit(WatchedProcess);

impl SupervisorExit {
    pub(crate) fn exited(&self) -> Result<bool, PeerError> {
        self.0.is_exited().map_err(|_| PeerError::Kernel)
    }
}

/// Admit a stream against an ALREADY authoritative process birth, as Linux
/// does with its socket-derived pidfd. The kernel names the peer's PID
/// (`LOCAL_PEERPID`); that PID must carry the expected birth, and the returned
/// kqueue becomes readable when it exits. This does not discover a role,
/// adopt or signal a process, or admit executable provenance.
pub(crate) fn admit_known_process_stream(
    stream: &UnixStream,
    expected: &ProcessIdentity,
) -> Result<OwnedFd, PeerError> {
    admit_known_process_socket(stream.as_fd(), expected)
}

/// As [`admit_known_process_stream`], for any connected Unix socket.
pub(crate) fn admit_known_process_socket(
    socket: BorrowedFd<'_>,
    expected: &ProcessIdentity,
) -> Result<OwnedFd, PeerError> {
    if peer_uid(socket)? != current_uid() || peer_pid(socket)? != expected.pid {
        return Err(PeerError::Identity);
    }
    let watched = WatchedProcess::watch(expected).map_err(|_| PeerError::Identity)?;
    // The PID was read before the birth check; read it again so a peer that
    // exited and was replaced in between is refused.
    if peer_pid(socket)? != expected.pid || watched.is_exited().map_err(|_| PeerError::Kernel)? {
        return Err(PeerError::Identity);
    }
    Ok(watched.into_exit_descriptor())
}

/// Admit a socket whose peer is the recorded process birth. The exit queue
/// is registered before the birth check, so a peer replaced after it is still
/// caught; its executable file is not consulted, so an in-place rebuild or
/// update of that file does not hide the process from its controller.
pub(crate) fn admit_known_birth_socket(
    socket: BorrowedFd<'_>,
    expected: &ProcessIdentity,
) -> Result<OwnedFd, PeerError> {
    if peer_uid(socket)? != current_uid() || peer_pid(socket)? != expected.pid {
        return Err(PeerError::Identity);
    }
    let watched = WatchedProcess::watch(expected).map_err(|_| PeerError::Identity)?;
    if peer_pid(socket)? != expected.pid || watched.is_exited().map_err(|_| PeerError::Kernel)? {
        return Err(PeerError::Identity);
    }
    Ok(watched.into_exit_descriptor())
}

/// The connected socket's peer user.
fn peer_uid(socket: BorrowedFd<'_>) -> Result<u32, PeerError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: a live socket descriptor and two writable outputs.
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(PeerError::Kernel);
    }
    Ok(uid)
}

fn peer_pid(socket: BorrowedFd<'_>) -> Result<u32, PeerError> {
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: a live socket descriptor and a writable pid_t-sized buffer
    // whose length is passed.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::pid_t>() {
        return Err(PeerError::Kernel);
    }
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(PeerError::Kernel)
}

const MAX_ARGV_BYTES: usize = 16 * 1024;

/// A process's arguments from `KERN_PROCARGS2`: argc, the executable path and
/// its padding, then argc NUL-terminated arguments. Only processes of this
/// user are readable.
fn process_argv(pid: u32) -> Result<Vec<OsString>, PeerError> {
    let pid = libc::c_int::try_from(pid).map_err(|_| PeerError::Identity)?;
    let mut maximum: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: a two-entry MIB and a c_int output whose size is passed.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut maximum).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || maximum <= 0
    {
        return Err(PeerError::Kernel);
    }
    let mut buffer = vec![0_u8; usize::try_from(maximum).map_err(|_| PeerError::Kernel)?];
    let mut size = buffer.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: a three-entry MIB and a writable buffer whose size is passed.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(PeerError::Identity);
    }
    parse_procargs2(buffer.get(..size).ok_or(PeerError::Kernel)?)
}

fn parse_procargs2(bytes: &[u8]) -> Result<Vec<OsString>, PeerError> {
    let (count, rest) = bytes.split_at_checked(4).ok_or(PeerError::Role)?;
    let count = usize::try_from(i32::from_ne_bytes(
        count.try_into().map_err(|_| PeerError::Role)?,
    ))
    .map_err(|_| PeerError::Role)?;
    if count == 0 || count > 64 {
        return Err(PeerError::Role);
    }
    let executable_end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(PeerError::Role)?;
    let start = rest[executable_end..]
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(PeerError::Role)?
        + executable_end;
    let mut argv = Vec::with_capacity(count);
    let mut remaining = &rest[start..];
    let mut total = 0_usize;
    for _ in 0..count {
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(PeerError::Role)?;
        total += end + 1;
        if end == 0 || total > MAX_ARGV_BYTES {
            return Err(PeerError::Role);
        }
        argv.push(OsString::from_vec(remaining[..end].to_vec()));
        remaining = &remaining[end + 1..];
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(count: i32, executable: &[u8], padding: usize, argv: &[&[u8]]) -> Vec<u8> {
        let mut bytes = count.to_ne_bytes().to_vec();
        bytes.extend_from_slice(executable);
        bytes.extend(std::iter::repeat_n(0, padding + 1));
        for arg in argv {
            bytes.extend_from_slice(arg);
            bytes.push(0);
        }
        bytes.extend_from_slice(b"HOME=/Users/x\0");
        bytes
    }

    #[test]
    fn procargs2_yields_exactly_argc_arguments() {
        let bytes = procargs(3, b"/cw", 3, &[b"/cw", b"__native-supervisor", b"--root"]);
        assert_eq!(
            parse_procargs2(&bytes).unwrap(),
            ["/cw", "__native-supervisor", "--root"].map(OsString::from)
        );
        for invalid in [
            Vec::new(),
            procargs(0, b"/cw", 0, &[]),
            procargs(65, b"/cw", 0, &[b"/cw"]),
            // Fewer arguments than argc says.
            procargs(4, b"/cw", 0, &[b"/cw", b"__native-supervisor"])[..18].to_vec(),
        ] {
            assert!(parse_procargs2(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn this_process_reads_its_own_arguments() {
        let own = process_argv(std::process::id()).unwrap();
        assert_eq!(own, std::env::args_os().collect::<Vec<_>>());
    }
}
