//! A live, socket-derived supervisor birth. No numeric-PID adoption or effects;
//! the pidfd signals an older supervisor only to end it in a handoff
//! (`terminate`).

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codewire_cw_release::sha256::Sha256;
use tokio::net::UnixStream;

use super::path::{FileIdentity, SocketIdentity, current_uid};
use super::process::ProcessIdentity;
use crate::process_birth::{AdmissionError, ProcessBirth, admit_retained_version};
use crate::supervisor_config::NativeRuntimeConfig;

const MAX_ARGV_BYTES: usize = 16 * 1024;
const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerError {
    #[error("kernel socket-derived process identity is unavailable")]
    Kernel,
    #[error("native supervisor process, socket or executable identity changed")]
    Identity,
    #[error("native supervisor role or configuration arguments do not match")]
    Role,
    #[error("retained native supervisor executable provenance is unavailable or changed")]
    Provenance,
}

impl From<AdmissionError> for PeerError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Identity => Self::Identity,
            AdmissionError::Provenance => Self::Provenance,
        }
    }
}

/// Opaque and shared: reconnects cannot replace its socket or process birth.
///
/// The peer is pinned by its pidfd, its process birth and executable file, and
/// its arguments. Only a peer running another cw version has its executable
/// hashed, once, to admit its provenance; a reconnect re-observes the birth
/// and never reads the executable again (#2549).
#[derive(Debug)]
pub(crate) struct SupervisorPeerPin {
    socket: PathBuf,
    socket_identity: SocketIdentity,
    pidfd: OwnedFd,
    peer: ProcessBirth,
    argv: Vec<OsString>,
    config: Option<NativeRuntimeConfig>,
}

impl SupervisorPeerPin {
    pub(crate) fn capture(
        stream: &UnixStream,
        socket: &Path,
        socket_identity: SocketIdentity,
        requested: Option<&NativeRuntimeConfig>,
    ) -> Result<Arc<Self>, PeerError> {
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let (pidfd, pid) = socket_pidfd(stream)?;
        require_live(&pidfd)?;
        let peer = ProcessBirth::observe(pid).map_err(|_| PeerError::Identity)?;
        let argv = process_argv(pid)?;
        let config = requested
            .map(|config| {
                config
                    .with_supervisor_executable(peer.executable().to_owned())
                    .map_err(|_| PeerError::Identity)
            })
            .transpose()?;
        if let Some(config) = &config
            && argv != config.supervisor_argv()
        {
            return Err(PeerError::Role);
        }
        if requested.is_some_and(|config| config.executable != peer.executable()) {
            admit_retained_version(&peer, &capture_process(pid, deadline)?)?;
        }
        let pin = Arc::new(Self {
            socket: socket.to_owned(),
            socket_identity,
            pidfd,
            peer,
            argv,
            config,
        });
        pin.revalidate(deadline)?;
        Ok(pin)
    }

    /// The admitted peer's PID and executable, for messages that name it.
    pub(crate) fn peer_process(&self) -> Option<(u32, &Path)> {
        Some((self.peer.pid(), self.peer.executable()))
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
        self.config
            .as_ref()
            .map(NativeRuntimeConfig::configuration_digest)
    }

    pub(crate) fn revalidate_stream(&self, stream: &UnixStream) -> Result<(), PeerError> {
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let (peer, pid) = socket_pidfd(stream)?;
        require_live(&peer)?;
        if pid != self.peer.pid() {
            return Err(PeerError::Identity);
        }
        self.revalidate(deadline)
    }

    /// The role is checked at every admission on Linux; a handoff only
    /// requires that this peer was admitted for a configuration.
    pub(crate) fn require_role(&self) -> Result<(), PeerError> {
        if self.config.is_none() {
            return Err(PeerError::Role);
        }
        Ok(())
    }

    /// Watch this supervisor's exit for a handoff (supervisor_handoff), once
    /// its birth, arguments and socket check out again. The pidfd names this
    /// birth.
    pub(crate) fn watch_exit(&self) -> Result<SupervisorExit, PeerError> {
        self.require_role()?;
        self.revalidate(Instant::now() + ADMISSION_TIMEOUT)?;
        Ok(SupervisorExit(
            rustix::io::dup(&self.pidfd).map_err(|_| PeerError::Kernel)?,
        ))
    }

    /// End this supervisor for a handoff: SIGTERM through the pidfd, which
    /// never reaches a reused PID, once `watch_exit` holds.
    pub(crate) fn terminate(&self) -> Result<SupervisorExit, PeerError> {
        let exit = self.watch_exit()?;
        rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::TERM)
            .map_err(|_| PeerError::Kernel)?;
        Ok(exit)
    }

    fn revalidate(&self, deadline: Instant) -> Result<(), PeerError> {
        require_live(&self.pidfd)?;
        self.socket_identity
            .revalidate(&self.socket)
            .map_err(|_| PeerError::Identity)?;
        if ProcessBirth::observe(self.peer.pid()).map_err(|_| PeerError::Identity)? != self.peer
            || process_argv(self.peer.pid())? != self.argv
        {
            return Err(PeerError::Identity);
        }
        require_live(&self.pidfd)?;
        if Instant::now() >= deadline {
            return Err(PeerError::Identity);
        }
        Ok(())
    }
}

/// The ended supervisor's pidfd, readable once it has exited.
#[derive(Debug)]
pub(crate) struct SupervisorExit(OwnedFd);

impl SupervisorExit {
    pub(crate) fn exited(&self) -> Result<bool, PeerError> {
        let mut entry = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized entry and a nonblocking timeout.
        let result = unsafe { libc::poll(&mut entry, 1, 0) };
        if result < 0 {
            return Err(PeerError::Kernel);
        }
        Ok(result != 0)
    }
}

fn socket_pidfd(stream: &UnixStream) -> Result<(OwnedFd, u32), PeerError> {
    // SO_PEERPIDFD pins the birth that supplied this connected socket. A later
    // pidfd_open(SO_PEERCRED.pid) could instead open a reused numeric PID.
    let mut raw = -1_i32;
    let mut length = std::mem::size_of_val(&raw) as libc::socklen_t;
    // SAFETY: the socket is live, and the output and length are initialized.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut raw as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 || raw < 0 {
        return Err(PeerError::Kernel);
    }
    // SAFETY: getsockopt returned a new descriptor owned by this call.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    if length as usize != std::mem::size_of::<i32>() {
        return Err(PeerError::Kernel);
    }
    // SAFETY: fcntl reads/sets flags on our live descriptor only.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(PeerError::Kernel);
    }
    let credentials = stream.peer_cred().map_err(|_| PeerError::Kernel)?;
    let pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or(PeerError::Kernel)?;
    if credentials.uid() != current_uid() {
        return Err(PeerError::Identity);
    }
    let info = read_bounded(&PathBuf::from(format!("/proc/self/fdinfo/{raw}")), 4096)?;
    let target = std::str::from_utf8(&info)
        .map_err(|_| PeerError::Kernel)?
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|value| value.parse::<u32>().ok());
    if target != Some(pid) {
        return Err(PeerError::Kernel);
    }
    Ok((pidfd, pid))
}

/// Admit a stream against an ALREADY authoritative process birth. This does
/// not discover a role, adopt a process, or admit executable provenance.
/// The runtime publisher uses the persisted, revalidated VMM identity.
pub(crate) fn admit_known_process_stream(
    stream: &UnixStream,
    expected: &ProcessIdentity,
) -> Result<OwnedFd, PeerError> {
    let (pidfd, pid) = socket_pidfd(stream)?;
    require_live(&pidfd)?;
    if pid != expected.pid || capture_process(pid, Instant::now() + ADMISSION_TIMEOUT)? != *expected
    {
        return Err(PeerError::Identity);
    }
    require_live(&pidfd)?;
    Ok(pidfd)
}

fn require_live(pidfd: &OwnedFd) -> Result<(), PeerError> {
    let mut entry = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized entry and a nonblocking timeout.
    let result = unsafe { libc::poll(&mut entry, 1, 0) };
    if result != 0 || entry.revents != 0 {
        return Err(PeerError::Identity);
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, PeerError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PeerError::Identity)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PeerError::Identity)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(PeerError::Identity);
    }
    Ok(bytes)
}

fn process_argv(pid: u32) -> Result<Vec<OsString>, PeerError> {
    let bytes = read_bounded(
        &PathBuf::from(format!("/proc/{pid}/cmdline")),
        MAX_ARGV_BYTES,
    )?;
    if bytes.last() != Some(&0) {
        return Err(PeerError::Role);
    }
    let argv = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|arg| OsString::from_vec(arg.to_vec()))
        .collect::<Vec<_>>();
    if argv.iter().any(|arg| arg.as_bytes().is_empty()) || argv.len() > 64 {
        return Err(PeerError::Role);
    }
    Ok(argv)
}

fn capture_process(pid: u32, deadline: Instant) -> Result<ProcessIdentity, PeerError> {
    let boot = read_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let boot_id = std::str::from_utf8(&boot)
        .map_err(|_| PeerError::Identity)?
        .trim()
        .to_owned();
    if uuid::Uuid::parse_str(&boot_id).is_err() {
        return Err(PeerError::Identity);
    }
    let stat = read_bounded(&PathBuf::from(format!("/proc/{pid}/stat")), 4096)?;
    let stat = std::str::from_utf8(&stat).map_err(|_| PeerError::Identity)?;
    let fields = stat.rsplit_once(") ").ok_or(PeerError::Identity)?.1;
    let start_time_ticks = fields
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|ticks| *ticks > 0)
        .ok_or(PeerError::Identity)?;
    let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
    let executable = fs::read_link(&proc_executable).map_err(|_| PeerError::Identity)?;
    if !executable.is_absolute() || fs::canonicalize(&executable).ok().as_ref() != Some(&executable)
    {
        return Err(PeerError::Identity);
    }
    // Only this kernel-owned proc symlink is deliberately followed.
    let mut file = File::open(&proc_executable).map_err(|_| PeerError::Identity)?;
    let before = file.metadata().map_err(|_| PeerError::Identity)?;
    let executable_file = FileIdentity::from_metadata(&before);
    if !before.is_file()
        || before.len() == 0
        || before.len() > MAX_IMAGE_BYTES
        || before.mode() & 0o6022 != 0
    {
        return Err(PeerError::Identity);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        if Instant::now() >= deadline {
            return Err(PeerError::Identity);
        }
        let count = file.read(&mut buffer).map_err(|_| PeerError::Identity)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(PeerError::Identity)?;
        if total > before.len() {
            return Err(PeerError::Identity);
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| PeerError::Identity)?;
    let path_metadata = fs::symlink_metadata(&executable).map_err(|_| PeerError::Identity)?;
    if total != before.len()
        || FileIdentity::from_metadata(&after) != executable_file
        || FileIdentity::from_metadata(&path_metadata) != executable_file
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(PeerError::Identity);
    }
    Ok(ProcessIdentity {
        pid,
        boot_id,
        start_time_ticks,
        executable,
        executable_file,
        executable_sha256: format!("{:x}", digest.finalize()),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod runtime_peer_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    #[tokio::test]
    async fn live_runtime_known_socket_peer_pins_the_actual_kernel_birth() {
        let parent = tempfile::Builder::new()
            .prefix("cw-rp-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(std::fs::canonicalize("/var/tmp").unwrap())
            .unwrap();
        let socket = parent.path().join("peer.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        crate::linux::path::set_socket_private(&socket).unwrap();
        let expected = ProcessIdentity::capture(std::process::id()).unwrap();
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (_accepted, _) = listener.accept().await.unwrap();
        let pidfd = admit_known_process_stream(&stream, &expected).unwrap();
        let flags = unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut foreign = expected.clone();
        foreign.start_time_ticks += 1;
        assert!(admit_known_process_stream(&stream, &foreign).is_err());
        foreign = expected.clone();
        foreign.executable_sha256 = "a".repeat(64);
        assert!(admit_known_process_stream(&stream, &foreign).is_err());
        foreign = expected;
        foreign.pid = foreign.pid.checked_add(1).unwrap();
        assert!(admit_known_process_stream(&stream, &foreign).is_err());
    }
}
