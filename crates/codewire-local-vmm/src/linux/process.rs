use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use codewire_cw_release::sha256::Sha256;
use rustix::process::{
    Pid, PidfdFlags, PidfdGetfdFlags, Signal, pidfd_getfd, pidfd_open, pidfd_send_signal,
};

use super::path::FileIdentity;
pub use crate::supervisor_metadata::legacy::ProcessIdentity;

impl ProcessIdentity {
    pub fn capture(pid: u32) -> Result<Self, RecoveryError> {
        let (boot_id, start_time_ticks) = birth_of(pid)?;
        let executable =
            fs::read_link(format!("/proc/{pid}/exe")).map_err(RecoveryError::ReadProcess)?;
        if !executable.is_absolute()
            || executable
                .as_os_str()
                .to_string_lossy()
                .ends_with(" (deleted)")
        {
            return Err(RecoveryError::MalformedProcess);
        }
        let executable_handle =
            fs::File::open(format!("/proc/{pid}/exe")).map_err(RecoveryError::ReadProcess)?;
        let executable_metadata = executable_handle
            .metadata()
            .map_err(RecoveryError::ReadProcess)?;
        let executable_file = FileIdentity::from_metadata(&executable_metadata);
        let executable_sha256 = sha256_reader(executable_handle)?;
        Ok(Self {
            pid,
            boot_id,
            start_time_ticks,
            executable,
            executable_file,
            executable_sha256,
        })
    }
}

fn sha256_reader(mut reader: fs::File) -> Result<String, RecoveryError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(RecoveryError::ReadProcess)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub struct LiveProcess {
    identity: ProcessIdentity,
    pidfd: OwnedFd,
}

impl std::fmt::Debug for LiveProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveProcess")
            .field("identity", &self.identity)
            .field("pidfd", &self.pidfd.as_raw_fd())
            .finish()
    }
}

impl LiveProcess {
    pub fn capture_child(pid: u32, expected_executable: &Path) -> Result<Self, RecoveryError> {
        // The caller still owns the unreaped Child, so this numeric PID cannot
        // be recycled while the pidfd and identity are captured. Open the
        // pidfd first and hash the executable once; a second full capture
        // would add latency without strengthening the process-birth binding.
        let pidfd = open_process_pidfd(pid)?;
        let identity = ProcessIdentity::capture(pid)?;
        if identity.executable != expected_executable {
            return Err(RecoveryError::UnexpectedSpawnedExecutable);
        }
        let process = Self { identity, pidfd };
        if process.is_exited()? {
            return Err(RecoveryError::ProcessExited);
        }
        Ok(process)
    }

    pub fn recover(expected: &ProcessIdentity) -> Result<Self, RecoveryError> {
        // Open the pidfd before performing the one full identity comparison.
        // The pidfd pins that process birth while `open_stable` verifies the
        // boot ID, start time, executable metadata, and executable digest.
        // Capturing once before and once after pidfd_open adds no identity
        // guarantee: a PID recycled between those operations is still caught
        // by the post-open comparison against `expected`.
        Self::open_stable(expected.clone())
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn signal(&self, signal: Signal) -> Result<(), RecoveryError> {
        pidfd_send_signal(&self.pidfd, signal).map_err(RecoveryError::Pidfd)
    }

    pub(crate) fn duplicate_wait_descriptor(&self) -> Result<OwnedFd, RecoveryError> {
        rustix::io::dup(&self.pidfd).map_err(RecoveryError::Pidfd)
    }

    /// Duplicate one descriptor from this exact process birth and return its
    /// socket domain. This is deliberately narrower than exposing the pidfd or
    /// a general remote-fd duplication primitive: the qualified-host verifier
    /// uses it to reject even unbound AF_INET/AF_INET6 sockets that `/proc/net`
    /// does not report.
    pub fn socket_domain_for_fd(&self, target_fd: i32) -> Result<i32, RecoveryError> {
        if target_fd < 0 {
            return Err(RecoveryError::InvalidTargetFd(target_fd));
        }
        let duplicate = pidfd_getfd(&self.pidfd, target_fd, PidfdGetfdFlags::empty())
            .map_err(RecoveryError::DuplicateProcessFd)?;
        socket_domain(&duplicate)
    }

    pub fn is_exited(&self) -> Result<bool, RecoveryError> {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized entry for the duration of
        // the call, and a zero timeout never blocks.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 {
            return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
        }
        Ok(result == 1 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    pub async fn wait_exited(&self, timeout: Duration) -> Result<bool, RecoveryError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_exited()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn open_stable(identity: ProcessIdentity) -> Result<Self, RecoveryError> {
        let pidfd = open_process_pidfd(identity.pid)?;
        if ProcessIdentity::capture(identity.pid)? != identity {
            return Err(RecoveryError::IdentityMismatch);
        }
        let process = Self { identity, pidfd };
        if process.is_exited()? {
            return Err(RecoveryError::ProcessExited);
        }
        Ok(process)
    }
}

fn open_process_pidfd(expected_pid: u32) -> Result<OwnedFd, RecoveryError> {
    let raw_pid =
        i32::try_from(expected_pid).map_err(|_| RecoveryError::InvalidPid(expected_pid))?;
    let pid = Pid::from_raw(raw_pid).ok_or(RecoveryError::InvalidPid(expected_pid))?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(classify_pidfd_open_error)?;
    validate_pidfd_target(&pidfd, expected_pid)?;
    Ok(pidfd)
}

fn classify_pidfd_open_error(error: rustix::io::Errno) -> RecoveryError {
    if error == rustix::io::Errno::SRCH {
        RecoveryError::ProcessExited
    } else {
        RecoveryError::Pidfd(error)
    }
}

fn socket_domain(socket: &OwnedFd) -> Result<i32, RecoveryError> {
    let mut domain = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: socket is an owned live descriptor, and domain/length are
    // initialized writable values of the exact sizes required by
    // getsockopt(SOL_SOCKET, SO_DOMAIN).
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&raw mut domain).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(RecoveryError::InspectSocket(io::Error::last_os_error()));
    }
    if length as usize != std::mem::size_of::<i32>() {
        return Err(RecoveryError::MalformedSocketDomain);
    }
    Ok(domain)
}

/// Signal a just-spawned child before full identity admission. The caller must
/// still own the unreaped `Child`; that guarantees the numeric PID cannot be
/// recycled between spawn and `pidfd_open`. The signal itself is pidfd-only.
pub(crate) fn signal_unreaped_child(pid: u32, signal: Signal) -> Result<(), RecoveryError> {
    let raw_pid = i32::try_from(pid).map_err(|_| RecoveryError::InvalidPid(pid))?;
    let pid = Pid::from_raw(raw_pid).ok_or(RecoveryError::InvalidPid(pid))?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(RecoveryError::Pidfd)?;
    pidfd_send_signal(&pidfd, signal).map_err(RecoveryError::Pidfd)
}

fn validate_pidfd_target(pidfd: &OwnedFd, expected_pid: u32) -> Result<(), RecoveryError> {
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(RecoveryError::ReadProcess)?;
    let pid = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(RecoveryError::MalformedProcess)?;
    if pid != i64::from(expected_pid) {
        return Err(RecoveryError::IdentityMismatch);
    }
    Ok(())
}

/// A live process's boot ID and start time in clock ticks: its birth.
pub(crate) fn birth_of(pid: u32) -> Result<(String, u64), RecoveryError> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(RecoveryError::InvalidPid(pid));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(RecoveryError::ReadProcess)?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        return Err(RecoveryError::MalformedProcess);
    }
    let stat =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(RecoveryError::ReadProcess)?;
    Ok((boot_id, parse_start_time(&stat)?))
}

/// The executable a live process runs: its canonical path, and the metadata of
/// the running file, which that path must still name.
pub(crate) fn executable_of(pid: u32) -> Result<(PathBuf, fs::Metadata), RecoveryError> {
    let link = format!("/proc/{pid}/exe");
    let executable = fs::read_link(&link).map_err(RecoveryError::ReadProcess)?;
    if !executable.is_absolute() || fs::canonicalize(&executable).ok().as_ref() != Some(&executable)
    {
        return Err(RecoveryError::MalformedProcess);
    }
    // Only this kernel-owned proc link is followed: it names the running file.
    let metadata = fs::metadata(&link).map_err(RecoveryError::ReadProcess)?;
    let named = fs::symlink_metadata(&executable).map_err(RecoveryError::ReadProcess)?;
    if FileIdentity::from_metadata(&named) != FileIdentity::from_metadata(&metadata) {
        return Err(RecoveryError::IdentityMismatch);
    }
    Ok((executable, metadata))
}

fn parse_start_time(stat: &str) -> Result<u64, RecoveryError> {
    let suffix = stat
        .rfind(") ")
        .and_then(|index| stat.get(index + 2..))
        .ok_or(RecoveryError::MalformedProcess)?;
    // The suffix begins at field 3 (state); starttime is field 22.
    suffix
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(RecoveryError::MalformedProcess)
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("invalid persisted process ID {0}")]
    InvalidPid(u32),
    #[error("read process identity failed: {0}")]
    ReadProcess(io::Error),
    #[error("process identity data is malformed")]
    MalformedProcess,
    #[error("persisted process identity no longer matches the live process")]
    IdentityMismatch,
    #[error("spawned process executable does not match the admitted VMM")]
    UnexpectedSpawnedExecutable,
    #[error("spawned process identity changed while acquiring its pidfd")]
    SpawnedIdentityChangedDuringCapture,
    #[error("invalid target process file descriptor {0}")]
    InvalidTargetFd(i32),
    #[error("process exited during recovery")]
    ProcessExited,
    #[error("duplicate exact process descriptor failed: {0}")]
    DuplicateProcessFd(rustix::io::Errno),
    #[error("inspect duplicated process socket failed: {0}")]
    InspectSocket(io::Error),
    #[error("duplicated process socket returned a malformed domain")]
    MalformedSocketDomain,
    #[error("pidfd operation failed: {0}")]
    Pidfd(rustix::io::Errno),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn proc_stat_parser_uses_last_close_paren() {
        let mut fields = vec!["S".to_owned()];
        fields.extend((4..=21).map(|field| field.to_string()));
        fields.push("987654".to_owned());
        fields.extend((23..=52).map(|field| field.to_string()));
        let stat = format!("123 (tricky ) process name) {}", fields.join(" "));
        assert_eq!(parse_start_time(&stat).unwrap(), 987654);
    }

    #[test]
    fn recovery_holds_a_pidfd_for_the_exact_current_process() {
        let pid = std::process::id();
        let identity = ProcessIdentity::capture(pid).unwrap();
        let live = LiveProcess::recover(&identity).unwrap();
        assert_eq!(live.identity(), &identity);
        assert!(!live.is_exited().unwrap());
    }

    #[test]
    fn stale_identity_is_rejected_before_any_signal_surface_exists() {
        let mut identity = ProcessIdentity::capture(std::process::id()).unwrap();
        identity.start_time_ticks += 1;
        assert!(matches!(
            LiveProcess::recover(&identity),
            Err(RecoveryError::IdentityMismatch)
        ));
    }

    #[test]
    fn pidfd_open_normalizes_only_a_disappeared_process() {
        assert!(matches!(
            classify_pidfd_open_error(rustix::io::Errno::SRCH),
            RecoveryError::ProcessExited
        ));
        assert!(matches!(
            classify_pidfd_open_error(rustix::io::Errno::PERM),
            RecoveryError::Pidfd(rustix::io::Errno::PERM)
        ));
    }

    #[test]
    fn identity_from_another_host_boot_is_rejected_before_any_signal_surface_exists() {
        let mut identity = ProcessIdentity::capture(std::process::id()).unwrap();
        identity.boot_id.push_str("-from-another-boot");
        assert!(matches!(
            LiveProcess::recover(&identity),
            Err(RecoveryError::IdentityMismatch)
        ));
    }

    #[test]
    fn unbound_inet_socket_domain_is_detected_without_proc_table_membership() {
        // SAFETY: socket returns a new descriptor or -1. OwnedFd assumes sole
        // ownership only after the error case has been excluded.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0, "create unbound AF_INET socket failed");
        // SAFETY: raw is a newly created descriptor owned by this test.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(socket_domain(&socket).unwrap(), libc::AF_INET);
    }

    #[test]
    fn exact_pidfd_socket_inspection_succeeds_or_fails_closed_under_outer_seccomp() {
        // SAFETY: socket returns a new descriptor or -1. OwnedFd assumes sole
        // ownership only after the error case has been excluded.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0, "create unbound AF_INET socket failed");
        // SAFETY: raw is a newly created descriptor owned by this test.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let identity = ProcessIdentity::capture(std::process::id()).unwrap();
        let live = LiveProcess::recover(&identity).unwrap();
        match live.socket_domain_for_fd(socket.as_raw_fd()) {
            Ok(domain) => assert_eq!(domain, libc::AF_INET),
            Err(RecoveryError::DuplicateProcessFd(rustix::io::Errno::PERM)) => {
                // Forgejo's unprivileged job container applies an outer
                // seccomp filter that may deny pidfd_getfd. Accept only that
                // exact fail-closed result when a filter is demonstrably
                // active. The required qualified-host KVM smoke remains the
                // end-to-end proof that exact VMM descriptor inspection works.
                let status = fs::read_to_string("/proc/self/status").unwrap();
                assert!(status.lines().any(|line| line == "Seccomp:\t2"));
                assert!(status.lines().any(|line| {
                    line.strip_prefix("Seccomp_filters:\t")
                        .and_then(|value| value.parse::<u32>().ok())
                        .is_some_and(|filters| filters > 0)
                }));
            }
            Err(error) => panic!("unexpected exact pidfd inspection failure: {error}"),
        }
    }
}
