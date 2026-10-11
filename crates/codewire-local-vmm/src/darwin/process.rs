//! Boot and process-birth observations, and control of owned children.
//!
//! The native start counter is not a Linux start-time tick value, a retained
//! kernel handle, or authenticated executing-code identity. An observation
//! neither pins a process nor authorizes signaling, adoption, or cleanup.
//! `LiveProcess` controls only a child this process spawned and has not
//! reaped: while unreaped, its PID cannot be reused, so signaling it is exact.

use std::fs;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use codewire_cw_release::sha256::Sha256;
use rustix::process::{Pid, Signal};

use super::path::FileIdentity;
pub use crate::supervisor_metadata::legacy::ProcessIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootSessionId([u8; 16]);

impl BootSessionId {
    /// Read the current boot session without a framework or subprocess.
    pub fn current() -> Result<Self, ObservationError> {
        let mut bytes = [0_u8; 37];
        let mut length = bytes.len();
        // SAFETY: the name is NUL-terminated, the writable buffer and length
        // remain live, and null newp/zero newlen make this a read-only query.
        let result = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        syscall_result(result).map_err(ObservationError::BootRead)?;
        Self::from_sysctl(&bytes, length)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The lowercase hyphenated form persisted as a process `boot_id`.
    pub fn to_hyphenated(self) -> String {
        uuid::Uuid::from_bytes(self.0).hyphenated().to_string()
    }

    fn from_sysctl(bytes: &[u8; 37], length: usize) -> Result<Self, ObservationError> {
        if length != bytes.len()
            || bytes[36] != 0
            || [8, 13, 18, 23]
                .into_iter()
                .any(|index| bytes[index] != b'-')
        {
            return Err(ObservationError::MalformedBootSession);
        }
        let id = uuid::Uuid::try_parse_ascii(&bytes[..36])
            .map_err(|_| ObservationError::MalformedBootSession)?;
        if id.is_nil() {
            return Err(ObservationError::MalformedBootSession);
        }
        Ok(Self(*id.as_bytes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessBirthObservation {
    pid: u32,
    boot_session: BootSessionId,
    start_abstime: u64,
}

impl ProcessBirthObservation {
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn boot_session(&self) -> BootSessionId {
        self.boot_session
    }

    /// Native absolute start counter, not wall time or a globally unique handle.
    pub const fn start_abstime(&self) -> u64 {
        self.start_abstime
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    #[error("cannot read native boot session: {0}")]
    BootRead(#[source] io::Error),
    #[error("native boot session is malformed")]
    MalformedBootSession,
    #[error("boot session changed during process observation")]
    BootChanged,
    #[error("cannot read native process information: {0}")]
    ProcessRead(#[source] io::Error),
    #[error("native process information is malformed")]
    MalformedProcess,
    #[error("the observed process has exited")]
    ProcessExited,
    #[error("cannot inspect owned child status: {0}")]
    ChildWait(#[source] io::Error),
    #[error("cannot inspect child-wait signal disposition: {0}")]
    ChildWaitDisposition(#[source] io::Error),
    #[error("child-wait disposition permits automatic reaping")]
    IncompatibleChildWait,
    #[error("child-wait disposition changed during observation")]
    ChildWaitDispositionChanged,
}

pub fn observe_current() -> Result<ProcessBirthObservation, ObservationError> {
    observe_pid(std::process::id())
}

/// Observe a freshly owned child while its caller remains the exclusive waiter.
///
/// The caller must keep that ownership and the SIGCHLD disposition stable for
/// the whole call: no other thread/handler may reap this child, including through
/// `waitpid(-1, ...)`. A mutable `Child` borrow alone does not enforce this.
/// Pre/post checks detect observed changes, not transient intervening ones.
/// The returned value retains neither the child nor a liveness guarantee.
pub fn observe_owned_child(child: &mut Child) -> Result<ProcessBirthObservation, ObservationError> {
    observe_child_with(child, observe_pid)
}

fn observe_child_with(
    child: &mut Child,
    capture: impl FnOnce(u32) -> Result<ProcessBirthObservation, ObservationError>,
) -> Result<ProcessBirthObservation, ObservationError> {
    let before = ChildWaitDisposition::current()?;
    ensure_unreaped(child)?;
    let observation = capture(child.id());
    ensure_unreaped(child)?;
    let after = ChildWaitDisposition::current()?;
    if before != after {
        return Err(ObservationError::ChildWaitDispositionChanged);
    }
    observation
}

fn ensure_unreaped(child: &mut Child) -> Result<(), ObservationError> {
    if child
        .try_wait()
        .map_err(ObservationError::ChildWait)?
        .is_some()
    {
        return Err(ObservationError::ProcessExited);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ChildWaitDisposition {
    handler: libc::sighandler_t,
    flags: libc::c_int,
    mask: libc::sigset_t,
}

impl ChildWaitDisposition {
    fn current() -> Result<Self, ObservationError> {
        // SAFETY: all-zero sigaction is a valid initialized output buffer;
        // null act only inspects disposition, without changing process state.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) };
        syscall_result(result).map_err(ObservationError::ChildWaitDisposition)?;
        Self::from_action(&action)
    }

    fn from_action(action: &libc::sigaction) -> Result<Self, ObservationError> {
        if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(ObservationError::IncompatibleChildWait);
        }
        Ok(Self {
            handler: action.sa_sigaction,
            flags: action.sa_flags,
            mask: action.sa_mask,
        })
    }
}

fn observe_pid(pid: u32) -> Result<ProcessBirthObservation, ObservationError> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(ObservationError::MalformedProcess);
    }
    let before = BootSessionId::current()?;
    // This SDK-exposed libproc API has a header stability caveat; use the bound
    // V0 ABI and fail closed on unavailable/denied calls. Do not copy private
    // PROC_PIDUNIQIDENTIFIERINFO or treat ri_uuid as code authentication.
    const _: () = assert!(std::mem::size_of::<libc::rusage_info_v0>() == 96);
    const _: () = assert!(std::mem::offset_of!(libc::rusage_info_v0, ri_proc_start_abstime) == 80);
    // SAFETY: V0 consists only of byte arrays and integer fields. The API writes
    // that complete structure directly into the supplied buffer. Despite its
    // pointer-to-pointer-looking typedef, pass the structure's address, NOT
    // the address of a pointer variable. Return 0 is success, not a byte count.
    let mut usage: libc::rusage_info_v0 = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V0,
            (&mut usage as *mut libc::rusage_info_v0).cast(),
        )
    };
    syscall_result(result).map_err(ObservationError::ProcessRead)?;
    let after = BootSessionId::current()?;
    admit_observation(pid, before, after, &usage)
}

fn admit_observation(
    pid: u32,
    before: BootSessionId,
    after: BootSessionId,
    usage: &libc::rusage_info_v0,
) -> Result<ProcessBirthObservation, ObservationError> {
    if before != after {
        return Err(ObservationError::BootChanged);
    }
    if usage.ri_proc_exit_abstime != 0 {
        return Err(ObservationError::ProcessExited);
    }
    if usage.ri_proc_start_abstime == 0 {
        return Err(ObservationError::MalformedProcess);
    }
    Ok(ProcessBirthObservation {
        pid,
        boot_session: before,
        start_abstime: usage.ri_proc_start_abstime,
    })
}

fn syscall_result(result: libc::c_int) -> io::Result<()> {
    match result {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected native observation syscall result",
        )),
    }
}

impl ProcessIdentity {
    /// Record a live process birth: boot session, native start counter and
    /// the kernel-reported executable with that file's identity and digest.
    /// Darwin reads the executable by path, so this records provenance; it
    /// does not authenticate the code the process is executing.
    pub fn capture(pid: u32) -> Result<Self, RecoveryError> {
        let birth = observe_pid(pid).map_err(RecoveryError::from_observation)?;
        let executable = executable_path(pid)?;
        let handle = fs::File::open(&executable).map_err(RecoveryError::ReadProcess)?;
        let metadata = handle.metadata().map_err(RecoveryError::ReadProcess)?;
        let executable_file = FileIdentity::from_metadata(&metadata);
        let executable_sha256 = sha256_reader(handle)?;
        if observe_pid(pid).map_err(RecoveryError::from_observation)? != birth {
            return Err(RecoveryError::IdentityMismatch);
        }
        Ok(Self {
            pid,
            boot_id: birth.boot_session.to_hyphenated(),
            start_time_ticks: birth.start_abstime,
            executable,
            executable_file,
            executable_sha256,
        })
    }
}

/// A live process's boot session and native start counter: its birth.
pub(crate) fn birth_of(pid: u32) -> Result<(String, u64), RecoveryError> {
    let birth = observe_pid(pid).map_err(RecoveryError::from_observation)?;
    Ok((birth.boot_session.to_hyphenated(), birth.start_abstime))
}

/// The executable a live process runs, as the kernel reports its path, and
/// the metadata of the file that path names. Darwin offers no handle to the
/// running file.
pub(crate) fn executable_of(pid: u32) -> Result<(PathBuf, fs::Metadata), RecoveryError> {
    let executable = executable_path(pid)?;
    let metadata = fs::metadata(&executable).map_err(RecoveryError::ReadProcess)?;
    Ok((executable, metadata))
}

fn executable_path(pid: u32) -> Result<PathBuf, RecoveryError> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is writable for exactly the length passed.
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
    }
    buffer.truncate(length as usize);
    let path = PathBuf::from(std::ffi::OsString::from_vec(buffer));
    if !path.is_absolute() {
        return Err(RecoveryError::MalformedProcess);
    }
    Ok(path)
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

/// An owned, unreaped child with a kqueue that becomes readable on its exit.
pub struct LiveProcess {
    identity: ProcessIdentity,
    exit: OwnedFd,
}

impl std::fmt::Debug for LiveProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveProcess")
            .field("identity", &self.identity)
            .field("exit", &self.exit.as_raw_fd())
            .finish()
    }
}

impl LiveProcess {
    /// Admit a child this process just spawned. The caller must keep the
    /// unreaped `Child` for as long as this value can signal it.
    pub fn capture_child(pid: u32, expected_executable: &Path) -> Result<Self, RecoveryError> {
        let exit = exit_queue(pid)?;
        let identity = ProcessIdentity::capture(pid)?;
        if identity.executable != expected_executable {
            return Err(RecoveryError::UnexpectedSpawnedExecutable);
        }
        let process = Self { identity, exit };
        if process.is_exited()? {
            return Err(RecoveryError::ProcessExited);
        }
        Ok(process)
    }

    /// Darwin has no handle that pins a process this process did not spawn,
    /// so a recorded process is never adopted. This only proves it is gone:
    /// absent or a different birth is `ProcessExited`/`IdentityMismatch`,
    /// and the same live birth is `Unowned`.
    pub fn recover(expected: &ProcessIdentity) -> Result<Self, RecoveryError> {
        let observed = match observe_pid(expected.pid) {
            Ok(observed) => observed,
            Err(ObservationError::ProcessRead(error))
                if error.raw_os_error() == Some(libc::ESRCH) =>
            {
                return Err(RecoveryError::ProcessExited);
            }
            Err(error) => return Err(RecoveryError::from_observation(error)),
        };
        if observed.boot_session.to_hyphenated() != expected.boot_id
            || observed.start_abstime != expected.start_time_ticks
        {
            return Err(RecoveryError::IdentityMismatch);
        }
        Err(RecoveryError::Unowned)
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Wait for a recorded process that this process does not own to exit.
    /// Owned descendants watch their parent, so after an owner exits they stop
    /// on their own; this only observes that, never signals. `false` means the
    /// same birth is still alive at the deadline.
    pub async fn wait_recorded_exit(
        expected: &ProcessIdentity,
        timeout: Duration,
    ) -> Result<bool, RecoveryError> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::recover(expected) {
                Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => {
                    return Ok(true);
                }
                Err(RecoveryError::Unowned) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(RecoveryError::Unowned) => return Ok(false),
                Err(error) => return Err(error),
                Ok(_) => unreachable!("Darwin recovery never adopts a process"),
            }
        }
    }

    /// Signal the owned child. As with a Linux pidfd, signaling an exited but
    /// unreaped child has no effect and a reaped one reports `ProcessExited`.
    /// The birth is rechecked first, so a reused PID is never signaled.
    pub fn signal(&self, signal: Signal) -> Result<(), RecoveryError> {
        match owned_child_state(self.identity.pid)? {
            ChildState::Exited => return Ok(()),
            ChildState::Reaped => return Err(RecoveryError::ProcessExited),
            ChildState::Running => {}
        }
        let observed = observe_pid(self.identity.pid).map_err(RecoveryError::from_observation)?;
        if observed.boot_session.to_hyphenated() != self.identity.boot_id
            || observed.start_abstime != self.identity.start_time_ticks
        {
            return Err(RecoveryError::ProcessExited);
        }
        signal_unreaped_child(self.identity.pid, signal)
    }

    /// A descriptor that polls readable once the child exits.
    pub(crate) fn duplicate_wait_descriptor(&self) -> Result<OwnedFd, RecoveryError> {
        rustix::io::fcntl_dupfd_cloexec(&self.exit, 0)
            .map_err(|error| RecoveryError::ReadProcess(error.into()))
    }

    pub fn is_exited(&self) -> Result<bool, RecoveryError> {
        let mut pollfd = libc::pollfd {
            fd: self.exit.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized entry for the duration of
        // the call, and a zero timeout never blocks.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 {
            return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
        }
        if result == 1 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return Ok(true);
        }
        // Also ask the parent-only wait state, which covers an exit that
        // completed while the kqueue was being registered.
        Ok(owned_child_state(self.identity.pid)? != ChildState::Running)
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
}

/// A recorded process this process did not spawn, observed for liveness only.
/// It is never adopted or signaled. Its kqueue becomes readable when that
/// exact birth exits, like a Linux pidfd recovered for the same identity.
#[derive(Debug)]
pub(crate) struct WatchedProcess {
    identity: ProcessIdentity,
    exit: OwnedFd,
}

impl WatchedProcess {
    /// Register for the exit first, then require the recorded birth, so an
    /// exit or PID reuse after the check is still reported by the queue.
    pub(crate) fn watch(expected: &ProcessIdentity) -> Result<Self, RecoveryError> {
        let exit = exit_queue(expected.pid)?;
        match LiveProcess::recover(expected) {
            Err(RecoveryError::Unowned) => Ok(Self {
                identity: expected.clone(),
                exit,
            }),
            Err(error) => Err(error),
            Ok(_) => unreachable!("Darwin recovery never adopts a process"),
        }
    }

    pub(crate) fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub(crate) fn is_exited(&self) -> Result<bool, RecoveryError> {
        let mut pollfd = libc::pollfd {
            fd: self.exit.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized entry for the call; zero timeout never blocks.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 {
            return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
        }
        Ok(result != 0)
    }

    /// The exit queue alone, for a caller that only polls it.
    pub(crate) fn into_exit_descriptor(self) -> OwnedFd {
        self.exit
    }
}

/// Register for one process's exit. A child that already exited fails
/// registration with ESRCH; because it is still unreaped, that means exited.
pub(crate) fn exit_queue(pid: u32) -> Result<OwnedFd, RecoveryError> {
    // SAFETY: kqueue has no arguments; a non-negative result is a new
    // descriptor owned here.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
    }
    // SAFETY: raw is a fresh descriptor that nothing else owns.
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: scalar fcntl on the owned descriptor; no child inherits it.
    if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(RecoveryError::ReadProcess(io::Error::last_os_error()));
    }
    match register_exit(&queue, pid) {
        Ok(()) => Ok(queue),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
            Err(RecoveryError::ProcessExited)
        }
        Err(error) => Err(RecoveryError::ReadProcess(error)),
    }
}

fn register_exit(queue: &OwnedFd, pid: u32) -> io::Result<()> {
    // SAFETY: an all-zero kevent is a valid value for every field.
    let mut change: libc::kevent = unsafe { std::mem::zeroed() };
    change.ident = pid as libc::uintptr_t;
    change.filter = libc::EVFILT_PROC;
    change.flags = libc::EV_ADD | libc::EV_RECEIPT;
    change.fflags = libc::NOTE_EXIT;
    // SAFETY: EV_RECEIPT returns the registration result in the one output
    // entry instead of draining events; both buffers are live and sized.
    let mut receipt: libc::kevent = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &change,
            1,
            &mut receipt,
            1,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result != 1 || receipt.flags & libc::EV_ERROR == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected kqueue registration receipt",
        ));
    }
    match receipt.data {
        0 => Ok(()),
        errno => Err(io::Error::from_raw_os_error(errno as i32)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildState {
    Running,
    Exited,
    Reaped,
}

/// Parent-only, non-reaping wait state of an owned child.
fn owned_child_state(pid: u32) -> Result<ChildState, RecoveryError> {
    // SAFETY: an all-zero siginfo_t is a valid output buffer.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: WNOWAIT leaves the child waitable by its owner; WNOHANG never
    // blocks. The output buffer is live for the call.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == 0 {
        return Ok(if info.si_pid == pid as libc::pid_t {
            ChildState::Exited
        } else {
            ChildState::Running
        });
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        // Already reaped by its owner, or never our child: never signal it.
        return Ok(ChildState::Reaped);
    }
    Err(RecoveryError::ReadProcess(error))
}

/// Signal a just-spawned child before admission. The caller must still own
/// the unreaped `Child`, so this numeric PID cannot have been reused.
pub(crate) fn signal_unreaped_child(pid: u32, signal: Signal) -> Result<(), RecoveryError> {
    let raw = i32::try_from(pid).map_err(|_| RecoveryError::InvalidPid(pid))?;
    let pid = Pid::from_raw(raw).ok_or(RecoveryError::InvalidPid(pid))?;
    match rustix::process::kill_process(pid, signal) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Err(RecoveryError::ProcessExited),
        Err(error) => Err(RecoveryError::ReadProcess(error.into())),
    }
}

/// Exit this process when its parent exits. Darwin has no parent-death
/// signal, so a spawned child calls this at entry. The parent PID is checked
/// again after registering, so a parent that exited first is also caught.
pub fn exit_with_parent() -> io::Result<()> {
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        exit_now();
    }
    // SAFETY: kqueue has no arguments; the result is owned below.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a fresh descriptor that nothing else owns.
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    match register_exit(&queue, parent as u32) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => exit_now(),
        Err(error) => return Err(error),
    }
    // SAFETY: getppid has no preconditions.
    if unsafe { libc::getppid() } != parent {
        exit_now();
    }
    std::thread::Builder::new()
        .name("parent-exit".to_owned())
        .spawn(move || {
            loop {
                // SAFETY: an all-zero kevent is a valid output buffer.
                let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                // SAFETY: one live output entry; a null timeout blocks.
                let result = unsafe {
                    libc::kevent(
                        queue.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        &mut event,
                        1,
                        std::ptr::null(),
                    )
                };
                if result == 1 {
                    exit_now();
                }
            }
        })?;
    Ok(())
}

fn exit_now() -> ! {
    // SAFETY: _exit terminates immediately, like the Linux parent-death
    // SIGKILL; it runs no handlers that could race other threads.
    unsafe { libc::_exit(1) }
}

/// Mark every descriptor from 3 up close-on-exec, as Linux does with
/// `close_range(CLOSE_RANGE_CLOEXEC)`. Darwin creates sockets, pipes and
/// accepted or received descriptors first and marks them close-on-exec in a
/// second call, so a descriptor another thread is creating can reach a child
/// spawned in between. Call it between fork and exec, before clearing the flag
/// on the descriptors the child is meant to inherit. It makes only
/// getdtablesize and fcntl calls.
pub fn mark_inherited_descriptors_close_on_exec() {
    // SAFETY: scalar libc calls. A number that is not an open descriptor
    // fails with EBADF and is skipped.
    unsafe {
        for descriptor in 3..libc::getdtablesize() {
            libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
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
    #[error("spawned process executable does not match the admitted executable")]
    UnexpectedSpawnedExecutable,
    #[error("process exited during recovery")]
    ProcessExited,
    #[error("a process from an earlier owner is still running and cannot be adopted")]
    Unowned,
    #[error(transparent)]
    Observation(ObservationError),
}

impl RecoveryError {
    fn from_observation(error: ObservationError) -> Self {
        match error {
            ObservationError::ProcessExited => Self::ProcessExited,
            error => Self::Observation(error),
        }
    }
}

#[cfg(test)]
mod tests;
