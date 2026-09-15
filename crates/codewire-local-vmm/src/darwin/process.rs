//! Boot and process-birth observations, not process-control capabilities.
//!
//! The native start counter is not a Linux start-time tick value, a retained
//! kernel handle, or authenticated executing-code identity. An observation
//! neither pins a process nor authorizes signaling, adoption, or cleanup.

use std::io;
use std::process::Child;

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

#[cfg(test)]
mod tests;
