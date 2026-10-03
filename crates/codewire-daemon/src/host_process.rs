//! Ownership of ordinary trusted-host descendants, not sandbox containment.
//! Keep the exact leader unreaped until the last group signal. A persisted PID
//! never enters this API; deliberately escaped user processes are not adopted.
use std::io;
use std::time::Duration;

pub(crate) const TERM_GRACE: Duration = Duration::from_millis(250);
pub(crate) const JOIN_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct OwnedProcessGroup {
    pid: libc::pid_t,
    armed: bool,
}

impl OwnedProcessGroup {
    pub(crate) fn new(pid: u32) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("host leader PID is invalid"))?;
        let group = Self { pid, armed: true };
        // The caller retains the Child. waitid checks ownership without reaping.
        group.exited()?;
        // SAFETY: getpgid only queries the exact owned child.
        if unsafe { libc::getpgid(pid) } != pid {
            return Err(io::Error::other(
                "host child is not its owned process group leader",
            ));
        }
        Ok(group)
    }

    fn exit_status(&self) -> io::Result<Option<i32>> {
        // SAFETY: waitid initializes siginfo for this child only. WNOWAIT keeps
        // its PID reserved, including after exit, until the owner calls wait.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        Ok(Some(if info.si_code == libc::CLD_EXITED {
            unsafe { info.si_status() }
        } else {
            1
        }))
    }

    pub(crate) fn exited(&self) -> io::Result<bool> {
        Ok(self.exit_status()?.is_some())
    }

    pub(crate) async fn wait_for_exit(&self) -> io::Result<i32> {
        loop {
            if let Some(code) = self.exit_status()? {
                return Ok(code);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        // ECHILD must forbid signaling: an unrelated/reused PID is never safe.
        self.exited()?;
        // SAFETY: the caller still owns the unreaped group leader.
        if unsafe { libc::kill(-self.pid, signal) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) async fn terminate(&mut self) -> io::Result<()> {
        let term = self.signal(libc::SIGTERM);
        #[cfg(target_os = "linux")]
        let term = term.and(self.signal_session_members(libc::SIGTERM).map(|_| ()));
        tokio::time::sleep(TERM_GRACE).await;
        // Always send KILL before reaping, even if TERM already ended the
        // leader: shell children may still hold stdin/stdout or ignore TERM.
        #[cfg(target_os = "linux")]
        let descendants = self.terminate_session_members().await;
        let kill = self.signal(libc::SIGKILL);
        self.armed = false;
        #[cfg(target_os = "linux")]
        return kill.and(descendants).and(term);
        #[cfg(not(target_os = "linux"))]
        kill.and(term)
    }
    /// PTY job control can create additional process groups without escaping the
    /// owned session. Linux pidfds signal those exact processes, never bare PIDs.
    #[cfg(target_os = "linux")]
    async fn terminate_session_members(&self) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
        loop {
            if self.signal_session_members(libc::SIGKILL)? == 0 {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::other("host session descendants did not settle"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(target_os = "linux")]
    fn signal_session_members(&self, signal: libc::c_int) -> io::Result<usize> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        fn member(stat: &str, session_id: i32) -> bool {
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                return false;
            };
            let mut fields = fields.split_whitespace();
            let state = fields.next();
            fields.next();
            fields.next();
            let session = fields.next().and_then(|value| value.parse::<i32>().ok());
            session == Some(session_id) && !matches!(state, Some("Z" | "X"))
        }
        self.exited()?; // The exact leader continues reserving the session ID.
        let mut live = 0;
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == self.pid as u32 {
                continue;
            }
            let path = entry.path().join("stat");
            let Ok(stat) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !member(&stat, self.pid) {
                continue;
            }
            // Open identity and RECHECK current /proc membership. If the numeric
            // PID was reused, the fd is dead or refers to the inspected process.
            // Signals through this fd can never hit a later unrelated process.
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if raw == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(error);
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            let Ok(stat) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !member(&stat, self.pid) {
                continue;
            }
            live += 1;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(live)
    }
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.signal(libc::SIGKILL);
        }
    }
}
