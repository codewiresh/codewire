//! Ownership of ordinary trusted-host descendants, not sandbox containment.
//! Keep the exact leader unreaped until the last group signal. A persisted PID
//! never enters this API; deliberately escaped user processes are not adopted.
use std::io;
use std::time::Duration;

use crate::confirm::CheckBudget;

pub(crate) const TERM_GRACE: Duration = Duration::from_millis(250);
/// The product's bound on a host group's whole cleanup after [`TERM_GRACE`]:
/// descendants settling after KILL, the leader's reap, and the control and
/// output joins share it. With the grace it ends 4 s after a stop, inside the
/// 5 s that host control and orchestration give a stop. Cleanup that has not
/// settled by then is unknown. One bound per step (1 s) let an ordinary slow
/// step report unknown (#3777).
pub(crate) const CLEANUP_BUDGET: Duration = Duration::from_millis(3_750);

pub(crate) struct OwnedProcessGroup {
    pid: libc::pid_t,
    armed: bool,
    cleanup: CheckBudget,
}

impl OwnedProcessGroup {
    /// Owns `pid`'s group; `cleanup_budget` bounds its whole cleanup, which
    /// is [`CLEANUP_BUDGET`] in the product.
    pub(crate) fn new(pid: u32, cleanup_budget: Duration) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("host leader PID is invalid"))?;
        let group = Self {
            pid,
            armed: true,
            cleanup: CheckBudget::new(cleanup_budget),
        };
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

    /// The checks every step of this group's cleanup spends.
    pub(crate) fn cleanup(&self) -> &CheckBudget {
        &self.cleanup
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
            // Darwin reports EPERM, not ESRCH, for a group of only zombies,
            // such as an exited leader that this owner has not yet reaped.
            #[cfg(target_os = "macos")]
            if error.raw_os_error() == Some(libc::EPERM)
                && !listed_pids(PROC_PGRP_ONLY, self.pid as u32)?
                    .into_iter()
                    .any(live)
            {
                return Ok(());
            }
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) async fn terminate(&mut self) -> io::Result<()> {
        let term = self.signal(libc::SIGTERM);
        let term = term.and(self.signal_session_members(libc::SIGTERM).map(|_| ()));
        tokio::time::sleep(TERM_GRACE).await;
        // Always send KILL before reaping, even if TERM already ended the
        // leader: shell children may still hold stdin/stdout or ignore TERM.
        let descendants = self.terminate_session_members().await;
        let kill = self.signal(libc::SIGKILL);
        self.armed = false;
        kill.and(descendants).and(term)
    }
    /// PTY job control can create additional process groups without escaping the
    /// owned session. Linux pidfds signal those exact processes, never bare PIDs.
    async fn terminate_session_members(&self) -> io::Result<()> {
        crate::confirm::check_spending(&self.cleanup, || {
            match self.signal_session_members(libc::SIGKILL) {
                Ok(0) => Some(Ok(())),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .await
        .unwrap_or_else(|| Err(io::Error::other("host session descendants did not settle")))
    }

    /// macOS has no pidfd. Each member is rechecked with getsid immediately
    /// before its signal, and the unreaped leader keeps the session ID from
    /// being reused, so a recycled PID can match only a process that joined
    /// this session itself. The remaining window between that check and the
    /// signal is a PID reuse in microseconds, by a process of this same user.
    #[cfg(target_os = "macos")]
    fn signal_session_members(&self, signal: libc::c_int) -> io::Result<usize> {
        self.exited()?; // The exact leader continues reserving the session ID.
        let mut live = 0;
        for pid in listed_pids(PROC_ALL_PIDS, 0)? {
            // Darwin's getsid fails with ESRCH for a zombie, so this also
            // skips members that have exited but are not yet reaped.
            if pid <= 0 || pid == self.pid || unsafe { libc::getsid(pid) } != self.pid {
                continue;
            }
            live += 1;
            // SAFETY: plain kill of a just-rechecked member of the owned session.
            if unsafe { libc::kill(pid, signal) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(live)
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

// <libproc.h> selectors; the libc crate does not export them.
#[cfg(target_os = "macos")]
const PROC_ALL_PIDS: u32 = 1;
#[cfg(target_os = "macos")]
const PROC_PGRP_ONLY: u32 = 2;

/// The PIDs a libproc selector names. The kernel may add processes between
/// the size query and the listing, so the buffer has headroom and is retried.
#[cfg(target_os = "macos")]
fn listed_pids(selector: u32, argument: u32) -> io::Result<Vec<libc::pid_t>> {
    for _ in 0..2 {
        // SAFETY: a null buffer asks only for the required size in bytes.
        let bytes = unsafe { libc::proc_listpids(selector, argument, std::ptr::null_mut(), 0) };
        if bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = bytes as usize / std::mem::size_of::<libc::pid_t>() + 256;
        let mut pids = vec![0 as libc::pid_t; capacity];
        let size = (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: the buffer holds exactly `size` bytes of pid_t entries.
        let used =
            unsafe { libc::proc_listpids(selector, argument, pids.as_mut_ptr().cast(), size) };
        if used < 0 {
            return Err(io::Error::last_os_error());
        }
        if used < size {
            pids.truncate(used as usize / std::mem::size_of::<libc::pid_t>());
            return Ok(pids);
        }
    }
    Err(io::Error::other("process list kept growing"))
}

/// Whether `pid` names a process that has not exited. Darwin's proc_pidinfo
/// fails with ESRCH for a zombie, which kill(pid, 0) still accepts.
#[cfg(target_os = "macos")]
pub(crate) fn live(pid: libc::pid_t) -> bool {
    const SZOMB: u32 = 5;
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    pid > 0 && written == size && info.pbi_status != SZOMB
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.signal(libc::SIGKILL);
        }
    }
}
