//! Ownership of a session's processes: a trusted host's, and a guest's run
//! natively (#5472). This is not sandbox containment. Keep the exact leader
//! unreaped until the last group signal. A persisted PID never enters this
//! API; deliberately escaped user processes are not adopted.
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
/// A guest session's TERM grace: long enough for a database or dev server to
/// finish a write before KILL (#5472).
pub(crate) const GUEST_TERM_GRACE: Duration = Duration::from_secs(2);
/// A guest group's whole cleanup after [`GUEST_TERM_GRACE`], which with it
/// also ends 4 s after a stop.
pub(crate) const GUEST_CLEANUP_BUDGET: Duration = Duration::from_secs(2);

/// A process a group signal reached besides the leader: what a session's
/// end says it ended. `name` is the kernel's short command name, empty
/// where the platform gives none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndedProcess {
    pub(crate) pid: libc::pid_t,
    pub(crate) name: String,
}

pub(crate) struct OwnedProcessGroup {
    pid: libc::pid_t,
    armed: bool,
    term_grace: Duration,
    cleanup: CheckBudget,
}

impl OwnedProcessGroup {
    /// Owns `pid`'s group; KILL follows TERM after `term_grace`, and
    /// `cleanup_budget` bounds the whole cleanup after it: [`TERM_GRACE`] and
    /// [`CLEANUP_BUDGET`] on a trusted host, [`GUEST_TERM_GRACE`] and
    /// [`GUEST_CLEANUP_BUDGET`] in a guest.
    pub(crate) fn new(
        pid: u32,
        term_grace: Duration,
        cleanup_budget: Duration,
    ) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("session leader PID is invalid"))?;
        let group = Self {
            pid,
            armed: true,
            term_grace,
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
        leader_exit_status(self.pid)
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

    /// Signals only the exact leader, which its owner keeps unreaped.
    fn signal_leader(&self, signal: libc::c_int) -> io::Result<()> {
        if self.exited()? {
            return Ok(());
        }
        // SAFETY: the caller still owns the unreaped leader, so its PID is not reused.
        if unsafe { libc::kill(self.pid, signal) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    /// One TERM to the leader and to every member of the session, KILL to
    /// the group and the session after the grace. Returns the members
    /// besides the leader that TERM reached.
    pub(crate) async fn terminate(&mut self) -> io::Result<Vec<EndedProcess>> {
        // The leader first, so a live leader's own TERM handler runs before
        // its children's exit can wake it. Then the session's members, each
        // listed as it is signalled; the leader's group is part of the
        // session. No group TERM follows: it would reach every one of them a
        // second time, and many servers take a second TERM as "quit now"
        // and skip their graceful shutdown.
        let leader_exited = matches!(self.exit_status(), Ok(Some(_)));
        let term = self.signal_leader(libc::SIGTERM);
        let (term, members) = match scan_session_members(self.pid, libc::SIGTERM).await {
            Ok(members) => (term, members),
            Err(error) => (term.and(Err(error)), Vec::new()),
        };
        // The grace is for processes to finish a write. A leader that had
        // exited, in a session the scan found no member of, leaves none, and
        // none can start: so a command that exits alone ends at once, not
        // after a guest's 2 s grace.
        if !(leader_exited && members.is_empty() && term.is_ok()) {
            tokio::time::sleep(self.term_grace).await;
        }
        // Always send KILL before reaping, even if TERM already ended the
        // leader: shell children may still hold stdin/stdout or ignore TERM.
        // The leader first: a live one, such as a shell that trapped TERM,
        // would start a new child for each one the member scan ends, and the
        // scan would never settle.
        let leader = self.signal_leader(libc::SIGKILL);
        let descendants = self.terminate_session_members().await;
        let kill = self.signal(libc::SIGKILL);
        self.armed = false;
        kill.and(leader)
            .and(descendants)
            .and(term)
            .map(|()| members)
    }
    /// PTY job control can create additional process groups without escaping the
    /// owned session. Linux pidfds signal those exact processes, never bare PIDs.
    async fn terminate_session_members(&self) -> io::Result<()> {
        let leader = self.pid;
        crate::confirm::check_spending_async(&self.cleanup, || async move {
            match scan_session_members(leader, libc::SIGKILL).await {
                Ok(members) if members.is_empty() => Some(Ok(())),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .await
        .unwrap_or_else(|| Err(io::Error::other("host session descendants did not settle")))
    }
}

/// The exit status of the owned group leader `pid`, without reaping it.
fn leader_exit_status(pid: libc::pid_t) -> io::Result<Option<i32>> {
    // SAFETY: waitid initializes siginfo for this child only. WNOWAIT keeps
    // its PID reserved, including after exit, until the owner calls wait.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
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

/// Signals every member of the session `leader` leads, off the async
/// workers. A stop scans twice, for TERM and then for KILL, and each scan
/// reads every process in the daemon's PID namespace (#4237):
/// - in a hosted sandbox or a local VM, the namespace holds that
///   environment's own few processes, so a scan is cheap;
/// - on a user's own Linux host it holds the whole host: at about 1,600
///   processes a scan measured 100–200 ms, and a starved host stretches it
///   to seconds.
///
/// The group's owner keeps the leader unreaped while this runs, so the
/// session ID stays reserved.
async fn scan_session_members(
    leader: libc::pid_t,
    signal: libc::c_int,
) -> io::Result<Vec<EndedProcess>> {
    tokio::task::spawn_blocking(move || signal_session_members(leader, signal))
        .await
        .map_err(|_| io::Error::other("host session member scan did not finish"))?
}

/// macOS has no pidfd. Each member is rechecked with getsid immediately
/// before its signal, and the unreaped leader keeps the session ID from
/// being reused, so a recycled PID can match only a process that joined
/// this session itself. The remaining window between that check and the
/// signal is a PID reuse in microseconds, by a process of this same user.
#[cfg(target_os = "macos")]
fn signal_session_members(
    leader: libc::pid_t,
    signal: libc::c_int,
) -> io::Result<Vec<EndedProcess>> {
    leader_exit_status(leader)?; // The exact leader continues reserving the session ID.
    let mut members = Vec::new();
    for pid in listed_pids(PROC_ALL_PIDS, 0)? {
        // Darwin's getsid fails with ESRCH for a zombie, so this also
        // skips members that have exited but are not yet reaped.
        if pid <= 0 || pid == leader || unsafe { libc::getsid(pid) } != leader {
            continue;
        }
        members.push(EndedProcess {
            pid,
            name: String::new(),
        });
        // SAFETY: plain kill of a just-rechecked member of the owned session.
        if unsafe { libc::kill(pid, signal) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
    }
    Ok(members)
}

#[cfg(target_os = "linux")]
fn signal_session_members(
    leader: libc::pid_t,
    signal: libc::c_int,
) -> io::Result<Vec<EndedProcess>> {
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
    leader_exit_status(leader)?; // The exact leader continues reserving the session ID.
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == leader as u32 {
            continue;
        }
        let path = entry.path().join("stat");
        let Ok(stat) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !member(&stat, leader) {
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
        if !member(&stat, leader) {
            continue;
        }
        let name = stat
            .split_once(" (")
            .and_then(|(_, rest)| rest.rsplit_once(") "))
            .map(|(name, _)| name.to_owned())
            .unwrap_or_default();
        members.push(EndedProcess {
            pid: pid as libc::pid_t,
            name,
        });
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
    Ok(members)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tokio::process::Command;

    /// The grace in a test that must not wait it out: long enough that a
    /// loaded test host cannot mistake a slow end for it.
    const LONG_GRACE: Duration = Duration::from_secs(60);

    /// `script` under `sh`, leading its own session as a session command does.
    fn spawn_session(script: &str) -> tokio::process::Child {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        // SAFETY: setsid is async-signal-safe and takes no arguments.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    /// A command that exits leaving nothing in its session ends without the
    /// grace: there is no process to give it to.
    #[tokio::test]
    async fn a_leader_that_exits_alone_ends_without_the_grace() {
        let mut child = spawn_session("exit 0");
        let mut group =
            OwnedProcessGroup::new(child.id().unwrap(), LONG_GRACE, LONG_GRACE).unwrap();
        tokio::time::timeout(LONG_GRACE, group.wait_for_exit())
            .await
            .unwrap()
            .unwrap();
        let ended = tokio::time::timeout(LONG_GRACE / 2, group.terminate())
            .await
            .expect("an exited leader alone does not wait the grace")
            .unwrap();
        assert!(ended.is_empty());
        assert_eq!(child.wait().await.unwrap().code(), Some(0));
    }

    /// A process the command left running still gets its TERM and the whole
    /// grace before KILL.
    #[tokio::test]
    async fn a_process_left_running_still_gets_the_grace() {
        let grace = Duration::from_millis(300);
        let mut child = spawn_session("sleep 60 & exit 0");
        let mut group = OwnedProcessGroup::new(child.id().unwrap(), grace, LONG_GRACE).unwrap();
        tokio::time::timeout(LONG_GRACE, group.wait_for_exit())
            .await
            .unwrap()
            .unwrap();
        let started = std::time::Instant::now();
        let ended = tokio::time::timeout(LONG_GRACE, group.terminate())
            .await
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= grace);
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert_eq!(ended[0].name, "sleep");
        child.wait().await.unwrap();
    }
}
