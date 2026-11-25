//! How an owned session's output readers end, and who still holds that
//! output once every process of the session is gone (#5635).

use tokio::task::JoinHandle;

use super::SessionError;
use crate::host_process::EndedProcess;

/// How an owned session's output reader ended.
#[cfg(unix)]
pub(super) enum OutputJoin {
    Drained,
    Failed(String),
    /// Still open when the cleanup budget ran out; the reader is stopped.
    Held,
}

#[cfg(unix)]
impl OutputJoin {
    /// What the session's end records for it. A held drain is not an error
    /// once every process of the session is confirmed gone.
    pub(super) fn error(self, host: bool, confirmed: bool) -> Option<String> {
        match self {
            Self::Drained => None,
            Self::Failed(error) => Some(error),
            Self::Held if confirmed => None,
            Self::Held => {
                let owner = if host { "host" } else { "session" };
                Some(format!(
                    "{owner} output drain timed out; cleanup is unknown"
                ))
            }
        }
    }
}

#[cfg(unix)]
impl super::ProcessCompletion {
    /// Whether every process of the session itself is confirmed gone: it
    /// exited, or a stop confirmed its end. Output still open then is a
    /// process that left the session on purpose (#5490), or a reader still
    /// stopping, and neither leaves the session's cleanup unknown (#5635).
    pub(super) fn confirmed(&self) -> bool {
        matches!(
            self,
            Self::Exited(Ok(_)) | Self::Stopped { result: Ok(()), .. }
        )
    }
}

#[cfg(unix)]
pub(super) async fn bounded_output_join(
    mut task: JoinHandle<Result<(), SessionError>>,
    budget: &crate::confirm::CheckBudget,
    host: bool,
) -> OutputJoin {
    let owner = if host { "host" } else { "session" };
    match crate::confirm::await_spending(budget, &mut task).await {
        Some(Ok(Ok(()))) => OutputJoin::Drained,
        Some(Ok(Err(error))) => OutputJoin::Failed(error.to_string()),
        Some(Err(error)) => OutputJoin::Failed(format!("{owner} output task failed: {error}")),
        None => {
            task.abort();
            let _ = task.await;
            OutputJoin::Held
        }
    }
}

/// The inodes of a session's stdout and stderr pipes, by which
/// [`output_holders`] finds a process outside the session still holding
/// them. Only Linux names one, from `/proc` (#5635).
#[cfg(target_os = "linux")]
pub(super) fn output_pipe_inodes(
    stdout: &impl std::os::fd::AsFd,
    stderr: &impl std::os::fd::AsFd,
) -> Vec<u64> {
    [rustix::fs::fstat(stdout), rustix::fs::fstat(stderr)]
        .into_iter()
        .filter_map(|status| status.ok().map(|status| status.st_ino))
        .collect()
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn output_pipe_inodes<O, E>(_stdout: &O, _stderr: &E) -> Vec<u64> {
    Vec::new()
}

/// The processes, by PID in their own namespace and kernel command name,
/// that hold one of `pipes` (pipe inodes) open, from `/proc`. This daemon's
/// own descriptors are not counted. Best effort: a process that cannot be
/// read is left out.
#[cfg(unix)]
pub(super) fn output_holders(pipes: &[u64]) -> Vec<EndedProcess> {
    #[cfg(target_os = "linux")]
    {
        let links: Vec<String> = pipes
            .iter()
            .map(|inode| format!("pipe:[{inode}]"))
            .collect();
        let me = libc::pid_t::try_from(std::process::id()).unwrap_or_default();
        let Ok(processes) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut holders = Vec::new();
        for process in processes.flatten() {
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|pid| pid.parse::<libc::pid_t>().ok())
            else {
                continue;
            };
            if pid == me {
                continue;
            }
            let Ok(descriptors) = std::fs::read_dir(process.path().join("fd")) else {
                continue;
            };
            let holds = descriptors.flatten().any(|descriptor| {
                std::fs::read_link(descriptor.path()).is_ok_and(|target| {
                    links.iter().any(|link| target.as_os_str() == link.as_str())
                })
            });
            if !holds {
                continue;
            }
            let status = std::fs::read_to_string(process.path().join("status")).unwrap_or_default();
            // The PID the process has in its own namespace, as `ps` shows it
            // there: the last of NSpid's.
            let own_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .and_then(|pids| pids.split_whitespace().last()?.parse().ok())
                .unwrap_or(pid);
            let name = std::fs::read_to_string(process.path().join("comm")).unwrap_or_default();
            holders.push(EndedProcess {
                pid: own_pid,
                name: name.trim().to_owned(),
            });
        }
        holders.sort_by_key(|holder| holder.pid);
        holders
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pipes;
        Vec::new()
    }
}

/// The line an owned session's end records when it ended processes its
/// command left running (#5472): up to three of them by PID and kernel
/// command name, and how to keep a server on purpose.
pub(super) fn ended_note(ended: &[EndedProcess]) -> Option<String> {
    let count = match ended.len() {
        0 => return None,
        1 => "1 process".to_owned(),
        count => format!("{count} processes"),
    };
    Some(format!(
        "Ended {count} left running after the command exited ({}). \
         To keep a server running, run it in its own named session, or start it \
         with setsid; nohup alone is not enough.",
        listed(ended)
    ))
}

/// The line a session's end records when its output was still open in
/// processes outside the session once all of its own had gone (#5635).
pub(super) fn held_output_note(holders: &[EndedProcess]) -> String {
    let who = match holders.len() {
        0 => "a process that left the session".to_owned(),
        1 => format!("1 process that left the session ({})", listed(holders)),
        count => format!(
            "{count} processes that left the session ({})",
            listed(holders)
        ),
    };
    format!(
        "Its output is still open in {who}, which keeps running; what that writes now \
         is not kept. Redirect a server's output when you start it with setsid."
    )
}

/// Up to three processes by PID and command name, and how many more. A name
/// is the workload's own text (`comm`, at most 15 bytes), so only printable
/// ASCII other than a backtick is kept.
fn listed(processes: &[EndedProcess]) -> String {
    let named = processes
        .iter()
        .take(3)
        .map(|process| {
            let name: String = process
                .name
                .chars()
                .filter(|c| c.is_ascii_graphic() && *c != '`')
                .collect();
            if name.is_empty() {
                format!("pid {}", process.pid)
            } else {
                format!("pid {} `{name}`", process.pid)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    match processes.len() {
        0..=3 => named,
        count => format!("{named} and {} more", count - 3),
    }
}
