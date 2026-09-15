//! Fixed Git child custody, following initial_private_checkout_fixture/linux.rs.
//! No shell, ambient environment, credential input, listener or detached task.

use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use codewire_credential_broker::BrokerUpstreamError as Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

pub(super) const IO_LIMIT: usize = 1024 * 1024;
pub(super) const CHILD_LIMIT: Duration = Duration::from_secs(20);
pub(super) const DRAIN_LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct Failure {
    pub(super) error: Error,
    pub(super) drained: bool,
}

impl Failure {
    fn drained(error: Error) -> Self {
        Self {
            error,
            drained: true,
        }
    }
    fn unproven(error: Error) -> Self {
        Self {
            error,
            drained: false,
        }
    }
}

pub(super) fn command(directory: &Path) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_EXEC_PATH", "/usr/lib/git-core")
        .env("LC_ALL", "C")
        .env("HOME", directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
        ])
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    command
}

// The unreaped direct child reserves its process-group ID until all helpers
// have been killed. Waiting/reaping first would permit reuse of that ID.
struct OwnedChild {
    child: Child,
    group: Option<i32>,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> Result<Self, Error> {
        let child = command.spawn().map_err(|_| Error::Connect)?;
        let group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or(Error::Protocol)?;
        Ok(Self {
            child,
            group: Some(group),
        })
    }

    async fn exited(&self) -> Result<(), Error> {
        loop {
            let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: writable status and an unreaped direct child owned here.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.group.ok_or(Error::Protocol)? as u32,
                    status.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                return Err(Error::Protocol);
            }
            // SAFETY: successful waitid initializes status; a live child has PID 0.
            if unsafe { status.assume_init().si_pid() } != 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn kill_group(&self) -> Result<(), Error> {
        if let Some(group) = self.group {
            // SAFETY: this unreaped leader reserves the private process group.
            if unsafe { libc::kill(-group, libc::SIGKILL) } != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(Error::Protocol);
            }
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<ExitStatus, Error> {
        self.kill_group()?;
        // A successful signal consumes group authority before wait can reap
        // its leader. Drop must not signal a potentially reused ID if wait
        // subsequently errors, times out or is cancelled.
        self.group = None;
        let status = tokio::time::timeout(DRAIN_LIMIT, self.child.wait())
            .await
            .map_err(|_| Error::ResourceLimit)?
            .map_err(|_| Error::Protocol)?;
        Ok(status)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.kill_group();
    }
}

async fn bounded_bytes(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(IO_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Error::Protocol)?;
    if bytes.len() > IO_LIMIT {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

pub(super) async fn run(
    command: &mut Command,
    input: &[u8],
    stop: &CancellationToken,
) -> Result<Vec<u8>, Failure> {
    run_with_limit(command, input, stop, CHILD_LIMIT).await
}

async fn run_with_limit(
    command: &mut Command,
    input: &[u8],
    stop: &CancellationToken,
    limit: Duration,
) -> Result<Vec<u8>, Failure> {
    if stop.is_cancelled() {
        return Err(Failure::drained(Error::Protocol));
    }
    let mut child = OwnedChild::spawn(command).map_err(Failure::unproven)?;
    let mut stdin = Some(
        child
            .child
            .stdin
            .take()
            .ok_or_else(|| Failure::unproven(Error::Protocol))?,
    );
    let mut stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| Failure::unproven(Error::Protocol))?;
    let mut stderr = child
        .child
        .stderr
        .take()
        .ok_or_else(|| Failure::unproven(Error::Protocol))?;
    // Borrow the output pipes: cancellation closes the input writer, but the
    // reader handles remain owned until bounded post-kill EOF is proven.
    let result = tokio::select! {
        biased;
        () = stop.cancelled() => Err(Error::Protocol),
        result = tokio::time::timeout(limit, async {
            let (_, _, output, _) = tokio::try_join!(
                child.exited(),
                async {
                    let mut stdin = stdin.take().ok_or(Error::Protocol)?;
                    stdin.write_all(input).await.map_err(|_| Error::Protocol)?;
                    drop(stdin);
                    Ok(())
                },
                bounded_bytes(&mut stdout),
                bounded_bytes(&mut stderr),
            )?;
            Ok(output)
        }) => result.unwrap_or(Err(Error::ResourceLimit)),
    };
    drop(stdin);
    let status = child.finish().await.map_err(Failure::unproven)?;
    tokio::time::timeout(DRAIN_LIMIT, async {
        tokio::try_join!(bounded_bytes(&mut stdout), bounded_bytes(&mut stderr))
    })
    .await
    .map_err(|_| Failure::unproven(Error::ResourceLimit))?
    .map_err(Failure::unproven)?;
    let output = result.map_err(Failure::drained)?;
    if !status.success() {
        return Err(Failure::drained(Error::Protocol));
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
