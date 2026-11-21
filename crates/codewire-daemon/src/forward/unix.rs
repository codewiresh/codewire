//! `ForwardUnix`: one connection to a Unix socket in the workload, as the
//! workload user (#5608; `SPEC.md`, "Port forwarding over SSH").
//!
//! - **Where the daemon runs as the workload user** in the workload's
//!   filesystem, as a hosted Sandbox's does, it connects itself
//!   ([`crate::unix_forward::connect`]).
//! - **Where it runs as root outside the workload** (the `Runc` placement of
//!   a local VM), it never changes its own credentials. It starts a helper,
//!   `init workspace-unix-connect PATH [DEVICE:INODE]...`, the way every
//!   workload process starts, with no terminal, `/` as its working directory
//!   and an empty environment: none of the launch projection or application
//!   secrets a workload process is given. The helper connects
//!   ([`crate::unix_forward::relay`]) and relays the forward's bytes over its
//!   standard input and output; no descriptor crosses to the daemon.
//!
//! The workload controls that helper, so the daemon trusts nothing it says:
//! it reads one status line of at most
//! [`crate::unix_forward::MAX_STATUS_BYTES`] within
//! [`super::FORWARD_CONNECT_TIMEOUT`], accepts only the fixed codes
//! [`Refusal::parse`] knows, answers in its own words with its own escaped
//! copy of the target, and reads at most [`DISCARDED_STDERR_BYTES`] more of
//! the helper's stderr. The helper's process group is killed when the status
//! does not come in time, when the forward ends, and when its stream is
//! dropped because the client went away.

use std::path::{Path, PathBuf};

use codewire_daemon_proto::daemon::v1;
use tokio::io::AsyncReadExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::config::Config;
use crate::execution::{PreparedProcess, ProcessExecution, ProcessSpecCleanup, RuncExecution};
use crate::platform_sockets;
use crate::unix_forward::{self, MAX_STATUS_BYTES, Refusal, UnixForwardError};

/// How much of a connected helper's stderr the daemon reads, and drops,
/// before it closes the pipe.
pub(crate) const DISCARDED_STDERR_BYTES: usize = 4 * 1024;

/// `ForwardUnix`'s target, if its shape is one a forward takes.
pub(crate) fn admit(open: &v1::ForwardUnixOpen) -> Result<PathBuf, Status> {
    unix_forward::target(&open.path).map_err(status)
}

/// Connect to `path` as the workload user and serve the forward.
pub(crate) async fn serve(
    config: &Config,
    path: PathBuf,
    inbound: Streaming<v1::ForwardTcpMessage>,
) -> Result<ReceiverStream<Result<v1::ForwardTcpMessage, Status>>, Status> {
    match &config.process_execution {
        // A native daemon starts workload processes as itself, so it is the
        // workload user in the workload's filesystem, and its own connect is
        // the one a workload process would make.
        ProcessExecution::Native => {
            let stream = tokio::task::spawn_blocking(move || unix_forward::connect(&path))
                .await
                .map_err(|error| Status::internal(format!("connect a socket forward: {error}")))?
                .map_err(status)?;
            let stream = stream
                .set_nonblocking(true)
                .and_then(|()| tokio::net::UnixStream::from_std(stream))
                .map_err(|error| Status::internal(format!("connect a socket forward: {error}")))?;
            let (from, to) = stream.into_split();
            Ok(super::serve_halves(from, to, inbound, ()))
        }
        ProcessExecution::Runc(runc) => {
            let helper = Helper::start(config, runc, &path).await?;
            let Helper {
                stdout,
                stdin,
                guard,
            } = helper;
            Ok(super::serve_halves(stdout, stdin, inbound, guard))
        }
    }
}

fn status(error: UnixForwardError) -> Status {
    match error {
        UnixForwardError::Refused(reason) => Status::permission_denied(reason),
        UnixForwardError::Failed(reason) => Status::unavailable(reason),
    }
}

/// A connected helper: its pipes, and the guard that ends it.
struct Helper {
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
    guard: HelperGuard,
}

/// Kills the helper's process group, and so the helper, when dropped.
pub(crate) struct HelperGuard {
    child: tokio::process::Child,
    _spec: ProcessSpecCleanup,
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        if let Some(group) = self.child.id().and_then(|id| i32::try_from(id).ok()) {
            // SAFETY: killpg takes a process group ID and a signal. The
            // helper's launcher leads its own group, and the helper dies with
            // it (`workspace-exec` binds it to its runc parent).
            unsafe {
                libc::killpg(group, libc::SIGKILL);
            }
        }
        // The group kill above has usually ended it already, and then this
        // fails with nothing left to do; kill_on_drop reaps it either way.
        let _ = self.child.start_kill();
    }
}

impl Helper {
    async fn start(config: &Config, runc: &RuncExecution, path: &Path) -> Result<Self, Status> {
        let shown = unix_forward::shown(&path.to_string_lossy());
        let init = runc
            .process_wrapper
            .first()
            .ok_or_else(|| Status::internal("the workload has no process wrapper"))?;
        let platform = platform_sockets::snapshot();
        let names: Vec<&str> = platform.iter().map(|(_, _, name)| *name).collect();
        let mut command = vec![
            init.clone(),
            "workspace-unix-connect".to_owned(),
            path.to_string_lossy().into_owned(),
        ];
        command.extend(
            platform
                .iter()
                .map(|(device, inode, _)| format!("{device}:{inode}")),
        );
        let mut prepared =
            PreparedProcess::prepare(&config.process_execution, &command, "/", &[], false, 0, 0)
                .map_err(|error| {
                    Status::internal(format!("prepare the forward helper: {error}"))
                })?;
        let mut process = prepared.tokio_command();
        process.process_group(0);
        let child = process
            .spawn()
            .map_err(|error| Status::internal(format!("start the forward helper: {error}")))?;
        let guard = HelperGuard {
            child,
            _spec: prepared.spawned(),
        };
        answer(guard, &shown, &names).await
    }
}

/// Wait for a started helper's status line, then hand back its pipes, or
/// end it and say why in the daemon's own words.
async fn answer(mut guard: HelperGuard, shown: &str, names: &[&str]) -> Result<Helper, Status> {
    let (Some(stdout), Some(stdin), Some(mut stderr)) = (
        guard.child.stdout.take(),
        guard.child.stdin.take(),
        guard.child.stderr.take(),
    ) else {
        return Err(Status::internal("the forward helper's pipes are missing"));
    };
    let line = tokio::time::timeout(super::FORWARD_CONNECT_TIMEOUT, status_line(&mut stderr))
        .await
        .ok()
        .flatten();
    let parsed = line
        .as_deref()
        .and_then(|line| Refusal::parse(line, names.len()));
    match parsed {
        Some(Ok(())) => {
            tokio::spawn(async move {
                let mut discarded = Vec::with_capacity(DISCARDED_STDERR_BYTES);
                // Only drained, so a helper writing more does not block on a
                // full pipe; what it says is never used, so an error is not
                // either. Past the bound the pipe closes.
                let _ = (&mut stderr)
                    .take(DISCARDED_STDERR_BYTES as u64)
                    .read_to_end(&mut discarded)
                    .await;
            });
            Ok(Helper {
                stdout,
                stdin,
                guard,
            })
        }
        Some(Err(refusal)) => Err(status(refusal.describe(shown, names))),
        None => Err(Status::unavailable(format!(
            "the environment did not answer for {shown} within {} s",
            super::FORWARD_CONNECT_TIMEOUT.as_secs()
        ))),
    }
}

/// The helper's first line, without its newline, if it ends within
/// [`MAX_STATUS_BYTES`] and is UTF-8.
async fn status_line(stderr: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<String> {
    let mut line = Vec::with_capacity(MAX_STATUS_BYTES);
    let mut byte = [0; 1];
    while line.len() < MAX_STATUS_BYTES {
        if stderr.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line).ok();
        }
        line.push(byte[0]);
    }
    None
}

#[cfg(test)]
mod tests;
