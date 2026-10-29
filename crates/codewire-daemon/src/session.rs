use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use codewire_daemon_proto::daemon::v1;
use portable_pty::{PtySize, native_pty_system};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt as _};
use tonic::{Status, Streaming};

use crate::config::Config;
use crate::credential_bridge::CredentialBridge;
use crate::env::{build_process_env, default_shell_for};
use crate::execution::{PreparedProcess, ProcessExecution};

const BUFFER_SIZE: usize = 32 * 1024;
/// Input a PTY session holds before its launch completes. The session reads
/// its input promptly up to this bound, joining consecutive Stdin, and only
/// then stops reading until the launch completes: flow control pauses the
/// client instead of the launch failing (#2830).
const MAX_PRELAUNCH_PTY_INPUT_BYTES: usize = 64 * 1024;
/// What a held resize or end of input counts against that bound, so a stream
/// of them is bounded too.
const PRELAUNCH_PTY_CONTROL_COST: usize = 64;
/// How long a session's process group has after each signal before the next
/// one, when the session's client is gone.
const PROCESS_GROUP_GRACE: Duration = Duration::from_secs(2);

enum PtyControl {
    Stdin(Vec<u8>),
    Resize { width: i32, height: i32 },
    CloseStdin,
}

/// Input that arrived before the launch completed, in order, replayed once
/// it does.
#[derive(Default)]
struct PrelaunchPtyInput {
    controls: Vec<PtyControl>,
    bytes: usize,
    stdin_closed: bool,
    stream_ended: bool,
}

pub(crate) fn exec_session(
    config: Config,
    bridge: CredentialBridge,
    stream: Streaming<v1::ExecMessage>,
    start: v1::ExecStartRequest,
) -> ReceiverStream<Result<v1::ExecMessage, Status>> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_exec_session(config, bridge, stream, start, tx).await;
    });
    ReceiverStream::new(rx)
}

pub(crate) fn pty_session(
    config: Config,
    bridge: CredentialBridge,
    stream: Streaming<v1::PtyMessage>,
    start: v1::PtyStartRequest,
) -> ReceiverStream<Result<v1::PtyMessage, Status>> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_pty_session(config, bridge, stream, start, tx).await;
    });
    ReceiverStream::new(rx)
}

async fn run_exec_session(
    config: Config,
    bridge: CredentialBridge,
    stream: Streaming<v1::ExecMessage>,
    start: v1::ExecStartRequest,
    tx: mpsc::Sender<Result<v1::ExecMessage, Status>>,
) {
    let command = command_or_default(start.command, &config);
    let working_dir = normalize_working_dir(&config, &start.working_dir);
    let env = match build_process_env(&config, &start.env, "") {
        Ok(environment) => environment,
        Err(error) => {
            send_exec_startup_failure(&tx, error.to_string()).await;
            return;
        }
    };

    let mut prepared = match PreparedProcess::prepare_configured(
        (&config, &bridge),
        &command,
        &working_dir,
        &env,
        false,
        0,
        0,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            send_exec_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };
    let mut cmd = prepared.tokio_command();
    // The command leads its own process group, so a session whose client is
    // gone can end everything it started that did not detach itself.
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(child) => {
            prepared.spawned();
            child
        }
        Err(err) => {
            send_exec_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };

    let projection = tokio::select! {
        result = prepared.project_spawned(child.id()) => result,
        _ = tx.closed() => Err(std::io::Error::other("environment launch cancelled")),
    };
    if projection.is_err() {
        log_unadmitted_launch(&config);
        let _ = child.kill().await;
        finish_cancelled_exec_launch(child.wait().await, &tx).await;
        return;
    }

    let Some(stdin) = child.stdin.take() else {
        let _ = tx
            .send(Err(Status::internal("exec stdin pipe missing")))
            .await;
        return;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = tx
            .send(Err(Status::internal("exec stdout pipe missing")))
            .await;
        return;
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = tx
            .send(Err(Status::internal("exec stderr pipe missing")))
            .await;
        return;
    };

    let stdout_task = tokio::spawn(copy_exec_output(tx.clone(), stdout, true));
    let stderr_task = tokio::spawn(copy_exec_output(tx.clone(), stderr, false));
    let (disconnected_tx, disconnected_rx) = oneshot::channel();
    let control_task = tokio::spawn(forward_exec_control(stream, stdin, disconnected_tx));

    let wait_result = tokio::select! {
        status = child.wait() => status,
        disconnected = disconnected_rx => {
            if disconnected.unwrap_or(true) {
                end_exec_session(&mut child).await
            } else {
                tokio::select! {
                    status = child.wait() => status,
                    _ = tx.closed() => end_exec_session(&mut child).await,
                }
            }
        }
        _ = tx.closed() => end_exec_session(&mut child).await,
    };
    let completion = exec_wait_result(wait_result);
    if completion.is_err() {
        // An unconfirmed child may still hold its pipes open. Do not wait on
        // those pipes before reporting ambiguity, or invent an Exit ACK.
        let _ = child.start_kill();
        stdout_task.abort();
        stderr_task.abort();
        control_task.abort();
    }
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    let _ = tx.send(completion).await;
    let _ = control_task.await;
}

fn exec_wait_result(
    result: io::Result<std::process::ExitStatus>,
) -> Result<v1::ExecMessage, Status> {
    // As with PTY, only a successful wait proves child completion. In
    // particular, hosted setup must retain its exact-Pod recovery on error.
    match result {
        Ok(status) => Ok(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus {
                code: exit_code(status),
            })),
        }),
        Err(_) => Err(Status::unavailable(
            "environment process cleanup was not confirmed",
        )),
    }
}

/// A launch whose environment projection was not delivered: cancelled by
/// its caller, refused, or not admitted before its deadline. A hosted
/// daemon's launch waits for the platform's credential bridge, so name that
/// dependency; nothing about the request or its values is logged.
fn log_unadmitted_launch(config: &Config) {
    let hosted = config
        .credential_bridge
        .as_ref()
        .is_some_and(|identity| identity.transport == crate::CredentialBridgeTransport::Hosted);
    tracing::warn!(
        hosted_credential_bridge = hosted,
        "environment launch was cancelled or not admitted before its deadline; \
         a hosted launch waits for the platform credential bridge to connect"
    );
}

async fn finish_cancelled_exec_launch(
    reaped: io::Result<std::process::ExitStatus>,
    output: &mpsc::Sender<Result<v1::ExecMessage, Status>>,
) {
    if reaped.is_ok() {
        send_exec_startup_failure(output, "environment launch denied or expired".into()).await;
    } else {
        let _ = output
            .send(Err(Status::unavailable(
                "environment launcher cleanup was not confirmed",
            )))
            .await;
    }
}

async fn run_pty_session<S>(
    config: Config,
    bridge: CredentialBridge,
    mut stream: S,
    start: v1::PtyStartRequest,
    tx: mpsc::Sender<Result<v1::PtyMessage, Status>>,
) where
    S: Stream<Item = Result<v1::PtyMessage, Status>> + Send + Unpin + 'static,
{
    let command = command_or_default(start.command, &config);
    let working_dir = normalize_working_dir(&config, &start.working_dir);
    if matches!(&config.process_execution, ProcessExecution::Native)
        && !std::path::Path::new(&working_dir).is_dir()
    {
        send_pty_startup_failure(
            &tx,
            format!("chdir {working_dir}: no such file or directory"),
        )
        .await;
        return;
    }
    let env = match build_process_env(&config, &start.env, &start.term) {
        Ok(environment) => environment,
        Err(error) => {
            send_pty_startup_failure(&tx, error.to_string()).await;
            return;
        }
    };
    let size = pty_size(start.width, start.height);

    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(size) {
        Ok(pair) => pair,
        Err(err) => {
            send_pty_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };

    let mut prepared = match PreparedProcess::prepare_configured(
        (&config, &bridge),
        &command,
        &working_dir,
        &env,
        true,
        size.cols,
        size.rows,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            send_pty_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };
    let builder = prepared.pty_command();

    let child = match pair.slave.spawn_command(builder) {
        Ok(child) => {
            prepared.spawned();
            child
        }
        Err(err) => {
            send_pty_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };
    drop(pair.slave);

    let child = crate::execution::PtyLaunchGuard::new(child);
    let prelaunch = match await_pty_projection(
        prepared.project_spawned(child.process_id()),
        &mut stream,
        &tx,
    )
    .await
    {
        Ok(input) => input,
        Err(_) => {
            log_unadmitted_launch(&config);
            // Dropping the projection future closes the exact rendezvous and
            // cancels its bridge operation. Do not acknowledge cancellation
            // until this launcher has actually been reaped.
            finish_cancelled_pty_launch(child, &tx).await;
            return;
        }
    };

    let reader = match pair.master.try_clone_reader() {
        Ok(reader) => reader,
        Err(err) => {
            let _ = tx.send(Err(Status::internal(err.to_string()))).await;
            return;
        }
    };
    let writer = match pair.master.take_writer() {
        Ok(writer) => writer,
        Err(err) => {
            let _ = tx.send(Err(Status::internal(err.to_string()))).await;
            return;
        }
    };

    let (control_tx, control_rx) = std_mpsc::channel();
    let child = child.release();
    let leader = child.process_id();
    let master = pair.master;
    let control_thread = std::thread::spawn(move || pty_control_loop(master, writer, control_rx));
    let output_task = tokio::task::spawn_blocking({
        let tx = tx.clone();
        move || copy_pty_output(reader, tx)
    });
    let mut wait_task = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait().map(|status| status.exit_code() as i32)
    });
    let (disconnected_tx, disconnected_rx) = oneshot::channel();
    let control_task = tokio::spawn(forward_pty_control(
        stream,
        control_tx,
        disconnected_tx,
        prelaunch,
    ));

    let wait_result = tokio::select! {
        result = &mut wait_task => result,
        disconnected = disconnected_rx => {
            if disconnected.unwrap_or(true) {
                end_pty_session(leader, &mut wait_task).await
            } else {
                tokio::select! {
                    result = &mut wait_task => result,
                    _ = tx.closed() => end_pty_session(leader, &mut wait_task).await,
                }
            }
        }
        _ = tx.closed() => end_pty_session(leader, &mut wait_task).await,
    };
    let _ = output_task.await;
    let _ = tx.send(pty_wait_result(wait_result)).await;
    let _ = control_task.await;
    let _ = control_thread.join();
}

/// End an exec session whose client is gone: SIGTERM to the command's
/// process group, then SIGKILL to whatever of it is left, and reap the
/// command.
async fn end_exec_session(
    child: &mut tokio::process::Child,
) -> io::Result<std::process::ExitStatus> {
    tracing::info!("exec session client is gone; ending its process group");
    let leader = child.id();
    end_process_group(
        leader,
        GroupEnd::Terminate,
        PROCESS_GROUP_GRACE,
        child.wait(),
    )
    .await
}

/// End a PTY session whose client is gone as a terminal hangup does.
async fn end_pty_session(
    leader: Option<u32>,
    wait: &mut tokio::task::JoinHandle<io::Result<i32>>,
) -> Result<io::Result<i32>, tokio::task::JoinError> {
    tracing::info!("PTY session client is gone; hanging up its process group");
    end_process_group(leader, GroupEnd::HangUp, PROCESS_GROUP_GRACE, wait).await
}

/// How a session's process group is ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupEnd {
    /// SIGTERM to the group, then SIGKILL to whatever of it is left.
    Terminate,
    /// SIGHUP to the group first, as a terminal hangup sends. When the
    /// leader exits, what is left of its group ignored the hangup, as
    /// `nohup` jobs do, and keeps running. A leader that ignores it is
    /// ended as [`GroupEnd::Terminate`] ends it.
    HangUp,
}

/// End the process group that `leader` leads, waiting `grace` after each
/// signal for the leader, and for the rest of the group, before the next.
/// Processes that left the group, such as `setsid` children and the daemon's
/// own durable `cw` sessions, are never signalled. Returns `wait`, the
/// leader's reap.
async fn end_process_group<W, T>(leader: Option<u32>, end: GroupEnd, grace: Duration, wait: W) -> T
where
    W: Future<Output = T>,
{
    let Some(group) = leader.and_then(|pid| i32::try_from(pid).ok()) else {
        // Already reaped: nothing to signal.
        return wait.await;
    };
    tokio::pin!(wait);
    if end == GroupEnd::HangUp {
        signal_process_group(group, GroupSignal::HangUp);
        if let Ok(result) = tokio::time::timeout(grace, &mut wait).await {
            return result;
        }
    }
    signal_process_group(group, GroupSignal::Terminate);
    let deadline = tokio::time::Instant::now() + grace;
    let reaped = tokio::time::timeout_at(deadline, &mut wait).await.ok();
    if reaped.is_some() {
        while process_group_has_members(group) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    if reaped.is_none() || process_group_has_members(group) {
        signal_process_group(group, GroupSignal::Kill);
    }
    match reaped {
        Some(result) => result,
        None => wait.await,
    }
}

#[derive(Clone, Copy)]
enum GroupSignal {
    HangUp,
    Terminate,
    Kill,
}

/// Send `signal` to the process group `group` leads.
#[cfg(unix)]
fn signal_process_group(group: i32, signal: GroupSignal) {
    let signal = match signal {
        GroupSignal::HangUp => libc::SIGHUP,
        GroupSignal::Terminate => libc::SIGTERM,
        GroupSignal::Kill => libc::SIGKILL,
    };
    // Group 0 would be the daemon's own, and -1 every process it may signal.
    if group > 1 {
        // SAFETY: kill takes no pointers; a negative id names exactly the
        // process group `group`.
        unsafe { libc::kill(-group, signal) };
    }
}

#[cfg(not(unix))]
fn signal_process_group(_group: i32, _signal: GroupSignal) {}

/// Whether any process, a zombie included, is still in `group`.
#[cfg(unix)]
fn process_group_exists(group: i32) -> bool {
    // SAFETY: kill takes no pointers; signal 0 only checks that the group
    // `group` has a member.
    group > 1 && unsafe { libc::kill(-group, 0) } == 0
}

/// Whether a live process is still in `group`. A zombie is not: it waits
/// only for its parent, or PID 1, to reap it.
#[cfg(target_os = "linux")]
fn process_group_has_members(group: i32) -> bool {
    let Ok(processes) = std::fs::read_dir("/proc") else {
        return process_group_exists(group);
    };
    processes.flatten().any(|process| {
        process
            .file_name()
            .to_str()
            .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            && std::fs::read_to_string(process.path().join("stat"))
                .is_ok_and(|stat| is_live_member(&stat, group))
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_group_has_members(group: i32) -> bool {
    process_group_exists(group)
}

#[cfg(not(unix))]
fn process_group_has_members(_group: i32) -> bool {
    false
}

/// Whether a `/proc/<pid>/stat` line is a live process in `group`.
#[cfg(target_os = "linux")]
fn is_live_member(stat: &str, group: i32) -> bool {
    // `pid (comm) state ppid pgrp ...`; comm may contain spaces and ')'.
    let Some((_, fields)) = stat.rsplit_once(") ") else {
        return false;
    };
    let mut fields = fields.split_ascii_whitespace();
    let (state, _parent, process_group) = (fields.next(), fields.next(), fields.next());
    !matches!(state, None | Some("Z" | "X"))
        && process_group.and_then(|value| value.parse().ok()) == Some(group)
}

fn pty_wait_result(
    result: Result<io::Result<i32>, tokio::task::JoinError>,
) -> Result<v1::PtyMessage, Status> {
    // Exit is a child-completion acknowledgement, not a replacement for a
    // failed waiter. Consumers must retain ambiguous admission on failure.
    match result {
        Ok(Ok(code)) => Ok(v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code })),
        }),
        Ok(Err(_)) | Err(_) => Err(Status::unavailable(
            "environment process cleanup was not confirmed",
        )),
    }
}

/// Poll input during the existing launch deadline, without starting a second
/// reader or reconstructing/retrying the projection. A retained response can
/// therefore observe cancellation while withholding all command stdin until
/// projection commits. Explicit stdin half-close remains a normal launch.
///
/// Input is read promptly and held in order. A burst of keystroke-sized
/// frames, such as a fast paste or `ssh -tt host < file` at connect, is
/// therefore never left unread in HTTP/2, whose flood guard ends the whole
/// connection when unread small DATA frames pile up (#2822, #3688). Only at
/// the byte bound does the session stop reading, still watching for
/// cancellation, until the launch completes; the client then waits behind
/// flow control rather than the launch being cancelled (#2830).
async fn await_pty_projection<P, S>(
    projection: P,
    stream: &mut S,
    output: &mpsc::Sender<Result<v1::PtyMessage, Status>>,
) -> io::Result<PrelaunchPtyInput>
where
    P: Future<Output = io::Result<()>>,
    S: Stream<Item = Result<v1::PtyMessage, Status>> + Unpin,
{
    tokio::pin!(projection);
    let mut input = PrelaunchPtyInput::default();
    loop {
        tokio::select! {
            biased;
            _ = output.closed() => return Err(pty_launch_cancelled()),
            message = stream.next(), if !input.stream_ended && !input.is_full() => match message {
                Some(Ok(message)) => input.queue(message),
                Some(Err(_)) => return Err(pty_launch_cancelled()),
                None if !input.stdin_closed => return Err(pty_launch_cancelled()),
                None => input.stream_ended = true,
            },
            result = &mut projection => {
                result?;
                return Ok(input);
            }
        }
    }
}

impl PrelaunchPtyInput {
    /// Whether the session must stop reading input until the launch
    /// completes. It is checked before each read, so the queue never holds
    /// more than the bound plus the one frame that reached it, which the
    /// transport's message limit bounds.
    fn is_full(&self) -> bool {
        self.bytes >= MAX_PRELAUNCH_PTY_INPUT_BYTES
    }

    /// Hold one input frame. Stdin joins the Stdin held right before it, so
    /// it never passes a resize or end of input; Stdin after end of input is
    /// dropped, as the terminal writer drops it.
    fn queue(&mut self, message: v1::PtyMessage) {
        match message.payload {
            Some(v1::pty_message::Payload::Stdin(data))
                if !data.is_empty() && !self.stdin_closed =>
            {
                self.bytes = self.bytes.saturating_add(data.len());
                match self.controls.last_mut() {
                    Some(PtyControl::Stdin(held)) => held.extend_from_slice(&data),
                    _ => self.controls.push(PtyControl::Stdin(data)),
                }
            }
            Some(v1::pty_message::Payload::Resize(resize)) => {
                self.bytes = self.bytes.saturating_add(PRELAUNCH_PTY_CONTROL_COST);
                self.controls.push(PtyControl::Resize {
                    width: resize.width,
                    height: resize.height,
                });
            }
            Some(v1::pty_message::Payload::CloseStdin(_)) if !self.stdin_closed => {
                self.stdin_closed = true;
                self.bytes = self.bytes.saturating_add(PRELAUNCH_PTY_CONTROL_COST);
                self.controls.push(PtyControl::CloseStdin);
            }
            _ => {}
        }
    }
}

fn pty_launch_cancelled() -> io::Error {
    io::Error::other("environment launch cancelled")
}

async fn finish_cancelled_pty_launch(
    child: crate::execution::PtyLaunchGuard,
    output: &mpsc::Sender<Result<v1::PtyMessage, Status>>,
) {
    let mut child = child.release();
    let reaped = tokio::task::spawn_blocking(move || {
        // A kill can race natural exit. The wait result, not kill success, is
        // the authoritative proof that this exact child no longer runs.
        let _ = child.kill();
        child.wait()
    })
    .await;
    if matches!(reaped, Ok(Ok(_))) {
        send_pty_startup_failure(output, "environment launch denied or expired".into()).await;
    } else {
        // No Exit ACK when wait/panic failed: the caller must retain its
        // existing ambiguous-admission recovery state, not assume a reap.
        let _ = output
            .send(Err(Status::unavailable(
                "environment launcher cleanup was not confirmed",
            )))
            .await;
    }
}

async fn copy_exec_output<R>(
    tx: mpsc::Sender<Result<v1::ExecMessage, Status>>,
    mut reader: R,
    stdout: bool,
) where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; BUFFER_SIZE];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                let data = buf[..n].to_vec();
                let payload = if stdout {
                    v1::exec_message::Payload::Stdout(data)
                } else {
                    v1::exec_message::Payload::Stderr(data)
                };
                if tx
                    .send(Ok(v1::ExecMessage {
                        payload: Some(payload),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(err) => {
                let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                return;
            }
        }
    }
}

async fn forward_exec_control(
    mut stream: Streaming<v1::ExecMessage>,
    stdin: tokio::process::ChildStdin,
    disconnected: oneshot::Sender<bool>,
) {
    let mut stdin = Some(stdin);
    let mut disconnected = Some(disconnected);
    let mut stdin_closed = false;
    loop {
        match stream.message().await {
            Ok(Some(msg)) => match msg.payload {
                Some(v1::exec_message::Payload::Stdin(data)) if !data.is_empty() => {
                    let Some(stdin) = stdin.as_mut() else {
                        continue;
                    };
                    if stdin.write_all(&data).await.is_err() {
                        return;
                    }
                }
                Some(v1::exec_message::Payload::CloseStdin(_)) => {
                    stdin_closed = true;
                    let Some(mut stdin) = stdin.take() else {
                        continue;
                    };
                    let _ = stdin.shutdown().await;
                }
                _ => {}
            },
            Ok(None) => {
                if let Some(mut stdin) = stdin.take() {
                    let _ = stdin.shutdown().await;
                }
                if let Some(disconnected) = disconnected.take() {
                    let _ = disconnected.send(!stdin_closed);
                }
                return;
            }
            Err(_) => {
                if let Some(mut stdin) = stdin.take() {
                    let _ = stdin.shutdown().await;
                }
                if let Some(disconnected) = disconnected.take() {
                    let _ = disconnected.send(true);
                }
                return;
            }
        }
    }
}

fn copy_pty_output(
    mut reader: Box<dyn Read + Send>,
    tx: mpsc::Sender<Result<v1::PtyMessage, Status>>,
) {
    let mut buf = vec![0; BUFFER_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                let data = buf[..n].to_vec();
                if tx
                    .blocking_send(Ok(v1::PtyMessage {
                        payload: Some(v1::pty_message::Payload::Stdout(data)),
                    }))
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Forward a running session's input to its terminal writer. It reads every
/// frame as it arrives, never waiting on the terminal: a frame left unread
/// in HTTP/2 counts against the connection's small DATA frame flood guard
/// (#2822).
async fn forward_pty_control<S>(
    mut stream: S,
    control_tx: std_mpsc::Sender<PtyControl>,
    disconnected: oneshot::Sender<bool>,
    prelaunch: PrelaunchPtyInput,
) where
    S: Stream<Item = Result<v1::PtyMessage, Status>> + Unpin,
{
    let mut disconnected = Some(disconnected);
    let mut stdin_closed = prelaunch.stdin_closed;
    for control in prelaunch.controls {
        let _ = control_tx.send(control);
    }
    if prelaunch.stream_ended {
        let _ = control_tx.send(PtyControl::CloseStdin);
        let _ = disconnected
            .take()
            .expect("disconnect sender is owned")
            .send(!stdin_closed);
        return;
    }
    loop {
        match stream.next().await {
            Some(Ok(msg)) => match msg.payload {
                Some(v1::pty_message::Payload::Stdin(data)) if !data.is_empty() => {
                    let _ = control_tx.send(PtyControl::Stdin(data));
                }
                Some(v1::pty_message::Payload::CloseStdin(_)) => {
                    stdin_closed = true;
                    let _ = control_tx.send(PtyControl::CloseStdin);
                }
                Some(v1::pty_message::Payload::Resize(resize)) => {
                    let _ = control_tx.send(PtyControl::Resize {
                        width: resize.width,
                        height: resize.height,
                    });
                }
                _ => {}
            },
            None => {
                let _ = control_tx.send(PtyControl::CloseStdin);
                if let Some(disconnected) = disconnected.take() {
                    let _ = disconnected.send(!stdin_closed);
                }
                return;
            }
            Some(Err(_)) => {
                let _ = control_tx.send(PtyControl::CloseStdin);
                if let Some(disconnected) = disconnected.take() {
                    let _ = disconnected.send(true);
                }
                return;
            }
        }
    }
}

fn pty_control_loop(
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    control_rx: std_mpsc::Receiver<PtyControl>,
) {
    let mut writer = Some(writer);
    for control in control_rx {
        match control {
            PtyControl::Stdin(data) => {
                if let Some(writer) = writer.as_mut() {
                    let _ = writer.write_all(&data);
                    let _ = writer.flush();
                }
            }
            PtyControl::Resize { width, height } => {
                let _ = master.resize(pty_size(width, height));
            }
            PtyControl::CloseStdin => {
                writer.take();
            }
        }
    }
}

async fn send_exec_startup_failure(
    tx: &mpsc::Sender<Result<v1::ExecMessage, Status>>,
    error: String,
) {
    let _ = tx
        .send(Ok(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Error(error)),
        }))
        .await;
    let _ = tx
        .send(Ok(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus { code: 1 })),
        }))
        .await;
}

async fn send_pty_startup_failure(
    tx: &mpsc::Sender<Result<v1::PtyMessage, Status>>,
    error: String,
) {
    let _ = tx
        .send(Ok(v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Error(error)),
        }))
        .await;
    let _ = tx
        .send(Ok(v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code: 1 })),
        }))
        .await;
}

fn command_or_default(command: Vec<String>, config: &Config) -> Vec<String> {
    if command.is_empty() {
        vec![default_shell_for(config)]
    } else {
        command
    }
}

fn normalize_working_dir(config: &Config, dir: &str) -> String {
    if dir.trim().is_empty() {
        config.home_root.to_string_lossy().into_owned()
    } else {
        dir.into()
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn pty_size(width: i32, height: i32) -> PtySize {
    PtySize {
        rows: u16::try_from(height.max(0)).unwrap_or(u16::MAX),
        cols: u16::try_from(width.max(0)).unwrap_or(u16::MAX),
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "session/projection_tests.rs"]
mod projection_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "session/process_group_tests.rs"]
mod process_group_tests;
