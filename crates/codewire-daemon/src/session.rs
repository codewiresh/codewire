use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::mpsc as std_mpsc;

use codewire_gateway_proto::daemon::v1;
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
const MAX_PRELAUNCH_PTY_CONTROLS: usize = 32;
const MAX_PRELAUNCH_PTY_INPUT_BYTES: usize = 64 * 1024;

enum PtyControl {
    Stdin(Vec<u8>),
    Resize { width: i32, height: i32 },
    CloseStdin,
}

#[derive(Default)]
struct PrelaunchPtyInput {
    controls: Vec<PtyControl>,
    frames: usize,
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
                let _ = child.kill().await;
                child.wait().await
            } else {
                tokio::select! {
                    status = child.wait() => status,
                    _ = tx.closed() => {
                        let _ = child.kill().await;
                        child.wait().await
                    }
                }
            }
        }
        _ = tx.closed() => {
            let _ = child.kill().await;
            child.wait().await
        }
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
    let master = pair.master;
    let control_thread = std::thread::spawn(move || pty_control_loop(master, writer, control_rx));
    let output_task = tokio::task::spawn_blocking({
        let tx = tx.clone();
        move || copy_pty_output(reader, tx)
    });
    let mut killer = Some(child.clone_killer());
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
                if let Some(mut killer) = killer.take() {
                    let _ = tokio::task::spawn_blocking(move || killer.kill()).await;
                }
                wait_task.await
            } else {
                tokio::select! {
                    result = &mut wait_task => result,
                    _ = tx.closed() => {
                        if let Some(mut killer) = killer.take() {
                            let _ = tokio::task::spawn_blocking(move || killer.kill()).await;
                        }
                        wait_task.await
                    }
                }
            }
        }
        _ = tx.closed() => {
            if let Some(mut killer) = killer.take() {
                let _ = tokio::task::spawn_blocking(move || killer.kill()).await;
            }
            wait_task.await
        }
    };
    let _ = output_task.await;
    let _ = tx.send(pty_wait_result(wait_result)).await;
    let _ = control_task.await;
    let _ = control_thread.join();
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
            message = stream.next(), if !input.stream_ended => match message {
                Some(Ok(message)) => input.queue(message)?,
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
    fn queue(&mut self, message: v1::PtyMessage) -> io::Result<()> {
        self.frames += 1;
        if self.frames > MAX_PRELAUNCH_PTY_CONTROLS {
            return Err(pty_launch_cancelled());
        }
        match message.payload {
            Some(v1::pty_message::Payload::Stdin(data)) if !data.is_empty() => {
                self.bytes = self
                    .bytes
                    .checked_add(data.len())
                    .ok_or_else(pty_launch_cancelled)?;
                if self.bytes > MAX_PRELAUNCH_PTY_INPUT_BYTES {
                    return Err(pty_launch_cancelled());
                }
                if !self.stdin_closed {
                    self.controls.push(PtyControl::Stdin(data));
                }
            }
            Some(v1::pty_message::Payload::Resize(resize)) => {
                self.controls.push(PtyControl::Resize {
                    width: resize.width,
                    height: resize.height,
                });
            }
            Some(v1::pty_message::Payload::CloseStdin(_)) if !self.stdin_closed => {
                self.stdin_closed = true;
                self.controls.push(PtyControl::CloseStdin);
            }
            _ => {}
        }
        Ok(())
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
