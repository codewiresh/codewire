use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::mpsc as std_mpsc;

use codewire_gateway_proto::daemon::v1;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::config::Config;
use crate::env::{build_process_env, default_shell};

const BUFFER_SIZE: usize = 32 * 1024;

enum PtyControl {
    Stdin(Vec<u8>),
    Resize { width: i32, height: i32 },
    CloseStdin,
}

pub fn exec_session(
    config: Config,
    stream: Streaming<v1::ExecMessage>,
    start: v1::ExecStartRequest,
) -> ReceiverStream<Result<v1::ExecMessage, Status>> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_exec_session(config, stream, start, tx).await;
    });
    ReceiverStream::new(rx)
}

pub fn pty_session(
    config: Config,
    stream: Streaming<v1::PtyMessage>,
    start: v1::PtyStartRequest,
) -> ReceiverStream<Result<v1::PtyMessage, Status>> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_pty_session(config, stream, start, tx).await;
    });
    ReceiverStream::new(rx)
}

async fn run_exec_session(
    config: Config,
    stream: Streaming<v1::ExecMessage>,
    start: v1::ExecStartRequest,
    tx: mpsc::Sender<Result<v1::ExecMessage, Status>>,
) {
    let command = command_or_default(start.command);
    let working_dir = normalize_working_dir(&config, &start.working_dir);
    let env = build_process_env(&config, &start.env, "");

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(&working_dir)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_env(&mut cmd, &env);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            send_exec_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };

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

    let exit_code = tokio::select! {
        status = child.wait() => status.map(exit_code).unwrap_or(1),
        disconnected = disconnected_rx => {
            if disconnected.unwrap_or(true) {
                let _ = child.kill().await;
            }
            child.wait().await.map(exit_code).unwrap_or(1)
        }
    };
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    let _ = tx
        .send(Ok(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus {
                code: exit_code,
            })),
        }))
        .await;
    let _ = control_task.await;
}

async fn run_pty_session(
    config: Config,
    stream: Streaming<v1::PtyMessage>,
    start: v1::PtyStartRequest,
    tx: mpsc::Sender<Result<v1::PtyMessage, Status>>,
) {
    let command = command_or_default(start.command);
    let working_dir = normalize_working_dir(&config, &start.working_dir);
    if !std::path::Path::new(&working_dir).is_dir() {
        send_pty_startup_failure(
            &tx,
            format!("chdir {working_dir}: no such file or directory"),
        )
        .await;
        return;
    }
    let env = build_process_env(&config, &start.env, &start.term);
    let size = pty_size(start.width, start.height);

    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(size) {
        Ok(pair) => pair,
        Err(err) => {
            send_pty_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };

    let mut builder = CommandBuilder::new(&command[0]);
    builder.args(&command[1..]);
    builder.cwd(&working_dir);
    builder.env_clear();
    for entry in env {
        if let Some((key, value)) = entry.split_once('=') {
            builder.env(key, value);
        }
    }

    let child = match pair.slave.spawn_command(builder) {
        Ok(child) => child,
        Err(err) => {
            send_pty_startup_failure(&tx, err.to_string()).await;
            return;
        }
    };
    drop(pair.slave);

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
    let master = pair.master;
    let control_thread = std::thread::spawn(move || pty_control_loop(master, writer, control_rx));
    let output_task = tokio::task::spawn_blocking({
        let tx = tx.clone();
        move || copy_pty_output(reader, tx)
    });
    let mut killer = child.clone_killer();
    let mut wait_task = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child
            .wait()
            .map(|status| status.exit_code() as i32)
            .unwrap_or(1)
    });
    let (disconnected_tx, disconnected_rx) = oneshot::channel();
    let control_task = tokio::spawn(forward_pty_control(stream, control_tx, disconnected_tx));

    let exit_code = tokio::select! {
        result = &mut wait_task => result.unwrap_or(1),
        disconnected = disconnected_rx => {
            if disconnected.unwrap_or(true) {
                let _ = tokio::task::spawn_blocking(move || killer.kill()).await;
            }
            wait_task.await.unwrap_or(1)
        }
    };
    let _ = output_task.await;
    let _ = tx
        .send(Ok(v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus {
                code: exit_code,
            })),
        }))
        .await;
    let _ = control_task.await;
    let _ = control_thread.join();
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

async fn forward_pty_control(
    mut stream: Streaming<v1::PtyMessage>,
    control_tx: std_mpsc::Sender<PtyControl>,
    disconnected: oneshot::Sender<bool>,
) {
    let mut disconnected = Some(disconnected);
    let mut stdin_closed = false;
    loop {
        match stream.message().await {
            Ok(Some(msg)) => match msg.payload {
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
            Ok(None) => {
                let _ = control_tx.send(PtyControl::CloseStdin);
                if let Some(disconnected) = disconnected.take() {
                    let _ = disconnected.send(!stdin_closed);
                }
                return;
            }
            Err(_) => {
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

fn command_or_default(command: Vec<String>) -> Vec<String> {
    if command.is_empty() {
        vec![default_shell()]
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

fn apply_env(cmd: &mut tokio::process::Command, env: &[String]) {
    for entry in env {
        if let Some((key, value)) = entry.split_once('=') {
            cmd.env(key, value);
        }
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
