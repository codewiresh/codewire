//! Workspace exec. Every command the worker runs inside a workspace container
//! goes through `build_workspace_exec_command`; Rust-owned fixtures under
//! `tests/fixtures/sandbox` pin its output byte-for-byte.

use std::collections::BTreeMap;

use futures::SinkExt;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;
use kube::api::{Api, AttachParams, AttachedProcess, TerminalSize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use super::client::SandboxClient;
use crate::worker::scripts::shell_quote;

const WORKSPACE_EXEC_CAPTURE_BYTES: usize = 64 * 1024;

/// Mirrors `sandbox.WorkspaceExecResult`.
#[derive(Debug, Default, Clone)]
pub struct WorkspaceExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// A workspace command whose Kubernetes attachment handshake has completed.
/// Setup fencing retains this handle until `wait` observes the remote exit;
/// dropping it is ambiguous and therefore requires Pod recovery.
pub struct WorkspaceExecHandle {
    attached: AttachedProcess,
}

/// Interactive terminal command whose Kubernetes attachment handshake has
/// completed. Runtime admission can be released before the long-lived stream
/// is driven; environment teardown then closes the established attachment by
/// deleting its Pod.
pub struct WorkspaceTerminalHandle {
    attached: AttachedProcess,
}

struct BoundedOutput {
    bytes: Zeroizing<Vec<u8>>,
}

impl WorkspaceExecHandle {
    pub async fn wait(mut self) -> anyhow::Result<WorkspaceExecResult> {
        let stdout: anyhow::Result<Vec<u8>>;
        let stderr: anyhow::Result<Vec<u8>>;
        let mut out_reader = self.attached.stdout();
        let mut err_reader = self.attached.stderr();
        let status_fut = self.attached.take_status();
        let out_task = async {
            if let Some(reader) = out_reader.as_mut() {
                read_bounded(reader, WORKSPACE_EXEC_CAPTURE_BYTES)
                    .await
                    .map(|output| output.bytes.to_vec())
                    .map_err(|error| anyhow::anyhow!("workspace exec stdout: {error}"))
            } else {
                Ok(Vec::new())
            }
        };
        let err_task = async {
            if let Some(reader) = err_reader.as_mut() {
                read_bounded(reader, WORKSPACE_EXEC_CAPTURE_BYTES)
                    .await
                    .map(|output| output.bytes.to_vec())
                    .map_err(|error| anyhow::anyhow!("workspace exec stderr: {error}"))
            } else {
                Ok(Vec::new())
            }
        };
        let status = if let Some(future) = status_fut {
            let (out, err, status) = tokio::join!(out_task, err_task, future);
            stdout = out;
            stderr = err;
            status
        } else {
            let (out, err) = tokio::join!(out_task, err_task);
            stdout = out;
            stderr = err;
            None
        };
        self.attached
            .join()
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec completion: {error}"))?;
        let stdout = stdout?;
        let stderr = stderr?;

        let result = WorkspaceExecResult {
            stdout,
            stderr,
            exit_code: 0,
        };
        classify_workspace_exec_status(status, result)
    }

    pub async fn stream(
        mut self,
        tx: tokio::sync::mpsc::Sender<(bool, Vec<u8>)>,
    ) -> anyhow::Result<i32> {
        let status_fut = self.attached.take_status();
        let mut out_reader = self.attached.stdout();
        let mut err_reader = self.attached.stderr();

        let out_tx = tx.clone();
        let out_task = async move {
            let mut receiver_open = true;
            if let Some(reader) = out_reader.as_mut() {
                let mut buffer = [0u8; 32 * 1024];
                loop {
                    let count = reader.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    if receiver_open
                        && out_tx
                            .send((false, buffer[..count].to_vec()))
                            .await
                            .is_err()
                    {
                        receiver_open = false;
                    }
                }
            }
            Ok::<(), std::io::Error>(())
        };
        let err_tx = tx.clone();
        let err_task = async move {
            let mut receiver_open = true;
            if let Some(reader) = err_reader.as_mut() {
                let mut buffer = [0u8; 32 * 1024];
                loop {
                    let count = reader.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    if receiver_open && err_tx.send((true, buffer[..count].to_vec())).await.is_err()
                    {
                        receiver_open = false;
                    }
                }
            }
            Ok::<(), std::io::Error>(())
        };
        let (out, err, status) = if let Some(future) = status_fut {
            let (out, err, status) = tokio::join!(out_task, err_task, future);
            (out, err, status)
        } else {
            let (out, err) = tokio::join!(out_task, err_task);
            (out, err, None)
        };
        let completion = self
            .attached
            .join()
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec completion: {error}"));
        completion?;
        out.map_err(|error| anyhow::anyhow!("workspace exec stdout: {error}"))?;
        err.map_err(|error| anyhow::anyhow!("workspace exec stderr: {error}"))?;
        Ok(status.as_ref().and_then(exit_code_from_status).unwrap_or(0))
    }
}

impl WorkspaceTerminalHandle {
    pub async fn run(
        mut self,
        mut stdin_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        stdout_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        mut resize_rx: tokio::sync::mpsc::Receiver<TerminalSize>,
    ) -> anyhow::Result<()> {
        let mut stdin = self
            .attached
            .stdin()
            .ok_or_else(|| anyhow::anyhow!("workspace terminal exec: stdin unavailable"))?;
        let mut stdout = self
            .attached
            .stdout()
            .ok_or_else(|| anyhow::anyhow!("workspace terminal exec: stdout unavailable"))?;
        let mut terminal_size = self.attached.terminal_size();

        let stdin_task = tokio::spawn(async move {
            while let Some(bytes) = stdin_rx.recv().await {
                if stdin.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        let stdout_task = tokio::spawn(async move {
            let mut buffer = [0u8; 32 * 1024];
            loop {
                match stdout.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if stdout_tx.send(buffer[..count].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let resize_task = tokio::spawn(async move {
            let Some(mut terminal_size) = terminal_size.take() else {
                return;
            };
            while let Some(size) = resize_rx.recv().await {
                if terminal_size.send(size).await.is_err() {
                    break;
                }
            }
        });

        let join = self.attached.join().await;
        stdin_task.abort();
        resize_task.abort();
        let _ = stdout_task.await;
        join.map_err(|error| anyhow::anyhow!("workspace terminal exec: {error}"))
    }
}

/// Mirrors `buildWorkspaceExecCommand`: source the env file, cd into
/// the workdir, export sorted env vars, then exec the quoted argv —
/// all under `sh -lc`.
pub fn build_workspace_exec_command(
    command: &[String],
    work_dir: &str,
    env: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut steps: Vec<String> = Vec::with_capacity(env.len() + 3);
    steps.push(
        r#"if [ -f "$HOME/.codewire/environment.sh" ]; then . "$HOME/.codewire/environment.sh"; fi"#
            .to_string(),
    );
    if !work_dir.is_empty() {
        steps.push(format!("cd {}", shell_quote(work_dir)));
    }
    for (key, value) in env {
        steps.push(format!("export {key}={}", shell_quote(value)));
    }
    let quoted: Vec<String> = command.iter().map(|a| shell_quote(a)).collect();
    steps.push(format!("exec {}", quoted.join(" ")));
    vec!["sh".to_string(), "-lc".to_string(), steps.join(" && ")]
}

impl SandboxClient {
    /// Mirrors the terminal path's raw `sandbox.Client.Exec` call: run
    /// the provided command in a TTY in the `workspace` container and
    /// bridge stdin/stdout/resize without applying the non-interactive
    /// workspace command wrapper.
    pub async fn exec_workspace_terminal_on_pod(
        &self,
        pod_name: &str,
        command: &[String],
        stdin_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        stdout_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        resize_rx: tokio::sync::mpsc::Receiver<TerminalSize>,
    ) -> anyhow::Result<()> {
        self.start_workspace_terminal_on_pod(pod_name, command)
            .await?
            .run(stdin_rx, stdout_tx, resize_rx)
            .await
    }

    pub async fn start_workspace_terminal_on_pod(
        &self,
        pod_name: &str,
        command: &[String],
    ) -> anyhow::Result<WorkspaceTerminalHandle> {
        if command.is_empty() {
            anyhow::bail!("workspace terminal exec: command is required");
        }
        if pod_name.trim().is_empty() {
            anyhow::bail!("workspace terminal exec: pod name is required");
        }

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let params = AttachParams::default()
            .container("workspace")
            .stdin(true)
            .stdout(true)
            .stderr(false)
            .tty(true);

        let attached = pods
            .exec(pod_name, command.to_vec(), &params)
            .await
            .map_err(|e| anyhow::anyhow!("workspace terminal exec: {e}"))?;
        Ok(WorkspaceTerminalHandle { attached })
    }

    /// Mirrors `ExecWorkspaceResultOnPod`: run in the `workspace`
    /// container of a concrete pod, capture output, and map a nonzero
    /// exit into `exit_code` rather than an error.
    pub async fn exec_workspace_result_on_pod(
        &self,
        pod_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<WorkspaceExecResult> {
        self.start_workspace_exec_on_pod(pod_name, command, work_dir, env)
            .await?
            .wait()
            .await
    }

    /// Attach to a command in a concrete Pod without waiting for exit.
    /// Fenced setup callers hold their lease row lock across this handshake.
    pub async fn start_workspace_exec_on_pod(
        &self,
        pod_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<WorkspaceExecHandle> {
        if command.is_empty() {
            anyhow::bail!("workspace exec: command is required");
        }
        if pod_name.trim().is_empty() {
            anyhow::bail!("workspace exec: pod name is required");
        }

        let exec_command = build_workspace_exec_command(command, work_dir, env);
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let params = AttachParams::default()
            .container("workspace")
            .stdin(false)
            .stdout(true)
            .stderr(true)
            .tty(false);

        let attached = pods
            .exec(pod_name, exec_command, &params)
            .await
            .map_err(|e| anyhow::anyhow!("workspace exec: {e}"))?;
        Ok(WorkspaceExecHandle { attached })
    }

    /// Mirrors `ExecWorkspaceResult`: resolve the pod, then exec.
    pub async fn exec_workspace_result(
        &self,
        env_id: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<WorkspaceExecResult> {
        if command.is_empty() {
            anyhow::bail!("workspace exec: command is required");
        }
        let pod_name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("workspace exec: resolve pod name: {e}"))?;
        self.exec_workspace_result_on_pod(&pod_name, command, work_dir, env)
            .await
    }

    /// Mirrors `ExecWorkspaceStreamOnPod`: stream stdout/stderr chunks
    /// to the caller as they arrive (each side tagged), returning the
    /// exit code (0 on success, the real code on nonzero, error only on
    /// transport failure). Chunks are sent as `(is_stderr, bytes)` on
    /// `tx`; the caller frames them. Closing the receiver stops forwarding,
    /// while this side continues draining the attachment through remote exit.
    pub async fn exec_workspace_stream_on_pod(
        &self,
        pod_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
        tx: tokio::sync::mpsc::Sender<(bool, Vec<u8>)>,
    ) -> anyhow::Result<i32> {
        self.start_workspace_exec_on_pod(pod_name, command, work_dir, env)
            .await?
            .stream(tx)
            .await
    }

    /// Mirrors `ExecWorkspace`: error on nonzero exit without copying opaque
    /// child output into an error that may be logged or persisted.
    pub async fn exec_workspace(
        &self,
        env_id: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<()> {
        let result = self
            .exec_workspace_result(env_id, command, work_dir, env)
            .await?;
        if result.exit_code != 0 {
            anyhow::bail!("workspace exec exited {}", result.exit_code);
        }
        Ok(())
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<BoundedOutput> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1024)));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let retain = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retain]);
    }
    Ok(BoundedOutput { bytes })
}

fn classify_workspace_exec_status(
    status: Option<Status>,
    mut result: WorkspaceExecResult,
) -> anyhow::Result<WorkspaceExecResult> {
    let Some(status) = status else {
        return Ok(result);
    };
    if status.status.as_deref() == Some("Success") {
        return Ok(result);
    }
    if let Some(code) = exit_code_from_status(&status) {
        result.exit_code = code;
        return Ok(result);
    }

    // An unclassified Kubernetes status and the captured child streams are
    // opaque, so none of this content is safe to retain in an error, Temporal
    // failure, or log record.
    Err(anyhow::anyhow!(
        "workspace exec returned an unclassified failure status"
    ))
}

fn exit_code_from_status(s: &Status) -> Option<i32> {
    if s.reason.as_deref() != Some("NonZeroExitCode") {
        return None;
    }
    let causes = s.details.as_ref()?.causes.as_ref()?;
    for cause in causes {
        if cause.reason.as_deref() == Some("ExitCode") {
            return cause.message.as_deref()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn golden_argv(name: &str) -> Vec<String> {
        let path = format!(
            "{}/tests/fixtures/sandbox/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read golden {path}: {e}"));
        serde_json::from_str(&data).expect("golden is a JSON argv array")
    }

    #[test]
    fn exec_command_matches_golden_basic() {
        let cmd: Vec<String> = [
            "git",
            "clone",
            "https://github.com/org/repo.git",
            "/workspace/repo",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            build_workspace_exec_command(&cmd, "", &BTreeMap::new()),
            golden_argv("execcommand-basic.golden.json")
        );
    }

    #[test]
    fn exec_command_matches_golden_full() {
        let cmd: Vec<String> = ["sh", "-c", "npm install && echo 'done'"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut env = BTreeMap::new();
        env.insert("Z_LAST".to_string(), "with 'single' quotes".to_string());
        env.insert("A_FIRST".to_string(), "plain".to_string());
        env.insert("B_META".to_string(), "$HOME `cmd` \"dq\"".to_string());
        let argv = build_workspace_exec_command(&cmd, "/workspace/my repo", &env);
        assert_eq!(argv, golden_argv("execcommand-full.golden.json"));
    }

    #[tokio::test]
    async fn bounded_reader_drains_but_retains_only_the_limit() {
        let input = vec![0x41; WORKSPACE_EXEC_CAPTURE_BYTES + 137];
        let mut reader = std::io::Cursor::new(input);
        let output = read_bounded(&mut reader, WORKSPACE_EXEC_CAPTURE_BYTES)
            .await
            .unwrap();
        assert_eq!(output.bytes.len(), WORKSPACE_EXEC_CAPTURE_BYTES);
        assert_eq!(
            reader.position(),
            (WORKSPACE_EXEC_CAPTURE_BYTES + 137) as u64
        );
    }

    #[test]
    fn exit_code_parses_from_failure_status() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Status, StatusCause, StatusDetails};
        let s = Status {
            status: Some("Failure".into()),
            reason: Some("NonZeroExitCode".into()),
            details: Some(StatusDetails {
                causes: Some(vec![StatusCause {
                    reason: Some("ExitCode".into()),
                    message: Some("42".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(exit_code_from_status(&s), Some(42));
        let other = Status {
            status: Some("Failure".into()),
            reason: Some("InternalError".into()),
            ..Default::default()
        };
        assert_eq!(exit_code_from_status(&other), None);
    }

    #[test]
    fn missing_optional_status_is_clean_exit_zero() {
        let result = WorkspaceExecResult {
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
        };

        let result = classify_workspace_exec_status(None, result).expect("missing status");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"done");
    }

    #[test]
    fn explicit_success_status_is_clean_exit_zero() {
        let status = Status {
            status: Some("Success".into()),
            ..Default::default()
        };

        let result = classify_workspace_exec_status(Some(status), WorkspaceExecResult::default())
            .expect("success status");
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn nonzero_exit_status_preserves_exit_code() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{StatusCause, StatusDetails};
        let status = Status {
            status: Some("Failure".into()),
            reason: Some("NonZeroExitCode".into()),
            details: Some(StatusDetails {
                causes: Some(vec![StatusCause {
                    reason: Some("ExitCode".into()),
                    message: Some("42".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = classify_workspace_exec_status(Some(status), WorkspaceExecResult::default())
            .expect("nonzero exit status");
        assert_eq!(result.exit_code, 42);
    }

    #[test]
    fn unclassified_failure_status_remains_an_error() {
        let marker = "synthetic-secret-marker";
        let status = Status {
            status: Some("Failure".into()),
            reason: Some("InternalError".into()),
            message: Some(format!("remote failure containing {marker}")),
            ..Default::default()
        };
        let result = WorkspaceExecResult {
            stdout: marker.as_bytes().to_vec(),
            stderr: marker.as_bytes().to_vec(),
            exit_code: 0,
        };

        let error = classify_workspace_exec_status(Some(status), result)
            .expect_err("unclassified failure must stay an error");
        assert_eq!(
            error.to_string(),
            "workspace exec returned an unclassified failure status"
        );
        assert!(!format!("{error:?}").contains(marker));
    }
}
