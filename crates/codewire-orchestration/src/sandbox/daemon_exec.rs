//! A `standard` workspace's commands (#5602; `standard-exec` in
//! `docs/journeys/standard-runtime.md`). Its `workspace` container is the
//! runtime's, outside the VM, so a command goes to the guest daemon's
//! `ExecSession` over the exact Pod's daemon port with the Pod-scoped daemon
//! credential, as `api/cw_runtime/execute.rs` does. Completion is as strict as
//! `cw __hosted-exec`: only an exit in 0..=255 followed by a clean end of the
//! stream is a result, and anything else is an error that has setup recycle
//! the Pod. Nothing the command carries (its environment, its output, the
//! credential, the daemon's own error text) enters an error or a log.

use std::collections::BTreeMap;
use std::sync::Arc;

use codewire_daemon_bridge::client::{
    DaemonClient, DaemonClientError, DaemonRunInput, DaemonRunOutput, DaemonRunReceiver,
    DaemonRunSender, DaemonRunStart,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use zeroize::Zeroizing;

use super::client::SandboxClient;
use super::exec::{
    StderrTap, WORKSPACE_EXEC_CAPTURE_BYTES, WorkspaceExecHandle, WorkspaceExecResult,
};
use super::sidecar::PortForwardedStream;
use super::template::RUNTIME_CLASS_STANDARD;

const WORKSPACE_DAEMON_PORT: u16 = super::template::WORKSPACE_DAEMON_PORT as u16;

/// The Pod-scoped daemon credential setup presents to a `standard`
/// workspace's daemon. It is never printed.
pub struct WorkspaceExecCredential(Zeroizing<String>);

impl WorkspaceExecCredential {
    pub fn new(credential: String) -> Self {
        Self(Zeroizing::new(credential))
    }
}

impl std::fmt::Debug for WorkspaceExecCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkspaceExecCredential(..)")
    }
}

/// A started command on the guest daemon.
pub(crate) struct DaemonExec {
    /// Held until the exit is read: the daemon ends a command whose request
    /// stream closes first, so a dropped handle never leaves it running
    /// unseen. The daemon ends its response only after this closes.
    input: DaemonRunSender,
    output: DaemonRunReceiver,
}

/// The output frames of one command, so completion is tested without a daemon.
pub(crate) trait RunOutputs {
    async fn next(&mut self) -> Result<Option<DaemonRunOutput>, DaemonClientError>;
}

impl RunOutputs for DaemonRunReceiver {
    async fn next(&mut self) -> Result<Option<DaemonRunOutput>, DaemonClientError> {
        self.next_output().await
    }
}

impl SandboxClient {
    /// Whether the Pod named `pod_name` is of the `standard` class.
    pub(crate) async fn is_standard_pod(&self, pod_name: &str) -> anyhow::Result<bool> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let pod = pods
            .get(pod_name)
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec: get Pod {pod_name}: {error}"))?;
        Ok(pod
            .spec
            .and_then(|spec| spec.runtime_class_name)
            .is_some_and(|class| class == RUNTIME_CLASS_STANDARD))
    }

    /// Starts `command` on the daemon of the Pod named `pod_name`, without
    /// waiting for it to exit. Once this returns, it may already be running.
    pub(crate) async fn start_daemon_exec_on_pod(
        &self,
        pod_name: &str,
        credential: &WorkspaceExecCredential,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<WorkspaceExecHandle> {
        if command.is_empty() {
            anyhow::bail!("workspace exec: command is required");
        }
        let stream = self
            .port_forward_pod_stream(pod_name, WORKSPACE_DAEMON_PORT)
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec: {error}"))?;
        let client = DaemonClient::from_channel(channel_over(stream).await?, &*credential.0)
            .map_err(|error| anyhow::anyhow!("workspace exec: {}", described(&error)))?;
        let session = client
            .start_run(DaemonRunStart {
                command: command.to_vec(),
                working_dir: work_dir.to_owned(),
                env: env
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
                allocate_tty: false,
                term: String::new(),
                columns: 0,
                rows: 0,
            })
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec: {}", described(&error)))?;
        let (input, output) = session.into_split();
        input
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .map_err(|error| anyhow::anyhow!("workspace exec: {}", described(&error)))?;
        Ok(WorkspaceExecHandle::daemon(DaemonExec { input, output }))
    }
}

impl DaemonExec {
    pub(crate) async fn wait(self, tap: Option<&StderrTap>) -> anyhow::Result<WorkspaceExecResult> {
        let Self { input, mut output } = self;
        complete(&mut output, input, tap).await
    }
}

/// Reads one command to its end. The frames' bytes are kept to their first
/// [`WORKSPACE_EXEC_CAPTURE_BYTES`], and every stderr frame goes to `tap`.
/// `input`, the command's request stream, is held until the exit and closed
/// before the clean end is awaited: `CloseStdin` is only a half-close, and the
/// daemon ends its response once the request stream ends.
pub(crate) async fn complete<I>(
    output: &mut impl RunOutputs,
    input: I,
    tap: Option<&StderrTap>,
) -> anyhow::Result<WorkspaceExecResult> {
    let mut stdout = Zeroizing::new(Vec::new());
    let mut stderr = Zeroizing::new(Vec::new());
    let code = loop {
        match output.next().await {
            Ok(Some(DaemonRunOutput::Stdout(bytes))) => retain(&mut stdout, &bytes),
            Ok(Some(DaemonRunOutput::Stderr(bytes))) => {
                if let Some(tap) = tap {
                    // Best effort: a full receiver drops the chunk.
                    let _ = tap.try_send(Zeroizing::new(bytes.clone()));
                }
                retain(&mut stderr, &bytes);
            }
            Ok(Some(DaemonRunOutput::Exit(code))) => break code,
            Ok(None) => anyhow::bail!("workspace exec returned no terminal status"),
            Err(error) => anyhow::bail!("workspace exec completion: {}", described(&error)),
        }
    };
    drop(input);
    match output.next().await {
        Ok(None) => {}
        Ok(Some(_)) => anyhow::bail!("workspace exec completion: a frame followed the exit"),
        Err(error) => anyhow::bail!("workspace exec completion: {}", described(&error)),
    }
    // A child's own 125 is indistinguishable from the helper's ambiguous
    // completion, so it is treated as one, as on the other profiles.
    if code == codewire_daemon_proto::HOSTED_EXEC_AMBIGUOUS_EXIT_CODE {
        anyhow::bail!("workspace exec daemon completion is ambiguous");
    }
    if !(0..=255).contains(&code) {
        anyhow::bail!("workspace exec returned an unclassified failure status");
    }
    Ok(WorkspaceExecResult {
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        exit_code: code,
    })
}

fn retain(kept: &mut Vec<u8>, bytes: &[u8]) {
    let room = WORKSPACE_EXEC_CAPTURE_BYTES.saturating_sub(kept.len());
    kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// What an error says without anything the daemon sent: its status code at
/// most, never its message, which can echo the command.
fn described(error: &DaemonClientError) -> String {
    match error {
        DaemonClientError::Status(status) => format!("daemon RPC status {:?}", status.code()),
        DaemonClientError::Remote(_) => "the daemon reported a failure".into(),
        DaemonClientError::NotReady { state, .. } => format!("the daemon is not ready ({state:?})"),
        other => other.to_string(),
    }
}

/// A tonic channel over the one stream to the Pod's daemon port.
async fn channel_over(stream: PortForwardedStream) -> anyhow::Result<Channel> {
    let stream = Arc::new(Mutex::new(Some(stream)));
    let connector = service_fn(move |_| {
        let stream = Arc::clone(&stream);
        async move {
            stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "daemon stream already consumed",
                )
            })
        }
    });
    Endpoint::from_static("http://hosted-daemon.internal")
        .executor(codewire_server_core::span_free::DetachedExecutor)
        .connect_with_connector(connector)
        .await
        .map_err(|_| anyhow::anyhow!("workspace exec: connect to the daemon failed"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// Stands in for every secret-bearing thing a command carries: none of it
    /// may reach an error.
    const MARKER: &str = "s3cr3t-marker";

    /// The scripted frames, then the end of the stream. With `closed`, the
    /// end comes only once the request stream is closed, as from the daemon.
    struct Frames {
        frames: VecDeque<Result<Option<DaemonRunOutput>, DaemonClientError>>,
        closed: Option<Arc<std::sync::atomic::AtomicBool>>,
    }

    impl RunOutputs for Frames {
        async fn next(&mut self) -> Result<Option<DaemonRunOutput>, DaemonClientError> {
            if let Some(frame) = self.frames.pop_front() {
                return frame;
            }
            if let Some(closed) = &self.closed
                && !closed.load(std::sync::atomic::Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            Ok(None)
        }
    }

    fn frames(frames: Vec<Result<Option<DaemonRunOutput>, DaemonClientError>>) -> Frames {
        Frames {
            frames: frames.into(),
            closed: None,
        }
    }

    /// A request stream that records when it is closed.
    struct Input(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Input {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn output(text: &str) -> Vec<Result<Option<DaemonRunOutput>, DaemonClientError>> {
        vec![
            Ok(Some(DaemonRunOutput::Stdout(text.as_bytes().to_vec()))),
            Ok(Some(DaemonRunOutput::Stderr(text.as_bytes().to_vec()))),
        ]
    }

    async fn run(
        list: Vec<Result<Option<DaemonRunOutput>, DaemonClientError>>,
    ) -> anyhow::Result<WorkspaceExecResult> {
        complete(&mut frames(list), (), None).await
    }

    fn exited(code: i32) -> Vec<Result<Option<DaemonRunOutput>, DaemonClientError>> {
        let mut list = output("out");
        list.push(Ok(Some(DaemonRunOutput::Exit(code))));
        list
    }

    #[tokio::test]
    async fn an_exit_then_a_clean_end_is_the_commands_result() {
        for code in [0, 3, 255] {
            let result = run(exited(code)).await.unwrap();
            assert_eq!(result.exit_code, code);
            assert_eq!(result.stdout, b"out");
            assert_eq!(result.stderr, b"out");
        }
    }

    #[tokio::test]
    async fn anything_but_a_certain_exit_is_an_error_setup_recovers_from() {
        let mut after_exit = exited(0);
        after_exit.push(Ok(Some(DaemonRunOutput::Stdout(b"late".to_vec()))));
        let mut error_after_exit = exited(0);
        error_after_exit.push(Err(DaemonClientError::Status(tonic::Status::unavailable(
            "gone",
        ))));
        for (case, list, says) in [
            ("ambiguous 125", exited(125), "ambiguous"),
            ("negative exit", exited(-1), "unclassified"),
            ("exit past 255", exited(256), "unclassified"),
            ("no exit", output("out"), "no terminal status"),
            (
                "a frame after the exit",
                after_exit,
                "a frame followed the exit",
            ),
            ("an error after the exit", error_after_exit, "Unavailable"),
            (
                "an error frame",
                vec![Err(DaemonClientError::Remote("failed".into()))],
                "the daemon reported a failure",
            ),
        ] {
            let error = run(list).await.unwrap_err().to_string();
            assert!(error.contains(says), "{case}: {error}");
        }
    }

    #[tokio::test]
    async fn no_error_carries_the_commands_output_or_the_daemons_text() {
        let mut errors = vec![
            DaemonClientError::Remote(MARKER.into()),
            DaemonClientError::Status(tonic::Status::internal(MARKER)),
            DaemonClientError::NotReady {
                state: codewire_daemon_proto::daemon::v1::DaemonState::Unspecified,
                message: MARKER.into(),
            },
        ];
        while let Some(error) = errors.pop() {
            let mut list = output(MARKER);
            list.push(Err(error));
            let text = format!("{:#}", run(list).await.unwrap_err());
            assert!(!text.contains(MARKER), "{text}");
        }
        let mut late = output(MARKER);
        late.push(Ok(Some(DaemonRunOutput::Exit(0))));
        late.push(Ok(Some(DaemonRunOutput::Stdout(
            MARKER.as_bytes().to_vec(),
        ))));
        let text = format!("{:#}", run(late).await.unwrap_err());
        assert!(!text.contains(MARKER), "{text}");
    }

    #[test]
    fn the_credential_is_never_printed() {
        let credential = WorkspaceExecCredential::new(MARKER.into());
        assert!(!format!("{credential:?}").contains(MARKER));
    }

    #[tokio::test]
    async fn output_is_kept_to_its_limit_and_all_of_stderr_is_tapped() {
        let chunk = vec![b'x'; WORKSPACE_EXEC_CAPTURE_BYTES];
        let mut list = Vec::new();
        for _ in 0..2 {
            list.push(Ok(Some(DaemonRunOutput::Stdout(chunk.clone()))));
            list.push(Ok(Some(DaemonRunOutput::Stderr(chunk.clone()))));
        }
        list.push(Ok(Some(DaemonRunOutput::Exit(0))));
        let (tap, mut tapped) = tokio::sync::mpsc::channel(8);
        let result = complete(&mut frames(list), (), Some(&tap)).await.unwrap();
        assert_eq!(result.stdout.len(), WORKSPACE_EXEC_CAPTURE_BYTES);
        assert_eq!(result.stderr.len(), WORKSPACE_EXEC_CAPTURE_BYTES);
        drop(tap);
        let mut total = 0;
        while let Some(bytes) = tapped.recv().await {
            total += bytes.len();
        }
        assert_eq!(total, 2 * WORKSPACE_EXEC_CAPTURE_BYTES);
    }

    #[tokio::test]
    async fn the_request_stream_closes_at_the_exit_so_the_daemon_ends_its_response() {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut daemon = Frames {
            frames: exited(0).into(),
            closed: Some(closed.clone()),
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            complete(&mut daemon, Input(closed.clone()), None),
        )
        .await
        .expect("completion waited on a request stream it still held")
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_request_stream_is_held_until_the_exit() {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut daemon = Frames {
            frames: output("out").into(),
            closed: Some(closed.clone()),
        };
        // No exit yet: completion waits, and the command's request stream
        // stays open, so the daemon does not end the command.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                complete(&mut daemon, Input(closed.clone()), None),
            )
            .await
            .is_err()
        );
    }
}
