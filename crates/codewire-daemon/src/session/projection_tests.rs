use std::future::pending;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::{
    CredentialBridgeConfig, CredentialBridgeTransport, DaemonAuthToken, LaunchProjectionConfig,
    NativeLaunchProjectionConfig,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_TEST: &str = "session::projection_tests::synthetic_pending_pty_launcher";
const JOURNEY_TEST: &str = "session::projection_tests::eof_during_actual_pending_projection_reaps_launcher_before_terminal_exit";
const ISOLATED_JOURNEY: &str = "CW_TEST_PTY_ISOLATED_JOURNEY";

async fn isolated_journey() {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", JOURNEY_TEST, "--nocapture"])
        .env_clear()
        .env(ISOLATED_JOURNEY, "1")
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        // Keep the checked-in gate's executable scratch location. This is
        // location metadata only, not a copy of the owner's environment.
        .env("TMPDIR", std::env::temp_dir())
        .current_dir(home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = match tokio::time::timeout(TIMEOUT * 3, child.wait()).await {
        Ok(status) => status.unwrap(),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            panic!("isolated PTY projection journey timed out");
        }
    };
    assert!(status.success(), "isolated PTY projection journey failed");
}

fn frame(payload: v1::pty_message::Payload) -> Result<v1::PtyMessage, Status> {
    Ok(v1::PtyMessage {
        payload: Some(payload),
    })
}

// Unlike tokio_stream::iter (which yields Pending after 32 items in the pinned
// release), this finite fixture makes every queued frame immediately visible.
// Only that condition promises input priority before projection is polled.
struct ReadyFrames(std::vec::IntoIter<Result<v1::PtyMessage, Status>>);

impl Stream for ReadyFrames {
    type Item = Result<v1::PtyMessage, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.0.next())
    }
}

#[test]
fn synthetic_pending_pty_launcher() {
    let Some(socket) = std::env::var_os("CW_TEST_PTY_LAUNCH_SOCKET") else {
        return;
    };
    let channel =
        codewire_workload_secrets::launcher::connect_to_parent(Path::new(&socket)).unwrap();
    let mut phase =
        std::os::unix::net::UnixStream::connect(std::env::var_os("CW_TEST_PTY_PHASE").unwrap())
            .unwrap();
    // The real final-launcher channel is connected. Report this process's
    // identity over a separate synthetic synchronization socket, not a sleep.
    phase.write_all(b"P").unwrap();
    let command = [
        "/bin/sh".into(),
        "-c".into(),
        "printf launched > \"$CW_TEST_PTY_MARKER\"".into(),
    ];
    let _ = codewire_workload_secrets::launcher::exec_from_channel(channel, &command);
    std::process::exit(71);
}

struct SessionTask(tokio::task::JoinHandle<()>);
impl Drop for SessionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn eof_during_actual_pending_projection_reaps_launcher_before_terminal_exit() {
    if std::env::var_os(ISOLATED_JOURNEY).is_none() {
        isolated_journey().await;
        return;
    }
    // Native build_process_env intentionally inherits its process environment.
    // Run that production path only after the complete test journey was moved
    // into an env-cleared child, not after filtering selected credential names.
    assert_eq!(std::env::var(ISOLATED_JOURNEY).unwrap(), "1");
    assert!(
        std::env::vars_os().all(|(name, _)| {
            [ISOLATED_JOURNEY, "HOME", "PATH", "SHELL", "TMPDIR"]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed))
        }),
        "isolated test daemon received an unexpected environment name"
    );
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let process_directory = temp.path().join("processes");
    std::fs::create_dir(&process_directory).unwrap();
    std::fs::set_permissions(&process_directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let phase = temp.path().join("phase.sock");
    let listener = tokio::net::UnixListener::bind(&phase).unwrap();
    std::fs::set_permissions(&phase, std::fs::Permissions::from_mode(0o600)).unwrap();
    let marker = temp.path().join("target-ran");
    let helper = temp.path().join("synthetic-cw");
    // This test-only installed helper enters the checked-in launcher receiver
    // in this same test binary; it does not read any ambient credential path.
    std::fs::write(&helper, b"#!/bin/sh\nexport CW_TEST_PTY_LAUNCH_SOCKET=\"$3\"\nexec \"$CW_TEST_PTY_BINARY\" --exact \"$CW_TEST_PTY_CASE\" --nocapture\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = Config {
        listen_addr: "unused:0".into(),
        workspace_root: temp.path().into(),
        home_root: temp.path().into(),
        auth_token: DaemonAuthToken::new("synthetic-pty-daemon-token").unwrap(),
        process_execution: ProcessExecution::Native,
        credential_bridge: Some(CredentialBridgeConfig {
            // With no host admitted, this real launcher waits on the original
            // projection deadline instead of accessing protected material.
            transport: CredentialBridgeTransport::Hosted,
            environment_id: uuid::Uuid::new_v4(),
            environment_generation: 7,
            ingress_socket: temp.path().join("unused-provider.sock"),
            ingress_uid: unsafe { libc::geteuid() },
            ingress_gid: unsafe { libc::getegid() },
        }),
        managed_credential_clients: Default::default(),
        launch_projection: Some(LaunchProjectionConfig {
            selection_sha256: [1; 32],
            native: Some(NativeLaunchProjectionConfig {
                helper_path: helper,
                process_directory: process_directory.clone(),
            }),
        }),
    };
    let bridge = CredentialBridge::new(config.credential_bridge.clone());
    let (input, input_rx) = mpsc::channel(4);
    let (output, mut output_rx) = mpsc::channel(4);
    let start = v1::PtyStartRequest {
        command: vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf launched > \"$CW_TEST_PTY_MARKER\"".into(),
        ],
        working_dir: temp.path().to_string_lossy().into_owned(),
        env: vec![
            format!(
                "CW_TEST_PTY_BINARY={}",
                std::env::current_exe().unwrap().display()
            ),
            format!("CW_TEST_PTY_CASE={CHILD_TEST}"),
            format!("CW_TEST_PTY_PHASE={}", phase.display()),
            format!("CW_TEST_PTY_MARKER={}", marker.display()),
        ],
        term: "xterm-256color".into(),
        width: 80,
        height: 24,
    };
    let mut worker = SessionTask(tokio::spawn(run_pty_session(
        config,
        bridge,
        ReceiverStream::new(input_rx),
        start,
        output,
    )));
    let (mut peer, _) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let pid = peer.peer_cred().unwrap().pid().unwrap();
    let mut phase_byte = [0];
    peer.read_exact(&mut phase_byte).await.unwrap();
    assert_eq!(phase_byte, *b"P");
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    assert!(process.exists());
    assert!(matches!(
        output_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    drop(input); // Deliberately NOT CloseStdin; retain the complete response.
    let error = tokio::time::timeout(TIMEOUT, output_rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        error.payload,
        Some(v1::pty_message::Payload::Error(_))
    ));
    assert!(
        !process.exists(),
        "launcher still exists at terminal error acknowledgement"
    );
    let exit = output_rx.recv().await.unwrap().unwrap();
    assert!(matches!(
        exit.payload,
        Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code: 1 }))
    ));
    tokio::time::timeout(TIMEOUT, &mut worker.0)
        .await
        .unwrap()
        .unwrap();
    assert!(output_rx.recv().await.is_none());
    assert!(
        !marker.exists(),
        "target command ran despite pending projection cancellation"
    );
    assert_eq!(std::fs::read_dir(process_directory).unwrap().count(), 0);
}

#[tokio::test]
async fn explicit_half_close_preserves_prelaunch_input_resize_and_normal_completion() {
    use v1::pty_message::Payload;
    let mut stream = tokio_stream::iter([
        frame(Payload::Stdin(vec![0, 255, b'x'])),
        frame(Payload::Resize(v1::ResizeRequest {
            width: 120,
            height: 32,
        })),
        frame(Payload::CloseStdin(())),
    ]);
    let (output, _rx) = mpsc::channel(4);
    let prelaunch = await_pty_projection(async { Ok(()) }, &mut stream, &output)
        .await
        .unwrap();
    assert!(prelaunch.stdin_closed && prelaunch.stream_ended);
    assert_eq!(prelaunch.bytes, 3);
    let (control, controls) = std_mpsc::channel();
    let (disconnected, disconnect) = oneshot::channel();
    forward_pty_control(stream, control, disconnected, prelaunch).await;
    assert!(!disconnect.await.unwrap(), "half-close became cancellation");
    let controls: Vec<_> = controls.into_iter().collect();
    assert!(
        matches!(controls.as_slice(), [PtyControl::Stdin(data), PtyControl::Resize { width: 120, height: 32 }, PtyControl::CloseStdin, PtyControl::CloseStdin] if data == &[0, 255, b'x'])
    );
}

#[tokio::test]
async fn half_close_keeps_original_projection_deadline_and_transport_failure_still_cancels() {
    use v1::pty_message::Payload;
    let (output, _rx) = mpsc::channel(4);
    let mut stream = tokio_stream::iter([frame(Payload::CloseStdin(()))]);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let projection = async {
        tokio::time::sleep_until(deadline).await;
        Err(io::Error::from(io::ErrorKind::TimedOut))
    };
    let result = tokio::time::timeout(
        TIMEOUT,
        await_pty_projection(projection, &mut stream, &output),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    let mut stream = tokio_stream::iter([
        frame(Payload::CloseStdin(())),
        Err(Status::cancelled("synthetic transport loss")),
    ]);
    assert!(
        await_pty_projection(pending(), &mut stream, &output)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prelaunch_control_and_byte_bounds_fail_closed_without_polling_projection() {
    use v1::pty_message::Payload;
    let (output, _rx) = mpsc::channel(4);
    for messages in [
        vec![frame(Payload::Stdin(vec![
            0;
            MAX_PRELAUNCH_PTY_INPUT_BYTES + 1
        ]))],
        (0..=MAX_PRELAUNCH_PTY_CONTROLS)
            .map(|_| {
                frame(Payload::Resize(v1::ResizeRequest {
                    width: 80,
                    height: 24,
                }))
            })
            .collect(),
    ] {
        let mut stream = ReadyFrames(messages.clone().into_iter());
        let polled = AtomicBool::new(false);
        let projection = std::future::poll_fn(|_| {
            polled.store(true, Ordering::SeqCst);
            std::task::Poll::<io::Result<()>>::Pending
        });
        assert!(
            await_pty_projection(projection, &mut stream, &output)
                .await
                .is_err()
        );
        assert!(!polled.load(Ordering::SeqCst));

        // A temporarily Pending input permits projection progress, but never
        // permits the prelaunch queue to exceed either cap when input resumes.
        // Preserve the real cooperative iterator as an independent vector.
        let mut stream = tokio_stream::iter(messages);
        assert!(
            await_pty_projection(pending(), &mut stream, &output)
                .await
                .is_err()
        );
    }
    let mut boundary = PrelaunchPtyInput::default();
    boundary
        .queue(frame(Payload::Stdin(vec![0; MAX_PRELAUNCH_PTY_INPUT_BYTES])).unwrap())
        .unwrap();
    for _ in 1..MAX_PRELAUNCH_PTY_CONTROLS {
        boundary
            .queue(
                frame(Payload::Resize(v1::ResizeRequest {
                    width: 80,
                    height: 24,
                }))
                .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(boundary.controls.len(), MAX_PRELAUNCH_PTY_CONTROLS);
    assert!(
        boundary
            .queue(frame(Payload::Stdin(vec![1])).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn response_drop_cancels_pending_projection_without_a_remote_ack_claim() {
    let (output, rx) = mpsc::channel(4);
    drop(rx);
    let mut stream = tokio_stream::pending();
    assert!(
        await_pty_projection(pending(), &mut stream, &output)
            .await
            .is_err()
    );
}

#[derive(Debug)]
struct GatedChild {
    reaped: Arc<AtomicBool>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    waiting: Option<oneshot::Sender<()>>,
    fail: bool,
}

#[tokio::test]
async fn running_pty_wait_errors_never_become_exit_acknowledgements() {
    for code in [0, 1, 23, 255] {
        assert!(matches!(
            pty_wait_result(Ok(Ok(code))).unwrap().payload,
            Some(v1::pty_message::Payload::Exit(exit)) if exit.code == code
        ));
    }
    let failed = pty_wait_result(Ok(Err(io::Error::other("synthetic wait failure"))));
    assert_eq!(failed.unwrap_err().code(), tonic::Code::Unavailable);
    let panicked = tokio::spawn(async {
        panic!("synthetic child waiter panic");
        #[allow(unreachable_code)]
        Ok(0)
    })
    .await;
    assert_eq!(
        pty_wait_result(panicked).unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[test]
fn running_exec_wait_errors_never_become_exit_acknowledgements() {
    use std::os::unix::process::ExitStatusExt as _;

    for code in [0, 1, 23, 255] {
        let status = std::process::ExitStatus::from_raw(code << 8);
        assert!(matches!(
            exec_wait_result(Ok(status)).unwrap().payload,
            Some(v1::exec_message::Payload::Exit(exit)) if exit.code == code
        ));
    }
    let status =
        exec_wait_result(Err(io::Error::other("synthetic-private-wait-detail"))).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert_eq!(
        status.message(),
        "environment process cleanup was not confirmed"
    );
}

#[tokio::test]
async fn cancelled_exec_launch_only_acknowledges_confirmed_reap() {
    use std::os::unix::process::ExitStatusExt as _;

    for failed in [false, true] {
        let (output, mut responses) = mpsc::channel(4);
        let result = if failed {
            Err(io::Error::other("synthetic-private-wait-detail"))
        } else {
            Ok(std::process::ExitStatus::from_raw(1 << 8))
        };
        finish_cancelled_exec_launch(result, &output).await;
        drop(output);
        if failed {
            let status = responses.recv().await.unwrap().unwrap_err();
            assert_eq!(status.code(), tonic::Code::Unavailable);
            assert_eq!(
                status.message(),
                "environment launcher cleanup was not confirmed"
            );
        } else {
            assert!(matches!(
                responses.recv().await.unwrap().unwrap().payload,
                Some(v1::exec_message::Payload::Error(_))
            ));
            assert!(matches!(
                responses.recv().await.unwrap().unwrap().payload,
                Some(v1::exec_message::Payload::Exit(exit)) if exit.code == 1
            ));
        }
        assert!(
            responses.recv().await.is_none(),
            "unexpected extra acknowledgement"
        );
    }
}

impl portable_pty::ChildKiller for GatedChild {
    fn kill(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        panic!("not used by launch cleanup")
    }
}
impl portable_pty::Child for GatedChild {
    fn try_wait(&mut self) -> io::Result<Option<portable_pty::ExitStatus>> {
        Ok(None)
    }
    fn process_id(&self) -> Option<u32> {
        None
    }
    fn wait(&mut self) -> io::Result<portable_pty::ExitStatus> {
        self.waiting.take().unwrap().send(()).unwrap();
        let (lock, signal) = &*self.release;
        let mut ready = lock.lock().unwrap();
        while !*ready {
            ready = signal.wait(ready).unwrap();
        }
        if self.fail {
            return Err(io::Error::other("synthetic wait failure"));
        }
        self.reaped.store(true, Ordering::SeqCst);
        Ok(portable_pty::ExitStatus::with_exit_code(1))
    }
}

struct ReleaseWait(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
impl Drop for ReleaseWait {
    fn drop(&mut self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}

#[tokio::test]
async fn terminal_ack_waits_for_reap_and_failed_reap_has_no_exit_ack() {
    for fail in [false, true] {
        let release = ReleaseWait(Arc::new((
            std::sync::Mutex::new(false),
            std::sync::Condvar::new(),
        )));
        let reaped = Arc::new(AtomicBool::new(false));
        let (waiting, wait_started) = oneshot::channel();
        let child = crate::execution::PtyLaunchGuard::new(Box::new(GatedChild {
            reaped: reaped.clone(),
            release: release.0.clone(),
            waiting: Some(waiting),
            fail,
        }));
        let (output, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            finish_cancelled_pty_launch(child, &output).await;
        });
        tokio::time::timeout(TIMEOUT, wait_started)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(release);
        tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap();
        if fail {
            assert_eq!(
                rx.recv().await.unwrap().unwrap_err().code(),
                tonic::Code::Unavailable
            );
            assert!(!reaped.load(Ordering::SeqCst));
        } else {
            assert!(reaped.load(Ordering::SeqCst));
            assert!(matches!(
                rx.recv().await.unwrap().unwrap().payload,
                Some(v1::pty_message::Payload::Error(_))
            ));
            assert!(matches!(
                rx.recv().await.unwrap().unwrap().payload,
                Some(v1::pty_message::Payload::Exit(_))
            ));
        }
        assert!(rx.recv().await.is_none());
    }
}
