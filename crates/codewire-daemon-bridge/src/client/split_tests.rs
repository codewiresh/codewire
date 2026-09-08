use super::*;

struct EmptyDecoder<T>(std::marker::PhantomData<T>);

impl<T> tonic::codec::Decoder for EmptyDecoder<T> {
    type Item = T;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        _source: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<T>, tonic::Status> {
        panic!("empty transport failure must not decode a message");
    }
}

fn failed_response<T: Send + 'static>() -> Streaming<T> {
    Streaming::new_response(
        EmptyDecoder(std::marker::PhantomData),
        tonic::body::Body::empty(),
        tonic::codegen::http::StatusCode::BAD_GATEWAY,
        None,
        None,
    )
}

#[tokio::test]
async fn split_receiver_keeps_transport_status_distinct_from_remote_error() {
    for inner in [
        RunOutput::Exec(failed_response()),
        RunOutput::Pty(failed_response()),
    ] {
        let mut receiver = DaemonRunReceiver { inner };
        assert!(matches!(
            receiver.next_output().await,
            Err(DaemonClientError::Status(status)) if status.code() == tonic::Code::Unavailable
        ));
    }
}

#[tokio::test]
async fn split_sender_preserves_frames_and_drop_is_not_close_stdin() {
    let (tx, mut rx) = mpsc::channel(4);
    let sender = DaemonRunSender {
        inner: RunInput::Exec(tx),
    };
    sender
        .send_input(DaemonRunInput::Stdin(vec![0, 255, b'x']))
        .await
        .unwrap();
    sender
        .send_input(DaemonRunInput::Resize {
            columns: 91,
            rows: 31,
        })
        .await
        .unwrap(); // Existing Exec resize is a no-op.
    assert_eq!(
        rx.recv().await.unwrap().payload,
        Some(v1::exec_message::Payload::Stdin(vec![0, 255, b'x']))
    );
    drop(sender);
    assert!(
        rx.recv().await.is_none(),
        "drop must not synthesize CloseStdin"
    );

    let (tx, mut rx) = mpsc::channel(4);
    let sender = DaemonRunSender {
        inner: RunInput::Pty(tx),
    };
    sender
        .send_input(DaemonRunInput::Stdin(vec![255, 0]))
        .await
        .unwrap();
    sender
        .send_input(DaemonRunInput::Resize {
            columns: 91,
            rows: 31,
        })
        .await
        .unwrap();
    sender.send_input(DaemonRunInput::CloseStdin).await.unwrap();
    assert_eq!(
        rx.recv().await.unwrap().payload,
        Some(v1::pty_message::Payload::Stdin(vec![255, 0]))
    );
    assert_eq!(
        rx.recv().await.unwrap().payload,
        Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
            width: 91,
            height: 31,
        }))
    );
    assert_eq!(
        rx.recv().await.unwrap().payload,
        Some(v1::pty_message::Payload::CloseStdin(()))
    );
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    drop(sender);
    assert!(rx.recv().await.is_none());

    for pty in [false, true] {
        let sender = if pty {
            let (tx, rx) = mpsc::channel(1);
            drop(rx);
            DaemonRunSender {
                inner: RunInput::Pty(tx),
            }
        } else {
            let (tx, rx) = mpsc::channel(1);
            drop(rx);
            DaemonRunSender {
                inner: RunInput::Exec(tx),
            }
        };
        assert!(matches!(
            sender.send_input(DaemonRunInput::Stdin(vec![0])).await,
            Err(DaemonClientError::RequestClosed)
        ));
    }
}

#[cfg(target_os = "linux")]
mod native {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;
    use crate::test_support::DaemonHarness;

    const ISOLATED: &str = "CW_TEST_SPLIT_CLIENT_JOURNEY";
    const TIMEOUT: Duration = Duration::from_secs(5);

    // The complete Native daemon journey runs in an env-cleared child, because
    // Native build_process_env deliberately copies its process environment.
    async fn enter_isolated_journey(test: &str) -> bool {
        if std::env::var_os(ISOLATED).is_some() {
            assert_eq!(std::env::var(ISOLATED).unwrap(), test);
            assert!(
                std::env::vars_os().all(|(name, _)| {
                    [ISOLATED, "HOME", "PATH", "SHELL", "TMPDIR"]
                        .iter()
                        .any(|allowed| name == std::ffi::OsStr::new(allowed))
                }),
                "isolated daemon received an unexpected environment name"
            );
            return true;
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env_clear()
            .env(ISOLATED, test)
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            // Only the checked-in gate's scratch location, never owner values.
            .env("TMPDIR", std::env::temp_dir())
            .current_dir(home.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let status = match tokio::time::timeout(TIMEOUT * 4, child.wait()).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                panic!("isolated split-client journey timed out");
            }
        };
        assert!(status.success(), "isolated split-client journey failed");
        false
    }

    fn start(harness: &DaemonHarness, pty: bool, command: Vec<String>) -> DaemonRunStart {
        DaemonRunStart {
            command,
            working_dir: harness.workspace_root().to_string_lossy().into_owned(),
            env: Vec::new(),
            allocate_tty: pty,
            term: if pty {
                "xterm-256color".into()
            } else {
                String::new()
            },
            columns: 80,
            rows: 24,
        }
    }

    #[tokio::test]
    async fn split_preserves_exec_pty_frames_half_close_and_remote_errors() {
        if !enter_isolated_journey(
            concat!(
                module_path!(),
                "::split_preserves_exec_pty_frames_half_close_and_remote_errors"
            )
            .strip_prefix("codewire_daemon_bridge::")
            .unwrap(),
        )
        .await
        {
            return;
        }
        let harness = DaemonHarness::spawn().await;
        let client = harness.client().await;
        for pty in [false, true] {
            let command = if pty {
                "read line; stty size; printf '%s:%s' \"$TERM\" \"$line\"; exit 23"
            } else {
                "read line; printf 'out:%s' \"$line\"; printf '\\377err' >&2; exit 23"
            };
            let session = client
                .start_run(start(
                    &harness,
                    pty,
                    vec!["/bin/sh".into(), "-c".into(), command.into()],
                ))
                .await
                .unwrap();
            let (sender, mut receiver) = session.into_split();
            sender
                .send_input(DaemonRunInput::Resize {
                    columns: 111,
                    rows: 37,
                })
                .await
                .unwrap();
            sender
                .send_input(DaemonRunInput::Stdin(b"split\n".to_vec()))
                .await
                .unwrap();
            sender.send_input(DaemonRunInput::CloseStdin).await.unwrap();
            // Explicit half-close followed by request EOF permits normal exit.
            drop(sender);
            let (stdout, stderr) = tokio::time::timeout(TIMEOUT, async {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut exit = None;
                while let Some(output) = receiver.next_output().await.unwrap() {
                    match output {
                        DaemonRunOutput::Stdout(data) => stdout.extend(data),
                        DaemonRunOutput::Stderr(data) => stderr.extend(data),
                        DaemonRunOutput::Exit(code) => assert_eq!(exit.replace(code), None),
                    }
                }
                assert_eq!(exit, Some(23));
                (stdout, stderr)
            })
            .await
            .unwrap();
            if pty {
                let stdout = String::from_utf8(stdout).unwrap();
                assert!(stdout.contains("37 111"));
                assert!(stdout.contains("xterm-256color:split"));
                assert!(stderr.is_empty());
            } else {
                assert_eq!(stdout, b"out:split");
                assert_eq!(stderr, b"\xfferr");
            }

            let absent = harness.workspace_root().join("absent-synthetic-command");
            let (sender, mut receiver) = client
                .start_run(start(
                    &harness,
                    pty,
                    vec![absent.to_string_lossy().into_owned()],
                ))
                .await
                .unwrap()
                .into_split();
            tokio::time::timeout(TIMEOUT, async {
                // Remote is a frame, not Status or terminal EOF. Keep receiving.
                assert!(matches!(
                    receiver.next_output().await,
                    Err(DaemonClientError::Remote(_))
                ));
                drop(sender);
                assert_eq!(
                    receiver.next_output().await.unwrap(),
                    Some(DaemonRunOutput::Exit(1))
                );
                assert_eq!(receiver.next_output().await.unwrap(), None);
            })
            .await
            .unwrap();
        }
        drop(client);
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn split_input_drop_retains_exit_and_eof_after_exact_child_reaping() {
        if !enter_isolated_journey(
            concat!(
                module_path!(),
                "::split_input_drop_retains_exit_and_eof_after_exact_child_reaping"
            )
            .strip_prefix("codewire_daemon_bridge::")
            .unwrap(),
        )
        .await
        {
            return;
        }
        let harness = DaemonHarness::spawn().await;
        let client = harness.client().await;
        for pty in [false, true] {
            let (sender, mut receiver) = client
                .start_run(start(
                    &harness,
                    pty,
                    vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf '%s\\n' $$; exec /bin/sleep 30".into(),
                    ],
                ))
                .await
                .unwrap()
                .into_split();
            // Exact child output synchronizes cancellation with actual execution.
            let pid = tokio::time::timeout(TIMEOUT, async {
                let mut stdout = Vec::new();
                loop {
                    match receiver.next_output().await.unwrap() {
                        Some(DaemonRunOutput::Stdout(data)) => {
                            stdout.extend(data);
                            if stdout.contains(&b'\n') {
                                break String::from_utf8(stdout)
                                    .unwrap()
                                    .trim()
                                    .parse::<u32>()
                                    .unwrap();
                            }
                        }
                        _ => panic!("child ended before synchronized process identity"),
                    }
                }
            })
            .await
            .unwrap();
            let process = PathBuf::from(format!("/proc/{pid}"));
            assert!(process.exists());
            drop(sender); // No CloseStdin: cancellation, with response retained.
            tokio::time::timeout(TIMEOUT, async {
                // PTY line-discipline CR/LF bytes may arrive after the PID's
                // first newline; output chunk boundaries are not frame barriers.
                let mut trailing_bytes = 0;
                loop {
                    match receiver.next_output().await.unwrap() {
                        Some(DaemonRunOutput::Stdout(bytes)) if pty => {
                            trailing_bytes += bytes.len();
                            assert!(trailing_bytes <= 16);
                            assert!(bytes.iter().all(|byte| matches!(byte, b'\r' | b'\n')));
                        }
                        Some(DaemonRunOutput::Exit(code)) => {
                            assert_ne!(code, 0);
                            break;
                        }
                        terminal => panic!("pty={pty}, expected cancelled exit, got {terminal:?}"),
                    }
                }
                assert!(!process.exists(), "exit preceded exact child reaping");
                assert_eq!(receiver.next_output().await.unwrap(), None);
            })
            .await
            .unwrap();
        }
        drop(client);
        harness.shutdown().await;
    }
}
