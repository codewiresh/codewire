use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future as _;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use super::*;
use v1::exec_message::Payload;

#[test]
fn hosted_exec_parser_preserves_only_explicit_argv_and_environment() {
    let request = parse_request([
        "cw",
        "__hosted-exec",
        "--work-dir",
        "/workspace/a b",
        "--env",
        "VALUE=one=two",
        "--env",
        "EMPTY=",
        "--env",
        "LINES=first\nsecond",
        "--",
        "/bin/sh",
        "-lc",
        "printf '%s' '$literal'",
        "",
        "--env=child-argument",
    ])
    .unwrap();
    assert_eq!(request.working_dir, "/workspace/a b");
    assert_eq!(
        request.env,
        ["VALUE=one=two", "EMPTY=", "LINES=first\nsecond"]
    );
    assert_eq!(
        request.command,
        [
            "/bin/sh",
            "-lc",
            "printf '%s' '$literal'",
            "",
            "--env=child-argument"
        ]
    );
}

#[test]
fn hosted_exec_omitted_work_dir_and_environment_use_daemon_defaults() {
    let request = parse_request(["/codewire/bin/cw", "__hosted-exec", "--", "true"]).unwrap();
    assert!(request.working_dir.is_empty());
    assert!(request.env.is_empty());
    assert_eq!(request.command, ["true"]);
}

#[test]
fn hosted_exec_parser_has_no_endpoint_token_config_or_help_path() {
    for arguments in [
        vec!["cw"],
        vec!["cw", "__hosted-exec"],
        vec!["cw", "__hosted-exec", "--"],
        vec!["cw", "__hosted-exec", "true"],
        vec!["cw", "__hosted-exec", "--help"],
        vec!["cw", "__hosted-exec", "--version"],
        vec!["cw", "help", "__hosted-exec"],
        vec![
            "cw",
            "--server",
            "http://other",
            "__hosted-exec",
            "--",
            "true",
        ],
        vec![
            "cw",
            "__hosted-exec",
            "--endpoint",
            "http://other",
            "--",
            "true",
        ],
        vec![
            "cw",
            "__hosted-exec",
            "--token",
            "synthetic-marker",
            "--",
            "true",
        ],
        vec![
            "cw",
            "__hosted-exec",
            "--server",
            "http://other",
            "--",
            "true",
        ],
        vec!["cw", "__hosted-exec", "--config", "/other", "--", "true"],
        vec!["cw", "__hosted-exec", "--work-dir", "", "--", "true"],
        vec!["cw", "__hosted-exec", "--", ""],
        vec!["cw", "__hosted-exec", "--", "contains\0nul"],
        vec![
            "cw",
            "__hosted-exec",
            "--work-dir",
            "/bad\0path",
            "--",
            "true",
        ],
    ] {
        assert_eq!(parse_request(arguments).unwrap_err(), HostedExecFailure);
    }
}

#[test]
fn hosted_exec_parser_rejects_malformed_duplicate_and_capability_overrides() {
    for environment in [
        "MISSING_EQUALS",
        "=empty-name",
        "1INVALID=value",
        "INVALID-KEY=value",
        "VALUE=contains\0nul",
        "CODEWIRE_DAEMON_AUTH_TOKEN=synthetic-marker",
    ] {
        assert_eq!(
            parse_request(["cw", "__hosted-exec", "--env", environment, "--", "true"]).unwrap_err(),
            HostedExecFailure
        );
    }
    assert_eq!(
        parse_request([
            "cw",
            "__hosted-exec",
            "--env",
            "VALUE=first",
            "--env",
            "VALUE=second",
            "--",
            "true"
        ])
        .unwrap_err(),
        HostedExecFailure
    );
}

#[test]
fn hosted_exec_parser_bounds_request_size_and_collection_counts() {
    let huge = "x".repeat(MAX_INPUT_BYTES);
    assert_eq!(
        parse_request(["cw", "__hosted-exec", "--", &huge]).unwrap_err(),
        HostedExecFailure
    );

    let mut arguments = vec!["cw", "__hosted-exec", "--"];
    arguments.extend(std::iter::repeat_n("x", MAX_COMMAND_ARGUMENTS));
    assert!(parse_request(arguments.clone()).is_ok());
    arguments.push("too-many");
    assert_eq!(parse_request(arguments).unwrap_err(), HostedExecFailure);

    let mut arguments = vec!["cw".to_owned(), "__hosted-exec".to_owned()];
    for index in 0..codewire_project::MAX_ENVIRONMENT_VALUES {
        arguments.extend(["--env".into(), format!("KEY_{index}=ordinary")]);
    }
    let mut maximum = arguments.clone();
    maximum.extend(["--".into(), "true".into()]);
    assert!(parse_request(maximum).is_ok());
    arguments.extend([
        "--env".into(),
        "EXTRA=value".into(),
        "--".into(),
        "true".into(),
    ]);
    assert_eq!(parse_request(arguments).unwrap_err(), HostedExecFailure);
}

#[cfg(unix)]
#[test]
fn hosted_exec_parser_rejects_non_utf8_arguments_without_printing_them() {
    use std::os::unix::ffi::OsStringExt as _;

    assert_eq!(
        parse_request([
            OsString::from("cw"),
            OsString::from("__hosted-exec"),
            OsString::from("--"),
            OsString::from_vec(vec![0xff]),
        ])
        .unwrap_err(),
        HostedExecFailure
    );
}

#[test]
fn hosted_exec_reads_only_the_fixed_daemon_capability() {
    let mut requested = Vec::new();
    let token = read_daemon_token(|name| {
        requested.push(name.to_owned());
        Ok("synthetic-daemon-capability".into())
    })
    .unwrap();
    assert_eq!(requested, ["CODEWIRE_DAEMON_AUTH_TOKEN"]);
    assert_eq!(token.as_str(), "synthetic-daemon-capability");
    assert_eq!(DAEMON_ENDPOINT, "http://127.0.0.1:7777");
    assert_eq!(HOSTED_EXEC_AMBIGUOUS_EXIT_CODE, 125);
}

#[test]
fn hosted_exec_rejects_missing_or_noncanonical_capability() {
    assert_eq!(
        read_daemon_token(|_| Err(HostedExecFailure)).unwrap_err(),
        HostedExecFailure
    );
    for invalid in [
        "",
        " ",
        " padded",
        "padded ",
        "non-ASCII-ä",
        "line\nbreak",
        "nul\0byte",
    ] {
        assert_eq!(
            read_daemon_token(|_| Ok(invalid.into())).unwrap_err(),
            HostedExecFailure
        );
    }
    assert_eq!(format!("{:?}", HostedExecFailure), "HostedExecFailure");
    assert_eq!(FAILURE_DIAGNOSTIC, "hosted exec failed");
}

fn frame(payload: Payload) -> Result<v1::ExecMessage, tonic::Status> {
    Ok(v1::ExecMessage {
        payload: Some(payload),
    })
}

fn exit(code: i32) -> Result<v1::ExecMessage, tonic::Status> {
    frame(Payload::Exit(v1::ExitStatus { code }))
}

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    fail_write: bool,
    fail_flush: bool,
}

impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let output = self.get_mut();
        if output.fail_write {
            return Poll::Ready(Err(std::io::Error::other("synthetic-write-marker")));
        }
        // Exercise write_all, including binary chunks without a newline.
        let count = bytes.len().min(2);
        output.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.fail_flush {
            Poll::Ready(Err(std::io::Error::other("synthetic-flush-marker")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn hosted_exec_relays_binary_output_and_preserves_every_child_exit_code() {
    for code in 0..=255 {
        let mut stdout = Output::default();
        let mut stderr = Output::default();
        let stream = tokio_stream::iter([
            frame(Payload::Stdout(vec![0, 255, b'o', b'u', b't'])),
            frame(Payload::Stderr(b"stderr\n".to_vec())),
            frame(Payload::Stdout(b"last".to_vec())),
            exit(code),
        ]);
        assert_eq!(
            relay_output(stream, &mut stdout, &mut stderr).await,
            Ok(code)
        );
        assert_eq!(
            stdout.bytes,
            [0, 255, b'o', b'u', b't', b'l', b'a', b's', b't']
        );
        assert_eq!(stderr.bytes, b"stderr\n");
    }
}

#[tokio::test]
async fn hosted_exec_requires_a_terminal_exit_before_clean_eof() {
    for frames in [vec![], vec![frame(Payload::Stdout(b"partial".to_vec()))]] {
        assert_eq!(
            relay_output(
                tokio_stream::iter(frames),
                &mut Output::default(),
                &mut Output::default()
            )
            .await,
            Err(HostedExecFailure)
        );
    }
}

#[tokio::test]
async fn hosted_exec_rejects_wrong_frames_invalid_exits_and_rpc_errors() {
    for message in [
        Ok(v1::ExecMessage { payload: None }),
        frame(Payload::Start(v1::ExecStartRequest::default())),
        frame(Payload::Stdin(b"unexpected".to_vec())),
        frame(Payload::CloseStdin(())),
        frame(Payload::Error("synthetic-daemon-error-marker".into())),
        exit(-1),
        exit(256),
        Err(tonic::Status::internal("synthetic-rpc-error-marker")),
    ] {
        let mut stdout = Output::default();
        let mut stderr = Output::default();
        assert_eq!(
            relay_output(
                tokio_stream::iter([message, exit(1)]),
                &mut stdout,
                &mut stderr
            )
            .await,
            Err(HostedExecFailure)
        );
        assert!(stdout.bytes.is_empty());
        assert!(stderr.bytes.is_empty());
    }
}

#[tokio::test]
async fn hosted_exec_rejects_frames_or_failed_trailers_after_exit() {
    for trailing in [
        exit(0),
        frame(Payload::Stdout(b"late".to_vec())),
        frame(Payload::Stderr(b"late".to_vec())),
        frame(Payload::Error("synthetic-error-marker".into())),
        Err(tonic::Status::unavailable("synthetic-trailer-marker")),
    ] {
        let mut stdout = Output::default();
        let mut stderr = Output::default();
        assert_eq!(
            relay_output(
                tokio_stream::iter([exit(0), trailing]),
                &mut stdout,
                &mut stderr
            )
            .await,
            Err(HostedExecFailure)
        );
        assert!(stdout.bytes.is_empty());
        assert!(stderr.bytes.is_empty());
    }
}

#[tokio::test]
async fn hosted_exec_write_and_flush_failures_never_certify_a_child_status() {
    for is_stdout in [true, false] {
        for fail_write in [true, false] {
            let mut failing = Output {
                fail_write,
                fail_flush: !fail_write,
                ..Output::default()
            };
            let mut other = Output::default();
            let (payload, stdout, stderr) = if is_stdout {
                (
                    Payload::Stdout(b"output".to_vec()),
                    &mut failing,
                    &mut other,
                )
            } else {
                (
                    Payload::Stderr(b"output".to_vec()),
                    &mut other,
                    &mut failing,
                )
            };
            assert_eq!(
                relay_output(
                    tokio_stream::iter([frame(payload), exit(0)]),
                    stdout,
                    stderr
                )
                .await,
                Err(HostedExecFailure)
            );
        }
    }
    for is_stdout in [true, false] {
        let mut failing = Output {
            fail_flush: true,
            ..Output::default()
        };
        let mut other = Output::default();
        let (stdout, stderr) = if is_stdout {
            (&mut failing, &mut other)
        } else {
            (&mut other, &mut failing)
        };
        assert_eq!(
            relay_output(tokio_stream::iter([exit(0)]), stdout, stderr).await,
            Err(HostedExecFailure)
        );
    }
}

struct OwnedStream {
    frames: VecDeque<Result<v1::ExecMessage, tonic::Status>>,
    polls: Rc<Cell<usize>>,
    dropped: Rc<Cell<bool>>,
}

impl Stream for OwnedStream {
    type Item = Result<v1::ExecMessage, tonic::Status>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        stream.polls.set(stream.polls.get() + 1);
        match stream.frames.pop_front() {
            Some(frame) => Poll::Ready(Some(frame)),
            None => Poll::Pending,
        }
    }
}

impl Drop for OwnedStream {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}

#[tokio::test]
async fn hosted_exec_output_failure_drops_the_owned_stream_without_detached_reader() {
    let polls = Rc::new(Cell::new(0));
    let dropped = Rc::new(Cell::new(false));
    let stream = OwnedStream {
        frames: [frame(Payload::Stdout(b"first".to_vec())), exit(0)].into(),
        polls: polls.clone(),
        dropped: dropped.clone(),
    };
    let mut stdout = Output {
        fail_write: true,
        ..Output::default()
    };
    assert_eq!(
        relay_output(stream, &mut stdout, &mut Output::default()).await,
        Err(HostedExecFailure)
    );
    assert!(dropped.get());
    assert_eq!(polls.get(), 1);
}

#[tokio::test]
async fn hosted_exec_cancellation_drops_stream_while_waiting_for_terminal_trailers() {
    let polls = Rc::new(Cell::new(0));
    let dropped = Rc::new(Cell::new(false));
    let stream = OwnedStream {
        frames: [frame(Payload::Stdout(b"first".to_vec())), exit(0)].into(),
        polls: polls.clone(),
        dropped: dropped.clone(),
    };
    let mut stdout = Output::default();
    let mut stderr = Output::default();
    let mut relay = Box::pin(relay_output(stream, &mut stdout, &mut stderr));
    std::future::poll_fn(|cx| {
        assert!(relay.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(!dropped.get());
    assert_eq!(polls.get(), 3);
    drop(relay);
    assert!(dropped.get());
    assert_eq!(stdout.bytes, b"first");
}
