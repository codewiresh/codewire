//! Built-CLI journeys for `cw feedback` (#4061) against a synthetic Codewire
//! server: what is sent signed in and anonymously, that nothing is sent
//! unconfirmed, the typed message in a terminal, and a refusal's retry time.
#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::Path;
use std::process::{Child, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Router, body::Bytes, extract::State};
use buffa::Message as _;
use codewire_client as rpc;

const API_KEY: &str = "cw_synthetic_feedback_key";
const ORG: &str = "org-feedback";
const FEEDBACK_ID: &str = "5f0c9a2e-0d7b-4c1e-9a43-2b8f6f3d1c11";

#[derive(Default)]
struct Fixture {
    /// Each SubmitFeedback request with the Authorization it carried.
    submitted: Vec<(Option<String>, rpc::SubmitFeedbackRequest)>,
    /// Refuse submissions as rate-limited.
    limited: bool,
}

async fn platform(
    State(state): State<Arc<Mutex<Fixture>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get("authorization")
        .map(|value| value.to_str().unwrap().to_owned());
    let mut state = state.lock().unwrap();
    let bytes = match uri.path() {
        "/codewire.v1.OrganizationService/ListOrganizations" => {
            assert_eq!(
                authorization.as_deref(),
                Some(&*format!("Bearer {API_KEY}"))
            );
            rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: ORG.into(),
                        name: "Feedback Org".into(),
                        slug: "feedback-org".into(),
                        ..Default::default()
                    })
                    .into(),
                    role: rpc::OrgRole::Owner.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec()
        }
        "/codewire.v1.FeedbackService/SubmitFeedback" => {
            let request = rpc::SubmitFeedbackRequest::decode(&mut body.as_ref()).unwrap();
            let signed_in = authorization.is_some();
            state.submitted.push((authorization, request));
            if state.limited {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("content-type", "application/json")],
                    r#"{"code":"resource_exhausted","message":"anonymous feedback is limited to 5 an hour from one address; try again in 42 seconds, or sign in"}"#,
                )
                    .into_response();
            }
            rpc::SubmitFeedbackResponse {
                id: FEEDBACK_ID.into(),
                signed_in,
                ..Default::default()
            }
            .encode_to_vec()
        }
        path => panic!("unexpected fixture request {path}"),
    };
    ([("content-type", "application/proto")], bytes).into_response()
}

async fn server(state: Arc<Mutex<Fixture>>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(platform).with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, task)
}

/// `cw --server URL ARGS` with private config, `stdin` as its input and, when
/// `api_key` is set, signed in with it.
async fn cw(root: &Path, url: &str, api_key: bool, stdin: &str, args: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", root.join("config"))
        .env("CW_MESH_DATA_DIR", root.join("mesh"))
        .env("NO_COLOR", "1")
        .args(["--server", url])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if api_key {
        command.env("CODEWIRE_API_KEY", API_KEY);
    }
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut input, stdin.as_bytes())
        .await
        .unwrap();
    drop(input);
    tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("cw feedback timed out")
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn feedback_sends_signed_in_or_anonymously_and_only_what_it_shows() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    // Signed in: the credential and the current organization are sent.
    let output = cw(
        root.path(),
        &url,
        true,
        "",
        &[
            "--cloud", "feedback", "works", "well", "--yes", "-o", "json",
        ],
    )
    .await;
    assert!(output.status.success(), "{}", text(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["id"], FEEDBACK_ID);
    assert_eq!(json["signed_in"], true);
    let shown = text(&output.stderr);
    assert!(
        shown.contains("From      the API key in CODEWIRE_API_KEY, organization Feedback Org\n"),
        "{shown}"
    );
    {
        let state = state.lock().unwrap();
        let (authorization, request) = state.submitted.last().unwrap();
        assert_eq!(
            authorization.as_deref(),
            Some(&*format!("Bearer {API_KEY}"))
        );
        assert_eq!(request.message, "works well");
        assert_eq!(request.org_id.as_deref(), Some(ORG));
        assert_eq!(request.os, std::env::consts::OS);
        assert_eq!(request.arch, std::env::consts::ARCH);
        assert!(!request.cli_version.is_empty());
        assert_eq!(
            request.placement.as_known(),
            Some(rpc::FeedbackPlacement::FEEDBACK_PLACEMENT_CLOUD)
        );
        assert_eq!(request.environment_id, None);
        assert!(
            shown.contains(&format!(
                "Attached  cw {}, {} {}, cloud\n",
                request.cli_version,
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
            "{shown}"
        );
    }

    // --anonymous while signed in: no credential and no organization.
    let output = cw(
        root.path(),
        &url,
        true,
        "",
        &[
            "feedback",
            "hi",
            "--anonymous",
            "--environment",
            "env-1",
            "--yes",
        ],
    )
    .await;
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout),
        format!("Feedback sent ({FEEDBACK_ID}). Thank you.\n")
    );
    assert!(
        text(&output.stderr)
            .contains("From      anonymous (--anonymous): no account or organization\n")
    );
    {
        let state = state.lock().unwrap();
        let (authorization, request) = state.submitted.last().unwrap();
        assert_eq!(authorization, &None);
        assert_eq!(request.org_id, None);
        assert_eq!(request.environment_id.as_deref(), Some("env-1"));
        assert_eq!(
            request.placement.as_known(),
            Some(rpc::FeedbackPlacement::FEEDBACK_PLACEMENT_UNSPECIFIED)
        );
    }

    // Not signed in, from stdin: anonymous, and said so.
    let output = cw(
        root.path(),
        &url,
        false,
        "from a script\n",
        &["feedback", "--yes"],
    )
    .await;
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr)
            .contains("From      anonymous (not signed in): no account or organization\n")
    );
    assert_eq!(state.lock().unwrap().submitted.len(), 3);
    {
        let state = state.lock().unwrap();
        let (authorization, request) = state.submitted.last().unwrap();
        assert_eq!(authorization, &None);
        assert_eq!(request.message, "from a script");
    }

    // Nothing is sent without confirmation, an empty or oversized message,
    // or an invalid environment ID.
    for (stdin, args, refusal) in [
        (
            "unconfirmed",
            vec!["feedback"],
            "pass --yes to send without asking",
        ),
        ("", vec!["feedback", "--yes"], "the message is empty"),
        (
            &*"x".repeat(10 * 1024 + 1),
            vec!["feedback", "--yes"],
            "longer than 10 KB",
        ),
        (
            "",
            vec!["feedback", "hi", "--environment", "../etc", "--yes"],
            "--environment must be an environment ID",
        ),
    ] {
        let output = cw(root.path(), &url, false, stdin, &args).await;
        assert!(!output.status.success());
        let stderr = text(&output.stderr);
        assert!(stderr.contains(refusal), "{args:?}: {stderr}");
    }
    assert_eq!(
        state.lock().unwrap().submitted.len(),
        3,
        "nothing more was sent"
    );

    // A refusal says when to try again.
    state.lock().unwrap().limited = true;
    let output = cw(
        root.path(),
        &url,
        false,
        "",
        &["feedback", "again", "--yes"],
    )
    .await;
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("not sent: "), "{stderr}");
    assert!(stderr.contains("try again in 42 seconds"), "{stderr}");
    server.abort();
}

/// A terminal for one `cw` run.
struct Pty {
    child: Child,
    master: File,
    output: Vec<u8>,
}

impl Pty {
    fn spawn(url: &str, args: &[&str], root: &Path) -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both descriptor pointers are valid for this call; null
        // termios/window pointers ask the OS for its default terminal state.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0);
        // SAFETY: successful openpty returned two distinct owned descriptors.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        // SAFETY: the descriptor is live and F_GETFL takes no argument.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        // SAFETY: the descriptor is live; F_SETFL changes only this test's PTY.
        let set =
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_ne!(set, -1);
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_cw"))
            .env_clear()
            .env("HOME", root)
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "1")
            .env("CW_CONFIG_DIR", root.join("config"))
            .env("CW_MESH_DATA_DIR", root.join("mesh"))
            .args(["--server", url])
            .args(args)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();
        Self {
            child,
            master,
            output: Vec::new(),
        }
    }

    fn read(&mut self) {
        let mut buffer = [0u8; 8192];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => self.output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                // The child closed the terminal.
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("read fixture PTY: {error}"),
            }
        }
    }

    fn expect(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.read();
            if String::from_utf8_lossy(&self.output).contains(text) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "cw exited before {text}: {}",
                String::from_utf8_lossy(&self.output)
            );
            assert!(
                Instant::now() < deadline,
                "waiting for {text}: {}",
                String::from_utf8_lossy(&self.output)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }

    fn finish(mut self, success: bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.read();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.read();
                let output = String::from_utf8_lossy(&self.output).into_owned();
                assert_eq!(status.success(), success, "{output}");
                return output;
            }
            assert!(Instant::now() < deadline, "cw did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_typed_in_the_terminal_is_sent_with_ctrl_d_or_canceled() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();

        // Escape, Ctrl-C, and Cancel at the confirmation send nothing.
        for cancel in [&b"\x1b"[..], b"\x03"] {
            let mut process = Pty::spawn(&url, &["feedback", "--anonymous"], root.path());
            process.expect("Ctrl-D send");
            process.send(b"draft");
            process.expect("> draft");
            process.send(cancel);
            let output = process.finish(false);
            assert!(output.contains("canceled; no feedback sent"), "{output}");
        }
        let mut process = Pty::spawn(&url, &["feedback", "--anonymous"], root.path());
        process.expect("Ctrl-D send");
        process.send(b"draft\x04");
        process.expect("Send this feedback?");
        // Down to Cancel, then Enter.
        process.send(b"\x1b[B");
        std::thread::sleep(Duration::from_millis(100));
        process.send(b"\r");
        let output = process.finish(false);
        assert!(output.contains("canceled; no feedback sent"), "{output}");
        assert!(state.lock().unwrap().submitted.is_empty());

        // Enter starts a new line; Ctrl-D sends once confirmed.
        let mut process = Pty::spawn(&url, &["feedback", "--anonymous"], root.path());
        process.expect("Ctrl-D send");
        process.send("first line\rsecond, é\r".as_bytes());
        process.expect("second, é");
        process.send(b"\x04");
        process.expect("Message   21 bytes");
        process.expect("Send this feedback?");
        process.send(b"\r");
        let output = process.finish(true);
        assert!(
            output.contains(&format!("Feedback sent ({FEEDBACK_ID}). Thank you.")),
            "{output}"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.submitted.len(), 1);
        let (authorization, request) = &state.submitted[0];
        assert_eq!(authorization, &None);
        assert_eq!(request.message, "first line\nsecond, é");
    })
    .await
    .unwrap();
    server.abort();
}
