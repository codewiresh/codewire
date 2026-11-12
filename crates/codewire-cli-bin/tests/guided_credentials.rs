//! Built-CLI journeys against a synthetic HTTP/2 credential authority.
#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{Router, body::Bytes, extract::State, http::Uri, response::IntoResponse};
use buffa::Message as _;
use codewire_client as rpc;

const CREDENTIAL: &str = "11111111-1111-4111-8111-111111111111";
const PROFILE: &str = "22222222-2222-4222-8222-222222222222";

#[derive(Default)]
struct Fixture {
    requests: Vec<String>,
    credential: Option<rpc::Credential>,
    by_id: bool,
    secret_exists: bool,
    expected_slot: Option<&'static str>,
}

async fn authority(
    State(state): State<Arc<Mutex<Fixture>>>,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    let method = uri.path().rsplit('/').next().unwrap();
    let mut state = state.lock().unwrap();
    state.requests.push(method.into());
    let bytes = match method {
        "AddApiKeyCredential" => {
            let request = rpc::AddApiKeyCredentialRequest::decode(&mut body.as_ref()).unwrap();
            assert_eq!(request.value, b"synthetic-x");
            let record = rpc::Credential {
                id: CREDENTIAL.into(),
                name: request.name,
                provider: request.provider,
                authentication_kind: rpc::CredentialAuthenticationKind::ApiKey.into(),
                status: rpc::CredentialStatus::Active.into(),
                revocation_generation: 1,
                ..Default::default()
            };
            state.credential = Some(record.clone());
            rpc::AddApiKeyCredentialResponse {
                credential: Some(record).into(),
                ..Default::default()
            }
            .encode_to_vec()
        }
        "ListCredentials" => rpc::ListCredentialsResponse {
            credentials: state.credential.iter().cloned().collect(),
            ..Default::default()
        }
        .encode_to_vec(),
        "ListAccessProfiles" => rpc::ListAccessProfilesResponse::default().encode_to_vec(),
        "GetCredential" => {
            let request = rpc::GetCredentialRequest::decode(&mut body.as_ref()).unwrap();
            let mut record = state.credential.clone().unwrap();
            if record.authentication_kind == rpc::CredentialAuthenticationKind::Oauth {
                assert!(
                    matches!(request.selector, Some(rpc::get_credential_request::Selector::Name(ref name)) if name == "work")
                );
            } else {
                state.by_id = matches!(request.selector, Some(rpc::get_credential_request::Selector::CredentialId(ref id)) if id == CREDENTIAL);
                assert!(
                    state.by_id,
                    "profile binding must use the save receipt's exact identity"
                );
                // A rename while the user is in a menu cannot change the bound identity.
                record.name = "renamed-while-choosing".into();
            }
            rpc::GetCredentialResponse {
                credential: Some(record).into(),
                ..Default::default()
            }
            .encode_to_vec()
        }
        "CreateAccessProfile" => {
            let request = rpc::CreateAccessProfileRequest::decode(&mut body.as_ref()).unwrap();
            assert_eq!(request.entries.len(), 1);
            assert_eq!(request.entries[0].credential_id, CREDENTIAL);
            if let Some(slot) = state.expected_slot {
                assert_eq!(request.entries[0].capability_slot, slot);
            }
            rpc::CreateAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    id: PROFILE.into(),
                    name: request.name,
                    revision: 1,
                    entries: request.entries,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
            .encode_to_vec()
        }
        "ListUserSecrets" => rpc::ListUserSecretsResponse {
            secrets: if state.secret_exists {
                vec![rpc::SecretMetadata {
                    key: "DATABASE_URL".into(),
                    ..Default::default()
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        }
        .encode_to_vec(),
        "SetUserSecret" => {
            let request = rpc::SetUserSecretRequest::decode(&mut body.as_ref()).unwrap();
            assert_eq!(request.key, "DATABASE_URL");
            assert_eq!(request.value, "synthetic-value");
            state.secret_exists = true;
            rpc::SetUserSecretResponse::default().encode_to_vec()
        }
        _ => panic!("unexpected fixture method {method}"),
    };
    ([("content-type", "application/proto")], bytes)
}

struct Pty {
    child: Child,
    master: File,
    slave: File,
    before: libc::termios,
    output: Vec<u8>,
}

impl Pty {
    fn spawn(url: &str, args: &[&str], root: &std::path::Path) -> Self {
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
        // SAFETY: the descriptor is live, and F_GETFL takes no pointer.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        // SAFETY: the descriptor is live; F_SETFL changes only this test's PTY.
        let set =
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_ne!(set, -1);
        let before = terminal_state(&slave);
        let child = Command::new(env!("CARGO_BIN_EXE_cw"))
            .args(["--server", url])
            .args(args)
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "1")
            .env("CW_CONFIG_DIR", root.join("config"))
            .env("CW_MESH_DATA_DIR", root.join("mesh"))
            .env("CODEWIRE_API_KEY", "cw_synthetic_guided_fixture")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            master,
            slave,
            before,
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
                "CLI exited before {text}: {}",
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
                assert_eq!(
                    status.success(),
                    success,
                    "{}",
                    String::from_utf8_lossy(&self.output)
                );
                break;
            }
            assert!(Instant::now() < deadline, "CLI did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        let after = terminal_state(&self.slave);
        assert_eq!(self.before.c_iflag, after.c_iflag);
        assert_eq!(self.before.c_oflag, after.c_oflag);
        assert_eq!(self.before.c_cflag, after.c_cflag);
        // Darwin's stock stty raw/-g round-trip itself sets PENDIN, a
        // transient pending-redraw flag. Every configuration bit, including
        // ECHO and ICANON, and every control character remains a strict check.
        let local_flags = |flags: libc::tcflag_t| {
            #[cfg(target_os = "macos")]
            {
                flags & !libc::PENDIN
            }
            #[cfg(not(target_os = "macos"))]
            {
                flags
            }
        };
        assert_eq!(local_flags(self.before.c_lflag), local_flags(after.c_lflag));
        assert_eq!(self.before.c_cc, after.c_cc);
        // POSIX stores the baud rates separately on some hosts.
        // SAFETY: each call reads one initialized termios value through a
        // reference that outlives it.
        let (input_before, input_after, output_before, output_after) = unsafe {
            (
                libc::cfgetispeed(&self.before),
                libc::cfgetispeed(&after),
                libc::cfgetospeed(&self.before),
                libc::cfgetospeed(&after),
            )
        };
        assert_eq!(input_before, input_after);
        assert_eq!(output_before, output_after);
        let output = String::from_utf8_lossy(&self.output).into_owned();
        assert!(!output.contains("synthetic-x"));
        assert!(!output.contains("synthetic-value"));
        assert!(!output.contains("synthetic-é"));
        assert!(!output.contains("synthetic-partial"));
        output
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

fn terminal_state(file: &File) -> libc::termios {
    let mut state = std::mem::MaybeUninit::uninit();
    // SAFETY: state points to enough writable memory and the descriptor is live.
    let read = unsafe { libc::tcgetattr(file.as_raw_fd(), state.as_mut_ptr()) };
    assert_eq!(read, 0);
    // SAFETY: successful tcgetattr initialized the complete termios value.
    unsafe { state.assume_init() }
}

async fn server(state: Arc<Mutex<Fixture>>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(authority).with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hidden_cancellation_restores_terminal_without_a_credential_write() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();
        for &cancel in b"\x1b\x03\x04" {
            let mut process = Pty::spawn(
                &url,
                &["--cloud", "credentials", "add", "openai"],
                root.path(),
            );
            process.expect("Credential name");
            process.send(b"\r");
            process.expect("Enter a value");
            process.send(b"work\r");
            process.expect("Credential material:");
            process.send(b"synthetic-partial");
            process.send(&[cancel]);
            process.finish(false);
            assert!(state.lock().unwrap().requests.is_empty());
        }
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_addition_binds_the_saved_id_after_unicode_correction() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();
        let mut process = Pty::spawn(
            &url,
            &["--cloud", "credentials", "add", "openai"],
            root.path(),
        );
        process.expect("Credential name");
        process.send(b"work\r");
        process.expect("Credential material:");
        process.send("synthetic-é".as_bytes());
        process.send(b"\x7fx\r");
        process.expect("Use this credential in a profile?");
        process.send(b"\r");
        process.expect("Choose a credential profile");
        process.send(b"\r");
        process.expect("New profile name");
        process.send(b"work\r");
        process.finish(true);
        let state = state.lock().unwrap();
        assert!(state.by_id);
        assert_eq!(
            state.requests.last().map(String::as_str),
            Some("CreateAccessProfile")
        );
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declined_reconnect_never_offers_or_changes_profile_assignment() {
    let state = Arc::new(Mutex::new(Fixture {
        credential: Some(rpc::Credential {
            id: CREDENTIAL.into(),
            name: "work".into(),
            provider: "openai".into(),
            authentication_kind: rpc::CredentialAuthenticationKind::Oauth.into(),
            status: rpc::CredentialStatus::Active.into(),
            revocation_generation: 1,
            ..Default::default()
        }),
        ..Default::default()
    }));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();
        let mut process = Pty::spawn(
            &url,
            &["--cloud", "credentials", "connect", "codex"],
            root.path(),
        );
        process.expect("Credential name");
        process.send(b"work\r");
        process.expect("Reconnect platform Codex");
        process.send(b"n\n");
        let output = process.finish(false);
        assert!(!output.contains("Credential saved"));
        assert!(!output.contains("Use this credential in a profile?"));
        assert_eq!(state.lock().unwrap().requests, ["GetCredential"]);
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_walkthrough_writes_hidden_value_and_confirms_replacement_before_reading() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();
        let mut process = Pty::spawn(&url, &["--cloud", "secrets", "set"], root.path());
        process.expect("Where should this secret live?");
        process.send(b"\x1b[B\r");
        process.expect("Secret key");
        process.send(b"DATABASE_URL\r");
        process.expect("Value:");
        process.send(b"synthetic-value\r");
        process.finish(true);
        assert!(state.lock().unwrap().secret_exists);
        state.lock().unwrap().requests.clear();
        let mut process = Pty::spawn(&url, &["--cloud", "secrets", "set"], root.path());
        process.expect("Where should this secret live?");
        process.send(b"\x1b[B\r");
        process.expect("Secret key");
        process.send(b"DATABASE_URL\r");
        process.expect("Replace the existing value for DATABASE_URL?");
        process.send(b"\x1b[B\r");
        let output = process.finish(true);
        assert!(!output.contains("Value:"));
        assert_eq!(state.lock().unwrap().requests, ["ListUserSecrets"]);
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_codex_profile_can_enroll_an_openai_api_key_and_return_to_binding() {
    let state = Arc::new(Mutex::new(Fixture {
        expected_slot: Some("codex"),
        ..Default::default()
    }));
    let (url, server) = server(state.clone()).await;
    tokio::task::spawn_blocking(move || {
        let root = tempfile::tempdir().unwrap();
        let mut process = Pty::spawn(
            &url,
            &[
                "--cloud",
                "credentials",
                "--profile",
                "work",
                "set",
                "codex",
            ],
            root.path(),
        );
        process.expect("No compatible credentials. Set one up now?");
        process.send(b"\r");
        process.expect("How should this profile access Codex?");
        process.send(b"\x1b[B\r");
        process.expect("Credential name");
        process.send(b"work\r");
        process.expect("Credential material:");
        process.send(b"synthetic-x\r");
        process.finish(true);
        let state = state.lock().unwrap();
        assert!(state.by_id);
        assert_eq!(
            state.requests.last().map(String::as_str),
            Some("CreateAccessProfile")
        );
    })
    .await
    .unwrap();
    server.abort();
}
