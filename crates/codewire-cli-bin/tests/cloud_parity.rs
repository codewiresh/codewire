//! Built-CLI journeys for cloud commands that now match their local
//! counterparts (#4717, `docs/dev/CLI-PARITY.md`), against a synthetic
//! Codewire server that answers as orchestration does and records each
//! request.
#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Router, body::Bytes, extract::State};
use codewire_client as rpc;

const API_KEY: &str = "cw_synthetic_parity_key";
const ORG: &str = "0b6f3f4e-6a3c-4d1b-9a55-1f2e3d4c5b6b";

#[derive(Default)]
struct Fixture {
    /// Each request path, in order.
    paths: Vec<String>,
}

fn proto(message: impl buffa::Message) -> Response {
    (
        [("content-type", "application/proto")],
        message.encode_to_vec(),
    )
        .into_response()
}

async fn platform(State(state): State<Arc<Mutex<Fixture>>>, uri: Uri, _body: Bytes) -> Response {
    state.lock().unwrap().paths.push(uri.path().to_owned());
    match uri.path() {
        "/codewire.v1.OrganizationService/ListOrganizations" => {
            proto(rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: ORG.into(),
                        name: "Parity Org".into(),
                        slug: "parity-org".into(),
                        ..Default::default()
                    })
                    .into(),
                    role: rpc::OrgRole::Owner.into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }
        _ => (
            StatusCode::NOT_IMPLEMENTED,
            [("content-type", "application/json")],
            r#"{"code":"unimplemented","message":"not in this fixture"}"#,
        )
            .into_response(),
    }
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

/// `cw --server URL ARGS` with `CODEWIRE_API_KEY` set, a private config,
/// and no terminal, run in `root`.
async fn cw(root: &Path, url: &str, args: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", root.join("config"))
        .env("CW_MESH_DATA_DIR", root.join("mesh"))
        .env("NO_COLOR", "1")
        .env("CODEWIRE_API_KEY", API_KEY)
        .current_dir(root)
        .args(["--server", url])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    tokio::time::timeout(
        Duration::from_secs(20),
        command.spawn().unwrap().wait_with_output(),
    )
    .await
    .expect("cw timed out")
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// H1: with an API key set, `cw setup --cloud` says the key is in use and
/// starts no sign-in: it asks the server nothing.
#[tokio::test]
async fn setup_with_an_api_key_says_the_key_is_in_use_and_starts_no_sign_in() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(root.path(), &url, &["--cloud", "setup", "--skip-ssh"]).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr,
        format!(
            "Welcome to Codewire.\nServer: {url}\n\
             Using the API key in CODEWIRE_API_KEY, so there is nothing to sign in to.\n\
             Setup complete.\n"
        )
    );
    assert!(!stderr.contains("Opening browser"), "{stderr}");
    assert_eq!(text(&output.stdout), "");

    // An organization flag has nothing to save without a sign-in.
    let output = cw(
        root.path(),
        &url,
        &["--cloud", "setup", "--skip-ssh", "--org", "acme"],
    )
    .await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("set CODEWIRE_ORG instead"), "{stderr}");

    assert_eq!(state.lock().unwrap().paths, Vec::<String>::new());
    assert!(!root.path().join("config").join("credentials.json").exists());
    server.abort();
}

/// B1: `cw cost --org` of an organization you aren't in is refused as not
/// found, naming `cw org list`, and exits 1; it used to print nothing and
/// exit 0.
#[tokio::test]
async fn cost_of_an_organization_that_isnt_yours_is_not_found() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(root.path(), &url, &["cost", "--org", "missing"]).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Organization \"missing\" not found"),
        "{stderr}"
    );
    assert!(stderr.contains("cw org list"), "{stderr}");
    assert_eq!(text(&output.stdout), "");
    assert_eq!(
        state.lock().unwrap().paths,
        ["/codewire.v1.OrganizationService/ListOrganizations"]
    );
    server.abort();
}
