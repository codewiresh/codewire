//! Built-CLI journeys for `cw update ENV --file` (#5949, journey
//! `sandbox-update-startup`), against a synthetic Codewire server: the
//! Sandbox's saved settings are compared with the file, only the startup
//! script is sent, and a refusal sends nothing.
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
use buffa::Message as _;
use codewire_client as rpc;

const API_KEY: &str = "cw_synthetic_startup_key";
const ORG: &str = "0b6f3f4e-6a3c-4d1b-9a55-1f2e3d4c5b6b";
const ENVIRONMENT: &str = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e40";
const SAVED: &str = "install_command: npm ci\n";
const SET: &str = "/codewire.v1.EnvironmentService/SetEnvironmentStartupScript";

#[derive(Default)]
struct Fixture {
    /// Each request path, in order.
    paths: Vec<String>,
    /// Each script sent to SetEnvironmentStartupScript.
    scripts: Vec<String>,
}

fn proto(message: impl buffa::Message) -> Response {
    (
        [("content-type", "application/proto")],
        message.encode_to_vec(),
    )
        .into_response()
}

fn environment() -> rpc::Environment {
    rpc::Environment {
        id: ENVIRONMENT.into(),
        org_id: ORG.into(),
        created_by: "user-startup".into(),
        r#type: "sandbox".into(),
        name: "app".into(),
        state: rpc::EnvironmentState::Running.into(),
        desired_state: rpc::DesiredState::Started.into(),
        cpu_millicores: 2000,
        memory_mb: 4096,
        disk_gb: 20,
        ..Default::default()
    }
}

async fn platform(State(state): State<Arc<Mutex<Fixture>>>, uri: Uri, body: Bytes) -> Response {
    state.lock().unwrap().paths.push(uri.path().to_owned());
    match uri.path() {
        "/codewire.v1.OrganizationService/ListOrganizations" => {
            proto(rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: ORG.into(),
                        name: "Startup Org".into(),
                        slug: "startup-org".into(),
                        ..Default::default()
                    })
                    .into(),
                    role: rpc::OrgRole::Owner.into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }
        "/codewire.v1.EnvironmentService/ListEnvironments" => {
            proto(rpc::ListEnvironmentsResponse {
                environments: vec![environment()],
                ..Default::default()
            })
        }
        "/codewire.v1.EnvironmentService/GetEnvironment" => proto(rpc::GetEnvironmentResponse {
            environment: Some(environment()).into(),
            ..Default::default()
        }),
        "/codewire.v1.EnvironmentService/GetEnvironmentProjectSpec" => {
            // SAVED, as the server returns it.
            proto(rpc::GetEnvironmentProjectSpecResponse {
                project_spec: Some(codewire_proto::codewire::v1::ProjectSpec {
                    schema_version: 1,
                    working_directory: "/workspace".into(),
                    install_command: "npm ci".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
        }
        SET => {
            let request =
                codewire_proto::codewire::v1::SetEnvironmentStartupScriptRequest::decode_from_slice(
                    &body,
                )
                .unwrap();
            assert_eq!(request.environment_id, ENVIRONMENT);
            state
                .lock()
                .unwrap()
                .scripts
                .push(request.startup_script.clone());
            proto(
                codewire_proto::codewire::v1::SetEnvironmentStartupScriptResponse {
                    changed: true,
                    state: rpc::EnvironmentState::Running.into(),
                    ..Default::default()
                },
            )
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

/// `cw --server URL --cloud ARGS` with `codewire.yaml` holding `file`,
/// signed in with an API key, private config, piped, run in `root`.
async fn cw(root: &Path, url: &str, file: &str, args: &[&str]) -> Output {
    std::fs::write(root.join("codewire.yaml"), file).unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", root.join("config"))
        .env("CW_MESH_DATA_DIR", root.join("mesh"))
        .env("NO_COLOR", "1")
        .env("LC_ALL", "C.UTF-8")
        .env("CODEWIRE_API_KEY", API_KEY)
        .current_dir(root)
        .args(["--server", url, "--cloud"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    tokio::time::timeout(
        Duration::from_secs(60),
        command.spawn().unwrap().wait_with_output(),
    )
    .await
    .expect("cw timed out")
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn a_sandbox_gains_the_file_s_startup_script_and_nothing_else() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();
    let file = format!("{SAVED}startup_script: echo started > /workspace/started\n");

    let output = cw(
        root.path(),
        &url,
        &file,
        &["update", "app", "--file", "codewire.yaml", "--yes"],
    )
    .await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(
        text(&output.stdout),
        "✓ Startup script added to app · it runs at the next start, not now\n\
         → cw --cloud stop app && cw --cloud start app\n"
    );
    assert!(
        stderr.contains(
            "Adds this startup script to app, from codewire.yaml:\n  echo started > /workspace/started\n"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains('\x1b'), "{stderr}");

    let output = cw(
        root.path(),
        &url,
        &file,
        &[
            "update",
            "app",
            "--file",
            "codewire.yaml",
            "--yes",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "environment_id": ENVIRONMENT,
            "changed": true,
            "change": "added",
            "state": "running",
        })
    );
    assert_eq!(text(&output.stderr), "");

    let scripts = state.lock().unwrap().scripts.clone();
    assert_eq!(
        scripts,
        [
            "echo started > /workspace/started",
            "echo started > /workspace/started"
        ]
    );
    server.abort();
}

#[tokio::test]
async fn an_identical_file_changes_nothing() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(
        root.path(),
        &url,
        SAVED,
        &["update", "app", "--file", "codewire.yaml"],
    )
    .await;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout),
        "Nothing to change: app's settings already match codewire.yaml.\n"
    );
    assert!(!state.lock().unwrap().paths.contains(&SET.to_owned()));
    server.abort();
}

#[tokio::test]
async fn a_file_that_changes_another_setting_is_refused_and_sends_nothing() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(
        root.path(),
        &url,
        "install_command: pnpm install\nstartup_script: echo started\n",
        &["update", "app", "--file", "codewire.yaml", "--yes"],
    )
    .await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "`cw update --file` changes only startup_script, and codewire.yaml also changes install_command (only a new Sandbox takes it, since create applies it once); nothing was saved\n\
             → cw --cloud create --file codewire.yaml\n"
        ),
        "{stderr}"
    );
    assert_eq!(text(&output.stdout), "");

    // Without a terminal or --yes nothing is saved either.
    let output = cw(
        root.path(),
        &url,
        &format!("{SAVED}startup_script: echo started\n"),
        &["update", "app", "--file", "codewire.yaml"],
    )
    .await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "Saving the startup script needs --yes when there's no terminal to confirm at; nothing was saved"
        ),
        "{stderr}"
    );

    // --file takes no other change, refused before any request.
    let before = state.lock().unwrap().paths.len();
    let output = cw(
        root.path(),
        &url,
        SAVED,
        &[
            "update",
            "app",
            "--file",
            "codewire.yaml",
            "--idle-stop",
            "1h",
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("doesn't combine with --idle-stop"),
        "{}",
        text(&output.stderr)
    );
    let paths = state.lock().unwrap().paths.clone();
    assert_eq!(paths.len(), before, "{paths:?}");
    assert!(!paths.contains(&SET.to_owned()), "{paths:?}");
    server.abort();
}
