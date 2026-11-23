//! Built-CLI journeys for `--env KEY` (#5222; `docs/journeys/cloud-sandbox.md`,
//! `sandbox-run-env`), against a synthetic Codewire server that records every
//! request. `cw run --env KEY` sends the value `KEY` has in `cw`'s own
//! environment, empty included; an unset `KEY` is refused by name before any
//! request; `cw create` and `cw init` refuse `KEY` alone; and no output of
//! `cw` holds the value.
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
use buffa::Message;
use codewire_client as rpc;

const API_KEY: &str = "cw_synthetic_run_env_key";
const ORG: &str = "5d0c6b9a-2f41-4e8a-9c3b-7a1e2d3c4b5f";
const ENVIRONMENT: &str = "8e2f1a3b-5c4d-4e6f-9a8b-0c1d2e3f4a5b";
const SESSION: &str = "3a4b5c6d-7e8f-4a0b-8c1d-2e3f4a5b6c7d";
const VALUE: &str = "walk-value-5222-synthetic";

#[derive(Default)]
struct Fixture {
    /// Each request path, in order.
    paths: Vec<String>,
    /// The `env` of each `LaunchSession` request.
    launched: Vec<std::collections::HashMap<String, String>>,
}

fn proto(message: impl Message) -> Response {
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
        created_by: "user-run-env".into(),
        r#type: "sandbox".into(),
        name: "walk".into(),
        state: rpc::EnvironmentState::Running.into(),
        desired_state: rpc::DesiredState::Started.into(),
        setup_complete: true,
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
                        name: "Run Env Org".into(),
                        slug: "run-env-org".into(),
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
        "/codewire.v1.EnvironmentSessionService/ListSessions" => {
            proto(rpc::ListSessionsResponse::default())
        }
        "/codewire.v1.EnvironmentSessionService/LaunchSession" => {
            let request = rpc::LaunchSessionRequest::decode_from_slice(&body).unwrap();
            state.lock().unwrap().launched.push(
                request
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            );
            proto(rpc::LaunchSessionResponse {
                session: Some(rpc::EnvironmentSession {
                    session_id: SESSION.into(),
                    state: rpc::EnvironmentSessionState::Running.into(),
                    command: request.command,
                    name: request.name,
                    ..Default::default()
                })
                .into(),
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

/// `cw --server URL ARGS`, signed in with an API key, private config, run in
/// `root`, with `WALK_TOKEN` as `walk_token` gives it (unset for `None`).
async fn cw(root: &Path, url: &str, walk_token: Option<&str>, args: &[&str]) -> Output {
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
    if let Some(value) = walk_token {
        command.env("WALK_TOKEN", value);
    }
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

fn run(name: &str) -> Vec<String> {
    [
        "--cloud",
        "run",
        "--in",
        "walk",
        "--name",
        name,
        "--detach",
        "--no-tty",
        "--env",
        "WALK_TOKEN",
        "--",
        "true",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn args(words: &[String]) -> Vec<&str> {
    words.iter().map(String::as_str).collect()
}

#[tokio::test]
async fn cw_run_sends_the_value_key_has_in_cws_environment_and_never_prints_it() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(root.path(), &url, Some(VALUE), &args(&run("env-job"))).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(!stdout.contains(VALUE), "{stdout}");
    assert!(!stderr.contains(VALUE), "{stderr}");

    let output = cw(root.path(), &url, Some(""), &args(&run("env-empty"))).await;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let launched = state.lock().unwrap().launched.clone();
    assert_eq!(launched.len(), 2, "{launched:?}");
    assert_eq!(
        launched[0].get("WALK_TOKEN").map(String::as_str),
        Some(VALUE)
    );
    assert_eq!(launched[1].get("WALK_TOKEN").map(String::as_str), Some(""));
    server.abort();
}

#[tokio::test]
async fn an_unset_key_is_refused_by_name_before_any_request() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let exec = [
        "--cloud",
        "exec",
        "--in",
        "walk",
        "--env",
        "WALK_TOKEN",
        "--",
        "true",
    ]
    .map(str::to_owned)
    .to_vec();
    for words in [run("env-unset"), exec] {
        let output = cw(root.path(), &url, None, &args(&words)).await;
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{words:?}: {stderr}");
        assert!(
            stderr.contains(
                "he variable WALK_TOKEN isn't set, so `--env WALK_TOKEN` has nothing to send\n"
            ),
            "{words:?}: {stderr}"
        );
        assert!(stderr.contains("export WALK_TOKEN=VALUE\n"), "{stderr}");
        assert_eq!(text(&output.stdout), "");
    }
    assert_eq!(state.lock().unwrap().paths, Vec::<String>::new());
    server.abort();
}

#[tokio::test]
async fn create_and_init_refuse_a_key_alone_and_name_cw_secrets() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let create = |placement| {
        vec![
            placement,
            "create",
            "--name",
            "walk-env",
            "--image",
            "ubuntu:24.04",
            "--no-file",
            "--no-profile",
            "--no-network",
            "--env",
            "WALK_TOKEN",
            "--yes",
        ]
    };
    let init = vec![
        "init",
        "--image",
        "ubuntu:24.04",
        "--env",
        "WALK_TOKEN",
        "--yes",
    ];
    for (words, command) in [
        (create("--cloud"), "cw create"),
        (create("--local"), "cw create"),
        (init, "cw init"),
    ] {
        let output = cw(root.path(), &url, Some(VALUE), &words).await;
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{words:?}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "`{command} --env` needs KEY=VALUE, since it saves a plain variable in the environment's settings; keep a secret with `cw secrets`\n"
            )),
            "{words:?}: {stderr}"
        );
        assert!(stderr.contains("cw secrets set\n"), "{stderr}");
        assert!(!stderr.contains(VALUE), "{stderr}");
        assert_eq!(text(&output.stdout), "");
    }
    assert!(!root.path().join("codewire.yaml").exists());
    let paths = state.lock().unwrap().paths.clone();
    assert!(
        !paths
            .iter()
            .any(|path| path.ends_with("/CreateEnvironment")),
        "{paths:?}"
    );
    server.abort();
}
