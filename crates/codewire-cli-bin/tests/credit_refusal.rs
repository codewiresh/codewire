//! Built-CLI journeys for a cloud create or start refused because the
//! organization has no compute credit (#3381), against a synthetic Codewire
//! server that refuses them as orchestration does: `failed_precondition`
//! with the `CREDIT_EXHAUSTED` reason. The CLI names the organization, links
//! its billing page and points at local sandboxes, in text and `--output json`.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Router, body::Bytes, extract::State};
use codewire_client as rpc;

const API_KEY: &str = "cw_synthetic_credit_key";
const ORG: &str = "0b6f3f4e-6a3c-4d1b-9a55-1f2e3d4c5b6a";
const ENVIRONMENT: &str = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
/// Orchestration's refusal text, unchanged: the API's contract.
const SERVER_MESSAGE: &str =
    "this organization has no compute credit left; add a card or credit on its billing page";

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

/// Orchestration's Connect rendering of the 402 `credit_exhausted` refusal.
fn credit_exhausted() -> Response {
    let info = codewire_proto::google::rpc::ErrorInfo {
        reason: "CREDIT_EXHAUSTED".into(),
        domain: "codewire.sh".into(),
        metadata: [(
            "hint".to_owned(),
            "Add a card or credit on the organization's billing page".to_owned(),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let body = serde_json::json!({
        "code": "failed_precondition",
        "message": SERVER_MESSAGE,
        "details": [connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &info)],
    });
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn environment() -> rpc::Environment {
    rpc::Environment {
        id: ENVIRONMENT.into(),
        org_id: ORG.into(),
        created_by: "user-credit".into(),
        r#type: "sandbox".into(),
        name: "app".into(),
        state: rpc::EnvironmentState::Stopped.into(),
        desired_state: rpc::DesiredState::Stopped.into(),
        ..Default::default()
    }
}

async fn platform(State(state): State<Arc<Mutex<Fixture>>>, uri: Uri, _body: Bytes) -> Response {
    state.lock().unwrap().paths.push(uri.path().to_owned());
    match uri.path() {
        "/codewire.v1.OrganizationService/ListOrganizations" => {
            proto(rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: ORG.into(),
                        name: "Credit Org".into(),
                        slug: "credit-org".into(),
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
        "/codewire.v1.EnvironmentService/CreateEnvironment"
        | "/codewire.v1.EnvironmentService/StartEnvironment" => credit_exhausted(),
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

/// `cw --server URL --cloud ARGS`, signed in with an API key, private config,
/// run in `root`.
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
        .args(["--server", url, "--cloud"])
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

fn expected_text(url: &str) -> String {
    format!(
        "Credit Org has no compute credit, so it can't run cloud sandboxes.\n\
         Add a card or credit on its billing page: {url}/credit-org/billing/\n\
         Local sandboxes stay free: cw create --local\n"
    )
}

fn expected_json(url: &str) -> serde_json::Value {
    serde_json::json!({"error": {
        "code": "credit_exhausted",
        "message": "Credit Org has no compute credit, so it can't run cloud sandboxes.",
        "organization": {"id": ORG, "name": "Credit Org", "slug": "credit-org"},
        "billing_url": format!("{url}/credit-org/billing/"),
        "local_create": "cw create --local",
    }})
}

const CREATE: &[&str] = &[
    "create",
    "--image",
    "ubuntu:24.04",
    "--no-file",
    "--no-profile",
    "--no-network",
    "--yes",
];

#[tokio::test]
async fn a_create_refused_for_credit_says_what_the_dashboard_says() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(root.path(), &url, CREATE).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.ends_with(&expected_text(&url)), "{stderr}");
    assert!(!stderr.contains("create environment:"), "{stderr}");
    assert!(!stderr.contains(SERVER_MESSAGE), "{stderr}");
    assert_eq!(text(&output.stdout), "");

    let output = cw(root.path(), &url, &[CREATE, &["--output", "json"]].concat()).await;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json, expected_json(&url));
    // The text still reaches stderr for a person reading a CI log.
    assert_eq!(text(&output.stderr), expected_text(&url));

    let paths = state.lock().unwrap().paths.clone();
    assert!(
        paths.contains(&"/codewire.v1.EnvironmentService/CreateEnvironment".to_owned()),
        "{paths:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_start_refused_for_credit_says_what_the_dashboard_says() {
    let state = Arc::new(Mutex::new(Fixture::default()));
    let (url, server) = server(state.clone()).await;
    let root = tempfile::tempdir().unwrap();

    let output = cw(root.path(), &url, &["start", "app", "--output", "json"]).await;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json, expected_json(&url));
    assert_eq!(text(&output.stderr), expected_text(&url));

    let output = cw(root.path(), &url, &["start", "app"]).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.ends_with(&expected_text(&url)), "{stderr}");
    assert!(!stderr.contains("start environment:"), "{stderr}");
    assert_eq!(text(&output.stdout), "");

    let paths = state.lock().unwrap().paths.clone();
    assert!(
        paths.contains(&"/codewire.v1.EnvironmentService/StartEnvironment".to_owned()),
        "{paths:?}"
    );
    server.abort();
}
