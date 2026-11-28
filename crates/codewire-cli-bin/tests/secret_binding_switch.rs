//! The built `cw` while host-bound secrets are off
//! (`codewire_access::HOST_BOUND_SECRETS`, #4003): every binding flag of
//! `cw secrets set`, and `cw secrets presets`, is refused in one sentence
//! before anything is asked or sent, in either store.
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

const SENTENCE: &str = "ending a secret only to its hosts isn't available yet\n";

/// Records every request and answers none of them.
async fn platform(
    State(paths): State<Arc<Mutex<Vec<String>>>>,
    uri: Uri,
    _body: Bytes,
) -> Response {
    paths.lock().unwrap().push(uri.path().to_owned());
    StatusCode::NOT_IMPLEMENTED.into_response()
}

async fn cw(root: &Path, url: &str, args: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", root.join("config"))
        .env("CW_MESH_DATA_DIR", root.join("mesh"))
        .env("NO_COLOR", "1")
        .env("CODEWIRE_API_KEY", "cw_synthetic_switch_key")
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

#[tokio::test]
async fn every_binding_flag_and_presets_are_refused_before_any_request() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(platform).with_state(paths.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();

    for args in [
        &[
            "--cloud",
            "secrets",
            "--project=walk",
            "set",
            "FANCY_TOKEN",
            "--host",
            "api.fancy.com",
        ][..],
        &[
            "--cloud",
            "secrets",
            "--user",
            "set",
            "FANCY_TOKEN",
            "--remove-host",
            "api.fancy.com",
        ],
        &[
            "--cloud",
            "secrets",
            "--organization",
            "set",
            "FANCY_TOKEN",
            "--preset",
            "stripe",
        ],
        &[
            "--local",
            "secrets",
            "--user",
            "set",
            "FANCY_TOKEN",
            "--plain",
        ],
        &[
            "--local",
            "secrets",
            "--project=walk",
            "set",
            "FANCY_TOKEN",
            "--prefix",
            "",
        ],
        &["secrets", "set", "--basic"],
        &["secrets", "presets"],
        &["secrets", "presets", "--output", "json"],
    ] {
        let output = cw(root.path(), &url, args).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        // `x Sending …` or `✗ Sending …`, as the locale allows, or the bare
        // `sending …` that every `--output json` failure prints; never a
        // next step.
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
        assert!(stderr.ends_with(SENTENCE), "{args:?}: {stderr}");
        assert_eq!(String::from_utf8_lossy(&output.stdout), "", "{args:?}");
    }
    assert_eq!(*paths.lock().unwrap(), Vec::<String>::new());
    // Nothing reached the local store either: no authority was started.
    assert!(!root.path().join(".codewire/credentials-v1").exists());
    server.abort();
}
