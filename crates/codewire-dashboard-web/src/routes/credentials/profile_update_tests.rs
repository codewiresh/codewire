//! Regression proof for Settings › Credentials › Edit Profile: omitting the
//! `gemini` form field preserves a profile's existing Gemini binding at the
//! observed revision, while submitting `gemini=""` clears it and submitting a
//! credential ID sets it (#6555).

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileEntry, GetAccessProfileRequest, GetAccessProfileResponse,
    UpdateAccessProfileRequest, UpdateAccessProfileResponse,
};

use super::entries;

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ACCOUNT: &str = "synthetic-account";
const ACTION: &str = "/settings/credentials/_actions/profiles/update";
const PROFILE_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const CODEX_ID: &str = "11111111-1111-4111-8111-111111111111";
const GEMINI_ID: &str = "22222222-2222-4222-8222-222222222222";
const GEMINI_NEW_ID: &str = "33333333-3333-4333-8333-333333333333";
const GET_PROFILE_RPC: &str = "/codewire.v1.AccessProfileService/GetAccessProfile";
const UPDATE_PROFILE_RPC: &str = "/codewire.v1.AccessProfileService/UpdateAccessProfile";
const SHOWN_REVISION: u64 = 3;

type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct TestServer {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    TestServer { origin, task }
}

fn config(upstream: &str) -> crate::Config {
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: ORIGIN.into(),
        api_origin: upstream.parse().unwrap(),
        credential_origin: upstream.parse().unwrap(),
        identity_origin_string: upstream.into(),
        browser_api_origin: ORIGIN.into(),
        billing_origin: upstream.parse().unwrap(),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
        support_email: None,
        updates_site: None,
        analytics: None,
    }
}

fn proto(message: impl buffa::Message) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
}

fn profile(revision: u64, entries: Vec<AccessProfileEntry>) -> AccessProfile {
    AccessProfile {
        id: PROFILE_ID.into(),
        name: "work".into(),
        revision,
        entries,
        ..Default::default()
    }
}

async fn upstream(existing_entries: Vec<AccessProfileEntry>) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        let existing_entries = existing_entries.clone();
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push((path.clone(), body.to_vec()));
            match path.as_str() {
                "/api/auth/get-session" => Json(serde_json::json!({"user": {
                    "id": ACCOUNT, "email": "synthetic@example.test", "two_factor_enabled": true
                }}))
                .into_response(),
                GET_PROFILE_RPC => {
                    let req = GetAccessProfileRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(req.revision, Some(SHOWN_REVISION));
                    proto(GetAccessProfileResponse {
                        access_profile: Some(profile(SHOWN_REVISION, existing_entries)).into(),
                        ..Default::default()
                    })
                }
                UPDATE_PROFILE_RPC => {
                    let req = UpdateAccessProfileRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(req.access_profile_id, PROFILE_ID);
                    assert_eq!(req.expected_revision, SHOWN_REVISION);
                    proto(UpdateAccessProfileResponse {
                        access_profile: Some(profile(SHOWN_REVISION + 1, req.entries)).into(),
                        ..Default::default()
                    })
                }
                _ => (StatusCode::NOT_FOUND, "unexpected").into_response(),
            }
        }
    }));
    (serve(router).await, calls)
}

fn authority(csrf: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(
        header::COOKIE,
        format!("codewire.session_token=synthetic-session; codewire_ssr_csrf={csrf}")
            .parse()
            .unwrap(),
    );
    headers
}

async fn post_update(dashboard: &TestServer, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let csrf = crate::security::new_csrf_token();
    let shown = SHOWN_REVISION.to_string();
    let mut form: Vec<(&str, &str)> = vec![
        ("_csrf", csrf.as_str()),
        ("profile_id", PROFILE_ID),
        ("expected_revision", shown.as_str()),
    ];
    form.extend_from_slice(fields);
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .post(format!("{}{ACTION}", dashboard.origin))
        .headers(authority(&csrf))
        .form(&form)
        .send()
        .await
        .unwrap();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (response.status(), location)
}

fn update_requests(calls: &Calls) -> Vec<UpdateAccessProfileRequest> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == UPDATE_PROFILE_RPC)
        .map(|(_, body)| UpdateAccessProfileRequest::decode_from_slice(body).unwrap())
        .collect()
}

fn entry(slot: &str, id: &str) -> AccessProfileEntry {
    AccessProfileEntry {
        capability_slot: slot.into(),
        credential_id: id.into(),
        ..Default::default()
    }
}

#[test]
fn entries_are_closed_and_use_exact_credential_ids() {
    let id = "00000000-0000-4000-8000-000000000001";
    let profile_entries = entries(
        id.into(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    )
    .unwrap();
    assert_eq!(profile_entries.len(), 1);
    assert_eq!(profile_entries[0].capability_slot, "codex");
    assert_eq!(profile_entries[0].credential_id, id);
    let gemini_entries = entries(
        String::new(),
        String::new(),
        String::new(),
        id.into(),
        String::new(),
    )
    .unwrap();
    assert_eq!(gemini_entries.len(), 1);
    assert_eq!(gemini_entries[0].capability_slot, "gemini");
    assert_eq!(gemini_entries[0].credential_id, id);
    assert!(
        entries(
            "not-an-id".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn omitting_gemini_field_preserves_existing_binding_while_empty_string_clears_it() {
    let existing = vec![entry("codex", CODEX_ID), entry("gemini", GEMINI_ID)];

    // 1. Form without `gemini` (matches current template): preserves existing gemini binding.
    let (up, calls) = upstream(existing.clone()).await;
    let dashboard = serve(crate::app(config(&up.origin))).await;
    let (status, location) = post_update(
        &dashboard,
        &[
            ("codex", CODEX_ID),
            ("openai", ""),
            ("anthropic", ""),
            ("ssh", ""),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("message=profile-updated"), "{location}");
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == GET_PROFILE_RPC),
        "omitted gemini field must read the observed revision"
    );
    let sent = update_requests(&calls);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].entries,
        vec![entry("codex", CODEX_ID), entry("gemini", GEMINI_ID)]
    );

    // 2. Explicit `gemini=""` (from future UI "None" choice): clears gemini without reading.
    let (up, calls) = upstream(existing.clone()).await;
    let dashboard = serve(crate::app(config(&up.origin))).await;
    let (status, location) = post_update(
        &dashboard,
        &[
            ("codex", CODEX_ID),
            ("openai", ""),
            ("anthropic", ""),
            ("gemini", ""),
            ("ssh", ""),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("message=profile-updated"), "{location}");
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == GET_PROFILE_RPC),
        "explicit gemini=\"\" must not preserve the previous binding"
    );
    let sent = update_requests(&calls);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].entries, vec![entry("codex", CODEX_ID)]);

    // 3. Explicit `gemini=<new-id>`: replaces gemini with the validated ID.
    let (up, calls) = upstream(existing).await;
    let dashboard = serve(crate::app(config(&up.origin))).await;
    let (status, location) = post_update(
        &dashboard,
        &[
            ("codex", CODEX_ID),
            ("openai", ""),
            ("anthropic", ""),
            ("gemini", GEMINI_NEW_ID),
            ("ssh", ""),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("message=profile-updated"), "{location}");
    let sent = update_requests(&calls);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].entries,
        vec![entry("codex", CODEX_ID), entry("gemini", GEMINI_NEW_ID)]
    );
}
