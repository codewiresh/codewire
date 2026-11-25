//! Registered-route proof for Settings › Credentials › Disconnect GitHub
//! (#4717 C6) against a synthetic session and credential services: an active
//! GitHub connection is revoked at its exact revision before the revoked
//! revision is deleted, and the page says what GitHub answered. No real
//! account or provider is used.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    Credential, CredentialAuthenticationKind, CredentialStatus, DeleteCredentialRequest,
    DeleteCredentialResponse, GetCredentialResponse, ProviderRevocation, ProviderRevocationOutcome,
    RevokeCredentialRequest, RevokeCredentialResponse,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ACCOUNT: &str = "synthetic-account";
const ACTION: &str = "/settings/credentials/_actions/credentials/delete";
const CREDENTIAL: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const GET_RPC: &str = "/codewire.v1.CredentialService/GetCredential";
const REVOKE_RPC: &str = "/codewire.v1.CredentialMutationService/RevokeCredential";
const DELETE_RPC: &str = "/codewire.v1.CredentialMutationService/DeleteCredential";
const SHOWN: u64 = 4;

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

/// The account's GitHub connection at `generation`, in `status`.
fn github(status: CredentialStatus, generation: u64) -> Credential {
    Credential {
        id: CREDENTIAL.into(),
        name: "GitHub".into(),
        provider: "github".into(),
        authentication_kind: CredentialAuthenticationKind::Oauth.into(),
        status: status.into(),
        revocation_generation: generation,
        ..Default::default()
    }
}

/// The synthetic services: an enrolled session, the active GitHub
/// connection at the shown revision, a revoke answered with `answer` (or
/// refused when `None`), and a delete that succeeds unless `delete_fails`.
async fn upstream(
    answer: Option<ProviderRevocationOutcome>,
    delete_fails: bool,
) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push((path.clone(), body.to_vec()));
            match path.as_str() {
                "/api/auth/get-session" => Json(serde_json::json!({"user": {
                    "id": ACCOUNT, "email": "synthetic@example.test", "two_factor_enabled": true
                }}))
                .into_response(),
                GET_RPC => proto(GetCredentialResponse {
                    credential: Some(github(CredentialStatus::Active, SHOWN)).into(),
                    ..Default::default()
                }),
                REVOKE_RPC => match answer {
                    Some(outcome) => proto(RevokeCredentialResponse {
                        credential: Some(github(CredentialStatus::Revoked, SHOWN + 1)).into(),
                        provider_revocation: Some(ProviderRevocation {
                            outcome: outcome.into(),
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    }),
                    None => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({"code": "unavailable", "message": "synthetic"})),
                    )
                        .into_response(),
                },
                DELETE_RPC if delete_fails => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"code": "unavailable", "message": "synthetic"})),
                )
                    .into_response(),
                DELETE_RPC => proto(DeleteCredentialResponse::default()),
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

/// Posts Disconnect for the revision the page showed; returns the redirect.
async fn disconnect(dashboard: &TestServer) -> (StatusCode, String) {
    let csrf = crate::security::new_csrf_token();
    let shown = SHOWN.to_string();
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .post(format!("{}{ACTION}", dashboard.origin))
        .headers(authority(&csrf))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("credential_id", CREDENTIAL),
            ("expected_revocation_generation", shown.as_str()),
        ])
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

/// The mutation calls in order, by RPC.
fn mutations(calls: &Calls) -> Vec<(String, Vec<u8>)> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == REVOKE_RPC || path == DELETE_RPC)
        .cloned()
        .collect()
}

#[tokio::test]
async fn disconnect_revokes_the_shown_revision_then_deletes_the_revoked_one() {
    for (outcome, message) in [
        (
            ProviderRevocationOutcome::Confirmed,
            "message=github-disconnected-confirmed",
        ),
        (
            ProviderRevocationOutcome::Failed,
            "message=github-disconnected",
        ),
    ] {
        let (services, calls) = upstream(Some(outcome), false).await;
        let dashboard = serve(crate::app(config(&services.origin))).await;
        let (status, location) = disconnect(&dashboard).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{outcome:?}");
        assert!(location.contains(message), "{outcome:?}: {location}");
        if outcome == ProviderRevocationOutcome::Failed {
            assert!(!location.contains("confirmed"), "{location}");
        }
        let mutations = mutations(&calls);
        assert_eq!(
            mutations
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [REVOKE_RPC, DELETE_RPC],
            "revoked first, then deleted"
        );
        let revoke = RevokeCredentialRequest::decode_from_slice(&mutations[0].1).unwrap();
        assert_eq!(revoke.credential_id, CREDENTIAL);
        assert_eq!(revoke.expected_revocation_generation, SHOWN);
        let delete = DeleteCredentialRequest::decode_from_slice(&mutations[1].1).unwrap();
        assert_eq!(delete.credential_id, CREDENTIAL);
        assert_eq!(delete.expected_revocation_generation, SHOWN + 1);
    }
}

#[tokio::test]
async fn a_disconnect_whose_revoke_fails_deletes_nothing() {
    let (services, calls) = upstream(None, false).await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let (status, location) = disconnect(&dashboard).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("error="), "{location}");
    assert_eq!(
        mutations(&calls)
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        [REVOKE_RPC],
        "nothing is deleted after a failed revoke"
    );
}

/// The revoke held but the record stayed: the page says GitHub is
/// disconnected and to disconnect again (owner, 2026-11-17, on #4717).
#[tokio::test]
async fn a_disconnect_whose_delete_fails_after_the_revoke_says_to_disconnect_again() {
    let (services, calls) = upstream(Some(ProviderRevocationOutcome::Confirmed), true).await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let (status, location) = disconnect(&dashboard).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.contains("error=github-revoked-not-removed"),
        "{location}"
    );
    assert_eq!(
        mutations(&calls)
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        [REVOKE_RPC, DELETE_RPC]
    );
    assert_eq!(
        super::super::approved_error("github-revoked-not-removed"),
        "GitHub is disconnected, but Codewire couldn't remove its record. Disconnect again to finish."
    );
}
