//! The OpenBao client against a fake transit that keeps key versions and a
//! `min_decryption_version`, as OpenBao does. Every input is synthetic.

use std::sync::Mutex as StdMutex;

use axum::Router;
use axum::extract::{Json, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::post;
use serde_json::Value;

use super::*;
use crate::secret_envelope::OpenBaoTransitConfig;

const MOUNT: &str = "codewire-credentials-test";
const KEY: &str = "local-boot-seal";

#[derive(Default)]
struct Fake {
    latest: StdMutex<u32>,
    min: StdMutex<u32>,
    /// Every `hmac` a verify request carried, as received.
    verified: StdMutex<Vec<String>>,
    /// Every path the fake doesn't serve.
    unserved: StdMutex<Vec<String>>,
    down: StdMutex<bool>,
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Fake {
    fn rotate(&self) {
        let mut latest = lock(&self.latest);
        *latest += 1;
        *lock(&self.min) = (*latest - 1).max(1);
    }
}

fn mac(version: u32, input: &str) -> String {
    format!("vault:v{version}:mac-of-{input}")
}

fn authenticated(headers: &HeaderMap) -> bool {
    headers
        .get("X-Vault-Token")
        .is_some_and(|value| value == "bao-token")
}

async fn login() -> Json<Value> {
    Json(serde_json::json!({"auth": {"client_token": "bao-token", "lease_duration": 300}}))
}

#[derive(serde::Deserialize)]
struct HmacBody {
    input: Option<String>,
}

#[derive(serde::Deserialize)]
struct VerifyBody {
    input: Option<String>,
    hmac: Option<String>,
}

async fn hmac(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Json(body): Json<HmacBody>,
) -> (StatusCode, Json<Value>) {
    if *lock(&fake.down) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})));
    }
    let Some(input) = body.input.as_deref().filter(|_| authenticated(&headers)) else {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
    };
    let latest = *lock(&fake.latest);
    (
        StatusCode::OK,
        Json(serde_json::json!({"data": {"hmac": mac(latest, input)}})),
    )
}

async fn verify(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> (StatusCode, Json<Value>) {
    if *lock(&fake.down) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})));
    }
    let (Some(input), Some(seal)) = (body.input.as_deref(), body.hmac.as_deref()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
    };
    if !authenticated(&headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
    }
    lock(&fake.verified).push(seal.to_owned());
    let Some(version) = parse_transit_version(seal) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
    };
    // As OpenBao: a version below the minimum, or above the latest, is an
    // error, not an answer.
    if version < *lock(&fake.min) || version > *lock(&fake.latest) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
    }
    let valid = mac(version, input) == seal;
    (
        StatusCode::OK,
        Json(serde_json::json!({"data": {"valid": valid}})),
    )
}

async fn unserved(State(fake): State<Arc<Fake>>, uri: Uri) -> StatusCode {
    lock(&fake.unserved).push(uri.path().to_owned());
    StatusCode::NOT_FOUND
}

fn provider(address: &str) -> Arc<OpenBaoTransitProvider> {
    let config = OpenBaoTransitConfig::new(
        address.parse().unwrap(),
        "kubernetes".into(),
        "credential-role".into(),
        "credentials-transit".into(),
        "tenant-dek".into(),
        "cluster-test-1".into(),
    )
    .unwrap();
    Arc::new(
        OpenBaoTransitProvider::new(
            config,
            crate::openbao_workload_identity::static_workload_identity("projected-jwt"),
        )
        .unwrap(),
    )
}

async fn serve() -> (OpenBaoTransitHmac, Arc<Fake>, tokio::task::JoinHandle<()>) {
    let fake = Arc::new(Fake::default());
    *lock(&fake.latest) = 1;
    *lock(&fake.min) = 1;
    let app = Router::new()
        .route("/v1/auth/kubernetes/login", post(login))
        .route(&format!("/v1/{MOUNT}/hmac/{KEY}/sha2-256"), post(hmac))
        .route(&format!("/v1/{MOUNT}/verify/{KEY}/sha2-256"), post(verify))
        .fallback(unserved)
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = OpenBaoTransitHmac::new(
        provider(&format!("http://{address}")),
        MOUNT.into(),
        KEY.into(),
    )
    .unwrap();
    (client, fake, server)
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(30), future)
        .await
        .expect("the fake transit answers in time")
}

/// A seal verifies for its own input only, and verify sends it exactly as
/// sealed, on the key's hmac and verify paths and nowhere else.
#[tokio::test]
async fn a_seal_verifies_its_input_and_is_sent_back_unchanged() {
    let (client, fake, server) = serve().await;
    let seal = bounded(client.hmac(b"boot record")).await.unwrap();
    assert!(seal.starts_with("vault:v1:"));
    assert!(bounded(client.verify(b"boot record", &seal)).await.unwrap());
    assert!(
        !bounded(client.verify(b"another record", &seal))
            .await
            .unwrap()
    );
    assert_eq!(*lock(&fake.verified), [seal.clone(), seal]);
    assert!(lock(&fake.unserved).is_empty());
    server.abort();
}

/// After one rotation the previous version still verifies; after two it is
/// below the minimum, which OpenBao refuses and the client reads as a seal
/// that doesn't verify.
#[tokio::test]
async fn a_seal_survives_one_rotation_and_not_two() {
    let (client, fake, server) = serve().await;
    let first = bounded(client.hmac(b"boot record")).await.unwrap();
    fake.rotate();
    assert!(
        bounded(client.verify(b"boot record", &first))
            .await
            .unwrap()
    );
    let second = bounded(client.hmac(b"boot record")).await.unwrap();
    assert!(second.starts_with("vault:v2:"));
    fake.rotate();
    assert!(
        !bounded(client.verify(b"boot record", &first))
            .await
            .unwrap()
    );
    assert!(
        bounded(client.verify(b"boot record", &second))
            .await
            .unwrap()
    );
    server.abort();
}

/// A seal that isn't transit's shape is refused without asking OpenBao.
#[tokio::test]
async fn a_malformed_seal_is_refused_unasked() {
    let (client, fake, server) = serve().await;
    for seal in ["", "vault:v0:x", "vault:v1:", "other:v1:x"] {
        assert!(!bounded(client.verify(b"boot record", seal)).await.unwrap());
    }
    assert!(lock(&fake.verified).is_empty());
    server.abort();
}

/// OpenBao failing, or not there, is unavailable for both calls: never a
/// pass and never a refusal.
#[tokio::test]
async fn openbao_down_is_unavailable_for_both_calls() {
    let (client, fake, server) = serve().await;
    let seal = bounded(client.hmac(b"boot record")).await.unwrap();
    *lock(&fake.down) = true;
    assert_eq!(
        bounded(client.hmac(b"boot record")).await,
        Err(TransitHmacError::Unavailable)
    );
    assert_eq!(
        bounded(client.verify(b"boot record", &seal)).await,
        Err(TransitHmacError::Unavailable)
    );
    server.abort();
    // Aborted on purpose: only the listener's absence matters here.
    let _ = server.await;
    let gone =
        OpenBaoTransitHmac::new(provider("http://127.0.0.1:1"), MOUNT.into(), KEY.into()).unwrap();
    assert_eq!(
        bounded(gone.verify(b"boot record", &seal)).await,
        Err(TransitHmacError::Unavailable)
    );
}

#[test]
fn the_key_is_a_plain_segment_and_never_the_envelope_key() {
    let provider = provider("http://127.0.0.1:1");
    for (mount, key) in [
        (MOUNT, "tenant-dek"),
        (MOUNT, "a/b"),
        ("", KEY),
        ("a/b", KEY),
        (MOUNT, ""),
    ] {
        assert!(
            OpenBaoTransitHmac::new(provider.clone(), mount.into(), key.into()).is_err(),
            "{mount} {key}"
        );
    }
}
