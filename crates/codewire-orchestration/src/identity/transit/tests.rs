use std::sync::Mutex as StdMutex;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::json;

use super::*;
use crate::identity::keys::tests::key_read;
use codewire_protected_store::openbao_workload_identity::static_workload_identity;

pub(crate) type Recorded = Arc<StdMutex<Vec<(String, String, String)>>>;

/// A 64-byte signature, base64url, as OpenBao's JWS marshaling gives it.
pub(crate) const SIGNATURE: &str =
    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QA";

/// An OpenBao that answers only the calls this client may make, and
/// records each one as (method and path, token, body).
async fn fake_openbao(cluster_id: &'static str) -> (Url, Recorded) {
    fake_openbao_with(
        cluster_id,
        key_read(
            &[(4, "2026-11-01T00:00:00Z"), (5, "2026-11-13T00:00:00Z")],
            4,
            4,
        ),
    )
    .await
}

/// [`fake_openbao`] listing the key as `read`. A sign answers a valid
/// JWS signature made by the version the request names.
pub(crate) async fn fake_openbao_with(
    cluster_id: &'static str,
    read: serde_json::Value,
) -> (Url, Recorded) {
    let recorded: Recorded = Arc::default();
    let captured = recorded.clone();
    let app = Router::new().fallback(move |request: Request| {
        let captured = captured.clone();
        let read = read.clone();
        async move {
            let call = format!("{} {}", request.method(), request.uri().path());
            let token = request
                .headers()
                .get("X-Vault-Token")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = to_bytes(request.into_body(), 4096).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            captured.lock().unwrap().push((call.clone(), token.clone(), body.clone()));
            let authorized = token == "bao-token";
            match call.as_str() {
                "GET /v1/sys/health" => axum::Json(json!({"cluster_id": cluster_id})).into_response(),
                "POST /v1/auth/cw-dev-k8s/login"
                    if serde_json::from_str::<serde_json::Value>(&body).unwrap()
                        == json!({"role": "sandbox-identity-signer-cw-dev", "jwt": "projected-jwt"}) =>
                {
                    axum::Json(json!({"auth": {"client_token": "bao-token", "lease_duration": 300}}))
                        .into_response()
                }
                "GET /v1/codewire-identity-dev/keys/sandbox-identity" if authorized => {
                    axum::Json(json!({"data": read})).into_response()
                }
                "POST /v1/codewire-identity-dev/sign/sandbox-identity" if authorized => {
                    let request: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let version = request["key_version"].as_u64().unwrap();
                    axum::Json(json!({"data": {
                        "key_version": version,
                        "signature": format!("vault:v{version}:{}", SIGNATURE),
                    }}))
                    .into_response()
                }
                "POST /v1/codewire-identity-dev/keys/sandbox-identity/rotate"
                | "POST /v1/codewire-identity-dev/keys/sandbox-identity/config"
                    if authorized =>
                {
                    StatusCode::NO_CONTENT.into_response()
                }
                _ => StatusCode::FORBIDDEN.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (Url::parse(&format!("http://{address}")).unwrap(), recorded)
}

pub(crate) fn signature() -> JwsSignature {
    JwsSignature(SIGNATURE.to_owned())
}

pub(crate) fn client(address: Url) -> TransitKeyClient {
    TransitKeyClient::new(
        TransitKeyConfig {
            address,
            auth_mount: "cw-dev-k8s".to_owned(),
            role: "sandbox-identity-signer-cw-dev".to_owned(),
            transit_mount: "codewire-identity-dev".to_owned(),
            expected_cluster_id: "cluster-dev".to_owned(),
        },
        static_workload_identity("projected-jwt"),
    )
    .unwrap()
}

#[tokio::test]
async fn the_client_reads_rotates_and_raises_minimums_on_its_own_key_only() {
    let (address, recorded) = fake_openbao("cluster-dev").await;
    let client = client(address);

    let key_set = client.read_key().await.unwrap();
    assert_eq!(
        serde_json::to_value(key_set.jwks()).unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    client.rotate().await.unwrap();
    client.raise_minimums(5).await.unwrap();

    let calls = recorded.lock().unwrap().clone();
    let without_health: Vec<_> = calls
        .iter()
        .filter(|(call, ..)| call != "GET /v1/sys/health")
        .map(|(call, token, body)| (call.as_str(), token.as_str(), body.as_str()))
        .collect();
    assert_eq!(
        without_health,
        [
            (
                "POST /v1/auth/cw-dev-k8s/login",
                "",
                r#"{"role":"sandbox-identity-signer-cw-dev","jwt":"projected-jwt"}"#
            ),
            (
                "GET /v1/codewire-identity-dev/keys/sandbox-identity",
                "bao-token",
                ""
            ),
            (
                "POST /v1/codewire-identity-dev/keys/sandbox-identity/rotate",
                "bao-token",
                ""
            ),
            (
                "POST /v1/codewire-identity-dev/keys/sandbox-identity/config",
                "bao-token",
                r#"{"min_decryption_version":5,"min_encryption_version":5}"#
            ),
        ],
        "one login, then exactly the key's own read, rotate and minimums"
    );
    // Every call first checks it is talking to the configured cluster.
    assert_eq!(calls.len() - without_health.len(), 3);
}

#[tokio::test]
async fn another_cluster_is_refused_before_any_login() {
    let (address, recorded) = fake_openbao("some-other-cluster").await;
    let error = client(address).read_key().await.unwrap_err();
    assert!(matches!(
        error,
        TransitError::InvalidResponse(TransitStage::Authority)
    ));
    let calls: Vec<_> = recorded
        .lock()
        .unwrap()
        .iter()
        .map(|(call, ..)| call.clone())
        .collect();
    assert_eq!(calls, ["GET /v1/sys/health"]);
}

#[tokio::test]
async fn a_sign_names_the_version_that_signs_now_in_jws_marshaling() {
    let now = chrono::Utc::now();
    let older = (now - chrono::Duration::hours(25)).to_rfc3339();
    let created = now.to_rfc3339();
    let (address, recorded) = fake_openbao_with(
        "cluster-dev",
        key_read(&[(1, older.as_str()), (2, created.as_str())], 1, 1),
    )
    .await;
    let client = client(address);

    let key = client.read_key().await.unwrap().signing_key(now).unwrap();
    let signature = client.sign(key, b"header.payload").await.unwrap();
    assert_eq!(signature.as_str(), SIGNATURE);

    let calls = recorded.lock().unwrap().clone();
    let (call, token, body) = calls.last().unwrap();
    assert_eq!(
        (call.as_str(), token.as_str()),
        (
            "POST /v1/codewire-identity-dev/sign/sandbox-identity",
            "bao-token"
        )
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        json!({"input": "aGVhZGVyLnBheWxvYWQ=", "key_version": 1, "marshaling_algorithm": "jws"}),
        "version 2 is a day too young to sign"
    );
}

#[test]
fn only_a_64_byte_signature_from_the_named_version_is_accepted() {
    let from = |value: &str| JwsSignature::from_transit(value, 3);
    assert_eq!(
        from(&format!("vault:v3:{SIGNATURE}")),
        Some(JwsSignature(SIGNATURE.to_owned()))
    );
    for value in [
        format!("vault:v4:{SIGNATURE}"),
        format!("vault:v3:{}", &SIGNATURE[..40]),
        format!("vault:v3:{SIGNATURE}="),
        format!("vault:v3:{}", SIGNATURE.replace('_', "/")),
        SIGNATURE.to_owned(),
    ] {
        assert_eq!(from(&value), None, "{value}");
    }
}
