//! `ReportCredentialUses` through the real Kubernetes driver against an
//! in-process fake API server: only the credential service's own identity
//! gets past authentication, and a report is parsed into nothing but a
//! provider, a checked host and counts.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header::AUTHORIZATION};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_daemon_proto::{
    CREDENTIAL_SERVICE_SERVICE_ACCOUNT, EGRESS_NODE_SERVICE_ACCOUNT, SANDBOX_SERVICE_ACCOUNT,
};
use http_body_util::BodyExt as _;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use serde_json::{Value, json};
use tower::{ServiceExt, service_fn};

use super::*;
use crate::runtime::kubernetes::rendering::KubernetesRenderConfig;

const SERVER: &str = "dev";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const CREDENTIAL: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000001";

fn token() -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
    format!("{header}.{payload}.c2ln")
}

/// A cluster whose TokenReview says the token is `account`'s in `namespace`,
/// for the audience it was asked about.
fn cluster(namespace: &'static str, account: &'static str) -> kube::Client {
    let service = service_fn(move |request: Request<kube::client::Body>| async move {
        assert_eq!(
            request.uri().path(),
            "/apis/authentication.k8s.io/v1/tokenreviews",
            "authentication reads nothing but the review"
        );
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let asked: TokenReview = serde_json::from_slice(&body).unwrap();
        let status = TokenReviewStatus {
            authenticated: Some(true),
            audiences: asked.spec.audiences,
            user: Some(UserInfo {
                username: Some(format!("system:serviceaccount:{namespace}:{account}")),
                extra: Some(BTreeMap::from([
                    (
                        "authentication.kubernetes.io/pod-name".into(),
                        vec!["caller-0".into()],
                    ),
                    (
                        "authentication.kubernetes.io/pod-uid".into(),
                        vec!["0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01".into()],
                    ),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };
        let review = TokenReview {
            status: Some(status),
            ..Default::default()
        };
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(StatusCode::CREATED)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&review).unwrap()))
                .unwrap(),
        )
    });
    kube::Client::new(service, SERVER)
}

/// A pool that never connects: a request that reaches the database is
/// answered unavailable.
fn unreachable_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://unused@127.0.0.1:1/unused")
        .unwrap()
}

fn app(client: kube::Client) -> axum::Router {
    let driver = crate::runtime::kubernetes::KubernetesDriver::shared(
        client,
        KubernetesRenderConfig {
            server_namespace: SERVER.into(),
            ..Default::default()
        },
    );
    codewire_server_core::connect::connect_router(router(Arc::new(AuditReportState {
        attestation: driver,
        server_namespace: SERVER.into(),
        pool: unreachable_pool(),
        unbound: AtomicU64::new(0),
        foreign: AtomicU64::new(0),
    })))
}

fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap()
}

fn report() -> Value {
    let now = now_ms();
    json!({
        "podUid": POD,
        "uses": [{
            "credentialId": CREDENTIAL,
            "provider": "openai",
            "host": "api.openai.com",
            "firstUnixMs": now.to_string(),
            "lastUnixMs": now.to_string(),
            "count": "3",
        }],
    })
}

async fn call(app: axum::Router, bearer: Option<String>, body: Value) -> StatusCode {
    let mut request =
        Request::post("/codewire.internal.v1.SandboxAuditService/ReportCredentialUses")
            .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let request = request
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), app.oneshot(request))
        .await
        .expect("the call answers")
        .unwrap()
        .status()
}

/// Connect's JSON status codes as HTTP statuses.
const UNAUTHENTICATED: StatusCode = StatusCode::UNAUTHORIZED;
const PERMISSION_DENIED: StatusCode = StatusCode::FORBIDDEN;
const UNAVAILABLE: StatusCode = StatusCode::SERVICE_UNAVAILABLE;
const INVALID_ARGUMENT: StatusCode = StatusCode::BAD_REQUEST;

#[tokio::test]
async fn only_the_credential_service_in_this_namespace_reports_credential_uses() {
    // Each of these is refused before the report is read: the pool behind
    // the service never connects, so reaching it would answer unavailable.
    for (namespace, account) in [
        (SERVER, EGRESS_NODE_SERVICE_ACCOUNT),
        (SERVER, SANDBOX_SERVICE_ACCOUNT),
        (
            SERVER,
            codewire_daemon_proto::CREDENTIAL_RELAY_SERVICE_ACCOUNT,
        ),
        ("elsewhere", CREDENTIAL_SERVICE_SERVICE_ACCOUNT),
    ] {
        assert_eq!(
            call(app(cluster(namespace, account)), Some(token()), report()).await,
            PERMISSION_DENIED,
            "{account} in {namespace}"
        );
    }
    let service = || app(cluster(SERVER, CREDENTIAL_SERVICE_SERVICE_ACCOUNT));
    assert_eq!(call(service(), None, report()).await, UNAUTHENTICATED);
    // The credential service gets past authentication: a malformed report is
    // refused, a well-formed one reaches the database.
    assert_eq!(
        call(
            service(),
            Some(token()),
            json!({"podUid": "not-a-pod", "uses": []})
        )
        .await,
        INVALID_ARGUMENT
    );
    assert_eq!(call(service(), Some(token()), report()).await, UNAVAILABLE);
}

fn wire_use(host: &str, withheld: bool, first: u64, last: u64, count: u64) -> CredentialUse {
    CredentialUse {
        credential_id: CREDENTIAL.into(),
        provider: "openai".into(),
        host: host.into(),
        host_withheld: withheld,
        first_unix_ms: first,
        last_unix_ms: last,
        count,
        ..Default::default()
    }
}

#[test]
fn a_report_parses_into_a_provider_a_checked_host_and_counts() {
    let now = Utc::now();
    let ms = u64::try_from(now.timestamp_millis()).unwrap();
    let hour_start = u64::try_from(now.timestamp().div_euclid(3600) * 3600 * 1000).unwrap();
    let parsed = parse_uses(
        &[
            wire_use("api.openai.com", false, hour_start, ms, 4),
            wire_use("", true, ms, ms, 1),
            // A name the check refuses is withheld, whatever the report says.
            wire_use("evil\u{1b}[2J.example.com", false, ms, ms, 2),
            wire_use("API.OpenAI.com", false, ms, ms, 1),
        ],
        now,
    )
    .expect("well formed");
    assert_eq!(
        parsed
            .iter()
            .map(|reported| reported.host.as_deref())
            .collect::<Vec<_>>(),
        [Some("api.openai.com"), None, None, None]
    );
    assert_eq!(parsed[0].credential.as_str(), CREDENTIAL);
    assert_eq!(parsed[0].provider.as_str(), "openai");
    assert_eq!(parsed[0].count, 4);
    assert_eq!(
        parsed[0].first.timestamp_millis(),
        i64::try_from(hour_start).unwrap()
    );

    let hour_ago = hour_start - 1;
    for malformed in [
        wire_use("api.openai.com", false, ms, ms, 0),
        wire_use("api.openai.com", false, ms, ms - 1, 1),
        // A fold never spans two hours.
        wire_use("api.openai.com", false, hour_ago, ms, 1),
        wire_use("api.openai.com", true, ms, ms, 1),
        wire_use(
            "api.openai.com",
            false,
            ms - 3 * 3_600_000,
            ms - 3 * 3_600_000,
            1,
        ),
        wire_use("api.openai.com", false, ms + 3_600_000, ms + 3_600_000, 1),
        CredentialUse {
            credential_id: "Not An Id".into(),
            ..wire_use("api.openai.com", false, ms, ms, 1)
        },
        CredentialUse {
            provider: String::new(),
            ..wire_use("api.openai.com", false, ms, ms, 1)
        },
    ] {
        assert!(
            parse_uses(std::slice::from_ref(&malformed), now).is_none(),
            "{malformed:?}"
        );
    }
    assert!(parse_uses(&[], now).is_none());
    let many = vec![wire_use("api.openai.com", false, ms, ms, 1); MAX_USES_PER_REPORT + 1];
    assert!(parse_uses(&many, now).is_none());
}

/// A credential use's event holds the stored provider and name and the
/// host, and nothing else: no value, placeholder, method, path, header or
/// body can be named by it (SPEC.md "Never recorded").
#[test]
fn a_credential_use_event_carries_only_its_allowed_fields() {
    let now = Utc::now();
    let ms = u64::try_from(now.timestamp_millis()).unwrap();
    let held = HeldCredential {
        name: "Team OpenAI".into(),
        provider: "openai".into(),
    };
    for (host, withheld, allowed) in [
        (
            "api.openai.com",
            false,
            &["action", "host", "name", "provider"][..],
        ),
        (
            "",
            true,
            &["action", "host", "name", "provider", "withheld"][..],
        ),
    ] {
        let parsed = parse_uses(&[wire_use(host, withheld, ms, ms, 1)], now).unwrap();
        let fields = serde_json::to_value(credential_used(&held, &parsed[0])).unwrap();
        let mut names: Vec<_> = fields.as_object().unwrap().keys().cloned().collect();
        names.sort();
        assert_eq!(names, allowed);
        assert_eq!(fields["action"], "used");
        assert_eq!(fields["name"], "Team OpenAI");
    }
}
