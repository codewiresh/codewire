//! Rust-owned black-box wire contract for the real coordinator binary.
//!
//! The selected service harness loads the deterministic PostgreSQL fixture,
//! starts `codewire-coordinator`, and runs this test against its TCP listener.
//! Hermetic unit tests retain the protocol-policy and mixed-transport matrix;
//! this suite owns the deployed health, raw-WebSocket guards, production
//! deleted-route guards, production credential dispatch, canonical Connect
//! errors, and peer round trip.

use std::time::Duration;

use base64::Engine as _;
use codewire_proto::codewire::internal::v1::{
    CoordinateHello as Hello, CoordinateNode as Node, CoordinateRequest, CoordinateResponse,
    CoordinatorServiceClient, coordinate_request, coordinate_response,
};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{ConnectError, ErrorCode};
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, COOKIE};
use reqwest::{Client, StatusCode};
use sha2::Sha256;
use uuid::Uuid;

/// How long these tests wait for the service under test: a hang guard, not a
/// speed expectation (docs/dev/AGENT-WORKFLOW.md "Failure convergence"). The
/// rejections they check are immediate server checks; on a loaded service lane
/// a 10-15 s client deadline fired first (#4315).
const SERVICE_HANG_GUARD: Duration = Duration::from_secs(120);
const ORG_ID: &str = "org_coordinator_contract";
const RUNNING_ENV_ID: &str = "00000000-0000-4000-8000-000000000901";
const STOPPED_ENV_ID: &str = "00000000-0000-4000-8000-000000000902";
const UNKNOWN_ENV_ID: &str = "00000000-0000-4000-8000-000000000999";
const SESSION_COOKIE: &str = "codewire.session_token";
/// The seeded running environment's operation generation.
const RUNNING_GENERATION: i64 = 1;

struct Harness {
    base_url: String,
    session_token: String,
    session_secret: String,
    http: Client,
}

impl Harness {
    fn from_env() -> Self {
        assert_eq!(required_env("COORDINATOR_SEEDED"), "1");
        Self {
            base_url: required_env("COORDINATOR_BASE_URL")
                .trim_end_matches('/')
                .to_owned(),
            session_token: required_env("COORDINATOR_USER_SESSION_TOKEN"),
            session_secret: required_env("COORDINATOR_SESSION_SECRET"),
            http: Client::builder()
                .timeout(SERVICE_HANG_GUARD)
                .pool_max_idle_per_host(0)
                .build()
                .expect("build coordinator contract client"),
        }
    }

    fn client(
        &self,
        cookie: Option<&str>,
        bearer: Option<&str>,
    ) -> CoordinatorServiceClient<HttpClient> {
        let mut config = ClientConfig::new(self.base_url.parse().expect("coordinator base URL"))
            .with_default_timeout(SERVICE_HANG_GUARD);
        if let Some(token) = cookie {
            config = config.with_default_header(COOKIE, format!("{SESSION_COOKIE}={token}"));
        }
        if let Some(token) = bearer {
            config = config.with_default_header(AUTHORIZATION, format!("Bearer {token}"));
        }
        CoordinatorServiceClient::new(HttpClient::plaintext_http2_only(), config)
    }

    async fn assert_health_and_raw_guards(&self) {
        for path in ["/healthz", "/readyz"] {
            let response = self
                .http
                .get(format!("{}{path}", self.base_url))
                .send()
                .await
                .unwrap_or_else(|error| panic!("GET {path}: {error}"));
            assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        }

        for path in [
            format!(
                "/api/v1/organizations/00000000-0000-0000-0000-000000000000/environments/{RUNNING_ENV_ID}/coordinate"
            ),
            "/api/v1/internal/gateway/coordinate".into(),
        ] {
            self.assert_raw_status(&path, None, StatusCode::NOT_FOUND)
                .await;
        }
    }

    async fn assert_raw_status(&self, path: &str, bearer: Option<&str>, expected: StatusCode) {
        let mut request = self.http.get(format!("{}{path}", self.base_url));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|error| panic!("GET {path}: {error}"));
        assert_eq!(response.status(), expected, "GET {path}");
    }

    async fn assert_rejection_codes(&self) {
        let sidecar = peer_token(&self.session_secret, RUNNING_ENV_ID, RUNNING_GENERATION);
        let stale = peer_token(&self.session_secret, RUNNING_ENV_ID, RUNNING_GENERATION + 1);
        let legacy = legacy_token(&self.session_secret, RUNNING_ENV_ID, "coordinate");
        let cases = [
            (
                None,
                None,
                CoordinateRequest::default(),
                ErrorCode::InvalidArgument,
            ),
            (
                None,
                None,
                request(Node {
                    id: Uuid::new_v4().to_string(),
                    ..sample_node(0x31, 0x32)
                }),
                ErrorCode::InvalidArgument,
            ),
            (
                None,
                None,
                request(Hello {
                    org_id: ORG_ID.into(),
                    environment_id: RUNNING_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::Unauthenticated,
            ),
            (
                None,
                Some(legacy.as_str()),
                request(Hello {
                    environment_id: RUNNING_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::Unauthenticated,
            ),
            (
                None,
                Some(stale.as_str()),
                request(Hello {
                    environment_id: RUNNING_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::Unauthenticated,
            ),
            (
                None,
                Some(sidecar.as_str()),
                request(Hello {
                    environment_id: UNKNOWN_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::Unauthenticated,
            ),
            (
                None,
                Some(sidecar.as_str()),
                request(Hello {
                    org_id: ORG_ID.into(),
                    environment_id: RUNNING_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::InvalidArgument,
            ),
            (
                Some(self.session_token.as_str()),
                None,
                request(Hello {
                    org_id: "org_coordinator_contract_unknown".into(),
                    environment_id: RUNNING_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::NotFound,
            ),
            (
                Some(self.session_token.as_str()),
                None,
                request(Hello {
                    org_id: ORG_ID.into(),
                    environment_id: UNKNOWN_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::NotFound,
            ),
            (
                Some(self.session_token.as_str()),
                None,
                request(Hello {
                    org_id: ORG_ID.into(),
                    environment_id: STOPPED_ENV_ID.into(),
                    ..Default::default()
                }),
                ErrorCode::FailedPrecondition,
            ),
        ];

        for (cookie, bearer, first, expected) in cases {
            let mut stream = self
                .client(cookie, bearer)
                .coordinate()
                .await
                .expect("open Coordinate");
            stream
                .send(first)
                .await
                .expect("send rejected Coordinate request");
            stream.close_send();
            let error = stream
                .message::<CoordinateResponse>()
                .await
                .expect_err("rejected Coordinate request returned data");
            assert_eq!(error.code, expected, "Coordinate rejection: {error:?}");
        }
    }

    async fn assert_peer_round_trip(&self) {
        let sidecar_token = peer_token(&self.session_secret, RUNNING_ENV_ID, RUNNING_GENERATION);
        let mut sidecar = self
            .client(None, Some(&sidecar_token))
            .coordinate()
            .await
            .expect("open sidecar Coordinate");
        sidecar
            .send(request(Hello {
                environment_id: RUNNING_ENV_ID.into(),
                ..Default::default()
            }))
            .await
            .expect("send sidecar hello");
        expect_derp_map(&mut sidecar).await;

        let mut user = self
            .client(Some(&self.session_token), None)
            .coordinate()
            .await
            .expect("open user Coordinate");
        user.send(request(Hello {
            org_id: ORG_ID.into(),
            environment_id: RUNNING_ENV_ID.into(),
            ..Default::default()
        }))
        .await
        .expect("send user hello");
        expect_derp_map(&mut user).await;

        let user_node = sample_node(0x11, 0x12);
        user.send(request(user_node.clone()))
            .await
            .expect("send user node");
        let assigned_user = expect_peer(&mut sidecar, &user_node).await;
        assert!(Uuid::parse_str(&assigned_user.id).is_ok());
        assert_ne!(assigned_user.id, user_node.id);

        let sidecar_node = Node {
            id: RUNNING_ENV_ID.into(),
            ..sample_node(0x21, 0x22)
        };
        sidecar
            .send(request(sidecar_node.clone()))
            .await
            .expect("send sidecar node");
        let received_sidecar = expect_peer(&mut user, &sidecar_node).await;
        assert_eq!(received_sidecar, sidecar_node);

        user.close_send();
        sidecar.close_send();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the selected coordinator service harness"]
async fn configured_coordinator_wire_contract() {
    let harness = Harness::from_env();
    harness.assert_health_and_raw_guards().await;
    harness.assert_rejection_codes().await;
    harness.assert_peer_round_trip().await;
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required by the selected contract"))
}

fn request(message: impl Into<coordinate_request::Msg>) -> CoordinateRequest {
    CoordinateRequest {
        msg: Some(message.into()),
        ..Default::default()
    }
}

fn sample_node(key_byte: u8, disco_byte: u8) -> Node {
    let mut node = Node {
        id: Uuid::new_v4().to_string(),
        as_of: Some(buffa_types::Timestamp::from_unix_secs(1_752_321_600)).into(),
        key: format!("nodekey:{}", format!("{key_byte:02x}").repeat(32)),
        disco_key: format!("discokey:{}", format!("{disco_byte:02x}").repeat(32)),
        preferred_derp: 1,
        endpoints: vec!["192.0.2.10:41641".into()],
        addresses: vec!["fd7a:115c:a1e0::901/128".into()],
        ..Default::default()
    };
    node.derp_latency.insert("1".into(), 0.01);
    node
}

fn peer_token(secret: &str, environment_id: &str, generation: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    codewire_server_core::peer_token::issue(secret, environment_id, generation, now + 600)
        .expect("issue peer token")
}

/// The retired coordinate-scope format, which the coordinator now refuses.
fn legacy_token(secret: &str, environment_id: &str, scope: &str) -> String {
    let payload = serde_json::to_vec(&serde_json::json!({
        "environment_id": environment_id,
        "scope": scope,
    }))
    .expect("serialize legacy token payload");
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = engine.encode(payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("legacy token key");
    mac.update(payload.as_bytes());
    format!("{payload}.{}", engine.encode(mac.finalize().into_bytes()))
}

type CoordinateStream = connectrpc::client::BidiStream<
    <HttpClient as connectrpc::client::ClientTransport>::ResponseBody,
    CoordinateRequest,
    codewire_proto::codewire::internal::v1::CoordinateResponseView<'static>,
>;

async fn next_message(stream: &mut CoordinateStream) -> Result<CoordinateResponse, ConnectError> {
    let message = tokio::time::timeout(SERVICE_HANG_GUARD, stream.message::<CoordinateResponse>())
        .await
        .expect("Coordinate response timed out")?
        .expect("Coordinate response stream ended");
    Ok(message.to_owned_message())
}

async fn expect_derp_map(stream: &mut CoordinateStream) {
    loop {
        match next_message(stream).await.expect("receive DERP map").msg {
            Some(coordinate_response::Msg::DerpMap(map)) => {
                assert!(!map.derp_map_json.is_empty());
                assert!(serde_json::from_slice::<serde_json::Value>(&map.derp_map_json).is_ok());
                return;
            }
            Some(coordinate_response::Msg::Ping(_)) => {}
            other => panic!("expected DERP map, got {other:?}"),
        }
    }
}

async fn expect_peer(stream: &mut CoordinateStream, expected: &Node) -> Node {
    loop {
        match next_message(stream).await.expect("receive peer update").msg {
            Some(coordinate_response::Msg::PeerUpdate(update)) => {
                if let Some(node) = update
                    .nodes
                    .into_iter()
                    .find(|node| node.key == expected.key)
                {
                    let mut normalized = node.clone();
                    normalized.id = expected.id.clone();
                    assert_eq!(normalized, *expected);
                    return node;
                }
            }
            Some(coordinate_response::Msg::Ping(_)) => {}
            _ => {}
        }
    }
}
