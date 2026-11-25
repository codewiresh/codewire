use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX, CapabilitySlot};
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, header};
use serde_json::{Value, json};

use super::*;
use crate::CommitFailure;
use crate::claude_oauth::CanonicalClaudeOAuthBundle;
use crate::http_test_support::Lease;
use crate::{
    BrokerCredentialRefreshRequest, BrokerLeaseError, BrokerRefreshAdmission, BrokerRefreshError,
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, CanonicalCodexOAuthBundle,
};

/// The body Claude Code 2.1.308 sends, shared with the other crates' tests.
const REQUEST_FIXTURE: &str = include_str!(
    "../../../../codewire-access/tests/fixtures/claude-oauth-token/refresh-request.json"
);
const OURS: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const TOKEN_PATH: &str = "/v1/oauth/token";
/// The scopes the stored sign-in holds: fewer than Claude Code asks for.
const STORED_SCOPES: [&str; 3] = [
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
];
const RENEW: &str = "Codewire: this environment's Claude sign-in needs to be renewed";

/// One outbound provider request: method, target, headers and body.
type Outbound = (Method, String, HeaderMap, Vec<u8>);

/// A placement holding one Claude sign-in for the Anthropic slot, whose
/// refresh rotates the material it leases.
struct SignIn {
    material: Mutex<Vec<u8>>,
    kind: CredentialAuthKind,
    placeholder: Option<&'static str>,
    lease_error: Option<BrokerLeaseError>,
    /// The leased grant's deadline, `None` for none.
    grant_expires_at: Option<u64>,
    leases: AtomicUsize,
    commits: AtomicUsize,
    failures: AtomicUsize,
    refreshing: AtomicBool,
}

impl SignIn {
    fn new(material: Vec<u8>) -> Self {
        Self {
            material: Mutex::new(material),
            kind: CredentialAuthKind::ClaudeSignIn,
            placeholder: Some(OURS),
            lease_error: None,
            grant_expires_at: None,
            leases: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            refreshing: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl BrokerLeaseProvider for Arc<SignIn> {
    type Lease = Lease;
    type RefreshReservation = ();
    type StartedRefresh = ();

    async fn lease_operation(
        &self,
        _id: Uuid,
        slot: CapabilitySlot,
        operation: codewire_access::BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        self.leases.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.lease_error {
            return Err(error);
        }
        let mut lease = Lease::new(
            "anthropic",
            self.kind,
            slot.as_str(),
            operation.as_str(),
            route.as_str(),
        );
        lease.material = zeroize::Zeroizing::new(self.material.lock().unwrap().clone());
        lease.grant.expires_at_unix = self.grant_expires_at;
        lease.placeholder = self
            .placeholder
            .map(|value| CredentialPlaceholder::parse(value).unwrap());
        Ok(lease)
    }

    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        if self.refreshing.swap(true, Ordering::AcqRel) {
            return Err(BrokerRefreshError::InProgress);
        }
        Ok(BrokerRefreshAdmission::Reserved(()))
    }

    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Ok(())
    }

    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        panic!("a Claude sign-in committed Codex material")
    }

    async fn commit_claude_oauth_refresh(
        &self,
        _: (),
        material: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        *self.material.lock().unwrap() = material.into_bytes().to_vec();
        self.commits.fetch_add(1, Ordering::Relaxed);
        self.refreshing.store(false, Ordering::Release);
        Ok(())
    }

    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        self.refreshing.store(false, Ordering::Release);
        Ok(())
    }

    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.refreshing.store(false, Ordering::Release);
        Ok(())
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

/// Records every request and answers each with the same reply.
struct Upstream {
    outbound: Arc<Mutex<Vec<Outbound>>>,
    reply: Result<(StatusCode, &'static str), BrokerUpstreamError>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        self.outbound
            .lock()
            .unwrap()
            .push((method, target.to_string(), headers, body));
        let (status, body) = self.reply?;
        Ok(BrokerUpstreamResponse::new(
            status,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::iter([Ok(Bytes::from_static(
                body.as_bytes(),
            ))])),
        ))
    }
}

struct Harness {
    sign_in: Arc<SignIn>,
    outbound: Arc<Mutex<Vec<Outbound>>>,
    broker: OpenAiBroker<Arc<SignIn>, Upstream>,
}

impl Harness {
    fn new(
        sign_in: SignIn,
        reply: Result<(StatusCode, &'static str), BrokerUpstreamError>,
    ) -> Self {
        let sign_in = Arc::new(sign_in);
        let outbound = Arc::new(Mutex::new(Vec::new()));
        let broker = OpenAiBroker::new(
            Arc::clone(&sign_in),
            Upstream {
                outbound: Arc::clone(&outbound),
                reply,
            },
        )
        .unwrap()
        .with_network_policy_allowing_hosts(["platform.claude.com"]);
        Self {
            sign_in,
            outbound,
            broker,
        }
    }

    fn outbound(&self) -> Vec<Outbound> {
        self.outbound.lock().unwrap().clone()
    }

    fn leases(&self) -> usize {
        self.sign_in.leases.load(Ordering::Relaxed)
    }

    async fn front_door(&self, request: v1::CredentialBridgeRequest) -> (StatusCode, Value) {
        let response = self.broker.execute_front_door(request).await.unwrap();
        collect(response).await
    }
}

/// A stored sign-in whose access token expires in `expires_in` seconds.
fn material(expires_in: u64) -> Vec<u8> {
    let now = current_unix_time().unwrap();
    json!({
        "version": 1,
        "access_token": "synthetic-stored-access",
        "refresh_token": "synthetic-stored-refresh",
        "expires_at_unix": now + expires_in,
        "scopes": STORED_SCOPES,
        "refreshed_at_unix": now - 8 * 3600 + expires_in,
    })
    .to_string()
    .into_bytes()
}

const FRESH: u64 = 7 * 3600;
const NEAR_EXPIRY: u64 = 60;

fn token_request(body: &[u8]) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: TOKEN_PATH.into(),
        query: String::new(),
        headers: vec![v1::CredentialHttpHeader {
            name: "content-type".into(),
            value: b"application/json".to_vec(),
        }],
        body: body.to_vec(),
        capability_slot: "anthropic".into(),
        route: CLAUDE_TOKEN_ROUTE.into(),
        intercepted_host: "platform.claude.com".into(),
        destination_ip: String::new(),
        streamed_body: false,
        intercept_decision: Vec::new(),
    }
}

/// The fixture's request with `refresh_token` replaced.
fn refresh_with(refresh_token: &str) -> Vec<u8> {
    let mut body: Value = serde_json::from_str(REQUEST_FIXTURE).unwrap();
    body["refresh_token"] = json!(refresh_token);
    body.to_string().into_bytes()
}

async fn collect(response: BrokerHttpResponse) -> (StatusCode, Value) {
    let (status, headers, mut body) = response.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend(chunk.unwrap());
    }
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Nothing Codewire hands the environment reached the provider.
fn assert_nothing_of_ours_sent(outbound: &[Outbound]) {
    for (_, _, headers, body) in outbound {
        let text = String::from_utf8_lossy(body);
        assert!(
            !text.contains(CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX),
            "{text}"
        );
        assert!(!text.contains("cwp1_"), "{text}");
        for value in headers.values() {
            let value = String::from_utf8_lossy(value.as_bytes());
            assert!(!value.contains("codewire-managed") && !value.contains("cwp1_"));
        }
    }
}

fn assert_managed_answer(answer: &Value, scope: &str) -> String {
    let members = answer.as_object().unwrap();
    let mut names: Vec<_> = members.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_eq!(answer["access_token"], OURS);
    assert_eq!(answer["expires_in"], 315_360_000);
    assert_eq!(answer["scope"], scope);
    assert_eq!(answer["token_type"], "Bearer");
    let marker = answer["refresh_token"].as_str().unwrap().to_owned();
    assert!(is_managed_claude_refresh_token(&marker), "{marker}");
    marker
}

/// A managed refresh with a fresh stored sign-in is answered from one lease
/// with this environment's placeholder, the stored scopes rather than the
/// six asked for, and a new marker; Claude is never contacted.
#[tokio::test]
async fn a_managed_refresh_is_answered_with_the_placeholder_and_the_stored_scopes() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    let (status, answer) = harness
        .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let marker = assert_managed_answer(&answer, &STORED_SCOPES.join(" "));
    let asked: Value = serde_json::from_str(REQUEST_FIXTURE).unwrap();
    assert_ne!(marker, asked["refresh_token"]);
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 1);
    assert_eq!(harness.sign_in.commits.load(Ordering::Relaxed), 0);
}

/// The agent refreshes with the marker it was last given. Every answer
/// carries the same access token, since a changed one makes Claude Code
/// retry for 90 s and more, and a different marker each time.
#[tokio::test]
async fn managed_answers_keep_the_access_token_and_rotate_the_marker() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    let (_, first) = harness
        .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
        .await;
    let first_marker = assert_managed_answer(&first, &STORED_SCOPES.join(" "));
    let (status, second) = harness
        .front_door(token_request(&refresh_with(&first_marker)))
        .await;
    assert_eq!(status, StatusCode::OK);
    let second_marker = assert_managed_answer(&second, &STORED_SCOPES.join(" "));
    assert_eq!(first["access_token"], second["access_token"]);
    assert_ne!(first_marker, second_marker);
    assert!(harness.outbound().is_empty());
}

/// A managed refresh that also carries a credential header, ours or any
/// other, is refused before a lease: nothing is answered or sent.
#[tokio::test]
async fn a_managed_refresh_with_a_credential_header_is_refused() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for (name, value) in [
        (
            "authorization",
            "Bearer synthetic-users-own-access".to_owned(),
        ),
        ("authorization", format!("Bearer {OURS}")),
        ("x-api-key", "synthetic-users-own-key".to_owned()),
        ("x-api-key", OURS.to_owned()),
        ("cookie", "session=synthetic".to_owned()),
    ] {
        let mut request = token_request(REQUEST_FIXTURE.as_bytes());
        request.headers.push(v1::CredentialHttpHeader {
            name: name.into(),
            value: value.into_bytes(),
        });
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{name}"
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// A body in a content-encoding other than identity can't be checked for a
/// Codewire value, so it is refused, never forwarded unread. An identity
/// encoding is forwarded as any other request is.
#[tokio::test]
async fn an_encoded_body_is_refused_and_identity_is_forwarded() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for coding in ["gzip", "br", "identity, gzip", "x-unknown"] {
        let mut request = token_request(&refresh_with("synthetic-users-own-refresh"));
        request.headers.push(v1::CredentialHttpHeader {
            name: "content-encoding".into(),
            value: coding.as_bytes().to_vec(),
        });
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{coding}"
        );
    }
    assert!(harness.outbound().is_empty());
    let mut identity = token_request(&refresh_with("synthetic-users-own-refresh"));
    identity.headers.push(v1::CredentialHttpHeader {
        name: "content-encoding".into(),
        value: b"identity".to_vec(),
    });
    harness.front_door(identity).await;
    assert_eq!(harness.outbound().len(), 1);
}

/// A stored sign-in, or a refresh of it, holding a scope beyond the ones
/// Codewire's sign-in asks for is `invalid_grant`, and the wider scope is
/// never handed on.
#[tokio::test]
async fn a_scope_beyond_the_sign_in_set_is_never_returned() {
    let widened = |expires_in: u64| {
        let mut stored: Value = serde_json::from_slice(&material(expires_in)).unwrap();
        stored["scopes"] = json!(["user:profile", "user:inference", "user:experimental"]);
        stored.to_string().into_bytes()
    };
    let invalid_grant = (
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_grant", "error_description": RENEW }),
    );
    let stored = Harness::new(SignIn::new(widened(FRESH)), Ok((StatusCode::OK, "{}")));
    assert_eq!(
        stored
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        invalid_grant
    );
    assert!(stored.outbound().is_empty());
    let refreshed = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Ok((
            StatusCode::OK,
            r#"{"access_token":"synthetic-rotated-access","refresh_token":"synthetic-rotated-refresh","expires_in":28800,"scope":"user:profile user:inference user:experimental"}"#,
        )),
    );
    assert_eq!(
        refreshed
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        invalid_grant
    );
    assert_nothing_of_ours_sent(&refreshed.outbound());
}

/// Two managed refreshes that find the stored token within its refresh
/// window share one real exchange, through the serialized refresh path; both
/// answer with the rotated sign-in's scopes, and only the stored refresh
/// token reaches Claude.
#[tokio::test]
async fn concurrent_managed_refreshes_near_expiry_make_one_real_exchange() {
    let harness = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Ok((
            StatusCode::OK,
            r#"{"access_token":"synthetic-rotated-access","refresh_token":"synthetic-rotated-refresh","expires_in":28800,"scope":"user:profile user:inference"}"#,
        )),
    );
    let (one, two) = tokio::join!(
        harness.front_door(token_request(REQUEST_FIXTURE.as_bytes())),
        harness.front_door(token_request(REQUEST_FIXTURE.as_bytes())),
    );
    for (status, answer) in [one, two] {
        assert_eq!(status, StatusCode::OK);
        assert_managed_answer(&answer, "user:profile user:inference");
    }
    let outbound = harness.outbound();
    assert_eq!(outbound.len(), 1);
    assert_eq!(
        (&outbound[0].0, outbound[0].1.as_str()),
        (&Method::POST, TOKEN_URL)
    );
    let sent: Value = serde_json::from_slice(&outbound[0].3).unwrap();
    assert_eq!(sent["refresh_token"], "synthetic-stored-refresh");
    assert_eq!(sent["scope"], STORED_SCOPES.join(" "));
    assert_nothing_of_ours_sent(&outbound);
    assert_eq!(harness.sign_in.commits.load(Ordering::Relaxed), 1);
}

/// A refresh with the user's own token takes no lease and reaches Claude's
/// token endpoint byte for byte; Claude's answer comes back as it came.
#[tokio::test]
async fn the_users_own_refresh_is_forwarded_untouched() {
    let reply = r#"{"access_token":"synthetic-users-access","expires_in":28800}"#;
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, reply)));
    let body = refresh_with("synthetic-users-own-refresh");
    let (status, answer) = harness.front_door(token_request(&body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer, serde_json::from_str::<Value>(reply).unwrap());
    let outbound = harness.outbound();
    assert_eq!(outbound.len(), 1);
    let (method, target, headers, sent) = &outbound[0];
    assert_eq!((method, target.as_str()), (&Method::POST, TOKEN_URL));
    assert_eq!(sent, &body);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    // Asked for an uncompressed answer, which the transport passes on (#6362).
    assert_eq!(headers[header::ACCEPT_ENCODING], "identity");
    assert_eq!(harness.leases(), 0);
}

/// A forwarded refresh the environment's transport does not admit is
/// refused without calling the user's login invalid; an unreachable Claude
/// is temporary.
#[tokio::test]
async fn a_forward_that_cannot_be_sent_is_not_invalid_grant() {
    for (error, status, code) in [
        (
            BrokerUpstreamError::DestinationDenied,
            StatusCode::FORBIDDEN,
            "invalid_request",
        ),
        (
            BrokerUpstreamError::Connect,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        ),
    ] {
        let harness = Harness::new(SignIn::new(material(FRESH)), Err(error));
        let answer = harness
            .front_door(token_request(&refresh_with("synthetic-users-own-refresh")))
            .await;
        assert_eq!(answer, (status, json!({ "error": code })), "{error:?}");
    }
}

/// A request that is not a managed refresh yet carries a placeholder or a
/// marker anywhere, however spelled, is refused and never forwarded.
#[tokio::test]
async fn a_codewire_value_is_never_forwarded() {
    let near_miss =
        format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}0123456789abcdef0123456789abcdeX");
    // `c` as a JSON escape, its backslash built so no source text holds it.
    let escaped_c = format!("{}u0063", char::from(0x5c_u8));
    let escaped = [
        format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{escaped_c}wp1_x","client_id":"c"}}"#
        ),
        format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"own","client_id":"c","{escaped_c}wp1_":1}}"#
        ),
        format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"own","client_id":"c","extra":"{escaped_c}odewire-managed-no-refresh-token"}}"#
        ),
    ];
    for body in &escaped {
        assert!(!body.contains("cwp1_") && !body.contains("codewire-managed"));
        assert!(carries_codewire_value(
            &ValidatedGuestRequest::parse(
                crate::bridge::BridgeEntry::FrontDoor,
                token_request(body.as_bytes()),
                false
            )
            .unwrap(),
            Some(&serde_json::from_str(body).unwrap())
        ));
    }
    let mut bodies: Vec<Vec<u8>> = escaped
        .iter()
        .map(|body| body.clone().into_bytes())
        .collect();
    bodies.extend([
        refresh_with(OURS),
        refresh_with(&near_miss),
        refresh_with(codewire_access::CODEX_MANAGED_REFRESH_TOKEN),
        refresh_with(&format!("own-{OURS}")),
        br#"{"grant_type":"refresh_token","refresh_token":"own","client_id":"c","extra":["codewire-managed-no-refresh-token"]}"#.to_vec(),
    ]);
    bodies.push({
        let mut body: Value = serde_json::from_str(REQUEST_FIXTURE).unwrap();
        body["refresh_token"] = json!("own");
        body["nested"] = json!({ "cwp1_": 1 });
        body.to_string().into_bytes()
    });
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for body in &bodies {
        assert_eq!(
            harness.front_door(token_request(body)).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
    for (name, value) in [
        ("authorization", format!("Bearer {OURS}")),
        ("x-api-key", OURS.to_owned()),
        ("x-anything", "codewire-managed-no-refresh-token".to_owned()),
    ] {
        let mut request = token_request(&refresh_with("own"));
        request.headers.push(v1::CredentialHttpHeader {
            name: name.into(),
            value: value.into_bytes(),
        });
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{name}"
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// A token request over the bound is `invalid_request` before it is parsed,
/// leased or sent.
#[tokio::test]
async fn an_oversized_token_request_is_invalid_request() {
    let mut oversized: Value = serde_json::from_str(REQUEST_FIXTURE).unwrap();
    oversized["padding"] = json!("x".repeat(MAX_TOKEN_REQUEST_BYTES));
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    assert_eq!(
        harness
            .front_door(token_request(&oversized.to_string().into_bytes()))
            .await,
        (
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_request" })
        )
    );
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// A token request that is not a managed refresh and carries nothing of
/// Codewire's is the user's own, whatever its grant or shape: the code
/// exchange of a `claude /login` inside the environment, a refresh with
/// its own token, or a body Claude will refuse itself. Each is forwarded
/// byte for byte without a lease.
#[tokio::test]
async fn any_other_token_request_is_forwarded_untouched() {
    let bodies: Vec<Vec<u8>> = vec![
        json!({
            "grant_type": "authorization_code",
            "code": "synthetic-code",
            "redirect_uri": "https://platform.claude.com/oauth/code/callback",
            "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            "code_verifier": "synthetic-verifier",
            "state": "synthetic-state",
        })
        .to_string()
        .into_bytes(),
        json!({ "grant_type": "client_credentials", "client_id": "c" })
            .to_string()
            .into_bytes(),
        b"grant_type=refresh_token".to_vec(),
        b"{".to_vec(),
        b"[]".to_vec(),
        b"".to_vec(),
        json!({ "grant_type": "refresh_token", "client_id": "c" })
            .to_string()
            .into_bytes(),
        json!({ "grant_type": "refresh_token", "refresh_token": "", "client_id": "c" })
            .to_string()
            .into_bytes(),
        json!({ "grant_type": "refresh_token", "refresh_token": 1, "client_id": "c" })
            .to_string()
            .into_bytes(),
    ];
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for (sent, body) in bodies.iter().enumerate() {
        assert_eq!(
            harness.front_door(token_request(body)).await,
            (StatusCode::OK, json!({})),
            "{}",
            String::from_utf8_lossy(body)
        );
        let outbound = harness.outbound();
        assert_eq!(outbound.len(), sent + 1);
        let (method, target, _, forwarded) = &outbound[sent];
        assert_eq!((method, target.as_str()), (&Method::POST, TOKEN_URL));
        assert_eq!(forwarded, body);
    }
    assert_eq!(harness.leases(), 0);
}

/// A token request that carries a managed marker in any shape other than a
/// managed refresh is refused, never forwarded and never answered.
#[tokio::test]
async fn a_marker_outside_a_managed_refresh_is_refused() {
    let marker = format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}0123456789abcdef0123456789abcdef");
    let bodies: Vec<Vec<u8>> = vec![
        json!({ "refresh_token": marker, "client_id": "c" }).to_string().into_bytes(),
        json!({ "grant_type": "refresh_token", "refresh_token": marker }).to_string().into_bytes(),
        json!({ "grant_type": "refresh_token", "refresh_token": marker, "client_id": "c", "scope": 6 })
            .to_string()
            .into_bytes(),
        json!({ "grant_type": "client_credentials", "refresh_token": marker, "client_id": "c" })
            .to_string()
            .into_bytes(),
        format!("grant_type=refresh_token&refresh_token={marker}").into_bytes(),
    ];
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for body in &bodies {
        assert_eq!(
            harness.front_door(token_request(body)).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// A stored sign-in Claude refuses to refresh, one that needs Reconnect,
/// and an Anthropic slot that holds no sign-in are all `invalid_grant`: the
/// agent drops the login.
#[tokio::test]
async fn a_sign_in_that_cannot_be_used_is_invalid_grant() {
    let invalid_grant = (
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_grant", "error_description": RENEW }),
    );
    let refused = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Ok((StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#)),
    );
    assert_eq!(
        refused
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        invalid_grant
    );
    assert_eq!(refused.sign_in.failures.load(Ordering::Relaxed), 1);
    assert_nothing_of_ours_sent(&refused.outbound());

    let reconnect = Harness::new(
        SignIn {
            lease_error: Some(BrokerLeaseError::ReconnectRequired(
                codewire_access::WithheldReason::NeedsReconnect,
            )),
            ..SignIn::new(material(FRESH))
        },
        Ok((StatusCode::OK, "{}")),
    );
    let api_key = Harness::new(
        SignIn {
            kind: CredentialAuthKind::ApiKey,
            ..SignIn::new(material(FRESH))
        },
        Ok((StatusCode::OK, "{}")),
    );
    for harness in [reconnect, api_key] {
        assert_eq!(
            harness
                .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
                .await,
            invalid_grant
        );
        assert!(harness.outbound().is_empty());
    }
}

/// A Claude that cannot be reached is `temporarily_unavailable`: the agent
/// keeps its token.
#[tokio::test]
async fn an_unreachable_claude_is_temporarily_unavailable() {
    let unreachable = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Err(BrokerUpstreamError::Connect),
    );
    assert_eq!(
        unreachable
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": "temporarily_unavailable" })
        )
    );
    assert_nothing_of_ours_sent(&unreachable.outbound());
}

/// A transport that refused to send the broker's own refresh never asked
/// Claude, so it says nothing about the sign-in: `temporarily_unavailable`,
/// not `invalid_grant`.
#[tokio::test]
async fn a_refused_refresh_transport_is_temporarily_unavailable() {
    let transport_refused = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Err(BrokerUpstreamError::DestinationDenied),
    );
    assert_eq!(
        transport_refused
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": "temporarily_unavailable" })
        )
    );
    assert_nothing_of_ours_sent(&transport_refused.outbound());
    assert_eq!(transport_refused.outbound().len(), 1);
}

/// A credential deadline that passes while the refresh runs refuses the
/// refresh's binding check only for running out of time, so it is a passing
/// failure, and the next request's lease decides. The harness can't move the
/// deadline between the first lease and the refresh, so the mapping is
/// checked directly: a deadline that has passed turns `Denied` into a
/// passing failure, and a future or absent one leaves it a denial.
#[test]
fn a_deadline_passed_during_the_refresh_is_not_invalid_grant() {
    let now = current_unix_time().unwrap();
    let mut grant = Lease::new(
        "anthropic",
        CredentialAuthKind::ClaudeSignIn,
        "anthropic",
        crate::anthropic::OPERATION,
        crate::anthropic::ROUTE,
    )
    .grant;
    grant.expires_at_unix = Some(now);
    assert_eq!(
        passing_if_expired(BrokerRequestError::Denied, &grant),
        BrokerRequestError::UpstreamFailed
    );
    grant.expires_at_unix = Some(now + 3600);
    assert_eq!(
        passing_if_expired(BrokerRequestError::Denied, &grant),
        BrokerRequestError::Denied
    );
    grant.expires_at_unix = None;
    assert_eq!(
        passing_if_expired(BrokerRequestError::Denied, &grant),
        BrokerRequestError::Denied
    );
}

/// An authority that cannot be reached, or a placement that leases no
/// placeholder, is no answer: the error reaches the bridge, which ends the
/// epoch, and nothing is sent.
#[tokio::test]
async fn an_unavailable_authority_is_an_error_not_an_answer() {
    let authority = Harness::new(
        SignIn {
            lease_error: Some(BrokerLeaseError::Unavailable),
            ..SignIn::new(material(FRESH))
        },
        Ok((StatusCode::OK, "{}")),
    );
    let no_placeholder = Harness::new(
        SignIn {
            placeholder: None,
            ..SignIn::new(material(FRESH))
        },
        Ok((StatusCode::OK, "{}")),
    );
    for harness in [authority, no_placeholder] {
        assert!(matches!(
            harness
                .broker
                .execute_front_door(token_request(REQUEST_FIXTURE.as_bytes()))
                .await,
            Err(BrokerRequestError::AuthorityUnavailable)
        ));
        assert!(harness.outbound().is_empty());
    }
}

/// A request to Claude's token host on `method`, `path` and `query`.
fn host_request(method: &str, path: &str, query: &str, body: &[u8]) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        ..token_request(body)
    }
}

/// The route exists only behind the front door, for its own host.
#[tokio::test]
async fn the_token_route_is_a_front_door_route_of_its_own_host() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    let mut loopback = token_request(REQUEST_FIXTURE.as_bytes());
    loopback.intercepted_host = String::new();
    assert!(matches!(
        harness.broker.execute(loopback).await,
        Err(BrokerRequestError::InvalidRequest)
    ));
    let mut other_host = token_request(REQUEST_FIXTURE.as_bytes());
    other_host.intercepted_host = "api.anthropic.com".into();
    assert!(matches!(
        harness.broker.execute_front_door(other_host).await,
        Err(BrokerRequestError::InvalidRequest)
    ));
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// Every other request to Claude's token host that carries nothing of
/// Codewire's, on any path and method, is forwarded untouched to that path
/// and query, every header kept, without a lease.
#[tokio::test]
async fn any_other_request_to_the_token_host_is_forwarded_untouched() {
    let own_refresh = refresh_with("synthetic-users-own-refresh");
    let cases: [(&str, &str, &str, &[u8], &str); 6] = [
        ("GET", TOKEN_PATH, "", b"", TOKEN_URL),
        (
            "POST",
            "/v1/oauth/revoke",
            "",
            br#"{"token":"synthetic-own"}"#,
            "https://platform.claude.com/v1/oauth/revoke",
        ),
        (
            "GET",
            "/api/oauth/profile",
            "account=1",
            b"",
            "https://platform.claude.com/api/oauth/profile?account=1",
        ),
        ("DELETE", "/", "", b"", "https://platform.claude.com/"),
        (
            "PUT",
            "/v1/oauth/token/x",
            "",
            b"own",
            "https://platform.claude.com/v1/oauth/token/x",
        ),
        (
            "POST",
            TOKEN_PATH,
            "next=1",
            own_refresh.as_slice(),
            "https://platform.claude.com/v1/oauth/token?next=1",
        ),
    ];
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for (sent, (method, path, query, body, target)) in cases.into_iter().enumerate() {
        let mut request = host_request(method, path, query, body);
        request.headers.push(v1::CredentialHttpHeader {
            name: "authorization".into(),
            value: b"Bearer synthetic-users-own-access".to_vec(),
        });
        assert_eq!(
            harness.front_door(request).await,
            (StatusCode::OK, json!({})),
            "{method} {path}"
        );
        let outbound = harness.outbound();
        assert_eq!(outbound.len(), sent + 1);
        let (sent_method, sent_target, headers, sent_body) = &outbound[sent];
        assert_eq!(
            (sent_method.as_str(), sent_target.as_str()),
            (method, target)
        );
        assert_eq!(sent_body, body);
        assert_eq!(
            headers[header::AUTHORIZATION],
            "Bearer synthetic-users-own-access"
        );
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    }
    assert_eq!(harness.leases(), 0);
}

/// A managed refresh is answered only at `POST /v1/oauth/token` with no
/// query. Elsewhere on the host the same body carries a marker, so it is
/// refused: never answered, never forwarded.
#[tokio::test]
async fn a_managed_refresh_elsewhere_on_the_host_is_refused() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    let body = REQUEST_FIXTURE.as_bytes();
    for request in [
        host_request("PUT", TOKEN_PATH, "", body),
        host_request("POST", "/v1/oauth/token/x", "", body),
        host_request("POST", TOKEN_PATH, "grant_type=refresh_token", body),
        host_request("POST", "/v1/oauth/revoke", "", body),
    ] {
        let shown = format!("{} {}?{}", request.method, request.path, request.query);
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{shown}"
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// A JSON body that repeats a key in any object, at any depth, however the
/// key is spelled, is refused where a managed refresh would be answered and
/// before any forward, even when no value of ours is in it.
#[tokio::test]
async fn a_body_with_a_repeated_key_is_refused() {
    let marker = format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}0123456789abcdef0123456789abcdef");
    // `x` as a JSON escape, its backslash built so no source text holds it.
    let escaped_x = format!("{}u0078", char::from(0x5c_u8));
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    let token_bodies = [
        format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{marker}","client_id":"c","refresh_token":"own"}}"#
        ),
        format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"own","client_id":"c","refresh_token":"{marker}"}}"#
        ),
        r#"{"grant_type":"refresh_token","refresh_token":"own","client_id":"c","client_id":"d"}"#
            .to_owned(),
        r#"{"grant_type":"authorization_code","code":"x","nested":{"a":1,"a":2}}"#.to_owned(),
        format!(
            r#"{{"grant_type":"authorization_code","code":"x","list":[{{"x":1,"{escaped_x}":2}}]}}"#
        ),
    ];
    let mut requests: Vec<_> = token_bodies
        .iter()
        .map(|body| token_request(body.as_bytes()))
        .collect();
    requests.push(host_request(
        "POST",
        "/v1/oauth/revoke",
        "",
        br#"{"token":"own","token":"other"}"#,
    ));
    for request in requests {
        let shown = String::from_utf8_lossy(&request.body).into_owned();
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{shown}"
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

#[test]
fn a_repeated_key_is_found_at_any_depth_and_json_is_otherwise_kept() {
    // `e` and `a` as JSON escapes, their backslash built so no source text
    // holds it.
    let backslash = char::from(0x5c_u8);
    let kept = format!(r#"{{"a":[1,{{"b":null,"c":1.5}}],"d":"{backslash}u0065"}}"#);
    assert_eq!(
        decode_body(kept.as_bytes()),
        Decoded::Json(json!({ "a": [1, { "b": null, "c": 1.5 }], "d": "e" }))
    );
    let escaped_repeat = format!(r#"{{"a":1,"{backslash}u0061":2}}"#);
    for repeated in [
        br#"{"a":1,"a":1}"#.as_slice(),
        br#"[{"a":{"b":{"c":1,"c":2}}}]"#,
        escaped_repeat.as_bytes(),
    ] {
        assert_eq!(
            decode_body(repeated),
            Decoded::RepeatedKey,
            "{}",
            String::from_utf8_lossy(repeated)
        );
    }
    for not_json in [b"".as_slice(), b"{", b"a=1&a=2", br#"{"a":1} x"#] {
        assert_eq!(decode_body(not_json), Decoded::NotJson);
    }
}

/// A placeholder or a marker in the path, the query or a form body, as sent
/// or percent-encoded, is refused and never forwarded.
#[tokio::test]
async fn a_codewire_value_in_the_path_query_or_form_is_refused() {
    let harness = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for request in [
        host_request("GET", "/v1/cwp1_x", "", b""),
        host_request("GET", "/v1/%63wp1_x", "", b""),
        host_request(
            "GET",
            "/api",
            "token=codewire-managed-no-refresh-token-1",
            b"",
        ),
        host_request(
            "GET",
            "/api",
            "token=%63odewire-managed-no-refresh-token",
            b"",
        ),
        host_request("POST", TOKEN_PATH, "", b"refresh_token=%63wp1_abc"),
        host_request(
            "POST",
            "/v1/oauth/revoke",
            "",
            b"token=codewire%2Dmanaged%2Dno%2Drefresh%2Dtoken",
        ),
    ] {
        let shown = format!("{}?{}", request.path, request.query);
        assert_eq!(
            harness.front_door(request).await,
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" })
            ),
            "{shown}"
        );
    }
    assert!(harness.outbound().is_empty());
    assert_eq!(harness.leases(), 0);
}

/// #5555: the user's own request to Claude's token host is sent only where
/// the policy allows that host by rule. Without the answer it is refused in
/// the token endpoint's own shape, never as `invalid_grant`, which would end
/// the user's login.
#[tokio::test]
async fn without_the_policys_answer_the_users_own_request_is_not_sent() {
    let Harness {
        sign_in,
        outbound,
        broker,
    } = Harness::new(SignIn::new(material(FRESH)), Ok((StatusCode::OK, "{}")));
    for hosted in [false, true] {
        let broker = OpenAiBroker::new(
            Arc::clone(&sign_in),
            Upstream {
                outbound: Arc::clone(&outbound),
                reply: Ok((StatusCode::OK, "{}")),
            },
        )
        .unwrap();
        let broker = if hosted {
            broker.with_untouched_forwards_refused()
        } else {
            broker
        };
        let harness = Harness {
            sign_in: Arc::clone(&sign_in),
            outbound: Arc::clone(&outbound),
            broker,
        };
        let mut request = host_request("GET", "/api/oauth/profile", "", b"");
        request.headers.push(v1::CredentialHttpHeader {
            name: "authorization".into(),
            value: b"Bearer synthetic-users-own-access".to_vec(),
        });
        assert_eq!(
            harness.front_door(request).await,
            (StatusCode::FORBIDDEN, json!({ "error": "invalid_request" })),
            "hosted: {hosted}"
        );
    }
    drop(broker);
    assert!(outbound.lock().unwrap().is_empty());
    assert_eq!(sign_in.leases.load(Ordering::Relaxed), 0);
}
