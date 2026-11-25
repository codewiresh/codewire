use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use codewire_access::WithheldReason;
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use http::HeaderValue;
use serde_json::json;

use super::*;
use crate::CommitFailure;
use crate::bridge::BridgeEntry;
use crate::claude_oauth::CanonicalClaudeOAuthBundle;
use crate::http_test_support::Lease;
use crate::{
    BrokerCredentialRefreshRequest, BrokerLeaseError, BrokerRefreshAdmission, BrokerRefreshError,
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, CanonicalCodexOAuthBundle,
};

/// The body Codex 0.160.0 sends, shared with the compatibility check.
const REQUEST_FIXTURE: &str = include_str!(
    "../../../../codewire-access/tests/fixtures/codex-oauth-token/refresh-request.json"
);
const OURS: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const ACCOUNT: &str = "account-synthetic";
/// A claim of the real ID token that the placeholder withholds.
const WITHHELD_CLAIM: &str = "synthetic-withheld-claim";
const RENEW: &str = "Codewire: this environment's Codex sign-in needs to be renewed";

/// One outbound provider request: method, target, headers and body.
type Outbound = (Method, String, HeaderMap, Vec<u8>);

/// A placement holding one Codex sign-in for the Codex slot, whose refresh
/// rotates the material it leases.
struct SignIn {
    material: Mutex<Vec<u8>>,
    kind: CredentialAuthKind,
    lease_error: Option<BrokerLeaseError>,
    leases: AtomicUsize,
    commits: AtomicUsize,
    failures: AtomicUsize,
    refreshing: AtomicBool,
}

impl SignIn {
    fn new(material: Vec<u8>) -> Self {
        Self {
            material: Mutex::new(material),
            kind: CredentialAuthKind::OAuth,
            lease_error: None,
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
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        self.leases.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.lease_error {
            return Err(error);
        }
        let mut lease = Lease::new(
            "openai",
            self.kind,
            slot.as_str(),
            operation.as_str(),
            route.as_str(),
        );
        lease.material = zeroize::Zeroizing::new(self.material.lock().unwrap().clone());
        lease.placeholder = Some(CredentialPlaceholder::parse(OURS).unwrap());
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
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        *self.material.lock().unwrap() = material.into_bytes().to_vec();
        self.commits.fetch_add(1, Ordering::Relaxed);
        self.refreshing.store(false, Ordering::Release);
        Ok(())
    }

    async fn commit_claude_oauth_refresh(
        &self,
        _: (),
        _: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        panic!("a Codex sign-in committed Claude material")
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

/// Records every request and answers each with the same reply; with no
/// reply, any request at all fails the test: OpenAI must not be asked.
struct Upstream {
    outbound: Arc<Mutex<Vec<Outbound>>>,
    reply: Option<Result<(StatusCode, String), BrokerUpstreamError>>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        let Some(reply) = self.reply.clone() else {
            panic!("{method} {target} reached OpenAI");
        };
        self.outbound
            .lock()
            .unwrap()
            .push((method, target.to_string(), headers, body));
        let (status, body) = reply?;
        Ok(BrokerUpstreamResponse::new(
            status,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::iter([Ok(Bytes::from(body))])),
        ))
    }
}

/// Where the broker runs: locally beside a policy that allows the token
/// host, or hosted, where no untouched forward is sent.
#[derive(Clone, Copy)]
enum Placement {
    LocalAllowed,
    Hosted,
}

struct Harness {
    sign_in: Arc<SignIn>,
    outbound: Arc<Mutex<Vec<Outbound>>>,
    broker: OpenAiBroker<Arc<SignIn>, Upstream>,
}

impl Harness {
    fn new(
        sign_in: SignIn,
        placement: Placement,
        reply: Option<Result<(StatusCode, String), BrokerUpstreamError>>,
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
        .unwrap();
        let broker = match placement {
            Placement::LocalAllowed => {
                broker.with_network_policy_allowing_hosts([OPENAI_AUTH_HOST])
            }
            Placement::Hosted => broker.with_untouched_forwards_refused(),
        };
        Self {
            sign_in,
            outbound,
            broker,
        }
    }

    /// OpenAI is never asked.
    fn unasked(sign_in: SignIn, placement: Placement) -> Self {
        Self::new(sign_in, placement, None)
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

fn encode(value: &Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
}

fn jwt(claims: &Value) -> String {
    format!(
        "{}.{}.synthetic-signature",
        encode(&json!({ "alg": "RS256" })),
        encode(claims)
    )
}

/// A stored sign-in whose access token expires in `expires_in` seconds.
fn material(expires_in: u64) -> Vec<u8> {
    let now = current_unix_time().unwrap();
    json!({
        "version": 1,
        "access_token": jwt(&json!({ "iat": now - 3600, "exp": now + expires_in })),
        "refresh_token": "synthetic-stored-refresh",
        "id_token": jwt(&json!({
            "email": "synthetic@example.invalid",
            WITHHELD_CLAIM: "synthetic-withheld",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": ACCOUNT,
                "chatgpt_plan_type": "plus",
                "chatgpt_user_id": "user-synthetic",
            },
        })),
        "account_id": ACCOUNT,
        "fedramp": false,
        "refreshed_at_unix": now - 3600,
    })
    .to_string()
    .into_bytes()
}

const FRESH: u64 = 7 * 3600;
const NEAR_EXPIRY: u64 = 60;

fn host_request(
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &[u8],
) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: vec![v1::CredentialHttpHeader {
            name: "content-type".into(),
            value: content_type.as_bytes().to_vec(),
        }],
        body: body.to_vec(),
        capability_slot: "codex".into(),
        route: OPENAI_ROUTE.into(),
        intercepted_host: OPENAI_AUTH_HOST.into(),
        destination_ip: String::new(),
        streamed_body: false,
        intercept_decision: Vec::new(),
    }
}

fn token_request(body: &[u8]) -> v1::CredentialBridgeRequest {
    host_request("POST", OPENAI_TOKEN_PATH, "", "application/json", body)
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

/// Nothing Codewire hands the environment reached OpenAI.
fn assert_nothing_of_ours_sent(outbound: &[Outbound]) {
    for (_, target, headers, body) in outbound {
        let text = String::from_utf8_lossy(body);
        assert!(!text.contains(CODEX_MANAGED_REFRESH_TOKEN), "{text}");
        assert!(!text.contains("cwp1_"), "{text}");
        assert!(!target.contains("cwp1_") && !target.contains("codewire-managed"));
        for value in headers.values() {
            let value = String::from_utf8_lossy(value.as_bytes());
            assert!(!value.contains("codewire-managed") && !value.contains("cwp1_"));
        }
    }
}

fn claims(token: &str) -> (Value, Value) {
    let mut parts = token.split('.');
    let decode = |part: Option<&str>| -> Value {
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part.unwrap())
                .unwrap(),
        )
        .unwrap()
    };
    (decode(parts.next()), decode(parts.next()))
}

/// Exactly the three members Codex reads: the placeholder, an unsigned ID
/// token of only the allow-listed claims, and the bare marker.
fn assert_managed_answer(answer: &Value) {
    let mut names: Vec<_> = answer
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["access_token", "id_token", "refresh_token"]);
    assert_eq!(answer["access_token"], OURS);
    assert_eq!(answer["refresh_token"], "codewire-managed-no-refresh-token");
    let (header, claims) = claims(answer["id_token"].as_str().unwrap());
    assert_eq!(header["alg"], "none");
    assert_eq!(claims["exp"], 4_070_908_800_u64);
    assert_eq!(claims["email"], "synthetic@example.invalid");
    let auth = &claims["https://api.openai.com/auth"];
    assert_eq!(auth["chatgpt_account_id"], ACCOUNT);
    assert_eq!(auth["chatgpt_plan_type"], "plus");
    assert!(claims.get(WITHHELD_CLAIM).is_none(), "{claims}");
}

/// Codex's own refresh with the marker, as the pinned Codex sends it, is
/// answered from one lease with this environment's placeholders. OpenAI is
/// never asked: the upstream fails the test if it is called.
#[tokio::test]
async fn a_managed_refresh_is_answered_with_placeholders_and_never_reaches_openai() {
    for placement in [Placement::LocalAllowed, Placement::Hosted] {
        let harness = Harness::unasked(SignIn::new(material(FRESH)), placement);
        let (status, headers, body) = harness
            .broker
            .execute_front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await
            .unwrap()
            .into_parts();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let (_, answer) = collect(BrokerHttpResponse::new(status, headers, body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_managed_answer(&answer);
        assert_eq!(harness.leases(), 1);
        assert_eq!(harness.sign_in.commits.load(Ordering::Relaxed), 0);
    }
}

/// The same refresh in a form body, and with a nonce after the marker, is
/// Codewire's too, and answered the same.
#[tokio::test]
async fn a_form_refresh_and_a_marker_with_a_nonce_are_answered() {
    let harness = Harness::unasked(SignIn::new(material(FRESH)), Placement::Hosted);
    let form = format!(
        "grant_type=refresh_token&client_id=app_synthetic&refresh_token={CODEX_MANAGED_REFRESH_TOKEN}"
    );
    let nonce = refresh_with(&format!(
        "{CODEX_MANAGED_REFRESH_TOKEN}-0123456789abcdef0123456789abcdef"
    ));
    for request in [
        host_request(
            "POST",
            OPENAI_TOKEN_PATH,
            "",
            "application/x-www-form-urlencoded",
            form.as_bytes(),
        ),
        token_request(&nonce),
    ] {
        let (status, answer) = harness.front_door(request).await;
        assert_eq!(status, StatusCode::OK);
        assert_managed_answer(&answer);
    }
}

/// A stored sign-in near expiry is refreshed first, server side, with its
/// own refresh token; the answer still carries only placeholders.
#[tokio::test]
async fn a_stored_sign_in_near_expiry_is_refreshed_with_its_own_token_first() {
    let now = current_unix_time().unwrap();
    let rotated = json!({
        "access_token": jwt(&json!({ "iat": now, "exp": now + FRESH })),
        "refresh_token": "synthetic-rotated-refresh",
    })
    .to_string();
    let harness = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Placement::Hosted,
        Some(Ok((StatusCode::OK, rotated))),
    );
    let (status, answer) = harness
        .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_managed_answer(&answer);
    let outbound = harness.outbound();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].1, TOKEN_URL);
    assert!(String::from_utf8_lossy(&outbound[0].3).contains("synthetic-stored-refresh"));
    assert_nothing_of_ours_sent(&outbound);
    assert_eq!(harness.sign_in.commits.load(Ordering::Relaxed), 1);
}

/// A revoked credential, one that needs Reconnect, one whose refresh OpenAI
/// refuses, and a Codex slot that holds no sign-in are all `invalid_grant`.
#[tokio::test]
async fn a_revoked_or_refresh_failed_sign_in_is_invalid_grant() {
    let invalid_grant = (
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_grant", "error_description": RENEW }),
    );
    let refused = Harness::new(
        SignIn::new(material(NEAR_EXPIRY)),
        Placement::Hosted,
        Some(Ok((
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant"}"#.to_owned(),
        ))),
    );
    assert_eq!(
        refused
            .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
            .await,
        invalid_grant
    );
    assert_eq!(refused.sign_in.failures.load(Ordering::Relaxed), 1);
    assert_nothing_of_ours_sent(&refused.outbound());

    let withheld = |reason| SignIn {
        lease_error: Some(BrokerLeaseError::ReconnectRequired(reason)),
        ..SignIn::new(material(FRESH))
    };
    let api_key = SignIn {
        kind: CredentialAuthKind::ApiKey,
        ..SignIn::new(material(FRESH))
    };
    for sign_in in [
        withheld(WithheldReason::Revoked),
        withheld(WithheldReason::NeedsReconnect),
        api_key,
    ] {
        let harness = Harness::unasked(sign_in, Placement::Hosted);
        assert_eq!(
            harness
                .front_door(token_request(REQUEST_FIXTURE.as_bytes()))
                .await,
            invalid_grant
        );
    }
}

/// The user's own requests to the token endpoint: a refresh with another
/// token, and another grant.
fn users_own_token_requests() -> [v1::CredentialBridgeRequest; 2] {
    [
        token_request(&refresh_with("synthetic-users-own-refresh")),
        token_request(
            br#"{"grant_type":"authorization_code","code":"synthetic-code","client_id":"app_synthetic"}"#,
        ),
    ]
}

/// The user's own request to another path of the token host: the sign-in
/// page.
fn sign_in_page() -> v1::CredentialBridgeRequest {
    host_request(
        "GET",
        "/oauth/authorize",
        "client_id=app_synthetic&response_type=code",
        "text/html",
        b"",
    )
}

/// On hosted, the user's own requests are refused before anything is sent
/// and with no lease, as every own key on a bound host is (#5555).
#[tokio::test]
async fn hosted_refuses_the_users_own_requests_with_nothing_sent() {
    let harness = Harness::unasked(SignIn::new(material(FRESH)), Placement::Hosted);
    let [refresh, grant] = users_own_token_requests();
    for request in [refresh, grant, sign_in_page()] {
        assert_eq!(
            harness.front_door(request).await,
            (StatusCode::FORBIDDEN, json!({ "error": "invalid_request" }))
        );
    }
    assert_eq!(harness.leases(), 0);
}

/// Where the policy allows the host, the user's own token requests go to
/// `auth.openai.com` as they were sent, with no lease, and the reply comes
/// back as it came.
#[tokio::test]
async fn where_the_policy_allows_it_the_users_own_request_is_forwarded_untouched() {
    let harness = Harness::new(
        SignIn::new(material(FRESH)),
        Placement::LocalAllowed,
        Some(Ok((StatusCode::OK, r#"{"provider":"answer"}"#.to_owned()))),
    );
    for request in users_own_token_requests() {
        let sent = request.clone();
        assert_eq!(
            harness.front_door(request).await,
            (StatusCode::OK, json!({ "provider": "answer" }))
        );
        let (method, target, headers, body) = harness.outbound().pop().unwrap();
        assert_eq!(method.as_str(), sent.method);
        let query = if sent.query.is_empty() {
            String::new()
        } else {
            format!("?{}", sent.query)
        };
        assert_eq!(
            target,
            format!("https://auth.openai.com{}{query}", sent.path)
        );
        assert_eq!(body, sent.body);
        assert_eq!(headers["content-type"].as_bytes(), sent.headers[0].value);
        // Asked for an uncompressed answer, which the transport passes on
        // (#6362).
        assert_eq!(headers["accept-encoding"], "identity");
    }
    assert_eq!(harness.outbound().len(), 2);
    assert_eq!(harness.leases(), 0);
}

/// Another path of the token host is handed to the transport untouched, and
/// the transport sends a sign-in's requests to its token endpoint only
/// (`network.rs`): its refusal is the agent's `invalid_request`, never
/// `invalid_grant`, since the user's own sign-in is not Codewire's to end.
#[tokio::test]
async fn another_path_the_transport_does_not_send_is_invalid_request() {
    let harness = Harness::new(
        SignIn::new(material(FRESH)),
        Placement::LocalAllowed,
        Some(Err(BrokerUpstreamError::DestinationDenied)),
    );
    assert_eq!(
        harness.front_door(sign_in_page()).await,
        (StatusCode::FORBIDDEN, json!({ "error": "invalid_request" }))
    );
    let (method, target, _, _) = harness.outbound().pop().unwrap();
    assert_eq!(
        (method, target.as_str()),
        (
            Method::GET,
            "https://auth.openai.com/oauth/authorize?client_id=app_synthetic&response_type=code"
        )
    );
    assert_eq!(harness.leases(), 0);
}

/// A marker or a placeholder anywhere but a managed refresh, and a managed
/// refresh beside a credential header, is refused and never forwarded.
#[tokio::test]
async fn a_codewire_value_outside_a_managed_refresh_is_refused() {
    let harness = Harness::unasked(SignIn::new(material(FRESH)), Placement::LocalAllowed);
    let mut with_header = token_request(REQUEST_FIXTURE.as_bytes());
    with_header.headers.push(v1::CredentialHttpHeader {
        name: "authorization".into(),
        value: b"Bearer synthetic-other".to_vec(),
    });
    let mut repeated = token_request(b"");
    repeated.body = br#"{"grant_type":"refresh_token","refresh_token":"a","refresh_token":"b","client_id":"c"}"#.to_vec();
    for request in [
        // The marker on another grant, and on another path.
        token_request(
            format!(
                r#"{{"grant_type":"authorization_code","code":"{CODEX_MANAGED_REFRESH_TOKEN}","client_id":"c"}}"#
            )
            .as_bytes(),
        ),
        host_request(
            "POST",
            "/oauth/revoke",
            "",
            "application/json",
            format!(r#"{{"token":"{CODEX_MANAGED_REFRESH_TOKEN}"}}"#).as_bytes(),
        ),
        // The placeholder, on the user's own refresh.
        token_request(&refresh_with(OURS)),
        with_header,
        repeated,
    ] {
        assert_eq!(
            harness.front_door(request).await,
            (StatusCode::BAD_REQUEST, json!({ "error": "invalid_request" }))
        );
    }
    assert_eq!(harness.leases(), 0);
}

/// Codex's token host is the Codex slot's alone, and only on a front-door
/// session: no other slot's route names it, and the Codex route names no
/// other token host.
#[tokio::test]
async fn the_token_host_is_served_only_on_the_codex_route_behind_the_front_door() {
    let harness = Harness::unasked(SignIn::new(material(FRESH)), Placement::Hosted);
    let mut anthropic = token_request(REQUEST_FIXTURE.as_bytes());
    anthropic.capability_slot = "anthropic".into();
    anthropic.route = "claude-oauth-token".into();
    let mut openai = token_request(REQUEST_FIXTURE.as_bytes());
    openai.capability_slot = "openai".into();
    let mut claude_host = token_request(REQUEST_FIXTURE.as_bytes());
    claude_host.intercepted_host = "platform.claude.com".into();
    for request in [anthropic, openai, claude_host] {
        assert!(matches!(
            harness.broker.execute_front_door(request).await,
            Err(BrokerRequestError::InvalidRequest)
        ));
    }
    let loopback = token_request(REQUEST_FIXTURE.as_bytes());
    assert!(matches!(
        harness
            .broker
            .execute_on(BridgeEntry::Loopback, loopback, None, None)
            .await,
        Err(BrokerRequestError::InvalidRequest)
    ));
    assert_eq!(harness.leases(), 0);
}
