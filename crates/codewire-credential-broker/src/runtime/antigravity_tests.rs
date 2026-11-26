//! Runtime proofs for Antigravity front-door swap, OAuth token host, loopback
//! refusal, and placeholder-only sealed login (#6555).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{
    ANTIGRAVITY_DAILY_HOST, ANTIGRAVITY_MANAGED_REFRESH_TOKEN, ANTIGRAVITY_PROD_HOST,
    CapabilitySlot, CredentialAuthKind, CredentialPlaceholder,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_workload_secrets::{CodexLoginContext, ProjectionRecipient};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::antigravity_oauth::{
    ANTIGRAVITY_REQUIRED_SCOPES, AntigravityIssuedTokens, import_antigravity_tokens,
};
use crate::bridge::BridgeEntry;
use crate::http_test_support::Lease;
use crate::network::RouteHost;
use crate::{
    BrokerCredentialRefreshRequest, BrokerLeaseError, BrokerRefreshAdmission, BrokerRefreshError,
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, CanonicalCodexOAuthBundle,
    CommitFailure,
};

const OURS: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REAL_ACCESS: &str = "ya29.a0SyntheticAntigravityAccessTokenForUnitTests0123456789";
const REAL_REFRESH: &str = "1//0gSyntheticAntigravityRefreshTokenForUnitTests0123456789";

type Outbound = (Method, String, HeaderMap, Vec<u8>);

struct AntigravitySignInProvider {
    material: Mutex<Vec<u8>>,
    placeholder: Option<&'static str>,
    leases: AtomicUsize,
    commits: AtomicUsize,
    refreshing: AtomicBool,
}

impl AntigravitySignInProvider {
    fn new(material: Vec<u8>) -> Self {
        Self {
            material: Mutex::new(material),
            placeholder: Some(OURS),
            leases: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            refreshing: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl BrokerLeaseProvider for Arc<AntigravitySignInProvider> {
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
        let mut lease = Lease::new(
            "google",
            CredentialAuthKind::OAuth,
            slot.as_str(),
            operation.as_str(),
            route.as_str(),
        );
        lease.grant.environment_id =
            codewire_access::EnvironmentId::parse("33333333-3333-4333-8333-333333333333").unwrap();
        lease.material = Zeroizing::new(self.material.lock().unwrap().clone());
        lease.placeholder = self
            .placeholder
            .map(|value| CredentialPlaceholder::parse(value).unwrap());
        Ok(lease)
    }

    async fn lease_antigravity_login(&self, id: Uuid) -> Result<Lease, BrokerLeaseError> {
        let perm = antigravity_login_permission();
        self.lease_operation(
            id,
            CapabilitySlot::antigravity(),
            perm.operation,
            perm.route,
        )
        .await
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
        panic!("Antigravity committed Codex material")
    }

    async fn commit_antigravity_oauth_refresh(
        &self,
        _: (),
        material: CanonicalAntigravityOAuthBundle,
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
        self.refreshing.store(false, Ordering::Release);
        Ok(())
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct RecordingUpstream {
    seen: Mutex<Vec<Outbound>>,
    reply_status: StatusCode,
    reply_body: Vec<u8>,
}

impl RecordingUpstream {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            reply_status: StatusCode::OK,
            reply_body: body,
        }
    }
}

#[async_trait]
impl BrokerUpstreamTransport for Arc<RecordingUpstream> {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.seen.lock().unwrap().push((
            request.method,
            request.target.to_string(),
            request.headers,
            request.body,
        ));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let body = Bytes::from(self.reply_body.clone());
        Ok(BrokerUpstreamResponse::new(
            self.reply_status,
            headers,
            Box::pin(futures::stream::once(async move { Ok(body) })),
        ))
    }
}

fn fresh_antigravity_bundle() -> Vec<u8> {
    let scope = ANTIGRAVITY_REQUIRED_SCOPES.join(" ");
    import_antigravity_tokens(AntigravityIssuedTokens {
        access_token: Zeroizing::new(REAL_ACCESS.to_owned()),
        refresh_token: Some(Zeroizing::new(REAL_REFRESH.to_owned())),
        expires_in: 3600,
        scope: Some(scope),
        id_token: None,
    })
    .unwrap()
    .into_parts()
    .0
    .into_bytes()
    .to_vec()
}

fn guest_request(
    method: Method,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
    body: Vec<u8>,
    intercepted_host: Option<RouteHost>,
) -> ValidatedGuestRequest {
    ValidatedGuestRequest {
        request_id: Uuid::new_v4(),
        slot: CapabilitySlot::antigravity(),
        route: BrokerRouteId::parse("antigravity-api").unwrap(),
        method,
        path: path.to_owned(),
        query: query.map(str::to_owned),
        headers,
        body,
        intercepted_host,
        routed: None,
    }
}

async fn read_body(response: BrokerHttpResponse) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (status, headers, mut stream) = response.into_parts();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    (status, headers, out)
}

#[tokio::test]
async fn antigravity_swaps_placeholder_only_on_post_v1internal_and_redacts_reflection() {
    let provider = Arc::new(AntigravitySignInProvider::new(fresh_antigravity_bundle()));
    let upstream = Arc::new(RecordingUpstream::ok(
        format!("{{\"ok\":true,\"echo\":\"{REAL_ACCESS}\"}}").into_bytes(),
    ));
    let broker = OpenAiBroker::new(provider.clone(), upstream.clone()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {OURS}")).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let response = broker
        .execute_antigravity_swap(
            RouteHost::AntigravityDaily,
            guest_request(
                Method::POST,
                "/v1internal:streamGenerateContent",
                Some("alt=sse"),
                headers,
                b"{}".to_vec(),
                Some(RouteHost::AntigravityDaily),
            ),
        )
        .await
        .unwrap();
    let (status, _, body) = read_body(response).await;
    assert_eq!(status, StatusCode::OK);
    let body_text = String::from_utf8(body).unwrap();
    assert!(
        !body_text.contains(REAL_ACCESS),
        "real access token must be redacted from response body"
    );

    let sent = upstream.seen.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].1,
        format!("https://{ANTIGRAVITY_DAILY_HOST}/v1internal:streamGenerateContent?alt=sse")
    );
    assert_eq!(
        sent[0].2.get(header::AUTHORIZATION).unwrap(),
        &format!("Bearer {REAL_ACCESS}")
    );
}

#[tokio::test]
async fn antigravity_refuses_non_v1internal_path_encoded_query_and_credential_conflict() {
    let provider = Arc::new(AntigravitySignInProvider::new(fresh_antigravity_bundle()));
    let upstream = Arc::new(RecordingUpstream::ok(b"{}".to_vec()));
    let broker = OpenAiBroker::new(provider, upstream.clone()).unwrap();

    let bearer_ours = || {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {OURS}")).unwrap(),
        );
        h
    };

    // 1. Non-POST or non-v1internal path with our placeholder -> 403 path_not_served.
    for (method, path) in [
        (Method::GET, "/v1internal:loadCodeAssist"),
        (Method::POST, "/v1/models"),
        (Method::POST, "/v1internal:foo/bar"),
    ] {
        let resp = broker
            .execute_antigravity_swap(
                RouteHost::AntigravityProd,
                guest_request(
                    method,
                    path,
                    None,
                    bearer_ours(),
                    Vec::new(),
                    Some(RouteHost::AntigravityProd),
                ),
            )
            .await
            .unwrap();
        let (status, headers, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "path {path}");
        assert_eq!(
            headers.get(codewire_access::REFUSAL_HEADER).unwrap(),
            "path_not_served",
            "host {ANTIGRAVITY_PROD_HOST} path {path}"
        );
    }

    // 2. Placeholder in percent-encoded query param -> 400 InvalidRequest.
    let encoded_query = format!("key=cwp1%5F{}", &OURS[5..]);
    let err = broker
        .execute_antigravity_swap(
            RouteHost::AntigravityDaily,
            guest_request(
                Method::POST,
                "/v1internal:loadCodeAssist",
                Some(&encoded_query),
                HeaderMap::new(),
                Vec::new(),
                Some(RouteHost::AntigravityDaily),
            ),
        )
        .await
        .err()
        .expect("encoded placeholder in query must fail closed");
    assert_eq!(err, BrokerRequestError::InvalidRequest);

    // 3. `key=` or `access_token=` query param beside swapped Bearer -> 400 credential_conflict.
    for query in ["key=other-key", "access_token=other-token"] {
        let resp = broker
            .execute_antigravity_swap(
                RouteHost::AntigravityDaily,
                guest_request(
                    Method::POST,
                    "/v1internal:loadCodeAssist",
                    Some(query),
                    bearer_ours(),
                    Vec::new(),
                    Some(RouteHost::AntigravityDaily),
                ),
            )
            .await
            .unwrap();
        let (status, _, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "query {query}");
    }
    assert!(
        upstream.seen.lock().unwrap().is_empty(),
        "no refused request may reach upstream"
    );
}

#[tokio::test]
async fn antigravity_is_refused_on_loopback_bridge_entry() {
    let provider = Arc::new(AntigravitySignInProvider::new(fresh_antigravity_bundle()));
    let upstream = Arc::new(RecordingUpstream::ok(b"{}".to_vec()));
    let broker = OpenAiBroker::new(provider, upstream).unwrap();
    let request = v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        capability_slot: "antigravity".to_owned(),
        route: "antigravity-api".to_owned(),
        method: "POST".to_owned(),
        path: "/v1internal:loadCodeAssist".to_owned(),
        query: String::new(),
        headers: vec![v1::CredentialHttpHeader {
            name: "authorization".to_owned(),
            value: format!("Bearer {OURS}").into_bytes(),
        }],
        body: b"{}".to_vec(),
        streamed_body: false,
        intercepted_host: String::new(),
        destination_ip: String::new(),
        intercept_decision: Vec::new(),
    };
    let err = broker
        .execute_on(BridgeEntry::Loopback, request, None, None)
        .await
        .err()
        .expect("antigravity must be refused on loopback");
    assert_eq!(err, BrokerRequestError::InvalidRequest);
}

#[tokio::test]
async fn antigravity_token_host_answers_managed_refresh_with_placeholder_and_refuses_revoke() {
    let provider = Arc::new(AntigravitySignInProvider::new(fresh_antigravity_bundle()));
    let upstream = Arc::new(RecordingUpstream::ok(b"{}".to_vec()));
    let broker = OpenAiBroker::new(provider, upstream.clone()).unwrap();

    let mut form_headers = HeaderMap::new();
    form_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let body = format!(
        "grant_type=refresh_token&refresh_token={ANTIGRAVITY_MANAGED_REFRESH_TOKEN}&client_id=test"
    )
    .into_bytes();
    let resp = broker
        .execute_antigravity_token(ValidatedGuestRequest {
            request_id: Uuid::new_v4(),
            slot: CapabilitySlot::antigravity(),
            route: BrokerRouteId::parse("antigravity-oauth-token").unwrap(),
            method: Method::POST,
            path: "/token".to_owned(),
            query: None,
            headers: form_headers.clone(),
            body,
            intercepted_host: Some(RouteHost::AntigravityOAuth),
            routed: None,
        })
        .await
        .unwrap();
    let (status, _, raw) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(parsed["access_token"], OURS);
    assert_eq!(parsed["refresh_token"], ANTIGRAVITY_MANAGED_REFRESH_TOKEN);
    assert_eq!(parsed["token_type"], "Bearer");
    assert!(!String::from_utf8_lossy(&raw).contains(REAL_ACCESS));
    assert!(!String::from_utf8_lossy(&raw).contains(REAL_REFRESH));

    // Sending Codewire's placeholder or managed marker to /revoke must fail closed (400).
    for token in [OURS, ANTIGRAVITY_MANAGED_REFRESH_TOKEN] {
        let resp = broker
            .execute_antigravity_token(ValidatedGuestRequest {
                request_id: Uuid::new_v4(),
                slot: CapabilitySlot::antigravity(),
                route: BrokerRouteId::parse("antigravity-oauth-token").unwrap(),
                method: Method::POST,
                path: "/revoke".to_owned(),
                query: None,
                headers: form_headers.clone(),
                body: format!("token={token}").into_bytes(),
                intercepted_host: Some(RouteHost::AntigravityOAuth),
                routed: None,
            })
            .await
            .unwrap();
        let (status, _, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "token {token}");
    }
    assert!(upstream.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antigravity_login_seals_only_placeholder_and_refuses_real_delivery() {
    let provider = Arc::new(AntigravitySignInProvider::new(fresh_antigravity_bundle()));
    let upstream = Arc::new(RecordingUpstream::ok(b"{}".to_vec()));
    let recipient = ProjectionRecipient::new();
    let now_ms = current_unix_time_ms().unwrap();
    let request_id = Uuid::new_v4();
    let request = v1::AntigravityLoginRequest {
        request_id: request_id.to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        deadline_unix_ms: now_ms + 30_000,
    };

    // Real (non-intercepted) and Refused deliveries MUST refuse antigravity_login.
    for delivery in [LoginDelivery::Real, LoginDelivery::Refused] {
        let mut broker = OpenAiBroker::new(provider.clone(), upstream.clone()).unwrap();
        broker.login_delivery = delivery;
        let err = broker
            .antigravity_login(request.clone())
            .await
            .expect_err("non-placeholder delivery must refuse antigravity_login");
        assert_eq!(err, BrokerRequestError::Denied);
    }

    // Placeholder delivery succeeds and seals ONLY the cwp1_ placeholder.
    let mut broker = OpenAiBroker::new(provider.clone(), upstream.clone()).unwrap();
    broker.login_delivery = LoginDelivery::Placeholder;
    let sealed = broker.antigravity_login(request.clone()).await.unwrap();
    let probe_lease = Lease::new(
        "google",
        CredentialAuthKind::OAuth,
        "antigravity",
        "antigravity-login",
        "antigravity-login",
    );
    let env_id = Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
    let context = CodexLoginContext {
        environment_id: env_id.into_bytes(),
        environment_generation: probe_lease.grant.environment_generation,
        request_id: request_id.into_bytes(),
        deadline_unix_ms: request.deadline_unix_ms,
    };
    let opened = recipient
        .open_antigravity_login(&sealed, &context, now_ms)
        .unwrap();
    assert_eq!(opened.login.placeholder(), OURS);
    assert!(!opened.login.placeholder().contains(REAL_ACCESS));
    assert!(!opened.login.placeholder().contains(REAL_REFRESH));
}
