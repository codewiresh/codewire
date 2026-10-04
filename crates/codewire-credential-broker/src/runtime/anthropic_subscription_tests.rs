//! The broker's Claude subscription token dispatch: the lease's credential
//! kind selects the form, and a provider 401 marks that exact generation as
//! needing a new token instead of being refreshed or replayed.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::http_test_support::{Lease, TOKEN};
use codewire_access::CapabilitySlot;

struct Authority {
    kind: CredentialAuthKind,
    rejections: Arc<Mutex<Vec<BrokerCredentialRejection>>>,
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerLeaseProvider for Authority {
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
        assert_eq!(slot, CapabilitySlot::anthropic());
        let mut lease = Lease::new(
            "anthropic",
            self.kind,
            "anthropic",
            operation.as_str(),
            route.as_str(),
        );
        lease.reads = self.reads.clone();
        Ok(lease)
    }
    async fn reject_credential(
        &self,
        rejection: BrokerCredentialRejection,
    ) -> Result<(), BrokerRefreshError> {
        self.rejections.lock().unwrap().push(rejection);
        Ok(())
    }
    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        panic!("a Claude subscription token has no refresh")
    }
    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("a Claude subscription token has no refresh")
    }
    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        panic!("a Claude subscription token has no refresh")
    }
    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("a Claude subscription token has no refresh")
    }
    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("a Claude subscription token has no refresh")
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct Upstream {
    status: StatusCode,
    error_type: &'static str,
    requests: Arc<Mutex<Vec<(String, HeaderMap)>>>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_, target, headers, _) = request.into_parts();
        self.requests
            .lock()
            .unwrap()
            .push((target.to_string(), headers));
        // The provider body reflects the token; it must never reach the guest.
        let body = format!(
            "{{\"type\":\"error\",\"error\":{{\"type\":\"{}\",\"message\":\"{}\"}}}}",
            self.error_type,
            std::str::from_utf8(TOKEN).unwrap()
        );
        let split = body.len() / 2;
        let (first, second) = (
            Bytes::copy_from_slice(&body.as_bytes()[..split]),
            Bytes::copy_from_slice(&body.as_bytes()[split..]),
        );
        Ok(BrokerUpstreamResponse::new(
            self.status,
            HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::iter([Ok(first), Ok(second)])),
        ))
    }
}

fn broker(kind: CredentialAuthKind, status: StatusCode) -> OpenAiBroker<Authority, Upstream> {
    broker_with(kind, status, "authentication_error")
}

fn broker_with(
    kind: CredentialAuthKind,
    status: StatusCode,
    error_type: &'static str,
) -> OpenAiBroker<Authority, Upstream> {
    OpenAiBroker::new(
        Authority {
            kind,
            rejections: Arc::new(Mutex::new(Vec::new())),
            reads: Arc::new(AtomicUsize::new(0)),
        },
        Upstream {
            status,
            error_type,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
    )
    .unwrap()
}

fn redacted_error(error_type: &str) -> Vec<u8> {
    format!(
        "{{\"type\":\"error\",\"error\":{{\"type\":\"{error_type}\",\"message\":\"[REDACTED]\"}}}}"
    )
    .into_bytes()
}

fn request(request_id: Uuid) -> v1::CredentialBridgeRequest {
    let header = |name: &str, value: &str| v1::CredentialHttpHeader {
        name: name.into(),
        value: value.as_bytes().to_vec(),
    };
    v1::CredentialBridgeRequest {
        request_id: request_id.to_string(),
        capability_slot: "anthropic".into(),
        route: "anthropic-api".into(),
        method: "POST".into(),
        path: "/messages".into(),
        query: "beta=true".into(),
        headers: vec![
            header("content-type", "application/json"),
            header("anthropic-version", "2023-06-01"),
            header("authorization", "Bearer codewire-managed"),
            header("anthropic-beta", "claude-code-20250219"),
            header("user-agent", "claude-cli/2.1.238 (external, sdk-cli)"),
            header("x-app", "cli"),
        ],
        body: br#"{"model":"synthetic","max_tokens":1,"messages":[]}"#.to_vec(),
    }
}

async fn read(body: BrokerResponseBody) -> Vec<u8> {
    let mut body = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend(chunk.unwrap());
    }
    bytes
}

#[tokio::test]
async fn an_oauth_lease_selects_the_subscription_form_with_the_stored_bearer() {
    let broker = broker(CredentialAuthKind::OAuth, StatusCode::OK);
    let response = broker.execute(request(Uuid::new_v4())).await.unwrap();
    let requests = broker.upstream.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    let (target, headers) = &requests[0];
    assert_eq!(target, "https://api.anthropic.com/v1/messages?beta=true");
    assert_eq!(
        headers["authorization"].as_bytes(),
        [b"Bearer ".as_slice(), TOKEN].concat()
    );
    assert!(!headers.contains_key("x-api-key"));
    assert_eq!(
        headers["anthropic-beta"],
        "claude-code-20250219,oauth-2025-04-20"
    );
    assert_eq!(headers["x-app"], "cli");
    assert_eq!(broker.leases.reads.load(Ordering::Relaxed), 1);
    assert!(broker.leases.rejections.lock().unwrap().is_empty());
    let (status, _, body) = response.into_parts();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read(body).await, redacted_error("authentication_error"));
}

#[tokio::test]
async fn a_provider_401_marks_the_exact_generation_and_answers_reconnect_without_retry() {
    let broker = broker(CredentialAuthKind::OAuth, StatusCode::UNAUTHORIZED);
    let request_id = Uuid::new_v4();
    let response = broker
        .execute(request(request_id))
        .await
        .expect("a refused token still answers its route");
    // One provider call: there is no refresh and no replay.
    assert_eq!(broker.upstream.requests.lock().unwrap().len(), 1);
    let rejections = broker.leases.rejections.lock().unwrap().clone();
    assert_eq!(rejections.len(), 1);
    let rejection = &rejections[0];
    let lease = Lease::new(
        "anthropic",
        CredentialAuthKind::OAuth,
        "anthropic",
        "messages",
        "anthropic-api",
    );
    assert_eq!(rejection.request_id, request_id);
    assert_eq!(rejection.grant, lease.grant);
    assert_eq!(rejection.operation.as_str(), "messages");
    assert_eq!(rejection.route.as_str(), "anthropic-api");
    assert_eq!(rejection.material_generation, 2);
    let (status, headers, body) = response.into_parts();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headers["content-type"], "application/json");
    let bytes = read(body).await;
    assert!(!bytes.windows(TOKEN.len()).any(|window| window == TOKEN));
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["type"], "error");
    assert_eq!(json["error"]["type"], "permission_error");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Codewire Settings → Credentials")
    );
}

#[tokio::test]
async fn a_401_that_is_not_an_authentication_refusal_is_returned_and_marks_nothing() {
    for error_type in [
        "invalid_request_error",
        "permission_error",
        "rate_limit_error",
    ] {
        let broker = broker_with(
            CredentialAuthKind::OAuth,
            StatusCode::UNAUTHORIZED,
            error_type,
        );
        let response = broker.execute(request(Uuid::new_v4())).await.unwrap();
        assert!(broker.leases.rejections.lock().unwrap().is_empty());
        assert_eq!(broker.upstream.requests.lock().unwrap().len(), 1);
        let (status, _, body) = response.into_parts();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(read(body).await, redacted_error(error_type));
    }
}

#[tokio::test]
async fn an_api_key_401_is_returned_unchanged_and_marks_nothing() {
    let broker = broker(CredentialAuthKind::ApiKey, StatusCode::UNAUTHORIZED);
    let response = broker.execute(request(Uuid::new_v4())).await.unwrap();
    let requests = broker.upstream.requests.lock().unwrap().clone();
    let (_, headers) = &requests[0];
    assert_eq!(headers["x-api-key"].as_bytes(), TOKEN);
    assert!(!headers.contains_key("authorization"));
    assert!(!headers.contains_key("x-app"));
    assert_eq!(headers["anthropic-beta"], "claude-code-20250219");
    assert!(broker.leases.rejections.lock().unwrap().is_empty());
    let (status, _, body) = response.into_parts();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(read(body).await, redacted_error("authentication_error"));
}
