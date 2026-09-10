use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use super::*;
use crate::http_test_support::Lease;

struct Authority {
    slot: &'static str,
    wrong_slot: bool,
    calls: Arc<Mutex<Vec<(String, String, String)>>>,
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
        self.calls.lock().unwrap().push((
            slot.to_string(),
            operation.to_string(),
            route.to_string(),
        ));
        if slot.as_str() != self.slot {
            return Err(BrokerLeaseError::Denied);
        }
        let (provider, kind) = match self.slot {
            "codex" | "openai" => ("openai", CredentialAuthKind::ApiKey),
            "anthropic" => ("anthropic", CredentialAuthKind::ApiKey),
            "github" => ("github", CredentialAuthKind::OAuth),
            _ => return Err(BrokerLeaseError::Denied),
        };
        let mut lease = Lease::new(
            provider,
            kind,
            self.slot,
            operation.as_str(),
            route.as_str(),
        );
        lease.reads = self.reads.clone();
        if self.wrong_slot {
            lease.grant.capability_slot = CapabilitySlot::parse("wrong-slot").unwrap();
        }
        Ok(lease)
    }
    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing HTTP identity attempted refresh")
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct Upstream {
    calls: Arc<Mutex<Vec<(Method, String)>>>,
    polls: Arc<AtomicUsize>,
    bad_encoding: bool,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, _) = request.into_parts();
        self.calls
            .lock()
            .unwrap()
            .push((method, target.to_string()));
        let material = headers
            .get("authorization")
            .or_else(|| headers.get("x-api-key"))
            .expect("synthetic injected authorization")
            .as_bytes()
            .to_vec();
        let media = if target.host_str() == Some("github.com") {
            if target.path().ends_with("/git-receive-pack") {
                "application/x-git-receive-pack-result"
            } else {
                "application/x-git-upload-pack-result"
            }
        } else {
            "application/json"
        };
        let mut headers =
            HeaderMap::from_iter([(http::header::CONTENT_TYPE, HeaderValue::from_static(media))]);
        if self.bad_encoding {
            headers.insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
        }
        let polls = self.polls.clone();
        let mut chunks = Vec::from([
            Bytes::copy_from_slice(&material[..material.len() / 2]),
            Bytes::copy_from_slice(&material[material.len() / 2..]),
        ])
        .into_iter();
        let body = futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(chunks.next().map(Ok))
        });
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Box::pin(body),
        ))
    }
}

fn broker(
    slot: &'static str,
    wrong_slot: bool,
    bad_encoding: bool,
) -> OpenAiBroker<Authority, Upstream> {
    OpenAiBroker::new(
        Authority {
            slot,
            wrong_slot,
            calls: Arc::new(Mutex::new(Vec::new())),
            reads: Arc::new(AtomicUsize::new(0)),
        },
        Upstream {
            calls: Arc::new(Mutex::new(Vec::new())),
            polls: Arc::new(AtomicUsize::new(0)),
            bad_encoding,
        },
    )
    .unwrap()
}

fn request(
    slot: &str,
    route: &str,
    method: &str,
    path: &str,
    body: &[u8],
    media: &str,
) -> v1::CredentialBridgeRequest {
    let mut headers = vec![v1::CredentialHttpHeader {
        name: "content-type".into(),
        value: media.as_bytes().to_vec(),
    }];
    if slot == "anthropic" {
        headers.push(v1::CredentialHttpHeader {
            name: "anthropic-version".into(),
            value: b"2023-06-01".to_vec(),
        });
    }
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        capability_slot: slot.into(),
        route: route.into(),
        method: method.into(),
        path: path.into(),
        query: String::new(),
        headers,
        body: body.to_vec(),
    }
}

type ProviderCase = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    &'static str,
    &'static str,
);

fn cases() -> Vec<ProviderCase> {
    vec![
        (
            "codex",
            "openai-api",
            "responses",
            "POST",
            "/responses",
            b"{}",
            "application/json",
            "https://api.openai.com/v1/responses",
        ),
        (
            "openai",
            "openai-api",
            "responses",
            "POST",
            "/responses",
            b"{}",
            "application/json",
            "https://api.openai.com/v1/responses",
        ),
        (
            "anthropic",
            "anthropic-api",
            "messages",
            "POST",
            "/messages",
            b"{}",
            "application/json",
            "https://api.anthropic.com/v1/messages",
        ),
        (
            "anthropic",
            "anthropic-api",
            "count-tokens",
            "POST",
            "/messages/count_tokens",
            b"{}",
            "application/json",
            "https://api.anthropic.com/v1/messages/count_tokens",
        ),
        (
            "github",
            "github-api",
            "rest",
            "GET",
            "/user",
            b"",
            "application/json",
            "https://api.github.com/user",
        ),
        (
            "github",
            "github-api",
            "graphql",
            "POST",
            "/graphql",
            br#"{"query":"query { viewer { login } }"}"#,
            "application/json",
            "https://api.github.com/graphql",
        ),
        (
            "github",
            "github-https",
            "git-fetch",
            "POST",
            "/owner/repo.git/git-upload-pack",
            b"0000",
            "application/x-git-upload-pack-request",
            "https://github.com/owner/repo.git/git-upload-pack",
        ),
        (
            "github",
            "github-https",
            "git-push",
            "POST",
            "/owner/repo.git/git-receive-pack",
            b"0000",
            "application/x-git-receive-pack-request",
            "https://github.com/owner/repo.git/git-receive-pack",
        ),
    ]
}

#[tokio::test]
async fn named_http_slots_dispatch_exact_operations_and_redact_before_guest_streaming() {
    for (slot, route, operation, method, path, body, media, target) in cases() {
        let broker = broker(slot, false, false);
        let response = broker
            .execute(request(slot, route, method, path, body, media))
            .await
            .unwrap();
        assert_eq!(
            *broker.leases.calls.lock().unwrap(),
            vec![(slot.into(), operation.into(), route.into())]
        );
        assert_eq!(
            *broker.upstream.calls.lock().unwrap(),
            vec![(
                Method::from_bytes(method.as_bytes()).unwrap(),
                target.into()
            )]
        );
        assert_eq!(broker.leases.reads.load(Ordering::Relaxed), 1);
        let (_, _, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            bytes.extend(chunk.unwrap());
        }
        assert_eq!(bytes, b"[REDACTED]", "{slot}/{operation}");
    }
}

#[tokio::test]
async fn wrong_slot_leases_and_unselected_routes_fail_before_material_or_upstream() {
    for (slot, route, _, method, path, body, media, _) in cases() {
        let broker = broker(slot, true, false);
        assert_eq!(
            broker
                .execute(request(slot, route, method, path, body, media))
                .await
                .err(),
            Some(BrokerRequestError::Denied)
        );
        assert_eq!(broker.leases.reads.load(Ordering::Relaxed), 0);
        assert!(broker.upstream.calls.lock().unwrap().is_empty());
    }
    for (slot, route) in [
        ("", "openai-api"),
        ("codex", ""),
        ("anthropic", "openai-api"),
        ("openai", "anthropic-api"),
        ("github", "https://evil.test"),
        ("other", "github-api"),
    ] {
        let broker = broker("codex", false, false);
        assert_eq!(
            broker
                .execute(request(
                    slot,
                    route,
                    "POST",
                    "/responses",
                    b"{}",
                    "application/json"
                ))
                .await
                .err(),
            Some(BrokerRequestError::InvalidRequest)
        );
        assert!(broker.leases.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn every_http_provider_rejects_encoded_response_before_any_body_poll() {
    for (slot, route, _, method, path, body, media, _) in cases() {
        let broker = broker(slot, false, true);
        assert_eq!(
            broker
                .execute(request(slot, route, method, path, body, media))
                .await
                .err(),
            Some(BrokerRequestError::UpstreamFailed)
        );
        assert_eq!(broker.upstream.polls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn application_only_none_transport_never_dials_a_provider() {
    let transport: Option<Upstream> = None;
    let request = BrokerUpstreamRequest {
        method: Method::POST,
        target: Url::parse("https://api.openai.com/v1/responses").unwrap(),
        headers: HeaderMap::new(),
        body: vec![],
    };
    assert_eq!(
        transport.execute(request).await.err(),
        Some(BrokerUpstreamError::DestinationDenied)
    );
}
