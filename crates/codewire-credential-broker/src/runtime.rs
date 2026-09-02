use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{BrokerOperationId, BrokerRouteId, CapabilitySlot};
use codewire_gateway_proto::daemon::v1;
use futures::Stream;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    BrokerCredentialLease, CredentialBrokerError, OpenAiApiKeyAdapter, OpenAiStreamingResponse,
};

const OPENAI_OPERATION: &str = "responses";
const OPENAI_ROUTE: &str = "openai-api";

/// Placement-specific admission for one exact provider operation.
#[async_trait]
pub trait BrokerLeaseProvider: Send + Sync {
    type Lease: BrokerCredentialLease + Send;

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError>;
}

/// Stable lease failures that never retain authority or protected-store
/// diagnostics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerLeaseError {
    #[error("credential broker lease request is invalid")]
    InvalidRequest,
    #[error("credential broker lease was denied")]
    Denied,
    #[error("credential broker lease authority is unavailable")]
    Unavailable,
    #[error("credential broker lease authority returned invalid metadata")]
    InvalidResponse,
}

#[cfg(feature = "local")]
#[async_trait]
impl<S> BrokerLeaseProvider for codewire_local_credentials::LocalCredentialBrokerLeaseClient<S>
where
    S: codewire_protected_store::ProtectedStore + Clone + 'static,
{
    type Lease = codewire_local_credentials::CredentialOperationLease;

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::lease_operation(
            &mut client,
            request_id,
            capability_slot,
            operation,
            route,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
                BrokerLeaseError::Unavailable
            }
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
        })
    }
}

/// Broker-owned transport for exactly one already-authorized upstream request.
/// Implementations own DNS resolution, socket creation, TLS, redirects, and
/// response framing; no credential-free process may implement this on behalf
/// of the broker.
#[async_trait]
pub trait BrokerUpstreamTransport: Send + Sync {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError>;
}

/// Stable upstream failures safe to map back to the guest.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerUpstreamError {
    #[error("credential broker upstream destination was denied")]
    DestinationDenied,
    #[error("credential broker upstream connection failed")]
    Connect,
    #[error("credential broker upstream protocol failed")]
    Protocol,
    #[error("credential broker upstream response exceeded a resource limit")]
    ResourceLimit,
}

/// Secret-bearing outbound request. This type intentionally has no `Debug`,
/// `Clone`, or serialization implementation.
pub struct BrokerUpstreamRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl BrokerUpstreamRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>) {
        (self.method, self.target, self.headers, self.body)
    }
}

pub type BrokerUpstreamBody =
    Pin<Box<dyn Stream<Item = Result<Bytes, BrokerUpstreamError>> + Send + 'static>>;

/// One upstream response before provider-specific filtering and redaction.
/// This type intentionally has no `Debug` or `Clone` implementation.
pub struct BrokerUpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: BrokerUpstreamBody,
}

impl BrokerUpstreamResponse {
    pub fn new(status: StatusCode, headers: HeaderMap, body: BrokerUpstreamBody) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    fn into_parts(self) -> (StatusCode, HeaderMap, BrokerUpstreamBody) {
        (self.status, self.headers, self.body)
    }
}

/// Fully filtered response ready for the material-free daemon bridge. The
/// body still streams with backpressure and may fail after response start.
pub struct BrokerHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: BrokerResponseBody,
}

pub type BrokerResponseBody =
    Pin<Box<dyn Stream<Item = Result<Bytes, BrokerRequestError>> + Send + 'static>>;

impl BrokerHttpResponse {
    /// Construct a response only after every header and body byte has passed
    /// provider filtering and redaction.
    pub fn new(status: StatusCode, headers: HeaderMap, body: BrokerResponseBody) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn into_parts(self) -> (StatusCode, HeaderMap, BrokerResponseBody) {
        (self.status, self.headers, self.body)
    }
}

/// Request/response failures safe to return over the material-free bridge.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerRequestError {
    #[error("credential broker guest request is invalid")]
    InvalidRequest,
    #[error("credential broker request was denied")]
    Denied,
    #[error("credential broker lease authority is unavailable")]
    AuthorityUnavailable,
    #[error("credential broker upstream request failed")]
    UpstreamFailed,
    #[error("credential broker response exceeded a resource limit")]
    ResponseTooLarge,
}

/// Provider broker shared by local and platform placements. Placement-specific
/// code supplies the lease authority and the broker-local upstream transport.
pub struct OpenAiBroker<P, U> {
    leases: P,
    upstream: U,
    adapter: OpenAiApiKeyAdapter,
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider,
    U: BrokerUpstreamTransport,
{
    pub fn new(leases: P, upstream: U) -> Result<Self, BrokerRequestError> {
        Ok(Self {
            leases,
            upstream,
            adapter: OpenAiApiKeyAdapter::new().map_err(map_adapter_error)?,
        })
    }

    /// Execute one credential-free guest request through the exact OpenAI
    /// adapter. The returned bytes are already filtered and redacted.
    pub async fn execute(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let request = ValidatedGuestRequest::parse(request)?;
        let provider_request = self
            .adapter
            .validate_request(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                CapabilitySlot::codex(),
                BrokerOperationId::parse(OPENAI_OPERATION)
                    .map_err(|_| BrokerRequestError::InvalidRequest)?,
                BrokerRouteId::parse(OPENAI_ROUTE)
                    .map_err(|_| BrokerRequestError::InvalidRequest)?,
            )
            .await
            .map_err(map_lease_error)?;
        let prepared = self
            .adapter
            .prepare_validated(lease, provider_request)
            .map_err(map_adapter_error)?;
        let (method, target, headers, body, response_policy) = prepared.into_parts();
        let upstream = self
            .upstream
            .execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
            })
            .await
            .map_err(map_upstream_error)?;
        let (status, upstream_headers, body) = upstream.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = response_policy
            .begin(&upstream_headers)
            .map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(redactor),
                finished: false,
            }),
        ))
    }
}

struct ValidatedGuestRequest {
    request_id: Uuid,
    method: Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ValidatedGuestRequest {
    fn parse(request: v1::CredentialBridgeRequest) -> Result<Self, BrokerRequestError> {
        let request_id =
            Uuid::parse_str(&request.request_id).map_err(|_| BrokerRequestError::InvalidRequest)?;
        if request_id.is_nil() || request_id.to_string() != request.request_id {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        if request.path.is_empty() || !request.path.starts_with('/') {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let query = (!request.query.is_empty()).then_some(request.query);
        let mut headers = HeaderMap::new();
        for header in request.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            let value = HeaderValue::from_bytes(&header.value)
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            headers.append(name, value);
        }
        Ok(Self {
            request_id,
            method,
            path: request.path,
            query,
            headers,
            body: request.body,
        })
    }
}

pub struct BrokerRedactedBody {
    upstream: BrokerUpstreamBody,
    redactor: Option<OpenAiStreamingResponse>,
    finished: bool,
}

impl Stream for BrokerRedactedBody {
    type Item = Result<Bytes, BrokerRequestError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match self.upstream.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                let Some(redactor) = self.redactor.as_mut() else {
                    self.finished = true;
                    return Poll::Ready(Some(Err(BrokerRequestError::UpstreamFailed)));
                };
                Poll::Ready(Some(
                    redactor
                        .push(&chunk)
                        .map(Bytes::from)
                        .map_err(map_adapter_error),
                ))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.redactor.take();
                Poll::Ready(Some(Err(map_upstream_error(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                let Some(redactor) = self.redactor.take() else {
                    return Poll::Ready(Some(Err(BrokerRequestError::UpstreamFailed)));
                };
                match redactor.finish().map_err(map_adapter_error) {
                    Ok(bytes) if bytes.is_empty() => Poll::Ready(None),
                    result => Poll::Ready(Some(result.map(Bytes::from))),
                }
            }
        }
    }
}

fn map_lease_error(error: BrokerLeaseError) -> BrokerRequestError {
    match error {
        BrokerLeaseError::InvalidRequest | BrokerLeaseError::Denied => BrokerRequestError::Denied,
        BrokerLeaseError::Unavailable | BrokerLeaseError::InvalidResponse => {
            BrokerRequestError::AuthorityUnavailable
        }
    }
}

fn map_adapter_error(error: CredentialBrokerError) -> BrokerRequestError {
    match error {
        CredentialBrokerError::RequestDenied
        | CredentialBrokerError::UnsupportedLease
        | CredentialBrokerError::InvalidCredentialMaterial => BrokerRequestError::Denied,
        CredentialBrokerError::ResponseTooLarge => BrokerRequestError::ResponseTooLarge,
        CredentialBrokerError::InvalidProviderPolicy | CredentialBrokerError::ResponseDenied => {
            BrokerRequestError::UpstreamFailed
        }
    }
}

fn map_upstream_error(error: BrokerUpstreamError) -> BrokerRequestError {
    match error {
        BrokerUpstreamError::DestinationDenied => BrokerRequestError::Denied,
        BrokerUpstreamError::ResourceLimit => BrokerRequestError::ResponseTooLarge,
        BrokerUpstreamError::Connect | BrokerUpstreamError::Protocol => {
            BrokerRequestError::UpstreamFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use codewire_access::{
        AccessProfileName, CapabilityPolicy, CredentialAuthKind, EnvironmentAccessBinding,
        EnvironmentId, GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
    };
    use codewire_local_credentials::{
        CredentialOperationLeaseRequest, LocalCredentialAuthority, NewCredential,
    };
    use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
    use futures::{StreamExt as _, stream};

    use super::*;

    const SYNTHETIC_KEY: &str = "CW_TEST_OPENAI_VALUE_123";

    struct TestLeaseProvider {
        authority: Arc<LocalCredentialAuthority<EphemeralProtectedStore>>,
        environment_id: EnvironmentId,
        lease_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BrokerLeaseProvider for TestLeaseProvider {
        type Lease = codewire_local_credentials::CredentialOperationLease;

        async fn lease_operation(
            &self,
            _request_id: Uuid,
            capability_slot: CapabilitySlot,
            operation: BrokerOperationId,
            route: BrokerRouteId,
        ) -> Result<Self::Lease, BrokerLeaseError> {
            self.lease_count.fetch_add(1, Ordering::Relaxed);
            self.authority
                .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
                    environment_id: self.environment_id.clone(),
                    environment_generation: 11,
                    capability_slot,
                    operation,
                    route,
                })
                .map_err(|_| BrokerLeaseError::Denied)
        }
    }

    struct SyntheticUpstream;

    #[async_trait]
    impl BrokerUpstreamTransport for SyntheticUpstream {
        async fn execute(
            &self,
            request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            let (method, target, headers, body) = request.into_parts();
            assert_eq!(method, Method::POST);
            assert_eq!(target.as_str(), "https://api.openai.com/v1/responses");
            assert_eq!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer CW_TEST_OPENAI_VALUE_123")
            );
            assert_eq!(body, br#"{"input":"hello"}"#);
            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                "content-type",
                HeaderValue::from_static("text/event-stream"),
            );
            response_headers.insert("x-request-id", HeaderValue::from_static(SYNTHETIC_KEY));
            Ok(BrokerUpstreamResponse::new(
                StatusCode::OK,
                response_headers,
                Box::pin(stream::iter([
                    Ok(Bytes::from_static(b"reflected CW_TEST_OPENAI_")),
                    Ok(Bytes::from_static(b"VALUE_123")),
                ])),
            ))
        }
    }

    fn provider_catalog() -> ProviderCatalog {
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse(OPENAI_OPERATION).unwrap(),
                        route: BrokerRouteId::parse(OPENAI_ROUTE).unwrap(),
                    }]),
                },
            )]),
        }])
        .unwrap()
    }

    fn broker_with_lease_count() -> (
        OpenAiBroker<TestLeaseProvider, SyntheticUpstream>,
        Arc<AtomicUsize>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.keep().join("authority");
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &root,
                EphemeralProtectedStore::default(),
                provider_catalog(),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "synthetic".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(SYNTHETIC_KEY.as_bytes()).unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id)]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();
        let lease_count = Arc::new(AtomicUsize::new(0));
        (
            OpenAiBroker::new(
                TestLeaseProvider {
                    authority,
                    environment_id,
                    lease_count: Arc::clone(&lease_count),
                },
                SyntheticUpstream,
            )
            .unwrap(),
            lease_count,
        )
    }

    fn broker() -> OpenAiBroker<TestLeaseProvider, SyntheticUpstream> {
        broker_with_lease_count().0
    }

    fn request() -> v1::CredentialBridgeRequest {
        v1::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(),
            method: "POST".into(),
            path: "/responses".into(),
            query: String::new(),
            headers: vec![v1::CredentialHttpHeader {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            }],
            body: br#"{"input":"hello"}"#.to_vec(),
        }
    }

    #[tokio::test]
    async fn executes_one_exact_request_and_redacts_stream_boundaries() {
        let response = broker().execute(request()).await.unwrap();
        let (status, headers, mut body) = response.into_parts();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("[REDACTED]")
        );
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend(chunk.unwrap());
        }
        assert_eq!(output, b"reflected [REDACTED]");
    }

    #[tokio::test]
    async fn malformed_and_out_of_policy_guest_requests_fail_before_upstream() {
        let (broker, lease_count) = broker_with_lease_count();
        let mut malformed = request();
        malformed.request_id = "not-a-uuid".into();
        assert!(matches!(
            broker.execute(malformed).await,
            Err(BrokerRequestError::InvalidRequest)
        ));

        for request_id in [Uuid::nil().to_string(), Uuid::new_v4().simple().to_string()] {
            let mut noncanonical = request();
            noncanonical.request_id = request_id;
            assert!(matches!(
                broker.execute(noncanonical).await,
                Err(BrokerRequestError::InvalidRequest)
            ));
        }

        let mut denied = request();
        denied.query = "exfiltrate=true".into();
        assert!(matches!(
            broker.execute(denied).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(lease_count.load(Ordering::Relaxed), 0);
    }
}
