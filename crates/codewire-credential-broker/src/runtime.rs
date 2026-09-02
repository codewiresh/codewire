use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, CredentialId,
};
use codewire_gateway_proto::daemon::v1;
#[cfg(feature = "local-broker-synthetic-smoke")]
use futures::stream;
use futures::{Stream, StreamExt as _};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::codex_oauth::{CanonicalCodexOAuthBundle, CodexOAuthCredential};
use crate::openai::OpenAiChatGptOAuthAdapter;
use crate::{
    BrokerCredentialLease, CredentialBrokerError, OpenAiApiKeyAdapter, OpenAiStreamingResponse,
    ValidatedOpenAiRequest,
};

const OPENAI_OPERATION: &str = "responses";
const OPENAI_ROUTE: &str = "openai-api";
const OPENAI_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_OAUTH_REFRESH_URL: &str = "https://auth.openai.com/oauth/token";
const MAX_OAUTH_REFRESH_RESPONSE_BYTES: usize = 1024 * 1024;
const OAUTH_REFRESH_WAIT_ATTEMPTS: usize = 64;
const OAUTH_REFRESH_WAIT_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(feature = "local-broker-synthetic-smoke")]
const SYNTHETIC_CODEX_ACCOUNT_ID: &str = "account-native-broker";

/// Metadata-only description of one exact OAuth generation to refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerCredentialRefreshRequest {
    pub refresh_id: Uuid,
    pub capability_slot: CapabilitySlot,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
    pub credential_id: CredentialId,
    pub credential_revocation_generation: u64,
    pub material_generation: u64,
}

/// Placement-specific admission for one exact provider operation.
#[async_trait]
pub trait BrokerLeaseProvider: Send + Sync {
    type Lease: BrokerCredentialLease + Send;
    type RefreshPermit: Send;

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError>;

    /// Serialize a refresh for the exact credential generation selected by an
    /// already-admitted operation. This boundary carries metadata only.
    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<Self::RefreshPermit, BrokerRefreshError>;

    /// Store and promote a validated provider bundle without returning it to
    /// the guest or a material-free authority RPC.
    async fn commit_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError>;

    /// Release a refresh reservation when no replacement bundle was written.
    async fn abort_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
    ) -> Result<(), BrokerRefreshError>;

    /// Invalidate the admitted generation after a terminal provider rejection.
    async fn fail_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
    ) -> Result<(), BrokerRefreshError>;
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

/// Stable refresh failures that never retain provider or protected-store
/// diagnostics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerRefreshError {
    #[error("credential refresh request is invalid")]
    InvalidRequest,
    #[error("credential refresh was denied")]
    Denied,
    #[error("credential refresh authority is unavailable")]
    Unavailable,
    #[error("credential refresh authority returned invalid metadata")]
    InvalidResponse,
    #[error("credential refresh is already in progress")]
    InProgress,
    #[error("credential refresh generation changed")]
    Stale,
}

#[cfg(feature = "local")]
#[async_trait]
impl<S> BrokerLeaseProvider for codewire_local_credentials::LocalCredentialBrokerLeaseClient<S>
where
    S: codewire_protected_store::ProtectedStore + Clone + 'static,
{
    type Lease = codewire_local_credentials::CredentialOperationLease;
    type RefreshPermit = codewire_local_credentials::BrokerCredentialRefreshPermit;

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
            codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
                BrokerLeaseError::Unavailable
            }
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
        })
    }

    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<Self::RefreshPermit, BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::begin_credential_refresh(
            &mut client,
            request.refresh_id,
            request.capability_slot,
            request.operation,
            request.route,
            request.credential_id,
            request.credential_revocation_generation,
            request.material_generation,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn commit_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        let mut bytes = material.into_bytes();
        let value = codewire_protected_store::ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| BrokerRefreshError::InvalidRequest)?;
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::commit_credential_refresh(
            &mut client,
            permit,
            value,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn abort_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
    ) -> Result<(), BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::abort_credential_refresh(
            &mut client,
            permit,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn fail_credential_refresh(
        &self,
        permit: Self::RefreshPermit,
    ) -> Result<(), BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::fail_credential_refresh(
            &mut client,
            permit,
        )
        .await
        .map_err(map_local_refresh_error)
    }
}

#[cfg(feature = "local")]
fn map_local_refresh_error(
    error: codewire_local_credentials::BrokerLeaseChannelError,
) -> BrokerRefreshError {
    match error {
        codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
            BrokerRefreshError::InvalidRequest
        }
        codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerRefreshError::Denied,
        codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
            BrokerRefreshError::Unavailable
        }
        codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
            BrokerRefreshError::InvalidResponse
        }
        codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
            BrokerRefreshError::InProgress
        }
        codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
            BrokerRefreshError::Stale
        }
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

/// Non-shipping upstream used only by the checked-in local broker product
/// smoke. It proves that the isolated broker injected protected material and
/// that response filtering removes a reflection before bytes return to the
/// guest, without contacting a provider.
#[cfg(feature = "local-broker-synthetic-smoke")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyntheticOpenAiSmokeTransport;

#[cfg(feature = "local-broker-synthetic-smoke")]
#[async_trait]
impl BrokerUpstreamTransport for SyntheticOpenAiSmokeTransport {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        let account_header_is_valid = match target.as_str() {
            "https://api.openai.com/v1/responses" => !headers.contains_key("chatgpt-account-id"),
            "https://chatgpt.com/backend-api/codex/responses" => {
                headers
                    .get("chatgpt-account-id")
                    .and_then(|value| value.to_str().ok())
                    == Some(SYNTHETIC_CODEX_ACCOUNT_ID)
            }
            _ => false,
        };
        if method != Method::POST
            || !account_header_is_valid
            || body.is_empty()
            || headers.contains_key("proxy-authorization")
            || headers.contains_key("cookie")
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let protected_value = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=256).contains(&value.len())
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
            .ok_or(BrokerUpstreamError::Protocol)?;
        let response = format!(
            concat!(
                "event: response.created\n",
                "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_codewire_broker_smoke\"}}}}\n\n",
                "event: response.output_item.done\n",
                "data: {{\"type\":\"response.output_item.done\",\"item\":{{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg_codewire_broker_smoke\",\"content\":[{{\"type\":\"output_text\",\"text\":\"CWCODEX149 broker {protected_value}\"}}]}}}}\n\n",
                "event: response.completed\n",
                "data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_codewire_broker_smoke\",\"usage\":{{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}}}}\n\n",
            ),
            protected_value = protected_value,
        );
        let reflected_at = response
            .find(protected_value)
            .ok_or(BrokerUpstreamError::Protocol)?;
        let split_at = reflected_at + protected_value.len() / 2;
        let first = Bytes::copy_from_slice(&response.as_bytes()[..split_at]);
        let second = Bytes::copy_from_slice(&response.as_bytes()[split_at..]);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );
        response_headers.insert(
            "x-request-id",
            HeaderValue::from_str(protected_value).map_err(|_| BrokerUpstreamError::Protocol)?,
        );
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            response_headers,
            Box::pin(stream::iter([Ok(first), Ok(second)])),
        ))
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
    api_key_adapter: OpenAiApiKeyAdapter,
    oauth_adapter: OpenAiChatGptOAuthAdapter,
    oauth_refresh: tokio::sync::Mutex<()>,
}

#[derive(Clone, PartialEq, Eq)]
struct OAuthCredentialGeneration {
    credential_id: CredentialId,
    material_generation: u64,
}

struct PreparedOAuthRequest {
    request: crate::PreparedOpenAiRequest,
    generation: OAuthCredentialGeneration,
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
            api_key_adapter: OpenAiApiKeyAdapter::new().map_err(map_adapter_error)?,
            oauth_adapter: OpenAiChatGptOAuthAdapter::new().map_err(map_adapter_error)?,
            oauth_refresh: tokio::sync::Mutex::new(()),
        })
    }

    /// Execute one credential-free guest request through the exact OpenAI
    /// adapter. The returned bytes are already filtered and redacted.
    pub async fn execute(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let request = ValidatedGuestRequest::parse(request)?;
        let operation = BrokerOperationId::parse(OPENAI_OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(OPENAI_ROUTE).map_err(|_| BrokerRequestError::InvalidRequest)?;
        let provider_request = self
            .api_key_adapter
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
                operation.clone(),
                route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        let (prepared, oauth_retry) = match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => (
                self.api_key_adapter
                    .prepare_validated(lease, provider_request)
                    .map_err(map_adapter_error)?,
                None,
            ),
            CredentialAuthKind::OAuth => {
                let generation = OAuthCredentialGeneration {
                    credential_id: lease.credential_metadata().id.clone(),
                    material_generation: lease.material_generation(),
                };
                let credential = self
                    .oauth_adapter
                    .credential_from_lease(lease)
                    .map_err(map_adapter_error)?;
                let retry_request = provider_request.clone();
                let prepared = if credential.should_refresh(current_unix_time()?) {
                    self.prepare_oauth_after_refresh(
                        request.request_id,
                        operation.clone(),
                        route.clone(),
                        provider_request,
                        None,
                    )
                    .await?
                } else {
                    PreparedOAuthRequest {
                        request: self
                            .oauth_adapter
                            .prepare_credential(credential, provider_request)
                            .map_err(map_adapter_error)?,
                        generation,
                    }
                };
                let generation = prepared.generation;
                (prepared.request, Some((retry_request, generation)))
            }
            _ => return Err(BrokerRequestError::Denied),
        };
        let (mut upstream, mut response_policy) = self.execute_prepared(prepared).await?;
        if upstream.status == StatusCode::UNAUTHORIZED
            && let Some((retry_request, rejected_generation)) = oauth_retry
        {
            drop(upstream);
            let retry = self
                .prepare_oauth_after_refresh(
                    request.request_id,
                    operation,
                    route,
                    retry_request,
                    Some(&rejected_generation),
                )
                .await?;
            (upstream, response_policy) = self.execute_prepared(retry.request).await?;
        }
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

    async fn execute_prepared(
        &self,
        prepared: crate::PreparedOpenAiRequest,
    ) -> Result<(BrokerUpstreamResponse, crate::PreparedOpenAiResponse), BrokerRequestError> {
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
        Ok((upstream, response_policy))
    }

    async fn prepare_oauth_after_refresh(
        &self,
        request_id: Uuid,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        provider_request: ValidatedOpenAiRequest,
        force_refresh_of: Option<&OAuthCredentialGeneration>,
    ) -> Result<PreparedOAuthRequest, BrokerRequestError> {
        let _refresh_guard = self.oauth_refresh.lock().await;
        for refresh_waits in 0..=OAUTH_REFRESH_WAIT_ATTEMPTS {
            let lease = self
                .leases
                .lease_operation(
                    request_id,
                    CapabilitySlot::codex(),
                    operation.clone(),
                    route.clone(),
                )
                .await
                .map_err(map_lease_error)?;
            if lease.credential_metadata().authentication_kind != CredentialAuthKind::OAuth {
                return Err(BrokerRequestError::Denied);
            }
            let generation = OAuthCredentialGeneration {
                credential_id: lease.credential_metadata().id.clone(),
                material_generation: lease.material_generation(),
            };
            let refresh_request = BrokerCredentialRefreshRequest {
                refresh_id: Uuid::new_v4(),
                capability_slot: CapabilitySlot::codex(),
                operation: operation.clone(),
                route: route.clone(),
                credential_id: lease.credential_metadata().id.clone(),
                credential_revocation_generation: lease.credential_metadata().revocation_generation,
                material_generation: lease.material_generation(),
            };
            let credential = self
                .oauth_adapter
                .credential_from_lease(lease)
                .map_err(map_adapter_error)?;
            let force_refresh = force_refresh_of == Some(&generation);
            if !force_refresh && !credential.should_refresh(current_unix_time()?) {
                return Ok(PreparedOAuthRequest {
                    request: self
                        .oauth_adapter
                        .prepare_credential(credential, provider_request)
                        .map_err(map_adapter_error)?,
                    generation,
                });
            }
            match self
                .refresh_oauth_credential(credential, refresh_request)
                .await?
            {
                Some(credential) => {
                    return Ok(PreparedOAuthRequest {
                        request: self
                            .oauth_adapter
                            .prepare_credential(credential, provider_request)
                            .map_err(map_adapter_error)?,
                        generation: OAuthCredentialGeneration {
                            credential_id: generation.credential_id,
                            material_generation: generation
                                .material_generation
                                .checked_add(1)
                                .ok_or(BrokerRequestError::AuthorityUnavailable)?,
                        },
                    });
                }
                None if refresh_waits < OAUTH_REFRESH_WAIT_ATTEMPTS => {
                    tokio::time::sleep(OAUTH_REFRESH_WAIT_INTERVAL).await;
                }
                None => return Err(BrokerRequestError::AuthorityUnavailable),
            }
        }
        Err(BrokerRequestError::AuthorityUnavailable)
    }

    async fn refresh_oauth_credential(
        &self,
        credential: CodexOAuthCredential,
        refresh_request: BrokerCredentialRefreshRequest,
    ) -> Result<Option<CodexOAuthCredential>, BrokerRequestError> {
        let refreshed_at_unix = current_unix_time()?;
        let permit = match self.leases.begin_credential_refresh(refresh_request).await {
            Ok(permit) => permit,
            Err(BrokerRefreshError::InProgress | BrokerRefreshError::Stale) => return Ok(None),
            Err(error) => return Err(map_refresh_error(error)),
        };
        let tokens = match self.request_oauth_refresh(credential.refresh_token()).await {
            Ok(tokens) => tokens,
            Err(OAuthRefreshError::Transient(error)) => {
                return match self.leases.abort_credential_refresh(permit).await {
                    Ok(()) => Err(error),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
            Err(OAuthRefreshError::Permanent) => {
                return match self.leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
        };
        let refreshed = match credential.refreshed(
            tokens.id_token,
            tokens.access_token,
            tokens.refresh_token,
            refreshed_at_unix,
        ) {
            Ok(refreshed) => refreshed,
            Err(_) => {
                return match self.leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
        };
        let bundle = match refreshed.to_bundle() {
            Ok(bundle) => bundle,
            Err(_) => {
                return match self.leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
        };
        self.leases
            .commit_credential_refresh(permit, bundle)
            .await
            .map_err(map_refresh_error)?;
        Ok(Some(refreshed))
    }

    async fn request_oauth_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<OAuthRefreshResponse, OAuthRefreshError> {
        let mut body = Zeroizing::new(
            serde_json::to_vec(&OAuthRefreshRequest {
                client_id: OPENAI_OAUTH_CLIENT_ID,
                grant_type: "refresh_token",
                refresh_token,
            })
            .map_err(|_| OAuthRefreshError::Permanent)?,
        );
        let target =
            Url::parse(OPENAI_OAUTH_REFRESH_URL).map_err(|_| OAuthRefreshError::Permanent)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let upstream = self
            .upstream
            .execute(BrokerUpstreamRequest {
                method: Method::POST,
                target,
                headers,
                body: std::mem::take(&mut *body),
            })
            .await
            .map_err(|error| OAuthRefreshError::Transient(map_upstream_error(error)))?;
        let (status, _headers, mut response_body) = upstream.into_parts();
        let mut response = Zeroizing::new(Vec::new());
        while let Some(chunk) = response_body.next().await {
            let chunk = chunk.map_err(|error| {
                if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Transient(map_upstream_error(error))
                }
            })?;
            let next_len = response
                .len()
                .checked_add(chunk.len())
                .filter(|length| *length <= MAX_OAUTH_REFRESH_RESPONSE_BYTES)
                .ok_or(if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Transient(BrokerRequestError::ResponseTooLarge)
                })?;
            let additional = next_len.saturating_sub(response.len());
            response.try_reserve(additional).map_err(|_| {
                if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Transient(BrokerRequestError::ResponseTooLarge)
                }
            })?;
            response.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(if oauth_refresh_rejection_is_permanent(status, &response) {
                OAuthRefreshError::Permanent
            } else {
                OAuthRefreshError::Transient(BrokerRequestError::UpstreamFailed)
            });
        }
        let parsed = serde_json::from_slice::<OAuthRefreshResponse>(&response)
            .map_err(|_| OAuthRefreshError::Permanent)?;
        response.zeroize();
        if parsed.access_token.is_none() {
            return Err(OAuthRefreshError::Permanent);
        }
        Ok(parsed)
    }
}

#[derive(Clone, Copy)]
enum OAuthRefreshError {
    Permanent,
    Transient(BrokerRequestError),
}

#[derive(Serialize)]
struct OAuthRefreshRequest<'a> {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct OAuthRefreshResponse {
    id_token: Option<Zeroizing<String>>,
    access_token: Option<Zeroizing<String>>,
    refresh_token: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
struct OAuthRefreshErrorBody {
    error: Option<OAuthRefreshErrorValue>,
    code: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OAuthRefreshErrorValue {
    Code(Zeroizing<String>),
    Detail { code: Option<Zeroizing<String>> },
}

fn oauth_refresh_rejection_is_permanent(status: StatusCode, body: &[u8]) -> bool {
    if status == StatusCode::UNAUTHORIZED {
        return true;
    }
    if status != StatusCode::BAD_REQUEST {
        return false;
    }
    let Ok(parsed) = serde_json::from_slice::<OAuthRefreshErrorBody>(body) else {
        return false;
    };
    let code = match parsed.error {
        Some(OAuthRefreshErrorValue::Code(code)) => Some(code),
        Some(OAuthRefreshErrorValue::Detail { code }) => code,
        None => parsed.code,
    };
    code.as_deref().is_some_and(|code| {
        [
            "invalid_grant",
            "refresh_token_expired",
            "refresh_token_reused",
            "refresh_token_invalidated",
        ]
        .iter()
        .any(|expected| code.eq_ignore_ascii_case(expected))
    })
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

fn map_refresh_error(error: BrokerRefreshError) -> BrokerRequestError {
    match error {
        BrokerRefreshError::InvalidRequest | BrokerRefreshError::Denied => {
            BrokerRequestError::Denied
        }
        BrokerRefreshError::Unavailable
        | BrokerRefreshError::InvalidResponse
        | BrokerRefreshError::InProgress
        | BrokerRefreshError::Stale => BrokerRequestError::AuthorityUnavailable,
    }
}

fn current_unix_time() -> Result<u64, BrokerRequestError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .ok()
        .filter(|value| *value > 0)
        .ok_or(BrokerRequestError::AuthorityUnavailable)
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use base64::Engine as _;
    use codewire_access::{
        AccessProfileName, CapabilityPolicy, CredentialAuthKind, EnvironmentAccessBinding,
        EnvironmentId, GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
    };
    use codewire_local_credentials::{
        CredentialOperationLeaseRequest, LocalCredentialAuthority, NewCredential,
    };
    use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
    use futures::{StreamExt as _, stream};
    use serde_json::json;

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
        type RefreshPermit = ();

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

        async fn begin_credential_refresh(
            &self,
            _request: BrokerCredentialRefreshRequest,
        ) -> Result<Self::RefreshPermit, BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn commit_credential_refresh(
            &self,
            _permit: Self::RefreshPermit,
            _material: CanonicalCodexOAuthBundle,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn abort_credential_refresh(
            &self,
            _permit: Self::RefreshPermit,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn fail_credential_refresh(
            &self,
            _permit: Self::RefreshPermit,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }
    }

    struct TestOAuthRefreshPermit {
        credential_id: CredentialId,
        material_generation: u64,
    }

    struct OAuthTestLeaseProvider {
        authority: Arc<LocalCredentialAuthority<EphemeralProtectedStore>>,
        environment_id: EnvironmentId,
        credential_id: CredentialId,
        material_generation: Arc<AtomicUsize>,
        refresh_active: Arc<AtomicBool>,
        begin_count: Arc<AtomicUsize>,
        commit_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
        failure_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BrokerLeaseProvider for OAuthTestLeaseProvider {
        type Lease = codewire_local_credentials::CredentialOperationLease;
        type RefreshPermit = TestOAuthRefreshPermit;

        async fn lease_operation(
            &self,
            _request_id: Uuid,
            capability_slot: CapabilitySlot,
            operation: BrokerOperationId,
            route: BrokerRouteId,
        ) -> Result<Self::Lease, BrokerLeaseError> {
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

        async fn begin_credential_refresh(
            &self,
            request: BrokerCredentialRefreshRequest,
        ) -> Result<Self::RefreshPermit, BrokerRefreshError> {
            self.begin_count.fetch_add(1, Ordering::Relaxed);
            if self
                .refresh_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrokerRefreshError::InProgress);
            }
            let current = self
                .authority
                .get_credential(&self.credential_id)
                .map_err(|_| BrokerRefreshError::Unavailable)?;
            let expected_material_generation =
                self.material_generation.load(Ordering::Acquire) as u64;
            if request.refresh_id.is_nil()
                || request.capability_slot != CapabilitySlot::codex()
                || request.operation.as_str() != OPENAI_OPERATION
                || request.route.as_str() != OPENAI_ROUTE
                || request.credential_id != self.credential_id
                || request.credential_revocation_generation
                    != current.metadata.revocation_generation
                || request.material_generation != expected_material_generation
            {
                self.refresh_active.store(false, Ordering::Release);
                return Err(BrokerRefreshError::Denied);
            }
            Ok(TestOAuthRefreshPermit {
                credential_id: request.credential_id,
                material_generation: request.material_generation,
            })
        }

        async fn commit_credential_refresh(
            &self,
            permit: Self::RefreshPermit,
            material: CanonicalCodexOAuthBundle,
        ) -> Result<(), BrokerRefreshError> {
            if !self.refresh_active.load(Ordering::Acquire)
                || permit.credential_id != self.credential_id
                || permit.material_generation
                    != self.material_generation.load(Ordering::Acquire) as u64
            {
                return Err(BrokerRefreshError::Denied);
            }
            let mut bytes = material.into_bytes();
            let value = ProtectedValue::new(std::mem::take(&mut *bytes))
                .map_err(|_| BrokerRefreshError::InvalidRequest)?;
            let result = self
                .authority
                .rotate_credential_material(&self.credential_id, value, None)
                .map_err(|_| BrokerRefreshError::Unavailable);
            if result.is_ok() {
                self.material_generation.fetch_add(1, Ordering::AcqRel);
                self.commit_count.fetch_add(1, Ordering::Relaxed);
            }
            self.refresh_active.store(false, Ordering::Release);
            result.map(|_| ())
        }

        async fn abort_credential_refresh(
            &self,
            permit: Self::RefreshPermit,
        ) -> Result<(), BrokerRefreshError> {
            if permit.credential_id != self.credential_id
                || !self.refresh_active.swap(false, Ordering::AcqRel)
            {
                return Err(BrokerRefreshError::Denied);
            }
            self.abort_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn fail_credential_refresh(
            &self,
            permit: Self::RefreshPermit,
        ) -> Result<(), BrokerRefreshError> {
            if permit.credential_id != self.credential_id
                || !self.refresh_active.swap(false, Ordering::AcqRel)
            {
                return Err(BrokerRefreshError::Denied);
            }
            self.authority
                .revoke_credential(&self.credential_id)
                .map_err(|_| BrokerRefreshError::Unavailable)?;
            self.failure_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
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

    struct OAuthSyntheticUpstream {
        refresh_status: StatusCode,
        refresh_response: Arc<Vec<u8>>,
        refresh_delay: Duration,
        expected_access_token: Arc<String>,
        unauthorized_access_tokens: Arc<BTreeSet<String>>,
        refresh_count: Arc<AtomicUsize>,
        response_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BrokerUpstreamTransport for OAuthSyntheticUpstream {
        async fn execute(
            &self,
            request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            let (method, target, headers, body) = request.into_parts();
            assert_eq!(method, Method::POST);
            match target.as_str() {
                OPENAI_OAUTH_REFRESH_URL => {
                    self.refresh_count.fetch_add(1, Ordering::Relaxed);
                    assert!(!headers.contains_key(http::header::AUTHORIZATION));
                    assert_eq!(
                        headers.get(http::header::CONTENT_TYPE),
                        Some(&HeaderValue::from_static("application/json"))
                    );
                    let value: serde_json::Value =
                        serde_json::from_slice(&body).expect("refresh JSON");
                    assert_eq!(value["client_id"], OPENAI_OAUTH_CLIENT_ID);
                    assert_eq!(value["grant_type"], "refresh_token");
                    assert_eq!(value["refresh_token"], "synthetic-old-refresh-token");
                    if !self.refresh_delay.is_zero() {
                        tokio::time::sleep(self.refresh_delay).await;
                    }
                    let refresh_response = Arc::clone(&self.refresh_response);
                    Ok(BrokerUpstreamResponse::new(
                        self.refresh_status,
                        HeaderMap::new(),
                        Box::pin(stream::once(async move {
                            Ok(Bytes::copy_from_slice(&refresh_response))
                        })),
                    ))
                }
                "https://chatgpt.com/backend-api/codex/responses" => {
                    self.response_count.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(body, br#"{"input":"hello"}"#);
                    let access_token = headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .expect("broker access token");
                    assert_eq!(
                        headers
                            .get("chatgpt-account-id")
                            .and_then(|value| value.to_str().ok()),
                        Some("account-work")
                    );
                    if self.unauthorized_access_tokens.contains(access_token) {
                        let mut response_headers = HeaderMap::new();
                        response_headers.insert(
                            "x-openai-authorization-error",
                            HeaderValue::from_static("token_expired"),
                        );
                        return Ok(BrokerUpstreamResponse::new(
                            StatusCode::UNAUTHORIZED,
                            response_headers,
                            Box::pin(stream::once(async {
                                Ok(Bytes::from_static(b"synthetic unauthorized"))
                            })),
                        ));
                    }
                    assert_eq!(access_token, self.expected_access_token.as_str());
                    Ok(BrokerUpstreamResponse::new(
                        StatusCode::OK,
                        HeaderMap::new(),
                        Box::pin(stream::once(async {
                            Ok(Bytes::from_static(b"synthetic response"))
                        })),
                    ))
                }
                _ => Err(BrokerUpstreamError::DestinationDenied),
            }
        }
    }

    struct OAuthTestState {
        begin_count: Arc<AtomicUsize>,
        commit_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
        failure_count: Arc<AtomicUsize>,
        refresh_count: Arc<AtomicUsize>,
        response_count: Arc<AtomicUsize>,
    }

    fn provider_catalog(authentication_kind: CredentialAuthKind) -> ProviderCatalog {
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([authentication_kind]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse(OPENAI_OPERATION).unwrap(),
                        route: BrokerRouteId::parse(OPENAI_ROUTE).unwrap(),
                    }]),
                },
            )]),
        }])
        .unwrap()
    }

    fn jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("JWT payload"));
        format!("{header}.{payload}.synthetic-signature")
    }

    fn oauth_material(access_token: &str) -> CanonicalCodexOAuthBundle {
        let source = serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": jwt(json!({
                    "email": "developer@example.test",
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-work",
                        "chatgpt_account_is_fedramp": false
                    }
                })),
                "access_token": access_token,
                "refresh_token": "synthetic-old-refresh-token",
                "account_id": "account-work"
            }
        }))
        .expect("Codex auth JSON");
        crate::import_codex_auth_json(&source)
            .expect("Codex OAuth import")
            .into_parts()
            .0
    }

    fn oauth_broker(
        refresh_status: StatusCode,
        refresh_response: Vec<u8>,
        expected_access_token: String,
        refresh_delay: Duration,
    ) -> (
        OpenAiBroker<OAuthTestLeaseProvider, OAuthSyntheticUpstream>,
        OAuthTestState,
    ) {
        let expired_access_token = jwt(json!({
            "exp": current_unix_time().expect("current time").saturating_sub(1)
        }));
        oauth_broker_with_initial_token(
            expired_access_token,
            BTreeSet::new(),
            refresh_status,
            refresh_response,
            expected_access_token,
            refresh_delay,
        )
    }

    fn oauth_broker_with_initial_token(
        initial_access_token: String,
        unauthorized_access_tokens: BTreeSet<String>,
        refresh_status: StatusCode,
        refresh_response: Vec<u8>,
        expected_access_token: String,
        refresh_delay: Duration,
    ) -> (
        OpenAiBroker<OAuthTestLeaseProvider, OAuthSyntheticUpstream>,
        OAuthTestState,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.keep().join("authority");
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &root,
                EphemeralProtectedStore::default(),
                provider_catalog(CredentialAuthKind::OAuth),
            )
            .unwrap(),
        );
        let material = oauth_material(&initial_access_token);
        let mut bytes = material.into_bytes();
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-oauth".into(),
                    account_hint: Some("developer@example.test".into()),
                    expires_at_unix: None,
                },
                ProtectedValue::new(std::mem::take(&mut *bytes)).unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic-oauth").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
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
        let material_generation = Arc::new(AtomicUsize::new(1));
        let refresh_active = Arc::new(AtomicBool::new(false));
        let begin_count = Arc::new(AtomicUsize::new(0));
        let commit_count = Arc::new(AtomicUsize::new(0));
        let abort_count = Arc::new(AtomicUsize::new(0));
        let failure_count = Arc::new(AtomicUsize::new(0));
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let response_count = Arc::new(AtomicUsize::new(0));
        let state = OAuthTestState {
            begin_count: Arc::clone(&begin_count),
            commit_count: Arc::clone(&commit_count),
            abort_count: Arc::clone(&abort_count),
            failure_count: Arc::clone(&failure_count),
            refresh_count: Arc::clone(&refresh_count),
            response_count: Arc::clone(&response_count),
        };
        let broker = OpenAiBroker::new(
            OAuthTestLeaseProvider {
                authority,
                environment_id,
                credential_id: credential.metadata.id,
                material_generation,
                refresh_active,
                begin_count,
                commit_count,
                abort_count,
                failure_count,
            },
            OAuthSyntheticUpstream {
                refresh_status,
                refresh_response: Arc::new(refresh_response),
                refresh_delay,
                expected_access_token: Arc::new(expected_access_token),
                unauthorized_access_tokens: Arc::new(unauthorized_access_tokens),
                refresh_count,
                response_count,
            },
        )
        .unwrap();
        (broker, state)
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
                provider_catalog(CredentialAuthKind::ApiKey),
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

    #[cfg(feature = "local-broker-synthetic-smoke")]
    #[tokio::test]
    async fn synthetic_smoke_transport_requires_the_exact_chatgpt_account_header() {
        fn oauth_request(account_id: Option<&'static str>) -> BrokerUpstreamRequest {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer cwlocalbrokersyntheticvalue"),
            );
            if let Some(account_id) = account_id {
                headers.insert("chatgpt-account-id", HeaderValue::from_static(account_id));
            }
            BrokerUpstreamRequest {
                method: Method::POST,
                target: Url::parse("https://chatgpt.com/backend-api/codex/responses").unwrap(),
                headers,
                body: br#"{"input":"hello"}"#.to_vec(),
            }
        }

        assert!(
            SyntheticOpenAiSmokeTransport
                .execute(oauth_request(Some(SYNTHETIC_CODEX_ACCOUNT_ID)))
                .await
                .is_ok()
        );
        for account_id in [None, Some("account-other")] {
            assert!(matches!(
                SyntheticOpenAiSmokeTransport
                    .execute(oauth_request(account_id))
                    .await,
                Err(BrokerUpstreamError::Protocol)
            ));
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

    #[tokio::test]
    async fn serializes_concurrent_oauth_refresh_and_uses_the_promoted_generation() {
        let access_token = jwt(json!({
            "exp": current_unix_time().expect("current time") + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (broker, state) = oauth_broker(
            StatusCode::OK,
            refresh_response,
            access_token,
            Duration::from_millis(250),
        );
        let broker = Arc::new(broker);
        let (first, second) = tokio::join!(broker.execute(request()), broker.execute(request()));

        for response in [first.unwrap(), second.unwrap()] {
            let (_, _, mut body) = response.into_parts();
            let mut output = Vec::new();
            while let Some(chunk) = body.next().await {
                output.extend(chunk.unwrap());
            }
            assert_eq!(output, b"synthetic response");
        }
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn refreshes_once_after_an_early_oauth_unauthorized_response() {
        let now = current_unix_time().expect("current time");
        let initial_access_token = jwt(json!({ "exp": now + 3_600 }));
        let refreshed_access_token = jwt(json!({ "exp": now + 7_200 }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": refreshed_access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (broker, state) = oauth_broker_with_initial_token(
            initial_access_token.clone(),
            BTreeSet::from([initial_access_token]),
            StatusCode::OK,
            refresh_response,
            refreshed_access_token,
            Duration::ZERO,
        );

        let response = broker.execute(request()).await.unwrap();
        let (status, _, mut body) = response.into_parts();
        assert_eq!(status, StatusCode::OK);
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend(chunk.unwrap());
        }
        assert_eq!(output, b"synthetic response");
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn retries_an_oauth_unauthorized_response_only_once() {
        let now = current_unix_time().expect("current time");
        let initial_access_token = jwt(json!({ "exp": now + 3_600 }));
        let refreshed_access_token = jwt(json!({ "exp": now + 7_200 }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": refreshed_access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (broker, state) = oauth_broker_with_initial_token(
            initial_access_token.clone(),
            BTreeSet::from([initial_access_token, refreshed_access_token.clone()]),
            StatusCode::OK,
            refresh_response,
            refreshed_access_token,
            Duration::ZERO,
        );

        let response = broker.execute(request()).await.unwrap();
        let (status, headers, mut body) = response.into_parts();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            headers
                .get("x-openai-authorization-error")
                .and_then(|value| value.to_str().ok()),
            Some("token_expired")
        );
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend(chunk.unwrap());
        }
        assert_eq!(output, b"synthetic unauthorized");
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn invalidates_terminal_oauth_refresh_without_forwarding_provider_error_material() {
        let (broker, state) = oauth_broker(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"code":"refresh_token_expired"},"secret":"provider-detail"}"#.to_vec(),
            "unused-access-token".into(),
            Duration::ZERO,
        );
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn aborts_transient_oauth_refresh_for_a_later_retry() {
        let (broker, state) = oauth_broker(
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"synthetic-unavailable"}"#.to_vec(),
            "unused-access-token".into(),
            Duration::ZERO,
        );
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::UpstreamFailed)
        ));
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn rejects_refreshed_oauth_identity_changes_before_commit() {
        let access_token = jwt(json!({
            "exp": current_unix_time().expect("current time") + 3_600
        }));
        let changed_id_token = jwt(json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "different-account",
                "chatgpt_account_is_fedramp": false
            }
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "id_token": changed_id_token,
            "access_token": access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token"
        }))
        .unwrap();
        let (broker, state) = oauth_broker(
            StatusCode::OK,
            refresh_response,
            access_token,
            Duration::ZERO,
        );
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
    }
}
