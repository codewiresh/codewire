use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, CredentialId,
    DerivedGrant, PROVIDER_REFRESH_TIMEOUT_SECONDS,
};
use codewire_gateway_proto::codewire::bridge::v1;
#[cfg(feature = "local-broker-synthetic-smoke")]
use futures::stream;
use futures::{Stream, StreamExt as _};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::task::TaskTracker;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::anthropic::{AnthropicApiKeyAdapter, AnthropicStreamingResponse};
use crate::codex_oauth::{CanonicalCodexOAuthBundle, CodexOAuthCredential};
use crate::github::GitHubOAuthAdapter;
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

#[cfg(test)]
#[path = "runtime_http_tests.rs"]
mod http_tests;

#[cfg(all(test, feature = "local-broker-synthetic-smoke"))]
#[path = "runtime/synthetic_smoke_tests.rs"]
mod synthetic_smoke_tests;

/// Metadata-only description of one exact OAuth generation to refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerCredentialRefreshRequest {
    pub refresh_id: Uuid,
    pub request_id: Uuid,
    pub grant: DerivedGrant,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
    pub material_generation: u64,
}

/// Refresh ownership or completion of a previously staged result.
/// Recovery carries no material or authority to execute a provider operation.
pub enum BrokerRefreshAdmission<R> {
    Reserved(R),
    Recovered,
}

/// Placement-specific admission for one exact provider operation.
#[async_trait]
pub trait BrokerLeaseProvider: Send + Sync {
    type Lease: BrokerCredentialLease + Send;
    type RefreshReservation: Send;
    type StartedRefresh: Send;

    /// Closed selected-key SSH operation. Provider key material is never
    /// returned to this dispatcher; an authority retains worker ownership
    /// through cancellation and terminal drain, then rechecks its exact grant.
    async fn ssh_operation(
        &self,
        _request: v1::CredentialSshRequest,
        _cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    /// Ciphertext for the immutable application sources bound to this runtime
    /// channel. Not a provider credential lease and not an HTTP operation.
    async fn project_environment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    async fn project_environment_fragment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

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
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError>;

    /// Durably mark the exact reservation as possibly sent, rechecking its
    /// original request/grant binding before provider work. An uncertain Start
    /// acknowledgement must never release a possibly started attempt to retry.
    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError>;

    /// Store and promote a validated provider bundle without returning it to
    /// the guest or a material-free authority RPC.
    /// Durably publish the provider's rotated material. Success is not an
    /// authorization to use it: the broker obtains a fresh operation lease
    /// after this call before preparing the original provider request.
    async fn commit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError>;

    /// Release a reservation only before Start. Absence of replacement material
    /// does not prove that a started provider request was safe to replay.
    async fn abort_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<(), BrokerRefreshError>;

    /// Invalidate the admitted generation after rejection or an ambiguous
    /// possibly-sent exchange. This must never make the old token retryable.
    async fn fail_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError>;

    /// Wait until every non-cancellable placement operation started by a
    /// broker request has finished. The bridge calls this only after it has
    /// stopped admitting requests and aborted the remaining request futures,
    /// before their authority channel is allowed to close.
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError>;
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
    type RefreshReservation = codewire_local_credentials::BrokerCredentialRefreshReservation;
    type StartedRefresh = codewire_local_credentials::StartedBrokerCredentialRefresh;

    async fn ssh_operation(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        if cancellation.is_cancelled() {
            return Err(BrokerLeaseError::Denied);
        }
        // Ordinary guest cancellation does not drop this unary call: retain
        // the broker slot until the authority finishes the original bounded
        // operation and its agent drain. The dispatcher suppresses the result.
        // Transport loss instead ends the epoch and relies on channel drain,
        // never on a local cancellation acknowledgement as remote proof.
        let mut client = self.clone();
        let response = codewire_local_credentials::LocalCredentialBrokerLeaseClient::ssh_operation(
            &mut client,
            request,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
            _ => BrokerLeaseError::Unavailable,
        })?;
        response.result.ok_or(BrokerLeaseError::InvalidResponse)
    }

    async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerLeaseError> {
        let request_id =
            Uuid::parse_str(&request.request_id).map_err(|_| BrokerLeaseError::InvalidRequest)?;
        if request_id.is_nil()
            || request_id.to_string() != request.request_id
            || !request.local_inventories.is_empty()
        {
            return Err(BrokerLeaseError::InvalidRequest);
        }
        let recipient = request
            .recipient_public_key
            .try_into()
            .map_err(|_| BrokerLeaseError::InvalidRequest)?;
        let selection = request
            .selection_sha256
            .try_into()
            .map_err(|_| BrokerLeaseError::InvalidRequest)?;
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::project_environment(
            self,
            request_id,
            recipient,
            selection,
            request.deadline_unix_ms,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
            _ => BrokerLeaseError::Unavailable,
        })
    }

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
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::begin_credential_refresh(
            &mut client,
            request.refresh_id,
            request.request_id,
            request.grant,
            request.operation,
            request.route,
            request.material_generation,
        )
        .await
        .map(|admission| match admission {
            codewire_local_credentials::BrokerCredentialRefreshAdmission::Reserved(reservation) => {
                BrokerRefreshAdmission::Reserved(reservation)
            }
            codewire_local_credentials::BrokerCredentialRefreshAdmission::Recovered => {
                BrokerRefreshAdmission::Recovered
            }
        })
        .map_err(map_local_refresh_error)
    }

    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::start_credential_refresh(
            &mut client,
            reservation,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn commit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
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
        permit: Self::RefreshReservation,
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
        permit: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::fail_credential_refresh(
            &mut client,
            permit,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::wait_for_protected_store_operations(
            self,
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

/// A runtime with application sources only has no provider DNS/socket setup.
#[async_trait]
impl<T: BrokerUpstreamTransport> BrokerUpstreamTransport for Option<T> {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        match self {
            Some(transport) => transport.execute(request).await,
            None => Err(BrokerUpstreamError::DestinationDenied),
        }
    }
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
    pub(crate) fn new(method: Method, target: Url, headers: HeaderMap, body: Vec<u8>) -> Self {
        Self {
            method,
            target,
            headers,
            body,
        }
    }

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

    pub(crate) fn into_parts(self) -> (StatusCode, HeaderMap, BrokerUpstreamBody) {
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
        if target.host_str() == Some("api.anthropic.com") {
            return Self::anthropic(method, target, headers, body);
        }
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
                Self::canary(
                    value,
                    if target.as_str() == "https://api.openai.com/v1/responses" {
                        "cwlocalopenai"
                    } else {
                        "cwlocalbroker"
                    },
                )
            })
            .ok_or(BrokerUpstreamError::Protocol)?;
        let marker = if target.as_str() == "https://api.openai.com/v1/responses" {
            "CWOPENAI"
        } else {
            "CWCODEX149"
        };
        let response = format!(
            concat!(
                "event: response.created\n",
                "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_codewire_broker_smoke\"}}}}\n\n",
                "event: response.output_item.done\n",
                "data: {{\"type\":\"response.output_item.done\",\"item\":{{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg_codewire_broker_smoke\",\"content\":[{{\"type\":\"output_text\",\"text\":\"{marker} broker {protected_value}\"}}]}}}}\n\n",
                "event: response.completed\n",
                "data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_codewire_broker_smoke\",\"usage\":{{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}}}}\n\n",
            ),
            protected_value = protected_value,
            marker = marker,
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
        response_headers.insert("x-error-json", Self::opaque_reflection(protected_value)?);
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            response_headers,
            Box::pin(stream::iter([Ok(first), Ok(second)])),
        ))
    }
}

#[cfg(feature = "local-broker-synthetic-smoke")]
impl SyntheticOpenAiSmokeTransport {
    fn canary(value: &str, prefix: &str) -> bool {
        value.strip_prefix(prefix).is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }

    fn opaque_reflection(value: &str) -> Result<HeaderValue, BrokerUpstreamError> {
        use base64::Engine as _;

        let opaque =
            base64::engine::general_purpose::STANDARD.encode(format!("{{\"error\":\"{value}\"}}"));
        HeaderValue::from_str(&opaque).map_err(|_| BrokerUpstreamError::Protocol)
    }

    fn anthropic(
        method: Method,
        target: Url,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let messages = match target.as_str() {
            "https://api.anthropic.com/v1/messages"
            | "https://api.anthropic.com/v1/messages?beta=true" => true,
            "https://api.anthropic.com/v1/messages/count_tokens"
            | "https://api.anthropic.com/v1/messages/count_tokens?beta=true" => false,
            _ => return Err(BrokerUpstreamError::Protocol),
        };
        // These are the adapter's outbound fields, not caller credentials. A
        // fixture must fail if injection/filtering or the fixed target changes.
        if method != Method::POST
            || body.is_empty()
            || body.len() > 4 * 1024 * 1024
            || headers.keys().any(|name| {
                !matches!(
                    name.as_str(),
                    "accept"
                        | "content-type"
                        | "anthropic-version"
                        | "anthropic-beta"
                        | "accept-encoding"
                        | "x-api-key"
                )
            })
            || headers
                .keys()
                .any(|name| headers.get_all(name).iter().count() != 1)
            || headers.get("anthropic-version").map(HeaderValue::as_bytes) != Some(b"2023-06-01")
            || headers.get("content-type").map(HeaderValue::as_bytes) != Some(b"application/json")
            || headers.get("accept-encoding").map(HeaderValue::as_bytes) != Some(b"identity")
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let protected_value = headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .filter(|value| Self::canary(value, "cwlocalanthropic"))
            .ok_or(BrokerUpstreamError::Protocol)?;
        let payload: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| BrokerUpstreamError::Protocol)?;
        if !payload.is_object()
            || payload.get("model").and_then(serde_json::Value::as_str) != Some("claude-sonnet-4-6")
            || payload
                .get("messages")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|messages| messages.is_empty())
            || (messages
                && (payload.get("stream").and_then(serde_json::Value::as_bool) != Some(true)
                    || payload
                        .get("max_tokens")
                        .and_then(serde_json::Value::as_u64)
                        .is_none_or(|maximum| maximum == 0)))
            || (!messages && payload.get("stream").is_some())
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            "content-type",
            HeaderValue::from_static(if messages {
                "text/event-stream"
            } else {
                "application/json"
            }),
        );
        response_headers.insert(
            "request-id",
            HeaderValue::from_str(protected_value).map_err(|_| BrokerUpstreamError::Protocol)?,
        );
        // Opaque provider diagnostics must be dropped, not mistaken for a
        // header whose contents can safely be forwarded after raw redaction.
        response_headers.insert("x-error-json", Self::opaque_reflection(protected_value)?);
        if !messages {
            return Ok(BrokerUpstreamResponse::new(
                StatusCode::OK,
                response_headers,
                Box::pin(stream::once(async {
                    Ok(Bytes::from_static(b"{\"input_tokens\":42}"))
                })),
            ));
        }
        // A complete text-only Messages stream consumed by the pinned Claude
        // CLI, including the final usage/stop events. Split inside the reflected
        // key, not at an SSE boundary, to exercise streaming redaction.
        let response = format!(
            concat!(
                "event: message_start\n",
                "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_codewire_claude_smoke\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{{\"input_tokens\":42,\"output_tokens\":0}}}}}}\n\n",
                "event: content_block_start\n",
                "data: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n",
                "event: content_block_delta\n",
                "data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"CWCLAUDE21238 broker {protected_value}\"}}}}\n\n",
                "event: content_block_stop\n",
                "data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n",
                "event: message_delta\n",
                "data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}},\"usage\":{{\"output_tokens\":8}}}}\n\n",
                "event: message_stop\n",
                "data: {{\"type\":\"message_stop\"}}\n\n",
            ),
            protected_value = protected_value
        );
        let reflected_at = response
            .find(protected_value)
            .ok_or(BrokerUpstreamError::Protocol)?;
        let split_at = reflected_at + protected_value.len() / 2;
        let chunks = [
            Bytes::copy_from_slice(&response.as_bytes()[..split_at]),
            Bytes::copy_from_slice(&response.as_bytes()[split_at..]),
        ];
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            response_headers,
            Box::pin(stream::iter(chunks.map(Ok))),
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
    leases: Arc<P>,
    upstream: Arc<U>,
    api_key_adapter: OpenAiApiKeyAdapter,
    oauth_adapter: OpenAiChatGptOAuthAdapter,
    anthropic_adapter: AnthropicApiKeyAdapter,
    github_adapter: GitHubOAuthAdapter,
    oauth_refresh: tokio::sync::Mutex<()>,
    oauth_refresh_operations: TaskTracker,
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

/// Refresh and its bounded retry belong to the original request binding, not
/// whichever account/profile happens to be current after an asynchronous wait.
/// Material and revocation generations may advance when tokens rotate.
fn validate_request_binding(
    current: &DerivedGrant,
    admitted: &DerivedGrant,
) -> Result<(), BrokerRequestError> {
    let now = current_unix_time()?;
    if current.environment_id != admitted.environment_id
        || current.environment_generation != admitted.environment_generation
        || current.profile_id != admitted.profile_id
        || current.profile_revision != admitted.profile_revision
        || current.capability_slot != admitted.capability_slot
        || current.credential_id != admitted.credential_id
        || admitted.expires_at_unix.is_some_and(|expiry| expiry <= now)
    {
        return Err(BrokerRequestError::Denied);
    }
    Ok(())
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    pub fn new(leases: P, upstream: U) -> Result<Self, BrokerRequestError> {
        Ok(Self {
            leases: Arc::new(leases),
            upstream: Arc::new(upstream),
            api_key_adapter: OpenAiApiKeyAdapter::new().map_err(map_adapter_error)?,
            oauth_adapter: OpenAiChatGptOAuthAdapter::new().map_err(map_adapter_error)?,
            anthropic_adapter: AnthropicApiKeyAdapter::new().map_err(map_adapter_error)?,
            github_adapter: GitHubOAuthAdapter::new().map_err(map_adapter_error)?,
            oauth_refresh: tokio::sync::Mutex::new(()),
            oauth_refresh_operations: TaskTracker::new(),
        })
    }

    pub(crate) async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        if !request.local_inventories.is_empty() {
            return Err(BrokerRequestError::Denied);
        }
        self.leases
            .project_environment(request)
            .await
            .map_err(map_lease_error)
    }

    pub(crate) async fn project_environment_fragment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, BrokerRequestError> {
        self.leases
            .project_environment_fragment(request)
            .await
            .map_err(map_lease_error)
    }

    pub(crate) async fn execute_ssh(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerRequestError> {
        self.leases
            .ssh_operation(request, cancellation)
            .await
            .map_err(map_lease_error)
    }

    /// Dispatch a credential-free request to its explicitly selected HTTP slot.
    /// The request carries no upstream URL, credential ID or owner authority.
    pub async fn execute(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let request = ValidatedGuestRequest::parse(request)?;
        match request.slot.as_str() {
            "anthropic" => return self.execute_anthropic(request).await,
            "github" => return self.execute_github(request).await,
            _ => {}
        }
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
                request.slot.clone(),
                operation.clone(),
                route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &route)?;
        let (prepared, oauth_retry) = match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => (
                self.api_key_adapter
                    .prepare_validated(lease, provider_request)
                    .map_err(map_adapter_error)?,
                None,
            ),
            CredentialAuthKind::OAuth => {
                if request.slot != CapabilitySlot::codex() {
                    return Err(BrokerRequestError::Denied);
                }
                let admitted_grant = lease.grant().clone();
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
                        &admitted_grant,
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
                (
                    prepared.request,
                    Some((retry_request, generation, admitted_grant)),
                )
            }
            _ => return Err(BrokerRequestError::Denied),
        };
        let (mut upstream, mut response_policy) = self.execute_prepared(prepared).await?;
        if upstream.status == StatusCode::UNAUTHORIZED
            && let Some((retry_request, rejected_generation, admitted_grant)) = oauth_retry
        {
            drop(upstream);
            let retry = self
                .prepare_oauth_after_refresh(
                    request.request_id,
                    operation,
                    route,
                    retry_request,
                    Some(&rejected_generation),
                    &admitted_grant,
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
                redactor: Some(ProviderStreamingResponse::OpenAi(redactor)),
                finished: false,
            }),
        ))
    }

    async fn execute_anthropic(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let validated = self
            .anthropic_adapter
            .validate_request(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let operation = BrokerOperationId::parse(validated.operation().operation_name())
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                request.slot.clone(),
                operation.clone(),
                request.route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &request.route)?;
        let (method, target, headers, body, policy) = self
            .anthropic_adapter
            .prepare_validated(lease, validated)
            .map_err(map_adapter_error)?
            .into_parts();
        let response = self
            .upstream
            .execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
            })
            .await
            .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = policy.begin(&headers).map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(ProviderStreamingResponse::Anthropic(redactor)),
                finished: false,
            }),
        ))
    }

    async fn execute_github(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let validated = self
            .github_adapter
            .validate_request(
                request.route.as_str(),
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let operation = BrokerOperationId::parse(validated.operation().operation_name())
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                request.slot.clone(),
                operation.clone(),
                request.route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &request.route)?;
        let (method, target, headers, body, policy) = self
            .github_adapter
            .prepare_validated(lease, validated)
            .map_err(map_adapter_error)?
            .into_parts();
        let response = self
            .upstream
            .execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
            })
            .await
            .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = policy.begin(status, &headers).map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(ProviderStreamingResponse::OpenAi(redactor)),
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

    pub(crate) async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.oauth_refresh_operations.close();
        self.oauth_refresh_operations.wait().await;
        self.leases
            .wait_for_active_operations()
            .await
            .map_err(map_refresh_error)
    }

    async fn prepare_oauth_after_refresh(
        &self,
        request_id: Uuid,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        provider_request: ValidatedOpenAiRequest,
        force_refresh_of: Option<&OAuthCredentialGeneration>,
        admitted_grant: &DerivedGrant,
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
            validate_request_binding(lease.grant(), admitted_grant)?;
            if lease.credential_metadata().authentication_kind != CredentialAuthKind::OAuth {
                return Err(BrokerRequestError::Denied);
            }
            let generation = OAuthCredentialGeneration {
                credential_id: lease.credential_metadata().id.clone(),
                material_generation: lease.material_generation(),
            };
            let refresh_request = BrokerCredentialRefreshRequest {
                refresh_id: Uuid::new_v4(),
                request_id,
                grant: {
                    let mut grant = lease.grant().clone();
                    // Rotation may advance credential versions, but it cannot
                    // extend the deadline of the original admitted request.
                    grant.expires_at_unix =
                        match (grant.expires_at_unix, admitted_grant.expires_at_unix) {
                            (Some(current), Some(original)) => Some(current.min(original)),
                            (current, original) => current.or(original),
                        };
                    grant
                },
                operation: operation.clone(),
                route: route.clone(),
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
                Some(()) => {
                    // Persisting a rotated token does not authorize using it.
                    // Refresh can outlive the original grant or binding; ask
                    // the placement authority again after durable commit.
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
                    validate_request_binding(lease.grant(), admitted_grant)?;
                    let generation = OAuthCredentialGeneration {
                        credential_id: lease.credential_metadata().id.clone(),
                        material_generation: lease.material_generation(),
                    };
                    let credential = self
                        .oauth_adapter
                        .credential_from_lease(lease)
                        .map_err(map_adapter_error)?;
                    return Ok(PreparedOAuthRequest {
                        request: self
                            .oauth_adapter
                            .prepare_credential(credential, provider_request)
                            .map_err(map_adapter_error)?,
                        generation,
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
    ) -> Result<Option<()>, BrokerRequestError> {
        let refreshed_at_unix = current_unix_time()?;
        let permit = match self.leases.begin_credential_refresh(refresh_request).await {
            Ok(BrokerRefreshAdmission::Reserved(reservation)) => reservation,
            Ok(BrokerRefreshAdmission::Recovered) => return Ok(Some(())),
            Err(BrokerRefreshError::InProgress | BrokerRefreshError::Stale) => return Ok(None),
            Err(error) => return Err(map_refresh_error(error)),
        };
        // A successful begin call owns an authority reservation. Transfer the
        // entire remaining refresh exchange to the shutdown tracker in this
        // same poll, before another await can make cancellation observable.
        // Graceful bridge loss can then abort the guest request while still
        // waiting for provider parsing and exactly one terminal authority
        // action. Start and the possibly-sent exchange share this tracked
        // lifetime; guest cancellation never returns a started token to retry.
        let leases = Arc::clone(&self.leases);
        let upstream = Arc::clone(&self.upstream);
        let refresh = self.oauth_refresh_operations.spawn(async move {
            Self::complete_oauth_refresh(leases, upstream, credential, permit, refreshed_at_unix)
                .await
        });
        refresh
            .await
            .map_err(|_| BrokerRequestError::AuthorityUnavailable)?
            .map(Some)
    }

    async fn complete_oauth_refresh(
        leases: Arc<P>,
        upstream: Arc<U>,
        credential: CodexOAuthCredential,
        reservation: P::RefreshReservation,
        refreshed_at_unix: u64,
    ) -> Result<(), BrokerRequestError> {
        let permit = leases
            .start_credential_refresh(reservation)
            .await
            // Start consumed the reservation. Even definite denial must end
            // this epoch so a still-Reserved attempt cannot retain an owner
            // that no caller can release. An uncertain ACK takes the same
            // drain path, but recovery never retries a Started attempt.
            .map_err(|_| BrokerRequestError::AuthorityUnavailable)?;
        let exchange = tokio::time::timeout(
            Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
            Self::request_oauth_refresh(&upstream, credential.refresh_token()),
        )
        .await;
        let tokens = match exchange {
            Ok(Ok(tokens)) => tokens,
            Ok(Err(OAuthRefreshError::Uncertain(error))) => {
                return match leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(error),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
            Ok(Err(OAuthRefreshError::Permanent)) => {
                return match leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
            Err(_) => {
                return match leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::UpstreamFailed),
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
                return match leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
        };
        let bundle = match refreshed.to_bundle() {
            Ok(bundle) => bundle,
            Err(_) => {
                return match leases.fail_credential_refresh(permit).await {
                    Ok(()) => Err(BrokerRequestError::Denied),
                    Err(_) => Err(BrokerRequestError::AuthorityUnavailable),
                };
            }
        };
        leases
            .commit_credential_refresh(permit, bundle)
            .await
            .map_err(map_refresh_error)?;
        Ok(())
    }

    async fn request_oauth_refresh(
        upstream: &U,
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
        let upstream = upstream
            .execute(BrokerUpstreamRequest {
                method: Method::POST,
                target,
                headers,
                body: std::mem::take(&mut *body),
            })
            .await
            .map_err(|error| OAuthRefreshError::Uncertain(map_upstream_error(error)))?;
        let (status, headers, mut response_body) = upstream.into_parts();
        // Refresh bypasses the guest response redactor, but every transport
        // must still deliver identity bytes before internal token parsing.
        crate::openai::validate_response_encoding(&headers)
            .map_err(|_| OAuthRefreshError::Uncertain(BrokerRequestError::UpstreamFailed))?;
        let mut response = Zeroizing::new(Vec::new());
        while let Some(chunk) = response_body.next().await {
            let chunk = chunk.map_err(|error| {
                if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Uncertain(map_upstream_error(error))
                }
            })?;
            let next_len = response
                .len()
                .checked_add(chunk.len())
                .filter(|length| *length <= MAX_OAUTH_REFRESH_RESPONSE_BYTES)
                .ok_or(if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Uncertain(BrokerRequestError::ResponseTooLarge)
                })?;
            let additional = next_len.saturating_sub(response.len());
            response.try_reserve(additional).map_err(|_| {
                if status.is_success() {
                    OAuthRefreshError::Permanent
                } else {
                    OAuthRefreshError::Uncertain(BrokerRequestError::ResponseTooLarge)
                }
            })?;
            response.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(if oauth_refresh_rejection_is_permanent(status, &response) {
                OAuthRefreshError::Permanent
            } else {
                OAuthRefreshError::Uncertain(BrokerRequestError::UpstreamFailed)
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
    Uncertain(BrokerRequestError),
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
    slot: CapabilitySlot,
    route: BrokerRouteId,
    method: Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ValidatedGuestRequest {
    fn parse(request: v1::CredentialBridgeRequest) -> Result<Self, BrokerRequestError> {
        if !matches!(
            (request.capability_slot.as_str(), request.route.as_str()),
            ("codex" | "openai", "openai-api")
                | ("anthropic", "anthropic-api")
                | ("github", "github-api" | "github-https")
        ) || request.body.len() > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES
            || request.headers.len() > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_HEADERS
            || request.path.len() > 2048
            || request.query.len() > 4096
        {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let slot = CapabilitySlot::parse(request.capability_slot)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(request.route).map_err(|_| BrokerRequestError::InvalidRequest)?;
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
        let mut header_bytes = 0_usize;
        for header in request.headers {
            if header.name.len() > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
                || header.value.len()
                    > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
            {
                return Err(BrokerRequestError::InvalidRequest);
            }
            header_bytes = header_bytes
                .checked_add(header.name.len() + header.value.len())
                .filter(|bytes| {
                    *bytes <= codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_HEADER_BYTES
                })
                .ok_or(BrokerRequestError::InvalidRequest)?;
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            let value = HeaderValue::from_bytes(&header.value)
                .map_err(|_| BrokerRequestError::InvalidRequest)?;
            headers.append(name, value);
        }
        Ok(Self {
            request_id,
            slot,
            route,
            method,
            path: request.path,
            query,
            headers,
            body: request.body,
        })
    }
}

fn validate_http_lease_coordinates(
    lease: &impl BrokerCredentialLease,
    slot: &CapabilitySlot,
    operation: &BrokerOperationId,
    route: &BrokerRouteId,
) -> Result<(), BrokerRequestError> {
    if &lease.grant().capability_slot != slot
        || &lease.permission().operation != operation
        || &lease.permission().route != route
    {
        return Err(BrokerRequestError::Denied);
    }
    Ok(())
}

enum ProviderStreamingResponse {
    OpenAi(OpenAiStreamingResponse),
    Anthropic(AnthropicStreamingResponse),
}
impl ProviderStreamingResponse {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CredentialBrokerError> {
        match self {
            Self::OpenAi(redactor) => redactor.push(chunk),
            Self::Anthropic(redactor) => redactor.push(chunk),
        }
    }
    fn finish(self) -> Result<Vec<u8>, CredentialBrokerError> {
        match self {
            Self::OpenAi(redactor) => redactor.finish(),
            Self::Anthropic(redactor) => redactor.finish(),
        }
    }
}

pub struct BrokerRedactedBody {
    upstream: BrokerUpstreamBody,
    redactor: Option<ProviderStreamingResponse>,
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
    use std::path::PathBuf;
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
    use codewire_protected_store::{
        EphemeralProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
        ProtectedStorePersistence, ProtectedValue,
    };
    use futures::{StreamExt as _, stream};
    use serde_json::json;
    use tokio::sync::{Notify, mpsc};

    use super::*;
    use crate::openai::response_admission_test_cases::{accepted_encodings, denied_encodings};

    const SYNTHETIC_KEY: &str = "CW_TEST_OPENAI_VALUE_123";

    struct TestLeaseProvider {
        authority: Arc<LocalCredentialAuthority<EphemeralProtectedStore>>,
        environment_id: EnvironmentId,
        lease_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BrokerLeaseProvider for TestLeaseProvider {
        type Lease = codewire_local_credentials::CredentialOperationLease;
        type RefreshReservation = ();
        type StartedRefresh = ();

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
        ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn start_credential_refresh(
            &self,
            _reservation: Self::RefreshReservation,
        ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn commit_credential_refresh(
            &self,
            _permit: Self::StartedRefresh,
            _material: CanonicalCodexOAuthBundle,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn abort_credential_refresh(
            &self,
            _permit: Self::RefreshReservation,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn fail_credential_refresh(
            &self,
            _permit: Self::StartedRefresh,
        ) -> Result<(), BrokerRefreshError> {
            Err(BrokerRefreshError::Denied)
        }

        async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
            Ok(())
        }
    }

    struct TestOAuthRefreshReservation(BrokerCredentialRefreshRequest);

    struct TestStartedOAuthRefresh {
        credential_id: CredentialId,
        material_generation: u64,
    }

    #[derive(Clone, Default)]
    struct OAuthTestProtectedStore(Arc<EphemeralProtectedStore>);

    impl ProtectedStore for OAuthTestProtectedStore {
        fn persistence(&self) -> ProtectedStorePersistence {
            self.0.persistence()
        }

        fn get(
            &self,
            id: &ProtectedEntryId,
        ) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
            self.0.get(id)
        }

        fn put(
            &self,
            id: &ProtectedEntryId,
            value: &ProtectedValue,
        ) -> Result<(), ProtectedStoreError> {
            self.0.put(id, value)
        }

        fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
            self.0.delete(id)
        }
    }

    /// Pause only after the new protected generation and metadata are durable.
    /// This models a delayed authority reply, not an uncommitted provider call.
    #[derive(Default)]
    struct CommitReturnGate {
        armed: AtomicBool,
        committed: Notify,
        release: Notify,
    }

    impl CommitReturnGate {
        async fn wait(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.committed.notified())
                .await
                .expect("refresh did not reach its durable commit barrier");
        }
    }

    struct OAuthTestLeaseProvider {
        authority: Arc<LocalCredentialAuthority<OAuthTestProtectedStore>>,
        environment_id: EnvironmentId,
        credential_id: CredentialId,
        material_generation: Arc<AtomicUsize>,
        refresh_active: Arc<AtomicBool>,
        begin_count: Arc<AtomicUsize>,
        start_count: Arc<AtomicUsize>,
        start_control: Option<Arc<BlockingRefreshControl>>,
        fail_start: bool,
        recovered_material: std::sync::Mutex<Option<CanonicalCodexOAuthBundle>>,
        commit_started: Arc<AtomicBool>,
        commit_delay: Duration,
        commit_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
        failure_count: Arc<AtomicUsize>,
        lease_count: Arc<AtomicUsize>,
        commit_return_gate: Arc<CommitReturnGate>,
        begin_control: Option<Arc<BlockingRefreshControl>>,
    }

    #[async_trait]
    impl BrokerLeaseProvider for OAuthTestLeaseProvider {
        type Lease = codewire_local_credentials::CredentialOperationLease;
        type RefreshReservation = TestOAuthRefreshReservation;
        type StartedRefresh = TestStartedOAuthRefresh;

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
            request: BrokerCredentialRefreshRequest,
        ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
            self.begin_count.fetch_add(1, Ordering::Relaxed);
            if let Some(material) = self.recovered_material.lock().unwrap().take() {
                let observed = self
                    .authority
                    .get_credential(&self.credential_id)
                    .map_err(|_| BrokerRefreshError::Unavailable)?
                    .metadata;
                let mut bytes = material.into_bytes();
                self.authority
                    .rotate_credential_material(
                        &self.credential_id,
                        observed.revocation_generation,
                        ProtectedValue::new(std::mem::take(&mut *bytes)).unwrap(),
                        observed.expires_at_unix,
                        observed.account_hint,
                    )
                    .map_err(|_| BrokerRefreshError::Unavailable)?;
                self.material_generation.fetch_add(1, Ordering::AcqRel);
                return Ok(BrokerRefreshAdmission::Recovered);
            }
            if let Some(control) = &self.begin_control
                && !control.accepted.swap(true, Ordering::AcqRel)
            {
                // Model a delayed reply that another authority client owns
                // this generation's refresh; no local permit was acquired.
                control.release.notified().await;
                return Err(BrokerRefreshError::InProgress);
            }
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
                || request.request_id.is_nil()
                || request.grant.capability_slot != CapabilitySlot::codex()
                || request.operation.as_str() != OPENAI_OPERATION
                || request.route.as_str() != OPENAI_ROUTE
                || request.grant.credential_id != self.credential_id
                || request.grant.credential_revocation_generation
                    != current.metadata.revocation_generation
                || request.material_generation != expected_material_generation
            {
                self.refresh_active.store(false, Ordering::Release);
                return Err(BrokerRefreshError::Denied);
            }
            Ok(BrokerRefreshAdmission::Reserved(
                TestOAuthRefreshReservation(request),
            ))
        }

        async fn start_credential_refresh(
            &self,
            reservation: Self::RefreshReservation,
        ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
            if let Some(control) = &self.start_control {
                control.accepted.store(true, Ordering::Release);
                control.release.notified().await;
            }
            let request = reservation.0;
            let current = self
                .authority
                .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
                    environment_id: self.environment_id.clone(),
                    environment_generation: 11,
                    capability_slot: request.grant.capability_slot.clone(),
                    operation: request.operation.clone(),
                    route: request.route.clone(),
                })
                .map_err(|_| BrokerRefreshError::Denied)?;
            validate_request_binding(current.grant(), &request.grant)
                .map_err(|_| BrokerRefreshError::Denied)?;
            if current.grant().credential_revocation_generation
                != request.grant.credential_revocation_generation
                || current.material_generation() != request.material_generation
            {
                return Err(BrokerRefreshError::Stale);
            }
            self.start_count.fetch_add(1, Ordering::Release);
            if self.fail_start {
                // Model a lost acknowledgement after durable Start. The
                // reservation must not be aborted, nor may the provider run.
                return Err(BrokerRefreshError::Unavailable);
            }
            Ok(TestStartedOAuthRefresh {
                credential_id: request.grant.credential_id,
                material_generation: request.material_generation,
            })
        }

        async fn commit_credential_refresh(
            &self,
            permit: Self::StartedRefresh,
            material: CanonicalCodexOAuthBundle,
        ) -> Result<(), BrokerRefreshError> {
            if !self.refresh_active.load(Ordering::Acquire)
                || permit.credential_id != self.credential_id
                || permit.material_generation
                    != self.material_generation.load(Ordering::Acquire) as u64
            {
                return Err(BrokerRefreshError::Denied);
            }
            self.commit_started.store(true, Ordering::Release);
            if !self.commit_delay.is_zero() {
                tokio::time::sleep(self.commit_delay).await;
            }
            let mut bytes = material.into_bytes();
            let value = ProtectedValue::new(std::mem::take(&mut *bytes))
                .map_err(|_| BrokerRefreshError::InvalidRequest)?;
            // Refresh rotates provider material, never the owner's hard
            // deadline. The previous fake silently cleared this field.
            let observed = self
                .authority
                .get_credential(&self.credential_id)
                .map_err(|_| BrokerRefreshError::Unavailable)?
                .metadata;
            let result = self
                .authority
                .rotate_credential_material(
                    &self.credential_id,
                    observed.revocation_generation,
                    value,
                    observed.expires_at_unix,
                    observed.account_hint,
                )
                .map_err(|_| BrokerRefreshError::Unavailable);
            if result.is_ok() {
                self.material_generation.fetch_add(1, Ordering::AcqRel);
                self.commit_count.fetch_add(1, Ordering::Relaxed);
            }
            self.refresh_active.store(false, Ordering::Release);
            if result.is_ok() && self.commit_return_gate.armed.swap(false, Ordering::AcqRel) {
                self.commit_return_gate.committed.notify_one();
                self.commit_return_gate.release.notified().await;
            }
            result.map(|_| ())
        }

        async fn abort_credential_refresh(
            &self,
            permit: Self::RefreshReservation,
        ) -> Result<(), BrokerRefreshError> {
            if permit.0.grant.credential_id != self.credential_id
                || !self.refresh_active.swap(false, Ordering::AcqRel)
            {
                return Err(BrokerRefreshError::Denied);
            }
            self.abort_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn fail_credential_refresh(
            &self,
            permit: Self::StartedRefresh,
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

        async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
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
        refresh_headers: HeaderMap,
        refresh_body_started: Arc<AtomicUsize>,
        refresh_delay: Duration,
        refresh_body_delay: Duration,
        refresh_error: Option<BrokerUpstreamError>,
        start_count: Arc<AtomicUsize>,
        refresh_control: Option<Arc<BlockingRefreshControl>>,
        unauthorized_control: Option<Arc<BlockingRefreshControl>>,
        expected_access_token: Arc<String>,
        unauthorized_access_tokens: Arc<BTreeSet<String>>,
        refresh_count: Arc<AtomicUsize>,
        response_count: Arc<AtomicUsize>,
        response_headers: HeaderMap,
        response_body_started: Arc<AtomicUsize>,
        reflect_authorization: bool,
    }

    #[derive(Default)]
    struct BlockingRefreshControl {
        accepted: AtomicBool,
        release: Notify,
    }

    impl BlockingRefreshControl {
        async fn wait_accepted(&self) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !self.accepted.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("synthetic request did not reach its barrier");
        }
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
                    assert!(
                        self.start_count.load(Ordering::Acquire) > 0,
                        "provider exchange preceded Start"
                    );
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
                    if let Some(control) = &self.refresh_control {
                        control.accepted.store(true, Ordering::Release);
                        control.release.notified().await;
                    }
                    if !self.refresh_delay.is_zero() {
                        tokio::time::sleep(self.refresh_delay).await;
                    }
                    if let Some(error) = self.refresh_error {
                        return Err(error);
                    }
                    let refresh_response = Arc::clone(&self.refresh_response);
                    let body_started = Arc::clone(&self.refresh_body_started);
                    let body_delay = self.refresh_body_delay;
                    Ok(BrokerUpstreamResponse::new(
                        self.refresh_status,
                        self.refresh_headers.clone(),
                        Box::pin(stream::once(async move {
                            body_started.fetch_add(1, Ordering::Relaxed);
                            if !body_delay.is_zero() {
                                tokio::time::sleep(body_delay).await;
                            }
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
                        if let Some(control) = &self.unauthorized_control
                            && !control.accepted.swap(true, Ordering::AcqRel)
                        {
                            control.release.notified().await;
                        }
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
                    let mut response_headers = self.response_headers.clone();
                    let response_body = if self.reflect_authorization {
                        let encoded = base64::engine::general_purpose::STANDARD
                            .encode(headers.get(http::header::AUTHORIZATION).unwrap().as_bytes());
                        response_headers
                            .insert("x-request-id", HeaderValue::from_str(&encoded).unwrap());
                        encoded.into_bytes()
                    } else {
                        b"synthetic response".to_vec()
                    };
                    let body_started = Arc::clone(&self.response_body_started);
                    Ok(BrokerUpstreamResponse::new(
                        StatusCode::OK,
                        response_headers,
                        Box::pin(stream::once(async move {
                            body_started.fetch_add(1, Ordering::Relaxed);
                            Ok(Bytes::from(response_body))
                        })),
                    ))
                }
                _ => Err(BrokerUpstreamError::DestinationDenied),
            }
        }
    }

    struct OAuthTestState {
        authority: Arc<LocalCredentialAuthority<OAuthTestProtectedStore>>,
        protected_store: OAuthTestProtectedStore,
        metadata_path: PathBuf,
        credential_id: CredentialId,
        environment_id: EnvironmentId,
        hard_deadline: u64,
        material_generation: Arc<AtomicUsize>,
        begin_count: Arc<AtomicUsize>,
        commit_started: Arc<AtomicBool>,
        commit_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
        failure_count: Arc<AtomicUsize>,
        refresh_count: Arc<AtomicUsize>,
        response_count: Arc<AtomicUsize>,
        lease_count: Arc<AtomicUsize>,
        commit_return_gate: Arc<CommitReturnGate>,
    }

    impl OAuthTestState {
        fn current_grant(&self) -> codewire_access::DerivedGrant {
            self.authority
                .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
                    environment_id: self.environment_id.clone(),
                    environment_generation: 11,
                    capability_slot: CapabilitySlot::codex(),
                    operation: BrokerOperationId::parse(OPENAI_OPERATION).unwrap(),
                    route: BrokerRouteId::parse(OPENAI_ROUTE).unwrap(),
                })
                .unwrap()
                .grant
        }

        fn replace_binding_revision(&self) {
            self.replace_binding_credential(&self.credential_id);
        }

        fn replace_binding_credential(&self, credential_id: &CredentialId) {
            let binding = self
                .authority
                .get_environment_access_binding(&self.environment_id)
                .unwrap()
                .binding;
            let replacement = self
                .authority
                .update_profile(
                    &binding.profile_id,
                    binding.profile_revision,
                    BTreeMap::from([(CapabilitySlot::codex(), credential_id.clone())]),
                )
                .unwrap();
            self.authority
                .replace_environment_access_binding(
                    &self.environment_id,
                    &binding.profile_id,
                    binding.profile_revision,
                    replacement.profile.id,
                    replacement.profile.revision,
                )
                .unwrap();
            // The selected credential is valid under the new revision;
            // failures below must be continuity denial, not missing access.
            let grant = self.current_grant();
            assert_eq!(grant.profile_revision, binding.profile_revision + 1);
            assert_eq!(&grant.credential_id, credential_id);
        }

        fn current_material(&self) -> Vec<u8> {
            let connection = rusqlite::Connection::open(&self.metadata_path).unwrap();
            let reference: String = connection
                .query_row(
                    "SELECT protected_entry_id FROM credentials WHERE id=?1",
                    [self.credential_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            let id = ProtectedEntryId::parse(reference).unwrap();
            self.protected_store
                .get(&id)
                .unwrap()
                .unwrap()
                .expose_secret()
                .to_vec()
        }
    }

    fn provider_catalog(authentication_kind: CredentialAuthKind) -> ProviderCatalog {
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            authentication_kinds: BTreeSet::from([authentication_kind]),
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
        oauth_broker_with_initial_token_and_commit_delay(
            initial_access_token,
            unauthorized_access_tokens,
            refresh_status,
            refresh_response,
            expected_access_token,
            refresh_delay,
            Duration::ZERO,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn oauth_broker_with_initial_token_and_commit_delay(
        initial_access_token: String,
        unauthorized_access_tokens: BTreeSet<String>,
        refresh_status: StatusCode,
        refresh_response: Vec<u8>,
        expected_access_token: String,
        refresh_delay: Duration,
        commit_delay: Duration,
        refresh_control: Option<Arc<BlockingRefreshControl>>,
    ) -> (
        OpenAiBroker<OAuthTestLeaseProvider, OAuthSyntheticUpstream>,
        OAuthTestState,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.keep().join("authority");
        let protected_store = OAuthTestProtectedStore::default();
        let hard_deadline = current_unix_time().expect("current time") + 3_600;
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &root,
                protected_store.clone(),
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
                    expires_at_unix: Some(hard_deadline),
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
        let start_count = Arc::new(AtomicUsize::new(0));
        let commit_started = Arc::new(AtomicBool::new(false));
        let commit_count = Arc::new(AtomicUsize::new(0));
        let abort_count = Arc::new(AtomicUsize::new(0));
        let failure_count = Arc::new(AtomicUsize::new(0));
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let response_count = Arc::new(AtomicUsize::new(0));
        let lease_count = Arc::new(AtomicUsize::new(0));
        let commit_return_gate = Arc::new(CommitReturnGate::default());
        let state = OAuthTestState {
            authority: Arc::clone(&authority),
            protected_store,
            metadata_path: root.join(codewire_local_credentials::DATABASE_FILE),
            credential_id: credential.metadata.id.clone(),
            environment_id: environment_id.clone(),
            hard_deadline,
            material_generation: Arc::clone(&material_generation),
            begin_count: Arc::clone(&begin_count),
            commit_started: Arc::clone(&commit_started),
            commit_count: Arc::clone(&commit_count),
            abort_count: Arc::clone(&abort_count),
            failure_count: Arc::clone(&failure_count),
            refresh_count: Arc::clone(&refresh_count),
            response_count: Arc::clone(&response_count),
            lease_count: Arc::clone(&lease_count),
            commit_return_gate: Arc::clone(&commit_return_gate),
        };
        let broker = OpenAiBroker::new(
            OAuthTestLeaseProvider {
                authority,
                environment_id,
                credential_id: credential.metadata.id,
                material_generation,
                refresh_active,
                begin_count,
                start_count: Arc::clone(&start_count),
                start_control: None,
                fail_start: false,
                recovered_material: std::sync::Mutex::new(None),
                commit_started,
                commit_delay,
                commit_count,
                abort_count,
                failure_count,
                lease_count,
                commit_return_gate,
                begin_control: None,
            },
            OAuthSyntheticUpstream {
                refresh_status,
                refresh_response: Arc::new(refresh_response),
                refresh_headers: HeaderMap::new(),
                refresh_body_started: Arc::new(AtomicUsize::new(0)),
                refresh_delay,
                refresh_body_delay: Duration::ZERO,
                refresh_error: None,
                start_count,
                refresh_control,
                unauthorized_control: None,
                expected_access_token: Arc::new(expected_access_token),
                unauthorized_access_tokens: Arc::new(unauthorized_access_tokens),
                refresh_count,
                response_count,
                response_headers: HeaderMap::new(),
                response_body_started: Arc::new(AtomicUsize::new(0)),
                reflect_authorization: false,
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
            capability_slot: "codex".into(),
            route: "openai-api".into(),
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
                HeaderValue::from_static("Bearer cwlocalbroker0123456789abcdef0123456789abcdef"),
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
    async fn response_admission_runtime_denies_before_polling_provider_body() {
        let access_token = jwt(json!({
            "exp": current_unix_time().unwrap() + 3_600
        }));
        for headers in denied_encodings() {
            let (mut broker, state) = oauth_broker_with_initial_token(
                access_token.clone(),
                BTreeSet::new(),
                StatusCode::OK,
                Vec::new(),
                access_token.clone(),
                Duration::ZERO,
            );
            let upstream = Arc::get_mut(&mut broker.upstream).unwrap();
            upstream.response_headers = headers;
            upstream.reflect_authorization = true;
            let body_started = Arc::clone(&upstream.response_body_started);
            assert!(matches!(
                broker.execute(request()).await,
                Err(BrokerRequestError::UpstreamFailed)
            ));
            assert_eq!(body_started.load(Ordering::Relaxed), 0);
            assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn response_admission_refresh_denial_fails_once_without_body_poll_or_retry() {
        let access_token = jwt(json!({
            "exp": current_unix_time().unwrap() + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": access_token,
            "refresh_token": "synthetic-new-refresh-token"
        }))
        .unwrap();
        for headers in denied_encodings() {
            let (mut broker, state) = oauth_broker(
                StatusCode::OK,
                refresh_response.clone(),
                access_token.clone(),
                Duration::ZERO,
            );
            let upstream = Arc::get_mut(&mut broker.upstream).unwrap();
            upstream.refresh_headers = headers;
            let body_started = Arc::clone(&upstream.refresh_body_started);
            assert!(matches!(
                broker.execute(request()).await,
                Err(BrokerRequestError::UpstreamFailed)
            ));
            broker.wait_for_active_operations().await.unwrap();
            assert_eq!(body_started.load(Ordering::Relaxed), 0);
            assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
            assert!(matches!(
                broker.execute(request()).await,
                Err(BrokerRequestError::Denied)
            ));
            assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn response_admission_identity_refresh_promotes_and_redacts_new_authorization() {
        let access_token = jwt(json!({
            "exp": current_unix_time().unwrap() + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": access_token,
            "refresh_token": "synthetic-new-refresh-token"
        }))
        .unwrap();
        for headers in accepted_encodings() {
            let (mut broker, state) = oauth_broker(
                StatusCode::OK,
                refresh_response.clone(),
                access_token.clone(),
                Duration::ZERO,
            );
            let upstream = Arc::get_mut(&mut broker.upstream).unwrap();
            upstream.refresh_headers = headers.clone();
            upstream.response_headers = headers;
            upstream.reflect_authorization = true;
            let body_started = Arc::clone(&upstream.refresh_body_started);
            let response = broker.execute(request()).await.unwrap();
            let (status, headers, mut body) = response.into_parts();
            assert_eq!(status, StatusCode::OK);
            assert!(!headers.contains_key(http::header::CONTENT_ENCODING));
            assert_eq!(headers.get("x-request-id").unwrap(), "[REDACTED]");
            let mut output = Vec::new();
            while let Some(chunk) = body.next().await {
                output.extend(chunk.unwrap());
            }
            assert_eq!(output, b"[REDACTED]");
            assert_eq!(body_started.load(Ordering::Relaxed), 1);
            assert_eq!(state.material_generation.load(Ordering::Relaxed), 2);
            assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
        }
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

    enum PostCommitInvalidation {
        HardExpiry,
        Revocation,
        BindingRemoval,
        BindingRevisionReplacement,
    }

    async fn assert_post_commit_admission_denied(invalidation: PostCommitInvalidation) {
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
            Duration::ZERO,
        );
        state
            .commit_return_gate
            .armed
            .store(true, Ordering::Release);
        let execution = tokio::spawn(async move { broker.execute(request()).await });
        state.commit_return_gate.wait().await;

        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.material_generation.load(Ordering::Acquire), 2);
        assert_eq!(
            state
                .authority
                .get_credential(&state.credential_id)
                .unwrap()
                .metadata
                .expires_at_unix,
            Some(state.hard_deadline)
        );
        let committed_material = state.current_material();
        assert!(
            committed_material
                .windows(b"synthetic-new-refresh-token".len())
                .any(|window| window == b"synthetic-new-refresh-token")
        );

        match invalidation {
            PostCommitInvalidation::HardExpiry => {
                // Advance only the isolated fixture's hard deadline; changing
                // no generation or protected bytes isolates expiry admission.
                let connection = rusqlite::Connection::open(&state.metadata_path).unwrap();
                assert_eq!(
                    connection
                        .execute(
                            "UPDATE credentials SET expires_at_unix=1 WHERE id=?1",
                            [state.credential_id.as_str()],
                        )
                        .unwrap(),
                    1
                );
            }
            PostCommitInvalidation::Revocation => {
                state
                    .authority
                    .revoke_credential(&state.credential_id)
                    .unwrap();
            }
            PostCommitInvalidation::BindingRemoval => {
                let binding = state
                    .authority
                    .get_environment_access_binding(&state.environment_id)
                    .unwrap()
                    .binding;
                state
                    .authority
                    .delete_environment_access_binding(
                        &state.environment_id,
                        &binding.profile_id,
                        binding.profile_revision,
                    )
                    .unwrap();
            }
            PostCommitInvalidation::BindingRevisionReplacement => {
                state.replace_binding_revision();
            }
        }

        state.commit_return_gate.release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(BrokerRequestError::Denied)));
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 3);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
        // Denying the pending Responses operation must not throw away a
        // refresh token that the provider has already durably rotated.
        assert_eq!(state.current_material(), committed_material);
        assert_eq!(state.material_generation.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn hard_expiry_after_refresh_commit_denies_without_discarding_material() {
        assert_post_commit_admission_denied(PostCommitInvalidation::HardExpiry).await;
    }

    #[tokio::test]
    async fn revocation_after_refresh_commit_denies_without_discarding_material() {
        assert_post_commit_admission_denied(PostCommitInvalidation::Revocation).await;
    }

    #[tokio::test]
    async fn binding_removal_after_refresh_commit_denies_without_discarding_material() {
        assert_post_commit_admission_denied(PostCommitInvalidation::BindingRemoval).await;
    }

    #[tokio::test]
    async fn binding_revision_after_refresh_commit_denies_without_discarding_material() {
        assert_post_commit_admission_denied(PostCommitInvalidation::BindingRevisionReplacement)
            .await;
    }

    #[tokio::test]
    async fn post_commit_admission_uses_actual_current_material_and_generation() {
        let now = current_unix_time().expect("current time");
        let refreshed_access_token = jwt(json!({ "exp": now + 3_600 }));
        let replacement_access_token = jwt(json!({ "exp": now + 7_200 }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": refreshed_access_token,
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (broker, state) = oauth_broker(
            StatusCode::OK,
            refresh_response,
            replacement_access_token.clone(),
            Duration::ZERO,
        );
        let broker = Arc::new(broker);
        state
            .commit_return_gate
            .armed
            .store(true, Ordering::Release);
        let guest_request = ValidatedGuestRequest::parse(request()).unwrap();
        let provider_request = broker
            .api_key_adapter
            .validate_request(
                &guest_request.method,
                &guest_request.path,
                guest_request.query.as_deref(),
                guest_request.headers,
                guest_request.body,
            )
            .unwrap();
        let admitted_grant = state.current_grant();
        let preparation = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move {
                broker
                    .prepare_oauth_after_refresh(
                        guest_request.request_id,
                        BrokerOperationId::parse(OPENAI_OPERATION).unwrap(),
                        BrokerRouteId::parse(OPENAI_ROUTE).unwrap(),
                        provider_request,
                        None,
                        &admitted_grant,
                    )
                    .await
            }
        });
        state.commit_return_gate.wait().await;
        assert_eq!(state.material_generation.load(Ordering::Acquire), 2);
        assert_eq!(
            state
                .authority
                .get_credential(&state.credential_id)
                .unwrap()
                .metadata
                .expires_at_unix,
            Some(state.hard_deadline)
        );

        // An owner can publish a later generation while the commit reply is
        // delayed. The broker must use that authority-admitted value, not the
        // in-memory refresh result or an inferred previous-generation + 1.
        let mut replacement = oauth_material(&replacement_access_token).into_bytes();
        let observed = state
            .authority
            .get_credential(&state.credential_id)
            .unwrap()
            .metadata;
        state
            .authority
            .rotate_credential_material(
                &state.credential_id,
                observed.revocation_generation,
                ProtectedValue::new(std::mem::take(&mut *replacement)).unwrap(),
                Some(state.hard_deadline),
                observed.account_hint,
            )
            .unwrap();
        state.material_generation.store(3, Ordering::Release);
        state.commit_return_gate.release.notify_one();

        let prepared = tokio::time::timeout(Duration::from_secs(2), preparation)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(prepared.generation.credential_id, state.credential_id);
        assert_eq!(prepared.generation.material_generation, 3);
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 2);
        let (response, _) = broker.execute_prepared(prepared.request).await.unwrap();
        assert_eq!(response.into_parts().0, StatusCode::OK);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn oauth_mutex_wait_does_not_switch_the_initial_request_binding() {
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
            Duration::ZERO,
        );
        let original_material = state.current_material();
        let broker = Arc::new(broker);
        let refresh_guard = broker.oauth_refresh.lock().await;
        let execution = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(request()).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.lease_count.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
        state.replace_binding_revision();
        drop(refresh_guard);

        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(BrokerRequestError::Denied)));
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 2);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.current_material(), original_material);
    }

    #[tokio::test]
    async fn oauth_in_progress_wait_does_not_recapture_a_replaced_binding() {
        let access_token = jwt(json!({
            "exp": current_unix_time().expect("current time") + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (mut broker, state) = oauth_broker(
            StatusCode::OK,
            refresh_response,
            access_token,
            Duration::ZERO,
        );
        let original_material = state.current_material();
        let begin_control = Arc::new(BlockingRefreshControl::default());
        Arc::get_mut(&mut broker.leases).unwrap().begin_control = Some(Arc::clone(&begin_control));
        let execution = tokio::spawn(async move { broker.execute(request()).await });
        begin_control.wait_accepted().await;
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 2);
        state.replace_binding_revision();
        begin_control.release.notify_one();

        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(BrokerRequestError::Denied)));
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 3);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.current_material(), original_material);
    }

    #[tokio::test]
    async fn oauth_unauthorized_retry_does_not_replay_under_a_newly_bound_credential() {
        let now = current_unix_time().expect("current time");
        let initial_access_token = jwt(json!({ "exp": now + 3_600 }));
        let replacement_access_token = jwt(json!({ "exp": now + 7_200 }));
        let (mut broker, state) = oauth_broker_with_initial_token(
            initial_access_token.clone(),
            BTreeSet::from([initial_access_token]),
            StatusCode::OK,
            br#"{"error":"refresh must not be attempted"}"#.to_vec(),
            replacement_access_token.clone(),
            Duration::ZERO,
        );
        let original_material = state.current_material();
        let unauthorized_control = Arc::new(BlockingRefreshControl::default());
        Arc::get_mut(&mut broker.upstream)
            .unwrap()
            .unauthorized_control = Some(Arc::clone(&unauthorized_control));
        let execution = tokio::spawn(async move { broker.execute(request()).await });
        unauthorized_control.wait_accepted().await;
        assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
        let mut replacement_material = oauth_material(&replacement_access_token).into_bytes();
        let replacement = state
            .authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-second-oauth".into(),
                    account_hint: None,
                    expires_at_unix: Some(state.hard_deadline),
                },
                ProtectedValue::new(std::mem::take(&mut *replacement_material)).unwrap(),
            )
            .unwrap();
        state.replace_binding_credential(&replacement.metadata.id);
        unauthorized_control.release.notify_one();

        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(BrokerRequestError::Denied)));
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 2);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        // Only the initial credential was used for the guest body. A valid
        // lease for the new credential must not authorize replaying that body.
        assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.current_material(), original_material);
    }

    #[tokio::test]
    async fn epoch_shutdown_waits_for_started_oauth_refresh_commit() {
        let expired_access_token = jwt(json!({
            "exp": current_unix_time().expect("current time").saturating_sub(1)
        }));
        let refreshed_access_token = jwt(json!({
            "exp": current_unix_time().expect("current time") + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": refreshed_access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let (broker, state) = oauth_broker_with_initial_token_and_commit_delay(
            expired_access_token,
            BTreeSet::new(),
            StatusCode::OK,
            refresh_response,
            refreshed_access_token,
            Duration::ZERO,
            Duration::from_millis(250),
            None,
        );
        let broker = Arc::new(broker);
        let execution = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(request()).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !state.commit_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        execution.abort();
        match execution.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("broker request was not cancelled"),
        }

        let mut shutdown = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.wait_for_active_operations().await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
                .await
                .is_err()
        );
        shutdown.await.unwrap().unwrap();

        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn bridge_shutdown_waits_after_the_refresh_provider_accepts_rotation() {
        let expired_access_token = jwt(json!({
            "exp": current_unix_time().expect("current time").saturating_sub(1)
        }));
        let refreshed_access_token = jwt(json!({
            "exp": current_unix_time().expect("current time") + 3_600
        }));
        let refresh_response = serde_json::to_vec(&json!({
            "access_token": refreshed_access_token.clone(),
            "refresh_token": "synthetic-new-refresh-token",
            "token_type": "bearer"
        }))
        .unwrap();
        let refresh_control = Arc::new(BlockingRefreshControl::default());
        let (broker, state) = oauth_broker_with_initial_token_and_commit_delay(
            expired_access_token,
            BTreeSet::new(),
            StatusCode::OK,
            refresh_response,
            refreshed_access_token,
            Duration::ZERO,
            Duration::ZERO,
            Some(Arc::clone(&refresh_control)),
        );
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(3);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let mut bridge = tokio::spawn(crate::bridge::tests::run_channel_test_bridge(
            Arc::new(broker),
            input_rx,
            output_tx,
            environment_id,
            4,
        ));
        input_tx
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                    v1::CredentialBridgeReady {
                        protocol_version:
                            codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: environment_id.to_string(),
                        environment_generation: 4,
                    },
                )),
            })
            .await
            .unwrap();
        input_tx
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                    request(),
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !refresh_control.accepted.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        drop(input_tx);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut bridge)
                .await
                .is_err()
        );
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.material_generation.load(Ordering::Acquire), 1);

        refresh_control.release.notify_one();
        assert_eq!(
            bridge.await.unwrap(),
            Err(crate::BrokerBridgeError::Unavailable)
        );
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.material_generation.load(Ordering::Acquire), 2);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
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
    async fn ambiguous_provider_failure_invalidates_without_retrying_the_old_token() {
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
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
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

    #[tokio::test]
    async fn post_send_transport_failure_never_aborts_into_a_retry() {
        let (mut broker, state) =
            oauth_broker(StatusCode::OK, Vec::new(), "unused".into(), Duration::ZERO);
        Arc::get_mut(&mut broker.upstream).unwrap().refresh_error =
            Some(BrokerUpstreamError::Connect);
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::UpstreamFailed)
        ));
        assert_eq!(broker.leases.start_count.load(Ordering::Acquire), 1);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
    }

    async fn assert_refresh_timeout(header_delay: Duration, body_delay: Duration) {
        let (mut broker, state) =
            oauth_broker(StatusCode::OK, Vec::new(), "unused".into(), Duration::ZERO);
        let upstream = Arc::get_mut(&mut broker.upstream).unwrap();
        upstream.refresh_body_delay = body_delay;
        upstream.refresh_delay = header_delay;
        let started_at = tokio::time::Instant::now();
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::UpstreamFailed)
        ));
        assert_eq!(
            started_at.elapsed(),
            Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS)
        );
        broker.wait_for_active_operations().await.unwrap();
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 0);
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::Denied)
        ));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_timeout_bounds_waiting_for_provider_headers() {
        assert_refresh_timeout(Duration::from_secs(90), Duration::ZERO).await;
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_timeout_bounds_the_entire_provider_body() {
        assert_refresh_timeout(Duration::ZERO, Duration::from_secs(90)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_headers_and_body_share_one_timeout_budget() {
        assert_refresh_timeout(Duration::from_secs(20), Duration::from_secs(20)).await;
    }

    #[tokio::test]
    async fn lost_start_acknowledgement_neither_sends_nor_aborts() {
        let (mut broker, state) =
            oauth_broker(StatusCode::OK, Vec::new(), "unused".into(), Duration::ZERO);
        Arc::get_mut(&mut broker.leases).unwrap().fail_start = true;
        assert!(matches!(
            broker.execute(request()).await,
            Err(BrokerRequestError::AuthorityUnavailable)
        ));
        assert_eq!(broker.leases.start_count.load(Ordering::Acquire), 1);
        assert!(broker.leases.refresh_active.load(Ordering::Acquire));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn binding_change_during_start_admission_denies_before_provider_send() {
        let (mut broker, state) =
            oauth_broker(StatusCode::OK, Vec::new(), "unused".into(), Duration::ZERO);
        let control = Arc::new(BlockingRefreshControl::default());
        Arc::get_mut(&mut broker.leases).unwrap().start_control = Some(Arc::clone(&control));
        let execution = tokio::spawn(async move { broker.execute(request()).await });
        control.wait_accepted().await;
        state.replace_binding_revision();
        control.release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(BrokerRequestError::AuthorityUnavailable)
        ));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn start_wait_preserves_original_deadline_even_when_current_grant_lives_longer() {
        let (mut broker, state) =
            oauth_broker(StatusCode::OK, Vec::new(), "unused".into(), Duration::ZERO);
        let control = Arc::new(BlockingRefreshControl::default());
        Arc::get_mut(&mut broker.leases).unwrap().start_control = Some(Arc::clone(&control));
        let guest = ValidatedGuestRequest::parse(request()).unwrap();
        let provider_request = broker
            .api_key_adapter
            .validate_request(
                &guest.method,
                &guest.path,
                guest.query.as_deref(),
                guest.headers,
                guest.body,
            )
            .unwrap();
        let mut original = state.current_grant();
        let original_deadline = current_unix_time().unwrap() + 2;
        original.expires_at_unix = Some(original_deadline);
        let preparation = tokio::spawn(async move {
            broker
                .prepare_oauth_after_refresh(
                    guest.request_id,
                    BrokerOperationId::parse(OPENAI_OPERATION).unwrap(),
                    BrokerRouteId::parse(OPENAI_ROUTE).unwrap(),
                    provider_request,
                    None,
                    &original,
                )
                .await
        });
        control.wait_accepted().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while current_unix_time().unwrap() < original_deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(state.current_grant().expires_at_unix.unwrap() > original_deadline);
        control.release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(2), preparation)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(BrokerRequestError::AuthorityUnavailable)
        ));
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.abort_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.commit_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn recovered_short_lived_material_requires_a_fresh_lease_not_another_refresh() {
        let access_token = jwt(json!({
            "exp": current_unix_time().unwrap() + 30
        }));
        let (broker, state) = oauth_broker(
            StatusCode::OK,
            Vec::new(),
            access_token.clone(),
            Duration::ZERO,
        );
        *broker.leases.recovered_material.lock().unwrap() = Some(oauth_material(&access_token));
        let mut response = broker.execute(request()).await.unwrap();
        while let Some(chunk) = response.body.next().await {
            chunk.unwrap();
        }
        assert_eq!(state.lease_count.load(Ordering::Relaxed), 3);
        assert_eq!(state.material_generation.load(Ordering::Relaxed), 2);
        assert_eq!(state.begin_count.load(Ordering::Relaxed), 1);
        assert_eq!(broker.leases.start_count.load(Ordering::Acquire), 0);
        assert_eq!(state.refresh_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.response_count.load(Ordering::Relaxed), 1);
    }
}
