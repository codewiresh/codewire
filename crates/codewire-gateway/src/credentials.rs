//! Material-free HTTPS request to private credential-RPC adapter.
//!
//! The process owner mounts this only behind the configured gateway TLS
//! identity. Each admission reloads the separate broker root and opens a new
//! verified private TLS channel; no previous RPC's trust snapshot is reused.
//! Each HTTP request owns one fresh bridge and private call. Projected tokens
//! are forwarded only as authentication metadata; the broker verifies their
//! exact Pod identities and original expiries. No token claims are trusted here.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, BodyDataStream, to_bytes};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use bytes::Bytes;
use codewire_credential_bridge::CredentialBridge;
use codewire_gateway_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADERS, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT,
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES, DAEMON_AUTH_TOKEN_HEADER,
};
use codewire_tls::ClientTlsEndpoint;
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, oneshot};
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::metadata::MetadataValue;
#[cfg(test)]
use tonic::transport::Channel;
use uuid::Uuid;
use zeroize::Zeroizing;

const WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";
const ASCII_WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Closed configuration failure, never a key, token, filesystem or TLS dump.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("credential ingress configuration is invalid")]
pub struct CredentialIngressConfigError;

/// Trusted deployment coordinates and transport, never HTTP-request options.
pub struct CredentialIngressConfig {
    environment_id: Uuid,
    environment_generation: u64,
    https_authority: String,
    gateway_token_path: PathBuf,
    broker: BrokerEndpoint,
}

enum BrokerEndpoint {
    Tls(ClientTlsEndpoint),
    #[cfg(test)]
    Preconfigured(Channel),
}

impl BrokerEndpoint {
    async fn connect(&self) -> Result<tonic::transport::Channel, StatusCode> {
        match self {
            Self::Tls(endpoint) => endpoint
                .connect()
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE),
            #[cfg(test)]
            Self::Preconfigured(channel) => Ok(channel.clone()),
        }
    }
}

impl CredentialIngressConfig {
    /// Projected-token symlinks are intentional Kubernetes rotation, not a
    /// source of configurable token paths in incoming requests. The endpoint
    /// reloads the purpose-specific roots for every admitted private call.
    pub fn new(
        environment_id: Uuid,
        environment_generation: u64,
        https_authority: &str,
        gateway_token_path: PathBuf,
        broker: ClientTlsEndpoint,
    ) -> Result<Self, CredentialIngressConfigError> {
        Self::with_endpoint(
            environment_id,
            environment_generation,
            https_authority,
            gateway_token_path,
            BrokerEndpoint::Tls(broker),
        )
    }

    #[cfg(test)]
    fn for_test(
        environment_id: Uuid,
        environment_generation: u64,
        https_authority: &str,
        gateway_token_path: PathBuf,
        broker: Channel,
    ) -> Result<Self, CredentialIngressConfigError> {
        Self::with_endpoint(
            environment_id,
            environment_generation,
            https_authority,
            gateway_token_path,
            BrokerEndpoint::Preconfigured(broker),
        )
    }

    fn with_endpoint(
        environment_id: Uuid,
        environment_generation: u64,
        https_authority: &str,
        gateway_token_path: PathBuf,
        broker: BrokerEndpoint,
    ) -> Result<Self, CredentialIngressConfigError> {
        let authority: axum::http::uri::Authority = https_authority
            .parse()
            .map_err(|_| CredentialIngressConfigError)?;
        if environment_id.is_nil()
            || environment_generation == 0
            || environment_generation > i64::MAX as u64
            || !gateway_token_path.is_absolute()
            || gateway_token_path.file_name().is_none()
            || !https_authority.is_ascii()
            || https_authority.contains('@')
            || authority.host().is_empty()
            || (authority.as_str() != authority.host()
                && authority.port_u16().is_none_or(|port| port == 0))
        {
            return Err(CredentialIngressConfigError);
        }
        Ok(Self {
            environment_id,
            environment_generation,
            https_authority: authority.as_str().to_ascii_lowercase(),
            gateway_token_path,
            broker,
        })
    }
}

struct State {
    config: CredentialIngressConfig,
    accepting: Mutex<bool>,
    permits: Arc<Semaphore>,
    workers: TaskTracker,
    shutdown: CancellationToken,
}

/// One gateway-wide admission budget and drain owner. Clones share that owner.
/// The process must await `shutdown` before terminating its async runtime.
#[derive(Clone)]
pub struct CredentialIngress {
    state: Arc<State>,
}

impl CredentialIngress {
    pub fn new(config: CredentialIngressConfig) -> Self {
        Self {
            state: Arc::new(State {
                config,
                accepting: Mutex::new(true),
                permits: Arc::new(Semaphore::new(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT)),
                workers: TaskTracker::new(),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    /// Serve one canonical request. Admission occurs before buffering its body.
    /// The handler owns cancellation until its returned response body takes it.
    pub async fn respond(&self, request: Request<Body>) -> Response<Body> {
        let cancellation = self.state.shutdown.child_token();
        let owner = RequestOwner(cancellation.clone());
        let (response_tx, response_rx) = oneshot::channel();
        {
            let Ok(accepting) = self.state.accepting.lock() else {
                return fixed_response(StatusCode::SERVICE_UNAVAILABLE);
            };
            if !*accepting {
                return fixed_response(StatusCode::SERVICE_UNAVAILABLE);
            }
            let Ok(permit) = self.state.permits.clone().try_acquire_owned() else {
                return fixed_response(StatusCode::TOO_MANY_REQUESTS);
            };
            let state = self.state.clone();
            // Register startup, HTTP body reads, RPC headers, response ownership
            // and driver teardown in one tracked worker. No detached writer.
            drop(self.state.workers.spawn(async move {
                let _permit = permit;
                serve_request(state, request, cancellation, response_tx).await;
            }));
        }
        let response = match response_rx.await {
            Ok(response) => response,
            Err(_) => return fixed_response(StatusCode::SERVICE_UNAVAILABLE),
        };
        let (parts, body) = response.into_parts();
        Response::from_parts(
            parts,
            Body::from_stream(OwnedResponseBody {
                body: Box::pin(body.into_data_stream()),
                owner,
            }),
        )
    }

    /// Close admission, cancel whole calls and wait for material-free workers.
    /// This does not claim remote refresh publication is finished: the isolated
    /// broker retains and drains that work under its own service owner.
    pub async fn shutdown(&self) {
        {
            let mut accepting = self
                .state
                .accepting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *accepting = false;
            self.state.workers.close();
            self.state.shutdown.cancel();
        }
        self.state.workers.wait().await;
    }
}

struct RequestOwner(CancellationToken);

impl Drop for RequestOwner {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct OwnedResponseBody {
    body: Pin<Box<BodyDataStream>>,
    owner: RequestOwner,
}

impl Stream for OwnedResponseBody {
    type Item = Result<Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let item = self.body.as_mut().poll_next(context);
        if matches!(item, Poll::Ready(None | Some(Err(_)))) {
            self.owner.0.cancel();
        }
        item
    }
}

async fn serve_request(
    state: Arc<State>,
    request: Request<Body>,
    cancellation: CancellationToken,
    response_tx: oneshot::Sender<Response<Body>>,
) {
    let (mut request, workspace) = match prepare_request(request, &state.config.https_authority) {
        Ok(prepared) => prepared,
        Err(status) => {
            let _ = response_tx.send(fixed_response(status));
            return;
        }
    };
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let body = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        body = tokio::time::timeout(BODY_TIMEOUT, to_bytes(body, CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES)) => match body {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => { let _ = response_tx.send(fixed_response(StatusCode::PAYLOAD_TOO_LARGE)); return; }
            Err(_) => { let _ = response_tx.send(fixed_response(StatusCode::REQUEST_TIMEOUT)); return; }
        }
    };
    *request.body_mut() = Body::from(body);
    let bridge = match CredentialBridge::new(
        state.config.environment_id,
        state.config.environment_generation,
    ) {
        Ok(bridge) => bridge,
        Err(_) => {
            let _ = response_tx.send(fixed_response(StatusCode::SERVICE_UNAVAILABLE));
            return;
        }
    };
    let (prepared, output) = match bridge.prepare_connection() {
        Ok(prepared) => prepared,
        Err(_) => {
            let _ = response_tx.send(fixed_response(StatusCode::SERVICE_UNAVAILABLE));
            return;
        }
    };
    let admission = async {
        let gateway = read_gateway_token(&state.config.gateway_token_path).await?;
        let mut rpc = tonic::Request::new(output.map_while(Result::ok));
        *rpc.metadata_mut() = credential_metadata(&gateway, &workspace)?;
        let channel = state.config.broker.connect().await?;
        let mut client = CredentialBrokerServiceClient::new(channel)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        client
            .credential_bridge(rpc)
            .await
            .map_err(|error| match error.code() {
                tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
                tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
                tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            })
    };
    let response = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        response = tokio::time::timeout(ADMISSION_TIMEOUT, admission) => match response {
            Ok(Ok(response)) => response,
            Ok(Err(status)) => { let _ = response_tx.send(fixed_response(status)); return; }
            Err(_) => { let _ = response_tx.send(fixed_response(StatusCode::SERVICE_UNAVAILABLE)); return; }
        }
    };
    drop(workspace);
    // A private server may send successful headers only after authenticating
    // these exact tokens and admitting Ready. Never fabricate an Open frame.
    let connection = match prepared.activate(response.into_inner()).await {
        Ok(connection) => connection,
        Err(_) => {
            let _ = response_tx.send(fixed_response(StatusCode::SERVICE_UNAVAILABLE));
            return;
        }
    };
    let driver = connection.run_until(cancellation.cancelled());
    tokio::pin!(driver);
    let (response, driver_finished) = tokio::select! {
        biased;
        _ = &mut driver => (fixed_response(StatusCode::SERVICE_UNAVAILABLE), true),
        response = bridge.respond(request) => (response, false),
    };
    if response_tx.send(response).is_err() {
        cancellation.cancel();
    }
    if !driver_finished {
        // Body ownership, original broker expiry, transport EOF and explicit
        // shutdown all end this same driver. Never abort it during detach.
        driver.await;
    }
}

fn prepare_request(
    mut request: Request<Body>,
    authority: &str,
) -> Result<(Request<Body>, Zeroizing<Vec<u8>>), StatusCode> {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/responses"
        || request.uri().query().is_some()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    match request.version() {
        Version::HTTP_2 => {
            if request.uri().scheme_str() != Some("https")
                || !request
                    .uri()
                    .authority()
                    .is_some_and(|value| value.as_str().eq_ignore_ascii_case(authority))
            {
                return Err(StatusCode::FORBIDDEN);
            }
            check_host(request.headers(), authority, false)?;
        }
        Version::HTTP_11 => {
            if request.uri().scheme().is_some() || request.uri().authority().is_some() {
                return Err(StatusCode::FORBIDDEN);
            }
            check_host(request.headers(), authority, true)?;
        }
        _ => return Err(StatusCode::FORBIDDEN),
    }
    if request.headers().len() > CREDENTIAL_BRIDGE_MAX_HEADERS
        || [
            WORKSPACE_AUTHORIZATION,
            ASCII_WORKSPACE_AUTHORIZATION,
            DAEMON_AUTH_TOKEN_HEADER,
        ]
        .iter()
        .any(|name| request.headers().contains_key(*name))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut authorizations = request.headers().get_all("authorization").iter();
    let workspace = match (authorizations.next(), authorizations.next()) {
        (Some(value), None) if canonical_bearer(value.as_bytes()) => {
            Zeroizing::new(value.as_bytes().to_vec())
        }
        _ => return Err(StatusCode::UNAUTHORIZED),
    };
    for name in ["authorization", "proxy-authorization", "cookie"] {
        request.headers_mut().remove(name);
    }
    let mut header_bytes = 0_usize;
    for (name, value) in request.headers() {
        header_bytes = header_bytes
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or(StatusCode::BAD_REQUEST)?;
        if name.as_str().len() > CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
            || value.as_bytes().len() > CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
            || header_bytes > CREDENTIAL_BRIDGE_MAX_HEADER_BYTES
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    // HTTP/2 puts :scheme and :authority in Uri. Normalize only after exact
    // ingress validation; the shared bridge retains its anti-proxy contract.
    *request.uri_mut() = Uri::from_static("/v1/responses");
    Ok((request, workspace))
}

fn check_host(headers: &HeaderMap, authority: &str, required: bool) -> Result<(), StatusCode> {
    let mut hosts = headers.get_all("host").iter();
    match (hosts.next(), hosts.next()) {
        (None, None) if !required => Ok(()),
        (Some(value), None)
            if value
                .to_str()
                .is_ok_and(|value| value.eq_ignore_ascii_case(authority)) =>
        {
            Ok(())
        }
        _ => Err(StatusCode::FORBIDDEN),
    }
}

fn canonical_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_bearer(bytes: &[u8]) -> bool {
    bytes.strip_prefix(b"Bearer ").is_some_and(canonical_token)
}

fn credential_metadata(
    gateway: &str,
    workspace: &[u8],
) -> Result<tonic::metadata::MetadataMap, StatusCode> {
    let authorization = Zeroizing::new(format!("Bearer {gateway}"));
    let mut gateway_value = MetadataValue::try_from(authorization.as_str())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    gateway_value.set_sensitive(true);
    let mut workspace_value = MetadataValue::from_bytes(workspace);
    workspace_value.set_sensitive(true);
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", gateway_value);
    metadata.insert_bin(WORKSPACE_AUTHORIZATION, workspace_value);
    Ok(metadata)
}

async fn read_gateway_token(path: &std::path::Path) -> Result<Zeroizing<String>, StatusCode> {
    // Kubernetes atomically rotates a projected volume using symlinks. The
    // configured path is trusted; every fresh RPC rereads its current target.
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // A raced FIFO must not strand a blocking file-open operation after the
    // request's admission deadline or owner cancellation. Projected symlinks
    // remain supported; validate the opened object, not a pathname precheck.
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut token = Zeroizing::new(String::with_capacity(2048));
    file.take((MAX_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut token)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !canonical_token(token.as_bytes()) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(token)
}

fn fixed_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
pub(crate) mod tls_test_support;
