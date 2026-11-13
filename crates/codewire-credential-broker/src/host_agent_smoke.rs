//! Test-only HTTP adapter for actual host agent CLIs over the protected broker.
//!
//! This fixture owns process-lifetime synthetic credentials. It has no login,
//! enrollment, protected-store RPC, live upstream, or product listener. The
//! ready record goes only to an inherited private pipe, never a terminal log.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{self, Read as _, Write as _};
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot,
    CredentialAuthKind, EnvironmentAccessBinding, EnvironmentId, GrantPermission, ProviderCatalog,
    ProviderDefinition, ProviderId,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_local_credentials::{
    CredentialOperationLease, CredentialOperationLeaseRequest, LocalCredentialAuthority,
    NewCredential,
};
use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
use futures::{StreamExt as _, stream};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rand::RngCore as _;
use serde_json::json;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    BrokerCredentialRefreshRequest, BrokerHttpResponse, BrokerLeaseError, BrokerLeaseProvider,
    BrokerRefreshAdmission, BrokerRefreshError, CanonicalCodexOAuthBundle, OpenAiBroker,
    SyntheticOpenAiSmokeTransport,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 32;
const MAX_CONNECTIONS: usize = 16;
const HEADER_DEADLINE: Duration = Duration::from_secs(10);
const BODY_DEADLINE: Duration = Duration::from_secs(15);
const PREPARE_DEADLINE: Duration = Duration::from_secs(15);
// Existing synthetic update holds last at most600s. Include a bounded margin.
const STREAM_DEADLINE: Duration = Duration::from_secs(660);
const RUN_DEADLINE: Duration = Duration::from_secs(1800);
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const ACCOUNT: &str = "account-native-broker";

/// Fixed diagnostics; no raw request, provider, protected-store or parser source.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HostAgentSmokeError {
    #[error("host-agent fixture inputs are invalid")]
    InvalidInput,
    #[error("host-agent fixture startup failed")]
    Startup,
    #[error("host-agent fixture private control failed")]
    Control,
    #[error("host-agent fixture lifetime expired")]
    Expired,
    #[error("host-agent fixture shutdown did not drain")]
    Drain,
}

type HttpBody = UnsyncBoxBody<Bytes, io::Error>;
type Broker = OpenAiBroker<SmokeAuthority, SyntheticOpenAiSmokeTransport>;

#[derive(Clone)]
struct SmokeAuthority {
    authority: Arc<LocalCredentialAuthority<EphemeralProtectedStore>>,
    environment_id: EnvironmentId,
    #[cfg(test)]
    leases: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerLeaseProvider for SmokeAuthority {
    type Lease = CredentialOperationLease;
    type RefreshReservation = ();
    type StartedRefresh = ();

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        if request_id.is_nil()
            || !matches!(
                (capability_slot.as_str(), operation.as_str(), route.as_str()),
                ("codex", "responses", "openai-api") | ("anthropic", "messages", "anthropic-api")
            )
        {
            return Err(BrokerLeaseError::Denied);
        }
        let lease = self
            .authority
            .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
                environment_id: self.environment_id.clone(),
                environment_generation: 1,
                capability_slot,
                operation,
                route,
            })
            .map_err(|_| BrokerLeaseError::Denied)?;
        #[cfg(test)]
        self.leases.fetch_add(1, Ordering::Relaxed);
        Ok(lease)
    }

    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }
    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }
    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }
    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }
    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
    // Direct Codex and Claude logins, SSH, projections and GitHub refresh
    // retain the trait's denied defaults. No HTTP endpoint can invoke those operations.
}

struct State {
    broker: Broker,
    capability: Zeroizing<String>,
    host: String,
    cancel: CancellationToken,
    #[cfg(test)]
    authority: SmokeAuthority,
    #[cfg(test)]
    leases: Arc<AtomicUsize>,
    connections: AtomicUsize,
}

struct Server {
    listener: TcpListener,
    state: Arc<State>,
}

fn random_hex<const N: usize>() -> Result<Zeroizing<String>, HostAgentSmokeError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| HostAgentSmokeError::Startup)?;
    Ok(Zeroizing::new(
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    ))
}

fn jwt(value: serde_json::Value) -> String {
    let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.synthetic-signature",
        encoding.encode(br#"{"alg":"none"}"#),
        encoding.encode(value.to_string())
    )
}

fn codex_material(access: &str) -> Result<CanonicalCodexOAuthBundle, HostAgentSmokeError> {
    crate::import_codex_tokens(
        Zeroizing::new(jwt(json!({"email":"host-fixture@example.test",
            "https://api.openai.com/auth":{"chatgpt_account_id":ACCOUNT,
                "chatgpt_account_is_fedramp":false}}))),
        Zeroizing::new(access.to_owned()),
        Zeroizing::new("synthetic-host-fixture-refresh".to_owned()),
    )
    .map(|import| import.into_parts().0)
    .map_err(|_| HostAgentSmokeError::Startup)
}

fn catalog() -> Result<ProviderCatalog, HostAgentSmokeError> {
    ProviderCatalog::from_definitions(
        [
            (
                "openai",
                CredentialAuthKind::OAuth,
                "codex",
                "openai-api",
                vec!["responses"],
            ),
            (
                "anthropic",
                CredentialAuthKind::ApiKey,
                "anthropic",
                "anthropic-api",
                vec!["messages"],
            ),
        ]
        .into_iter()
        .map(
            |(provider, kind, slot, route, operations)| ProviderDefinition {
                id: ProviderId::parse(provider).expect("fixed provider"),
                authentication_kinds: BTreeSet::from([kind]),
                capabilities: BTreeMap::from([(
                    CapabilitySlot::parse(slot).expect("fixed slot"),
                    CapabilityPolicy {
                        authentication_kinds: BTreeSet::from([kind]),
                        permissions: operations
                            .into_iter()
                            .map(|operation| GrantPermission {
                                operation: BrokerOperationId::parse(operation)
                                    .expect("fixed operation"),
                                route: BrokerRouteId::parse(route).expect("fixed route"),
                            })
                            .collect(),
                    },
                )]),
            },
        ),
    )
    .map_err(|_| HostAgentSmokeError::Startup)
}

fn admit_root(root: &Path) -> Result<(), HostAgentSmokeError> {
    let metadata =
        std::fs::symlink_metadata(root).map_err(|_| HostAgentSmokeError::InvalidInput)?;
    if !root.is_absolute()
        || std::fs::canonicalize(root).map_err(|_| HostAgentSmokeError::InvalidInput)? != root
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || std::fs::read_dir(root)
            .map_err(|_| HostAgentSmokeError::InvalidInput)?
            .next()
            .is_some()
    {
        return Err(HostAgentSmokeError::InvalidInput);
    }
    Ok(())
}

impl Server {
    async fn create(root: &Path, environment: &str) -> Result<Self, HostAgentSmokeError> {
        let id = Uuid::parse_str(environment).map_err(|_| HostAgentSmokeError::InvalidInput)?;
        if id.is_nil() || id.to_string() != environment {
            return Err(HostAgentSmokeError::InvalidInput);
        }
        admit_root(root)?;
        let authority = Arc::new(
            LocalCredentialAuthority::open(root, EphemeralProtectedStore::default(), catalog()?)
                .map_err(|_| HostAgentSmokeError::Startup)?,
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HostAgentSmokeError::Startup)?
            .as_secs();
        let canary = Zeroizing::new(format!("cwlocalbroker{}", random_hex::<16>()?.as_str()));
        let oauth = codex_material(&canary)?;
        let codex = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").expect("fixed provider"),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "host-fixture-codex".into(),
                    account_hint: Some("host-fixture@example.test".into()),
                    expires_at_unix: Some(now + 3600),
                },
                ProtectedValue::from_slice(oauth.as_bytes())
                    .map_err(|_| HostAgentSmokeError::Startup)?,
            )
            .map_err(|_| HostAgentSmokeError::Startup)?;
        let anthropic_canary =
            Zeroizing::new(format!("cwlocalanthropic{}", random_hex::<16>()?.as_str()));
        let anthropic = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("anthropic").expect("fixed provider"),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "host-fixture-anthropic".into(),
                    account_hint: None,
                    expires_at_unix: Some(now + 3600),
                },
                ProtectedValue::from_slice(anthropic_canary.as_bytes())
                    .map_err(|_| HostAgentSmokeError::Startup)?,
            )
            .map_err(|_| HostAgentSmokeError::Startup)?;
        let profile = authority
            .create_profile(
                AccessProfileName::parse("host-fixture").expect("fixed name"),
                BTreeMap::from([
                    (CapabilitySlot::codex(), codex.metadata.id),
                    (CapabilitySlot::anthropic(), anthropic.metadata.id),
                ]),
            )
            .map_err(|_| HostAgentSmokeError::Startup)?;
        let environment_id =
            EnvironmentId::parse(environment).map_err(|_| HostAgentSmokeError::InvalidInput)?;
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .map_err(|_| HostAgentSmokeError::Startup)?;
        #[cfg(test)]
        let leases = Arc::new(AtomicUsize::new(0));
        let owner = SmokeAuthority {
            authority,
            environment_id,
            #[cfg(test)]
            leases: Arc::clone(&leases),
        };
        let broker = OpenAiBroker::new(owner.clone(), SyntheticOpenAiSmokeTransport)
            .map_err(|_| HostAgentSmokeError::Startup)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| HostAgentSmokeError::Startup)?;
        let host = listener
            .local_addr()
            .map_err(|_| HostAgentSmokeError::Startup)?
            .to_string();
        Ok(Self {
            listener,
            state: Arc::new(State {
                broker,
                capability: Zeroizing::new(format!("cwhm_{}", random_hex::<32>()?.as_str())),
                host,
                cancel: CancellationToken::new(),
                #[cfg(test)]
                authority: owner,
                #[cfg(test)]
                leases,
                connections: AtomicUsize::new(0),
            }),
        })
    }

    async fn serve(
        self,
        shutdown: impl Future<Output = Result<(), HostAgentSmokeError>>,
    ) -> Result<(), HostAgentSmokeError> {
        tokio::pin!(shutdown);
        let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        let lifetime = tokio::time::sleep(RUN_DEADLINE);
        tokio::pin!(lifetime);
        let result = loop {
            tokio::select! {
                result = &mut shutdown => break result,
                () = &mut lifetime => break Err(HostAgentSmokeError::Expired),
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.listener.accept() => {
                    let (socket, address) = match accepted {
                        Ok(connection) => connection,
                        Err(_) => break Err(HostAgentSmokeError::Startup),
                    };
                    if !address.ip().is_loopback() { continue; }
                    let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                        drop(socket);
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _connection = ConnectionCount::new(Arc::clone(&state));
                        let cancel = state.cancel.clone();
                        let service = service_fn(move |request| handle(Arc::clone(&state), request));
                        let mut builder = http1::Builder::new();
                        builder.keep_alive(false).max_headers(MAX_HEADERS)
                            .max_buf_size(MAX_HEADER_BYTES).timer(TokioTimer::new())
                            .header_read_timeout(HEADER_DEADLINE);
                        let connection = builder.serve_connection(TokioIo::new(socket), service);
                        tokio::select! {
                            _ = cancel.cancelled() => {},
                            _ = connection => {},
                        }
                    });
                }
            }
        };
        self.state.cancel.cancel();
        drop(self.listener);
        if timeout(DRAIN_DEADLINE, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            return Err(HostAgentSmokeError::Drain);
        }
        result
    }
}

struct ConnectionCount(Arc<State>);
impl ConnectionCount {
    fn new(state: Arc<State>) -> Self {
        state.connections.fetch_add(1, Ordering::SeqCst);
        Self(state)
    }
}
impl Drop for ConnectionCount {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The fixture's own capability bearer selects nothing; the path does. Like
/// the product ingress, each provider family is transparent below its base.
fn closed_route<B>(
    state: &State,
    request: &Request<B>,
) -> Result<(&'static str, String), StatusCode> {
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.headers().len() > MAX_HEADERS
        || request
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > MAX_HEADER_BYTES
        || request.headers().contains_key("origin")
        || request.headers().contains_key("upgrade")
        || request.headers().contains_key("proxy-authorization")
        || request.headers().contains_key("cookie")
        || request.headers().contains_key("x-api-key")
        || request.headers().get_all("host").iter().count() != 1
        || request.headers().get("host").map(|v| v.as_bytes()) != Some(state.host.as_bytes())
        || request.headers().get_all("authorization").iter().count() != 1
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let authorization = request
        .headers()
        .get("authorization")
        .expect("count checked")
        .as_bytes();
    let expected = Zeroizing::new(format!("Bearer {}", state.capability.as_str()));
    if authorization.len() != expected.len()
        || !bool::from(authorization.ct_eq(expected.as_bytes()))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let path = request.uri().path();
    let (slot, provider_path) = if let Some(rest) = path.strip_prefix("/codex/v1/") {
        ("codex", rest)
    } else if let Some(rest) = path.strip_prefix("/anthropic/") {
        ("anthropic", rest)
    } else {
        return Err(StatusCode::FORBIDDEN);
    };
    Ok((slot, format!("/{provider_path}")))
}

fn fixed_response(status: StatusCode) -> Response<HttpBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from_static(
                br#"{"error":"host_fixture_request_refused"}"#,
            ))
            .map_err(|never| match never {})
            .boxed_unsync(),
        )
        .expect("fixed response")
}

async fn handle(
    state: Arc<State>,
    request: Request<Incoming>,
) -> Result<Response<HttpBody>, std::convert::Infallible> {
    let (slot, path) = match closed_route(&state, &request) {
        Ok(route) => route,
        Err(status) => return Ok(fixed_response(status)),
    };
    let (parts, incoming) = request.into_parts();
    let limit = codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES;
    if incoming
        .size_hint()
        .upper()
        .is_some_and(|size| size > limit as u64)
    {
        return Ok(fixed_response(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let bytes = match timeout(BODY_DEADLINE, Limited::new(incoming, limit).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        _ => return Ok(fixed_response(StatusCode::PAYLOAD_TOO_LARGE)),
    };
    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "authorization" | "host" | "connection" | "content-length" | "transfer-encoding"
            )
        })
        .map(|(name, value)| v1::CredentialHttpHeader {
            name: name.as_str().into(),
            value: value.as_bytes().to_vec(),
        })
        .collect();
    let request = v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        method: parts.method.as_str().into(),
        path,
        query: parts.uri.query().unwrap_or_default().into(),
        headers,
        body: bytes.to_vec(),
        capability_slot: slot.into(),
        route: if slot == "codex" {
            "openai-api"
        } else {
            "anthropic-api"
        }
        .into(),
        intercepted_host: String::new(),
        streamed_body: false,
    };
    let response = match timeout(PREPARE_DEADLINE, state.broker.execute(request)).await {
        Ok(Ok(response)) => response,
        _ => return Ok(fixed_response(StatusCode::BAD_GATEWAY)),
    };
    Ok(stream_response(response, state.cancel.clone()))
}

fn stream_response(response: BrokerHttpResponse, cancel: CancellationToken) -> Response<HttpBody> {
    let (status, headers, body) = response.into_parts();
    let deadline = Instant::now() + STREAM_DEADLINE;
    let chunks = stream::unfold(
        (body, cancel, 0usize, false),
        move |(mut body, cancel, bytes, finished)| async move {
            if finished {
                return None;
            }
            let next = tokio::select! {
                () = cancel.cancelled() => Err(io::Error::other("host fixture stream cancelled")),
                item = timeout_at(deadline, body.next()) => match item {
                    Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
                    Ok(None) => Ok(None),
                    _ => Err(io::Error::other("host fixture stream failed")),
                },
            };
            match next {
                Ok(None) => None,
                Ok(Some(chunk)) => match bytes
                    .checked_add(chunk.len())
                    .filter(|n| *n <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES)
                {
                    Some(total) => Some((Ok(Frame::data(chunk)), (body, cancel, total, false))),
                    None => Some((
                        Err(io::Error::other("host fixture stream exceeded limit")),
                        (body, cancel, bytes, true),
                    )),
                },
                Err(error) => Some((Err(error), (body, cancel, bytes, true))),
            }
        },
    );
    let mut result = Response::new(StreamBody::new(chunks).boxed_unsync());
    *result.status_mut() = status;
    *result.headers_mut() = headers;
    result
}

fn private_pipe(fd: impl std::os::fd::AsFd) -> Result<AsyncFd<std::fs::File>, HostAgentSmokeError> {
    let owned = rustix::io::fcntl_dupfd_cloexec(fd, 3).map_err(|_| HostAgentSmokeError::Control)?;
    let file = std::fs::File::from(owned);
    let metadata = file.metadata().map_err(|_| HostAgentSmokeError::Control)?;
    if rustix::fs::FileType::from_raw_mode(metadata.mode()) != rustix::fs::FileType::Fifo
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(HostAgentSmokeError::Control);
    }
    let flags = rustix::fs::fcntl_getfl(&file).map_err(|_| HostAgentSmokeError::Control)?;
    rustix::fs::fcntl_setfl(&file, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| HostAgentSmokeError::Control)?;
    // RUSTSEC-2026-0386: an owned `File` is outside `AsyncFd::new`'s unsound case; `register` migration is #3249.
    #[allow(deprecated)]
    let registered = AsyncFd::new(file);
    registered.map_err(|_| HostAgentSmokeError::Control)
}

async fn write_ready(
    output: &AsyncFd<std::fs::File>,
    bytes: &[u8],
) -> Result<(), HostAgentSmokeError> {
    if bytes.len() > 2048 {
        return Err(HostAgentSmokeError::Control);
    }
    let write = async {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let mut ready = output
                .writable()
                .await
                .map_err(|_| HostAgentSmokeError::Control)?;
            match ready.try_io(|descriptor| {
                let mut file = descriptor.get_ref();
                file.write(remaining)
            }) {
                Ok(Ok(0)) | Ok(Err(_)) => return Err(HostAgentSmokeError::Control),
                Ok(Ok(count)) => remaining = &remaining[count..],
                Err(_) => continue,
            }
        }
        Ok(())
    };
    timeout(Duration::from_secs(10), write)
        .await
        .map_err(|_| HostAgentSmokeError::Control)?
}

async fn read_shutdown(input: &AsyncFd<std::fs::File>) -> Result<(), HostAgentSmokeError> {
    let mut control = [0u8; 5];
    let mut used = 0;
    loop {
        let mut ready = input
            .readable()
            .await
            .map_err(|_| HostAgentSmokeError::Control)?;
        match ready.try_io(|descriptor| {
            let mut file = descriptor.get_ref();
            file.read(&mut control[used..])
        }) {
            Ok(Ok(0)) if used == 0 => return Ok(()),
            Ok(Ok(0)) | Ok(Err(_)) => return Err(HostAgentSmokeError::Control),
            Ok(Ok(count)) => {
                used += count;
                if used == control.len() {
                    return if control == *b"STOP\n" {
                        Ok(())
                    } else {
                        Err(HostAgentSmokeError::Control)
                    };
                }
            }
            Err(_) => continue,
        }
    }
}

/// Run the closed fixture. The caller must privately pipe stdout/stdin and
/// supply a fresh owned0700 root; the ready capability must never be logged.
pub async fn run(root: &Path, environment: &str) -> Result<(), HostAgentSmokeError> {
    // Blocking Tokio stdin can outlive a cancelled future and prevent runtime
    // shutdown while a controller holds an incomplete command. Kernel pipes
    // are duplicated CLOEXEC and polled without a detached blocking task.
    let input = private_pipe(std::io::stdin())?;
    let output = private_pipe(std::io::stdout())?;
    let server = Server::create(root, environment).await?;
    let ready = Zeroizing::new(
        json!({
            "schema":"codewire.host-agent-smoke/v1", "environment_id":environment,
            "codex_base_url":format!("http://{}/codex/v1",server.state.host),
            "anthropic_base_url":format!("http://{}/anthropic",server.state.host),
            "capability":server.state.capability.as_str(),
            "upstream":"synthetic", "protected_store":"process_lifetime"
        })
        .to_string()
            + "\n",
    );
    write_ready(&output, ready.as_bytes()).await?;
    server.serve(read_shutdown(&input)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    struct Fixture {
        root: tempfile::TempDir,
        state: Arc<State>,
        address: SocketAddr,
        stop: CancellationToken,
        task: tokio::task::JoinHandle<Result<(), HostAgentSmokeError>>,
    }
    impl Fixture {
        async fn start() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let authority = root.path().join("authority");
            std::fs::create_dir(&authority).unwrap();
            std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700)).unwrap();
            let server = Server::create(&authority, &Uuid::new_v4().to_string())
                .await
                .unwrap();
            let state = Arc::clone(&server.state);
            let address = server.listener.local_addr().unwrap();
            let stop = CancellationToken::new();
            let signal = stop.clone();
            let task = tokio::spawn(server.serve(async move {
                signal.cancelled().await;
                Ok(())
            }));
            Self {
                root,
                state,
                address,
                stop,
                task,
            }
        }
        async fn request(&self, path: &str, headers: &str, body: &[u8]) -> Vec<u8> {
            let mut stream = TcpStream::connect(self.address).await.unwrap();
            let start = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n",
                self.state.host,
                self.state.capability.as_str(),
                body.len()
            );
            stream.write_all(start.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut output = Vec::new();
            timeout(Duration::from_secs(5), stream.read_to_end(&mut output))
                .await
                .unwrap()
                .unwrap();
            output
        }
        async fn finish(self) {
            self.stop.cancel();
            assert_eq!(self.task.await.unwrap(), Ok(()));
            assert_eq!(self.state.connections.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn codex_uses_real_authority_lease_and_redacts_headers_and_stream_chunks() {
        let fixture = Fixture::start().await;
        let output = fixture
            .request("/codex/v1/responses", "", br#"{"input":"hello"}"#)
            .await;
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("CWCODEX149 broker [REDACTED]"));
        assert!(!text.contains("cwlocalbroker"));
        assert!(!text.contains("cwhm_"));
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 1);
        let database = std::fs::read(fixture.root.path().join("authority/credentials.db")).unwrap();
        assert!(
            !database
                .windows(b"cwlocalbroker".len())
                .any(|b| b == b"cwlocalbroker")
        );
        fixture.finish().await;
    }

    #[tokio::test]
    async fn claude_messages_and_count_tokens_use_same_protected_selected_slot() {
        let fixture = Fixture::start().await;
        for path in [
            "/anthropic/v1/messages",
            "/anthropic/v1/messages?beta=true",
            "/anthropic/v1/messages/count_tokens?beta=true",
        ] {
            let body: &[u8] = if path.contains("count_tokens") {
                br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#
            } else {
                br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"max_tokens":32,"stream":true}"#
            };
            let output = fixture
                .request(path, "anthropic-version: 2023-06-01\r\n", body)
                .await;
            let text = String::from_utf8(output).unwrap();
            assert!(
                text.starts_with("HTTP/1.1 200"),
                "filtered response was refused"
            );
            assert!(!text.contains("cwlocalanthropic"));
        }
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 3);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn route_origin_and_duplicate_auth_are_denied_before_lease() {
        let fixture = Fixture::start().await;
        for (path, extra) in [
            ("/v1/responses", ""),
            ("/openai/v1/responses", ""),
            ("/codex/v1/responses", "Origin: http://example.test\r\n"),
            ("/codex/v1/responses", "Authorization: Bearer wrong\r\n"),
            ("/codex/v1/responses", "X-Api-Key: wrong\r\n"),
            ("/codex/v1/responses", "Cookie: caller=value\r\n"),
            ("http://example.test/codex/v1/responses", ""),
        ] {
            let output = fixture.request(path, extra, br#"{"input":"hello"}"#).await;
            assert!(output.starts_with(b"HTTP/1.1 403"));
        }
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 0);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn wrong_capability_and_host_cannot_select_provider_material() {
        let fixture = Fixture::start().await;
        for (host, capability) in [
            (fixture.state.host.as_str(), "cwhm_wrong"),
            ("example.test", fixture.state.capability.as_str()),
        ] {
            let mut socket = TcpStream::connect(fixture.address).await.unwrap();
            let request = format!(
                "POST /codex/v1/responses HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {capability}\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut output = Vec::new();
            socket.read_to_end(&mut output).await.unwrap();
            assert!(output.starts_with(b"HTTP/1.1 401") || output.starts_with(b"HTTP/1.1 403"));
        }
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 0);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn oversize_request_is_refused_without_a_material_lease() {
        let fixture = Fixture::start().await;
        let mut socket = TcpStream::connect(fixture.address).await.unwrap();
        let request = format!(
            "POST /codex/v1/responses HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
            fixture.state.host,
            fixture.state.capability.as_str(),
            codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1
        );
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut output = Vec::new();
        socket.read_to_end(&mut output).await.unwrap();
        assert!(output.starts_with(b"HTTP/1.1 413"));
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 0);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn fixed_capability_has_no_login_ssh_projection_or_refresh_surface() {
        let fixture = Fixture::start().await;
        let leases = &fixture.state.authority;
        assert!(matches!(
            leases.lease_codex_login(Uuid::new_v4()).await,
            Err(BrokerLeaseError::Denied)
        ));
        assert!(matches!(
            leases.lease_claude_login(Uuid::new_v4()).await,
            Err(BrokerLeaseError::Denied)
        ));
        assert!(matches!(
            leases
                .ssh_operation(Default::default(), CancellationToken::new())
                .await,
            Err(BrokerLeaseError::Denied)
        ));
        assert!(matches!(
            leases.project_environment(Default::default()).await,
            Err(BrokerLeaseError::Denied)
        ));
        assert!(matches!(
            leases.start_credential_refresh(()).await,
            Err(BrokerRefreshError::Denied)
        ));
        assert!(matches!(
            leases.abort_credential_refresh(()).await,
            Err(BrokerRefreshError::Denied)
        ));
        assert!(matches!(
            leases.fail_credential_refresh(()).await,
            Err(BrokerRefreshError::Denied)
        ));
        assert!(matches!(
            leases
                .lease_operation(
                    Uuid::new_v4(),
                    CapabilitySlot::github(),
                    BrokerOperationId::parse("rest").unwrap(),
                    BrokerRouteId::parse("github-api").unwrap()
                )
                .await,
            Err(BrokerLeaseError::Denied)
        ));
        fixture.finish().await;
    }

    #[tokio::test]
    async fn shutdown_drops_unpolled_partial_requests_and_joins_owned_connections() {
        let fixture = Fixture::start().await;
        let mut sockets = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut socket = TcpStream::connect(fixture.address).await.unwrap();
            socket.write_all(b"POST /").await.unwrap();
            sockets.push(socket);
        }
        timeout(Duration::from_secs(2), async {
            while fixture.state.connections.load(Ordering::SeqCst) != MAX_CONNECTIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut rejected = TcpStream::connect(fixture.address).await.unwrap();
        let mut bytes = [0; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), rejected.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(fixture.state.leases.load(Ordering::Relaxed), 0);
        fixture.stop.cancel();
        assert_eq!(fixture.task.await.unwrap(), Ok(()));
        assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 0);
        for mut socket in sockets {
            assert_eq!(socket.read(&mut bytes).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn startup_refuses_reuse_links_permissions_and_noncanonical_uuid() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for id in [
            Uuid::nil().to_string(),
            Uuid::new_v4().simple().to_string(),
            "wrong".into(),
        ] {
            assert!(matches!(
                Server::create(root.path(), &id).await,
                Err(HostAgentSmokeError::InvalidInput)
            ));
        }
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Server::create(root.path(), &Uuid::new_v4().to_string()).await,
            Err(HostAgentSmokeError::InvalidInput)
        ));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.path().join("unrelated"), b"preserve").unwrap();
        assert!(matches!(
            Server::create(root.path(), &Uuid::new_v4().to_string()).await,
            Err(HostAgentSmokeError::InvalidInput)
        ));
        assert_eq!(
            std::fs::read(root.path().join("unrelated")).unwrap(),
            b"preserve"
        );
    }

    #[tokio::test]
    async fn cancel_after_response_start_fails_stream_without_successful_eof() {
        let cancel = CancellationToken::new();
        let source = stream::pending();
        let response =
            BrokerHttpResponse::new(StatusCode::OK, Default::default(), Box::pin(source));
        let mut response = stream_response(response, cancel.clone());
        cancel.cancel();
        assert!(response.body_mut().frame().await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_deadline_is_absolute_and_does_not_reissue_a_request() {
        let response = BrokerHttpResponse::new(
            StatusCode::OK,
            Default::default(),
            Box::pin(stream::pending()),
        );
        let mut response = stream_response(response, CancellationToken::new());
        tokio::time::advance(STREAM_DEADLINE + Duration::from_secs(1)).await;
        assert!(response.body_mut().frame().await.unwrap().is_err());
        assert!(response.body_mut().frame().await.is_none());
    }

    fn control_pipe() -> (std::fs::File, std::fs::File) {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        (std::fs::File::from(read), std::fs::File::from(write))
    }

    #[tokio::test]
    async fn private_control_pipe_is_cloexec_and_refuses_nonpipe_descriptors() {
        let (input, output) = control_pipe();
        let admitted = private_pipe(&input).unwrap();
        assert_ne!(admitted.get_ref().as_raw_fd(), input.as_raw_fd());
        assert!(
            rustix::io::fcntl_getfd(admitted.get_ref())
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        drop(output);
        assert_eq!(read_shutdown(&admitted).await, Ok(()));
        let regular = tempfile::tempfile().unwrap();
        assert!(matches!(
            private_pipe(regular),
            Err(HostAgentSmokeError::Control)
        ));
    }

    #[tokio::test]
    async fn private_control_requires_exact_shutdown_and_ready_is_bounded() {
        for marker in [b"STOP\n".as_slice(), b"ST", b"OTHER", b"STOPX"] {
            let (input, mut output) = control_pipe();
            let admitted = private_pipe(input).unwrap();
            output.write_all(marker).unwrap();
            drop(output);
            assert_eq!(
                read_shutdown(&admitted).await,
                if marker == b"STOP\n" {
                    Ok(())
                } else {
                    Err(HostAgentSmokeError::Control)
                }
            );
        }
        let (mut input, output) = control_pipe();
        let output = private_pipe(output).unwrap();
        assert_eq!(
            write_ready(&output, &[0; 2049]).await,
            Err(HostAgentSmokeError::Control)
        );
        write_ready(&output, b"owned-ready\n").await.unwrap();
        let mut bytes = [0; 12];
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"owned-ready\n");
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_control_does_not_survive_absolute_lifetime() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let authority = root.path().join("authority");
        std::fs::create_dir(&authority).unwrap();
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700)).unwrap();
        let server = Server::create(&authority, &Uuid::new_v4().to_string())
            .await
            .unwrap();
        let state = Arc::clone(&server.state);
        let (input, mut output) = control_pipe();
        output.write_all(b"ST").unwrap();
        let input = private_pipe(input).unwrap();
        let task = tokio::spawn(async move { server.serve(read_shutdown(&input)).await });
        tokio::task::yield_now().await;
        tokio::time::advance(RUN_DEADLINE + Duration::from_secs(1)).await;
        assert_eq!(task.await.unwrap(), Err(HostAgentSmokeError::Expired));
        assert_eq!(state.connections.load(Ordering::SeqCst), 0);
        assert!(output.write_all(b"OP\n").is_err());
    }
}
