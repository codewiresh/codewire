//! Private generated-service adapter, not a listener or production authenticator.
//!
//! The owner supplies the accepted trusted runtime identity implementation and
//! isolated store/upstream handles. It must call `shutdown` and await it before
//! dropping those dependencies. Dropping a server or runtime is not a promise
//! that provider-side rotation or protected-store publication was drained.
//!
//! The gateway must own both halves of each private call and end its outgoing
//! request stream when its response owner is dropped. Dropping only a remote
//! tonic response half need not send HTTP/2 cancellation while outgoing DATA
//! remains possible. The server observes input EOF/error or its own response
//! body being dropped, not an uncommunicated remote loss of interest; the
//! original authenticated expiry and owner shutdown still bound that epoch.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_gateway_proto::broker::v1::credential_broker_service_server::{
    CredentialBrokerService, CredentialBrokerServiceServer,
};
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformCredentialStore};
use futures::{Stream, StreamExt, stream::BoxStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status, Streaming, metadata::MetadataMap};
use uuid::Uuid;

use super::{
    LeaseBudget, PlatformBrokerLeaseProvider, PlatformRuntimeAuthority, PlatformRuntimeError,
};
use crate::timing::{self, Phase};
use crate::{
    AdmittedCredentialBridge, BrokerBridgeError, BrokerLeaseError, BrokerUpstreamTransport,
    CredentialBridgeResponseSink, CredentialBridgeTransport, GitHubAppAuthorizationOwner,
    OpenAiBroker, admit_credential_bridge, run_admitted_credential_bridge,
};

/// Admission and active/draining epochs share one process-wide service budget.
/// Each hosted Sandbox with credentials holds one long-lived epoch (two while
/// its gateway rotates), so this is the replica's Sandbox ceiling. An idle
/// epoch is one TLS connection and its tasks; its response buffer is bounded.
pub const PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS: usize = 1024;
/// Concurrent leases across all epochs: authority checks, grant and record
/// reads and the protected-material read (SQL and KEK unwrap). A lease runs
/// its statements one at a time, so it holds at most one of the credential
/// service's 16 pool connections and none during its Kubernetes reads or the
/// unwrap. Sixty-four leases queue at most four per connection for a few
/// statement times, far inside the pool's 5-second acquire timeout, whose
/// expiry would end the epoch, and bound Kubernetes and OpenBao concurrency.
pub const PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES: usize = 64;
/// Optional operations this broker serves, listed in the admitted stream's
/// response headers. The gateway copies them into the daemon's Open, and the
/// daemon sends an optional operation only when listed, so an older broker or
/// gateway is never sent a frame that would end its epoch.
pub const PLATFORM_CREDENTIAL_BRIDGE_CAPABILITIES: &[&str] =
    &[codewire_gateway_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN];
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_BUFFER: usize = 32;

/// Closed failures from the trusted process-local identity boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformBridgeAuthenticationError {
    #[error("platform credential bridge authentication is required")]
    Unauthenticated,
    #[error("platform credential bridge authority denied the session")]
    Denied,
    #[error("platform credential bridge authority is unavailable")]
    Unavailable,
}

impl PlatformBridgeAuthenticationError {
    fn status(self) -> Status {
        match self {
            Self::Unauthenticated => Status::unauthenticated(self.to_string()),
            Self::Denied => Status::permission_denied(self.to_string()),
            Self::Unavailable => Status::unavailable(self.to_string()),
        }
    }
}

/// Trusted process-local authentication, never a deserializer of guest scope.
///
/// Authenticate the exact gateway and forwarded workspace identities under the
/// accepted TLS/audience policy. The returned authority must retain those exact
/// presented identities and original verified expiries, and revalidate current
/// Pod/environment/owner/policy state on every session call. Token rotation must
/// not silently substitute a different identity or extend this connection.
/// Discard raw parser/Kubernetes/SQL errors and never log metadata or tokens.
#[async_trait]
pub trait PlatformBridgeAuthenticator: Send + Sync {
    type Authority: PlatformRuntimeAuthority + 'static;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Arc<Self::Authority>, PlatformBridgeAuthenticationError>;
}

struct ServiceState<A, U> {
    authenticator: Arc<A>,
    credentials: Arc<PlatformCredentialStore>,
    profiles: PlatformAccessProfileStore,
    upstream: U,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    permits: Arc<Semaphore>,
    stream_capacity: usize,
    leases: LeaseBudget,
    accepting: Arc<Mutex<bool>>,
    workers: TaskTracker,
    shutdown: CancellationToken,
    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    ssh: Option<Arc<super::ssh::Service>>,
}

/// One isolated broker service owner. Clones share admission limits, shutdown
/// and tracked workers; constructing another instance creates another budget.
pub struct PlatformCredentialBridgeService<A, U> {
    state: Arc<ServiceState<A, U>>,
}

impl<A, U> Clone for PlatformCredentialBridgeService<A, U> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<A, U> PlatformCredentialBridgeService<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    pub fn new(
        authenticator: Arc<A>,
        credentials: Arc<PlatformCredentialStore>,
        profiles: PlatformAccessProfileStore,
        upstream: U,
    ) -> Self {
        Self::with_limits(
            authenticator,
            credentials,
            profiles,
            upstream,
            PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS,
            PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES,
        )
    }

    /// The production limits come only from [`Self::new`]; tests use this
    /// seam to reach a full budget without opening a thousand streams.
    fn with_limits(
        authenticator: Arc<A>,
        credentials: Arc<PlatformCredentialStore>,
        profiles: PlatformAccessProfileStore,
        upstream: U,
        streams: usize,
        leases: usize,
    ) -> Self {
        Self {
            state: Arc::new(ServiceState {
                authenticator,
                credentials,
                profiles,
                upstream,
                github_app_authorization: None,
                permits: Arc::new(Semaphore::new(streams)),
                stream_capacity: streams,
                leases: LeaseBudget::new(leases),
                accepting: Arc::new(Mutex::new(true)),
                workers: TaskTracker::new(),
                shutdown: CancellationToken::new(),
                #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
                ssh: None,
            }),
        }
    }

    /// Explicit trusted process composition only, before cloning or serving.
    /// No executable lookup or catalog activation is inferred by this seam.
    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    pub fn with_ssh_agent_owner(
        mut self,
        owner: Arc<crate::ssh_agent::SshAgentOwner>,
    ) -> Result<Self, PlatformRuntimeError> {
        let state = Arc::get_mut(&mut self.state).ok_or(PlatformRuntimeError::Denied)?;
        if state.ssh.is_some() || state.shutdown.is_cancelled() {
            return Err(PlatformRuntimeError::Denied);
        }
        state.ssh = Some(super::ssh::Service::new(
            owner,
            state.accepting.clone(),
            state.workers.clone(),
            state.shutdown.clone(),
        ));
        Ok(self)
    }

    /// Private credential-service composition for the finite GitHub App
    /// refresh authority. No bridge frame, guest request, or profile-selected
    /// route can install or select this owner.
    pub fn with_github_app_authorization_owner(
        mut self,
        owner: Arc<GitHubAppAuthorizationOwner>,
    ) -> Result<Self, PlatformRuntimeError> {
        let state = Arc::get_mut(&mut self.state).ok_or(PlatformRuntimeError::Denied)?;
        if state.github_app_authorization.is_some() || state.shutdown.is_cancelled() {
            return Err(PlatformRuntimeError::Denied);
        }
        state.github_app_authorization = Some(owner);
        Ok(self)
    }

    /// Register only this private service, with the existing frame ceilings.
    /// Keep a clone of this owner to signal and await shutdown. This configures
    /// no socket, TLS identity, public route, reflection or daemon service.
    pub fn into_server(self) -> CredentialBrokerServiceServer<Self> {
        CredentialBrokerServiceServer::new(self)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
    }

    /// Admit an already-authenticated transport inside this same service owner.
    /// This is trusted process composition, not authentication of guest scope.
    ///
    /// The lazy future must include first selection-frame consumption and all
    /// authority construction. It is polled only after reserving the existing
    /// stream permit, under the same complete admission timeout as the private
    /// Pod RPC. The supplied authority must retain and recheck its exact original
    /// identity, selection and expiry; no raw identity token belongs in a frame.
    /// The adapter must bound decoding/allocation before yielding typed frames.
    ///
    /// Dropping this future cancels incomplete admission. After success, dropping
    /// the returned receiver signals transport cancellation; the tracked worker
    /// retains its permit until accepted refresh/signing work has drained. Only
    /// awaiting this owner's `shutdown` acknowledges that process-owned drain.
    pub async fn serve_authenticated<B, I, F>(
        &self,
        admission: F,
    ) -> Result<ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>, Status>
    where
        B: PlatformRuntimeAuthority + 'static,
        I: Stream<Item = Result<v1::CredentialBridgeGuestMessage, Status>> + Send + 'static,
        F: Future<Output = Result<(Arc<B>, I), PlatformBridgeAuthenticationError>> + Send,
    {
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let permit = self.acquire()?;
        // The TokenReviews and resolves of authentication, the Ready wait and
        // the recheck after it are all recorded into this one admission line.
        let (admission, timings) = timing::measure(async {
            tokio::select! {
                biased;
                _ = self.state.shutdown.cancelled() => Err(unavailable()),
                result = tokio::time::timeout_at(deadline, async {
                    let (authority, input) = admission.await
                        .map_err(PlatformBridgeAuthenticationError::status)?;
                    self.admit(authority, input.boxed()).await
                }) => {
                    result
                        .map_err(|_| Status::deadline_exceeded("platform credential bridge admission timed out"))
                        .and_then(|admission| admission)
                }
            }
        })
        .await;
        timing::epoch_admission(
            admission_outcome(&admission),
            self.streams_in_use(),
            &timings,
        );
        let Admission {
            broker,
            admitted,
            sink,
            receiver,
        } = admission?;
        sink.epoch.ensure_live().map_err(bridge_status)?;
        self.spawn_worker(permit, async move {
            // Never select cancellation against or abort this future. Transport
            // termination ends request tasks, then the shared runner drains
            // accepted refresh work before this worker releases its stream slot.
            if let Err(error) = run_admitted_credential_bridge(broker, admitted).await {
                let _ = sink.output.try_send(Err(bridge_status(error)));
            }
        })?;
        Ok(ReceiverStream::new(receiver))
    }

    /// Stop admission and signal transport cancellation synchronously. The
    /// runtime must still await `shutdown` before dropping dependencies.
    pub fn start_shutdown(&self) {
        {
            // Even a poisoned registry must close, rather than accept work or
            // skip shutdown. No user callback runs while this mutex is held.
            let mut accepting = self
                .state
                .accepting
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *accepting = false;
            self.state.workers.close();
        }
        // Queued leases fail now; leases already holding a slot finish.
        self.state.leases.close();
        self.state.shutdown.cancel();
    }

    /// Close admission and await every managed stream and blocking refresh.
    /// Safe to call concurrently or repeatedly. No mutex is held across await.
    pub async fn shutdown(&self) -> Result<(), PlatformRuntimeError> {
        self.start_shutdown();
        self.state.workers.wait().await;
        #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
        if let Some(ssh) = &self.state.ssh {
            ssh.shutdown().await?;
        }
        Ok(())
    }

    fn acquire(&self) -> Result<OwnedSemaphorePermit, Status> {
        let accepting = self.state.accepting.lock().map_err(|_| unavailable())?;
        if !*accepting {
            return Err(unavailable());
        }
        Arc::clone(&self.state.permits)
            .try_acquire_owned()
            .map_err(|_| {
                timing::capacity_rejected(
                    "bridge_streams",
                    "epoch",
                    self.state.stream_capacity,
                    self.streams_in_use(),
                );
                Status::resource_exhausted("platform credential bridge capacity reached")
            })
    }

    fn streams_in_use(&self) -> usize {
        self.state
            .stream_capacity
            .saturating_sub(self.state.permits.available_permits())
    }

    fn spawn_worker(
        &self,
        permit: OwnedSemaphorePermit,
        work: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), Status> {
        let accepting = self.state.accepting.lock().map_err(|_| unavailable())?;
        if !*accepting {
            return Err(unavailable());
        }
        // Admission/spawn and shutdown/close are serialized. Dropping this
        // JoinHandle does not abort its owner; the tracker retains the drain.
        drop(self.state.workers.spawn(async move {
            let _permit = permit;
            work.await;
        }));
        Ok(())
    }

    async fn admit<B: PlatformRuntimeAuthority + 'static>(
        &self,
        authority: Arc<B>,
        input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
    ) -> Result<Admission<B, U>, Status> {
        let provider = PlatformBrokerLeaseProvider {
            // Every epoch of this service shares its one lease budget.
            leases: Some(self.state.leases.clone()),
            ..PlatformBrokerLeaseProvider::connect(
                authority,
                Arc::clone(&self.state.credentials),
                self.state.profiles.clone(),
            )
            .await
            .map_err(runtime_status)?
        };
        #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
        let provider = PlatformBrokerLeaseProvider {
            ssh: self.state.ssh.as_ref().map(|ssh| ssh.epoch()),
            ..provider
        };
        let session = &provider.session;
        let environment_id =
            Uuid::parse_str(session.context.environment_id.as_str()).map_err(|_| denied())?;
        let generation = session.context.environment_generation;
        let expiry = session.identity_expires_at_unix;
        let epoch = Epoch {
            shutdown: self.state.shutdown.clone(),
            input_closed: CancellationToken::new(),
            expires_at_unix: expiry,
            deadline: expiry_deadline(expiry)?,
        };
        let (output, receiver) = mpsc::channel(RESPONSE_BUFFER);
        let sink = ResponseSink {
            output,
            epoch: epoch.clone(),
        };
        let transport = GatewayTransport {
            input,
            sink: sink.clone(),
        };
        let admitted = tokio::time::timeout_at(epoch.deadline, async {
            let admitted = timing::timed(
                Phase::Ready,
                admit_credential_bridge(transport, environment_id, generation),
            )
            .await
            .map_err(bridge_status)?;
            // Waiting for Ready cannot substitute another session or carry
            // revoked/stale authority through admission. This reread does not
            // unwrap or lease credential material.
            provider.session().await.map_err(lease_status)?;
            Ok::<_, Status>(admitted)
        })
        .await
        .map_err(|_| denied())??;
        epoch.ensure_live().map_err(bridge_status)?;
        let broker =
            OpenAiBroker::new(provider, self.state.upstream.clone()).map_err(|_| unavailable())?;
        let broker = match &self.state.github_app_authorization {
            Some(owner) => broker.with_github_app_authorization_owner(owner.clone()),
            None => broker,
        };
        Ok(Admission {
            broker,
            admitted,
            sink,
            receiver,
        })
    }
}

struct Admission<A, U> {
    broker: OpenAiBroker<PlatformBrokerLeaseProvider<A>, U>,
    admitted: AdmittedCredentialBridge<GatewayTransport>,
    sink: ResponseSink,
    receiver: mpsc::Receiver<Result<v1::CredentialBridgeHostMessage, Status>>,
}

#[tonic::async_trait]
impl<A, U> CredentialBrokerService for PlatformCredentialBridgeService<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;

    async fn credential_bridge(
        &self,
        request: Request<Streaming<v1::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        self.serve_authenticated(async move {
            let (metadata, _, input) = request.into_parts();
            // Preserve the private Pod path: no frame consumption, domain
            // lookup or material access precedes its existing authenticator.
            let authority = self.state.authenticator.authenticate(&metadata).await?;
            Ok((authority, input))
        })
        .await
        .map(|stream| {
            let mut response = Response::new(stream);
            for capability in PLATFORM_CREDENTIAL_BRIDGE_CAPABILITIES {
                response.metadata_mut().append(
                    codewire_gateway_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                    tonic::metadata::MetadataValue::from_static(capability),
                );
            }
            response
        })
    }
}

#[derive(Clone)]
struct Epoch {
    shutdown: CancellationToken,
    input_closed: CancellationToken,
    expires_at_unix: u64,
    deadline: Instant,
}

impl Epoch {
    fn ensure_live(&self) -> Result<(), BrokerBridgeError> {
        if self.shutdown.is_cancelled()
            || self.input_closed.is_cancelled()
            || Instant::now() >= self.deadline
            || super::unix_now().map_err(|_| BrokerBridgeError::Unavailable)?
                >= self.expires_at_unix
        {
            return Err(BrokerBridgeError::Unavailable);
        }
        Ok(())
    }
}

struct GatewayTransport {
    input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
    sink: ResponseSink,
}

#[derive(Clone)]
struct ResponseSink {
    output: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    epoch: Epoch,
}

#[async_trait]
impl CredentialBridgeTransport for GatewayTransport {
    type ResponseSink = ResponseSink;

    fn response_sink(&self) -> Self::ResponseSink {
        self.sink.clone()
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        self.sink.epoch.ensure_live()?;
        let result = tokio::select! {
            biased;
            _ = self.sink.epoch.shutdown.cancelled() => Err(BrokerBridgeError::Unavailable),
            _ = self.sink.output.closed() => Err(BrokerBridgeError::Unavailable),
            _ = tokio::time::sleep_until(self.sink.epoch.deadline) => Err(BrokerBridgeError::Unavailable),
            result = self.input.next() => result.transpose().map_err(|_| BrokerBridgeError::Unavailable),
        };
        if !matches!(result, Ok(Some(_))) {
            self.sink.epoch.input_closed.cancel();
        }
        result
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for ResponseSink {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError> {
        if matches!(
            payload,
            v1::credential_bridge_host_message::Payload::Open(_)
        ) {
            return Err(BrokerBridgeError::InvalidProtocol);
        }
        self.epoch.ensure_live()?;
        tokio::select! {
            biased;
            _ = self.epoch.shutdown.cancelled() => Err(BrokerBridgeError::Unavailable),
            _ = self.epoch.input_closed.cancelled() => Err(BrokerBridgeError::Unavailable),
            _ = tokio::time::sleep_until(self.epoch.deadline) => Err(BrokerBridgeError::Unavailable),
            result = self.output.send(Ok(v1::CredentialBridgeHostMessage { payload: Some(payload) })) => {
                result.map_err(|_| BrokerBridgeError::Unavailable)
            }
        }
    }
}

fn expiry_deadline(expires_at_unix: u64) -> Result<Instant, Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable())?;
    let remaining = Duration::from_secs(expires_at_unix)
        .checked_sub(now)
        .ok_or_else(denied)?;
    Instant::now().checked_add(remaining).ok_or_else(denied)
}

/// A closed label for one admission's result; status messages are not logged.
fn admission_outcome<T>(result: &Result<T, Status>) -> &'static str {
    match result {
        Ok(_) => "admitted",
        Err(status) => match status.code() {
            tonic::Code::Unauthenticated => "unauthenticated",
            tonic::Code::PermissionDenied => "denied",
            tonic::Code::Unavailable => "unavailable",
            tonic::Code::DeadlineExceeded => "timed_out",
            tonic::Code::InvalidArgument => "invalid_protocol",
            _ => "failed",
        },
    }
}

fn denied() -> Status {
    PlatformBridgeAuthenticationError::Denied.status()
}
fn unavailable() -> Status {
    PlatformBridgeAuthenticationError::Unavailable.status()
}

fn runtime_status(error: PlatformRuntimeError) -> Status {
    match error {
        PlatformRuntimeError::Denied => denied(),
        PlatformRuntimeError::Unavailable => unavailable(),
    }
}

fn lease_status(error: BrokerLeaseError) -> Status {
    match error {
        BrokerLeaseError::Denied
        | BrokerLeaseError::InvalidRequest
        | BrokerLeaseError::ReconnectRequired => denied(),
        BrokerLeaseError::Unavailable | BrokerLeaseError::InvalidResponse => unavailable(),
    }
}

fn bridge_status(error: BrokerBridgeError) -> Status {
    match error {
        BrokerBridgeError::InvalidIdentity => denied(),
        BrokerBridgeError::InvalidProtocol => {
            Status::invalid_argument("platform credential bridge protocol is invalid")
        }
        BrokerBridgeError::Unavailable => unavailable(),
    }
}

#[cfg(test)]
mod tests;
