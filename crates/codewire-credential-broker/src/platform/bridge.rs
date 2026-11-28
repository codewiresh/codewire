//! Private generated-service adapter, not a listener or production authenticator.
//!
//! The owner supplies the accepted trusted runtime identity implementation and
//! isolated store/upstream handles. It must call `shutdown` and await it before
//! dropping those dependencies. Dropping a server or runtime is not a promise
//! that provider-side rotation or protected-store publication was drained.
//!
//! The relay must own both halves of each private call and end its outgoing
//! request stream when its response owner is dropped. Dropping only a remote
//! tonic response half need not send HTTP/2 cancellation while outgoing DATA
//! remains possible. The server observes input EOF/error or its own response
//! body being dropped, not an uncommunicated remote loss of interest; the
//! original authenticated expiry and owner shutdown still bound that epoch.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_access::{
    AvailableGrants, CapabilitySlot, CredentialPlaceholder, EnvironmentId, OwnerId,
    ProjectedPlaceholders,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_daemon_proto::broker::v1::credential_broker_service_server::{
    CredentialBrokerService, CredentialBrokerServiceServer,
};
use codewire_daemon_proto::broker::v1::{
    EnsureInterceptionCaRequest, EnsureInterceptionCaResponse, SignInterceptionLeavesRequest,
    SignInterceptionLeavesResponse,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_platform_credentials::{
    EpochMaterialCache, PlatformAccessProfileStore, PlatformCredentialError,
    PlatformCredentialStore,
};
use futures::{Stream, StreamExt, stream::BoxStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status, Streaming, metadata::MetadataMap};
use uuid::Uuid;

use super::{
    EpochDecision, EpochPlaceholders, LeaseBudget, PlatformBrokerLeaseProvider,
    PlatformRuntimeAuthority, PlatformRuntimeError, RuntimeIdentity,
};
use crate::credential_uses::{CredentialUses, EpochUses, RecordingUses};
use crate::timing::{self, Phase};
use crate::{
    AdmittedCredentialBridge, BrokerBridgeError, BrokerLeaseError, BrokerUpstreamTransport,
    CredentialBridgeResponseSink, CredentialBridgeTransport, GitHubAppAuthorizationOwner,
    OpenAiBroker, admit_credential_bridge, run_admitted_credential_bridge,
    run_admitted_credential_bridge_with_front_doors,
};

mod front_door;
pub use front_door::FrontDoorScope;
use front_door::{EpochBounds, EpochHandle, Registry as FrontDoorRegistry};
mod interception;
pub use interception::{InterceptionCaError, InterceptionCas, LeafRequest, SignedLeaf};

/// A joined front-door stream with nothing in flight ends after this long;
/// cw-egress opens another on demand (#4963).
const FRONT_DOOR_IDLE: std::time::Duration = std::time::Duration::from_secs(120);

/// The operations a joined front-door stream serves, listed in its response
/// headers; the relay copies exactly these into the front door's Open.
pub const FRONT_DOOR_CAPABILITIES: &[&str] =
    codewire_daemon_proto::CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES;

/// Admission and active/draining epochs share one process-wide service budget.
/// Each hosted Sandbox with credentials holds one long-lived epoch, and two for
/// up to 90 seconds at each renewal, while its relay admits the next epoch
/// before the current identity expires. Kubelet rotates each Pod's 600-second
/// token every 480 seconds, so a Sandbox renews at most twice per 480 seconds
/// and holds at most 1.375 streams on average: 1024 streams serve about 740
/// Sandboxes whose renewals are spread out, and 512 even if all renew at once.
/// An idle epoch is one TLS connection and its tasks; its response buffer is
/// bounded.
pub const PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS: usize = 1024;
/// Concurrent leases across all epochs: a record read, any authority
/// evaluation (or full per-request checks), and the protected-material read
/// (SQL and KEK unwrap) or a reuse from the epoch's material cache. A lease
/// runs its statements one at a time, so it holds at most one of the
/// credential service's 16 pool connections and none during its Kubernetes
/// reads or the unwrap. Sixty-four leases queue at most four per connection
/// for a few statement times, far inside the pool's 5-second acquire timeout,
/// whose expiry would end the epoch, and bound Kubernetes and OpenBao
/// concurrency.
pub const PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES: usize = 64;
/// Optional operations this broker serves, listed in the admitted stream's
/// response headers. The relay copies them into the daemon's Open, and the
/// daemon sends an optional operation only when listed, so an older broker or
/// relay is never sent a frame that would end its epoch.
pub const PLATFORM_CREDENTIAL_BRIDGE_CAPABILITIES: &[&str] = &[
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_ANTIGRAVITY_LOGIN,
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
];
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
/// How often an intercepted epoch admitted with hosted placeholders off is
/// logged, at most: a misconfiguration, not an event per Sandbox.
const PLACEHOLDERS_OFF_LOG_INTERVAL: Duration = Duration::from_secs(600);
const RESPONSE_BUFFER: usize = 32;

/// Closed failures from the trusted process-local identity boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformBridgeAuthenticationError {
    #[error("platform credential bridge authentication is required")]
    Unauthenticated,
    #[error("platform credential bridge authority denied the session")]
    Denied,
    /// A denial the relay passes to the daemon by name (#6406): a Sandbox
    /// whose creator left its organization or was disabled.
    #[error("platform credential bridge authority denied the session")]
    Refused(codewire_access::Refusal),
    #[error("platform credential bridge authority is unavailable")]
    Unavailable,
}

impl PlatformBridgeAuthenticationError {
    fn status(self) -> Status {
        match self {
            Self::Unauthenticated => Status::unauthenticated(self.to_string()),
            Self::Denied => Status::permission_denied(self.to_string()),
            Self::Refused(refusal) => {
                let mut status = Status::permission_denied(self.to_string());
                let value = (codewire_credential_bridge::wire_refusal(refusal) as i32).to_string();
                if let Ok(value) = value.parse() {
                    status.metadata_mut().insert(
                        codewire_daemon_proto::CREDENTIAL_BRIDGE_REFUSAL_HEADER,
                        value,
                    );
                }
                status
            }
            Self::Unavailable => Status::unavailable(self.to_string()),
        }
    }
}

/// Trusted process-local authentication, never a deserializer of guest scope.
///
/// Authenticate the exact relay and forwarded workspace identities under the
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

    /// Orchestration's relay token alone, for `EnsureInterceptionCa` and
    /// nothing else (#4001); every other method takes [`Self::authenticate`].
    /// Refused unless an authenticator serves it.
    async fn authenticate_relay(
        &self,
        _metadata: &MetadataMap,
    ) -> Result<RelayCaller, PlatformBridgeAuthenticationError> {
        Err(PlatformBridgeAuthenticationError::Unauthenticated)
    }
}

/// The orchestration Pod a relay-only call came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelayCaller {
    pub pod_uid: Uuid,
}

struct ServiceState<A, U> {
    authenticator: Arc<A>,
    credentials: Arc<PlatformCredentialStore>,
    profiles: PlatformAccessProfileStore,
    upstream: U,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    /// Whether a hosted epoch's leases carry their environment's placeholder
    /// (#4001). Off unless the credential service's setting turns it on.
    hosted_placeholders: bool,
    /// When an intercepted epoch was last logged as admitted with hosted
    /// placeholders off.
    placeholders_off_logged: Mutex<Option<Instant>>,
    permits: Arc<Semaphore>,
    stream_capacity: usize,
    leases: LeaseBudget,
    accepting: Arc<Mutex<bool>>,
    workers: TaskTracker,
    shutdown: CancellationToken,
    /// Admitted epochs a front-door stream may join (#4001, #4909).
    front_doors: Arc<FrontDoorRegistry>,
    /// The interception CAs, where this service holds them (#4001).
    interception: Option<Arc<interception::Interception>>,
    front_door_idle: std::time::Duration,
    /// Where hosted epochs' credential uses fold for the Sandbox audit log
    /// (#6189). Off unless the credential service reports them.
    credential_uses: Option<Arc<CredentialUses>>,
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
                hosted_placeholders: false,
                placeholders_off_logged: Mutex::new(None),
                permits: Arc::new(Semaphore::new(streams)),
                stream_capacity: streams,
                leases: LeaseBudget::new(leases),
                accepting: Arc::new(Mutex::new(true)),
                workers: TaskTracker::new(),
                shutdown: CancellationToken::new(),
                front_doors: Arc::default(),
                interception: None,
                front_door_idle: FRONT_DOOR_IDLE,
                credential_uses: None,
                #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
                ssh: None,
            }),
        }
    }

    /// A local VM's seed placeholders on a platform profile (#4001): for
    /// each of `slots` that `grants` grants, the placeholder this service's
    /// owner-local leases of that grant carry, derived under `user`'s local
    /// root for `environment` from this service's own credential store. The
    /// caller has admitted `user`'s selection for `environment`, and `grants`
    /// are that admission's.
    pub async fn owner_local_seed_placeholders(
        &self,
        user: &OwnerId,
        environment: &EnvironmentId,
        grants: &AvailableGrants,
        slots: &[CapabilitySlot],
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, PlatformCredentialError> {
        super::placeholders::owner_local_seed_placeholders(
            &self.state.credentials,
            user,
            environment,
            grants,
            slots,
        )
        .await
    }

    /// Tests reach the idle end without waiting two minutes.
    #[cfg(test)]
    fn with_front_door_idle(mut self, idle: std::time::Duration) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("set before cloning or serving")
            .front_door_idle = idle;
        self
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

    /// Serve the interception CAs' methods from `cas` (#4001). Without it they
    /// answer UNAVAILABLE. Explicit trusted composition only, before cloning
    /// or serving.
    pub fn with_interception_cas(
        mut self,
        cas: Arc<dyn InterceptionCas>,
    ) -> Result<Self, PlatformRuntimeError> {
        let state = Arc::get_mut(&mut self.state).ok_or(PlatformRuntimeError::Denied)?;
        if state.interception.is_some() || state.shutdown.is_cancelled() {
            return Err(PlatformRuntimeError::Denied);
        }
        state.interception = Some(Arc::new(interception::Interception::new(cas)));
        Ok(self)
    }

    /// Give each hosted epoch's leases their environment's placeholder
    /// (#4001; docs/dev/SECRETS-AND-CREDENTIALS.md, "Per-environment
    /// placeholders"). Explicit process composition only, before cloning or
    /// serving; an owner-local epoch never gets one.
    pub fn with_hosted_placeholders(mut self) -> Result<Self, PlatformRuntimeError> {
        let state = Arc::get_mut(&mut self.state).ok_or(PlatformRuntimeError::Denied)?;
        if state.shutdown.is_cancelled() {
            return Err(PlatformRuntimeError::Denied);
        }
        state.hosted_placeholders = true;
        Ok(self)
    }

    /// Fold each hosted epoch's credential uses into `uses`, under the
    /// workspace binding the epoch serves (#6189; SPEC.md "Sandbox audit
    /// log"). Explicit process composition only, before cloning or serving;
    /// an owner-local epoch records none.
    pub fn with_credential_uses(
        mut self,
        uses: Arc<CredentialUses>,
    ) -> Result<Self, PlatformRuntimeError> {
        let state = Arc::get_mut(&mut self.state).ok_or(PlatformRuntimeError::Denied)?;
        if state.credential_uses.is_some() || state.shutdown.is_cancelled() {
            return Err(PlatformRuntimeError::Denied);
        }
        state.credential_uses = Some(uses);
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
    /// Also returns the epoch's verified identity expiry (Unix seconds), at
    /// which this epoch ends.
    pub async fn serve_authenticated<B, I, F>(
        &self,
        admission: F,
    ) -> Result<
        (
            ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>,
            u64,
        ),
        Status,
    >
    where
        B: PlatformRuntimeAuthority + 'static,
        I: Stream<Item = Result<v1::CredentialBridgeGuestMessage, Status>> + Send + 'static,
        F: Future<Output = Result<(Arc<B>, I), PlatformBridgeAuthenticationError>> + Send,
    {
        let (stream, expires_at_unix, _, _) = self.serve(admission, Joinable::No).await?;
        Ok((stream, expires_at_unix))
    }

    /// [`Self::serve_authenticated`] for a relayed hosted epoch whose
    /// admission also says whether its Pod is intercepted (#4001). Only an
    /// intercepted epoch can be joined by a front-door stream, and its broker
    /// then delivers placeholder logins or none, never the sign-in's own
    /// tokens beside the front door: one decision, the relay's, for both
    /// (cw-security, 2026-11-19). It returns the epoch's handle and the
    /// placeholders its Sandbox projects exactly then, for its response
    /// headers and nowhere else.
    pub async fn serve_authenticated_joinable<B, I, F>(
        &self,
        admission: F,
    ) -> Result<
        (
            ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>,
            u64,
            Option<JoinableEpoch>,
        ),
        Status,
    >
    where
        B: PlatformRuntimeAuthority + 'static,
        I: Stream<Item = Result<v1::CredentialBridgeGuestMessage, Status>> + Send + 'static,
        F: Future<Output = Result<(Arc<B>, I, bool), PlatformBridgeAuthenticationError>> + Send,
    {
        // Whether the relay said the Pod is intercepted: read only once
        // admission has succeeded.
        let intercepted = Arc::new(AtomicBool::new(false));
        let said = Arc::clone(&intercepted);
        let admission = async move {
            let (authority, input, intercepted) = admission.await?;
            said.store(intercepted, Ordering::Release);
            Ok((authority, input))
        };
        let (stream, expires_at_unix, handle, projected) = self
            .serve(admission, Joinable::Binding(intercepted))
            .await?;
        let joinable = match (handle, projected) {
            (Some(handle), Some(placeholders)) => Some(JoinableEpoch {
                handle: handle.header_value(),
                placeholders,
            }),
            _ => None,
        };
        Ok((stream, expires_at_unix, joinable))
    }

    /// [`Self::serve_authenticated`] for an owner's delegation epoch (#4909).
    /// The admission also says whether the delegation's Open declared a front
    /// door. If it did, the epoch's broker seals agent logins with
    /// placeholders from its first request, that owner's local front door may
    /// join it, and its handle is returned, for the admission answer and
    /// nowhere else. If not, logins are delivered as before, no front door
    /// can join, and the handle is empty.
    pub async fn serve_authenticated_delegation<B, I, F>(
        &self,
        owner: String,
        admission: F,
    ) -> Result<
        (
            ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>,
            u64,
            Vec<u8>,
        ),
        Status,
    >
    where
        B: PlatformRuntimeAuthority + 'static,
        I: Stream<Item = Result<v1::CredentialBridgeGuestMessage, Status>> + Send + 'static,
        F: Future<Output = Result<(Arc<B>, I, bool), PlatformBridgeAuthenticationError>> + Send,
    {
        // Whether the delegation's admitted Open declared a front door: read
        // only once admission has succeeded.
        let front_door = Arc::new(AtomicBool::new(false));
        let declared = Arc::clone(&front_door);
        let admission = async move {
            let (authority, input, wanted) = admission.await?;
            declared.store(wanted, Ordering::Release);
            Ok((authority, input))
        };
        let (stream, expires_at_unix, handle, _) = self
            .serve(admission, Joinable::Owner(owner, front_door))
            .await?;
        Ok((
            stream,
            expires_at_unix,
            handle.map(|handle| handle.to_vec()).unwrap_or_default(),
        ))
    }

    /// An owner's local front door joins one of that owner's delegation
    /// epochs by the handle in its request headers (#4909), read exactly as a
    /// hosted join's. The caller has checked the owner's OAuth; the epoch's
    /// environment comes from the epoch. A missing, repeated or wrong-length
    /// handle, or one that names no live epoch of this owner, is refused the
    /// same way as any other.
    pub async fn join_delegated_front_door(
        &self,
        owner: String,
        metadata: &MetadataMap,
        input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
    ) -> Result<ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>, Status> {
        let permit = self.acquire()?;
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let presented =
                EpochHandle::presented(metadata).ok_or_else(front_door::handle_refused)?;
            self.join(FrontDoorScope::Owner(owner), &presented, input, permit)
                .await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("front-door bridge admission timed out"))?
    }

    /// Join the epoch in `scope` whose handle is `presented`, as its
    /// front-door entry. Shared by the hosted and delegated joins.
    async fn join(
        &self,
        scope: FrontDoorScope,
        presented: &EpochHandle,
        input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
        permit: OwnedSemaphorePermit,
    ) -> Result<ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>, Status> {
        let claim = self.state.front_doors.claim(&scope, presented, permit)?;
        let epoch = Epoch {
            shutdown: self.state.shutdown.clone(),
            input_closed: CancellationToken::new(),
            expires_at_unix: claim.bounds.expires_at_unix,
            deadline: claim.bounds.deadline,
        };
        epoch.ensure_live().map_err(bridge_status)?;
        let (output, receiver) = mpsc::channel(RESPONSE_BUFFER);
        let sink = ResponseSink { output, epoch };
        let transport = RelayTransport {
            input,
            sink,
            _occupied: Some(claim.guard),
        };
        let admitted = admit_credential_bridge(transport, claim.environment_id, claim.generation)
            .await
            .map_err(bridge_status)?;
        claim
            .joins
            .send(admitted)
            .await
            .map_err(|_| unavailable())?;
        Ok(ReceiverStream::new(receiver))
    }

    async fn serve<B, I, F>(
        &self,
        admission: F,
        joinable: Joinable,
    ) -> Result<
        (
            ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>,
            u64,
            Option<EpochHandle>,
            Option<ProjectedPlaceholders>,
        ),
        Status,
    >
    where
        B: PlatformRuntimeAuthority + 'static,
        I: Stream<Item = Result<v1::CredentialBridgeGuestMessage, Status>> + Send + 'static,
        F: Future<Output = Result<(Arc<B>, I), PlatformBridgeAuthenticationError>> + Send,
    {
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let permit = self.acquire()?;
        // What the admission said, read once after it succeeds: the relay's
        // word on a hosted epoch, or whether a delegation's Open declared a
        // front door. Placeholders, login delivery and scope all follow it.
        let mut relay_intercepted = false;
        let mut delegated_front_door = false;
        // The TokenReviews and resolves of authentication, the Ready wait and
        // the recheck after it are all recorded into this one admission line.
        let (admission, timings) = timing::measure(async {
            tokio::select! {
                biased;
                _ = self.state.shutdown.cancelled() => Err(unavailable()),
                result = tokio::time::timeout_at(deadline, async {
                    let (authority, input) = admission.await
                        .map_err(PlatformBridgeAuthenticationError::status)?;
                    // An intercepted hosted epoch also derives the placeholders
                    // its Sandbox projects; the relay's word is read only now.
                    relay_intercepted = matches!(
                        &joinable,
                        Joinable::Binding(said) if said.load(Ordering::Acquire)
                    );
                    delegated_front_door = matches!(
                        &joinable,
                        Joinable::Owner(_, declared) if declared.load(Ordering::Acquire)
                    );
                    self.admit(authority, input.boxed(), relay_intercepted, delegated_front_door)
                        .await
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
            environment_id,
            generation,
            projected,
        } = admission?;
        sink.epoch.ensure_live().map_err(bridge_status)?;
        let expires_at_unix = sink.epoch.expires_at_unix;
        let scope = match joinable {
            Joinable::No => None,
            Joinable::Binding(_) => relay_intercepted.then_some(FrontDoorScope::Binding {
                environment_id,
                generation,
            }),
            Joinable::Owner(owner, _) => {
                delegated_front_door.then_some(FrontDoorScope::Owner(owner))
            }
        };
        // An intercepted hosted epoch, or a delegation that declared a front
        // door, delivers placeholders, never the sign-in's tokens, from its
        // first request: before any join, so a front door that never joins
        // fails closed.
        let broker = if seals_placeholders(scope.as_ref()) {
            broker.paired_with_front_door()
        } else {
            broker
        };
        let Some(scope) = scope else {
            self.spawn_worker(permit, async move {
                // Never select cancellation against or abort this future. Transport
                // termination ends request tasks, then the shared runner drains
                // accepted refresh work before this worker releases its stream slot.
                if let Err(error) = run_admitted_credential_bridge(broker, admitted).await {
                    let _ = sink.output.try_send(Err(bridge_status(error)));
                }
            })?;
            return Ok((ReceiverStream::new(receiver), expires_at_unix, None, None));
        };
        // An intercepted hosted epoch is served only with the placeholders it
        // derived at admission.
        if matches!(scope, FrontDoorScope::Binding { .. }) && projected.is_none() {
            return Err(unavailable());
        }
        let (joins, joining) = mpsc::channel(1);
        let bounds = EpochBounds {
            expires_at_unix,
            deadline: sink.epoch.deadline,
        };
        let (handle, registration) =
            self.state
                .front_doors
                .register(scope, environment_id, generation, bounds, joins)?;
        let front_door_idle = self.state.front_door_idle;
        self.spawn_worker(permit, async move {
            // The epoch can be joined for exactly as long as this worker runs.
            let _registration = registration;
            if let Err(error) = run_admitted_credential_bridge_with_front_doors(
                broker,
                admitted,
                joining,
                Some(front_door_idle),
            )
            .await
            {
                let _ = sink.output.try_send(Err(bridge_status(error)));
            }
        })?;
        Ok((
            ReceiverStream::new(receiver),
            expires_at_unix,
            Some(handle),
            projected,
        ))
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

    /// `intercepted` (the relay's word, #4001) also derives the placeholders
    /// the epoch's Sandbox projects, after its authority is read again.
    /// `delegated_front_door` (#4909) gives a delegation epoch whose Open
    /// declared a front door its leases' placeholders.
    async fn admit<B: PlatformRuntimeAuthority + 'static>(
        &self,
        authority: Arc<B>,
        input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
        intercepted: bool,
        delegated_front_door: bool,
    ) -> Result<Admission<B, U>, Status> {
        let provider = PlatformBrokerLeaseProvider {
            // Every epoch of this service shares its one lease budget.
            leases: Some(self.state.leases.clone()),
            // Each epoch owns its own material cache and drops it on exit.
            material: Some(EpochMaterialCache::new()),
            ..PlatformBrokerLeaseProvider::connect(
                authority,
                Arc::clone(&self.state.credentials),
                self.state.profiles.clone(),
            )
            .await
            .map_err(runtime_status)?
        };
        // A hosted epoch reuses one authority decision for at most a minute;
        // an owner-local delegation epoch keeps full per-request checks.
        let hosted = matches!(provider.session.identity, RuntimeIdentity::Hosted { .. });
        let provider = PlatformBrokerLeaseProvider {
            decision: hosted.then(EpochDecision::new),
            placeholders: lease_placeholders(
                hosted,
                self.state.hosted_placeholders,
                delegated_front_door,
            )
            .then(EpochPlaceholders::default),
            uses: epoch_uses(self.state.credential_uses.as_ref(), &provider.session),
            ..provider
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
        let transport = RelayTransport {
            input,
            sink: sink.clone(),
            _occupied: None,
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
            // unwrap or lease credential material; a hosted epoch evaluates
            // its first authority decision from it.
            provider.admit_authority().await.map_err(lease_status)?;
            if intercepted && !self.state.hosted_placeholders {
                self.log_placeholders_off();
            }
            let (projected, bound) = if intercepted {
                (
                    Some(
                        provider
                            .projected_placeholders()
                            .await
                            .map_err(lease_status)?,
                    ),
                    Some(
                        provider
                            .admitted_bound_secrets()
                            .await
                            .map_err(lease_status)?,
                    ),
                )
            } else {
                (None, None)
            };
            Ok::<_, Status>((admitted, projected, bound))
        })
        .await
        .map_err(|_| denied())??;
        let (admitted, projected, bound) = admitted;
        let provider = PlatformBrokerLeaseProvider { bound, ..provider };
        epoch.ensure_live().map_err(bridge_status)?;
        // A forward from here would leave from the platform, past the
        // Sandbox's own policy and cw-egress, so none is sent (#5555). Where
        // the Sandbox projects GitHub's placeholder, Git's requests that
        // carry none get GitHub's challenge instead, so Git asks its helper
        // for it (#4001).
        let broker = OpenAiBroker::new(provider, RecordingUses(self.state.upstream.clone()))
            .map_err(|_| unavailable())?;
        let broker = if projected
            .as_ref()
            .is_some_and(|projected| projected.github().is_some())
        {
            broker.with_untouched_forwards_refused_challenging_git()
        } else {
            broker.with_untouched_forwards_refused()
        };
        let broker = match &self.state.github_app_authorization {
            Some(owner) => broker.with_github_app_authorization_owner(owner.clone()),
            None => broker,
        };
        Ok(Admission {
            broker,
            admitted,
            sink,
            receiver,
            environment_id,
            generation,
            projected,
        })
    }
}

impl<A, U> PlatformCredentialBridgeService<A, U> {
    /// An intercepted epoch admitted while this service derives no hosted
    /// placeholders projects none (#4001): logged at most once per
    /// [`PLACEHOLDERS_OFF_LOG_INTERVAL`], naming the setting that is off.
    fn log_placeholders_off(&self) {
        let mut logged = self
            .state
            .placeholders_off_logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if logged.is_some_and(|at| now.duration_since(at) < PLACEHOLDERS_OFF_LOG_INTERVAL) {
            return;
        }
        *logged = Some(now);
        tracing::error!(
            setting = "CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED",
            "intercepted Sandboxes project no placeholders: turn on CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED with hosted interception"
        );
    }
}

struct Admission<A, U> {
    broker: OpenAiBroker<PlatformBrokerLeaseProvider<A>, RecordingUses<U>>,
    admitted: AdmittedCredentialBridge<RelayTransport>,
    sink: ResponseSink,
    receiver: mpsc::Receiver<Result<v1::CredentialBridgeHostMessage, Status>>,
    environment_id: Uuid,
    generation: u64,
    /// An intercepted epoch's projected placeholders; `None` for any other.
    projected: Option<ProjectedPlaceholders>,
}

/// What an intercepted epoch's admission gives the relay alone, in its
/// response headers: the handle a front-door stream joins it with, and the
/// placeholders its Sandbox projects (#4001).
pub struct JoinableEpoch {
    pub handle: tonic::metadata::BinaryMetadataValue,
    pub placeholders: ProjectedPlaceholders,
}

impl std::fmt::Debug for JoinableEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JoinableEpoch")
            .field("handle", &"[REDACTED]")
            .field("placeholders", &self.placeholders)
            .finish()
    }
}

#[tonic::async_trait]
impl<A, U> CredentialBrokerService for PlatformCredentialBridgeService<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;
    type FrontDoorBridgeStream = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;

    /// The one method that takes the relay token alone.
    async fn ensure_interception_ca(
        &self,
        request: Request<EnsureInterceptionCaRequest>,
    ) -> Result<Response<EnsureInterceptionCaResponse>, Status> {
        let interception = self.state.interception.clone().ok_or_else(unavailable)?;
        let (metadata, _, request) = request.into_parts();
        let caller = self
            .state
            .authenticator
            .authenticate_relay(&metadata)
            .await
            .map_err(PlatformBridgeAuthenticationError::status)?;
        interception
            .ensure(caller.pod_uid, &request)
            .await
            .map(Response::new)
    }

    async fn sign_interception_leaves(
        &self,
        request: Request<SignInterceptionLeavesRequest>,
    ) -> Result<Response<SignInterceptionLeavesResponse>, Status> {
        let interception = self.state.interception.clone().ok_or_else(unavailable)?;
        let (metadata, _, request) = request.into_parts();
        // The relay token and the workspace authorization, then the epoch's
        // handle, as a front-door stream presents them.
        let authority = self
            .state
            .authenticator
            .authenticate(&metadata)
            .await
            .map_err(PlatformBridgeAuthenticationError::status)?;
        let session = authority.current_session().await.map_err(runtime_status)?;
        let pod_uid = interception::workspace_pod_uid(&session).ok_or_else(denied)?;
        let environment_id =
            Uuid::parse_str(session.context.environment_id.as_str()).map_err(|_| denied())?;
        let generation = session.context.environment_generation;
        let presented = EpochHandle::presented(&metadata).ok_or_else(denied)?;
        let bounds = self
            .state
            .front_doors
            .bounds(environment_id, generation, &presented)?;
        let grants = self
            .state
            .profiles
            .evaluate_grants(&session.context)
            .await
            .map_err(|_| unavailable())?;
        // A bound secret's hosts, as its Pod's first bind recorded them and
        // only for a secret its selection holds (#4003).
        let bound = authority.bound_secrets().await.map_err(runtime_status)?;
        let mut hosts: BTreeSet<&str> = crate::network::RouteHost::interceptable(&grants);
        hosts.extend(
            bound
                .iter()
                .flat_map(|secret| secret.hosts.iter().map(String::as_str)),
        );
        interception
            .sign(interception::LeavesFor {
                pod_uid,
                environment_id,
                generation,
                epoch_digest: presented.digest(),
                epoch_expires_at_unix: bounds.expires_at_unix,
                public_key: &request.leaf_public_key,
                hosts: &hosts,
            })
            .await
            .map(Response::new)
    }

    async fn credential_bridge(
        &self,
        request: Request<Streaming<v1::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        self.serve_authenticated_joinable(async move {
            let (metadata, _, input) = request.into_parts();
            // Preserve the private Pod path: no frame consumption, domain
            // lookup or material access precedes its existing authenticator.
            let authority = self.state.authenticator.authenticate(&metadata).await?;
            // Read only on the relay-authenticated stream, after its
            // authentication; anything but one exact value refuses the epoch.
            let intercepted = intercepted(&metadata, self.state.hosted_placeholders)
                .ok_or(PlatformBridgeAuthenticationError::Denied)?;
            Ok((authority, input, intercepted))
        })
        .await
        .and_then(|(stream, expires_at_unix, joinable)| {
            let mut response = Response::new(stream);
            for capability in PLATFORM_CREDENTIAL_BRIDGE_CAPABILITIES {
                response.metadata_mut().append(
                    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                    tonic::metadata::MetadataValue::from_static(capability),
                );
            }
            // The verified expiry at which this epoch ends, so the relay can
            // admit the next one first. Not a credential; digits only.
            response.metadata_mut().insert(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER,
                tonic::metadata::MetadataValue::from(expires_at_unix),
            );
            // For the relay only, and only for an intercepted epoch: the
            // handle never reaches the daemon or the guest, and the relay
            // copies the placeholders into the daemon's Open. Exactly one
            // placeholders value, empty when the binding grants no projected
            // slot. Neither is logged.
            if let Some(JoinableEpoch {
                handle,
                placeholders,
            }) = joinable
            {
                response.metadata_mut().insert_bin(
                    codewire_daemon_proto::CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
                    handle,
                );
                insert_placeholders(response.metadata_mut(), &placeholders)?;
            }
            Ok(response)
        })
    }

    async fn front_door_bridge(
        &self,
        request: Request<Streaming<v1::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<Self::FrontDoorBridgeStream>, Status> {
        let permit = self.acquire()?;
        let (metadata, _, input) = request.into_parts();
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let joined = tokio::time::timeout_at(deadline, async {
            // The relay token and the workspace authorization, exactly as the
            // epoch's own CredentialBridge, before anything else is read.
            let authority = self
                .state
                .authenticator
                .authenticate(&metadata)
                .await
                .map_err(PlatformBridgeAuthenticationError::status)?;
            let session = authority.current_session().await.map_err(runtime_status)?;
            let environment_id =
                Uuid::parse_str(session.context.environment_id.as_str()).map_err(|_| denied())?;
            let generation = session.context.environment_generation;
            // Then the handle, only among this binding's live epochs.
            let presented =
                EpochHandle::presented(&metadata).ok_or_else(front_door::handle_refused)?;
            let scope = FrontDoorScope::Binding {
                environment_id,
                generation,
            };
            self.join(scope, &presented, input.boxed(), permit).await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("front-door bridge admission timed out"))??;
        let mut response = Response::new(joined);
        for capability in FRONT_DOOR_CAPABILITIES {
            response.metadata_mut().append(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                tonic::metadata::MetadataValue::from_static(capability),
            );
        }
        Ok(response)
    }
}

/// Whether an epoch joinable in `scope` seals its agent logins with
/// placeholders: every joinable one, an intercepted hosted epoch (#4001) and
/// a delegation that declared a front door (#4909).
/// A hosted epoch's uses, filed under the workspace Pod its identity was
/// reviewed as: the binding the credential service reports, never a name.
fn epoch_uses(
    uses: Option<&Arc<CredentialUses>>,
    session: &super::PlatformRuntimeSession,
) -> Option<EpochUses> {
    match (uses, &session.identity) {
        (Some(uses), RuntimeIdentity::Hosted { workspace, .. }) => {
            Some(EpochUses::new(Arc::clone(uses), workspace.uid))
        }
        _ => None,
    }
}

fn seals_placeholders(scope: Option<&FrontDoorScope>) -> bool {
    scope.is_some()
}

/// Whether an epoch's leases carry placeholders: a hosted epoch's while this
/// service's hosted placeholders are on (#4001), and a delegation epoch's
/// whose Open declared a front door (#4909), whatever that switch says. A
/// broker paired with a front door seals only placeholder logins, so a
/// delegation epoch without them would refuse every login.
pub(super) fn lease_placeholders(
    hosted: bool,
    hosted_placeholders: bool,
    delegated_front_door: bool,
) -> bool {
    (hosted && hosted_placeholders) || delegated_front_door
}

/// Whether an admitted epoch can be joined by a front door, and in which
/// scope.
enum Joinable {
    No,
    /// Hosted (#4001): the binding the workspace authorization names, and
    /// whether the relay said its Pod is intercepted.
    Binding(Arc<AtomicBool>),
    /// Delegated (#4909): the owner whose OAuth admitted the delegation, and
    /// whether its Open declared a front door.
    Owner(String, Arc<AtomicBool>),
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

struct RelayTransport {
    input: BoxStream<'static, Result<v1::CredentialBridgeGuestMessage, Status>>,
    sink: ResponseSink,
    /// A joined front-door stream holds its epoch's one place, and its
    /// stream permit, until the transport is dropped.
    _occupied: Option<front_door::Occupied>,
}

#[derive(Clone)]
struct ResponseSink {
    output: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    epoch: Epoch,
}

#[async_trait]
impl CredentialBridgeTransport for RelayTransport {
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
        PlatformRuntimeError::CreatorDeparted => PlatformBridgeAuthenticationError::Refused(
            codewire_access::Refusal::CredentialOwnerDeparted,
        )
        .status(),
        PlatformRuntimeError::CreatorDisabled => PlatformBridgeAuthenticationError::Refused(
            codewire_access::Refusal::CredentialOwnerDisabled,
        )
        .status(),
        PlatformRuntimeError::Unavailable => unavailable(),
    }
}

fn lease_status(error: BrokerLeaseError) -> Status {
    match error {
        BrokerLeaseError::Denied
        | BrokerLeaseError::CreatorDeparted
        | BrokerLeaseError::CreatorDisabled
        | BrokerLeaseError::InvalidRequest
        | BrokerLeaseError::ReconnectRequired(_)
        | BrokerLeaseError::NotSelected => denied(),
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

/// `placeholders` as the admission response's one placeholders value (#4001),
/// marked sensitive: HTTP/2 never indexes it, and no metadata `Debug`
/// prints it.
fn insert_placeholders(
    metadata: &mut MetadataMap,
    placeholders: &ProjectedPlaceholders,
) -> Result<(), Status> {
    let mut value = tonic::metadata::MetadataValue::try_from(placeholders.header_value())
        .map_err(|_| unavailable())?;
    value.set_sensitive(true);
    metadata.insert(
        codewire_daemon_proto::CREDENTIAL_BRIDGE_PLACEHOLDERS_HEADER,
        value,
    );
    Ok(())
}

/// Whether the relay says this epoch's Pod is intercepted (#4001): exactly
/// one value, `true` or `false`. `None` for a repeated or other value, which
/// refuses the epoch, so no relay fault can serve a front door beside a real
/// login, or a real login to an intercepted Pod. A missing value is a relay
/// older than this header, mid-rollout or after orchestration alone rolled
/// back: while this service's hosted placeholders are off it can serve no
/// intercepted epoch anyway, so the epoch is not intercepted; with them on,
/// it is refused.
fn intercepted(metadata: &tonic::metadata::MetadataMap, hosted_placeholders: bool) -> Option<bool> {
    let mut values = metadata
        .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_INTERCEPTED_HEADER)
        .iter();
    let Some(value) = values.next() else {
        return (!hosted_placeholders).then_some(false);
    };
    if values.next().is_some() {
        return None;
    }
    match value.as_bytes() {
        b"true" => Some(true),
        b"false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
