//! `WorkspaceBindingService` (design §4; daemon-hosted access §3 and §5).
//!
//! Every method authenticates the same way: TokenReview of the Pod-bound
//! projected token, the live Pod by the reviewed name and UID, and the TCP
//! peer equal to that Pod's own address (S1), so a leaked token is useless
//! from any other workload. `BindWorkspace` then waits for the recorded
//! binding; the other methods require it to exist already. Each re-reads the
//! Pod → Sandbox → SandboxClaim chain and the binding before answering.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use codewire_proto::codewire::internal::v1::{
    AllocatePeerRelayRequest, AllocatePeerRelayResponse, BindWorkspaceRequest,
    BindWorkspaceResponse, GitIdentity, IssueMeshEnrollmentRequest, IssueMeshEnrollmentResponse,
    MeshAttachmentReport as ProtoMeshAttachmentReport, RecordHostKeyRequest, RecordHostKeyResponse,
    RefreshAccessRequest, RefreshAccessResponse, ReportMeshAttachmentRequest,
    ReportMeshAttachmentResponse, WorkspaceAccess, WorkspaceBindingService, WorkspaceDefaults,
    WorkspaceMeshAttachment,
};
use codewire_server_core::bounded_http1::PeerAddr;
use codewire_server_core::peer_token::{self, PEER_TOKEN_LIFETIME_SECS};
use codewire_server_core::pod_identity::{
    PodIdentityError, VerifiedPodIdentity, pre_review_bearer_filter,
};
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use tokio::time::Instant;

use super::access::{
    self, AccessSettings, HttpRelayAllocator, RelayAllocationRequest, RelayAllocator, RelayError,
};
use super::authorize::{self, canonical_uid};
use super::limits::{PodSlot, RequestLimits};
use super::metrics;
use super::store::{
    BindDefaults, BindingNotifications, BindingStore, HostKeyRecord, LiveBinding, MeshAttachment,
    MeshAttachmentReport, MeshIssueOutcome,
};
use super::{BINDING_REQUERY_INTERVAL, MAX_BIND_WAIT};
use crate::environment_mesh::{
    ENROLLMENT_LIFETIME_SECS, enrollment_code_sha256, generate_enrollment_code,
};
use crate::runtime::{MemberFacts, Placement, RuntimeDriver};
use crate::runtime_transport::RuntimeTransportZone;
use crate::worker::environment_auth::{
    WorkspaceCredentialScope, issue_workspace_daemon_credential,
};

/// Value-blind failures (design §3.7). The daemon calls `BindWorkspace` again
/// at once on `NotFound` and backs off on everything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindError {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    ResourceExhausted,
    Unavailable,
    /// The request's own argument is malformed.
    InvalidArgument,
    /// The environment refuses the request as it stands: another host key is
    /// recorded for this generation, or no peer relay serves the Pod's node.
    FailedPrecondition,
}

impl BindError {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unavailable => "unavailable",
            Self::InvalidArgument => "invalid_argument",
            Self::FailedPrecondition => "failed_precondition",
        }
    }

    pub(super) fn connect(self) -> ConnectError {
        match self {
            Self::Unauthenticated => {
                ConnectError::unauthenticated("workspace binding identity was not authenticated")
            }
            Self::PermissionDenied => {
                ConnectError::permission_denied("workspace binding is not permitted")
            }
            Self::NotFound => ConnectError::not_found("workspace binding is not recorded"),
            Self::ResourceExhausted => {
                ConnectError::resource_exhausted("workspace binding request limit reached")
            }
            Self::Unavailable => ConnectError::unavailable("workspace binding is unavailable"),
            Self::InvalidArgument => {
                ConnectError::invalid_argument("workspace binding request is malformed")
            }
            Self::FailedPrecondition => ConnectError::failed_precondition(
                "workspace binding request conflicts with the environment",
            ),
        }
    }
}

fn identity_error(error: PodIdentityError) -> BindError {
    match error {
        PodIdentityError::Unauthenticated => BindError::Unauthenticated,
        PodIdentityError::PermissionDenied => BindError::PermissionDenied,
        PodIdentityError::Unavailable => BindError::Unavailable,
    }
}

/// Shared state of the workspace-binding listener for one process.
pub struct WorkspaceBindingState {
    runtime: Option<Arc<dyn RuntimeDriver>>,
    store: Arc<dyn BindingStore>,
    notifications: Arc<BindingNotifications>,
    limits: RequestLimits,
    sandbox_namespace: String,
    session_secret: String,
    access: AccessSettings,
    relay: Arc<dyn RelayAllocator>,
    max_wait: Duration,
    requery_interval: Duration,
}

/// A caller authenticated as a live workspace Pod, calling from that Pod's
/// own address (S1). Holds the Pod's only request slot.
struct Caller {
    identity: VerifiedPodIdentity,
    peer: IpAddr,
    member: MemberFacts,
    _slot: PodSlot,
}

/// A caller whose recorded binding and live chain were confirmed.
struct BoundCaller {
    caller: Caller,
    binding: LiveBinding,
}

impl WorkspaceBindingState {
    pub fn new(
        runtime: Option<Arc<dyn RuntimeDriver>>,
        store: Arc<dyn BindingStore>,
        notifications: Arc<BindingNotifications>,
        sandbox_namespace: &str,
        session_secret: &str,
    ) -> Self {
        Self {
            runtime,
            store,
            notifications,
            limits: RequestLimits::default(),
            sandbox_namespace: sandbox_namespace.to_owned(),
            session_secret: session_secret.to_owned(),
            access: AccessSettings::default(),
            relay: Arc::new(HttpRelayAllocator::new()),
            max_wait: MAX_BIND_WAIT,
            requery_interval: BINDING_REQUERY_INTERVAL,
        }
    }

    /// The public endpoints the access grant names and the UDP relay
    /// allocator orchestration calls with its own credential.
    pub fn with_access(mut self, access: AccessSettings, relay: Arc<dyn RelayAllocator>) -> Self {
        self.access = access;
        self.relay = relay;
        self
    }

    #[cfg(test)]
    pub(super) fn with_limits(mut self, limits: RequestLimits) -> Self {
        self.limits = limits;
        self
    }

    #[cfg(test)]
    pub(super) fn with_timing(mut self, max_wait: Duration, requery_interval: Duration) -> Self {
        self.max_wait = max_wait;
        self.requery_interval = requery_interval;
        self
    }

    fn runtime(&self) -> Result<&dyn RuntimeDriver, BindError> {
        self.runtime.as_deref().ok_or(BindError::Unavailable)
    }

    /// The live Pod by the reviewed name; `None` when it is gone.
    async fn attested_member(
        &self,
        identity: &VerifiedPodIdentity,
    ) -> Result<Option<MemberFacts>, BindError> {
        self.runtime()?
            .attested_member(identity)
            .await
            .map_err(|_| BindError::Unavailable)
    }

    /// §4.1–§4.4 and S1, shared by every method, in this order. Garbage and
    /// an over-budget peer are refused before any TokenReview (§4.1);
    /// TokenReview is the only authentication (§4.2); the namespace and
    /// per-Pod slot are checked before any Pod read (§4.3); then the live Pod
    /// by the reviewed name must be the reviewed incarnation, called from its
    /// own transport address (§4.4, S1). A missing Pod is `NotFound`, apart
    /// from a Pod that may not bind.
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<Caller, BindError> {
        // §4.1: reject before review, at no TokenReview cost.
        let peer = peer.ok_or(BindError::Unavailable)?;
        if !self.limits.allow_peer(peer) {
            return Err(BindError::ResourceExhausted);
        }
        pre_review_bearer_filter(headers).map_err(identity_error)?;

        // §4.2: TokenReview is the only authentication.
        let identity = {
            let _slot = self
                .limits
                .review_slot()
                .await
                .ok_or(BindError::Unavailable)?;
            metrics::observe_token_review();
            self.runtime()?
                .review_member_credential(headers)
                .await
                .map_err(identity_error)?
        };

        // §4.3: the sandbox namespace only, one request per reviewed Pod.
        if identity.namespace() != self.sandbox_namespace || !canonical_uid(identity.pod_uid()) {
            return Err(BindError::PermissionDenied);
        }
        let slot = self
            .limits
            .pod_slot(identity.pod_uid())
            .ok_or(BindError::ResourceExhausted)?;

        // §4.4: the live Pod by the reviewed name and UID, called from its
        // own address (S1).
        let member = self
            .attested_member(&identity)
            .await?
            .ok_or(BindError::NotFound)?;
        authorize::bindable_pod(&member, &identity).ok_or(BindError::PermissionDenied)?;
        if !authorize::peer_is_pod(&member, peer) {
            return Err(BindError::PermissionDenied);
        }
        Ok(Caller {
            identity,
            peer,
            member,
            _slot: slot,
        })
    }

    /// §4.6: the freshly read Pod, its Sandbox and SandboxClaim still match
    /// the recorded binding, the binding is Pod-scoped, and it is still the
    /// same live binding.
    async fn confirm(
        &self,
        caller: &Caller,
        member: &MemberFacts,
        binding: &LiveBinding,
    ) -> Result<(), BindError> {
        let identity = &caller.identity;
        let owner =
            authorize::bound_pod(member, identity, binding).ok_or(BindError::PermissionDenied)?;
        if !authorize::peer_is_pod(member, caller.peer) {
            return Err(BindError::PermissionDenied);
        }
        let sandbox = self
            .runtime()?
            .attested_runtime(&Placement::new(&binding.namespace), &owner.name)
            .await
            .map_err(|_| BindError::Unavailable)?
            .ok_or(BindError::PermissionDenied)?;
        if !authorize::bound_sandbox(&sandbox, &owner, binding) {
            return Err(BindError::PermissionDenied);
        }
        // A legacy Pod keeps its environment token; it never binds here.
        if binding.credential_scope != WorkspaceCredentialScope::Pod {
            return Err(BindError::PermissionDenied);
        }
        // The binding may have been released or moved while the chain was
        // re-read; answer only from a binding that is still the same and live.
        let current = self
            .store
            .live_binding(
                identity.pod_uid(),
                identity.namespace(),
                identity.pod_name(),
            )
            .await
            .map_err(|_| BindError::Unavailable)?
            .ok_or(BindError::NotFound)?;
        if current != *binding {
            return Err(BindError::PermissionDenied);
        }
        Ok(())
    }

    /// An already-bound caller: every method except `BindWorkspace`.
    async fn bound(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<BoundCaller, BindError> {
        let caller = self.authenticate(headers, peer).await?;
        let identity = &caller.identity;
        let binding = self
            .store
            .live_binding(
                identity.pod_uid(),
                identity.namespace(),
                identity.pod_name(),
            )
            .await
            .map_err(|_| BindError::Unavailable)?
            .ok_or(BindError::NotFound)?;
        self.confirm(&caller, &caller.member, &binding).await?;
        Ok(BoundCaller { caller, binding })
    }

    /// The whole §4 decision for one `BindWorkspace` request.
    pub(crate) async fn bind(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        wait_seconds: u32,
    ) -> Result<BindWorkspaceResponse, BindError> {
        let caller = self.authenticate(headers, peer).await?;

        // §4.5: the recorded binding, waiting when none exists yet.
        let wait = self
            .max_wait
            .min(Duration::from_secs(u64::from(wait_seconds)));
        let binding = self
            .wait_for_binding(&caller.identity, wait)
            .await?
            .ok_or(BindError::NotFound)?;

        // §4.6: the Pod may have changed during the wait; re-read the chain,
        // then the binding itself.
        let member = self
            .attested_member(&caller.identity)
            .await?
            .ok_or(BindError::NotFound)?;
        self.confirm(&caller, &member, &binding).await?;
        let access = self.access_grant(&member, &binding).await?;

        // §4.7: respond only while the reviewed token is still valid.
        still_valid(&caller.identity)?;
        respond(&self.session_secret, &caller.identity, binding, access)
    }

    /// A fresh access grant for an already-bound Pod.
    pub(crate) async fn refresh_access(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<RefreshAccessResponse, BindError> {
        let bound = self.bound(headers, peer).await?;
        let access = self
            .access_grant(&bound.caller.member, &bound.binding)
            .await?;
        still_valid(&bound.caller.identity)?;
        Ok(RefreshAccessResponse {
            access: Some(access).into(),
            ..Default::default()
        })
    }

    /// Records the daemon's SSH host public key for its bound Pod, write-once
    /// per Pod (S3). The environment, generation and Pod come only from the
    /// reviewed identity and its binding.
    pub(crate) async fn record_host_key(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        public_key: &str,
    ) -> Result<RecordHostKeyResponse, BindError> {
        if !access::valid_host_key(public_key) {
            return Err(BindError::InvalidArgument);
        }
        let bound = self.bound(headers, peer).await?;
        still_valid(&bound.caller.identity)?;
        let recorded = self
            .store
            .record_host_key(
                &bound.binding.environment_id,
                bound.binding.environment_generation,
                &bound.binding.pod_uid,
                public_key,
            )
            .await
            .map_err(|_| BindError::Unavailable)?;
        match recorded {
            HostKeyRecord::Recorded | HostKeyRecord::Unchanged => {
                Ok(RecordHostKeyResponse::default())
            }
            HostKeyRecord::Conflict => Err(BindError::FailedPrecondition),
        }
    }

    /// Allocates a UDP peer-relay slot for the bound environment on its
    /// node's relay, with orchestration's own allocator credential (S5).
    pub(crate) async fn allocate_peer_relay(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        request: &AllocatePeerRelayRequest,
    ) -> Result<AllocatePeerRelayResponse, BindError> {
        let client_disco: [String; 2] = match request.disco_keys.as_slice() {
            [first, second]
                if access::valid_disco_key(first)
                    && access::valid_disco_key(second)
                    && first != second =>
            {
                [first.clone(), second.clone()]
            }
            _ => return Err(BindError::InvalidArgument),
        };
        let bound = self.bound(headers, peer).await?;
        let allocator_url = self
            .node_zone(&bound.caller.member)
            .await?
            .and_then(|zone| zone.peer_relay)
            .map(|relay| relay.allocator_url.trim().to_owned())
            .filter(|url| !url.is_empty())
            .ok_or(BindError::FailedPrecondition)?;
        still_valid(&bound.caller.identity)?;
        let allocation = self
            .relay
            .allocate(
                &allocator_url,
                &RelayAllocationRequest {
                    client_disco,
                    generation: request.relay_generation,
                },
            )
            .await
            .map_err(|error| match error {
                RelayError::Refused => BindError::FailedPrecondition,
                RelayError::Unavailable => BindError::Unavailable,
            })?;
        let [first, second] = allocation.endpoint.client_disco;
        Ok(AllocatePeerRelayResponse {
            relay_generation: allocation.generation,
            server_disco_key: allocation.endpoint.server_disco,
            disco_keys: vec![first, second],
            lamport_id: allocation.endpoint.lamport_id,
            vni: allocation.endpoint.vni,
            bind_lifetime_ns: allocation.endpoint.bind_lifetime_ns,
            steady_state_lifetime_ns: allocation.endpoint.steady_state_lifetime_ns,
            addr_ports: allocation.endpoint.addr_ports,
            ..Default::default()
        })
    }

    /// Issues one Mesh enrollment code to the bound Pod for its current
    /// generation (#3350). The code is returned once and stored only as its
    /// digest.
    pub(crate) async fn issue_mesh_enrollment(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<IssueMeshEnrollmentResponse, BindError> {
        let bound = self.bound(headers, peer).await?;
        let attachment = self
            .mesh_target(&bound.binding)
            .await?
            .ok_or(BindError::FailedPrecondition)?;
        let code = generate_enrollment_code().map_err(|_| BindError::Unavailable)?;
        let expires_at = i64::try_from(unix_now()?)
            .map_err(|_| BindError::Unavailable)?
            .saturating_add(ENROLLMENT_LIFETIME_SECS);
        still_valid(&bound.caller.identity)?;
        let outcome = self
            .store
            .issue_mesh_enrollment(
                &bound.binding.environment_id,
                &bound.binding.pod_uid,
                bound.binding.environment_generation,
                &enrollment_code_sha256(&code),
            )
            .await
            .map_err(|_| BindError::Unavailable)?;
        match outcome {
            MeshIssueOutcome::Issued => Ok(IssueMeshEnrollmentResponse {
                enrollment_code: code,
                expires_at,
                attachment: Some(attachment).into(),
                ..Default::default()
            }),
            MeshIssueOutcome::NotAttached => Err(BindError::FailedPrecondition),
            MeshIssueOutcome::Exhausted => Err(BindError::ResourceExhausted),
        }
    }

    /// Records what the bound Pod's daemon observed of its Mesh membership.
    pub(crate) async fn report_mesh_attachment(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        report: ProtoMeshAttachmentReport,
    ) -> Result<ReportMeshAttachmentResponse, BindError> {
        let bound = self.bound(headers, peer).await?;
        let report = mesh_report(report).ok_or(BindError::InvalidArgument)?;
        still_valid(&bound.caller.identity)?;
        let recorded = self
            .store
            .report_mesh_attachment(
                &bound.binding.environment_id,
                &bound.binding.pod_uid,
                report,
            )
            .await
            .map_err(|_| BindError::Unavailable)?;
        if !recorded {
            return Err(BindError::FailedPrecondition);
        }
        Ok(ReportMeshAttachmentResponse::default())
    }

    /// The Mesh network node the bound environment serves, when it joins one
    /// and this platform offers hosted Mesh.
    async fn mesh_target(
        &self,
        binding: &LiveBinding,
    ) -> Result<Option<WorkspaceMeshAttachment>, BindError> {
        if self.access.mesh_url.is_empty() {
            return Ok(None);
        }
        let attachment = self
            .store
            .mesh_attachment(&binding.environment_id)
            .await
            .map_err(|_| BindError::Unavailable)?;
        Ok(attachment.map(
            |MeshAttachment {
                 org_id,
                 network_id,
                 node_name,
             }| {
                WorkspaceMeshAttachment {
                    mesh_url: self.access.mesh_url.clone(),
                    org_id,
                    network_id,
                    node_name,
                    ..Default::default()
                }
            },
        ))
    }

    /// The bound environment's tailnet access: a peer token for its current
    /// generation and the public endpoints its daemon may use.
    async fn access_grant(
        &self,
        member: &MemberFacts,
        binding: &LiveBinding,
    ) -> Result<WorkspaceAccess, BindError> {
        let expires_at = i64::try_from(unix_now()?)
            .map_err(|_| BindError::Unavailable)?
            .saturating_add(PEER_TOKEN_LIFETIME_SECS);
        let peer_token = peer_token::issue(
            &self.session_secret,
            &binding.environment_id,
            binding.environment_generation,
            expires_at,
        )
        .map_err(|_| BindError::Unavailable)?;
        // Endpoints are best effort: a missing Service or zone only narrows
        // the paths the daemon advertises.
        let runtime = self.runtime()?;
        let placement = Placement::new(&binding.namespace);
        let (direct_udp_endpoints, zone, app_ports, mesh) = tokio::join!(
            runtime.direct_udp_endpoints(&placement, &binding.environment_id),
            self.node_zone(member),
            self.store.app_ports(&binding.environment_id),
            self.mesh_target(binding),
        );
        // The daemon leaves its network when a grant names none, so an
        // unknown attachment fails the grant rather than detaching it.
        let mesh = mesh?;
        // The daemon replaces its served ports with this set, so an unknown
        // set fails the grant rather than clearing them.
        let app_ports = app_ports.map_err(|_| BindError::Unavailable)?;
        let peer_relay_endpoints = zone
            .ok()
            .flatten()
            .and_then(|zone| zone.peer_relay)
            .map(|relay| relay.public_endpoints)
            .unwrap_or_default();
        Ok(WorkspaceAccess {
            peer_token,
            peer_token_expires_at: expires_at,
            operation_generation: binding.environment_generation,
            coordinator_url: self.access.coordinator_url.clone(),
            direct_udp_endpoints,
            peer_relay_endpoints,
            app_ports,
            mesh: mesh.into(),
            ..Default::default()
        })
    }

    /// The enabled transport zone of the Pod's node, if it has one.
    async fn node_zone(
        &self,
        member: &MemberFacts,
    ) -> Result<Option<RuntimeTransportZone>, BindError> {
        let Some(zone_name) = self
            .runtime()?
            .member_transport_zone(member)
            .await
            .map_err(|_| BindError::Unavailable)?
        else {
            return Ok(None);
        };
        self.store
            .transport_zone(&zone_name)
            .await
            .map_err(|_| BindError::Unavailable)
    }

    async fn wait_for_binding(
        &self,
        identity: &VerifiedPodIdentity,
        wait: Duration,
    ) -> Result<Option<LiveBinding>, BindError> {
        // Subscribe before the first query so a binding committed in between
        // leaves a stored wakeup.
        let subscription = self.notifications.subscribe(identity.pod_uid());
        let deadline = Instant::now() + wait;
        loop {
            if let Some(binding) = self
                .store
                .live_binding(
                    identity.pod_uid(),
                    identity.namespace(),
                    identity.pod_name(),
                )
                .await
                .map_err(|_| BindError::Unavailable)?
            {
                return Ok(Some(binding));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let tick = (deadline - now).min(self.requery_interval);
            let _ = tokio::time::timeout(tick, subscription.notified()).await;
        }
    }
}

/// §4.7: answer only while the reviewed token is still valid.
fn still_valid(identity: &VerifiedPodIdentity) -> Result<(), BindError> {
    if identity.expires_at_unix() <= unix_now()? {
        return Err(BindError::Unauthenticated);
    }
    Ok(())
}

fn respond(
    session_secret: &str,
    identity: &VerifiedPodIdentity,
    binding: LiveBinding,
    access: WorkspaceAccess,
) -> Result<BindWorkspaceResponse, BindError> {
    // The lookup keys on the reviewed UID; refuse anything else outright.
    if binding.pod_uid != identity.pod_uid() {
        return Err(BindError::PermissionDenied);
    }
    let daemon_credential = issue_workspace_daemon_credential(
        session_secret,
        &binding.environment_id,
        &binding.pod_uid,
    )
    .map_err(|_| BindError::Unavailable)?;
    Ok(BindWorkspaceResponse {
        environment_id: binding.environment_id,
        pod_uid: binding.pod_uid,
        operation_generation: binding.operation_generation,
        daemon_credential,
        projection_selection_sha256: binding.projection_selection_sha256.unwrap_or_default(),
        managed_credential_clients: binding.managed_credential_clients,
        access: Some(access).into(),
        working_directory: binding.working_directory,
        defaults: binding.defaults.map(workspace_defaults).into(),
        ..Default::default()
    })
}

/// The bind response's form of the saved project defaults and Git author.
fn workspace_defaults(defaults: BindDefaults) -> WorkspaceDefaults {
    WorkspaceDefaults {
        environment: defaults.environment.into_iter().collect(),
        git: defaults
            .git
            .map(|(email, name)| GitIdentity {
                email,
                name,
                ..Default::default()
            })
            .into(),
        ..Default::default()
    }
}

/// The stored form of a daemon's report; `None` for an unknown value.
fn mesh_report(report: ProtoMeshAttachmentReport) -> Option<MeshAttachmentReport> {
    Some(match report {
        ProtoMeshAttachmentReport::Attached => MeshAttachmentReport::Attached,
        ProtoMeshAttachmentReport::Revoked => MeshAttachmentReport::Revoked,
        ProtoMeshAttachmentReport::MeshUnreachable => {
            MeshAttachmentReport::Failed("mesh_unreachable")
        }
        ProtoMeshAttachmentReport::NetworkNotFound => {
            MeshAttachmentReport::Failed("network_not_found")
        }
        ProtoMeshAttachmentReport::NotAMember => MeshAttachmentReport::Failed("not_a_member"),
        ProtoMeshAttachmentReport::NodeNameTaken => MeshAttachmentReport::Failed("node_name_taken"),
        ProtoMeshAttachmentReport::Refused => MeshAttachmentReport::Failed("refused"),
        ProtoMeshAttachmentReport::Unspecified => return None,
    })
}

fn unix_now() -> Result<u64, BindError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| BindError::Unavailable)
}

/// Registers the binding RPC. Mount it only on the dedicated listener.
pub fn workspace_binding_router(state: Arc<WorkspaceBindingState>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(WorkspaceBindingConnectService { state }))
}

struct WorkspaceBindingConnectService {
    state: Arc<WorkspaceBindingState>,
}

fn peer_of(ctx: &RequestContext) -> Option<IpAddr> {
    ctx.extensions()
        .get::<PeerAddr>()
        .map(|PeerAddr(peer)| peer.ip())
}

fn observe<T>(method: &'static str, result: Result<T, BindError>) -> ServiceResult<T> {
    match result {
        Ok(response) => {
            metrics::observe_request(method, "ok");
            connectrpc::Response::ok(response)
        }
        Err(error) => {
            metrics::observe_request(method, error.code());
            Err(error.connect())
        }
    }
}

#[allow(refining_impl_trait)]
impl WorkspaceBindingService for WorkspaceBindingConnectService {
    async fn bind_workspace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BindWorkspaceRequest>,
    ) -> ServiceResult<BindWorkspaceResponse> {
        let result = self
            .state
            .bind(ctx.headers(), peer_of(&ctx), request.wait_seconds)
            .await;
        observe("bind_workspace", result)
    }

    async fn refresh_access(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, RefreshAccessRequest>,
    ) -> ServiceResult<RefreshAccessResponse> {
        let result = self
            .state
            .refresh_access(ctx.headers(), peer_of(&ctx))
            .await;
        observe("refresh_access", result)
    }

    async fn record_host_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RecordHostKeyRequest>,
    ) -> ServiceResult<RecordHostKeyResponse> {
        let result = self
            .state
            .record_host_key(ctx.headers(), peer_of(&ctx), request.public_key_openssh)
            .await;
        observe("record_host_key", result)
    }

    async fn allocate_peer_relay(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AllocatePeerRelayRequest>,
    ) -> ServiceResult<AllocatePeerRelayResponse> {
        let result = self
            .state
            .allocate_peer_relay(ctx.headers(), peer_of(&ctx), &request.to_owned_message())
            .await;
        observe("allocate_peer_relay", result)
    }

    async fn issue_mesh_enrollment(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, IssueMeshEnrollmentRequest>,
    ) -> ServiceResult<IssueMeshEnrollmentResponse> {
        let result = self
            .state
            .issue_mesh_enrollment(ctx.headers(), peer_of(&ctx))
            .await;
        observe("issue_mesh_enrollment", result)
    }

    async fn report_mesh_attachment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportMeshAttachmentRequest>,
    ) -> ServiceResult<ReportMeshAttachmentResponse> {
        let report = request
            .report
            .as_known()
            .unwrap_or(ProtoMeshAttachmentReport::Unspecified);
        let result = self
            .state
            .report_mesh_attachment(ctx.headers(), peer_of(&ctx), report)
            .await;
        observe("report_mesh_attachment", result)
    }
}
