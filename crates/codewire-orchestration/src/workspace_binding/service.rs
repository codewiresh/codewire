//! `WorkspaceBindingService.BindWorkspace` (design §4).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use codewire_proto::codewire::internal::v1::{
    BindWorkspaceRequest, BindWorkspaceResponse, WorkspaceBindingService,
};
use codewire_server_core::bounded_http1::PeerAddr;
use codewire_server_core::pod_identity::{
    KubernetesPodIdentityVerifier, PodIdentityError, PodIdentityPurpose, VerifiedPodIdentity,
    pre_review_bearer_filter,
};
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use tokio::time::Instant;

use super::authorize::{self, SandboxOwner, canonical_uid};
use super::limits::RequestLimits;
use super::metrics;
use super::store::{BindingNotifications, BindingStore, LiveBinding};
use super::{BINDING_REQUERY_INTERVAL, MAX_BIND_WAIT};
use crate::sandbox::{CRD_VERSION, SANDBOX_GROUP};
use crate::worker::gatewayauth::{WorkspaceCredentialScope, issue_workspace_daemon_credential};

/// Value-blind `BindWorkspace` failures (design §3.7). The daemon calls again
/// at once on `NotFound` and backs off on everything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindError {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    ResourceExhausted,
    Unavailable,
}

impl BindError {
    fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unavailable => "unavailable",
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
    kube: Option<kube::Client>,
    verifier: KubernetesPodIdentityVerifier,
    store: Arc<dyn BindingStore>,
    notifications: Arc<BindingNotifications>,
    limits: RequestLimits,
    sandbox_namespace: String,
    session_secret: String,
    max_wait: Duration,
    requery_interval: Duration,
}

impl WorkspaceBindingState {
    pub fn new(
        kube: Option<kube::Client>,
        store: Arc<dyn BindingStore>,
        notifications: Arc<BindingNotifications>,
        sandbox_namespace: &str,
        session_secret: &str,
    ) -> Self {
        Self {
            verifier: KubernetesPodIdentityVerifier::new(
                kube.clone(),
                PodIdentityPurpose::WorkspaceBinding,
            ),
            kube,
            store,
            notifications,
            limits: RequestLimits::default(),
            sandbox_namespace: sandbox_namespace.to_owned(),
            session_secret: session_secret.to_owned(),
            max_wait: MAX_BIND_WAIT,
            requery_interval: BINDING_REQUERY_INTERVAL,
        }
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

    /// The whole §4 decision for one request.
    pub(crate) async fn bind(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        wait_seconds: u32,
    ) -> Result<BindWorkspaceResponse, BindError> {
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
            self.verifier
                .authenticate(headers)
                .await
                .map_err(identity_error)?
        };

        // §4.3: the sandbox namespace only, one request per reviewed Pod.
        if identity.namespace() != self.sandbox_namespace || !canonical_uid(identity.pod_uid()) {
            return Err(BindError::PermissionDenied);
        }
        let _pod_slot = self
            .limits
            .pod_slot(identity.pod_uid())
            .ok_or(BindError::ResourceExhausted)?;
        let kube = self.kube.as_ref().ok_or(BindError::Unavailable)?;

        // §4.4: the live Pod by the reviewed name.
        let pod = read_pod(kube, &identity)
            .await?
            .ok_or(BindError::NotFound)?;
        authorize::bindable_pod(&pod, &identity).ok_or(BindError::PermissionDenied)?;

        // §4.5: the recorded binding, waiting when none exists yet.
        let wait = self
            .max_wait
            .min(Duration::from_secs(u64::from(wait_seconds)));
        let binding = self
            .wait_for_binding(&identity, wait)
            .await?
            .ok_or(BindError::NotFound)?;

        // §4.6: the Pod may have changed during the wait; re-read the chain,
        // then the binding itself.
        let pod = read_pod(kube, &identity)
            .await?
            .ok_or(BindError::NotFound)?;
        let owner =
            authorize::bound_pod(&pod, &identity, &binding).ok_or(BindError::PermissionDenied)?;
        let sandbox = read_sandbox(kube, &binding.namespace, &owner)
            .await?
            .ok_or(BindError::PermissionDenied)?;
        if !authorize::bound_sandbox(&sandbox, &owner, &binding) {
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
        if current != binding {
            return Err(BindError::PermissionDenied);
        }

        // §4.7: respond only while the reviewed token is still valid.
        if identity.expires_at_unix() <= unix_now()? {
            return Err(BindError::Unauthenticated);
        }
        respond(&self.session_secret, &identity, binding)
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

fn respond(
    session_secret: &str,
    identity: &VerifiedPodIdentity,
    binding: LiveBinding,
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
        ..Default::default()
    })
}

fn unix_now() -> Result<u64, BindError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| BindError::Unavailable)
}

async fn read_pod(
    kube: &kube::Client,
    identity: &VerifiedPodIdentity,
) -> Result<Option<Pod>, BindError> {
    let pods: Api<Pod> = Api::namespaced(kube.clone(), identity.namespace());
    pods.get_opt(identity.pod_name())
        .await
        .map_err(|_| BindError::Unavailable)
}

async fn read_sandbox(
    kube: &kube::Client,
    namespace: &str,
    owner: &SandboxOwner,
) -> Result<Option<DynamicObject>, BindError> {
    let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxes");
    let sandboxes: Api<DynamicObject> = Api::namespaced_with(kube.clone(), namespace, &resource);
    sandboxes
        .get_opt(&owner.name)
        .await
        .map_err(|_| BindError::Unavailable)
}

/// Registers the binding RPC. Mount it only on the dedicated listener.
pub fn workspace_binding_router(state: Arc<WorkspaceBindingState>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(WorkspaceBindingConnectService { state }))
}

struct WorkspaceBindingConnectService {
    state: Arc<WorkspaceBindingState>,
}

#[allow(refining_impl_trait)]
impl WorkspaceBindingService for WorkspaceBindingConnectService {
    async fn bind_workspace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BindWorkspaceRequest>,
    ) -> ServiceResult<BindWorkspaceResponse> {
        let peer = ctx
            .extensions()
            .get::<PeerAddr>()
            .map(|PeerAddr(peer)| peer.ip());
        match self
            .state
            .bind(ctx.headers(), peer, request.wait_seconds)
            .await
        {
            Ok(response) => {
                metrics::observe_request("ok");
                connectrpc::Response::ok(response)
            }
            Err(error) => {
                metrics::observe_request(error.code());
                Err(error.connect())
            }
        }
    }

    async fn refresh_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, codewire_proto::codewire::internal::v1::RefreshAccessRequest>,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::RefreshAccessResponse> {
        Err(ConnectError::unimplemented("not implemented yet"))
    }

    async fn record_host_key(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, codewire_proto::codewire::internal::v1::RecordHostKeyRequest>,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::RecordHostKeyResponse> {
        Err(ConnectError::unimplemented("not implemented yet"))
    }

    async fn allocate_peer_relay(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<
            '_,
            codewire_proto::codewire::internal::v1::AllocatePeerRelayRequest,
        >,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::AllocatePeerRelayResponse> {
        Err(ConnectError::unimplemented("not implemented yet"))
    }
}
