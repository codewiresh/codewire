//! `EgressService` on the internal-connect listener (#4000). Every method
//! first authenticates cw-egress by TokenReview of its own token and reads
//! its node from its live Pod; every method that names a guest Pod refuses
//! one that is not on that node.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::PoisonError;
use std::time::Duration;

use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_assignment::Binding;
use codewire_proto::codewire::internal::v1::{
    AdmitRequest, AdmitResponse, BoundAssignment, EgressAssignment, EgressPolicyRevision,
    EgressService, FrontDoorSessionRequest, FrontDoorSessionResponse, PlatformAllow,
    ReportEnforcementRequest, ReportEnforcementResponse, ReportRecordsRequest,
    ReportRecordsResponse, WatchAssignmentRequest, WatchAssignmentResponse,
};
use codewire_server_core::pod_identity::PodIdentityError;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream,
};
use sqlx::PgPool;

use codewire_egress_node::replacement::StartLimiter;

use super::admission::{self, Reviewed};
use super::assignment::{AssignedPolicy, environment_policy};
use crate::runtime::RuntimeAttestation;
use crate::workspace_binding::BindingStore;

/// How often a watch re-reads a Pod's assignment and sends it if it changed.
/// Each re-read is one Pod GET and one or two indexed database reads, so a
/// hundred watched sandboxes cost about 50 Pod GETs and 50 to 100 database
/// reads a second. That is acceptable for the closed beta's few dozen
/// sandboxes. Before a deployment runs about a hundred broker-mode
/// sandboxes, this moves to reading only on change: the binding and policy
/// NOTIFY channels, and a per-node Pod watch.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// One destination every sandbox may reach whatever its policy: from the
/// deployment's configuration only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDestination {
    pub host: String,
    pub port: u16,
}

pub struct EgressServiceState {
    pub attestation: Arc<dyn RuntimeAttestation>,
    pub bindings: Arc<dyn BindingStore>,
    pub pool: PgPool,
    pub server_namespace: String,
    pub sandbox_namespace: String,
    pub platform: Vec<PlatformDestination>,
    /// Admissions per caller node and stream peer, counted before the
    /// guest's token is reviewed, so a guest flooding a cw-egress costs
    /// orchestration no review (#4000). cw-egress applies the same limit on
    /// its side before it calls.
    pub starts: std::sync::Mutex<HashMap<String, StartLimiter>>,
}

#[cfg(test)]
mod tests;

pub fn egress_router(state: Arc<EgressServiceState>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EgressConnectService { state }))
}

struct EgressConnectService {
    state: Arc<EgressServiceState>,
}

/// What a Pod is assigned, compared between watch reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Assignment {
    Unbound,
    Bound {
        environment_id: String,
        operation_generation: i64,
        policy: AssignedPolicy,
    },
}

/// A guest Pod named by name and UID; checked against its live Pod before
/// any use.
#[derive(Debug, Clone)]
struct GuestPod {
    namespace: String,
    name: String,
    uid: String,
}

impl GuestPod {
    fn reviewed(&self) -> Reviewed<'_> {
        Reviewed {
            namespace: &self.namespace,
            pod_name: &self.name,
            pod_uid: &self.uid,
        }
    }
}

/// The authenticated cw-egress behind a request, kept by a watch so it can
/// be checked again while the stream is open.
#[derive(Debug, Clone)]
struct Caller {
    namespace: String,
    name: String,
    uid: String,
    node: String,
    /// When the token it presented expires, on the runtime's clock; a watch
    /// ends then, and cw-egress opens it again with a fresh token.
    expires_at: tokio::time::Instant,
}

impl Caller {
    fn reviewed(&self) -> Reviewed<'_> {
        Reviewed {
            namespace: &self.namespace,
            pod_name: &self.name,
            pod_uid: &self.uid,
        }
    }
}

/// Consecutive failed Kubernetes reads a watch tolerates before it ends, so
/// one API blip does not send every stream on a node through a reconnect.
pub const WATCH_READ_FAILURES: u32 = 3;

/// The longest one recheck may take. A read that hangs past it counts as one
/// failed read, and a recheck never runs past the caller's token expiry.
pub const RECHECK_TIMEOUT: Duration = Duration::from_secs(5);

fn denied() -> ConnectError {
    ConnectError::permission_denied("egress is not admitted")
}

fn unavailable(what: &str, error: impl std::fmt::Display) -> ConnectError {
    tracing::warn!(%error, "egress service: {what}");
    ConnectError::unavailable("egress assignment is unavailable")
}

impl EgressServiceState {
    /// The caller, from its own reviewed token and live Pod.
    async fn caller(&self, ctx: &RequestContext) -> Result<Caller, ConnectError> {
        let identity = self
            .attestation
            .review_egress_node(ctx.headers(), &self.server_namespace)
            .await
            .map_err(|error| match error {
                PodIdentityError::PermissionDenied => denied(),
                PodIdentityError::Unavailable => unavailable("review the caller", "TokenReview"),
                _ => ConnectError::unauthenticated("egress node credential required"),
            })?;
        let caller = Caller {
            namespace: identity.namespace().to_owned(),
            name: identity.pod_name().to_owned(),
            uid: identity.pod_uid().to_owned(),
            node: String::new(),
            expires_at: tokio::time::Instant::now()
                + Duration::from_secs(identity.expires_at_unix().saturating_sub(unix_now())),
        };
        let node = self.caller_still_serving(&caller).await?;
        Ok(Caller { node, ..caller })
    }

    async fn caller_node(&self, ctx: &RequestContext) -> Result<String, ConnectError> {
        Ok(self.caller(ctx).await?.node)
    }

    /// The caller's node, read again from its live Pod: it must still be the
    /// reviewed cw-egress, in orchestration's own namespace.
    async fn caller_still_serving(&self, caller: &Caller) -> Result<String, ConnectError> {
        let facts = self
            .attestation
            .attested_pod(&caller.namespace, &caller.name)
            .await
            .map_err(|error| unavailable("read the caller Pod", error))?
            .ok_or_else(denied)?;
        admission::caller_node(caller.reviewed(), &facts, &self.server_namespace).map_err(
            |refusal| {
                tracing::warn!(?refusal, "egress caller refused");
                denied()
            },
        )
    }

    fn allow_start(&self, node: &str, peer: IpAddr) -> bool {
        self.starts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(node.to_owned())
            .or_default()
            .allow(peer, std::time::Instant::now())
    }

    /// A guest Pod as a request names it, in the sandbox namespace.
    fn named_guest(&self, name: &str, uid: &str) -> GuestPod {
        GuestPod {
            namespace: self.sandbox_namespace.clone(),
            name: name.to_owned(),
            uid: uid.to_owned(),
        }
    }

    /// The named guest Pod, if it is a broker-mode workspace on `node`.
    async fn guest_on_node(&self, guest: &GuestPod, node: &str) -> Result<(), ConnectError> {
        let facts = self
            .attestation
            .attested_pod(&guest.namespace, &guest.name)
            .await
            .map_err(|error| unavailable("read the guest Pod", error))?
            .ok_or_else(denied)?;
        admission::guest_on_node(guest.reviewed(), &facts, node, &self.sandbox_namespace).map_err(
            |refusal| {
                tracing::info!(?refusal, pod = %guest.name, "egress guest refused");
                denied()
            },
        )
    }

    async fn assignment(&self, guest: &GuestPod) -> Result<Assignment, ConnectError> {
        let binding = self
            .bindings
            .live_binding(&guest.uid, &guest.namespace, &guest.name)
            .await
            .map_err(|_| unavailable("read the binding", "binding store unavailable"))?;
        let Some(binding) = binding else {
            return Ok(Assignment::Unbound);
        };
        let policy = environment_policy(&self.pool, &binding.environment_id)
            .await
            .map_err(|error| unavailable("read the environment's policy", error))?;
        Ok(Assignment::Bound {
            environment_id: binding.environment_id,
            operation_generation: binding.operation_generation,
            policy,
        })
    }

    fn proto(&self, assignment: &Assignment) -> EgressAssignment {
        let binding = match assignment {
            Assignment::Unbound => Binding::Unbound(Box::default()),
            Assignment::Bound {
                environment_id,
                operation_generation,
                policy,
            } => Binding::Bound(Box::new(BoundAssignment {
                environment_id: environment_id.clone(),
                operation_generation: *operation_generation,
                policy: Some(EgressPolicyRevision {
                    reference: policy.name.clone(),
                    revision: policy.revision,
                    document: policy.document.clone(),
                    digest: policy.digest.to_vec(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })),
        };
        EgressAssignment {
            binding: Some(binding),
            platform_allows: self
                .platform
                .iter()
                .map(|destination| PlatformAllow {
                    host: destination.host.clone(),
                    port: u32::from(destination.port),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }
}

/// One Pod's assignment watch: the first message is the current
/// assignment, then each change. A Pod that leaves the caller's node, or
/// ends, gets one error and the stream ends.
struct Watch {
    state: Arc<EgressServiceState>,
    caller: Caller,
    guest: GuestPod,
    sent: Option<Assignment>,
    next: Option<Assignment>,
    read_failures: u32,
    ended: bool,
}

impl Watch {
    async fn step(mut self) -> Option<(Result<WatchAssignmentResponse, ConnectError>, Self)> {
        if self.ended {
            return None;
        }
        loop {
            if let Some(assignment) = self.next.take()
                && self.sent.as_ref() != Some(&assignment)
            {
                let message = WatchAssignmentResponse {
                    assignment: Some(self.state.proto(&assignment)).into(),
                    ..Default::default()
                };
                self.sent = Some(assignment);
                return Some((Ok(message), self));
            }
            tokio::time::sleep(WATCH_INTERVAL).await;
            if let Err(error) = self.recheck().await {
                if error.code == connectrpc::ErrorCode::Unavailable
                    && self.read_failures < WATCH_READ_FAILURES
                {
                    self.read_failures += 1;
                    continue;
                }
                self.ended = true;
                return Some((Err(error), self));
            }
            self.read_failures = 0;
            // A failed read keeps the last assignment; cw-egress enforces it.
            match self.state.assignment(&self.guest).await {
                Ok(assignment) => self.next = Some(assignment),
                Err(error) => tracing::warn!(?error, "egress watch kept the last assignment"),
            }
            // A read that straddled the token's expiry sends nothing.
            if tokio::time::Instant::now() >= self.caller.expires_at {
                self.ended = true;
                return Some((
                    Err(ConnectError::unauthenticated(
                        "egress node credential expired",
                    )),
                    self,
                ));
            }
        }
    }

    /// The caller's token has not expired, the caller is still the same
    /// cw-egress on the same node, and the guest is still on that node.
    async fn recheck(&self) -> Result<(), ConnectError> {
        let expired = || ConnectError::unauthenticated("egress node credential expired");
        let left = self
            .caller
            .expires_at
            .saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(expired());
        }
        let deadline = RECHECK_TIMEOUT.min(left);
        let reads = async {
            if self.state.caller_still_serving(&self.caller).await? != self.caller.node {
                return Err(denied());
            }
            self.state
                .guest_on_node(&self.guest, &self.caller.node)
                .await
        };
        let result = match tokio::time::timeout(deadline, reads).await {
            Ok(result) => result,
            Err(_) => Err(unavailable("recheck the stream", "a read timed out")),
        };
        // The token may have run out while the reads waited.
        if tokio::time::Instant::now() >= self.caller.expires_at {
            return Err(expired());
        }
        result
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[allow(refining_impl_trait)]
impl EgressService for EgressConnectService {
    async fn admit(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AdmitRequest>,
    ) -> ServiceResult<AdmitResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.view();
        let peer: IpAddr = request.peer_ip.parse().map_err(|_| denied())?;
        if !self.state.allow_start(&node, peer) {
            tracing::info!(%peer, %node, "egress stream starts limited");
            return Err(ConnectError::resource_exhausted(
                "egress stream starts are limited; retry shortly",
            ));
        }
        let identity = self
            .state
            .attestation
            .review_egress_guest(request.guest_token, &self.state.sandbox_namespace)
            .await
            .map_err(|error| match error {
                PodIdentityError::Unavailable => unavailable("review the guest", "TokenReview"),
                _ => denied(),
            })?;
        let guest = GuestPod {
            namespace: identity.namespace().to_owned(),
            name: identity.pod_name().to_owned(),
            uid: identity.pod_uid().to_owned(),
        };
        let facts = self
            .state
            .attestation
            .attested_pod(&guest.namespace, &guest.name)
            .await
            .map_err(|error| unavailable("read the guest Pod", error))?
            .ok_or_else(denied)?;
        admission::admit_guest(
            guest.reviewed(),
            &facts,
            &node,
            peer,
            &self.state.sandbox_namespace,
        )
        .map_err(|refusal| {
            tracing::info!(?refusal, pod = %guest.name, "egress stream refused");
            denied()
        })?;
        let assignment = self.state.assignment(&guest).await?;
        connectrpc::Response::ok(AdmitResponse {
            pod_uid: guest.uid,
            pod_name: guest.name,
            assignment: Some(self.state.proto(&assignment)).into(),
            ..Default::default()
        })
    }

    async fn watch_assignment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WatchAssignmentRequest>,
    ) -> ServiceResult<ServiceStream<WatchAssignmentResponse>> {
        let caller = self.state.caller(&ctx).await?;
        let request = request.view();
        let guest = self.state.named_guest(request.pod_name, request.pod_uid);
        self.state.guest_on_node(&guest, &caller.node).await?;
        let first = self.state.assignment(&guest).await?;
        let watch = Watch {
            state: Arc::clone(&self.state),
            caller,
            guest,
            sent: None,
            next: Some(first),
            read_failures: 0,
            ended: false,
        };
        let stream = futures::stream::unfold(watch, Watch::step);
        connectrpc::Response::stream_ok(stream)
    }

    async fn report_enforcement(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportEnforcementRequest>,
    ) -> ServiceResult<ReportEnforcementResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.view();
        let guest = self.state.named_guest(request.pod_name, request.pod_uid);
        self.state.guest_on_node(&guest, &node).await?;
        Err(ConnectError::unimplemented(
            "enforcement reports are stored from a later change",
        ))
    }

    async fn report_records(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportRecordsRequest>,
    ) -> ServiceResult<ReportRecordsResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.view();
        let guest = self.state.named_guest(request.pod_name, request.pod_uid);
        self.state.guest_on_node(&guest, &node).await?;
        Err(ConnectError::unimplemented(
            "egress records are stored from a later change",
        ))
    }

    async fn front_door_session(
        &self,
        ctx: RequestContext,
        _requests: InboundStream<FrontDoorSessionRequest>,
    ) -> ServiceResult<ServiceStream<FrontDoorSessionResponse>> {
        // Authenticated now, so a caller sees the final answer to the wrong
        // identity; the session itself is served from a later change (#4001).
        self.state.caller_node(&ctx).await?;
        Err(ConnectError::unimplemented(
            "front-door sessions are served from a later change",
        ))
    }
}
