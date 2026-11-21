//! `EgressService` on the internal-connect listener (#4000). Every method
//! first authenticates cw-egress by TokenReview of its own token and reads
//! its node from its live Pod; every method that names a guest Pod refuses
//! one that is not on that node.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::PoisonError;
use std::time::Duration;

use codewire_access::ManagedCredentialClients;
use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_assignment::Binding;
use codewire_proto::codewire::internal::v1::{
    AdmitRequest, AdmitResponse, BoundAssignment, EgressAssignment, EgressPolicyRevision,
    EgressService, FrontDoorSessionRequest, FrontDoorSessionResponse, InterceptionBinding,
    PlatformAllow, ReportEnforcementRequest, ReportEnforcementResponse, ReportRecordsRequest,
    ReportRecordsResponse, SignInterceptionLeavesRequest, SignInterceptionLeavesResponse,
    WatchAssignmentRequest, WatchAssignmentResponse,
};
use codewire_server_core::pod_identity::PodIdentityError;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream,
};
use sqlx::PgPool;

use codewire_egress_node::replacement::StartLimiter;

use super::admission::{self, Reviewed};
use super::assignment::{AssignedPolicy, Intercept, environment_policy, interception_bindings};
use super::lockdown;
use super::reports;

mod wire;
use crate::runtime::{Isolation, RuntimeAttestation};
use crate::workspace_binding::BindingStore;
use crate::workspace_binding::store::LiveBinding;

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
    /// Whether bound sandboxes intercept (#4001): each gets the bindings for
    /// its own binding's clients, or none when this is off. An unbound
    /// warm-pool member never gets them. Only a broker-mode sandbox gets an
    /// assignment at all (`admission::guest_on_node`), so this is the
    /// setting AND-ed with broker mode, as the bind response's is.
    pub interception: bool,
    /// Admissions per caller node and stream peer, counted before the
    /// guest's token is reviewed, so a guest flooding a cw-egress costs
    /// orchestration no review (#4000). cw-egress applies the same limit on
    /// its side before it calls.
    pub starts: std::sync::Mutex<HashMap<String, StartLimiter>>,
    /// The credential relay's admitted epochs on this process (#4001).
    /// `None` while hosted interception is off: `FrontDoorSession` answers
    /// UNIMPLEMENTED to an authenticated caller.
    pub front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
    /// The CA certificates of intercepting sandboxes, when interception is
    /// on (#4001).
    pub interception_cas: Option<Arc<dyn super::interception_ca::InterceptionCaSource>>,
}

mod front_door;
#[cfg(test)]
mod tests;

pub fn egress_router(state: Arc<EgressServiceState>) -> connectrpc::Router {
    connectrpc::Router::new()
        .add_service(Arc::new(EgressConnectService { state }))
        .with_route_limits(
            "/codewire.internal.v1.EgressService/FrontDoorSession",
            connectrpc::Limits::default().with_max_message_size(front_door::MAX_MESSAGE_BYTES),
        )
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
        /// The hosts its front door serves, from the binding's clients.
        intercepts: Vec<Intercept>,
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

/// How long a watch withholds a bound assignment whose lockdown is not
/// applied before it ends, failing closed. A claim records the binding as
/// soon as the Pod is bind-ready and applies the environment's NetworkPolicy
/// with the access stack afterwards, so a watch can read the binding first;
/// until the policy is the rendered one the member stays unbound, on
/// `locked`.
pub const LOCKDOWN_BIND_GRACE: Duration = Duration::from_secs(30);

fn invalid_report() -> ConnectError {
    ConnectError::invalid_argument("the report is not well formed")
}

fn denied() -> ConnectError {
    ConnectError::permission_denied("egress is not admitted")
}

/// The hosts a bound sandbox's front door serves, from its binding's encoded
/// clients, or none while the deployment doesn't intercept. The encoding is
/// read only while it does; then one this build can't read withholds the
/// assignment, so the sandbox has no egress rather than another selection's
/// hosts.
fn binding_intercepts(interception: bool, encoded: &str) -> Result<Vec<Intercept>, ConnectError> {
    if !interception {
        return Ok(Vec::new());
    }
    let clients = ManagedCredentialClients::decode(encoded)
        .map_err(|error| unavailable("read the binding's credential clients", error))?;
    interception_bindings(true, clients)
        .map_err(|error| unavailable("select the binding's interception hosts", error))
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

    /// The out-of-band half of the self-check (#4000 P6, #4964): the
    /// NetworkPolicy the cluster holds for the environment `binding` records
    /// is the one orchestration renders for it and selects the guest, and
    /// every other policy that selects the guest is its template's as
    /// orchestration renders it, or allows nothing. `Some` is why it is not;
    /// an error is a read that could not be made, never a pass.
    /// Nothing the guest reports is read here. A pass clears a refusal stored
    /// for the guest earlier (#5068).
    async fn lockdown_refusal(
        &self,
        guest: &GuestPod,
        facts: &crate::runtime::MemberFacts,
        binding: &LiveBinding,
    ) -> Result<Option<lockdown::LockdownRefusal>, ConnectError> {
        let isolation = Isolation::of_tier(&binding.isolation_tier)
            .map_err(|error| unavailable("read the environment's isolation", error))?;
        let rendered = self
            .attestation
            .rendered_workspace_network_policy(&guest.namespace, &binding.environment_id, isolation)
            .map_err(|error| unavailable("render the guest's NetworkPolicy", error))?;
        let rendered_template = match lockdown::template_ref_hash(facts) {
            Some(hash) => self
                .attestation
                .rendered_template_network_policy(isolation, hash)
                .map_err(|error| unavailable("render the guest's template NetworkPolicy", error))?,
            None => None,
        };
        let live = self
            .attestation
            .workspace_network_policies(&guest.namespace)
            .await
            .map_err(|error| unavailable("read the guest's NetworkPolicies", error))?;
        let refusal = lockdown::lockdown_applied(
            facts,
            &binding.environment_id,
            rendered.as_ref(),
            rendered_template.as_ref(),
            &live,
        )
        .err();
        if refusal.is_none()
            && let Err(error) = reports::clear_lockdown_refusal(&self.pool, &guest.uid).await
        {
            tracing::warn!(%error, pod = %guest.name, "clearing a passed lockdown's refusal failed");
        }
        Ok(refusal)
    }

    /// The guest fails closed for `refusal`, as it does for a failed probe:
    /// counted by reason, logged, and recorded as its enforcement status
    /// (#5068). A failed record is logged and changes nothing else: the
    /// stream ends either way.
    async fn failed_closed(
        &self,
        guest: &GuestPod,
        refusal: &lockdown::LockdownRefusal,
    ) -> ConnectError {
        lockdown::count_failed_closed(refusal);
        if let Err(error) = reports::record_lockdown_refusal(&self.pool, &guest.uid, refusal).await
        {
            tracing::warn!(%error, pod = %guest.name, "recording a lockdown refusal failed");
        }
        let policy = match refusal {
            lockdown::LockdownRefusal::PolicyDiffers { policy } => Some(policy.as_str()),
            _ => None,
        };
        tracing::warn!(
            reason = refusal.reason(),
            pod = %guest.name,
            namespace = %guest.namespace,
            policy,
            outcome = "self_check_failed",
            "egress lockdown is not applied; the sandbox fails closed"
        );
        denied()
    }

    /// [`Self::lockdown_refusal`] for Admit: a refusal fails the stream
    /// closed at once.
    async fn lockdown_applied(
        &self,
        guest: &GuestPod,
        facts: &crate::runtime::MemberFacts,
        binding: &LiveBinding,
    ) -> Result<(), ConnectError> {
        match self.lockdown_refusal(guest, facts, binding).await? {
            Some(refusal) => Err(self.failed_closed(guest, &refusal).await),
            None => Ok(()),
        }
    }

    /// What a watch of `guest` may send now. A binding to an environment the
    /// stream has not been sent as bound to (`bound_to`) is a first bound
    /// assignment: a member admitted unbound and since claimed, or a guest
    /// whose watch has just opened. Its lockdown is checked before the
    /// assignment is read, exactly as Admit checks it, and a refusal
    /// withholds it.
    async fn watched_assignment(
        &self,
        guest: &GuestPod,
        bound_to: Option<&str>,
    ) -> Result<Watched, ConnectError> {
        let binding = self.live_binding(guest).await?;
        if let Some(binding) = &binding
            && bound_to != Some(binding.environment_id.as_str())
        {
            let facts = self
                .attestation
                .attested_pod(&guest.namespace, &guest.name)
                .await
                .map_err(|error| unavailable("read the guest Pod", error))?
                .ok_or_else(denied)?;
            if let Some(refusal) = self.lockdown_refusal(guest, &facts, binding).await? {
                return Ok(Watched::Withheld(refusal));
            }
        }
        Ok(Watched::Assignment(self.assignment_of(binding).await?))
    }

    /// Whether `guest`'s streams intercept. Hosted interception is decided
    /// once per Pod, at its first bind, and recorded on the binding (C5,
    /// #5468); an unbound warm member has no decision yet, and the setting,
    /// which its first bind will record, decides. Until the binding carries
    /// that decision (#5496), the setting decides for a bound Pod too.
    fn intercepts(&self, _binding: Option<&LiveBinding>) -> bool {
        self.interception
    }

    /// The guest's interception CA certificate, or nothing when it does not
    /// intercept. An intercepting guest whose certificate can't be had is
    /// refused rather than admitted with an empty trust frame: the guest
    /// keeps the trust of its first session for the Pod's life (#5006), so an
    /// empty one would refuse every later session that carries the CA. It
    /// redials instead.
    async fn interception_ca(
        &self,
        guest: &GuestPod,
        binding: Option<&LiveBinding>,
    ) -> Result<Vec<u8>, ConnectError> {
        if !self.intercepts(binding) {
            return Ok(Vec::new());
        }
        let source = self
            .interception_cas
            .as_ref()
            .ok_or_else(|| unavailable("get the interception CA", "no source"))?;
        source
            .ensure(&guest.uid, &guest.name)
            .await
            .map_err(|error| unavailable("get the interception CA", error))
    }

    /// Orchestration's own record of whether `guest` is bound, and to what.
    async fn live_binding(&self, guest: &GuestPod) -> Result<Option<LiveBinding>, ConnectError> {
        self.bindings
            .live_binding(&guest.uid, &guest.namespace, &guest.name)
            .await
            .map_err(|_| unavailable("read the binding", "binding store unavailable"))
    }

    async fn assignment_of(
        &self,
        binding: Option<LiveBinding>,
    ) -> Result<Assignment, ConnectError> {
        let Some(binding) = binding else {
            return Ok(Assignment::Unbound);
        };
        let policy = environment_policy(&self.pool, &binding.environment_id)
            .await
            .map_err(|error| unavailable("read the environment's policy", error))?;
        let intercepts =
            binding_intercepts(self.interception, &binding.managed_credential_clients)?;
        Ok(Assignment::Bound {
            environment_id: binding.environment_id,
            operation_generation: binding.operation_generation,
            policy,
            intercepts,
        })
    }

    fn proto(&self, assignment: &Assignment) -> EgressAssignment {
        let binding = match assignment {
            Assignment::Unbound => Binding::Unbound(Box::default()),
            Assignment::Bound {
                environment_id,
                operation_generation,
                policy,
                intercepts,
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
                interception: !intercepts.is_empty(),
                interception_bindings: intercepts
                    .iter()
                    .map(|intercept| InterceptionBinding {
                        host: intercept.binding.hostname().to_owned(),
                        port: u32::from(intercept.binding.port()),
                        suffix: intercept.suffix,
                        ..Default::default()
                    })
                    .collect(),
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

/// What one read of a watched Pod's assignment found.
enum Watched {
    Assignment(Assignment),
    /// The Pod is bound, but its lockdown is not applied: the bound
    /// assignment is not sent.
    Withheld(lockdown::LockdownRefusal),
}

/// One Pod's assignment watch: the first message is the current
/// assignment, then each change. A Pod that leaves the caller's node, or
/// ends, gets one error and the stream ends.
///
/// A bound assignment is sent only after the lockdown check passes for it
/// (#4000 P6). While the check refuses, the stream says unbound, so the
/// member stays on `locked`; a refusal that outlasts
/// [`LOCKDOWN_BIND_GRACE`] ends the stream, failing closed.
struct Watch {
    state: Arc<EgressServiceState>,
    caller: Caller,
    guest: GuestPod,
    sent: Option<Assignment>,
    next: Option<Assignment>,
    /// When the bound assignment now withheld was first refused.
    withheld_since: Option<tokio::time::Instant>,
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
            match self
                .state
                .watched_assignment(&self.guest, self.bound_to())
                .await
            {
                Ok(watched) => {
                    if let Err(error) = self.take(watched).await {
                        self.ended = true;
                        return Some((Err(error), self));
                    }
                }
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

    /// The environment this stream was last sent as bound to, if any.
    fn bound_to(&self) -> Option<&str> {
        match &self.sent {
            Some(Assignment::Bound { environment_id, .. }) => Some(environment_id),
            Some(Assignment::Unbound) | None => None,
        }
    }

    /// Take one read as what to send next. A withheld bound assignment is
    /// sent as unbound; once it has been withheld for
    /// [`LOCKDOWN_BIND_GRACE`] the watch ends instead, failing closed.
    async fn take(&mut self, watched: Watched) -> Result<(), ConnectError> {
        match watched {
            Watched::Assignment(assignment) => {
                self.withheld_since = None;
                self.next = Some(assignment);
            }
            Watched::Withheld(refusal) => {
                let now = tokio::time::Instant::now();
                let since = *self.withheld_since.get_or_insert_with(|| {
                    tracing::info!(
                        reason = refusal.reason(),
                        pod = %self.guest.name,
                        "egress watch withholds a bound assignment until the lockdown is applied"
                    );
                    now
                });
                if now.duration_since(since) >= LOCKDOWN_BIND_GRACE {
                    return Err(self.state.failed_closed(&self.guest, &refusal).await);
                }
                self.next = Some(Assignment::Unbound);
            }
        }
        Ok(())
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
        let binding = self.state.live_binding(&guest).await?;
        // An unbound warm member has no environment policy yet: its lockdown
        // is the shared template's, and it is assigned nothing of an
        // environment's. Its watch checks the lockdown before its first
        // bound assignment.
        if let Some(binding) = &binding {
            self.state.lockdown_applied(&guest, &facts, binding).await?;
        }
        let ca_certificate_der = self.state.interception_ca(&guest, binding.as_ref()).await?;
        let assignment = self.state.assignment_of(binding).await?;
        connectrpc::Response::ok(AdmitResponse {
            pod_uid: guest.uid,
            pod_name: guest.name,
            assignment: Some(self.state.proto(&assignment)).into(),
            ca_certificate_der,
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
        let first = self.state.watched_assignment(&guest, None).await?;
        let mut watch = Watch {
            state: Arc::clone(&self.state),
            caller,
            guest,
            sent: None,
            next: None,
            withheld_since: None,
            read_failures: 0,
            ended: false,
        };
        watch.take(first).await?;
        let stream = futures::stream::unfold(watch, Watch::step);
        connectrpc::Response::stream_ok(stream)
    }

    async fn report_enforcement(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportEnforcementRequest>,
    ) -> ServiceResult<ReportEnforcementResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.to_owned_message();
        let guest = self.state.named_guest(&request.pod_name, &request.pod_uid);
        self.state.guest_on_node(&guest, &node).await?;
        let enforcement = wire::enforcement(&request).ok_or_else(invalid_report)?;
        reports::record_enforcement(&self.state.pool, &guest.uid, &node, &enforcement)
            .await
            .map_err(|error| match error {
                reports::ReportError::Store(error) => {
                    unavailable("store the enforcement report", error)
                }
                // A retry cannot fix it.
                _ => invalid_report(),
            })?;
        connectrpc::Response::ok(ReportEnforcementResponse::default())
    }

    async fn report_records(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportRecordsRequest>,
    ) -> ServiceResult<ReportRecordsResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.to_owned_message();
        let guest = self.state.named_guest(&request.pod_name, &request.pod_uid);
        self.state.guest_on_node(&guest, &node).await?;
        if request.records.len() > reports::MAX_RECORDS_PER_REPORT {
            return Err(invalid_report());
        }
        let records = request
            .records
            .iter()
            .map(wire::record)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid_report)?;
        match reports::record_records(&self.state.pool, &guest.uid, &records).await {
            // An unbound warm member has no log; its records are dropped.
            Ok(_) => connectrpc::Response::ok(ReportRecordsResponse::default()),
            Err(reports::ReportError::Store(error)) => {
                Err(unavailable("store the egress records", error))
            }
            Err(_) => Err(invalid_report()),
        }
    }

    async fn front_door_session(
        &self,
        ctx: RequestContext,
        requests: InboundStream<FrontDoorSessionRequest>,
    ) -> ServiceResult<ServiceStream<FrontDoorSessionResponse>> {
        self.state.front_door_session(&ctx, requests).await
    }

    async fn sign_interception_leaves(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SignInterceptionLeavesRequest>,
    ) -> ServiceResult<SignInterceptionLeavesResponse> {
        let node = self.state.caller_node(&ctx).await?;
        let request = request.view();
        let guest = self.state.named_guest(request.pod_name, request.pod_uid);
        self.state.guest_on_node(&guest, &node).await?;
        match self.state.live_binding(&guest).await? {
            Some(binding) if self.state.intercepts(Some(&binding)) => {}
            _ => return Err(denied()),
        }
        // Signing goes through the Pod's live relay epoch, which a later
        // change attaches (#4001); until then cw-egress retries, and the
        // front door's hosts fail closed.
        Err(ConnectError::unavailable(
            "interception leaves are not signed yet",
        ))
    }
}
