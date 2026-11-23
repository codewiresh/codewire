//! Placement-neutral admission core for one Codewire egress broker.
//!
//! This crate owns no process, credential, or audit sink. It composes the pure
//! policy/lease state with injected resolver, connector, and monotonic-clock
//! ports, supplies bounded host DNS/TCP adapters for general egress, and, on
//! Unix, defines the authenticated capability IPC used to reach that core
//! across a confinement boundary.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::intercept::InterceptSet;
use codewire_egress_policy::lease::{
    Admission, AdmittedDnsQuery, AdmittedDnsResolution, DnsResolution, EgressLeaseTable,
    EstablishedFlow, InterceptReplacement, LeaseError, LeaseInstant, PolicyReplacement,
    Readmission, Refusal, RefusalCounts, RefusalReason, TcpAdmission, TcpInterception, TcpVerdict,
};
use codewire_egress_policy::record::{Destination, Transport};
use codewire_egress_policy::{CompiledPolicy, PolicyDecision, PolicyDigest, RouteClass};
use thiserror::Error;
use tokio::sync::Mutex;

pub mod adapters;
pub mod handoff;
mod intercept;
#[cfg(unix)]
pub mod ipc;
pub mod records;
pub mod refusals;

pub use intercept::{InterceptHandoff, InterceptRevision};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordFamily {
    Ipv4,
    Ipv6,
}

impl DnsRecordFamily {
    fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    fn accepts(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResolverRequest {
    name: String,
    family: DnsRecordFamily,
}

impl DnsResolverRequest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn family(&self) -> DnsRecordFamily {
        self.family
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResolverOutcome {
    Positive(DnsResolution),
    NoData,
    NameError,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerAdapterFailure {
    #[error("adapter unavailable")]
    Unavailable,
    #[error("adapter timed out")]
    Timeout,
    #[error("adapter returned malformed data")]
    Malformed,
}

#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    /// Resolve one canonical policy-admitted name.
    async fn resolve(
        &self,
        request: DnsResolverRequest,
    ) -> Result<DnsResolverOutcome, BrokerAdapterFailure>;
}

#[async_trait]
pub trait TcpConnector: Send + Sync + 'static {
    type Stream: Send + 'static;

    /// Connect the exact already-admitted destination without resolving it.
    async fn connect(&self, destination: SocketAddr) -> Result<Self::Stream, BrokerAdapterFailure>;
}

pub trait BrokerClock: Send + Sync + 'static {
    fn now(&self) -> LeaseInstant;
}

#[derive(Clone, Debug)]
pub struct SystemBrokerClock {
    epoch: Instant,
}

impl SystemBrokerClock {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemBrokerClock {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerClock for SystemBrokerClock {
    fn now(&self) -> LeaseInstant {
        let milliseconds = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        LeaseInstant::from_millis(milliseconds)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerDnsResponse {
    Positive(AdmittedDnsResolution),
    NoData(AdmittedDnsQuery),
    NameError(AdmittedDnsQuery),
}

#[derive(Debug)]
pub struct BrokerTcpConnection<S> {
    stream: S,
    admission: TcpAdmission,
    revision: InterceptRevision,
}

impl<S> BrokerTcpConnection<S> {
    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn admission(&self) -> &TcpAdmission {
        &self.admission
    }

    /// The interception set the dial was admitted under, for
    /// [`PolicyEgressBroker::record_passed_flow`].
    pub fn intercept_revision(&self) -> InterceptRevision {
        self.revision
    }

    pub fn into_parts(self) -> (S, TcpAdmission) {
        (self.stream, self.admission)
    }
}

/// What the table admitted a dial to: dial it, or hand it to the front door.
#[derive(Debug, PartialEq, Eq)]
pub enum TcpAuthorization {
    Dial(TcpAdmission),
    Intercept(TcpInterception),
}

/// A connection the broker made for the worker: dialled, or the worker's end
/// of a stream handed to the front door.
#[derive(Debug)]
pub enum BrokerConnection<S> {
    Dialled(BrokerTcpConnection<S>),
    Intercepted {
        stream: OwnedFd,
        interception: TcpInterception,
        revision: InterceptRevision,
    },
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("egress policy denied request")]
    Denied(PolicyDecision),
    #[error("egress policy state rejected request")]
    Policy(#[from] LeaseError),
    #[error("egress resolver failed: {0}")]
    Resolver(BrokerAdapterFailure),
    #[error("egress connector failed: {0}")]
    Connector(BrokerAdapterFailure),
    #[error("egress resolver returned an address outside the requested family")]
    MalformedDnsAnswer,
    #[error("the egress policy was replaced while the dial was in progress")]
    PolicyReplaced,
    #[error("the interception set was replaced while the dial was in progress")]
    InterceptsReplaced,
    #[error("the broker already holds its maximum of passed flows")]
    TooManyPassedFlows,
}

/// At most this many passed flows are recorded at once. It is above every
/// worker's own bound on the flows it holds (its netstack's connections and
/// the dials waiting for their SYN), so it only refuses a worker that leaks.
pub const MAX_PASSED_FLOWS: usize = 1024;

/// A TCP flow the broker dialed and passed on, which it ends if a later
/// policy revision refuses it (#2537). The broker keeps it only while it can
/// still carry traffic.
pub trait PassedFlow: Send + Sync + 'static {
    /// Whether the flow has ended where it was passed, in both directions.
    fn finished(&self) -> bool;
    /// End the flow in both directions, wherever it is held.
    fn end(&self);
}

/// How a passed flow was admitted, judged again on every replacement.
enum PassedAdmission {
    Dialled(TcpAdmission),
    Intercepted(TcpInterception),
}

impl<'a> From<&'a PassedAdmission> for EstablishedFlow<'a> {
    fn from(admission: &'a PassedAdmission) -> Self {
        match admission {
            PassedAdmission::Dialled(admission) => EstablishedFlow::Dialled(admission),
            PassedAdmission::Intercepted(interception) => {
                EstablishedFlow::Intercepted(interception)
            }
        }
    }
}

struct PassedFlows {
    next: u64,
    flows: BTreeMap<u64, (Box<dyn PassedFlow>, PassedAdmission)>,
}

impl PassedFlows {
    fn forget_finished(&mut self) {
        self.flows.retain(|_, (flow, _)| !flow.finished());
    }
}

pub struct PolicyEgressBroker<R, C, K> {
    route_class: RouteClass,
    state: Mutex<EgressLeaseTable>,
    /// Taken only while `state` is held, so a replacement sees every passed
    /// flow and no flow is recorded against a replaced revision.
    passed: std::sync::Mutex<PassedFlows>,
    /// Without one, an intercepted dial is refused and never dialled.
    handoff: Option<Arc<dyn InterceptHandoff>>,
    /// Bumped by every [`Self::replace_intercepts`], only while `state` is
    /// held; a flow admitted under an older set is not recorded.
    intercept_revision: AtomicU64,
    /// Where each refusal is folded for the owner's log (#5058), when the
    /// broker reports them.
    refusals: Option<Arc<refusals::RefusalFold>>,
    resolver: Arc<R>,
    connector: Arc<C>,
    clock: Arc<K>,
}

impl<R, C, K> PolicyEgressBroker<R, C, K>
where
    R: DnsResolver,
    C: TcpConnector,
    K: BrokerClock,
{
    pub fn new(
        policy: CompiledPolicy,
        route_class: RouteClass,
        resolver: Arc<R>,
        connector: Arc<C>,
        clock: Arc<K>,
    ) -> Self {
        Self {
            route_class,
            state: Mutex::new(EgressLeaseTable::new(policy)),
            passed: std::sync::Mutex::new(PassedFlows {
                next: 0,
                flows: BTreeMap::new(),
            }),
            handoff: None,
            intercept_revision: AtomicU64::new(0),
            refusals: None,
            resolver,
            connector,
            clock,
        }
    }

    /// Hand intercepted dials to `handoff` instead of refusing them.
    pub fn with_intercept_handoff(mut self, handoff: Arc<dyn InterceptHandoff>) -> Self {
        self.handoff = Some(handoff);
        self
    }

    /// Fold every refusal into `fold`, for the owner's log (#5058).
    pub fn with_refusal_fold(mut self, fold: Arc<refusals::RefusalFold>) -> Self {
        self.refusals = Some(fold);
        self
    }

    /// Folds `refusal` of `destination`, when the broker reports refusals.
    pub(crate) fn note(
        &self,
        destination: Destination,
        address: Option<IpAddr>,
        transport: Transport,
        refusal: &Refusal,
    ) -> PolicyDecision {
        if let Some(fold) = &self.refusals {
            fold.record(
                destination,
                address,
                transport,
                refusal.reason(),
                refusal.decision().policy_digest,
            );
        }
        refusal.decision().clone()
    }

    /// A refused dial or datagram to `address`, under the name of the lease
    /// that points at it when one does.
    pub(crate) fn note_dial(
        &self,
        state: &EgressLeaseTable,
        address: IpAddr,
        transport: Transport,
        refusal: &Refusal,
    ) -> PolicyDecision {
        let name = state
            .lease_name_at(address, self.route_class)
            .map(Destination::checked_name);
        self.note(
            name.unwrap_or(Destination::Address(address)),
            Some(address),
            transport,
            refusal,
        )
    }

    /// Refuse a guest UDP datagram to `destination`, which the worker
    /// dropped (#3997): counted and folded as a refused dial is, so the
    /// owner's log shows it. Nothing reaches the destination either way.
    pub async fn refuse_udp(&self, destination: SocketAddr) {
        let state = self.state.lock().await;
        let refusal = state.refuse_udp();
        let transport = Transport::Udp {
            port: destination.port(),
        };
        self.note_dial(&state, destination.ip(), transport, &refusal);
    }

    pub fn route_class(&self) -> RouteClass {
        self.route_class
    }

    pub async fn policy_digest(&self) -> PolicyDigest {
        self.state.lock().await.policy_digest()
    }

    /// Refusals by reason since start, never a name or an address. They are
    /// the only place a refusal's reason is visible (#2537): every refused
    /// lookup looks the same to the guest.
    pub async fn refusal_counts(&self) -> RefusalCounts {
        self.state.lock().await.refusal_counts()
    }

    /// Enforce `policy` from now on (#2537): later lookups and dials see only
    /// it, every lease it refuses is dropped, and every passed flow it refuses
    /// is ended. Nothing observes the broker between the two revisions.
    pub async fn replace_policy(&self, policy: CompiledPolicy) -> PolicyReplacement<u64> {
        let mut state = self.state.lock().await;
        let mut passed = self
            .passed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        passed.forget_finished();
        let replacement = state.replace_policy(
            policy,
            passed
                .flows
                .iter()
                .map(|(key, (_, admission))| (*key, admission)),
            self.clock.now(),
        );
        for key in replacement.refused_flows() {
            if let Some((flow, _)) = passed.flows.remove(key) {
                flow.end();
            }
        }
        replacement
    }

    /// Replace the interception bindings (#3999), as [`Self::replace_policy`]
    /// replaces the policy: every passed flow whose outcome changes is ended.
    pub async fn replace_intercepts(&self, intercepts: InterceptSet) -> InterceptReplacement<u64> {
        let mut state = self.state.lock().await;
        let mut passed = self
            .passed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        passed.forget_finished();
        self.intercept_revision.fetch_add(1, Ordering::AcqRel);
        let replacement = state.replace_intercepts(
            intercepts,
            passed
                .flows
                .iter()
                .map(|(key, (_, admission))| (*key, admission)),
            self.clock.now(),
        );
        for key in replacement.reset_flows() {
            if let Some((flow, _)) = passed.flows.remove(key) {
                flow.end();
            }
        }
        replacement
    }

    /// Record a flow `connect_tcp` admitted before it is passed on, so a later
    /// revision can end it. It is refused when the policy was replaced since
    /// its admission, or when the record holds [`MAX_PASSED_FLOWS`] live flows;
    /// the caller then drops the connection instead of passing it.
    pub async fn record_passed_flow(
        &self,
        admission: TcpAdmission,
        revision: InterceptRevision,
        flow: Box<dyn PassedFlow>,
    ) -> Result<(), BrokerError> {
        let digest = admission.decision().policy_digest;
        self.record(digest, revision, PassedAdmission::Dialled(admission), flow)
            .await
    }

    /// Record an intercepted flow before it is passed on, as
    /// [`Self::record_passed_flow`] records a dialled one.
    pub async fn record_intercepted_flow(
        &self,
        interception: TcpInterception,
        revision: InterceptRevision,
        flow: Box<dyn PassedFlow>,
    ) -> Result<(), BrokerError> {
        let digest = interception.policy_digest();
        self.record(
            digest,
            revision,
            PassedAdmission::Intercepted(interception),
            flow,
        )
        .await
    }

    async fn record(
        &self,
        digest: PolicyDigest,
        revision: InterceptRevision,
        admission: PassedAdmission,
        flow: Box<dyn PassedFlow>,
    ) -> Result<(), BrokerError> {
        let state = self.state.lock().await;
        if digest != state.policy_digest() {
            return Err(BrokerError::PolicyReplaced);
        }
        if revision != self.current_intercept_revision() {
            return Err(BrokerError::InterceptsReplaced);
        }
        let mut passed = self
            .passed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if passed.flows.len() >= MAX_PASSED_FLOWS {
            passed.forget_finished();
        }
        if passed.flows.len() >= MAX_PASSED_FLOWS {
            return Err(BrokerError::TooManyPassedFlows);
        }
        let key = passed.next;
        passed.next += 1;
        passed.flows.insert(key, (flow, admission));
        Ok(())
    }

    /// Passed flows that can still carry traffic.
    pub async fn passed_flows(&self) -> usize {
        let _state = self.state.lock().await;
        let mut passed = self
            .passed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        passed.forget_finished();
        passed.flows.len()
    }

    /// Replace the addresses local to the host this broker dials from (#2614);
    /// later admissions, including a dial already authorized, refuse them.
    pub async fn set_host_addresses(&self, addresses: HostAddressSet) {
        self.state.lock().await.set_host_addresses(addresses);
    }

    /// Resolve only after the policy admits the canonical query, then bind the
    /// complete bounded answer set into expiring TCP evidence.
    pub async fn resolve_dns(
        &self,
        name: &str,
        family: DnsRecordFamily,
    ) -> Result<BrokerDnsResponse, BrokerError> {
        let query = {
            let state = self.state.lock().await;
            match state.authorize_dns_query(name, self.route_class)? {
                Admission::Allowed(query) => query,
                Admission::Denied(decision) => {
                    if let Some(fold) = &self.refusals {
                        fold.record(
                            Destination::checked_name(name),
                            None,
                            Transport::Dns,
                            RefusalReason::NameNotAllowed,
                            decision.policy_digest,
                        );
                    }
                    return Err(BrokerError::Denied(decision));
                }
            }
        };
        let request = DnsResolverRequest {
            name: query.name().to_string(),
            family,
        };
        match self
            .resolver
            .resolve(request)
            .await
            .map_err(BrokerError::Resolver)?
        {
            DnsResolverOutcome::NoData => Ok(BrokerDnsResponse::NoData(query)),
            DnsResolverOutcome::NameError => Ok(BrokerDnsResponse::NameError(query)),
            DnsResolverOutcome::Positive(resolution) => {
                if resolution
                    .addresses()
                    .iter()
                    .any(|record| !family.accepts(record.address()))
                {
                    return Err(BrokerError::MalformedDnsAnswer);
                }
                let now = self.clock.now();
                let mut state = self.state.lock().await;
                match state.admit_resolution(query.name(), self.route_class, resolution, now)? {
                    Ok(resolution) => Ok(BrokerDnsResponse::Positive(resolution)),
                    Err(refusal) => Err(BrokerError::Denied(self.note(
                        Destination::checked_name(query.name()),
                        None,
                        Transport::Dns,
                        &refusal,
                    ))),
                }
            }
        }
    }

    /// Perform the cheap pre-listener admission used by a packet worker.
    pub async fn authorize_tcp(
        &self,
        destination: SocketAddr,
    ) -> Result<TcpAuthorization, BrokerError> {
        Ok(self.admit_tcp(destination).await?.0)
    }

    /// Re-evaluate policy and lease expiry immediately before every dial. An
    /// intercepted dial is refused here; [`Self::connect_or_intercept`] hands
    /// it over instead.
    pub async fn connect_tcp(
        &self,
        destination: SocketAddr,
    ) -> Result<BrokerTcpConnection<C::Stream>, BrokerError> {
        match self.admit_tcp(destination).await? {
            (TcpAuthorization::Dial(admission), revision) => {
                let stream = self
                    .connector
                    .connect(destination)
                    .await
                    .map_err(BrokerError::Connector)?;
                Ok(BrokerTcpConnection {
                    stream,
                    admission,
                    revision,
                })
            }
            (TcpAuthorization::Intercept(interception), _) => {
                let state = self.state.lock().await;
                Err(BrokerError::Denied(
                    self.refuse_interception(&state, interception),
                ))
            }
        }
    }

    /// Admit a dial against the policy and the lease table. When only an
    /// expired lease would admit it, re-resolve that lease's own name once,
    /// never a guest-supplied one, and admit the dial only if the fresh
    /// answer, checked like any guest lookup, still contains its address.
    ///
    /// A dial the table would intercept goes to the front door. Without a
    /// hand-off it is refused, failing closed, never dialled.
    async fn admit_tcp(
        &self,
        destination: SocketAddr,
    ) -> Result<(TcpAuthorization, InterceptRevision), BrokerError> {
        let expired = {
            let mut state = self.state.lock().await;
            let revision = self.current_intercept_revision();
            match state.admit_tcp_or_expired(
                destination.ip(),
                destination.port(),
                self.route_class,
                self.clock.now(),
            )? {
                TcpVerdict::Allowed(admission) => {
                    return Ok((TcpAuthorization::Dial(admission), revision));
                }
                TcpVerdict::Intercepted(interception) => {
                    return Ok((self.intercept_or_refuse(&state, interception)?, revision));
                }
                TcpVerdict::Refused(refusal) => {
                    return Err(BrokerError::Denied(self.note_dial(
                        &state,
                        destination.ip(),
                        Transport::Tcp {
                            port: destination.port(),
                        },
                        &refusal,
                    )));
                }
                TcpVerdict::LeaseExpired(expired) => expired,
            }
        };
        let family = DnsRecordFamily::of(destination.ip());
        let request = DnsResolverRequest {
            name: expired.name().to_string(),
            family,
        };
        let name = Destination::checked_name(expired.name());
        // A failed, empty or wrong-family lookup is no answer: the dial is
        // refused as `lease_expired`.
        let resolution = match self.resolver.resolve(request).await {
            Ok(DnsResolverOutcome::Positive(resolution))
                if resolution
                    .addresses()
                    .iter()
                    .all(|record| family.accepts(record.address())) =>
            {
                Some(resolution)
            }
            _ => None,
        };
        let mut state = self.state.lock().await;
        let revision = self.current_intercept_revision();
        match state.readmit_expired(expired, resolution, self.clock.now())? {
            Ok(Readmission::Allowed(admission)) => {
                Ok((TcpAuthorization::Dial(admission), revision))
            }
            Ok(Readmission::Intercepted(interception)) => {
                Ok((self.intercept_or_refuse(&state, interception)?, revision))
            }
            Err(refusal) => Err(BrokerError::Denied(self.note(
                name,
                Some(destination.ip()),
                Transport::Tcp {
                    port: destination.port(),
                },
                &refusal,
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
