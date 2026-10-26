//! UDP peer-relay allocation for an environment's tailnet peer.
//!
//! The path ladder is direct UDP, then a shared UDP relay, then DERP. A
//! client peer that has not proven a direct UDP path within
//! [`PEER_RELAY_DIRECT_GRACE`] of appearing gets a relay slot from the
//! environment peer, proactively; a client that asks for one (a disco
//! `AllocateUDPRelayEndpointRequest`) is answered the same way. A peer that
//! leaves, or proves a direct path, has its pending allocation cancelled.
//!
//! The allocation itself is made by a [`PeerRelayBackend`]: a bound
//! workspace daemon asks orchestration, so the allocator credential never
//! enters the sandbox. The backend admits calls at its own pace; an attempt's
//! deadline starts once it is admitted, and the wait for admission has its
//! own bound.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::UDPRelayEndpoint;
use codewire_tailnet::node::{DiscoPublic, Node, NodePublic};
use tokio::net::lookup_host;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::Instant;

/// How long one admitted allocation may take.
pub const PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long an allocation may wait for the backend to admit it.
pub const PEER_RELAY_ALLOCATION_QUEUE_LIMIT: Duration = Duration::from_secs(10);
/// How long a new client peer has to prove a direct UDP path before it is
/// offered a relay. A direct client's first ping reaches the environment one
/// path delay after both learn of each other.
pub const PEER_RELAY_DIRECT_GRACE: Duration = Duration::from_secs(1);
const PEER_RELAY_ALLOCATION_RETRY_DELAY: Duration = Duration::from_millis(250);
/// The longest wait between attempts for a peer whose allocations keep
/// failing or whose relays it never takes up (a DERP-only client).
const PEER_RELAY_ALLOCATION_MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const PEER_RELAY_ALLOCATION_RECONCILE_INTERVAL: Duration = Duration::from_millis(100);
const PEER_RELAY_REGISTRATION_GRACE: Duration = Duration::from_secs(1);

/// Makes one relay allocation for a pair of disco keys (the environment's
/// own first, then the client's), echoing the caller's generation.
#[async_trait]
pub trait PeerRelayBackend: Send + Sync + 'static {
    /// Wait until the backend can take another allocation call. Waiters are
    /// admitted in arrival order; a waiter that is cancelled uses nothing.
    async fn admit(&self) {}

    async fn allocate(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<UDPRelayEndpoint>;
}

/// A token bucket, in arrival order: `burst` calls at once, refilled at
/// `per_second`.
pub struct CallBudget {
    per_second: f64,
    burst: f64,
    state: tokio::sync::Mutex<CallBudgetState>,
}

struct CallBudgetState {
    tokens: f64,
    updated: Instant,
}

impl CallBudget {
    pub fn new(per_second: f64, burst: u32) -> Self {
        assert!(per_second > 0.0 && burst >= 1, "a call budget admits calls");
        Self {
            per_second,
            burst: f64::from(burst),
            state: tokio::sync::Mutex::new(CallBudgetState {
                tokens: f64::from(burst),
                updated: Instant::now(),
            }),
        }
    }

    /// Take one call's token, waiting behind earlier callers. The fair lock
    /// keeps arrival order; dropping the future while it waits takes nothing.
    pub async fn admit(&self) {
        let mut state = self.state.lock().await;
        while let Some(wait) = self.try_take(&mut state, Instant::now()) {
            tokio::time::sleep(wait).await;
        }
    }

    /// Refill to `now` and take a token, or say how long until one is due.
    /// The wait is never zero: a token a rounding error short must not spin.
    fn try_take(&self, state: &mut CallBudgetState, now: Instant) -> Option<Duration> {
        let elapsed = now.saturating_duration_since(state.updated).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.per_second).min(self.burst);
        state.updated = now;
        if state.tokens >= 1.0 - CALL_BUDGET_TOKEN_SLACK {
            state.tokens = (state.tokens - 1.0).max(0.0);
            return None;
        }
        let due = Duration::from_secs_f64((1.0 - state.tokens) / self.per_second);
        Some(due.max(CALL_BUDGET_MIN_WAIT))
    }
}

/// Floating-point refills can leave a due token a hair short of one.
const CALL_BUDGET_TOKEN_SLACK: f64 = 1e-9;
const CALL_BUDGET_MIN_WAIT: Duration = Duration::from_millis(1);

#[derive(Debug, thiserror::Error)]
#[error("UDP peer relay allocation waited {waited:?} without being admitted")]
struct QueueWaitExceeded {
    waited: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerRelayKey {
    peer: NodePublic,
    peer_disco: DiscoPublic,
}

/// What the tracker needs to know about one peer from the tailnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerPathState {
    /// The peer has proven a direct UDP path, so it needs no relay.
    direct: bool,
    relay: direct_udp::PeerRelayEndpointState,
}

impl PeerPathState {
    #[cfg(test)]
    fn relay(relay: direct_udp::PeerRelayEndpointState) -> Self {
        Self {
            direct: false,
            relay,
        }
    }
}

struct TrackedPeer {
    first_seen: Instant,
    queued: Option<PeerRelayQueuedState>,
    /// Consecutive attempts that failed, or whose relay the peer never took
    /// up. Each one doubles the wait before the next attempt.
    misses: u32,
    /// No attempt starts before this, after a miss.
    retry_at: Option<Instant>,
}

impl TrackedPeer {
    fn new(now: Instant) -> Self {
        Self {
            first_seen: now,
            queued: None,
            misses: 0,
            retry_at: None,
        }
    }

    fn missed(&mut self, now: Instant) {
        self.misses = self.misses.saturating_add(1);
        let doublings = (self.misses - 1).min(16);
        let delay = PEER_RELAY_ALLOCATION_RETRY_DELAY
            .saturating_mul(1 << doublings)
            .min(PEER_RELAY_ALLOCATION_MAX_RETRY_DELAY);
        self.retry_at = Some(now + delay);
    }
}

#[derive(Clone, Copy)]
struct PeerRelayQueuedState {
    queued_at: Instant,
    observed_by_tailnet: bool,
    active: bool,
}

#[derive(Default)]
struct PeerRelayAllocationTracker {
    peers: HashMap<PeerRelayKey, TrackedPeer>,
    /// One allocation at most per peer: waiting for admission or calling.
    in_flight: HashMap<PeerRelayKey, Option<AbortHandle>>,
    attempts: usize,
    failures: usize,
    cancelled: usize,
}

#[derive(Clone, Copy, Debug)]
struct PeerRelayAllocationState {
    peer_count: usize,
    queued_count: usize,
    in_flight_count: usize,
    attempts: usize,
    failures: usize,
    cancelled: usize,
}

impl PeerRelayAllocationTracker {
    /// Track exactly `peers`. Allocations for peers that left are cancelled.
    fn replace_peers(&mut self, now: Instant, peers: impl IntoIterator<Item = PeerRelayKey>) {
        let current = peers.into_iter().collect::<HashSet<_>>();
        self.peers.retain(|key, _| current.contains(key));
        for key in current {
            self.peers
                .entry(key)
                .or_insert_with(|| TrackedPeer::new(now));
        }
        let gone = self
            .in_flight
            .keys()
            .filter(|key| !self.peers.contains_key(key))
            .copied()
            .collect::<Vec<_>>();
        for key in gone {
            self.cancel(key);
        }
    }

    fn cancel(&mut self, key: PeerRelayKey) {
        if let Some(handle) = self.in_flight.remove(&key) {
            if let Some(handle) = handle {
                handle.abort();
            }
            self.cancelled += 1;
        }
    }

    /// Start an allocation for every peer that needs one, and cancel the
    /// pending allocation of every peer that has proven a direct path.
    fn begin_pending(
        &mut self,
        now: Instant,
        mut path_state: impl FnMut(PeerRelayKey) -> PeerPathState,
    ) -> Vec<PeerRelayKey> {
        let keys = self.peers.keys().copied().collect::<Vec<_>>();
        let mut started = Vec::new();
        for key in keys {
            let state = path_state(key);
            if state.direct {
                self.cancel(key);
                continue;
            }
            if self.in_flight.contains_key(&key) {
                continue;
            }
            let Some(peer) = self.peers.get_mut(&key) else {
                continue;
            };
            if now.saturating_duration_since(peer.first_seen) < PEER_RELAY_DIRECT_GRACE {
                continue;
            }

            if let Some(queued) = peer.queued.as_mut() {
                match state.relay {
                    direct_udp::PeerRelayEndpointState::Negotiating => {
                        queued.observed_by_tailnet = true;
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Active => {
                        queued.observed_by_tailnet = true;
                        queued.active = true;
                        peer.misses = 0;
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing
                        if !queued.observed_by_tailnet
                            && now.saturating_duration_since(queued.queued_at)
                                < PEER_RELAY_REGISTRATION_GRACE =>
                    {
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing => {}
                }
                // The relay expired. One the peer never took up counts as a
                // miss, so a peer that cannot use relays is asked less often.
                let active = queued.active;
                peer.queued = None;
                if !active {
                    peer.missed(now);
                }
            } else if state.relay != direct_udp::PeerRelayEndpointState::Missing {
                peer.queued = Some(PeerRelayQueuedState {
                    queued_at: now,
                    observed_by_tailnet: true,
                    active: state.relay == direct_udp::PeerRelayEndpointState::Active,
                });
                continue;
            }

            if peer.retry_at.is_some_and(|retry_at| now < retry_at) {
                continue;
            }
            self.in_flight.insert(key, None);
            self.attempts += 1;
            started.push(key);
        }
        started
    }

    /// Remember the task running `key`'s allocation, unless it already
    /// finished or was cancelled.
    fn attach(&mut self, key: PeerRelayKey, handle: AbortHandle) {
        if let Some(slot) = self.in_flight.get_mut(&key) {
            *slot = Some(handle);
        }
    }

    fn finish_success(&mut self, key: PeerRelayKey, now: Instant) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if let Some(peer) = self.peers.get_mut(&key) {
            peer.queued = Some(PeerRelayQueuedState {
                queued_at: now,
                observed_by_tailnet: false,
                active: false,
            });
        }
        self.state()
    }

    fn finish_failure(&mut self, key: PeerRelayKey, now: Instant) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if let Some(peer) = self.peers.get_mut(&key) {
            peer.missed(now);
        }
        self.failures += 1;
        self.state()
    }

    fn state(&self) -> PeerRelayAllocationState {
        PeerRelayAllocationState {
            peer_count: self.peers.len(),
            queued_count: self
                .peers
                .values()
                .filter(|peer| peer.queued.is_some())
                .count(),
            in_flight_count: self.in_flight.len(),
            attempts: self.attempts,
            failures: self.failures,
            cancelled: self.cancelled,
        }
    }
}

/// Keeps one relay allocation per client peer that needs one.
#[derive(Clone)]
pub struct PeerRelayAllocator {
    backend: Arc<dyn PeerRelayBackend>,
    /// Who logs, such as `workspace daemon`. Diagnostics match on the
    /// message text.
    component: &'static str,
    attempt_timeout: Duration,
    queue_limit: Duration,
    bind_addr_ports: Arc<[String]>,
    local_disco: DiscoPublic,
    handle: direct_udp::Handle,
    allocations: Arc<Mutex<PeerRelayAllocationTracker>>,
    answering: Arc<Mutex<HashSet<(NodePublic, u32)>>>,
}

impl PeerRelayAllocator {
    /// `bind_addr_ports`, when non-empty, replaces the relay's advertised
    /// addresses for this side's own binding (an in-cluster route to the
    /// relay); a workspace binds through the public addresses.
    pub fn new(
        backend: Arc<dyn PeerRelayBackend>,
        component: &'static str,
        bind_addr_ports: Vec<String>,
        local_disco: DiscoPublic,
        handle: direct_udp::Handle,
    ) -> Self {
        Self {
            backend,
            component,
            attempt_timeout: PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT,
            queue_limit: PEER_RELAY_ALLOCATION_QUEUE_LIMIT,
            bind_addr_ports: Arc::from(bind_addr_ports),
            local_disco,
            handle,
            allocations: Arc::new(Mutex::new(PeerRelayAllocationTracker::default())),
            answering: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Bound each admitted allocation attempt by `timeout` instead of the
    /// default.
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.attempt_timeout = timeout;
        self
    }

    /// Track the current client peers; allocations for peers that left are
    /// cancelled, and new peers are considered on the next reconcile.
    pub fn observe_peers(&self, nodes: &[Node]) {
        let peers = nodes.iter().filter_map(|node| {
            if node.key.is_zero() || node.disco_key.is_zero() || node.disco_key == self.local_disco
            {
                return None;
            }
            Some(PeerRelayKey {
                peer: node.key,
                peer_disco: node.disco_key,
            })
        });
        let state = {
            let mut allocations = self.allocations.lock().unwrap();
            let cancelled = allocations.cancelled;
            allocations.replace_peers(Instant::now(), peers);
            (allocations.cancelled != cancelled).then(|| allocations.state())
        };
        if let Some(state) = state {
            self.log_allocation_diagnostic("cancelled", state);
        }
        self.reconcile_allocations();
    }

    /// Start, retry and cancel allocations until the task is aborted.
    pub fn spawn_reconciler(&self) -> tokio::task::JoinHandle<()> {
        let allocator = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PEER_RELAY_ALLOCATION_RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                allocator.reconcile_allocations();
            }
        })
    }

    fn path_state(&self, key: PeerRelayKey) -> PeerPathState {
        PeerPathState {
            direct: self.handle.has_verified_endpoint(&key.peer),
            relay: self
                .handle
                .peer_relay_endpoint_state(&key.peer, &key.peer_disco),
        }
    }

    fn reconcile_allocations(&self) {
        let mut allocations = self.allocations.lock().unwrap();
        let cancelled = allocations.cancelled;
        let pending = allocations.begin_pending(Instant::now(), |key| self.path_state(key));
        let state = allocations.state();
        if allocations.cancelled != cancelled {
            self.log_allocation_diagnostic("cancelled", state);
        }
        for key in pending {
            self.log_allocation_diagnostic("started", state);
            let allocator = self.clone();
            let task = tokio::spawn(async move {
                match allocator.attempt(allocator.allocate_once(key)).await {
                    Ok(()) => {
                        let state = allocator.finish_allocation_success(key);
                        allocator.log_allocation_diagnostic("queued", state);
                    }
                    Err(error) => {
                        allocator.log_allocation_failure(&error);
                        let state = allocator.finish_allocation_failure(key);
                        allocator.log_allocation_diagnostic("retry_scheduled", state);
                    }
                }
            });
            allocations.attach(key, task.abort_handle());
        }
    }

    async fn attempt<T>(&self, call: impl Future<Output = Result<T>>) -> Result<T> {
        admitted_attempt(
            self.backend.as_ref(),
            self.component,
            self.queue_limit,
            self.attempt_timeout,
            call,
        )
        .await
    }

    fn log_allocation_failure(&self, error: &anyhow::Error) {
        if let Some(exceeded) = error.downcast_ref::<QueueWaitExceeded>() {
            tracing::warn!(
                queue_wait_ms = u64::try_from(exceeded.waited.as_millis()).unwrap_or(u64::MAX),
                "{} UDP peer relay allocation queue wait exceeded",
                self.component
            );
        } else {
            tracing::warn!(
                error = %format!("{error:#}"),
                "{} UDP peer relay allocation failed",
                self.component
            );
        }
    }

    fn finish_allocation_success(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations
            .lock()
            .unwrap()
            .finish_success(key, Instant::now())
    }

    fn finish_allocation_failure(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations
            .lock()
            .unwrap()
            .finish_failure(key, Instant::now())
    }

    fn allocation_state(&self) -> PeerRelayAllocationState {
        self.allocations.lock().unwrap().state()
    }

    fn log_allocation_diagnostic(&self, outcome: &str, state: PeerRelayAllocationState) {
        tracing::info!(
            outcome,
            path = "peer_relay",
            peer_count = state.peer_count,
            queued_count = state.queued_count,
            in_flight_count = state.in_flight_count,
            attempt_count = state.attempts,
            failure_count = state.failures,
            cancelled_count = state.cancelled,
            "{} UDP peer relay allocation diagnostic",
            self.component
        );
    }

    async fn allocate_once(&self, key: PeerRelayKey) -> Result<()> {
        let (endpoint, bind_endpoint) = self
            .allocate_endpoint([self.local_disco, key.peer_disco], 0)
            .await?;
        self.handle
            .request_peer_relay_with_bind_endpoint(key.peer, bind_endpoint, endpoint)
            .context("apply UDP peer relay endpoint")?;
        tracing::info!(
            "{} UDP peer relay proactive allocation queued",
            self.component
        );
        Ok(())
    }

    async fn answer_allocation_once(
        &self,
        event: direct_udp::PeerRelayAllocationEvent,
    ) -> Result<()> {
        tracing::info!(
            outcome = "answer_requested",
            path = "peer_relay",
            "{} UDP peer relay allocation responder",
            self.component
        );
        let (endpoint, bind_endpoint) = self
            .allocate_endpoint(event.client_disco, event.generation)
            .await?;
        self.handle
            .answer_peer_relay_allocation_with_bind_endpoint(
                event.peer,
                event.generation,
                bind_endpoint,
                endpoint,
            )
            .context("answer UDP peer relay allocation")?;
        tracing::info!(
            outcome = "answer_queued",
            path = "peer_relay",
            "{} UDP peer relay allocation responder",
            self.component
        );
        Ok(())
    }

    async fn allocate_endpoint(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<(UDPRelayEndpoint, UDPRelayEndpoint)> {
        let endpoint = self.backend.allocate(client_disco, generation).await?;
        tracing::debug!(
            outcome = "endpoint_received",
            relay_addr_count = endpoint.addr_ports.len(),
            "{} UDP peer relay allocator returned endpoint",
            self.component
        );
        let bind_endpoint = relay_bind_endpoint(&endpoint, &self.bind_addr_ports)
            .await
            .context("resolve UDP peer relay bind endpoint")?;
        Ok((endpoint, bind_endpoint))
    }

    /// Answer clients' allocation requests as they arrive, one at a time per
    /// peer and generation.
    pub fn spawn_allocation_responder(
        &self,
        mut events: mpsc::UnboundedReceiver<direct_udp::PeerRelayAllocationEvent>,
    ) {
        let allocator = self.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let request = (event.peer, event.generation);
                if !allocator.answering.lock().unwrap().insert(request) {
                    continue;
                }
                let allocator = allocator.clone();
                tokio::spawn(async move {
                    let result = allocator
                        .attempt(allocator.answer_allocation_once(event))
                        .await;
                    allocator.answering.lock().unwrap().remove(&request);
                    if let Err(error) = result {
                        allocator.log_allocation_failure(&error);
                        allocator.log_allocation_diagnostic(
                            "answer_retry_deferred",
                            allocator.allocation_state(),
                        );
                    }
                });
            }
        });
    }
}

/// Wait for `backend` to admit the call, at most `queue_limit`, then run it
/// within `attempt_timeout`, which starts at admission: time spent behind
/// other calls never counts against this one.
async fn admitted_attempt<T>(
    backend: &dyn PeerRelayBackend,
    component: &str,
    queue_limit: Duration,
    attempt_timeout: Duration,
    call: impl Future<Output = Result<T>>,
) -> Result<T> {
    let queued = Instant::now();
    if tokio::time::timeout(queue_limit, backend.admit())
        .await
        .is_err()
    {
        return Err(QueueWaitExceeded {
            waited: queued.elapsed(),
        }
        .into());
    }
    tracing::info!(
        outcome = "admitted",
        path = "peer_relay",
        queue_wait_ms = u64::try_from(queued.elapsed().as_millis()).unwrap_or(u64::MAX),
        "{component} UDP peer relay allocation admitted"
    );
    tokio::time::timeout(attempt_timeout, call)
        .await
        .context("UDP peer relay allocation attempt timed out")?
}

async fn relay_bind_endpoint(
    advertised_endpoint: &UDPRelayEndpoint,
    bind_addr_ports: &[String],
) -> Result<UDPRelayEndpoint> {
    if bind_addr_ports.is_empty() {
        return Ok(advertised_endpoint.clone());
    }

    let mut resolved = Vec::new();
    for addr_port in bind_addr_ports {
        let addrs = lookup_host(addr_port.as_str())
            .await
            .with_context(|| format!("resolve UDP peer relay bind addr {addr_port:?}"))?;
        for addr in addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }
    if resolved.is_empty() {
        return Err(anyhow!(
            "UDP peer relay bind addr list resolved to no addresses"
        ));
    }

    let mut endpoint = advertised_endpoint.clone();
    endpoint.addr_ports = resolved;
    Ok(endpoint)
}

#[cfg(test)]
#[path = "peer_relay/tests.rs"]
mod tests;
