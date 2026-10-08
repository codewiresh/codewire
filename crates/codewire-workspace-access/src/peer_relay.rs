//! UDP peer-relay allocation for an environment's tailnet peer.
//!
//! When a client peer appears, the environment peer proactively asks for a
//! relay slot for the pair, and it answers a client's own allocation request
//! (a disco `AllocateUDPRelayEndpointRequest`) the same way. The allocation
//! itself is made by a [`PeerRelayBackend`]: a bound workspace daemon asks
//! orchestration, so the allocator credential never enters the sandbox.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::UDPRelayEndpoint;
use codewire_tailnet::node::{DiscoPublic, Node, NodePublic};
use tokio::net::lookup_host;
use tokio::sync::mpsc;

pub const PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const PEER_RELAY_ALLOCATION_RETRY_DELAY: Duration = Duration::from_millis(250);
const PEER_RELAY_ALLOCATION_RECONCILE_INTERVAL: Duration = Duration::from_millis(100);
const PEER_RELAY_REGISTRATION_GRACE: Duration = Duration::from_secs(1);

/// Makes one relay allocation for a pair of disco keys (the environment's
/// own first, then the client's), echoing the caller's generation.
#[async_trait]
pub trait PeerRelayBackend: Send + Sync + 'static {
    async fn allocate(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<UDPRelayEndpoint>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerRelayKey {
    peer: NodePublic,
    peer_disco: DiscoPublic,
}

#[derive(Default)]
struct PeerRelayAllocationTracker {
    peers: HashSet<PeerRelayKey>,
    queued: HashMap<PeerRelayKey, PeerRelayQueuedState>,
    in_flight: HashSet<PeerRelayKey>,
    last_started: HashMap<PeerRelayKey, Instant>,
    attempts: usize,
    failures: usize,
}

#[derive(Clone, Copy)]
struct PeerRelayQueuedState {
    queued_at: Instant,
    observed_by_tailnet: bool,
}

#[derive(Clone, Copy)]
struct PeerRelayAllocationState {
    peer_count: usize,
    queued_count: usize,
    in_flight_count: usize,
    attempts: usize,
    failures: usize,
}

impl PeerRelayAllocationTracker {
    fn replace_peers(&mut self, peers: impl IntoIterator<Item = PeerRelayKey>) {
        self.peers = peers.into_iter().collect();
        self.queued.retain(|key, _| self.peers.contains(key));
        self.last_started
            .retain(|key, _| self.peers.contains(key) || self.in_flight.contains(key));
    }

    fn begin_pending(
        &mut self,
        now: Instant,
        mut peer_relay_state: impl FnMut(PeerRelayKey) -> direct_udp::PeerRelayEndpointState,
    ) -> Vec<PeerRelayKey> {
        let keys = self.peers.iter().copied().collect::<Vec<_>>();
        let mut started = Vec::new();
        for key in keys {
            if self.in_flight.contains(&key) {
                continue;
            }

            let relay_state = peer_relay_state(key);
            if let Some(queued) = self.queued.get_mut(&key) {
                match relay_state {
                    direct_udp::PeerRelayEndpointState::Negotiating
                    | direct_udp::PeerRelayEndpointState::Active => {
                        queued.observed_by_tailnet = true;
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing
                        if !queued.observed_by_tailnet
                            && now.duration_since(queued.queued_at)
                                < PEER_RELAY_REGISTRATION_GRACE =>
                    {
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing => {}
                }
                self.queued.remove(&key);
            } else if relay_state != direct_udp::PeerRelayEndpointState::Missing {
                self.queued.insert(
                    key,
                    PeerRelayQueuedState {
                        queued_at: now,
                        observed_by_tailnet: true,
                    },
                );
                continue;
            }

            if self
                .last_started
                .get(&key)
                .is_some_and(|last| now.duration_since(*last) < PEER_RELAY_ALLOCATION_RETRY_DELAY)
            {
                continue;
            }
            self.in_flight.insert(key);
            self.last_started.insert(key, now);
            self.attempts += 1;
            started.push(key);
        }
        started
    }

    fn finish_success(&mut self, key: PeerRelayKey, now: Instant) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if self.peers.contains(&key) {
            self.queued.insert(
                key,
                PeerRelayQueuedState {
                    queued_at: now,
                    observed_by_tailnet: false,
                },
            );
        } else {
            self.last_started.remove(&key);
        }
        self.state()
    }

    fn finish_failure(&mut self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if !self.peers.contains(&key) {
            self.last_started.remove(&key);
        }
        self.failures += 1;
        self.state()
    }

    fn state(&self) -> PeerRelayAllocationState {
        PeerRelayAllocationState {
            peer_count: self.peers.len(),
            queued_count: self.queued.len(),
            in_flight_count: self.in_flight.len(),
            attempts: self.attempts,
            failures: self.failures,
        }
    }
}

/// Keeps one relay allocation per client peer of an environment.
#[derive(Clone)]
pub struct PeerRelayAllocator {
    backend: Arc<dyn PeerRelayBackend>,
    /// Who logs, such as `workspace daemon`. Diagnostics match on the
    /// message text.
    component: &'static str,
    attempt_timeout: Duration,
    bind_addr_ports: Arc<[String]>,
    local_disco: DiscoPublic,
    handle: direct_udp::Handle,
    allocations: Arc<Mutex<PeerRelayAllocationTracker>>,
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
            bind_addr_ports: Arc::from(bind_addr_ports),
            local_disco,
            handle,
            allocations: Arc::new(Mutex::new(PeerRelayAllocationTracker::default())),
        }
    }

    /// Bound each allocation attempt by `timeout` instead of the default.
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.attempt_timeout = timeout;
        self
    }

    /// Track the current client peers; allocations start for new ones.
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
        self.allocations.lock().unwrap().replace_peers(peers);
        self.reconcile_allocations();
    }

    /// Retry missing or expired allocations until the task is aborted.
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

    fn reconcile_allocations(&self) {
        let (pending, state) = {
            let mut allocations = self.allocations.lock().unwrap();
            let pending = allocations.begin_pending(Instant::now(), |key| {
                self.handle
                    .peer_relay_endpoint_state(&key.peer, &key.peer_disco)
            });
            let state = allocations.state();
            (pending, state)
        };
        for key in pending {
            self.log_allocation_diagnostic("started", state);
            let allocator = self.clone();
            tokio::spawn(async move {
                match bounded_peer_relay_allocation_attempt(
                    allocator.attempt_timeout,
                    allocator.allocate_once(key),
                )
                .await
                {
                    Ok(()) => {
                        let state = allocator.finish_allocation_success(key);
                        allocator.log_allocation_diagnostic("queued", state);
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "{} UDP peer relay allocation failed",
                            allocator.component
                        );
                        let state = allocator.finish_allocation_failure(key);
                        allocator.log_allocation_diagnostic("retry_scheduled", state);
                    }
                }
            });
        }
    }

    fn finish_allocation_success(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations
            .lock()
            .unwrap()
            .finish_success(key, Instant::now())
    }

    fn finish_allocation_failure(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations.lock().unwrap().finish_failure(key)
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

    /// Answer clients' allocation requests as they arrive.
    pub fn spawn_allocation_responder(
        &self,
        mut events: mpsc::UnboundedReceiver<direct_udp::PeerRelayAllocationEvent>,
    ) {
        let allocator = self.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let allocator = allocator.clone();
                tokio::spawn(async move {
                    if bounded_peer_relay_allocation_attempt(
                        allocator.attempt_timeout,
                        allocator.answer_allocation_once(event),
                    )
                    .await
                    .is_err()
                    {
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

async fn bounded_peer_relay_allocation_attempt<T>(
    timeout: Duration,
    attempt: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, attempt)
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
