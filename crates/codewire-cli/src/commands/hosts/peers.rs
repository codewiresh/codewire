//! A host's tailnet peers (#3609, slice 3 design §2): one for each placed VM
//! that runs here, keyed by its environment, local ID and boot generation.
//! Each is the hosted daemon's peer (`daemon_tailnet::run`), with its control
//! plane over the host session ([`plane`]) and its port 22 spliced into the
//! supervisor's SSH for that VM ([`splice`]).
//!
//! A peer runs only for a VM that both the host last reported running on the
//! session and the supervisor runs now, at the same boot. The control plane
//! admits a call only against the host's report, so a peer started ahead of
//! the report would be refused for good. A changed VM's old peer is stopped
//! before its new one starts.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use codewire_client::hosts::{HostEnvironmentObservation, HostEnvironmentState};
use codewire_daemon::app_ports::AppPorts;
use codewire_local_vmm::supervisor_config::SupervisorFeature;
use codewire_workspace_access::daemon_access::{
    AccessControlPlane as _, ControlPlaneError, record_host_key_until_accepted,
};
use codewire_workspace_access::daemon_tailnet::{
    self, AccessGrants, CoordinatorDialer, DaemonTailnetConfig,
};
use futures::future::BoxFuture;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::operations::Placement;

mod plane;
mod splice;

pub(super) use plane::{AccessLink, Call, Pending, link};

/// How often the peers look at what the supervisor runs, for a VM that
/// stopped or restarted without an operation.
const POLL: Duration = Duration::from_secs(15);
/// How long a stopping peer has before it is aborted.
const PEER_STOP: Duration = Duration::from_secs(5);
const RETRY_INITIAL: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
const HOST_KEY_RECORD_INITIAL: Duration = Duration::from_millis(250);
const HOST_KEY_RECORD_MAX: Duration = Duration::from_secs(5);

/// The VM a peer serves: its environment, the host's own ID for it and its
/// boot generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PeerKey {
    pub environment_id: Uuid,
    pub local_environment_id: Uuid,
    pub generation: u64,
}

impl PeerKey {
    /// The key of a VM `observation` reports running.
    fn running(observation: &HostEnvironmentObservation) -> Option<Self> {
        (observation.state.as_known()
            == Some(HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING))
        .then_some(())?;
        Some(Self {
            environment_id: Uuid::parse_str(&observation.environment_id).ok()?,
            local_environment_id: Uuid::parse_str(&observation.local_environment_id).ok()?,
            generation: observation.generation,
        })
    }
}

/// How a peer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PeerEnd {
    /// It was asked to stop.
    Stopped,
    /// It can't serve its VM at this boot; it isn't started again for it.
    Refused,
}

/// What the peers need from this computer.
pub(super) trait PeerHost: Send + Sync + 'static {
    /// The placed VMs as the supervisor has them now.
    fn inventory(&self) -> BoxFuture<'_, anyhow::Result<Vec<HostEnvironmentObservation>>>;
    /// Serves `vm` until `stop` is set or it is refused.
    fn serve(
        self: Arc<Self>,
        vm: PeerKey,
        stop: watch::Receiver<bool>,
    ) -> BoxFuture<'static, PeerEnd>;
}

/// What the host reported on the session: the running VMs by environment.
type Reported = BTreeMap<Uuid, PeerKey>;

/// The agent's peers, kept by one task.
pub(super) struct Peers {
    reported: watch::Sender<Reported>,
    /// Set once Codewire's server is found to answer no access calls.
    unsupported: watch::Sender<bool>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Peers {
    pub(super) fn start(host: Arc<dyn PeerHost>) -> Self {
        let (reported, reported_rx) = watch::channel(Reported::new());
        let (unsupported, unsupported_rx) = watch::channel(false);
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(keep(host, reported_rx, unsupported_rx, stop_rx));
        Self {
            reported,
            unsupported,
            stop,
            task: Some(task),
        }
    }

    /// The hello's inventory: everything the host reported on a new session.
    pub(super) fn hello(&self, inventory: &[HostEnvironmentObservation]) {
        self.reported.send_replace(
            inventory
                .iter()
                .filter_map(PeerKey::running)
                .map(|vm| (vm.environment_id, vm))
                .collect(),
        );
    }

    /// One environment as an operation's result reported it.
    pub(super) fn reported(&self, observation: &HostEnvironmentObservation) {
        let Ok(environment_id) = Uuid::parse_str(&observation.environment_id) else {
            return;
        };
        self.reported.send_modify(|reported| {
            match PeerKey::running(observation) {
                Some(vm) => reported.insert(environment_id, vm),
                None => reported.remove(&environment_id),
            };
        });
    }

    /// Codewire's server answers no access calls: stop every peer and start
    /// none for as long as this agent runs.
    pub(super) fn unsupported(&self) {
        if !self.unsupported.send_replace(true) {
            eprintln!(
                "Codewire's server doesn't serve tailnet access for hosts yet; environments here are reached through Codewire only"
            );
        }
    }

    /// Stops every peer, each before this returns.
    pub(super) async fn stop(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Peers {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

/// One running peer.
struct Running {
    vm: PeerKey,
    stop: watch::Sender<bool>,
    task: JoinHandle<PeerEnd>,
}

impl Running {
    async fn stop(mut self) {
        self.stop.send_replace(true);
        if tokio::time::timeout(PEER_STOP, &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = self.task.await;
        }
    }
}

async fn keep(
    host: Arc<dyn PeerHost>,
    mut reported: watch::Receiver<Reported>,
    mut unsupported: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
) {
    let mut running: BTreeMap<Uuid, Running> = BTreeMap::new();
    let mut refused: BTreeSet<PeerKey> = BTreeSet::new();
    let mut poll = tokio::time::interval(POLL);
    loop {
        tokio::select! {
            _ = poll.tick() => {}
            changed = reported.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = unsupported.changed() => {}
            _ = stop.wait_for(|stop| *stop) => break,
        }
        let wanted = if *unsupported.borrow() {
            Reported::new()
        } else {
            let reported = reported.borrow_and_update().clone();
            match host.inventory().await {
                // A VM the supervisor runs now, at the boot the host reported.
                Ok(inventory) => inventory
                    .iter()
                    .filter_map(PeerKey::running)
                    .filter(|vm| reported.get(&vm.environment_id) == Some(vm))
                    .map(|vm| (vm.environment_id, vm))
                    .collect(),
                // Unread, the peers stay as they are.
                Err(_) => continue,
            }
        };
        reconcile(&host, &mut running, &mut refused, &wanted).await;
    }
    for (_, peer) in running {
        peer.stop().await;
    }
}

async fn reconcile(
    host: &Arc<dyn PeerHost>,
    running: &mut BTreeMap<Uuid, Running>,
    refused: &mut BTreeSet<PeerKey>,
    wanted: &Reported,
) {
    // A peer that ended by itself was refused at its key.
    let ended: Vec<Uuid> = running
        .iter()
        .filter(|(_, peer)| peer.task.is_finished())
        .map(|(environment_id, _)| *environment_id)
        .collect();
    for environment_id in ended {
        if let Some(peer) = running.remove(&environment_id)
            && !matches!(peer.task.await, Ok(PeerEnd::Stopped))
        {
            refused.insert(peer.vm);
        }
    }
    // Every peer whose VM stopped, left or changed stops first.
    let stale: Vec<Uuid> = running
        .iter()
        .filter(|(environment_id, peer)| wanted.get(environment_id) != Some(&peer.vm))
        .map(|(environment_id, _)| *environment_id)
        .collect();
    for environment_id in stale {
        if let Some(peer) = running.remove(&environment_id) {
            peer.stop().await;
        }
    }
    refused.retain(|vm| wanted.get(&vm.environment_id) == Some(vm));
    for (environment_id, vm) in wanted {
        if running.contains_key(environment_id) || refused.contains(vm) {
            continue;
        }
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(Arc::clone(host).serve(*vm, stop_rx));
        running.insert(
            *environment_id,
            Running {
                vm: *vm,
                stop,
                task,
            },
        );
    }
}

/// This computer: its supervisor, and the host session through `link`.
pub(super) struct OnThisComputer {
    link: AccessLink,
    placement: Placement,
    coordinator: Arc<dyn CoordinatorDialer>,
}

impl OnThisComputer {
    pub(super) fn new(
        link: AccessLink,
        placement: Placement,
        coordinator: Arc<dyn CoordinatorDialer>,
    ) -> Self {
        Self {
            link,
            placement,
            coordinator,
        }
    }
}

impl PeerHost for OnThisComputer {
    fn inventory(&self) -> BoxFuture<'_, anyhow::Result<Vec<HostEnvironmentObservation>>> {
        Box::pin(super::operations::inventory(&self.placement))
    }

    fn serve(
        self: Arc<Self>,
        vm: PeerKey,
        stop: watch::Receiver<bool>,
    ) -> BoxFuture<'static, PeerEnd> {
        Box::pin(async move { self.serve_vm(vm, stop).await })
    }
}

impl OnThisComputer {
    async fn serve_vm(&self, vm: PeerKey, stop: watch::Receiver<bool>) -> PeerEnd {
        // Set by a stop or by a final refusal; the peer and every connection
        // it spliced end with it.
        let (end, ended) = watch::channel(false);
        let asked = stop.clone();
        let follow = {
            let end = end.clone();
            let mut stop = stop;
            tokio::spawn(async move {
                let _ = stop.wait_for(|stop| *stop).await;
                end.send_replace(true);
            })
        };
        let plane = Arc::new(plane::HostPlane::new(self.link.clone(), vm, end.clone()));
        let prepared = {
            let mut ended = ended.clone();
            tokio::select! {
                prepared = prepare(&plane, vm) => prepared,
                _ = ended.wait_for(|ended| *ended) => Err(ControlPlaneError::Refused),
            }
        };
        if let Ok((host_key, grant)) = prepared {
            let recorded = grant.operation_generation();
            let grants = AccessGrants::new(plane.clone(), grant);
            // Both end at `end`.
            tokio::spawn(grants.clone().keep_fresh(ended.clone()));
            // A new operation generation without a reboot leaves its host-key
            // slot empty: the lookup answers not ready until the same key is
            // recorded into it.
            tokio::spawn(daemon_tailnet::record_host_key_per_generation(
                plane.clone(),
                grants.subscribe(),
                host_key,
                recorded,
                ended.clone(),
            ));
            let (_no_ports, app_ports) = watch::channel(AppPorts::new());
            let ssh = Arc::new(splice::SupervisorSplice::new(
                self.placement.vm_name(vm.environment_id),
                vm,
                ended.clone(),
            ));
            let config = DaemonTailnetConfig {
                environment_id: vm.environment_id,
                // Its own port, found from outside with STUN.
                udp_listen_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                reserved_ports: BTreeSet::new(),
                platform: None,
                quiet: codewire_workspace_access::quiet::PlatformQuiet::new(),
            };
            if let Err(error) = daemon_tailnet::run(
                config,
                grants,
                plane,
                Arc::clone(&self.coordinator),
                ssh,
                app_ports,
                ended,
            )
            .await
            {
                eprintln!(
                    "environment {}: the tailnet peer stopped: {error:#}",
                    vm.environment_id
                );
            }
        }
        follow.abort();
        // Whatever ended it, its renewals end too: they hold the plane, and
        // with it a sender of `end`.
        end.send_replace(true);
        // Ended without being asked: refused, or its tailnet failed for good.
        if *asked.borrow() {
            PeerEnd::Stopped
        } else {
            PeerEnd::Refused
        }
    }
}

/// Everything before the peer joins its tailnet: a supervisor that keeps
/// remote streams apart, the VM's host key, a first grant, and the key
/// recorded for that grant's generation, so no client is served a key
/// Codewire doesn't hold.
async fn prepare(
    plane: &plane::HostPlane,
    vm: PeerKey,
) -> Result<(String, codewire_daemon::access::WorkspaceAccessGrant), ControlPlaneError> {
    let host_key = retrying(|| async {
        let client = super::super::native::native_client().await?;
        if !client.supports(SupervisorFeature::RemoteSsh) {
            return Ok(None);
        }
        super::super::native::native_environment_diagnostic_client(
            &vm.local_environment_id.to_string(),
        )
        .await?
        .host_key()
        .await
        .map(Some)
        .map_err(anyhow::Error::from)
    })
    .await;
    let Some(host_key) = host_key else {
        eprintln!(
            "environment {}: no tailnet peer: this computer's VMs run on an older cw's supervisor, which can't keep a remote connection apart from yours; `cw upgrade --vms` moves them to this cw once they are idle",
            vm.environment_id
        );
        return Err(ControlPlaneError::Refused);
    };
    let mut backoff = RETRY_INITIAL;
    let grant = loop {
        match plane.refresh_access().await {
            Ok(grant) => break grant,
            Err(ControlPlaneError::Refused) => return Err(ControlPlaneError::Refused),
            Err(ControlPlaneError::Retryable) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
        }
    };
    record_host_key_until_accepted(
        plane,
        &host_key,
        HOST_KEY_RECORD_INITIAL,
        HOST_KEY_RECORD_MAX,
    )
    .await?;
    Ok((host_key, grant))
}

/// `attempt`'s value, retried with backoff while it fails.
async fn retrying<T, F, Fut>(attempt: F) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut backoff = RETRY_INITIAL;
    loop {
        if let Ok(value) = attempt().await {
            return value;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RETRY_MAX);
    }
}

#[cfg(test)]
mod tests;
