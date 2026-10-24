//! A hosted environment's membership in its hosted Mesh network (#3350).
//!
//! When the access grant names a network, the daemon joins it as the
//! environment's node: for every peer coordinate stream it asks the
//! workspace-binding listener for one enrollment code (one use, 60 seconds,
//! bound to this Pod), presents it to Mesh once, and serves the environment's
//! application ports on the node's Mesh address. This membership is separate
//! from the environment's access tailnet: its own WireGuard and disco keys,
//! its own UDP socket, and Mesh's coordinator.
//!
//! A stream that ends (a recheck, a revocation, a newer stream, a network
//! fault) is replaced with a fresh code. A refusal is reported once and
//! retried slowly, since a network owner can repair it; a fault is retried
//! with backoff. No code is ever logged or kept past its one use.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codewire_daemon::access::{MeshTarget, WorkspaceAccessGrant};
use codewire_daemon::app_ports::AppPorts;
use codewire_tailnet::conn::Conn;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _,
};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::daemon_access::ControlPlaneError;
use crate::daemon_tailnet::forward_app_ports;

/// What the daemon observed of its Mesh membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshReport {
    Attached,
    MeshUnreachable,
    NetworkNotFound,
    NotAMember,
    NodeNameTaken,
    Revoked,
    Refused,
}

/// One enrollment code and the network it joins. Never printed.
pub struct MeshEnrollment {
    pub code: Zeroizing<String>,
    pub target: MeshTarget,
}

impl fmt::Debug for MeshEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshEnrollment")
            .field("code", &"[redacted]")
            .field("target", &self.target)
            .finish()
    }
}

/// The daemon's Pod-bound exchange for Mesh membership.
#[async_trait]
pub trait MeshControlPlane: Send + Sync {
    /// One code for one peer stream. `Refused` when the environment joins no
    /// network (any more).
    async fn issue_mesh_enrollment(&self) -> Result<MeshEnrollment, ControlPlaneError>;
    async fn report_mesh_attachment(&self, report: MeshReport) -> Result<(), ControlPlaneError>;
}

/// Why joining failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// Mesh refused the node for a reason a person must repair.
    Refused(MeshReport),
    /// Mesh refused this code (expired, used, or the Pod moved on): ask for
    /// another at once.
    CodeRefused,
    /// Mesh or the network path failed; try again later.
    Unreachable,
}

/// A byte stream to another member.
pub trait MeshStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> MeshStream for T {}

/// One open membership: its tailnet connection, while it lasts.
#[async_trait]
pub trait MeshMembership: Send + Sync {
    fn conn(&self) -> Arc<Conn>;
    fn is_ready(&self) -> bool;
    /// One TCP stream to `port` on the member named `node` in this network.
    async fn dial(&self, node: &str, port: u16) -> anyhow::Result<Box<dyn MeshStream>>;
}

/// The open membership, for the local connect socket: `None` while the
/// environment has not joined.
pub type CurrentMembership = watch::Receiver<Option<Arc<dyn MeshMembership>>>;

/// Opens one peer stream with one code.
#[async_trait]
pub trait MeshJoiner: Send + Sync {
    async fn join(
        &self,
        target: &MeshTarget,
        code: &str,
        environment_id: Uuid,
    ) -> Result<Arc<dyn MeshMembership>, JoinError>;
}

/// Joins through [`codewire_client::member_tailnet::MemberTailnet`], with a
/// fresh key per stream and absolute DNS lookups (#2701). Hosted daemons run
/// on Linux only, as the member tailnet does.
#[cfg(target_os = "linux")]
pub struct MemberTailnetJoiner;

#[cfg(target_os = "linux")]
#[async_trait]
impl MeshMembership for codewire_client::member_tailnet::MemberTailnet {
    fn conn(&self) -> Arc<Conn> {
        codewire_client::member_tailnet::MemberTailnet::conn(self)
    }

    fn is_ready(&self) -> bool {
        codewire_client::member_tailnet::MemberTailnet::is_ready(self)
    }

    async fn dial(&self, node: &str, port: u16) -> anyhow::Result<Box<dyn MeshStream>> {
        let stream = self.dial_node(node, port).await?;
        Ok(Box::new(stream))
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl MeshJoiner for MemberTailnetJoiner {
    async fn join(
        &self,
        target: &MeshTarget,
        code: &str,
        environment_id: Uuid,
    ) -> Result<Arc<dyn MeshMembership>, JoinError> {
        use codewire_client::member_tailnet::{
            MemberSetupError, MemberTailnet, MemberTransportOptions,
        };
        let secret = codewire_tailnet::wg::StaticSecret::random_from_rng(rand::rngs::OsRng);
        match MemberTailnet::peer(
            target.mesh_url(),
            code,
            target.org_id(),
            target.network_id(),
            environment_id,
            secret,
            MemberTransportOptions {
                absolute_dns: true,
                ..Default::default()
            },
        )
        .await
        {
            Ok(member) => Ok(Arc::new(member)),
            Err(error) => {
                let rpc = error
                    .downcast_ref::<MemberSetupError>()
                    .map(|setup| setup.rpc);
                tracing::warn!(error = %error, "workspace Mesh membership setup failed");
                Err(join_error(rpc))
            }
        }
    }
}

/// The meaning of a refused peer stream's Connect code (Mesh's documented
/// refusals for an environment's code).
pub fn join_error(rpc: Option<&str>) -> JoinError {
    match rpc {
        Some("not_found") => JoinError::Refused(MeshReport::NetworkNotFound),
        Some("permission_denied") => JoinError::Refused(MeshReport::NotAMember),
        Some("already_exists") => JoinError::Refused(MeshReport::NodeNameTaken),
        Some("failed_precondition") => JoinError::Refused(MeshReport::Revoked),
        Some("unauthenticated") => JoinError::CodeRefused,
        Some("invalid_argument") => JoinError::Refused(MeshReport::Refused),
        _ => JoinError::Unreachable,
    }
}

/// Pacing of the membership loop.
#[derive(Clone, Copy, Debug)]
pub struct MeshTiming {
    /// First wait after a fault; doubles up to `max_fault_backoff`.
    pub fault_backoff: Duration,
    pub max_fault_backoff: Duration,
    /// Wait after a refusal a person must repair; doubles up to
    /// `max_refused_backoff`.
    pub refused_backoff: Duration,
    pub max_refused_backoff: Duration,
    /// How often an open membership is checked for its end.
    pub readiness_poll: Duration,
}

impl Default for MeshTiming {
    fn default() -> Self {
        Self {
            fault_backoff: Duration::from_secs(1),
            max_fault_backoff: Duration::from_secs(30),
            refused_backoff: Duration::from_secs(60),
            max_refused_backoff: Duration::from_secs(300),
            readiness_poll: Duration::from_secs(2),
        }
    }
}

/// Everything the membership loop serves with.
pub struct DaemonMeshConfig {
    pub environment_id: Uuid,
    /// Local ports never served on the Mesh address (as on the tailnet).
    pub reserved_ports: BTreeSet<u16>,
    pub timing: MeshTiming,
}

/// Keep the environment's node in its network while the grant names one,
/// until `shutdown`.
pub async fn run(
    config: DaemonMeshConfig,
    mut grants: watch::Receiver<WorkspaceAccessGrant>,
    plane: Arc<dyn MeshControlPlane>,
    joiner: Arc<dyn MeshJoiner>,
    app_ports: watch::Receiver<AppPorts>,
    current: watch::Sender<Option<Arc<dyn MeshMembership>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let timing = config.timing;
    let mut fault_wait = timing.fault_backoff;
    let mut refused_wait = timing.refused_backoff;
    let mut last_report: Option<MeshReport> = None;
    let report = |report: MeshReport, last: &mut Option<MeshReport>| {
        let plane = plane.clone();
        let changed = *last != Some(report);
        *last = Some(report);
        async move {
            if changed && let Err(error) = plane.report_mesh_attachment(report).await {
                tracing::warn!(?report, error = %error, "workspace Mesh report failed");
            }
        }
    };
    loop {
        if *shutdown.borrow() {
            return;
        }
        let target = grants.borrow_and_update().mesh().cloned();
        let Some(target) = target else {
            // No network: wait for a grant that names one.
            tokio::select! {
                _ = shutdown.changed() => return,
                changed = grants.changed() => if changed.is_err() { return },
            }
            continue;
        };
        let enrollment = match plane.issue_mesh_enrollment().await {
            Ok(enrollment) => enrollment,
            Err(ControlPlaneError::Refused) => {
                // The platform says the environment joins no network: wait
                // for the next grant rather than asking again and again.
                if !wait(timing.max_refused_backoff, &mut grants, &mut shutdown).await {
                    return;
                }
                continue;
            }
            Err(ControlPlaneError::Retryable) => {
                if !wait(fault_wait, &mut grants, &mut shutdown).await {
                    return;
                }
                fault_wait = (fault_wait * 2).min(timing.max_fault_backoff);
                continue;
            }
        };
        let joined = joiner
            .join(&enrollment.target, &enrollment.code, config.environment_id)
            .await;
        drop(enrollment);
        match joined {
            Ok(membership) => {
                fault_wait = timing.fault_backoff;
                refused_wait = timing.refused_backoff;
                report(MeshReport::Attached, &mut last_report).await;
                tracing::info!(
                    network = target.network_id(),
                    node = target.node_name(),
                    "workspace joined its Mesh network"
                );
                current.send_replace(Some(membership.clone()));
                let (stop, stopped) = watch::channel(false);
                let forwarding = tokio::spawn(forward_app_ports(
                    membership.conn(),
                    app_ports.clone(),
                    config.reserved_ports.clone(),
                    stopped,
                ));
                let keep = serve_until_ended(
                    membership.as_ref(),
                    &target,
                    &mut grants,
                    &mut shutdown,
                    timing.readiness_poll,
                )
                .await;
                current.send_replace(None);
                let _ = stop.send(true);
                forwarding.abort();
                drop(membership);
                if !keep {
                    return;
                }
                tracing::info!("workspace Mesh membership ended; rejoining");
                if !wait(timing.fault_backoff, &mut grants, &mut shutdown).await {
                    return;
                }
            }
            Err(JoinError::CodeRefused) => {
                if !wait(fault_wait, &mut grants, &mut shutdown).await {
                    return;
                }
                fault_wait = (fault_wait * 2).min(timing.max_fault_backoff);
            }
            Err(JoinError::Unreachable) => {
                report(MeshReport::MeshUnreachable, &mut last_report).await;
                if !wait(fault_wait, &mut grants, &mut shutdown).await {
                    return;
                }
                fault_wait = (fault_wait * 2).min(timing.max_fault_backoff);
            }
            Err(JoinError::Refused(reason)) => {
                report(reason, &mut last_report).await;
                if !wait(refused_wait, &mut grants, &mut shutdown).await {
                    return;
                }
                refused_wait = (refused_wait * 2).min(timing.max_refused_backoff);
            }
        }
    }
}

/// How long a local client has to send its request line.
const CONNECT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve [`codewire_daemon_proto::HOSTED_DAEMON_MESH_SOCKET`] until
/// `shutdown`: each connection names one member and port, gets `OK` and a
/// stream to it, or `ERR <reason>` (`invalid`, `not_joined`,
/// `unreachable`). Only processes that can open the owner-only socket, the
/// workspace's own, reach other members; the stream carries their bytes and
/// nothing else.
pub async fn serve_connect(
    listener: tokio::net::UnixListener,
    current: CurrentMembership,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                while connections.try_join_next().is_some() {}
                connections.spawn(connect_one(stream, current.clone()));
            }
        }
    }
}

async fn connect_one(stream: tokio::net::UnixStream, current: CurrentMembership) {
    let mut local = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    let read = tokio::time::timeout(
        CONNECT_REQUEST_TIMEOUT,
        (&mut local)
            .take(codewire_daemon_proto::MESH_CONNECT_MAX_LINE as u64)
            .read_line(&mut line),
    )
    .await;
    let request = match read {
        Ok(Ok(_)) => line
            .strip_suffix('\n')
            .and_then(codewire_daemon_proto::parse_mesh_connect_request),
        _ => None,
    };
    let Some((node, port)) = request else {
        let _ = local.get_mut().write_all(b"ERR invalid\n").await;
        return;
    };
    let membership = current.borrow().clone();
    let Some(membership) = membership else {
        let _ = local.get_mut().write_all(b"ERR not_joined\n").await;
        return;
    };
    let mut remote = match membership.dial(node, port).await {
        Ok(remote) => remote,
        Err(error) => {
            tracing::info!(node, port, error = %format!("{error:#}"), "workspace Mesh connect failed");
            let _ = local.get_mut().write_all(b"ERR unreachable\n").await;
            return;
        }
    };
    drop(membership);
    if local.get_mut().write_all(b"OK\n").await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
}

/// Serve while the membership lasts and the grant still names `target`.
/// False on shutdown.
async fn serve_until_ended(
    membership: &dyn MeshMembership,
    target: &MeshTarget,
    grants: &mut watch::Receiver<WorkspaceAccessGrant>,
    shutdown: &mut watch::Receiver<bool>,
    poll: Duration,
) -> bool {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return false,
            changed = grants.changed() => {
                if changed.is_err() {
                    return false;
                }
                if grants.borrow_and_update().mesh() != Some(target) {
                    return true;
                }
            }
            () = tokio::time::sleep(poll) => {
                if !membership.is_ready() {
                    return true;
                }
            }
        }
    }
}

/// Wait `delay`, ending early when the grant changes. False on shutdown.
async fn wait(
    delay: Duration,
    grants: &mut watch::Receiver<WorkspaceAccessGrant>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = shutdown.changed() => false,
        changed = grants.changed() => changed.is_ok(),
        () = tokio::time::sleep(delay) => true,
    }
}

#[cfg(test)]
#[path = "daemon_mesh/tests.rs"]
mod tests;
