//! Tunnels to a host's environments (#3609, slice 2, design §5.3): the API
//! attach path to a host VM's daemon.
//!
//! A caller that needs a daemon connection asks [`HostTunnels::open`]. The
//! host's current session on this replica sends the host `open_tunnel` with
//! a fresh nonce, and the host answers by opening `OpenHostTunnel`, signing
//! that nonce with its key. The two are paired here, in this process, by
//! tunnel ID. A host whose session is on another replica cannot be reached
//! from this one yet (#4511): the caller gets a retryable refusal.
//!
//! A tunnel lives no longer than the session that asked for it: when that
//! session ends, for any reason, its tunnels end too, and the daemon
//! capability each holds is dropped with it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_proto::codewire::v1::{HostOpenTunnel, HostTunnelKind};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::host_session::{NONCE_BYTES, new_nonce};

/// How long a host has to open a tunnel it was asked for.
pub const TUNNEL_OPEN_SECS: u64 = 10;
/// Tunnel requests waiting for one session to send them.
const REQUESTS_PER_SESSION: usize = 16;

/// The environment a tunnel reaches, as its host last reported it.
#[derive(Clone, Debug)]
pub struct TunnelTarget {
    pub host_id: String,
    pub environment_id: String,
    pub local_environment_id: String,
    pub generation: u64,
}

/// An open tunnel: bytes to and from the environment's daemon.
pub struct OpenedTunnel {
    pub stream: DuplexStream,
    /// The running generation's daemon capability. Held for this tunnel
    /// only; never recorded.
    pub daemon_capability: Zeroizing<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// No session of the host is attached to this replica.
    #[error("the host is not connected here")]
    HostNotHere,
    #[error("the host did not open the tunnel in time")]
    TimedOut,
    /// The host could not reach the environment; its words.
    #[error("the host refused the tunnel: {0}")]
    Refused(String),
}

/// A tunnel the host was asked for and has not opened yet.
pub(crate) struct Pending {
    pub(crate) host_id: String,
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) expires: Instant,
    /// Ends with the session that asked.
    pub(crate) session: CancellationToken,
    pub(crate) opened: oneshot::Sender<Result<OpenedTunnel, TunnelError>>,
}

struct Session {
    generation: i64,
    requests: mpsc::Sender<HostOpenTunnel>,
    ended: CancellationToken,
}

#[derive(Default)]
struct Inner {
    /// The current session of each host attached here.
    sessions: HashMap<String, Session>,
    pending: HashMap<String, Pending>,
}

#[derive(Default)]
pub struct HostTunnels {
    inner: Mutex<Inner>,
}

/// Removes a tunnel's pending entry however its `open` ends: answered,
/// timed out, or dropped by its caller.
struct PendingEntry<'a> {
    tunnels: &'a HostTunnels,
    tunnel_id: &'a str,
}

impl Drop for PendingEntry<'_> {
    fn drop(&mut self) {
        self.tunnels.lock().pending.remove(self.tunnel_id);
    }
}

/// The registration of one session; ends its tunnels when dropped.
pub(crate) struct Registration {
    tunnels: Arc<HostTunnels>,
    host_id: String,
    generation: i64,
    ended: CancellationToken,
    pub(crate) requests: mpsc::Receiver<HostOpenTunnel>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.ended.cancel();
        let mut inner = self.tunnels.lock();
        if inner
            .sessions
            .get(&self.host_id)
            .is_some_and(|session| session.generation == self.generation)
        {
            inner.sessions.remove(&self.host_id);
        }
    }
}

impl HostTunnels {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    // The map stays valid after a panic elsewhere: every change is one
    // insert or remove.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the session holding `generation` as the one tunnels for
    /// `host_id` go through, replacing an older session's registration.
    pub(crate) fn register(self: &Arc<Self>, host_id: &str, generation: i64) -> Registration {
        let (requests, receiver) = mpsc::channel(REQUESTS_PER_SESSION);
        let ended = CancellationToken::new();
        let mut inner = self.lock();
        let replaces = inner
            .sessions
            .get(host_id)
            .is_none_or(|session| session.generation < generation);
        if replaces {
            inner.sessions.insert(
                host_id.to_owned(),
                Session {
                    generation,
                    requests,
                    ended: ended.clone(),
                },
            );
        }
        Registration {
            tunnels: Arc::clone(self),
            host_id: host_id.to_owned(),
            generation,
            ended,
            requests: receiver,
        }
    }

    /// Opens a tunnel to the daemon of `target`'s environment.
    pub async fn open(&self, target: &TunnelTarget) -> Result<OpenedTunnel, TunnelError> {
        let tunnel_id = uuid::Uuid::new_v4().to_string();
        let nonce = new_nonce();
        let (opened, waiting) = oneshot::channel();
        let requests = {
            let mut inner = self.lock();
            let session = inner
                .sessions
                .get(&target.host_id)
                .ok_or(TunnelError::HostNotHere)?;
            let (requests, ended) = (session.requests.clone(), session.ended.clone());
            inner.pending.insert(
                tunnel_id.clone(),
                Pending {
                    host_id: target.host_id.clone(),
                    nonce,
                    expires: Instant::now() + Duration::from_secs(TUNNEL_OPEN_SECS),
                    session: ended,
                    opened,
                },
            );
            requests
        };
        let _entry = PendingEntry {
            tunnels: self,
            tunnel_id: &tunnel_id,
        };
        let request = HostOpenTunnel {
            tunnel_id: tunnel_id.clone(),
            environment_id: target.environment_id.clone(),
            local_environment_id: target.local_environment_id.clone(),
            generation: target.generation,
            kind: HostTunnelKind::HOST_TUNNEL_KIND_DAEMON_GRPC.into(),
            nonce: nonce.to_vec(),
            ..Default::default()
        };
        match requests.try_send(request) {
            Ok(()) => {
                match tokio::time::timeout(Duration::from_secs(TUNNEL_OPEN_SECS), waiting).await {
                    Ok(Ok(opened)) => opened,
                    // The session ended before the host opened it.
                    Ok(Err(_)) => Err(TunnelError::HostNotHere),
                    Err(_) => Err(TunnelError::TimedOut),
                }
            }
            Err(_) => Err(TunnelError::HostNotHere),
        }
    }

    /// The host and nonce of the tunnel `tunnel_id` names, without taking
    /// it, so an open is checked before it can spend the tunnel.
    pub(crate) fn pending_proof(&self, tunnel_id: &str) -> Option<(String, [u8; NONCE_BYTES])> {
        let inner = self.lock();
        let pending = inner.pending.get(tunnel_id)?;
        Some((pending.host_id.clone(), pending.nonce))
    }

    /// The tunnel `tunnel_id` names, once: unknown, opened before or
    /// expired is `None`.
    pub(crate) fn take_pending(&self, tunnel_id: &str) -> Option<Pending> {
        let pending = self.lock().pending.remove(tunnel_id)?;
        (Instant::now() < pending.expires && !pending.session.is_cancelled()).then_some(pending)
    }
}

#[cfg(test)]
mod tests;
