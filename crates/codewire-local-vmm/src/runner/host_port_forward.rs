//! Host-port connections into the guest (#4347).
//!
//! Each connection accepted on a published `127.0.0.1` host port goes through
//! the guest daemon's `ForwardTcp` to the same port on the workload's
//! loopback, made as the workload user, as Codewire's SSH forwards are. A
//! server bound only to `127.0.0.1` in the VM therefore answers, and one on
//! `0.0.0.0` still does. The daemon refuses platform listeners. A forward that
//! cannot connect closes the host connection and leaves one event in the
//! runner log; the network worker never sees a host connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use codewire_daemon::DaemonAuthToken;
use codewire_workspace_access::daemon::DaemonSessionClient;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::AcceptedHostPort;
use crate::diagnostic_log::{self, DiagnosticLog, LogField};
use crate::guest_loopback::{GuestLoopbackError, open_guest_loopback};
use crate::hybrid_vsock::HybridVsockTarget;

/// Coordinates automatic wake of a suspended VM when an inbound host-port
/// connection arrives (#5529). When the VM is not suspended, checking
/// `is_suspended` is a single atomic load with zero channel traffic.
#[derive(Debug)]
pub(crate) struct WakeHook {
    suspended: AtomicBool,
    wake_tx: mpsc::UnboundedSender<oneshot::Sender<Result<(), ()>>>,
}

impl WakeHook {
    pub(crate) fn new() -> (
        Arc<Self>,
        mpsc::UnboundedReceiver<oneshot::Sender<Result<(), ()>>>,
    ) {
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                suspended: AtomicBool::new(false),
                wake_tx,
            }),
            wake_rx,
        )
    }

    pub(crate) fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Ordering::Release);
    }

    pub(crate) fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Acquire)
    }

    /// Requests a wake and waits for the runner to finish resuming the VM.
    pub(crate) async fn wake_if_suspended(&self) -> Result<(), GuestLoopbackError> {
        if !self.is_suspended() {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.wake_tx
            .send(reply_tx)
            .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
        match reply_rx.await {
            Ok(Ok(())) => Ok(()),
            _ => Err(GuestLoopbackError::DaemonUnreachable),
        }
    }
}

/// Host connections forwarded at once per VM, as many as one SSH connection
/// may forward. A connection past it is closed.
pub(super) const MAX_HOST_PORT_FORWARDS: usize = 256;

/// Why a forward ended without carrying the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ForwardFailure {
    /// Every forward slot was in use.
    Limit,
    Guest(GuestLoopbackError),
}

impl ForwardFailure {
    /// The closed name the runner log records.
    fn name(&self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Guest(error) => error.name(),
        }
    }
}

/// How the forwarder reaches the VM's daemon.
enum DaemonRoute {
    /// The VM's hybrid-vsock socket and one-boot capability.
    Hybrid {
        target: HybridVsockTarget,
        token: Zeroizing<String>,
    },
    /// A daemon already connected, as tests run one in process.
    #[cfg(test)]
    Connected(DaemonSessionClient),
}

/// One running VM's host-port forwards, over one daemon connection made on
/// first use and made again after it fails.
pub(super) struct HostPortForwarder {
    route: DaemonRoute,
    client: Mutex<Option<DaemonSessionClient>>,
    slots: Arc<Semaphore>,
    wake_hook: Option<Arc<WakeHook>>,
    log: Option<DiagnosticLog>,
}

impl HostPortForwarder {
    pub(super) fn new(
        target: HybridVsockTarget,
        token: Zeroizing<String>,
        wake_hook: Option<Arc<WakeHook>>,
    ) -> Arc<Self> {
        Self::with_route(DaemonRoute::Hybrid { target, token }, wake_hook)
    }

    #[cfg(test)]
    pub(super) fn connected(client: DaemonSessionClient) -> Arc<Self> {
        Self::with_route(DaemonRoute::Connected(client), None)
    }

    #[cfg(test)]
    pub(super) fn connected_with_wake(
        client: DaemonSessionClient,
        wake_hook: Arc<WakeHook>,
    ) -> Arc<Self> {
        Self::with_route(DaemonRoute::Connected(client), Some(wake_hook))
    }

    fn with_route(route: DaemonRoute, wake_hook: Option<Arc<WakeHook>>) -> Arc<Self> {
        Arc::new(Self {
            route,
            client: Mutex::new(None),
            slots: Arc::new(Semaphore::new(MAX_HOST_PORT_FORWARDS)),
            wake_hook,
            log: DiagnosticLog::inherited(),
        })
    }

    /// Carries `accepted` on a task in `tasks`, so the forward ends when the
    /// set is dropped with the forwarder that owns it.
    pub(super) fn forward(self: &Arc<Self>, accepted: AcceptedHostPort, tasks: &mut JoinSet<()>) {
        let guest_port = accepted.binding.guest_port;
        let Ok(slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            self.record(guest_port, &ForwardFailure::Limit);
            return;
        };
        let forwarder = Arc::clone(self);
        tasks.spawn(async move {
            let _slot = slot;
            if let Some(wake) = forwarder.wake_hook.as_ref()
                && let Err(error) = wake.wake_if_suspended().await
            {
                forwarder.record(guest_port, &ForwardFailure::Guest(error));
                return;
            }
            let outcome = match forwarder.client().await {
                Ok(client) => carry(&client, accepted.stream, guest_port).await,
                Err(error) => Err(error),
            };
            if let Err(error) = outcome {
                if error == GuestLoopbackError::DaemonUnreachable {
                    *forwarder.client.lock().await = None;
                }
                forwarder.record(guest_port, &ForwardFailure::Guest(error));
            }
        });
    }

    async fn client(&self) -> Result<DaemonSessionClient, GuestLoopbackError> {
        let (target, token) = match &self.route {
            DaemonRoute::Hybrid { target, token } => (target, token),
            #[cfg(test)]
            DaemonRoute::Connected(client) => return Ok(client.clone()),
        };
        let mut client = self.client.lock().await;
        if let Some(client) = client.as_ref() {
            return Ok(client.clone());
        }
        let channel = target
            .connect_channel()
            .await
            .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
        let token = DaemonAuthToken::new(token.as_str())
            .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
        let connected = DaemonSessionClient::from_channel(channel, token);
        *client = Some(connected.clone());
        Ok(connected)
    }

    fn record(&self, guest_port: u16, failure: &ForwardFailure) {
        diagnostic_log::record(
            self.log.as_ref(),
            "host_port_forward_failed",
            &[
                ("guest_port", LogField::Count(u64::from(guest_port))),
                ("reason", LogField::Name(failure.name())),
            ],
        );
    }
}

/// Copies between `host` and `guest_port` on the workload's loopback until
/// either side closes.
pub(super) async fn carry(
    client: &DaemonSessionClient,
    mut host: TcpStream,
    guest_port: u16,
) -> Result<(), GuestLoopbackError> {
    let mut guest = open_guest_loopback(client, guest_port).await?;
    // Either side closing, cleanly or not, is how a connection ends.
    let _ = tokio::io::copy_bidirectional(&mut host, &mut guest).await;
    Ok(())
}

#[cfg(test)]
mod tests;
