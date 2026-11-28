//! Lightweight supervisor-owned TCP wake listeners for published host ports of
//! hibernated local Linux VMs (#5529, `docs/dev/LOCAL-VM-SLEEP.md`).
//!
//! When a VM with published host ports hibernates, its runner and VMM exit so
//! the host reclaims RAM. The supervisor binds `127.0.0.1:<host_port>` while
//! the VM stays hibernated. On the first inbound connection (or several
//! simultaneous connections), each connection is accepted, triggers a single
//! coalesced wake/restore, releases the supervisor's listening sockets right
//! before the restoring runner binds them, and forwards the accepted TCP
//! streams to the restored runner's loopback listeners.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use super::Supervisor;
use crate::host_port::HostPortBinding;

const RESTORED_PORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESTORED_PORT_RETRY_DELAY: Duration = Duration::from_millis(25);

struct ArmedPort {
    cancel: watch::Sender<bool>,
    closed: oneshot::Receiver<()>,
}

#[derive(Default)]
pub(super) struct HibernatePortWakers {
    armed: Mutex<HashMap<Uuid, Vec<ArmedPort>>>,
}

impl HibernatePortWakers {
    /// Binds wake-stub listeners for every published host port of a hibernated
    /// environment. Best-effort per port: a port already occupied on the host
    /// is skipped rather than failing hibernate.
    pub(super) async fn arm(
        &self,
        supervisor: Arc<Supervisor>,
        environment_id: Uuid,
        name: String,
        host_ports: &[HostPortBinding],
    ) {
        self.release(environment_id).await;
        if host_ports.is_empty() {
            return;
        }
        let mut armed_ports = Vec::with_capacity(host_ports.len());
        for binding in host_ports {
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, binding.host_port);
            let Ok(listener) = TcpListener::bind(addr).await else {
                continue;
            };
            let (cancel_tx, cancel_rx) = watch::channel(false);
            let (closed_tx, closed_rx) = oneshot::channel();
            let supervisor = Arc::clone(&supervisor);
            let name = name.clone();
            let host_port = binding.host_port;
            drop(tokio::spawn(async move {
                serve_wake_listener(listener, cancel_rx, closed_tx, supervisor, name, host_port)
                    .await;
            }));
            armed_ports.push(ArmedPort {
                cancel: cancel_tx,
                closed: closed_rx,
            });
        }
        if !armed_ports.is_empty() {
            let mut guard = self
                .armed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.insert(environment_id, armed_ports);
        }
    }

    /// Closes all wake-stub listeners for `environment_id` and waits until the
    /// kernel sockets are dropped so a restoring runner can bind them cleanly.
    pub(super) async fn release(&self, environment_id: Uuid) {
        let removed = {
            let mut guard = self
                .armed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.remove(&environment_id)
        };
        let Some(ports) = removed else {
            return;
        };
        for port in ports {
            let _ = port.cancel.send(true);
            let _ = port.closed.await;
        }
    }
}

async fn serve_wake_listener(
    listener: TcpListener,
    mut cancel_rx: watch::Receiver<bool>,
    closed_tx: oneshot::Sender<()>,
    supervisor: Arc<Supervisor>,
    name: String,
    host_port: u16,
) {
    loop {
        tokio::select! {
            biased;
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((inbound, _)) = accepted else {
                    break;
                };
                let supervisor = Arc::clone(&supervisor);
                let name = name.clone();
                drop(tokio::spawn(forward_after_wake(
                    supervisor, name, host_port, inbound,
                )));
            }
        }
    }
    drop(listener);
    let _ = closed_tx.send(());
}

fn forward_after_wake(
    supervisor: Arc<Supervisor>,
    name: String,
    host_port: u16,
    mut inbound: TcpStream,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Ok(_lease) = supervisor.quiet_lease(&name).await else {
            return;
        };
        if supervisor.daemon_access(&name).await.is_err() {
            return;
        }
        drop(_lease);
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_port);
        let deadline = Instant::now() + RESTORED_PORT_CONNECT_TIMEOUT;
        let mut outbound = loop {
            match TcpStream::connect(target).await {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(RESTORED_PORT_RETRY_DELAY).await;
                }
                Err(_) => return,
            }
        };
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    })
}
