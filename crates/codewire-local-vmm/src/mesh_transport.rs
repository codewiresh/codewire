//! Host-owned Mesh TCP ingress adapter.
//!
//! WireGuard, relay/direct-UDP transport, coordinator state, and credentials
//! remain in the host Mesh owner. This module turns an accepted userspace
//! tailnet TCP stream into one connected AF_UNIX stream capability. The runner
//! then authenticates that capability onto the confined network-worker
//! control channel; neither the guest nor the worker receives Mesh identity.

use std::io;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;

use codewire_tailnet::conn::Conn;
use codewire_tailnet::netstack::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::mesh_ingress::{
    MeshIngressError, MeshIngressPublisher, validate_canonical_mesh_ingress_ports,
};

const MESH_ACCEPT_QUEUE_CAPACITY: usize = 64;
const MAX_ACTIVE_MESH_STREAMS: usize = 256;

/// A fully bound set of immutable Mesh application-port listeners.
pub struct MeshIngressBridge {
    _conn: Arc<Conn>,
    listeners: Vec<(u16, TcpListener)>,
    publisher: MeshIngressPublisher,
}

impl MeshIngressBridge {
    pub async fn bind(
        conn: Arc<Conn>,
        guest_ports: &[u16],
        publisher: MeshIngressPublisher,
    ) -> Result<Self, MeshTransportError> {
        validate_canonical_mesh_ingress_ports(guest_ports)?;
        let mut listeners = Vec::with_capacity(guest_ports.len());
        for guest_port in guest_ports {
            let listener = conn
                .listen("tcp", &format!(":{guest_port}"))
                .await
                .map_err(MeshTransportError::Tailnet)?;
            if listener.local_port() != *guest_port {
                return Err(MeshTransportError::ListenerIdentity);
            }
            listeners.push((*guest_port, listener));
        }
        Ok(Self {
            _conn: conn,
            listeners,
            publisher,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), MeshTransportError> {
        if *shutdown.borrow() {
            return Ok(());
        }
        if self.listeners.is_empty() {
            wait_for_shutdown(&mut shutdown).await;
            return Ok(());
        }

        let (accepted_tx, mut accepted_rx) = mpsc::channel(MESH_ACCEPT_QUEUE_CAPACITY);
        let mut acceptors = JoinSet::new();
        for (guest_port, listener) in self.listeners {
            let accepted_tx = accepted_tx.clone();
            acceptors.spawn(accept_mesh_streams(guest_port, listener, accepted_tx));
        }
        drop(accepted_tx);

        let mut bridges = JoinSet::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    let _ = changed;
                    return Ok(());
                }
                accepted = accepted_rx.recv() => {
                    let accepted = accepted.ok_or(MeshTransportError::ListenerClosed)?;
                    if bridges.len() >= MAX_ACTIVE_MESH_STREAMS {
                        continue;
                    }
                    let (publisher_stream, bridge_stream) = StdUnixStream::pair()?;
                    bridge_stream.set_nonblocking(true)?;
                    let bridge_stream = tokio::net::UnixStream::from_std(bridge_stream)?;
                    self.publisher
                        .publish(accepted.guest_port, publisher_stream)?;
                    bridges.spawn(bridge_mesh_stream(accepted.stream, bridge_stream));
                }
                completed = acceptors.join_next(), if !acceptors.is_empty() => {
                    let _ = completed;
                    return Err(MeshTransportError::ListenerClosed);
                }
                completed = bridges.join_next(), if !bridges.is_empty() => {
                    if completed.is_some_and(|result| result.is_err()) {
                        return Err(MeshTransportError::BridgeTask);
                    }
                }
            }
        }
    }
}

struct AcceptedTailnetStream {
    guest_port: u16,
    stream: TcpStream,
}

async fn accept_mesh_streams(
    guest_port: u16,
    mut listener: TcpListener,
    accepted: mpsc::Sender<AcceptedTailnetStream>,
) {
    while let Some(stream) = listener.accept().await {
        if stream.local_addr().port() != guest_port {
            continue;
        }
        if accepted
            .send(AcceptedTailnetStream { guest_port, stream })
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn bridge_mesh_stream(
    mut tailnet: TcpStream,
    mut ingress: tokio::net::UnixStream,
) -> io::Result<()> {
    copy_bidirectional(&mut tailnet, &mut ingress)
        .await
        .map(|_| ())
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshTransportError {
    #[error("Mesh ingress admission failed: {0}")]
    Admission(#[from] MeshIngressError),
    #[error("Mesh tailnet listener failed: {0}")]
    Tailnet(#[source] codewire_tailnet::conn::Error),
    #[error("Mesh tailnet listener identity changed")]
    ListenerIdentity,
    #[error("Mesh tailnet listener closed unexpectedly")]
    ListenerClosed,
    #[error("Mesh stream bridge task failed")]
    BridgeTask,
    #[error("Mesh stream bridge I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    use codewire_tailnet::conn::{Options, PeerTransport, Transport, WgDatagram};
    use codewire_tailnet::derp::NodePublic as DerpPublic;
    use codewire_tailnet::node::Prefix;
    use codewire_tailnet::wg::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use uuid::Uuid;

    use crate::mesh_ingress::{MeshIngressError, mesh_ingress_channel};

    use super::*;

    const PEER_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x101);
    const DIAL_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x102);

    fn relay_shim(a: DerpPublic, b: DerpPublic) -> (Transport, Transport) {
        let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();

        let b_in_for_a = b_in_tx.clone();
        tokio::spawn(async move {
            while let Some(datagram) = a_out_rx.recv().await {
                let _ = b_in_for_a.send(WgDatagram {
                    peer: a.clone(),
                    data: datagram.data,
                });
            }
        });
        let a_in_for_b = a_in_tx.clone();
        tokio::spawn(async move {
            while let Some(datagram) = b_out_rx.recv().await {
                let _ = a_in_for_b.send(WgDatagram {
                    peer: b.clone(),
                    data: datagram.data,
                });
            }
        });

        (
            Transport {
                to_transport: a_out_tx,
                from_transport: a_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
            Transport {
                to_transport: b_out_tx,
                from_transport: b_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
        )
    }

    fn options(secret: &StaticSecret, ip: Ipv6Addr) -> Options {
        let mut options = Options::new(Uuid::new_v4());
        options.addresses = vec![Prefix::new(IpAddr::V6(ip), 128)];
        options.private_key = Some(secret.clone());
        options
    }

    fn synthetic_tailnet() -> (Arc<Conn>, Arc<Conn>) {
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let dial_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        let dial_public = PublicKey::from(&dial_secret);
        let (peer_transport, dial_transport) = relay_shim(
            DerpPublic::from_raw(peer_public.to_bytes()),
            DerpPublic::from_raw(dial_public.to_bytes()),
        );
        let peer = Arc::new(Conn::new(options(&peer_secret, PEER_IP), peer_transport).unwrap());
        let dial = Arc::new(Conn::new(options(&dial_secret, DIAL_IP), dial_transport).unwrap());
        peer.update_peers(&[dial.node()]).unwrap();
        dial.update_peers(&[peer.node()]).unwrap();
        (peer, dial)
    }

    #[tokio::test]
    async fn encrypted_relay_stream_becomes_only_an_admitted_unix_capability() {
        let (peer, dial) = synthetic_tailnet();
        assert_eq!(
            dial.probe_peer_path(&peer.node()).unwrap().transport,
            PeerTransport::DerpRelay
        );
        let ports = vec![3_000];
        let (publisher, mut published) = mesh_ingress_channel(&ports).unwrap();
        let bridge = MeshIngressBridge::bind(peer, &ports, publisher)
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let runtime = tokio::spawn(bridge.run(shutdown_rx));

        let mut remote = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            dial.dial_context_tcp(SocketAddr::new(IpAddr::V6(PEER_IP), 3_000)),
        )
        .await
        .expect("synthetic tailnet dial timed out")
        .unwrap();
        remote.write_all(b"mesh request").await.unwrap();
        remote.shutdown().await.unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(15), published.recv())
            .await
            .expect("Mesh bridge did not publish the accepted stream")
            .unwrap();
        assert_eq!(accepted.binding.guest_port, 3_000);
        accepted.stream.set_nonblocking(true).unwrap();
        let mut worker = tokio::net::UnixStream::from_std(accepted.stream).unwrap();
        let mut request = [0_u8; 12];
        worker.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"mesh request");
        let mut eof = [0_u8; 1];
        assert_eq!(worker.read(&mut eof).await.unwrap(), 0);

        worker.write_all(b"mesh response").await.unwrap();
        worker.shutdown().await.unwrap();
        let mut response = [0_u8; 13];
        remote.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"mesh response");

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), runtime)
            .await
            .expect("Mesh bridge did not stop")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn publisher_rejects_unadmitted_ports_and_closed_runner() {
        let (publisher, receiver) = mesh_ingress_channel(&[3_000]).unwrap();
        let (stream, _peer) = StdUnixStream::pair().unwrap();
        assert_eq!(
            publisher.publish(4_000, stream),
            Err(MeshIngressError::PortDenied)
        );

        drop(receiver);
        let (stream, _peer) = StdUnixStream::pair().unwrap();
        assert_eq!(
            publisher.publish(3_000, stream),
            Err(MeshIngressError::PublisherClosed)
        );
    }
}
