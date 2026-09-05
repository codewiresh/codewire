//! Host-owned Mesh TCP ingress adapter.
//!
//! WireGuard, relay/direct-UDP transport, coordinator state, and credentials
//! remain in the host Mesh owner. This module turns an accepted userspace
//! tailnet TCP stream into one connected AF_UNIX stream capability. The runner
//! then authenticates that capability onto the confined network-worker
//! control channel; neither the guest nor the worker receives Mesh identity.

use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use codewire_tailnet::conn::Conn;
use codewire_tailnet::netstack::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::mesh_ingress::{
    MESH_INGRESS_CONTROL_FRAME_LEN, MESH_INGRESS_CONTROL_KEY_LEN, MeshIngressBinding,
    MeshIngressControlFrame, MeshIngressControlReceiver, MeshIngressError, MeshIngressPublisher,
    validate_canonical_mesh_ingress_ports,
};
use crate::network_worker::{receive_mesh_ingress_descriptor, send_mesh_ingress_descriptor};

const MESH_ACCEPT_QUEUE_CAPACITY: usize = 64;
const MAX_ACTIVE_MESH_STREAMS: usize = 256;
const MESH_SUBMISSION_TIMEOUT: Duration = Duration::from_secs(2);

/// Generation-bound client used by the isolated Mesh process to submit only
/// connected AF_UNIX stream capabilities to the environment runner.
pub struct MeshIngressSubmitter {
    control: tokio::net::UnixStream,
    environment_id: Uuid,
    generation: u64,
    key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    next_sequence: u64,
}

impl MeshIngressSubmitter {
    pub fn new(
        control: tokio::net::UnixStream,
        environment_id: Uuid,
        generation: u64,
        key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    ) -> Result<Self, MeshTransportError> {
        if environment_id.is_nil() || generation == 0 || key.iter().all(|byte| *byte == 0) {
            return Err(MeshTransportError::InvalidSubmission);
        }
        Ok(Self {
            control,
            environment_id,
            generation,
            key,
            next_sequence: 1,
        })
    }

    pub(crate) async fn submit(
        &mut self,
        guest_port: u16,
        stream: &StdUnixStream,
    ) -> Result<(), MeshTransportError> {
        let binding = MeshIngressBinding::new(guest_port)?;
        let frame = MeshIngressControlFrame::encode(
            self.environment_id,
            self.generation,
            self.next_sequence,
            binding,
            &self.key,
        )?;
        let deadline = tokio::time::Instant::now() + MESH_SUBMISSION_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            self.control.write_all(&frame).await?;
            self.control.flush().await
        })
        .await
        .map_err(|_| MeshTransportError::SubmissionControl)?
        .map_err(|_| MeshTransportError::SubmissionControl)?;
        tokio::time::timeout_at(deadline, async {
            loop {
                self.control
                    .writable()
                    .await
                    .map_err(|_| MeshTransportError::SubmissionControl)?;
                match send_mesh_ingress_descriptor(self.control.as_raw_fd(), stream.as_raw_fd()) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(()) => return Ok(()),
                    Err(_) => return Err(MeshTransportError::SubmissionControl),
                }
            }
        })
        .await
        .map_err(|_| MeshTransportError::SubmissionControl)??;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(MeshTransportError::InvalidSubmission)?;
        Ok(())
    }
}

enum MeshIngressTarget {
    InProcess(MeshIngressPublisher),
    Isolated(MeshIngressSubmitter),
}

impl MeshIngressTarget {
    async fn publish(
        &mut self,
        guest_port: u16,
        stream: &StdUnixStream,
    ) -> Result<bool, MeshTransportError> {
        match self {
            Self::InProcess(publisher) => {
                match publisher.publish(guest_port, stream.try_clone()?) {
                    Ok(()) => Ok(true),
                    Err(MeshIngressError::PublisherFull) => Ok(false),
                    Err(error) => Err(MeshTransportError::Admission(error)),
                }
            }
            Self::Isolated(submitter) => {
                submitter.submit(guest_port, stream).await?;
                Ok(true)
            }
        }
    }
}

/// A fully bound set of immutable Mesh application-port listeners.
pub struct MeshIngressBridge {
    _conn: Arc<Conn>,
    listeners: Vec<(u16, TcpListener)>,
    target: MeshIngressTarget,
}

impl MeshIngressBridge {
    pub async fn bind(
        conn: Arc<Conn>,
        guest_ports: &[u16],
        publisher: MeshIngressPublisher,
    ) -> Result<Self, MeshTransportError> {
        Self::bind_target(conn, guest_ports, MeshIngressTarget::InProcess(publisher)).await
    }

    /// Bind listeners whose accepted streams cross an authenticated private
    /// descriptor channel into the environment runner.
    pub async fn bind_isolated(
        conn: Arc<Conn>,
        guest_ports: &[u16],
        submitter: MeshIngressSubmitter,
    ) -> Result<Self, MeshTransportError> {
        Self::bind_target(conn, guest_ports, MeshIngressTarget::Isolated(submitter)).await
    }

    async fn bind_target(
        conn: Arc<Conn>,
        guest_ports: &[u16],
        target: MeshIngressTarget,
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
            target,
        })
    }

    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), MeshTransportError> {
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
                    if !self
                        .target
                        .publish(accepted.guest_port, &publisher_stream)
                        .await?
                    {
                        continue;
                    }
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

/// Receive authenticated stream capabilities from one isolated Mesh process
/// and publish them into the runner-owned generation queue. A closed channel
/// removes Mesh reachability without changing VM or general-egress state.
pub async fn receive_mesh_ingress_submissions(
    mut control: tokio::net::UnixStream,
    publisher: MeshIngressPublisher,
    environment_id: Uuid,
    generation: u64,
    guest_ports: Vec<u16>,
    key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
) -> Result<(), MeshTransportError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(MeshTransportError::InvalidSubmission);
    }
    let mut receiver = MeshIngressControlReceiver::new(environment_id, generation, &guest_ports)?;
    loop {
        let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
        match control.read(&mut frame[..1]).await {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte Mesh submission prefix buffer"),
            Err(_) => return Err(MeshTransportError::SubmissionControl),
        }
        control
            .read_exact(&mut frame[1..])
            .await
            .map_err(|_| MeshTransportError::SubmissionControl)?;
        let frame = receiver
            .decode(&frame, &key)
            .map_err(|_| MeshTransportError::InvalidSubmission)?;
        let descriptor = receive_mesh_ingress_descriptor(&control)
            .await
            .map_err(|_| MeshTransportError::SubmissionControl)?;
        let stream = StdUnixStream::from(descriptor);
        match publisher.publish(frame.binding.guest_port, stream) {
            Ok(()) | Err(MeshIngressError::PublisherFull) => {}
            Err(MeshIngressError::PublisherClosed) => return Ok(()),
            Err(error) => return Err(MeshTransportError::Admission(error)),
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
    #[error("Mesh ingress submission is invalid")]
    InvalidSubmission,
    #[error("Mesh ingress submission control failed")]
    SubmissionControl,
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
        let (submission, runner) = StdUnixStream::pair().unwrap();
        submission.set_nonblocking(true).unwrap();
        runner.set_nonblocking(true).unwrap();
        let environment_id = Uuid::new_v4();
        let key = [0x6d; MESH_INGRESS_CONTROL_KEY_LEN];
        let submitter = MeshIngressSubmitter::new(
            tokio::net::UnixStream::from_std(submission).unwrap(),
            environment_id,
            7,
            Zeroizing::new(key),
        )
        .unwrap();
        let submission_receiver = tokio::spawn(receive_mesh_ingress_submissions(
            tokio::net::UnixStream::from_std(runner).unwrap(),
            publisher,
            environment_id,
            7,
            ports.clone(),
            Zeroizing::new(key),
        ));
        let bridge = MeshIngressBridge::bind_isolated(peer, &ports, submitter)
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
        tokio::time::timeout(std::time::Duration::from_secs(1), submission_receiver)
            .await
            .expect("Mesh submission receiver did not observe transport shutdown")
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

    #[tokio::test]
    async fn isolated_submission_rejects_the_wrong_generation_key() {
        let ports = vec![3_000];
        let (publisher, mut published) = mesh_ingress_channel(&ports).unwrap();
        let (submission, runner) = StdUnixStream::pair().unwrap();
        submission.set_nonblocking(true).unwrap();
        runner.set_nonblocking(true).unwrap();
        let environment_id = Uuid::new_v4();
        let receiver = tokio::spawn(receive_mesh_ingress_submissions(
            tokio::net::UnixStream::from_std(runner).unwrap(),
            publisher,
            environment_id,
            9,
            ports,
            Zeroizing::new([0x41; MESH_INGRESS_CONTROL_KEY_LEN]),
        ));
        let mut submitter = MeshIngressSubmitter::new(
            tokio::net::UnixStream::from_std(submission).unwrap(),
            environment_id,
            9,
            Zeroizing::new([0x42; MESH_INGRESS_CONTROL_KEY_LEN]),
        )
        .unwrap();
        let (stream, _peer) = StdUnixStream::pair().unwrap();
        submitter.submit(3_000, &stream).await.unwrap();

        assert!(matches!(
            receiver.await.unwrap(),
            Err(MeshTransportError::InvalidSubmission)
        ));
        assert!(published.recv().await.is_none());
        let (invalid, _peer) = StdUnixStream::pair().unwrap();
        invalid.set_nonblocking(true).unwrap();
        assert!(
            MeshIngressSubmitter::new(
                tokio::net::UnixStream::from_std(invalid).unwrap(),
                Uuid::nil(),
                9,
                Zeroizing::new([0x42; MESH_INGRESS_CONTROL_KEY_LEN]),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn isolated_submission_distinguishes_clean_close_from_truncation() {
        let environment_id = Uuid::new_v4();
        let key = [0x51; MESH_INGRESS_CONTROL_KEY_LEN];
        for (prefix, expected_ok) in [(&b""[..], true), (&b"C"[..], false)] {
            let (sender, runner) = StdUnixStream::pair().unwrap();
            sender.set_nonblocking(true).unwrap();
            runner.set_nonblocking(true).unwrap();
            let (publisher, _published) = mesh_ingress_channel(&[3_000]).unwrap();
            let receiver = tokio::spawn(receive_mesh_ingress_submissions(
                tokio::net::UnixStream::from_std(runner).unwrap(),
                publisher,
                environment_id,
                11,
                vec![3_000],
                Zeroizing::new(key),
            ));
            let mut sender = tokio::net::UnixStream::from_std(sender).unwrap();
            sender.write_all(prefix).await.unwrap();
            sender.shutdown().await.unwrap();
            let result = receiver.await.unwrap();
            assert_eq!(result.is_ok(), expected_ok);
            if !expected_ok {
                assert!(matches!(result, Err(MeshTransportError::SubmissionControl)));
            }
        }
    }
}
