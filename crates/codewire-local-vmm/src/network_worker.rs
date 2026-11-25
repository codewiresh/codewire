//! The local runtime's product network worker: the `CWNETB4` bootstrap and
//! the Mesh ingress control it carries. The worker core it runs on is
//! `codewire-egress-worker`'s (#4000), re-exported here at its old paths.

pub use codewire_egress_worker::worker::*;

use codewire_egress_worker::session::{InboundGuestStream, MAX_INBOUND_STREAM_FLOWS};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex as StdMutex};

use codewire_egress_broker::ipc::{
    BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS, BrokerIpcBinding, BrokerIpcKey,
};
use codewire_egress_policy::PolicyDigest;
use codewire_vmm_guest_probe::{NETWORK_KEY_LEN, NetworkKey};
use tokio::io::Interest;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::mesh_ingress::{
    MAX_MESH_INGRESS_PORTS, MESH_INGRESS_CONTROL_FRAME_LEN, MESH_INGRESS_CONTROL_KEY_LEN,
    MeshIngressControlReceiver, is_mesh_ingress_control_frame,
    validate_canonical_mesh_ingress_ports,
};

mod control;

use control::run_ingress_control;
pub(crate) use control::{LATE_STATUS_FRAME_LEN, LateStatusFrame};

const WORKER_MESH_INGRESS_DESCRIPTOR_MARKER: u8 = b'M';

// B4 (#4347): host ports no longer reach the worker, so its host-port key is gone.
const PRODUCT_BOOTSTRAP_MAGIC: &[u8; 8] = b"CWNETB4\0";
const PRODUCT_BOOTSTRAP_LEN: usize = 304;
const PRODUCT_POLICY_DIGEST_OFFSET: usize = 64;
const PRODUCT_BROKER_KEY_OFFSET: usize = 96;
const PRODUCT_MESH_INGRESS_KEY_OFFSET: usize = 128;
const PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET: usize = 160;
const PRODUCT_MESH_INGRESS_PORTS_OFFSET: usize = 162;

pub(crate) fn send_mesh_ingress_descriptor(bootstrap: RawFd, stream: RawFd) -> io::Result<()> {
    validate_inherited_unix_socket(stream).map_err(io::Error::other)?;
    send_worker_descriptor(bootstrap, stream, WORKER_MESH_INGRESS_DESCRIPTOR_MARKER)
}

pub(crate) async fn receive_mesh_ingress_descriptor(
    control: &tokio::net::UnixStream,
) -> Result<OwnedFd, NetworkWorkerError> {
    loop {
        control
            .readable()
            .await
            .map_err(|_| NetworkWorkerError::FrameIo)?;
        match receive_worker_descriptor(control.as_raw_fd(), WORKER_MESH_INGRESS_DESCRIPTOR_MARKER)
        {
            Ok(descriptor) => {
                validate_inherited_unix_socket(descriptor.as_raw_fd())?;
                return Ok(descriptor);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(NetworkWorkerError::InheritedDescriptor),
        }
    }
}

/// Encode the product bootstrap containing one generation network key, one
/// policy digest, separate non-provider ingress/broker HMAC keys, and the
/// immutable Mesh guest-port allowlist.
#[allow(clippy::too_many_arguments)]
pub fn encode_product_worker_bootstrap(
    vm_id: Uuid,
    generation: u64,
    network_key: &NetworkKey,
    broker_key: &[u8; BROKER_IPC_KEY_LEN],
    mesh_ingress_key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    mesh_ingress_ports: &[u16],
    policy_digest: PolicyDigest,
) -> Result<Zeroizing<[u8; PRODUCT_BOOTSTRAP_LEN]>, NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    if broker_key.iter().all(|byte| *byte == 0)
        || mesh_ingress_key.iter().all(|byte| *byte == 0)
        || validate_canonical_mesh_ingress_ports(mesh_ingress_ports).is_err()
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut bytes = Zeroizing::new([0_u8; PRODUCT_BOOTSTRAP_LEN]);
    bytes[..8].copy_from_slice(PRODUCT_BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(vm_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_le_bytes());
    network_key.with_bytes(|key| bytes[32..64].copy_from_slice(key));
    bytes[PRODUCT_POLICY_DIGEST_OFFSET..PRODUCT_BROKER_KEY_OFFSET]
        .copy_from_slice(policy_digest.as_bytes());
    bytes[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET].copy_from_slice(broker_key);
    bytes[PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET]
        .copy_from_slice(mesh_ingress_key);
    bytes[PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET..PRODUCT_MESH_INGRESS_PORTS_OFFSET]
        .copy_from_slice(&(mesh_ingress_ports.len() as u16).to_le_bytes());
    for (index, port) in mesh_ingress_ports.iter().enumerate() {
        let offset = PRODUCT_MESH_INGRESS_PORTS_OFFSET + index * std::mem::size_of::<u16>();
        bytes[offset..offset + std::mem::size_of::<u16>()].copy_from_slice(&port.to_le_bytes());
    }
    Ok(bytes)
}

struct ProductWorkerBootstrap {
    network_key: NetworkKey,
    broker_binding: BrokerIpcBinding,
    broker_key: BrokerIpcKey,
    mesh_ingress_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    mesh_ingress_ports: Vec<u16>,
}

struct ProductWorkerSession {
    network_key: NetworkKey,
    mesh_ingress_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    mesh_ingress_ports: Vec<u16>,
    /// The guest network's /30, from the runner's own launch.
    addresses: SessionAddresses,
}

/// Entrypoint used only by the hidden product `cw` worker command. The runner
/// that spawned it names `addresses`; nothing the guest sends chooses them.
pub async fn run_inherited_worker(
    vm_id: Uuid,
    generation: u64,
    addresses: SessionAddresses,
) -> Result<(), NetworkWorkerError> {
    validate_identity(vm_id, generation)?;
    let mut bootstrap = inherited_std_unix_stream(NETWORK_BOOTSTRAP_FD)?;
    let prepared = (|| {
        bootstrap
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        bootstrap
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        if ambient_environment_present() {
            return Err(NetworkWorkerError::AmbientEnvironment);
        }
        let mut bytes = Zeroizing::new([0_u8; PRODUCT_BOOTSTRAP_LEN]);
        bootstrap
            .read_exact(bytes.as_mut())
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation)
    })();
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    if let Err(error) = confine_network_worker() {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    bootstrap
        .set_read_timeout(None)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    write_worker_control_message(&bootstrap, WORKER_PREPARED_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    // One descriptor per broker IPC session, in session order (#2638).
    let broker_streams = (0..BROKER_IPC_SESSIONS)
        .map(|_| {
            receive_worker_broker_descriptor(bootstrap.as_raw_fd())
                .and_then(transferred_tokio_unix_stream)
        })
        .collect::<Result<Vec<_>, NetworkWorkerError>>()
        .and_then(|streams| {
            IpcEgressBroker::new(streams, prepared.broker_binding, prepared.broker_key)
        });
    let broker = match broker_streams {
        Ok(broker) => Arc::new(broker),
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    if let Err(error) = broker.verify_binding().await {
        let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
        return Err(error);
    }
    write_worker_control_message(&bootstrap, WORKER_BROKER_READY_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    run_prepared_product_worker(
        bootstrap,
        ProductWorkerSession {
            network_key: prepared.network_key,
            mesh_ingress_key: prepared.mesh_ingress_key,
            mesh_ingress_ports: prepared.mesh_ingress_ports,
            addresses,
        },
        vm_id,
        generation,
        broker,
    )
    .await
}

async fn run_prepared_product_worker<B: EgressBroker>(
    bootstrap: StdUnixStream,
    session: ProductWorkerSession,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
) -> Result<(), NetworkWorkerError> {
    let descriptor = match receive_worker_network_descriptor(bootstrap.as_raw_fd()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let network = match transferred_stream(descriptor) {
        Ok(network) => network,
        Err(_) => {
            let error = NetworkWorkerError::InheritedDescriptor;
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    bootstrap
        .set_nonblocking(true)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let control =
        tokio::net::UnixStream::from_std(bootstrap).map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let (inbound_tx, inbound_rx) = mpsc::channel(MAX_INBOUND_STREAM_FLOWS);
    let (status_tx, status_rx) = oneshot::channel::<&'static [u8]>();
    let status = Arc::new(StdMutex::new(Some(status_tx)));
    let ready_status = Arc::clone(&status);
    let mut control_task = tokio::spawn(run_ingress_control(
        control,
        status_rx,
        inbound_tx,
        session.mesh_ingress_key,
        session.mesh_ingress_ports,
        vm_id,
        generation,
        broker.late_answer_watch(),
    ));
    let session = run_host_session_with_ingress(
        network,
        session.network_key,
        vm_id,
        generation,
        session.addresses,
        broker,
        Some(inbound_rx),
        move || publish_product_worker_status(&ready_status, WORKER_READY_MESSAGE),
    );
    tokio::pin!(session);
    tokio::select! {
        result = &mut session => {
            if let Err(error) = &result {
                let _ = publish_product_worker_status(&status, error.startup_failure().message());
            }
            let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, &mut control_task).await;
            result
        }
        result = &mut control_task => {
            result
                .map_err(|_| NetworkWorkerError::Engine)?
        }
    }
}

fn publish_product_worker_status(
    status: &StdMutex<Option<oneshot::Sender<&'static [u8]>>>,
    message: &'static [u8],
) -> io::Result<()> {
    status
        .lock()
        .map_err(|_| io::Error::other("network worker status lock failed"))?
        .take()
        .ok_or_else(|| io::Error::other("network worker status was already published"))?
        .send(message)
        .map_err(|_| io::Error::other("network worker status channel closed"))
}

fn decode_product_worker_bootstrap(
    bytes: &[u8],
    expected_vm_id: Uuid,
    expected_generation: u64,
) -> Result<ProductWorkerBootstrap, NetworkWorkerError> {
    validate_identity(expected_vm_id, expected_generation)?;
    if bytes.len() != PRODUCT_BOOTSTRAP_LEN || &bytes[..8] != PRODUCT_BOOTSTRAP_MAGIC {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let vm_id =
        Uuid::from_slice(&bytes[8..24]).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let generation = u64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .expect("fixed product worker bootstrap generation"),
    );
    if vm_id != expected_vm_id || generation != expected_generation {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut network_key = Zeroizing::new([0_u8; NETWORK_KEY_LEN]);
    network_key.copy_from_slice(&bytes[32..64]);
    let network_key = NetworkKey::from_derived_bytes(*network_key)
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    // The selected policy's digest (#2537). The worker enforces nothing; it
    // binds every broker request to the digest the broker itself checked.
    let policy_digest = PolicyDigest::from_bytes(
        bytes[PRODUCT_POLICY_DIGEST_OFFSET..PRODUCT_BROKER_KEY_OFFSET]
            .try_into()
            .expect("fixed product worker policy digest"),
    );
    if policy_digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let broker_binding = BrokerIpcBinding::new(vm_id, generation, policy_digest)
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let mut broker_key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
    broker_key.copy_from_slice(&bytes[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET]);
    let broker_key =
        BrokerIpcKey::from_bytes(*broker_key).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let mut mesh_ingress_key = Zeroizing::new([0_u8; MESH_INGRESS_CONTROL_KEY_LEN]);
    mesh_ingress_key.copy_from_slice(
        &bytes[PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET],
    );
    if mesh_ingress_key.iter().all(|byte| *byte == 0) {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let port_count = u16::from_le_bytes(
        bytes[PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET..PRODUCT_MESH_INGRESS_PORTS_OFFSET]
            .try_into()
            .expect("fixed Mesh ingress port count"),
    ) as usize;
    if port_count > MAX_MESH_INGRESS_PORTS {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut mesh_ingress_ports = Vec::with_capacity(port_count);
    for index in 0..port_count {
        let offset = PRODUCT_MESH_INGRESS_PORTS_OFFSET + index * std::mem::size_of::<u16>();
        mesh_ingress_ports.push(u16::from_le_bytes(
            bytes[offset..offset + std::mem::size_of::<u16>()]
                .try_into()
                .expect("fixed Mesh ingress port"),
        ));
    }
    let used_ports_end =
        PRODUCT_MESH_INGRESS_PORTS_OFFSET + port_count * std::mem::size_of::<u16>();
    if bytes[used_ports_end..].iter().any(|byte| *byte != 0)
        || validate_canonical_mesh_ingress_ports(&mesh_ingress_ports).is_err()
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    Ok(ProductWorkerBootstrap {
        network_key,
        broker_binding,
        broker_key,
        mesh_ingress_key,
        mesh_ingress_ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_egress_policy::CompiledPolicy;
    use std::io::Write as _;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "local-worker-test-token-0123456789abcdef";

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    use crate::mesh_ingress::{MeshIngressBinding, MeshIngressControlFrame};

    #[tokio::test]
    async fn mesh_descriptor_is_role_bound_and_must_be_a_connected_unix_stream() {
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (_peer, bridge) = StdUnixStream::pair().unwrap();

        send_worker_descriptor(
            runner.as_raw_fd(),
            bridge.as_raw_fd(),
            WORKER_NETWORK_DESCRIPTOR_MARKER,
        )
        .unwrap();
        assert!(matches!(
            receive_mesh_ingress_descriptor(&worker).await,
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        send_worker_descriptor(
            runner.as_raw_fd(),
            accepted.as_raw_fd(),
            WORKER_MESH_INGRESS_DESCRIPTOR_MARKER,
        )
        .unwrap();
        assert!(matches!(
            receive_mesh_ingress_descriptor(&worker).await,
            Err(NetworkWorkerError::InheritedDescriptor)
        ));

        let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(send_mesh_ingress_descriptor(runner.as_raw_fd(), datagram.as_raw_fd()).is_err());
    }

    /// #4347: host ports reach the guest through the daemon's `ForwardTcp`,
    /// so the worker takes no host-port frame, and no host connection with one.
    #[tokio::test]
    async fn the_worker_refuses_a_host_port_frame() {
        let (vm_id, generation) = identity();
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let mut runner = tokio::net::UnixStream::from_std(runner).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = oneshot::channel();
        let control = tokio::spawn(run_ingress_control(
            worker,
            status_rx,
            inbound_tx,
            Zeroizing::new([0x4d; MESH_INGRESS_CONTROL_KEY_LEN]),
            Vec::new(),
            vm_id,
            generation,
            None,
        ));
        status_tx.send(WORKER_READY_MESSAGE).unwrap();
        let mut ready = [0_u8; WORKER_READY_MESSAGE.len()];
        runner.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, WORKER_READY_MESSAGE);

        let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
        frame[..8].copy_from_slice(b"CWHOSTP1");
        runner.write_all(&frame).await.unwrap();
        runner.flush().await.unwrap();
        assert!(matches!(
            control.await.unwrap(),
            Err(NetworkWorkerError::Protocol)
        ));
        assert!(inbound_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn authenticated_mesh_control_delivers_only_an_allowed_unix_stream() {
        let (vm_id, generation) = identity();
        let mesh_key = [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
        let guest_port = 3_000;
        let (runner, worker) = StdUnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        worker.set_nonblocking(true).unwrap();
        let mut runner = tokio::net::UnixStream::from_std(runner).unwrap();
        let worker = tokio::net::UnixStream::from_std(worker).unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = oneshot::channel();
        let control = tokio::spawn(run_ingress_control(
            worker,
            status_rx,
            inbound_tx,
            Zeroizing::new(mesh_key),
            vec![guest_port],
            vm_id,
            generation,
            None,
        ));
        status_tx.send(WORKER_READY_MESSAGE).unwrap();
        let mut ready = [0_u8; WORKER_READY_MESSAGE.len()];
        runner.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, WORKER_READY_MESSAGE);

        let binding = MeshIngressBinding::new(guest_port).unwrap();
        let frame =
            MeshIngressControlFrame::encode(vm_id, generation, 1, binding, &mesh_key).unwrap();
        runner.write_all(&frame).await.unwrap();
        runner.flush().await.unwrap();
        let (mut mesh_peer, bridge) = StdUnixStream::pair().unwrap();
        send_mesh_ingress_descriptor(runner.as_raw_fd(), bridge.as_raw_fd()).unwrap();
        // The worker says it holds the connection, which is what lets the
        // runner let go of its copy (#5084).
        // Generous, so a loaded host fails only a missing acknowledgement.
        const WAIT: Duration = Duration::from_secs(30);
        let held = crate::mesh_ingress_ack::mesh_ingress_ack(1);
        let mut said = [0_u8; crate::mesh_ingress_ack::MESH_INGRESS_ACK_LEN];
        tokio::time::timeout(WAIT, runner.read_exact(&mut said))
            .await
            .expect("the worker did not acknowledge the connection")
            .unwrap();
        assert_eq!(said, held);

        let mut incoming = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("control did not deliver the Mesh stream")
            .expect("control closed the ingress channel");
        assert_eq!(incoming.guest_port, guest_port);
        mesh_peer.write_all(b"mesh-stream").unwrap();
        let mut received = [0_u8; 11];
        incoming.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"mesh-stream");

        drop(runner);
        assert!(matches!(
            control.await.unwrap(),
            Err(NetworkWorkerError::FrameIo)
        ));
    }

    #[test]
    fn product_bootstrap_binds_network_broker_and_policy_to_one_generation() {
        let (vm_id, generation) = identity();
        let network_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let broker_key = [0x5a; BROKER_IPC_KEY_LEN];
        let mesh_ingress_key = [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
        let mesh_ingress_ports = [22, 3_000];
        let bytes = encode_product_worker_bootstrap(
            vm_id,
            generation,
            &network_key,
            &broker_key,
            &mesh_ingress_key,
            &mesh_ingress_ports,
            CompiledPolicy::open().digest(),
        )
        .unwrap();
        let decoded = decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation).unwrap();
        assert_eq!(decoded.broker_binding.environment_id(), vm_id);
        assert_eq!(decoded.broker_binding.generation(), generation);
        assert_eq!(
            decoded.broker_binding.policy_digest(),
            CompiledPolicy::open().digest()
        );
        network_key.with_bytes(|expected| {
            decoded
                .network_key
                .with_bytes(|actual| assert_eq!(actual, expected));
        });
        assert_eq!(decoded.mesh_ingress_ports, mesh_ingress_ports);
        assert!(decode_product_worker_bootstrap(bytes.as_ref(), vm_id, generation + 1).is_err());

        // The worker binds whichever selected policy the runner names; the
        // broker, which compiles the document, refuses a mismatch (#2537).
        let mut other_policy = bytes.clone();
        other_policy[PRODUCT_POLICY_DIGEST_OFFSET] ^= 1;
        let other =
            decode_product_worker_bootstrap(other_policy.as_ref(), vm_id, generation).unwrap();
        assert_ne!(
            other.broker_binding.policy_digest(),
            CompiledPolicy::open().digest()
        );
        let mut zero_policy = bytes.clone();
        zero_policy[PRODUCT_POLICY_DIGEST_OFFSET..PRODUCT_BROKER_KEY_OFFSET].fill(0);
        assert!(decode_product_worker_bootstrap(zero_policy.as_ref(), vm_id, generation).is_err());
        let mut zero_broker_key = bytes.clone();
        zero_broker_key[PRODUCT_BROKER_KEY_OFFSET..PRODUCT_MESH_INGRESS_KEY_OFFSET].fill(0);
        assert!(
            decode_product_worker_bootstrap(zero_broker_key.as_ref(), vm_id, generation).is_err()
        );
        assert!(
            encode_product_worker_bootstrap(
                vm_id,
                generation,
                &network_key,
                &[0_u8; BROKER_IPC_KEY_LEN],
                &mesh_ingress_key,
                &mesh_ingress_ports,
                CompiledPolicy::open().digest(),
            )
            .is_err()
        );
        let mut zero_mesh_ingress_key = bytes.clone();
        zero_mesh_ingress_key
            [PRODUCT_MESH_INGRESS_KEY_OFFSET..PRODUCT_MESH_INGRESS_PORT_COUNT_OFFSET]
            .fill(0);
        assert!(
            decode_product_worker_bootstrap(zero_mesh_ingress_key.as_ref(), vm_id, generation)
                .is_err()
        );
        let mut noncanonical_mesh_ports = bytes.clone();
        noncanonical_mesh_ports[PRODUCT_MESH_INGRESS_PORTS_OFFSET
            ..PRODUCT_MESH_INGRESS_PORTS_OFFSET + std::mem::size_of::<u16>()]
            .copy_from_slice(&3_000_u16.to_le_bytes());
        noncanonical_mesh_ports[PRODUCT_MESH_INGRESS_PORTS_OFFSET + std::mem::size_of::<u16>()
            ..PRODUCT_MESH_INGRESS_PORTS_OFFSET + 2 * std::mem::size_of::<u16>()]
            .copy_from_slice(&22_u16.to_le_bytes());
        assert!(
            decode_product_worker_bootstrap(noncanonical_mesh_ports.as_ref(), vm_id, generation)
                .is_err()
        );
        let mut nonzero_padding = bytes.clone();
        nonzero_padding[PRODUCT_MESH_INGRESS_PORTS_OFFSET
            + mesh_ingress_ports.len() * std::mem::size_of::<u16>()] = 1;
        assert!(
            decode_product_worker_bootstrap(nonzero_padding.as_ref(), vm_id, generation).is_err()
        );
        assert!(
            !bytes
                .windows(TOKEN.len())
                .any(|window| window == TOKEN.as_bytes())
        );
    }
}
