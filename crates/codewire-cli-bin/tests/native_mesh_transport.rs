#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codewire_client::{CoordinatorHandlers, MeshCoordinateIdentity, MeshCoordinatorPeerSession};
use codewire_derp::{Relay, self_signed_tls_config, serve_stun, serve_tls};
use codewire_local_vmm::mesh_enrollment::{
    MESH_ENROLLMENT_BOOTSTRAP_FD, MESH_ENROLLMENT_CONFINE_MESSAGE,
    MESH_ENROLLMENT_PREPARED_MESSAGE, MESH_ENROLLMENT_READY_MESSAGE,
    MESH_ENROLLMENT_STATUS_MAX_BYTES, MESH_ENROLLMENT_TRANSFER_FD, MeshEnrollmentAuthSource,
    encode_mesh_enrollment_bootstrap,
};
use codewire_local_vmm::mesh_ingress::{
    MESH_INGRESS_CONTROL_KEY_LEN, MeshAttachment, mesh_ingress_channel,
};
use codewire_local_vmm::mesh_process::{
    MESH_TRANSPORT_BOOTSTRAP_FD, MESH_TRANSPORT_CONFINE_MESSAGE, MESH_TRANSPORT_ENROLLMENT_FD,
    MESH_TRANSPORT_PREPARED_MESSAGE, MESH_TRANSPORT_READY_MESSAGE, MESH_TRANSPORT_STATUS_MAX_BYTES,
    MeshTransportStartupFailure, MeshTransportStartupStatus, decode_mesh_transport_startup_status,
    encode_mesh_transport_bootstrap, encode_mesh_transport_enrollment,
};
use codewire_local_vmm::mesh_transport::receive_mesh_ingress_submissions;
use codewire_mesh::mesh_authorization::hash_local_environment_token;
use codewire_mesh::{Config as MeshConfig, LocalMeshAuthorizationConfig, StunServerConfig};
use codewire_proto::codewire::v1::{
    CreateMeshNetworkRequest, CreateMeshNodeEnrollmentRequest, MeshNetworkServiceClient,
    MeshNodeServiceClient, RevokeMeshNodeRequest,
};
use codewire_server_core::auth::hash_api_key;
use codewire_tailnet::conn::{Conn, Options as ConnOptions, PeerTransport};
use codewire_tailnet::derp::NodePrivate as DerpPrivate;
use codewire_tailnet::derp_transport::{
    DerpTarget, DerpTransport, connect_derp_transport_resolved,
};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::DiscoPrivate;
use codewire_tailnet::node::{Node, NodePublic, prefix_from_uuid};
use codewire_tailnet::wg::{PublicKey, StaticSecret};
use connectrpc::client::{ClientConfig, HttpClient};
use rand::rngs::OsRng;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

const ORGANIZATION_ID: &str = "org-native-mesh-process";
const NETWORK_ID: &str = "network-native-mesh-process";
const NODE_NAME: &str = "sandbox-native-mesh-process";
const API_KEY: &str = "cw_native-mesh-process-api";
const OWNER_ENVIRONMENT_ID: &str = "native-mesh-process-owner";
const OWNER_ENVIRONMENT_TOKEN: &str = "native-mesh-process-environment-token";
const GUEST_PORT: u16 = 3_000;
const DENIED_GUEST_PORT: u16 = 3_001;
const TEST_KEY: [u8; MESH_INGRESS_CONTROL_KEY_LEN] = [0x6d; MESH_INGRESS_CONTROL_KEY_LEN];

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Mesh transport process {} did not terminate",
                self.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_wait(&mut self) -> ExitStatus {
        self.0.as_mut().unwrap().kill().unwrap();
        self.wait_bounded()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Fixture {
    mesh_address: SocketAddr,
    derp_address: SocketAddr,
    stun_address: Option<SocketAddr>,
    mesh_task: tokio::task::JoinHandle<()>,
    derp_task: tokio::task::JoinHandle<()>,
    stun_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.mesh_task.abort();
        self.derp_task.abort();
        if let Some(task) = &self.stun_task {
            task.abort();
        }
    }
}

async fn start_fixture(with_stun: bool) -> Fixture {
    let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let derp_address = derp_listener.local_addr().unwrap();
    let relay = Relay::new(DerpPrivate::generate(&mut OsRng));
    let tls = self_signed_tls_config(&[]).unwrap();
    let derp_task = tokio::spawn(async move {
        serve_tls(derp_listener, relay, tls).await.unwrap();
    });

    let (stun_address, stun_task) = if with_stun {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            serve_stun(socket).await.unwrap();
        });
        (Some(address), Some(task))
    } else {
        (None, None)
    };

    let mesh_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mesh_address = mesh_listener.local_addr().unwrap();
    let config = MeshConfig {
        bind_addr: mesh_address,
        base_url: format!("http://{mesh_address}"),
        // The map's test-only marker selects TLS with certificate validation
        // disabled. The actual relay listener above still uses encrypted TLS.
        derp_url: Some(format!("http://{derp_address}")),
        stun_servers: stun_address
            .map(|address| {
                vec![StunServerConfig {
                    host: address.ip().to_string(),
                    port: address.port(),
                }]
            })
            .unwrap_or_default(),
        database_url: None,
        mesh_authorization: None,
        local_authorization: Some(LocalMeshAuthorizationConfig {
            organization_id: ORGANIZATION_ID.to_owned(),
            api_key_hash: hash_api_key(API_KEY),
            environment_id: OWNER_ENVIRONMENT_ID.to_owned(),
            environment_token_hash: hash_local_environment_token(OWNER_ENVIRONMENT_TOKEN),
        }),
    };
    let app = codewire_mesh::router(config);
    let mesh_task = tokio::spawn(async move {
        axum::serve(mesh_listener, app).await.unwrap();
    });
    Fixture {
        mesh_address,
        derp_address,
        stun_address,
        mesh_task,
        derp_task,
        stun_task,
    }
}

fn client_config(address: SocketAddr) -> ClientConfig {
    ClientConfig::new(format!("http://{address}").parse().unwrap())
        .with_default_header("authorization", format!("Bearer {API_KEY}"))
}

async fn seed_network(address: SocketAddr) {
    MeshNetworkServiceClient::new(HttpClient::plaintext(), client_config(address))
        .create_mesh_network(CreateMeshNetworkRequest {
            org_id: ORGANIZATION_ID.to_owned(),
            network_id: NETWORK_ID.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn create_enrollment(address: SocketAddr) -> String {
    MeshNodeServiceClient::new(HttpClient::plaintext(), client_config(address))
        .create_mesh_node_enrollment(CreateMeshNodeEnrollmentRequest {
            org_id: ORGANIZATION_ID.to_owned(),
            network_id: NETWORK_ID.to_owned(),
            node_name: NODE_NAME.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned()
        .enrollment_code
}

async fn revoke_node(address: SocketAddr) {
    MeshNodeServiceClient::new(HttpClient::plaintext(), client_config(address))
        .revoke_mesh_node(RevokeMeshNodeRequest {
            org_id: ORGANIZATION_ID.to_owned(),
            network_id: NETWORK_ID.to_owned(),
            node_name: NODE_NAME.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
}

fn attachment(mesh_address: SocketAddr) -> MeshAttachment {
    MeshAttachment::new(
        &format!("http://{mesh_address}"),
        ORGANIZATION_ID,
        NETWORK_ID,
        NODE_NAME,
        [GUEST_PORT],
    )
    .unwrap()
}

fn private_auth_roots(mesh_url: &str) -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let mesh = root.path().join("mesh");
    let platform = root.path().join("unused-missing-platform-root");
    fs::create_dir(&mesh).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&mesh, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        "mesh_url = {mesh_url:?}\nmesh_auth_token = {API_KEY:?}\n\n[local_identity]\norganization_id = {ORGANIZATION_ID:?}\napi_key = {API_KEY:?}\nenvironment_id = {OWNER_ENVIRONMENT_ID:?}\nenvironment_token = {OWNER_ENVIRONMENT_TOKEN:?}\n"
    );
    let config_path = mesh.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(config_path, fs::Permissions::from_mode(0o600)).unwrap();
    (root, mesh, platform)
}

fn spawn_enrollment_broker(
    environment_id: Uuid,
    generation: u64,
    mesh_data_dir: &Path,
    platform_config_dir: &Path,
    transfer_child: StdUnixStream,
) -> (StdUnixStream, ChildGuard) {
    let (control_parent, control_child) = StdUnixStream::pair().unwrap();
    control_parent
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    control_parent
        .set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let control_source = control_child.as_raw_fd();
    let transfer_source = transfer_child.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-mesh-enrollment-broker")
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .arg("--mesh-data-dir")
        .arg(mesh_data_dir)
        .arg("--platform-config-dir")
        .arg(platform_config_dir)
        .env_clear()
        .current_dir(mesh_data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook performs only async-signal-safe descriptor/prctl
    // syscalls and installs exactly the two private connected capabilities.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                || libc::getppid() != expected_parent
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let control_copy = libc::fcntl(control_source, libc::F_DUPFD_CLOEXEC, 6);
            let transfer_copy = libc::fcntl(transfer_source, libc::F_DUPFD_CLOEXEC, 6);
            if control_copy == -1 || transfer_copy == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(control_copy, MESH_ENROLLMENT_BOOTSTRAP_FD) == -1
                || libc::dup2(transfer_copy, MESH_ENROLLMENT_TRANSFER_FD) == -1
                || libc::fcntl(MESH_ENROLLMENT_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1
                || libc::fcntl(MESH_ENROLLMENT_TRANSFER_FD, libc::F_SETFD, 0) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(control_copy);
            libc::close(transfer_copy);
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(control_child);
    drop(transfer_child);
    (control_parent, ChildGuard(Some(child)))
}

fn spawn_transport(
    environment_id: Uuid,
    generation: u64,
) -> (StdUnixStream, StdUnixStream, ChildGuard) {
    let (enrollment_parent, enrollment_child) = StdUnixStream::pair().unwrap();
    enrollment_parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (control, child) =
        spawn_transport_with_enrollment(environment_id, generation, enrollment_child);
    (control, enrollment_parent, child)
}

fn spawn_transport_with_enrollment(
    environment_id: Uuid,
    generation: u64,
    enrollment_child: StdUnixStream,
) -> (StdUnixStream, ChildGuard) {
    let (control_parent, control_child) = StdUnixStream::pair().unwrap();
    control_parent
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    control_parent
        .set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let control_source = control_child.as_raw_fd();
    let enrollment_source = enrollment_child.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-mesh-transport")
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook performs only async-signal-safe descriptor/prctl
    // syscalls. Each source is first duplicated above the fixed target range,
    // avoiding aliasing if the parent happened to allocate fd 4 or 5.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let control_copy = libc::fcntl(control_source, libc::F_DUPFD_CLOEXEC, 6);
            let enrollment_copy = libc::fcntl(enrollment_source, libc::F_DUPFD_CLOEXEC, 6);
            if control_copy == -1 || enrollment_copy == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(control_copy, MESH_TRANSPORT_BOOTSTRAP_FD) == -1
                || libc::dup2(enrollment_copy, MESH_TRANSPORT_ENROLLMENT_FD) == -1
                || libc::fcntl(MESH_TRANSPORT_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1
                || libc::fcntl(MESH_TRANSPORT_ENROLLMENT_FD, libc::F_SETFD, 0) == -1
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(control_copy);
            libc::close(enrollment_copy);
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(control_child);
    drop(enrollment_child);
    (control_parent, ChildGuard(Some(child)))
}

fn start_transport(
    mesh_address: SocketAddr,
    enrollment: &str,
    environment_id: Uuid,
    generation: u64,
) -> (StdUnixStream, ChildGuard) {
    let bootstrap = encode_mesh_transport_bootstrap(
        environment_id,
        generation,
        &attachment(mesh_address),
        &TEST_KEY,
    )
    .unwrap();
    let enrollment_record = encode_mesh_transport_enrollment(enrollment).unwrap();
    let (mut control, mut enrollment_stream, child) = spawn_transport(environment_id, generation);
    control.write_all(&bootstrap).unwrap();
    enrollment_stream.write_all(&enrollment_record).unwrap();
    enrollment_stream
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    drop(enrollment_stream);
    (control, child)
}

fn admit_transport(control: &mut StdUnixStream) {
    assert_eq!(read_status_frame(control), MESH_TRANSPORT_PREPARED_MESSAGE);
    control.write_all(MESH_TRANSPORT_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(control), MESH_TRANSPORT_READY_MESSAGE);
}

fn read_status_frame(stream: &StdUnixStream) -> Vec<u8> {
    read_bounded_status_frame(stream, MESH_TRANSPORT_STATUS_MAX_BYTES)
}

fn read_enrollment_status_frame(stream: &StdUnixStream) -> Vec<u8> {
    read_bounded_status_frame(stream, MESH_ENROLLMENT_STATUS_MAX_BYTES)
}

fn read_bounded_status_frame(stream: &StdUnixStream, maximum_bytes: usize) -> Vec<u8> {
    let mut stream = stream;
    let mut frame = Vec::new();
    loop {
        assert!(
            frame.len() < maximum_bytes,
            "native Mesh process status exceeded its bound"
        );
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return frame;
        }
    }
}

struct DialTailnet {
    conn: Arc<Conn>,
    target: watch::Receiver<Option<Node>>,
    coordinator_task: tokio::task::JoinHandle<()>,
    direct_udp: Option<direct_udp::Handle>,
}

impl Drop for DialTailnet {
    fn drop(&mut self) {
        self.coordinator_task.abort();
        self.conn.close();
    }
}

async fn connect_dial_tailnet(fixture: &Fixture, target_address: IpAddr) -> DialTailnet {
    let mut coordinator = MeshCoordinatorPeerSession::connect_resolved_with_setup_timeout(
        &format!("http://{}", fixture.mesh_address),
        API_KEY,
        MeshCoordinateIdentity::dial(ORGANIZATION_ID, NETWORK_ID),
        vec![fixture.mesh_address],
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let map = coordinator.take_setup_derp_map().unwrap();
    assert_eq!(
        map["Regions"]["1"]["Nodes"][0]["DERPPort"],
        fixture.derp_address.port()
    );
    let secret = StaticSecret::random_from_rng(OsRng);
    let fallback = connect_derp_transport_resolved(
        &DerpTarget {
            host: fixture.derp_address.ip().to_string(),
            port: fixture.derp_address.port(),
            transport: DerpTransport::Tls { skip_verify: true },
        },
        vec![fixture.derp_address],
        &secret,
    )
    .await
    .unwrap();
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    let (transport, direct_udp) = match fixture.stun_address {
        Some(stun_address) => {
            let local_node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
            let (transport, handle) = direct_udp::wrap_transport(
                fallback,
                direct_udp::Options::new(
                    "0.0.0.0:0".parse().unwrap(),
                    Vec::new(),
                    local_node_key,
                    disco_private.clone(),
                )
                .with_stun_servers(vec![stun_address]),
            )
            .await
            .unwrap();
            (transport, Some(handle))
        }
        None => (fallback, None),
    };
    let endpoints = direct_udp
        .as_ref()
        .map(|handle| handle.advertised_endpoints())
        .unwrap_or_default();
    let dial_id = Uuid::new_v4();
    let mut options = ConnOptions::new(dial_id);
    options.addresses = vec![prefix_from_uuid(&dial_id)];
    options.endpoints = endpoints;
    options.private_key = Some(secret);
    options.disco_private = Some(disco_private);
    let conn = Arc::new(Conn::new(options, transport).unwrap());
    conn.set_preferred_derp(1);
    coordinator.subscribe(NODE_NAME).await.unwrap();
    let (node_tx, node_rx) = mpsc::unbounded_channel();
    conn.set_node_callback(move |node| {
        let _ = node_tx.send(node.clone());
    });
    let (target_tx, target) = watch::channel(None);
    let update_conn = Arc::clone(&conn);
    let coordinator_task = tokio::spawn(async move {
        let _ = coordinator
            .run_with_node_updates(
                node_rx,
                CoordinatorHandlers {
                    on_peers: move |nodes| {
                        update_conn.update_peers(nodes).unwrap();
                        if let Some(node) = nodes.iter().find(|node| {
                            node.addresses
                                .iter()
                                .any(|prefix| prefix.addr() == target_address)
                        }) {
                            let _ = target_tx.send(Some(node.clone()));
                        }
                    },
                    on_derp_map: |_| {},
                },
            )
            .await;
    });
    DialTailnet {
        conn,
        target,
        coordinator_task,
        direct_udp,
    }
}

async fn wait_for_target(target: &mut watch::Receiver<Option<Node>>) -> Node {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(node) = target.borrow().clone() {
                return node;
            }
            target.changed().await.unwrap();
        }
    })
    .await
    .expect("dial coordinator did not publish the isolated Mesh peer")
}

async fn wait_for_direct_path(dial: &DialTailnet, target: &Node) {
    let direct_udp = dial.direct_udp.as_ref().expect("direct UDP fixture handle");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if dial.conn.probe_peer_path(target).unwrap().transport == PeerTransport::DirectUdp {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("isolated Mesh peer did not establish direct UDP");
    assert!(direct_udp.has_verified_endpoint(&target.key));
}

#[test]
fn cw_hidden_mesh_transport_preserves_its_typed_failure_exit() {
    let invalid = File::open("/dev/null").unwrap();
    let source = invalid.as_raw_fd();
    let environment_id = Uuid::new_v4();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-mesh-transport")
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg("9")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook deliberately installs a non-socket at the first fixed
    // descriptor; validation fails before descriptor 5 is inspected.
    unsafe {
        command.pre_exec(move || {
            if source != MESH_TRANSPORT_BOOTSTRAP_FD
                && libc::dup2(source, MESH_TRANSPORT_BOOTSTRAP_FD) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(MESH_TRANSPORT_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().unwrap();
    assert_eq!(
        status.code(),
        Some(MeshTransportStartupFailure::InheritedDescriptor.exit_code())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_broker_transfers_directly_to_the_confined_mesh_process() {
    let fixture = start_fixture(false).await;
    seed_network(fixture.mesh_address).await;
    let (_auth_root, mesh_data_dir, platform_config_dir) =
        private_auth_roots(&format!("http://{}", fixture.mesh_address));
    let environment_id = Uuid::new_v4();
    let generation = 6;
    let attachment = attachment(fixture.mesh_address);
    let transport_bootstrap =
        encode_mesh_transport_bootstrap(environment_id, generation, &attachment, &TEST_KEY)
            .unwrap();
    let enrollment_bootstrap = encode_mesh_enrollment_bootstrap(
        environment_id,
        generation,
        MeshEnrollmentAuthSource::StandaloneLocal,
        &attachment,
    )
    .unwrap();

    // The runner-shaped parent creates this capability channel and gives one
    // end to each child. It never reads or writes the enrollment payload.
    let (broker_transfer, transport_enrollment) = StdUnixStream::pair().unwrap();
    let (mut transport_control, mut transport_child) =
        spawn_transport_with_enrollment(environment_id, generation, transport_enrollment);
    let (mut enrollment_control, mut enrollment_child) = spawn_enrollment_broker(
        environment_id,
        generation,
        &mesh_data_dir,
        &platform_config_dir,
        broker_transfer,
    );
    transport_control.write_all(&transport_bootstrap).unwrap();
    transport_control.flush().unwrap();
    enrollment_control.write_all(&enrollment_bootstrap).unwrap();
    enrollment_control.flush().unwrap();

    assert_eq!(
        read_enrollment_status_frame(&enrollment_control),
        MESH_ENROLLMENT_PREPARED_MESSAGE
    );
    enrollment_control
        .write_all(MESH_ENROLLMENT_CONFINE_MESSAGE)
        .unwrap();
    enrollment_control.flush().unwrap();
    assert_eq!(
        read_enrollment_status_frame(&enrollment_control),
        MESH_ENROLLMENT_READY_MESSAGE
    );
    assert!(enrollment_child.wait_bounded().success());

    assert_eq!(
        read_status_frame(&transport_control),
        MESH_TRANSPORT_PREPARED_MESSAGE
    );
    transport_control
        .write_all(MESH_TRANSPORT_CONFINE_MESSAGE)
        .unwrap();
    transport_control.flush().unwrap();
    assert_eq!(
        read_status_frame(&transport_control),
        MESH_TRANSPORT_READY_MESSAGE
    );

    revoke_node(fixture.mesh_address).await;
    assert!(transport_child.wait_bounded().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confined_mesh_process_relays_only_admitted_ports_and_requires_fresh_enrollment() {
    let fixture = start_fixture(false).await;
    seed_network(fixture.mesh_address).await;
    let environment_id = Uuid::new_v4();
    let generation = 7;
    let enrollment = create_enrollment(fixture.mesh_address).await;
    let (mut control, mut child) = start_transport(
        fixture.mesh_address,
        &enrollment,
        environment_id,
        generation,
    );
    admit_transport(&mut control);

    control.set_nonblocking(true).unwrap();
    let (publisher, mut accepted) = mesh_ingress_channel(&[GUEST_PORT]).unwrap();
    let receiver = tokio::spawn(receive_mesh_ingress_submissions(
        tokio::net::UnixStream::from_std(control).unwrap(),
        publisher,
        environment_id,
        generation,
        vec![GUEST_PORT],
        Zeroizing::new(TEST_KEY),
    ));
    let target_address = prefix_from_uuid(&environment_id).addr();
    let mut dial = connect_dial_tailnet(&fixture, target_address).await;
    let target = wait_for_target(&mut dial.target).await;
    assert_eq!(
        dial.conn.probe_peer_path(&target).unwrap().transport,
        PeerTransport::DerpRelay
    );

    let mut remote = tokio::time::timeout(
        Duration::from_secs(10),
        dial.conn
            .dial_context_tcp(SocketAddr::new(target_address, GUEST_PORT)),
    )
    .await
    .expect("DERP-backed Mesh TCP dial timed out")
    .unwrap();
    remote.write_all(b"isolated mesh request").await.unwrap();
    remote.shutdown().await.unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
        .await
        .expect("isolated Mesh process did not submit the stream")
        .unwrap();
    assert_eq!(admitted.binding.guest_port, GUEST_PORT);
    admitted.stream.set_nonblocking(true).unwrap();
    let mut worker = tokio::net::UnixStream::from_std(admitted.stream).unwrap();
    let mut request = [0_u8; 21];
    worker.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"isolated mesh request");
    let mut eof = [0_u8; 1];
    assert_eq!(worker.read(&mut eof).await.unwrap(), 0);
    worker.write_all(b"isolated mesh response").await.unwrap();
    worker.shutdown().await.unwrap();
    let mut response = [0_u8; 22];
    remote.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"isolated mesh response");

    let denied = tokio::time::timeout(
        Duration::from_secs(2),
        dial.conn
            .dial_context_tcp(SocketAddr::new(target_address, DENIED_GUEST_PORT)),
    )
    .await;
    // The minimal userspace dialer may return a handle before the virtual TCP
    // handshake reports a missing listener. Admission is defined by whether a
    // connected capability can cross into the runner, not that eager handle.
    drop(denied);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), accepted.recv())
            .await
            .is_err(),
        "an unadmitted Mesh port reached the runner queue"
    );

    revoke_node(fixture.mesh_address).await;
    assert!(child.wait_bounded().success());
    receiver.await.unwrap().unwrap();

    let (replay_control, _replay_enrollment, mut replay_child) =
        spawn_transport(environment_id, generation + 1);
    let replay_bootstrap = encode_mesh_transport_bootstrap(
        environment_id,
        generation + 1,
        &attachment(fixture.mesh_address),
        &TEST_KEY,
    )
    .unwrap();
    let replay_record = encode_mesh_transport_enrollment(&enrollment).unwrap();
    let mut replay_control = replay_control;
    let mut replay_enrollment = _replay_enrollment;
    replay_control.write_all(&replay_bootstrap).unwrap();
    replay_enrollment.write_all(&replay_record).unwrap();
    replay_enrollment
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    drop(replay_enrollment);
    assert_eq!(
        decode_mesh_transport_startup_status(&read_status_frame(&replay_control)),
        Some(MeshTransportStartupStatus::Failed(
            MeshTransportStartupFailure::CoordinatorSetup
        ))
    );
    assert_eq!(
        replay_child.wait_bounded().code(),
        Some(MeshTransportStartupFailure::CoordinatorSetup.exit_code())
    );

    let fresh_enrollment = create_enrollment(fixture.mesh_address).await;
    let (mut fresh_control, mut fresh_child) = start_transport(
        fixture.mesh_address,
        &fresh_enrollment,
        environment_id,
        generation + 2,
    );
    admit_transport(&mut fresh_control);
    let status = fresh_child.kill_and_wait();
    assert!(!status.success());
    let mut eof = [0_u8; 1];
    assert_eq!(fresh_control.read(&mut eof).unwrap(), 0);
    revoke_node(fixture.mesh_address).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confined_mesh_process_establishes_a_stun_discovered_direct_udp_path() {
    let fixture = start_fixture(true).await;
    seed_network(fixture.mesh_address).await;
    let environment_id = Uuid::new_v4();
    let generation = 11;
    let enrollment = create_enrollment(fixture.mesh_address).await;
    let (mut control, mut child) = start_transport(
        fixture.mesh_address,
        &enrollment,
        environment_id,
        generation,
    );
    admit_transport(&mut control);

    control.set_nonblocking(true).unwrap();
    let (publisher, mut accepted) = mesh_ingress_channel(&[GUEST_PORT]).unwrap();
    let receiver = tokio::spawn(receive_mesh_ingress_submissions(
        tokio::net::UnixStream::from_std(control).unwrap(),
        publisher,
        environment_id,
        generation,
        vec![GUEST_PORT],
        Zeroizing::new(TEST_KEY),
    ));
    let target_address = prefix_from_uuid(&environment_id).addr();
    let mut dial = connect_dial_tailnet(&fixture, target_address).await;
    let target = wait_for_target(&mut dial.target).await;
    assert!(!target.endpoints.is_empty());
    assert!(
        !dial
            .direct_udp
            .as_ref()
            .unwrap()
            .advertised_endpoints()
            .is_empty()
    );
    wait_for_direct_path(&dial, &target).await;

    let mut remote = tokio::time::timeout(
        Duration::from_secs(10),
        dial.conn
            .dial_context_tcp(SocketAddr::new(target_address, GUEST_PORT)),
    )
    .await
    .expect("direct-UDP Mesh TCP dial timed out")
    .unwrap();
    remote.write_all(b"direct mesh request").await.unwrap();
    remote.shutdown().await.unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
        .await
        .expect("direct Mesh process did not submit the stream")
        .unwrap();
    admitted.stream.set_nonblocking(true).unwrap();
    let mut worker = tokio::net::UnixStream::from_std(admitted.stream).unwrap();
    let mut request = [0_u8; 19];
    worker.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"direct mesh request");
    worker.write_all(b"direct mesh response").await.unwrap();
    worker.shutdown().await.unwrap();
    let mut response = [0_u8; 20];
    remote.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"direct mesh response");
    let stats = dial.direct_udp.as_ref().unwrap().stats();
    assert!(stats.direct_wg_sent > 0);
    assert!(stats.direct_wg_received > 0);

    revoke_node(fixture.mesh_address).await;
    assert!(child.wait_bounded().success());
    receiver.await.unwrap().unwrap();
}
