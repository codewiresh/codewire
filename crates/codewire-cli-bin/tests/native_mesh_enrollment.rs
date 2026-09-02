#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use codewire_local_vmm::mesh_enrollment::{
    MESH_ENROLLMENT_BOOTSTRAP_FD, MESH_ENROLLMENT_CONFINE_MESSAGE,
    MESH_ENROLLMENT_PREPARED_MESSAGE, MESH_ENROLLMENT_READY_MESSAGE,
    MESH_ENROLLMENT_STATUS_MAX_BYTES, MESH_ENROLLMENT_TRANSFER_FD, MeshEnrollmentAuthSource,
    MeshEnrollmentStartupFailure, encode_mesh_enrollment_bootstrap,
};
use codewire_local_vmm::mesh_ingress::MeshAttachment;
use codewire_mesh::mesh_authorization::hash_local_environment_token;
use codewire_mesh::{Config as MeshConfig, LocalMeshAuthorizationConfig};
use codewire_proto::codewire::v1::{CreateMeshNetworkRequest, MeshNetworkServiceClient};
use codewire_server_core::auth::hash_api_key;
use connectrpc::client::{ClientConfig, HttpClient};
use tempfile::TempDir;
use uuid::Uuid;

const ORGANIZATION_ID: &str = "org-native-enrollment";
const NETWORK_ID: &str = "network-native-enrollment";
const NODE_NAME: &str = "sandbox-native-enrollment";
const API_KEY: &str = "cw_native-enrollment-owner-secret";
const OWNER_ENVIRONMENT_ID: &str = "native-enrollment-owner";
const OWNER_ENVIRONMENT_TOKEN: &str = "native-enrollment-environment-token";
const GUEST_PORT: u16 = 3_000;

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
                "Mesh enrollment issuer {} did not terminate",
                self.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
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

struct MeshFixture {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MeshFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_mesh_fixture() -> MeshFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = codewire_mesh::router(MeshConfig {
        bind_addr: address,
        base_url: format!("http://{address}"),
        derp_url: Some("http://127.0.0.1:9".to_owned()),
        stun_servers: Vec::new(),
        database_url: None,
        mesh_authorization: None,
        local_authorization: Some(LocalMeshAuthorizationConfig {
            organization_id: ORGANIZATION_ID.to_owned(),
            api_key_hash: hash_api_key(API_KEY),
            environment_id: OWNER_ENVIRONMENT_ID.to_owned(),
            environment_token_hash: hash_local_environment_token(OWNER_ENVIRONMENT_TOKEN),
        }),
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MeshFixture { address, task }
}

async fn seed_network(address: SocketAddr) {
    let config = ClientConfig::new(format!("http://{address}").parse().unwrap())
        .with_default_header("authorization", format!("Bearer {API_KEY}"));
    MeshNetworkServiceClient::new(HttpClient::plaintext(), config)
        .create_mesh_network(CreateMeshNetworkRequest {
            org_id: ORGANIZATION_ID.to_owned(),
            network_id: NETWORK_ID.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
}

fn private_roots(mesh_url: &str) -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
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

fn attachment(address: SocketAddr) -> MeshAttachment {
    MeshAttachment::new(
        &format!("http://{address}"),
        ORGANIZATION_ID,
        NETWORK_ID,
        NODE_NAME,
        [GUEST_PORT],
    )
    .unwrap()
}

fn spawn_issuer(
    environment_id: Uuid,
    generation: u64,
    mesh_data_dir: &std::path::Path,
    platform_config_dir: &std::path::Path,
) -> (StdUnixStream, StdUnixStream, ChildGuard) {
    let (control_parent, control_child) = StdUnixStream::pair().unwrap();
    let (transfer_parent, transfer_child) = StdUnixStream::pair().unwrap();
    control_parent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    transfer_parent
        .set_read_timeout(Some(Duration::from_secs(10)))
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
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                || libc::getppid() != expected_parent
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
    (control_parent, transfer_parent, ChildGuard(Some(child)))
}

fn read_status(control: &mut StdUnixStream) -> Vec<u8> {
    let mut status = Vec::with_capacity(MESH_ENROLLMENT_STATUS_MAX_BYTES);
    loop {
        assert!(status.len() < MESH_ENROLLMENT_STATUS_MAX_BYTES);
        let mut byte = [0_u8; 1];
        control.read_exact(&mut byte).unwrap();
        status.push(byte[0]);
        if byte[0] == b'\n' {
            return status;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confined_issuer_mints_one_enrollment_directly_from_standalone_owner_auth() {
    let fixture = start_mesh_fixture().await;
    seed_network(fixture.address).await;
    let (_root, mesh_root, platform_root) = private_roots(&format!("http://{}", fixture.address));
    let environment_id = Uuid::new_v4();
    let generation = 7;
    let bootstrap = encode_mesh_enrollment_bootstrap(
        environment_id,
        generation,
        MeshEnrollmentAuthSource::StandaloneLocal,
        &attachment(fixture.address),
    )
    .unwrap();
    let (mut control, mut transfer, mut child) =
        spawn_issuer(environment_id, generation, &mesh_root, &platform_root);
    control.write_all(&bootstrap).unwrap();
    control.flush().unwrap();
    assert_eq!(read_status(&mut control), MESH_ENROLLMENT_PREPARED_MESSAGE);

    let cmdline = fs::read(format!("/proc/{}/cmdline", child.id())).unwrap();
    let environ = fs::read(format!("/proc/{}/environ", child.id())).unwrap();
    assert!(
        !cmdline
            .windows(API_KEY.len())
            .any(|value| value == API_KEY.as_bytes())
    );
    assert!(
        !environ
            .windows(API_KEY.len())
            .any(|value| value == API_KEY.as_bytes())
    );
    assert!(environ.is_empty());

    control.write_all(MESH_ENROLLMENT_CONFINE_MESSAGE).unwrap();
    control.flush().unwrap();
    assert_eq!(read_status(&mut control), MESH_ENROLLMENT_READY_MESSAGE);
    let mut enrollment = Vec::new();
    transfer.read_to_end(&mut enrollment).unwrap();
    assert_eq!(&enrollment[..8], b"CWMENR1\0");
    let length = u16::from_be_bytes(enrollment[8..10].try_into().unwrap()) as usize;
    assert_eq!(enrollment.len(), 12 + length);
    let code = std::str::from_utf8(&enrollment[12..]).unwrap();
    assert!(code.starts_with("cw_enr_"));
    assert!(!code.contains(API_KEY));
    assert!(child.wait_bounded().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_store_is_not_read_before_confinement_admission() {
    let mesh_url = "http://127.0.0.1:18090";
    let (_root, mesh_root, platform_root) = private_roots(mesh_url);
    let environment_id = Uuid::new_v4();
    let generation = 8;
    let bootstrap = encode_mesh_enrollment_bootstrap(
        environment_id,
        generation,
        MeshEnrollmentAuthSource::StandaloneLocal,
        &attachment("127.0.0.1:18090".parse().unwrap()),
    )
    .unwrap();
    let (mut control, _transfer, mut child) =
        spawn_issuer(environment_id, generation, &mesh_root, &platform_root);
    control.write_all(&bootstrap).unwrap();
    control.flush().unwrap();
    assert_eq!(read_status(&mut control), MESH_ENROLLMENT_PREPARED_MESSAGE);

    fs::remove_file(mesh_root.join("config.toml")).unwrap();
    control.write_all(MESH_ENROLLMENT_CONFINE_MESSAGE).unwrap();
    control.flush().unwrap();
    assert_eq!(
        read_status(&mut control),
        b"CWMENROLL1 failed credential-unavailable\n"
    );
    assert_eq!(
        child.wait_bounded().code(),
        Some(MeshEnrollmentStartupFailure::CredentialUnavailable.exit_code())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_response_never_forwards_the_owner_bearer() {
    let redirected_requests = Arc::new(AtomicUsize::new(0));
    let redirected_counter = Arc::clone(&redirected_requests);
    let redirected_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirected_address = redirected_listener.local_addr().unwrap();
    let redirected = Router::new().fallback(move |_request: Request<Body>| {
        let redirected_counter = Arc::clone(&redirected_counter);
        async move {
            redirected_counter.fetch_add(1, Ordering::SeqCst);
            StatusCode::NO_CONTENT
        }
    });
    let redirected_task = tokio::spawn(async move {
        axum::serve(redirected_listener, redirected).await.unwrap();
    });

    let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_requests = Arc::new(AtomicUsize::new(0));
    let origin_counter = Arc::clone(&origin_requests);
    let location = format!("http://{redirected_address}/capture");
    let origin = Router::new().fallback(move |request: Request<Body>| {
        let origin_counter = Arc::clone(&origin_counter);
        let location = location.clone();
        async move {
            origin_counter.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.headers().get(header::AUTHORIZATION).unwrap(),
                &format!("Bearer {API_KEY}")
            );
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, location)
                .body(Body::empty())
                .unwrap()
        }
    });
    let origin_task = tokio::spawn(async move {
        axum::serve(origin_listener, origin).await.unwrap();
    });

    let (_root, mesh_root, platform_root) = private_roots(&format!("http://{origin_address}"));
    let environment_id = Uuid::new_v4();
    let generation = 9;
    let bootstrap = encode_mesh_enrollment_bootstrap(
        environment_id,
        generation,
        MeshEnrollmentAuthSource::StandaloneLocal,
        &attachment(origin_address),
    )
    .unwrap();
    let (mut control, _transfer, mut child) =
        spawn_issuer(environment_id, generation, &mesh_root, &platform_root);
    control.write_all(&bootstrap).unwrap();
    control.flush().unwrap();
    assert_eq!(read_status(&mut control), MESH_ENROLLMENT_PREPARED_MESSAGE);
    control.write_all(MESH_ENROLLMENT_CONFINE_MESSAGE).unwrap();
    control.flush().unwrap();
    assert_eq!(
        read_status(&mut control),
        b"CWMENROLL1 failed enrollment-request\n"
    );
    assert_eq!(
        child.wait_bounded().code(),
        Some(MeshEnrollmentStartupFailure::EnrollmentRequest.exit_code())
    );
    tokio::task::yield_now().await;
    assert_eq!(origin_requests.load(Ordering::SeqCst), 1);
    assert_eq!(redirected_requests.load(Ordering::SeqCst), 0);
    origin_task.abort();
    redirected_task.abort();
}

#[test]
fn invalid_inherited_descriptors_have_a_typed_silent_exit() {
    let (_root, mesh_root, platform_root) = private_roots("http://127.0.0.1:18090");
    let status = Command::new(env!("CARGO_BIN_EXE_cw"))
        .arg("__native-mesh-enrollment-broker")
        .arg("--environment-id")
        .arg(Uuid::new_v4().to_string())
        .arg("--generation")
        .arg("1")
        .arg("--mesh-data-dir")
        .arg(mesh_root)
        .arg("--platform-config-dir")
        .arg(platform_root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(MeshEnrollmentStartupFailure::InheritedDescriptor.exit_code())
    );
}
