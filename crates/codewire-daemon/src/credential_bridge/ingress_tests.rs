use std::future::pending;
use std::os::unix::fs::MetadataExt as _;

use codewire_daemon_proto::{CREDENTIAL_BRIDGE_MAX_IN_FLIGHT, CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::*;

// The hosted ingress fixtures each bind their own loopback port. They are
// serialized within this process only because the prebind case rebinds a port
// it released, by number.
pub(super) static LOOPBACK_TEST: Mutex<()> = Mutex::const_new(());

/// Where a unit test's Hosted ingress listens: port 0, so the kernel gives
/// each ingress a port no other socket holds, and no test run on this host
/// contends for a fixed or pre-picked port. A test that needs a second owner
/// of the same address sets that bridge's `loopback` to the first one's.
pub(super) const TEST_LOOPBACK_ADDRESS: std::net::SocketAddr =
    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

/// The kernel identity (inode) of a socket this process holds.
#[cfg(target_os = "linux")]
fn socket_inode(socket: &impl std::os::fd::AsFd) -> u64 {
    rustix::fs::fstat(socket).unwrap().st_ino
}

/// The inodes of every socket this process holds open.
#[cfg(target_os = "linux")]
fn process_socket_inodes() -> std::collections::BTreeSet<u64> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|link| {
            link.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// Whether this process still holds the socket with `inode`. This asks the
/// process's own descriptor table, so another process reusing the port can
/// never make a released socket look held, nor a held one released.
#[cfg(target_os = "linux")]
fn process_holds_socket(inode: u64) -> bool {
    process_socket_inodes().contains(&inode)
}

/// The inodes of the kernel's listening IPv4 TCP sockets on `address`, in
/// this network namespace, whichever process holds them.
#[cfg(target_os = "linux")]
fn listening_socket_inodes(address: std::net::SocketAddr) -> Vec<u64> {
    const LISTEN: &str = "0A";
    let std::net::SocketAddr::V4(address) = address else {
        panic!("hosted ingress listens on IPv4 loopback");
    };
    let local = format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.ip().octets()),
        address.port()
    );
    std::fs::read_to_string("/proc/self/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.get(1) == Some(&local.as_str()) && fields.get(3) == Some(&LISTEN))
                .then(|| fields.get(9)?.parse::<u64>().ok())
                .flatten()
        })
        .collect()
}

/// Whether this process holds a listening IPv4 TCP socket on `address`.
/// Another process listening there, including a child another test forked
/// that still holds a copy of a closed listener until it execs, does not
/// count.
#[cfg(target_os = "linux")]
fn process_listens_on(address: std::net::SocketAddr) -> bool {
    let held = process_socket_inodes();
    listening_socket_inodes(address)
        .into_iter()
        .any(|inode| held.contains(&inode))
}

/// Wait until the kernel has closed every listener on `address` this test
/// released. A child that a concurrent test forks while a listener is open
/// holds a copy of its descriptor until it execs, so the socket can outlive
/// this process's close by that long.
#[cfg(target_os = "linux")]
async fn released_by_every_process(address: std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !listening_socket_inodes(address).is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a released listener stayed open in another process");
}
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

trait HttpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> HttpIo for T {}
type HttpStream = Box<dyn HttpIo>;

fn config(path: PathBuf, transport: CredentialBridgeTransport) -> CredentialBridgeConfig {
    CredentialBridgeConfig {
        transport,
        environment_id: uuid::Uuid::new_v4(),
        environment_generation: 7,
        ingress_socket: path,
        ingress_uid: unsafe { libc::geteuid() },
        ingress_gid: unsafe { libc::getegid() },
    }
}

struct Harness {
    _temp: tempfile::TempDir,
    bridge: CredentialBridge,
    address: std::net::SocketAddr,
    #[cfg(target_os = "linux")]
    loopback_inode: u64,
    token: PathBuf,
    stop: CancellationToken,
    server: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

impl Harness {
    fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let token = temp.path().join("synthetic-token");
        std::fs::write(&token, "workspace.synthetic.ingress").unwrap();
        let config = config(
            temp.path().join("ingress.sock"),
            CredentialBridgeTransport::Hosted,
        );
        let bridge = CredentialBridge::new(Some(config));
        let ingress = bridge.prepare_ingress(false).unwrap().unwrap();
        let loopback = ingress.loopback.as_ref().unwrap();
        let address = loopback.local_addr().unwrap();
        assert!(address.ip().is_loopback() && address.port() != 0);
        #[cfg(target_os = "linux")]
        let loopback_inode = socket_inode(loopback);
        // The release checks in `stop` see a held listener as held.
        #[cfg(target_os = "linux")]
        assert!(process_holds_socket(loopback_inode) && process_listens_on(address));
        let stop = CancellationToken::new();
        let server = tokio::spawn(ingress.serve(stop.clone().cancelled_owned()));
        Self {
            _temp: temp,
            bridge,
            address,
            #[cfg(target_os = "linux")]
            loopback_inode,
            token,
            stop,
            server: Some(server),
        }
    }

    fn socket(&self) -> &Path {
        &self.bridge.config.as_ref().unwrap().ingress_socket
    }

    async fn connect(&self, tcp: bool) -> HttpStream {
        if tcp {
            Box::new(TcpStream::connect(self.address).await.unwrap())
        } else {
            Box::new(UnixStream::connect(self.socket()).await.unwrap())
        }
    }

    async fn prepare_host(
        &self,
    ) -> (
        mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
        CredentialBridgeOutput,
    ) {
        let (sender, input) = mpsc::channel(32);
        let mut connection = self
            .bridge
            .connect_with_token_file(ReceiverStream::new(input), &self.token)
            .await
            .unwrap();
        assert!(matches!(
            connection.output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        (sender, connection.output)
    }

    async fn open_host(
        &self,
        sender: &mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    ) {
        let config = self.bridge.config.as_ref().unwrap();
        sender
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::Open(
                    v1::CredentialBridgeOpen {
                        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: config.environment_id.to_string(),
                        environment_generation: config.environment_generation,
                        capabilities: Vec::new(),
                    },
                )),
            }))
            .await
            .unwrap();
    }

    async fn first_host(
        &self,
    ) -> (
        mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
        CredentialBridgeOutput,
    ) {
        let (sender, output) = self.prepare_host().await;
        self.open_host(&sender).await;
        let config = self.bridge.config.as_ref().unwrap();
        self.bridge
            .wait_for_initial_host(&codewire_workload_secrets::ProjectionContext {
                environment_id: *config.environment_id.as_bytes(),
                operation_generation: config.environment_generation,
                selection_sha256: [1; 32],
                deadline_unix_ms: codewire_workload_secrets::launcher::now_unix_ms().unwrap()
                    + 3_000,
            })
            .await
            .unwrap();
        (sender, output)
    }

    async fn stop(mut self) {
        self.stop.cancel();
        tokio::time::timeout(TEST_TIMEOUT, self.server.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(self.bridge.owner.tasks.is_empty());
        assert!(!self.socket().exists());
        assert!(
            self.bridge
                .connect_with_token_file(tokio_stream::pending(), &self.token)
                .await
                .is_err()
        );
        // The owner closed the real loopback socket, not merely its pathname:
        // the listener it bound is gone from this process, which no other
        // process's use of the port can disguise.
        #[cfg(target_os = "linux")]
        {
            assert!(!process_holds_socket(self.loopback_inode));
            assert!(!process_listens_on(self.address));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

async fn request(
    mut stream: HttpStream,
    method: &str,
    path: &str,
    host: &str,
    body: &[u8],
) -> HttpStream {
    let header = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(TEST_TIMEOUT, async {
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    })
    .await
    .unwrap();
    stream
}

async fn response(mut stream: HttpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    tokio::time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

async fn host_request(output: &mut CredentialBridgeOutput) -> v1::CredentialBridgeRequest {
    let message = tokio::time::timeout(TEST_TIMEOUT, output.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Some(v1::credential_bridge_guest_message::Payload::Request(request)) = message.payload
    else {
        panic!("expected bounded provider request");
    };
    request
}

async fn complete(
    sender: &mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    request: v1::CredentialBridgeRequest,
) {
    for payload in [
        v1::credential_bridge_host_message::Payload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request.request_id.clone(),
                status_code: 204,
                headers: vec![],
            },
        ),
        v1::credential_bridge_host_message::Payload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: request.request_id,
        }),
    ] {
        sender
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn hosted_prebind_is_exact_exclusive_and_does_not_unlink_previous_unix_owner() {
    let _lock = LOOPBACK_TEST.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ingress.sock");
    let config = config(path.clone(), CredentialBridgeTransport::Hosted);
    let bridge = CredentialBridge::new(Some(config.clone()));
    let ingress = bridge.prepare_ingress(false).unwrap().unwrap();
    let address = ingress.loopback.as_ref().unwrap().local_addr().unwrap();
    assert!(address.ip().is_loopback() && address.port() != 0);
    #[cfg(target_os = "linux")]
    let first_inode = socket_inode(ingress.loopback.as_ref().unwrap());
    #[cfg(target_os = "linux")]
    assert!(process_holds_socket(first_inode) && process_listens_on(address));
    let before = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(before.mode() & 0o777, 0o600);
    assert_eq!(before.uid(), config.ingress_uid);
    // A second Hosted owner of the same address is refused while the first
    // holds it.
    let mut second = CredentialBridge::new(Some(config));
    second.loopback = address;
    assert!(
        matches!(second.prepare_ingress(false), Err(error) if error.kind() == io::ErrorKind::AddrInUse)
    );
    let after = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    let client = UnixStream::connect(&path).await.unwrap();
    drop(ingress.listener.inner.accept().await.unwrap());
    drop(client);
    drop(ingress);
    assert!(!path.exists());
    #[cfg(target_os = "linux")]
    {
        assert!(!process_holds_socket(first_inode));
        released_by_every_process(address).await;
    }

    // A Unix-path failure after successful TCP prebind releases the port and
    // preserves the unexpected filesystem object byte-for-byte. The second
    // owner binds the address the first one just released.
    std::fs::write(&path, b"synthetic existing non-socket").unwrap();
    assert!(
        matches!(second.prepare_ingress(false), Err(error) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"synthetic existing non-socket"
    );
    #[cfg(target_os = "linux")]
    assert!(!process_listens_on(address));
}

#[tokio::test]
async fn local_ingress_does_not_claim_the_guest_forwarders_loopback_socket() {
    let _lock = LOOPBACK_TEST.lock().await;
    let existing_forwarder = bind_hosted_loopback(TEST_LOOPBACK_ADDRESS).unwrap();
    let address = existing_forwarder.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("local.sock");
    // A Local bridge pointed at the forwarder's own address never binds it.
    let mut bridge =
        CredentialBridge::new(Some(config(path.clone(), CredentialBridgeTransport::Local)));
    bridge.loopback = address;
    let ingress = bridge.prepare_ingress(false).unwrap().unwrap();
    assert!(ingress.loopback.is_none());
    drop(ingress);
    assert!(!path.exists());
    assert_eq!(existing_forwarder.local_addr().unwrap(), address);
}

#[tokio::test]
async fn hosted_both_endpoints_are_ready_before_admission_and_share_closed_routes_and_body_limits()
{
    let _lock = LOOPBACK_TEST.lock().await;
    let harness = Harness::start();
    let (_prepared_sender, mut prepared_output) = harness.prepare_host().await;
    // Ready is preparatory only. Neither HTTP endpoint waits for broker admission.
    for tcp in [false, true] {
        for (method, path, host) in [
            ("POST", "/v1/responses", "localhost"),
            ("POST", "/_codewire/openai/v1/responses", "localhost"),
            (
                "POST",
                "/_codewire/anthropic/v1/messages?beta=true",
                "localhost",
            ),
            ("GET", "/_codewire/anthropic/api/oauth/usage", "localhost"),
            (
                "GET",
                "/_codewire/github/a/b.git/info/refs?service=git-upload-pack",
                "localhost",
            ),
            ("GET", "/repos/a/b/issues?state=open", "api.github.com"),
        ] {
            let stream = request(harness.connect(tcp).await, method, path, host, b"{}").await;
            assert!(
                response(stream)
                    .await
                    .starts_with(b"HTTP/1.1 503 Service Unavailable")
            );
        }
        for (method, path, host) in [
            ("OPTIONS", "/v1/responses", "localhost"),
            ("POST", "/v1/responses", "api.github.com"),
            ("POST", "/messages", "localhost"),
            ("POST", "/_codewire/anthropic/v1/../messages", "localhost"),
            (
                "GET",
                "/_codewire/github/a/b.git/info/refs?service=other",
                "localhost",
            ),
            ("POST", "http://foreign.invalid/v1/responses", "localhost"),
        ] {
            // No body is sent: a closed route must reject without polling one.
            let mut stream = harness.connect(tcp).await;
            stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 100\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            assert!(
                response(stream)
                    .await
                    .starts_with(b"HTTP/1.1 403 Forbidden")
            );
        }
        for headers in [
            "Host: localhost\r\nHost: api.github.com\r\n",
            "Host: localhost\r\nUpgrade: websocket\r\n",
        ] {
            let mut stream = harness.connect(tcp).await;
            stream.write_all(format!("POST /v1/responses HTTP/1.1\r\n{headers}Content-Length: 100\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let response = response(stream).await;
            assert!(
                response.starts_with(b"HTTP/1.1 400 Bad Request")
                    || response.starts_with(b"HTTP/1.1 403 Forbidden")
            );
        }
        let body = vec![b'x'; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1];
        let stream = request(
            harness.connect(tcp).await,
            "POST",
            "/v1/responses",
            "localhost",
            &body,
        )
        .await;
        assert!(
            response(stream)
                .await
                .starts_with(b"HTTP/1.1 413 Payload Too Large")
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), prepared_output.next())
            .await
            .is_err()
    );
    harness.stop().await;
    assert!(prepared_output.next().await.is_none());
}

#[tokio::test]
async fn hosted_shared_budget_and_replacement_cover_both_endpoints_without_replay() {
    let _lock = LOOPBACK_TEST.lock().await;
    let harness = Harness::start();
    let (first_sender, mut first) = harness.first_host().await;
    let mut pending = Vec::new();
    for index in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        let stream = request(
            harness.connect(index % 2 == 0).await,
            "POST",
            "/v1/responses",
            "localhost",
            b"{}",
        )
        .await;
        let request = host_request(&mut first).await;
        assert_eq!(
            (request.capability_slot.as_str(), request.route.as_str()),
            ("codex", "openai-api")
        );
        pending.push(stream);
    }
    for tcp in [false, true] {
        let extra = request(
            harness.connect(tcp).await,
            "POST",
            "/v1/responses",
            "localhost",
            b"{}",
        )
        .await;
        assert!(
            response(extra)
                .await
                .starts_with(b"HTTP/1.1 503 Service Unavailable")
        );
    }
    let (second_sender, mut second) = harness.prepare_host().await;
    // Merely preparing replacement leaves the old epoch and budget intact.
    let extra = request(
        harness.connect(true).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    assert!(
        response(extra)
            .await
            .starts_with(b"HTTP/1.1 503 Service Unavailable")
    );
    harness.open_host(&second_sender).await;
    // The replaced epoch drains: it stays open, its requests stay pending and
    // keep their share of the budget, and none is replayed to its successor.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), first.next())
            .await
            .is_err()
    );
    let extra = request(
        harness.connect(false).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    assert!(
        response(extra)
            .await
            .starts_with(b"HTTP/1.1 503 Service Unavailable")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second.next())
            .await
            .is_err()
    );
    // Its host ends it unanswered: only its own requests fail.
    drop(first_sender);
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, first.next())
            .await
            .unwrap()
            .is_none()
    );
    for stream in pending {
        assert!(
            response(stream)
                .await
                .starts_with(b"HTTP/1.1 503 Service Unavailable")
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second.next())
            .await
            .is_err()
    );
    for tcp in [false, true] {
        let stream = request(
            harness.connect(tcp).await,
            "POST",
            "/_codewire/anthropic/v1/messages?beta=true",
            "localhost",
            b"{}",
        )
        .await;
        let request = host_request(&mut second).await;
        assert_eq!(
            (
                request.capability_slot.as_str(),
                request.route.as_str(),
                request.query.as_str()
            ),
            ("anthropic", "anthropic-api", "beta=true")
        );
        complete(&second_sender, request).await;
        assert!(
            response(stream)
                .await
                .starts_with(b"HTTP/1.1 204 No Content")
        );
    }
    harness.stop().await;
    assert!(second.next().await.is_none());
}

#[tokio::test]
async fn hosted_replacement_completes_the_request_pending_on_the_replaced_epoch() {
    let _lock = LOOPBACK_TEST.lock().await;
    let harness = Harness::start();
    let (first_sender, mut first) = harness.first_host().await;
    let pending = request(
        harness.connect(true).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    let pending_request = host_request(&mut first).await;
    let (second_sender, mut second) = harness.prepare_host().await;
    harness.open_host(&second_sender).await;
    // New requests reach only the successor, on both endpoints.
    for tcp in [false, true] {
        let stream = request(
            harness.connect(tcp).await,
            "POST",
            "/v1/responses",
            "localhost",
            b"{}",
        )
        .await;
        complete(&second_sender, host_request(&mut second).await).await;
        assert!(
            response(stream)
                .await
                .starts_with(b"HTTP/1.1 204 No Content")
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), first.next())
            .await
            .is_err()
    );
    // The request sent before the successor activated still completes.
    complete(&first_sender, pending_request).await;
    assert!(
        response(pending)
            .await
            .starts_with(b"HTTP/1.1 204 No Content")
    );
    drop(first_sender);
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, first.next())
            .await
            .unwrap()
            .is_none()
    );
    harness.stop().await;
    assert!(second.next().await.is_none());
}

#[tokio::test]
async fn hosted_successor_can_be_prepared_while_one_epoch_is_active_and_one_drains() {
    let _lock = LOOPBACK_TEST.lock().await;
    let harness = Harness::start();
    let (first_sender, mut first) = harness.first_host().await;
    let oldest = request(
        harness.connect(false).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    host_request(&mut first).await;
    let (second_sender, mut second) = harness.prepare_host().await;
    harness.open_host(&second_sender).await;
    let draining = request(
        harness.connect(true).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    let draining_request = host_request(&mut second).await;
    // Active, draining and prepared each hold one admission permit; a fourth
    // preparation is refused rather than queued.
    let (third_sender, mut third) = harness.prepare_host().await;
    assert_eq!(
        harness
            .bridge
            .connect_with_token_file(tokio_stream::pending(), &harness.token)
            .await
            .err()
            .map(|status| status.code()),
        Some(tonic::Code::ResourceExhausted)
    );
    harness.open_host(&third_sender).await;
    // The third activation loses only the oldest epoch.
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, first.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        response(oldest)
            .await
            .starts_with(b"HTTP/1.1 503 Service Unavailable")
    );
    complete(&second_sender, draining_request).await;
    assert!(
        response(draining)
            .await
            .starts_with(b"HTTP/1.1 204 No Content")
    );
    let stream = request(
        harness.connect(false).await,
        "POST",
        "/v1/responses",
        "localhost",
        b"{}",
    )
    .await;
    complete(&third_sender, host_request(&mut third).await).await;
    assert!(
        response(stream)
            .await
            .starts_with(b"HTTP/1.1 204 No Content")
    );
    drop(first_sender);
    harness.stop().await;
    assert!(second.next().await.is_none());
    assert!(third.next().await.is_none());
}

#[tokio::test]
async fn hosted_shutdown_drains_active_pending_and_partial_http_on_both_endpoints() {
    let _lock = LOOPBACK_TEST.lock().await;
    let harness = Harness::start();
    let (sender, mut output) = harness.first_host().await;
    let mut streams = Vec::new();
    for tcp in [false, true] {
        // An actually accepted partial upload: 100 Continue synchronizes the
        // parser/body phase without sleeps or guessing from a connected socket.
        let mut partial = harness.connect(tcp).await;
        partial.write_all(b"POST /v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
        let mut interim = [0; 25];
        tokio::time::timeout(TEST_TIMEOUT, partial.read_exact(&mut interim))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        streams.push(partial);

        let pending = request(
            harness.connect(tcp).await,
            "POST",
            "/v1/responses",
            "localhost",
            b"{}",
        )
        .await;
        let _request = host_request(&mut output).await;
        streams.push(pending);

        let mut streaming = request(
            harness.connect(tcp).await,
            "POST",
            "/v1/responses",
            "localhost",
            b"{}",
        )
        .await;
        let request = host_request(&mut output).await;
        sender
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::ResponseStart(
                    v1::CredentialBridgeResponseStart {
                        request_id: request.request_id,
                        status_code: 200,
                        headers: vec![],
                    },
                )),
            }))
            .await
            .unwrap();
        // Observe final response headers but deliberately never finish its body.
        let mut header = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(streaming.read_u8().await.unwrap());
                assert!(header.len() < 4096);
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"HTTP/1.1 200 OK"));
        streams.push(streaming);
    }
    harness.stop().await;
    assert!(output.next().await.is_none());
    for mut stream in streams {
        // Force-close may report EOF or a reset; it must not remain readable
        // indefinitely and cannot receive new provider data after drain ACK.
        let mut tail = Vec::new();
        let _ = tokio::time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut tail))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn hosted_listener_failure_stops_sibling_and_drain_failure_is_not_success() {
    for unix_fails in [false, true] {
        let owner = CredentialBridge::new(None);
        let drain = HostedIngressDrain {
            stop: CancellationToken::new(),
            transports: TransportShutdown::new(),
            owner: owner.clone(),
        };
        let stopped = drain.stop.clone();
        let sibling_drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = sibling_drained.clone();
        let listener = |fails: bool| {
            let stopped = stopped.clone();
            let done = done.clone();
            async move {
                if fails {
                    return Err(io::Error::other("synthetic accept failure"));
                }
                stopped.cancelled().await;
                done.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        };
        let result = serve_hosted_listeners(
            listener(unix_fails),
            listener(!unix_fails),
            pending(),
            CancellationToken::new(),
            drain,
        )
        .await;
        assert!(result.is_err());
        assert!(sibling_drained.load(std::sync::atomic::Ordering::SeqCst));
        assert!(owner.owner.shutdown.is_cancelled());
        assert!(owner.owner.tasks.is_closed());
    }

    let drain = HostedIngressDrain {
        stop: CancellationToken::new(),
        transports: TransportShutdown::new(),
        owner: CredentialBridge::new(None),
    };
    let error = serve_hosted_listeners(
        pending(),
        pending(),
        async {},
        CancellationToken::new(),
        drain,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn hosted_accept_errors_are_terminal_but_transient_connection_errors_are_not() {
    let failed = CancellationToken::new();
    stop_failed_listener(&io::Error::from(io::ErrorKind::ConnectionAborted), &failed).await;
    assert!(!failed.is_cancelled());
    let error = io::Error::from(io::ErrorKind::PermissionDenied);
    let accept = stop_failed_listener(&error, &failed);
    tokio::pin!(accept);
    tokio::select! {
        biased;
        () = &mut accept => panic!("terminal accept must suspend until owner cancellation"),
        () = failed.cancelled() => {},
    }
    assert!(failed.is_cancelled());
}

#[test]
fn hosted_ingress_listens_on_the_fixed_guest_port_in_the_product() {
    // The product's default, asserted without binding it: guests reach the
    // provider routes at 127.0.0.1:38081 (see env.rs base URLs).
    assert_eq!(
        hosted_loopback_address(),
        "127.0.0.1:38081".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(CREDENTIAL_BRIDGE_LOOPBACK_PORT, 38081);
    // Unit tests never take it, nor any fixed port: each ingress binds port 0.
    assert_eq!(CredentialBridge::new(None).loopback, TEST_LOOPBACK_ADDRESS);
    assert_eq!(TEST_LOOPBACK_ADDRESS, "127.0.0.1:0".parse().unwrap());
}
