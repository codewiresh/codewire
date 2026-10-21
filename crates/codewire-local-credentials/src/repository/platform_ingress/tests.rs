use codewire_credential_bridge::CredentialBridgeOutput;
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use super::*;

const SOURCE: &str = "https://github.com/synthetic-owner/synthetic-repo.git";
const BOUND: Duration = Duration::from_secs(3);

struct Fixture {
    ingress: PlatformRepositoryGitIngress,
    address: SocketAddr,
    host_input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, tonic::Status>>,
    host_output: CredentialBridgeOutput,
    shutdown: oneshot::Sender<()>,
    driver: JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
        let (prepared, mut host_output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            host_output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        let (host_input, receiver) = mpsc::channel(8);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let driver = tokio::spawn(connection.run_until(async {
            let _ = stopped.await;
        }));
        let ingress = PlatformRepositoryGitIngress::bind(SOURCE, bridge, Instant::now() + BOUND)
            .await
            .unwrap();
        let endpoint = url::Url::parse(ingress.endpoint()).unwrap();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.port().unwrap()));
        Self {
            ingress,
            address,
            host_input,
            host_output,
            shutdown,
            driver,
        }
    }

    fn authorization(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("x-access-token:{}", self.ingress.capability()))
        )
    }

    fn request(&self) -> String {
        format!(
            "GET /_codewire/github/synthetic-owner/synthetic-repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\n\r\n",
            self.address,
            self.authorization()
        )
    }

    async fn next_request(&mut self) -> v1::CredentialBridgeRequest {
        let frame = tokio::time::timeout(BOUND, self.host_output.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(v1::credential_bridge_guest_message::Payload::Request(request)) = frame.payload
        else {
            panic!("only a repository request may reach the synthetic bridge");
        };
        assert_eq!(request.capability_slot, "github");
        assert_eq!(request.route, "github-https");
        assert!(
            request
                .headers
                .iter()
                .all(|header| !header.name.eq_ignore_ascii_case("authorization"))
        );
        assert!(
            !request
                .encode_to_vec()
                .windows(self.ingress.capability().len())
                .any(|bytes| bytes == self.ingress.capability().as_bytes())
        );
        request
    }

    async fn send(&self, payload: v1::credential_bridge_host_message::Payload) {
        self.host_input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
    }

    async fn start_and_body(&self, request_id: &str) {
        self.send(v1::credential_bridge_host_message::Payload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request_id.into(),
                status_code: 200,
                // Framing headers are deliberately forbidden in shared host
                // frames. Exercise ingress framing at its HTTP boundary below.
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".into(),
                    value: b"application/x-git-upload-pack-advertisement".to_vec(),
                }],
            },
        ))
        .await;
        self.send(v1::credential_bridge_host_message::Payload::ResponseBody(
            v1::CredentialBridgeResponseBody {
                request_id: request_id.into(),
                data: b"PACK".to_vec(),
            },
        ))
        .await;
    }

    async fn end(&self, request_id: &str) {
        self.send(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: request_id.into(),
            },
        ))
        .await;
    }

    /// Closes the ingress and proves it released its own listener and
    /// connections. On Linux the proof is the exact sockets the ingress held
    /// before close: none of them stays open in this process. A probe connect
    /// to the old port would also reach any later listener that a concurrent
    /// test bound there, or a child forked before its exec, under load.
    #[cfg(target_os = "linux")]
    async fn finish(mut self) -> Result<(), RepositoryExecutorError> {
        let held = own_sockets_at(self.address);
        assert!(
            held.values().any(|state| state == LISTEN),
            "the ingress listener is visible before close: {held:?}"
        );
        let result = tokio::time::timeout(BOUND, self.ingress.close())
            .await
            .expect("owned ingress drain is bounded");
        let open = own_socket_inodes();
        let kept: Vec<_> = held.keys().filter(|inode| open.contains(*inode)).collect();
        assert!(
            kept.is_empty(),
            "the closed ingress at {} still holds sockets {kept:?} of {held:?}",
            self.address
        );
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(BOUND, self.driver)
            .await
            .unwrap()
            .unwrap();
        result
    }

    #[cfg(not(target_os = "linux"))]
    async fn finish(mut self) -> Result<(), RepositoryExecutorError> {
        // Reserve a distinct client source while the ingress still owns its port.
        // A fresh auto-bound loopback client can otherwise connect to itself.
        let probe = tokio::net::TcpSocket::new_v4().unwrap();
        probe
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let probe_address = probe.local_addr().unwrap();
        assert_ne!(probe_address, self.address);
        let result = tokio::time::timeout(BOUND, self.ingress.close())
            .await
            .expect("owned ingress drain is bounded");
        let probe_result = tokio::time::timeout(BOUND, probe.connect(self.address)).await;
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(BOUND, self.driver)
            .await
            .unwrap()
            .unwrap();
        let probe_result = probe_result.expect("owned post-close ingress probe is bounded");
        assert!(
            probe_result.is_err(),
            "post-close connection succeeded: bound source {probe_address}, observed {:?}",
            probe_result
                .as_ref()
                .map(|stream| (stream.local_addr(), stream.peer_addr()))
        );
        result
    }
}

/// `/proc/net/tcp` state of a listening socket.
#[cfg(target_os = "linux")]
const LISTEN: &str = "0A";

/// This process's TCP sockets whose local address is `address`, by inode,
/// with their `/proc/net/tcp` state.
#[cfg(target_os = "linux")]
fn own_sockets_at(address: SocketAddr) -> std::collections::BTreeMap<u64, String> {
    let SocketAddr::V4(address) = address else {
        panic!("the ingress binds IPv4 loopback");
    };
    // The kernel prints the address as its in-memory 32 bits, then the port.
    let local = format!(
        "{:08X}:{:04X}",
        u32::from_ne_bytes(address.ip().octets()),
        address.port()
    );
    let open = own_socket_inodes();
    std::fs::read_to_string("/proc/self/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let inode = fields.get(9)?.parse::<u64>().ok()?;
            (fields.get(1) == Some(&local.as_str()) && open.contains(&inode))
                .then(|| (inode, fields[3].to_owned()))
        })
        .collect()
}

/// Inodes of every socket this process has open.
#[cfg(target_os = "linux")]
fn own_socket_inodes() -> std::collections::BTreeSet<u64> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

use prost::Message as _;

async fn raw_exchange(address: SocketAddr, request: String) -> Vec<u8> {
    tokio::time::timeout(BOUND, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .expect("bounded synthetic HTTP exchange")
}

async fn read_through_pack(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(BOUND, async {
        let mut response = Vec::new();
        loop {
            let mut bytes = [0; 1024];
            let read = stream.read(&mut bytes).await.unwrap();
            assert_ne!(read, 0, "response ended before synthetic body");
            response.extend_from_slice(&bytes[..read]);
            if response.windows(4).any(|bytes| bytes == b"PACK") {
                return response;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn unauthenticated_traffic_never_reaches_bridge_or_poisons_authorized_job() {
    let mut fixture = Fixture::new().await;
    for variant in 0..7 {
        let auth = format!("Authorization: {}\r\n", fixture.authorization());
        let request = match variant {
            0 => fixture.request().replace(&auth, ""),
            1 => fixture
                .request()
                .replace(&auth, "Authorization: Basic invalid\r\n"),
            2 => fixture.request().replace(
                &auth,
                &format!(
                    "Authorization: Basic {}\r\n",
                    STANDARD.encode(format!("other-user:{}", fixture.ingress.capability()))
                ),
            ),
            3 => fixture.request().replace(&auth, &format!("{auth}{auth}")),
            4 => fixture.request().replace(
                &auth,
                &format!("{auth}Proxy-Authorization: Basic unexpected\r\n"),
            ),
            5 => fixture
                .request()
                .replace(&auth, &format!("{auth}Cookie: unexpected\r\n")),
            _ => fixture
                .request()
                .replace(&auth, "Authorization: Bearer unexpected\r\n"),
        };
        let response = raw_exchange(fixture.address, request).await;
        assert!(response.starts_with(b"HTTP/1.1 401"));
        assert!(fixture.host_output.next().now_or_never().is_none());
    }
    let client = tokio::spawn(raw_exchange(fixture.address, fixture.request()));
    let request = fixture.next_request().await;
    assert_eq!(
        request.path,
        "/synthetic-owner/synthetic-repo.git/info/refs"
    );
    assert_eq!(request.query, "service=git-upload-pack");
    fixture.start_and_body(&request.request_id).await;
    fixture.end(&request.request_id).await;
    let response = client.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"0\r\n\r\n"));
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn exact_repository_upload_only_routes_and_loopback_host_are_required() {
    for variant in 0..9 {
        let mut fixture = Fixture::new().await;
        let request = match variant {
            0 => fixture.request().replace("GET ", "DELETE "),
            1 => fixture
                .request()
                .replace("synthetic-repo.git", "another-repo.git"),
            2 => fixture
                .request()
                .replace("service=git-upload-pack", "service=git-receive-pack"),
            3 => fixture.request().replace(
                "service=git-upload-pack",
                "service=git-upload-pack&extra=true",
            ),
            4 => fixture
                .request()
                .replace("GET /", &format!("GET http://{}/", fixture.address)),
            5 => fixture.request().replace(
                &format!("Host: {}", fixture.address),
                "Host: api.github.com",
            ),
            6 => fixture
                .request()
                .replace("/_codewire/github/", "/_codewire/%67ithub/"),
            7 => fixture.request().replace("GET ", "POST "),
            _ => fixture
                .request()
                .replace(
                    "info/refs?service=git-upload-pack",
                    "git-upload-pack?extra=true",
                )
                .replace("GET ", "POST "),
        };
        let response = raw_exchange(fixture.address, request).await;
        assert!(response.starts_with(b"HTTP/1.1 403"), "variant {variant}");
        assert!(fixture.host_output.next().now_or_never().is_none());
        assert!(fixture.finish().await.is_err());
    }
}

// Platform delegation is the Linux consumption path; macOS stores only.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn streaming_eof_waits_for_shared_response_end() {
    let mut fixture = Fixture::new().await;
    let mut client = TcpStream::connect(fixture.address).await.unwrap();
    client
        .write_all(fixture.request().as_bytes())
        .await
        .unwrap();
    let request = fixture.next_request().await;
    fixture.start_and_body(&request.request_id).await;
    let mut response = read_through_pack(&mut client).await;
    let text = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(!text.contains("content-length:"));
    assert!(text.contains("transfer-encoding: chunked"));
    // Actual body bytes have reached the socket; the client must not observe
    // EOF/terminal chunk before the shared terminal ACK.
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(25), client.read(&mut byte))
            .await
            .is_err()
    );
    fixture.end(&request.request_id).await;
    tokio::time::timeout(BOUND, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with(b"0\r\n\r\n"));
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn http_response_framing_cannot_bypass_body_terminal_proof() {
    use hyper::body::Body as _;

    let state = Arc::new(IngressState {
        bridge: CredentialBridge::new(Uuid::new_v4(), 1).unwrap(),
        host: "127.0.0.1:1".into(),
        discovery: String::new(),
        upload: String::new(),
        authorization: Zeroizing::new(String::new()),
        failed: AtomicBool::new(false),
    });
    for (header, value) in [(CONTENT_LENGTH, "4"), (TRANSFER_ENCODING, "chunked")] {
        let exchange = Arc::new(Exchange::default());
        let (sender, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(1);
        let response = Response::builder()
            .header(header, value)
            .body(Body::from_stream(ReceiverStream::new(receiver)))
            .unwrap();
        let response = completion_gated_response(response, state.clone(), exchange.clone());
        assert!(!response.headers().contains_key(CONTENT_LENGTH));
        assert!(!response.headers().contains_key(TRANSFER_ENCODING));
        assert_eq!(response.body().size_hint().upper(), None);
        let mut body = http_body_util::BodyExt::into_data_stream(response.into_body());
        sender.send(Ok(Bytes::from_static(b"PACK"))).await.unwrap();
        assert_eq!(body.next().await.unwrap().unwrap(), b"PACK"[..]);
        assert!(body.next().now_or_never().is_none());
        assert!(!exchange.response_complete.load(Ordering::Acquire));
        drop(sender);
        assert!(body.next().await.is_none());
        assert!(exchange.response_complete.load(Ordering::Acquire));
        assert!(!state.failed.load(Ordering::Acquire));
    }

    // Even a fixed-size body must not make Hyper synthesize Content-Length
    // from its size hint instead of polling the tracked terminal boundary.
    let exchange = Arc::new(Exchange::default());
    let body = Body::from("PACK");
    assert_eq!(body.size_hint().exact(), Some(4));
    let response = completion_gated_response(Response::new(body), state.clone(), exchange.clone());
    assert_eq!(response.body().size_hint().upper(), None);
    let mut body = http_body_util::BodyExt::into_data_stream(response.into_body());
    assert_eq!(body.next().await.unwrap().unwrap(), b"PACK"[..]);
    assert!(!exchange.response_complete.load(Ordering::Acquire));
    assert!(body.next().await.is_none());
    assert!(exchange.response_complete.load(Ordering::Acquire));
    assert!(!state.failed.load(Ordering::Acquire));
}

#[tokio::test]
async fn post_upload_pack_uses_shared_request_and_complete_response_without_auth_header() {
    let mut fixture = Fixture::new().await;
    let request = fixture.request().replace("GET ", "POST ")
        .replace("info/refs?service=git-upload-pack", "git-upload-pack")
        .replace("\r\n\r\n", "\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: 4\r\n\r\n0000");
    let client = tokio::spawn(raw_exchange(fixture.address, request));
    let request = fixture.next_request().await;
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path,
        "/synthetic-owner/synthetic-repo.git/git-upload-pack"
    );
    assert!(request.query.is_empty());
    assert_eq!(request.body, b"0000");
    fixture.start_and_body(&request.request_id).await;
    fixture.end(&request.request_id).await;
    assert!(client.await.unwrap().starts_with(b"HTTP/1.1 200"));
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn authenticated_truncation_or_client_loss_never_acknowledges_local_completion() {
    for disconnect in [false, true] {
        let mut fixture = Fixture::new().await;
        let mut client = TcpStream::connect(fixture.address).await.unwrap();
        client
            .write_all(fixture.request().as_bytes())
            .await
            .unwrap();
        let request = fixture.next_request().await;
        fixture.start_and_body(&request.request_id).await;
        let response = read_through_pack(&mut client).await;
        assert!(!response.ends_with(b"0\r\n\r\n"));
        if disconnect {
            drop(client);
        }
        assert!(fixture.finish().await.is_err());
    }
}

#[tokio::test]
async fn close_joins_idle_unauthenticated_connections_without_latching_failure() {
    let fixture = Fixture::new().await;
    let mut clients = Vec::new();
    for _ in 0..MAX_CONNECTIONS + 2 {
        let mut client = TcpStream::connect(fixture.address).await.unwrap();
        // Excess accepted sockets may already have been refused at capacity.
        let _ = client.write_all(b"GET /").await;
        clients.push(client);
    }
    fixture.finish().await.unwrap();
    for mut client in clients {
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(BOUND, client.read_to_end(&mut bytes))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn cancelled_close_retains_same_driver_until_join_and_sticky_result() {
    let (shutdown, _stopped) = watch::channel(false);
    let (release, released) = oneshot::channel();
    let driver = tokio::spawn(async {
        let _ = released.await;
        Ok(())
    });
    let mut ingress = PlatformRepositoryGitIngress {
        endpoint: "http://127.0.0.1:1/synthetic".into(),
        capability: Zeroizing::new("synthetic-only".into()),
        shutdown,
        driver: Some(driver),
        closed_ok: false,
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(10), ingress.close())
            .await
            .is_err()
    );
    assert!(ingress.driver.is_some());
    release.send(()).unwrap();
    ingress.close().await.unwrap();
    assert!(ingress.driver.is_none());
    ingress.close().await.unwrap();
}

#[tokio::test]
async fn original_deadline_closes_listener_and_does_not_report_success() {
    let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
    let deadline = Instant::now() + Duration::from_millis(30);
    let mut ingress = PlatformRepositoryGitIngress::bind(SOURCE, bridge, deadline)
        .await
        .unwrap();
    tokio::time::sleep_until(deadline + Duration::from_millis(1)).await;
    assert!(matches!(
        ingress.close().await,
        Err(RepositoryExecutorError::GitTimeout)
    ));
    assert!(ingress.close().await.is_err());
}

#[tokio::test]
async fn declared_oversized_body_is_rejected_before_bridge_or_body_polling() {
    let mut fixture = Fixture::new().await;
    let request = fixture
        .request()
        .replace("GET ", "POST ")
        .replace("info/refs?service=git-upload-pack", "git-upload-pack")
        .replace(
            "\r\n\r\n",
            &format!(
                "\r\nContent-Length: {}\r\n\r\n",
                codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1
            ),
        );
    let response = raw_exchange(fixture.address, request).await;
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert!(fixture.host_output.next().now_or_never().is_none());
    assert!(fixture.finish().await.is_err());
}

#[tokio::test]
async fn oversized_unauthenticated_headers_cannot_reach_or_poison_bridge() {
    let mut fixture = Fixture::new().await;
    let mut client = TcpStream::connect(fixture.address).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nX-Oversized: {}\r\n\r\n",
        fixture.address,
        "x".repeat(MAX_HEADER_BYTES + 1)
    );
    // Hyper may reject while the peer is still writing the deliberately large
    // header. Either reset or a 4xx is a denial, never bridge admission.
    let _ = tokio::time::timeout(BOUND, client.write_all(request.as_bytes()))
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(BOUND, client.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 4"));
    assert!(fixture.host_output.next().now_or_never().is_none());
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn malformed_source_or_expired_job_never_binds_an_ingress() {
    for source in [
        "https://example.com/owner/repo",
        "https://github.com/owner/repo?ref=main",
        "https://github.com/owner/./repo",
        "https://github.com/owner/repo/extra",
    ] {
        let result = PlatformRepositoryGitIngress::bind(
            source,
            CredentialBridge::new(Uuid::new_v4(), 1).unwrap(),
            Instant::now() + BOUND,
        )
        .await;
        assert!(matches!(
            result,
            Err(RepositoryExecutorError::InvalidConfiguration)
        ));
    }
    let result = PlatformRepositoryGitIngress::bind(
        SOURCE,
        CredentialBridge::new(Uuid::new_v4(), 1).unwrap(),
        Instant::now(),
    )
    .await;
    assert!(matches!(result, Err(RepositoryExecutorError::GitTimeout)));
}
