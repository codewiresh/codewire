use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::Extension;
use axum::routing::{get, post};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::oneshot;

use super::*;

fn limits() -> BoundedHttp1Limits {
    BoundedHttp1Limits {
        max_connections: 8,
        max_connections_per_peer: 2,
        header_read_timeout: Duration::from_secs(5),
        max_headers: 16,
        max_header_bytes: 16 * 1024,
        max_body_bytes: 64,
        request_read_timeout: Duration::from_secs(5),
        connection_deadline: Duration::from_secs(10),
    }
}

struct Server {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn start(limits: BoundedHttp1Limits) -> Server {
    let app = Router::new()
        .route(
            "/echo",
            post(
                |Extension(PeerAddr(peer)): Extension<PeerAddr>, body: axum::body::Bytes| async move {
                    format!("{} {}", peer.ip(), body.len())
                },
            ),
        )
        .route(
            "/counted",
            post(|body: axum::body::Bytes| async move {
                HANDLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                format!("{}", body.len())
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "late"
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_bounded_http1_until(app, listener, limits, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    Server {
        addr,
        stop: Some(stop),
    }
}

async fn connect_from(source: Ipv4Addr, server: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(IpAddr::V4(source), 0)).unwrap();
    socket.connect(server).await.unwrap()
}

/// Reads until the server closes the connection, bounded so a test never
/// hangs. A reset counts as closed.
async fn read_until_closed(stream: &mut TcpStream, within: Duration) -> Option<String> {
    let mut buffer = Vec::new();
    let read = tokio::time::timeout(within, async {
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    })
    .await;
    read.ok()
        .map(|()| String::from_utf8_lossy(&buffer).into_owned())
}

static HANDLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const ECHO: &str = "POST /echo HTTP/1.1\r\nhost: binding\r\ncontent-length: 2\r\n\r\nhi";

#[tokio::test]
async fn serves_one_request_per_connection_with_the_peer_address() {
    let server = start(limits()).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    // Two pipelined requests: only the first is served.
    stream
        .write_all(format!("{ECHO}{ECHO}").as_bytes())
        .await
        .unwrap();
    let response = read_until_closed(&mut stream, Duration::from_secs(5))
        .await
        .expect("connection closes after one response");
    assert_eq!(response.matches("HTTP/1.1 200").count(), 1, "{response}");
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    assert!(response.ends_with("127.0.0.1 2"), "{response}");
}

#[tokio::test]
async fn connections_over_the_peer_or_global_limit_are_closed_at_accept() {
    let server = start(BoundedHttp1Limits {
        max_connections: 2,
        max_connections_per_peer: 1,
        ..limits()
    })
    .await;
    // Held open mid-head, inside the header timeout.
    let mut first = connect_from(Ipv4Addr::new(127, 0, 0, 1), server.addr).await;
    first.write_all(b"POST /echo HTTP/1.1\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A second connection from the same peer is refused.
    let mut same_peer = connect_from(Ipv4Addr::new(127, 0, 0, 1), server.addr).await;
    let _ = same_peer.write_all(ECHO.as_bytes()).await;
    let refused = read_until_closed(&mut same_peer, Duration::from_secs(2))
        .await
        .expect("refused connection closes");
    assert!(refused.is_empty(), "{refused}");

    // Another peer fits under the global limit, then the global limit refuses.
    let mut second = connect_from(Ipv4Addr::new(127, 0, 0, 2), server.addr).await;
    second.write_all(b"POST /echo HTTP/1.1\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third_peer = connect_from(Ipv4Addr::new(127, 0, 0, 3), server.addr).await;
    let _ = third_peer.write_all(ECHO.as_bytes()).await;
    let refused = read_until_closed(&mut third_peer, Duration::from_secs(2))
        .await
        .expect("refused connection closes");
    assert!(refused.is_empty(), "{refused}");

    // Closing a held connection frees its peer slot and the global slot.
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut retry = connect_from(Ipv4Addr::new(127, 0, 0, 1), server.addr).await;
    retry.write_all(ECHO.as_bytes()).await.unwrap();
    let served = read_until_closed(&mut retry, Duration::from_secs(5))
        .await
        .expect("served connection closes");
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");
}

#[tokio::test]
async fn a_slow_request_head_is_closed_at_the_header_timeout() {
    let server = start(BoundedHttp1Limits {
        header_read_timeout: Duration::from_millis(300),
        ..limits()
    })
    .await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nhost")
        .await
        .unwrap();
    let response = read_until_closed(&mut stream, Duration::from_secs(3))
        .await
        .expect("slow head is closed");
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert!(!response.contains("200"), "{response}");
}

#[tokio::test]
async fn an_http2_prior_knowledge_preface_is_rejected() {
    let server = start(limits()).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let response = read_until_closed(&mut stream, Duration::from_secs(3))
        .await
        .expect("HTTP/2 preface is closed");
    // No HTTP/2 SETTINGS frame: either nothing or an HTTP/1.1 error.
    assert!(
        response.is_empty()
            || response.starts_with("HTTP/1.1 4")
            || response.starts_with("HTTP/1.1 5"),
        "{response:?}"
    );
}

#[tokio::test]
async fn bodies_over_the_cap_are_refused() {
    let server = start(limits()).await;
    let mut declared = TcpStream::connect(server.addr).await.unwrap();
    declared
        .write_all(
            format!(
                "POST /echo HTTP/1.1\r\nhost: binding\r\ncontent-length: 65\r\n\r\n{}",
                "a".repeat(65)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_until_closed(&mut declared, Duration::from_secs(3))
        .await
        .expect("declared oversize closes");
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");

    let mut chunked = TcpStream::connect(server.addr).await.unwrap();
    chunked
        .write_all(
            format!(
                "POST /echo HTTP/1.1\r\nhost: binding\r\ntransfer-encoding: chunked\r\n\r\n41\r\n{}\r\n0\r\n\r\n",
                "a".repeat(0x41)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_until_closed(&mut chunked, Duration::from_secs(3))
        .await
        .expect("streamed oversize closes");
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!response.contains("127.0.0.1"), "{response}");
}

#[tokio::test]
async fn too_many_or_too_large_headers_are_refused() {
    let server = start(limits()).await;
    let mut many = TcpStream::connect(server.addr).await.unwrap();
    let headers: String = (0..20)
        .map(|index| format!("x-extra-{index}: 1\r\n"))
        .collect();
    many.write_all(
        format!("POST /echo HTTP/1.1\r\nhost: binding\r\n{headers}content-length: 0\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let response = read_until_closed(&mut many, Duration::from_secs(3))
        .await
        .expect("too many headers closes");
    assert!(response.starts_with("HTTP/1.1 431"), "{response}");

    // hyper reads at most one more buffer-sized chunk after an incomplete
    // head, so an accepted head stays below twice the buffer cap.
    let mut large = TcpStream::connect(server.addr).await.unwrap();
    let _ = large
        .write_all(
            format!(
                "POST /echo HTTP/1.1\r\nhost: binding\r\nx-large: {}\r\ncontent-length: 0\r\n\r\n",
                "a".repeat(2 * 16 * 1024)
            )
            .as_bytes(),
        )
        .await;
    let response = read_until_closed(&mut large, Duration::from_secs(3))
        .await
        .expect("oversized head closes");
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn the_connection_deadline_closes_a_stalled_response() {
    let server = start(BoundedHttp1Limits {
        header_read_timeout: Duration::from_millis(300),
        request_read_timeout: Duration::from_millis(300),
        connection_deadline: Duration::from_millis(400),
        ..limits()
    })
    .await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nhost: binding\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_closed(&mut stream, Duration::from_secs(5))
        .await
        .expect("deadline closes the connection");
    assert!(response.is_empty(), "{response}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn invalid_limits_fail_before_serving() {
    for invalid in [
        BoundedHttp1Limits {
            max_connections_per_peer: 9,
            ..limits()
        },
        BoundedHttp1Limits {
            max_connections: 0,
            ..limits()
        },
        BoundedHttp1Limits {
            max_header_bytes: 4096,
            ..limits()
        },
        BoundedHttp1Limits {
            header_read_timeout: Duration::ZERO,
            ..limits()
        },
        BoundedHttp1Limits {
            request_read_timeout: Duration::from_secs(11),
            ..limits()
        },
        BoundedHttp1Limits {
            header_read_timeout: Duration::from_secs(6),
            ..limits()
        },
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(
            serve_bounded_http1_until(Router::new(), listener, invalid, async {})
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn a_trickled_body_is_refused_before_the_handler_runs() {
    let server = start(BoundedHttp1Limits {
        header_read_timeout: Duration::from_millis(300),
        request_read_timeout: Duration::from_millis(400),
        ..limits()
    })
    .await;
    let before = HANDLED.load(std::sync::atomic::Ordering::SeqCst);
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    // A valid head inside the header timeout, then only part of the body.
    stream
        .write_all(b"POST /counted HTTP/1.1\r\nhost: binding\r\ncontent-length: 10\r\n\r\nab")
        .await
        .unwrap();
    let response = read_until_closed(&mut stream, Duration::from_secs(5))
        .await
        .expect("trickled body is closed");
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "held for {:?}",
        started.elapsed()
    );
    assert_eq!(HANDLED.load(std::sync::atomic::Ordering::SeqCst), before);

    // A complete request inside the deadline still reaches the handler.
    let mut complete = TcpStream::connect(server.addr).await.unwrap();
    complete
        .write_all(b"POST /counted HTTP/1.1\r\nhost: binding\r\ncontent-length: 2\r\n\r\nab")
        .await
        .unwrap();
    let response = read_until_closed(&mut complete, Duration::from_secs(5))
        .await
        .expect("complete request closes");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(HANDLED.load(std::sync::atomic::Ordering::SeqCst) > before);
}

#[test]
fn accept_errors_pause_with_growing_backoff_and_a_bounded_log_rate() {
    let mut backoff = AcceptBackoff::default();
    let start = std::time::Instant::now();
    let exhausted = std::io::Error::from_raw_os_error(24); // EMFILE
    let (first, logged) = backoff.on_error(&exhausted, start);
    assert_eq!(first, ACCEPT_BACKOFF_INITIAL);
    assert!(logged);
    let mut pause = first;
    for step in 1..20 {
        let (next, logged) = backoff.on_error(&exhausted, start + Duration::from_millis(step));
        assert!(next >= pause && next <= ACCEPT_BACKOFF_MAX);
        assert!(!logged, "logged again within the interval");
        pause = next;
    }
    assert_eq!(pause, ACCEPT_BACKOFF_MAX);
    // The next log is allowed only after the interval.
    assert!(
        backoff
            .on_error(&exhausted, start + ACCEPT_ERROR_LOG_INTERVAL)
            .1
    );
    // A peer that reset before accept completed does not pause the loop.
    let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
    assert_eq!(backoff.on_error(&reset, start).0, Duration::ZERO);
    // A successful accept restarts the backoff.
    backoff.reset();
    assert_eq!(
        backoff.on_error(&exhausted, start).0,
        ACCEPT_BACKOFF_INITIAL
    );
}

/// An upgrade that never completes, like a client stalling its handshake.
#[derive(Clone)]
struct StalledUpgrade;

impl ConnectionUpgrade for StalledUpgrade {
    type Io = TcpStream;

    async fn upgrade(&self, _stream: TcpStream) -> std::io::Result<TcpStream> {
        std::future::pending().await
    }
}

/// An upgrade that fails, like a refused handshake.
#[derive(Clone)]
struct RefusedUpgrade;

impl ConnectionUpgrade for RefusedUpgrade {
    type Io = TcpStream;

    async fn upgrade(&self, _stream: TcpStream) -> std::io::Result<TcpStream> {
        Err(std::io::Error::other("refused"))
    }
}

async fn start_upgraded(
    limits: BoundedHttp1Limits,
    upgrade: impl ConnectionUpgrade,
) -> (Server, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let handled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = handled.clone();
    let app = Router::new().route(
        "/counted",
        post(move || async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            "handled"
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_bounded_http1_upgraded_until(app, listener, limits, upgrade, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    (
        Server {
            addr,
            stop: Some(stop),
        },
        handled,
    )
}

#[tokio::test]
async fn a_stalled_upgrade_holds_its_slots_and_closes_at_the_read_deadline() {
    let limits = BoundedHttp1Limits {
        header_read_timeout: Duration::from_millis(300),
        request_read_timeout: Duration::from_millis(300),
        ..limits()
    };
    let (server, handled) = start_upgraded(limits, StalledUpgrade).await;
    let started = Instant::now();
    let mut first = TcpStream::connect(server.addr).await.unwrap();
    let mut second = TcpStream::connect(server.addr).await.unwrap();
    // The stalled upgrades hold this peer's two slots: a third is refused.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut third = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(
        read_until_closed(&mut third, Duration::from_millis(200)).await,
        Some(String::new())
    );
    first
        .write_all(b"POST /counted HTTP/1.1\r\nhost: b\r\ncontent-length: 0\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_until_closed(&mut first, Duration::from_secs(3)).await,
        Some(String::new())
    );
    assert_eq!(
        read_until_closed(&mut second, Duration::from_secs(3)).await,
        Some(String::new())
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failed_upgrade_closes_without_a_response() {
    let (server, handled) = start_upgraded(limits(), RefusedUpgrade).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let _ = stream
        .write_all(b"POST /counted HTTP/1.1\r\nhost: b\r\ncontent-length: 0\r\n\r\n")
        .await;
    assert_eq!(
        read_until_closed(&mut stream, Duration::from_secs(3)).await,
        Some(String::new())
    );
    assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 0);
}
