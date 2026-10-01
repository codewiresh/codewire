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
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(
            serve_bounded_http1_until(Router::new(), listener, invalid, async {})
                .await
                .is_err()
        );
    }
}
