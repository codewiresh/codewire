use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use codewire_workspace_access::daemon::DaemonSessionClient;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use uuid::Uuid;

use super::ca::{CA_CERTIFICATE_FILE, CA_DIRECTORY, LocalCa};
use super::{Route, Router, Routes, hostname, under_suffix, url};
use crate::guest_loopback::tests::in_process_daemon;

/// A failure guard, longer than anything under test takes.
const WAIT: Duration = Duration::from_secs(30);

#[test]
fn a_labelled_port_gets_one_lowercase_dns_label_under_the_suffix() {
    assert_eq!(
        hostname("web", "shop-a").as_deref(),
        Some("web-shop-a.cw.localhost")
    );
    assert_eq!(
        hostname("Web", "Shop").as_deref(),
        Some("web-shop.cw.localhost")
    );
    let longest = "a".repeat(59);
    assert!(hostname("web", &longest).is_some(), "63 characters");
    assert!(hostname("web", &format!("{longest}a")).is_none(), "64");
    for (label, environment) in [
        ("web", "shop_a"),
        ("web", "shop.a"),
        ("my app", "shop"),
        ("web", "shop-"),
        ("-web", "shop"),
        ("", "shop"),
    ] {
        assert!(
            hostname(label, environment).is_none(),
            "{label}-{environment}"
        );
    }
    assert!(under_suffix("web-shop-a.cw.localhost"));
    assert!(!under_suffix("a.web-shop-a.cw.localhost"));
    assert!(!under_suffix("cw.localhost"));
    assert_eq!(
        url("web-shop.cw.localhost", 443),
        "https://web-shop.cw.localhost"
    );
    assert_eq!(
        url("web-shop.cw.localhost", 8443),
        "https://web-shop.cw.localhost:8443"
    );
}

struct Fake {
    routes: Mutex<HashMap<String, Route>>,
    daemon: DaemonSessionClient,
    running: AtomicBool,
}

impl Fake {
    async fn new(temp: &std::path::Path) -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::default(),
            daemon: in_process_daemon(temp).await,
            running: AtomicBool::new(true),
        })
    }

    fn serve(&self, environment: &str, label: &str, guest_port: u16) -> String {
        let host = hostname(label, environment).unwrap();
        self.routes.lock().unwrap().insert(
            host.clone(),
            Route {
                environment_id: Uuid::new_v4(),
                environment: environment.to_owned(),
                guest_port,
            },
        );
        host
    }
}

impl Routes for Fake {
    fn route(&self, host: &str) -> Option<Route> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }
        self.routes.lock().unwrap().get(host).cloned()
    }

    async fn daemon(&self, _route: &Route) -> Option<DaemonSessionClient> {
        self.running
            .load(Ordering::SeqCst)
            .then(|| self.daemon.clone())
    }
}

/// A guest server on `127.0.0.1` only. It answers each request with its
/// name and the request's head, or, for a WebSocket opening, switches
/// protocols and echoes what it receives.
async fn guest_server(name: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(answer(stream, name));
        }
    });
    port
}

async fn answer(mut stream: TcpStream, name: &'static str) {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    if head.contains("upgrade: websocket") {
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => stream.write_all(&buffer[..read]).await.unwrap(),
            }
        }
    }
    let body = format!("{name}\n{head}");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

struct Harness {
    _temp: tempfile::TempDir,
    routes: Arc<Fake>,
    router: Router,
    root: CertificateDer<'static>,
}

async fn harness() -> Harness {
    let temp = tempfile::tempdir().unwrap();
    let ca = Arc::new(LocalCa::load_or_create(temp.path()).unwrap());
    let pem = std::fs::read(temp.path().join(CA_DIRECTORY).join(CA_CERTIFICATE_FILE)).unwrap();
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
    let routes = Fake::new(temp.path()).await;
    let router = Router::start(ca, routes.clone(), 0).unwrap();
    Harness {
        _temp: temp,
        routes,
        router,
        root: CertificateDer::from(block.contents),
    }
}

impl Harness {
    async fn connect(&self, host: &str) -> std::io::Result<TlsStream<TcpStream>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = TcpStream::connect(("127.0.0.1", self.router.port())).await?;
        tokio::time::timeout(
            WAIT,
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp),
        )
        .await
        .expect("the handshake ends")
    }

    /// One GET through the router: the status and the body.
    async fn get(&self, host: &str) -> (StatusCode, String) {
        let tls = self.connect(host).await.expect("handshake");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        let request = Request::get("/page?q=1")
            .header(HOST, format!("{host}:{}", self.router.port()))
            .header("x-forwarded-proto", "http")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = tokio::time::timeout(WAIT, sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }
}

#[tokio::test]
async fn two_environments_are_served_at_once_each_on_its_own_host() {
    let harness = harness().await;
    let a = harness
        .routes
        .serve("shop-a", "web", guest_server("a").await);
    let b = harness
        .routes
        .serve("shop-b", "web", guest_server("b").await);
    let authority = |host: &str| format!("{host}:{}", harness.router.port());

    for (host, name) in [(&a, "a"), (&b, "b")] {
        let (status, body) = harness.get(host).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut lines = body.lines();
        assert_eq!(lines.next(), Some(name));
        assert_eq!(lines.next(), Some("get /page?q=1 http/1.1"));
        let head = body.to_ascii_lowercase();
        assert!(
            head.contains(&format!("host: {}\r", authority(host))),
            "{head}"
        );
        // The browser's own X-Forwarded-Proto is replaced.
        assert!(head.contains("x-forwarded-proto: https\r"), "{head}");
        assert!(!head.contains("x-forwarded-proto: http\r"), "{head}");
        assert!(
            head.contains(&format!("x-forwarded-host: {}\r", authority(host))),
            "{head}"
        );
        assert!(head.contains("x-forwarded-for: 127.0.0.1\r"), "{head}");
    }
}

#[tokio::test]
async fn a_name_no_running_environment_has_is_refused_at_the_handshake() {
    let harness = harness().await;
    let host = harness
        .routes
        .serve("shop-a", "web", guest_server("a").await);
    assert!(harness.connect("api-shop-a.cw.localhost").await.is_err());
    assert!(harness.connect("example.com").await.is_err());

    harness.routes.running.store(false, Ordering::SeqCst);
    assert!(
        harness.connect(&host).await.is_err(),
        "a stopped environment"
    );
    harness.routes.running.store(true, Ordering::SeqCst);
    assert_eq!(harness.get(&host).await.0, StatusCode::OK, "started again");
}

#[tokio::test]
async fn a_request_whose_host_names_another_environment_is_misdirected() {
    let harness = harness().await;
    let a = harness
        .routes
        .serve("shop-a", "web", guest_server("a").await);
    let b = harness
        .routes
        .serve("shop-b", "web", guest_server("b").await);
    let tls = harness.connect(&a).await.expect("handshake");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = Request::get("/")
        .header(HOST, format!("{b}:{}", harness.router.port()))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = tokio::time::timeout(WAIT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn a_port_with_nothing_listening_answers_502_naming_it() {
    let harness = harness().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let host = harness.routes.serve("shop-a", "web", port);
    let (status, body) = harness.get(&host).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        body,
        format!("Nothing in shop-a listens on 127.0.0.1:{port} yet.\n")
    );
}

#[tokio::test]
async fn a_websocket_is_spliced_to_the_guest_server() {
    let harness = harness().await;
    let host = harness
        .routes
        .serve("shop-a", "web", guest_server("a").await);
    let mut tls = harness.connect(&host).await.unwrap();
    let opening = format!(
        "GET /socket HTTP/1.1\r\nHost: {host}:{}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n",
        harness.router.port()
    );
    tls.write_all(opening.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(WAIT, tls.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    tls.write_all(b"frame bytes").await.unwrap();
    let mut echoed = [0; 11];
    tokio::time::timeout(WAIT, tls.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"frame bytes");
}

#[tokio::test]
async fn dropping_the_router_closes_its_port() {
    let harness = harness().await;
    let port = harness.router.port();
    drop(harness.router);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}
