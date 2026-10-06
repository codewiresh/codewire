use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::{Router, routing::get as route_get};
use futures::{StreamExt, poll};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(8);

struct Ca {
    certificate: Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        Self {
            certificate: params.self_signed(&key).unwrap(),
            key,
        }
    }

    fn leaf(&self, name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .unwrap();
        (
            format!("{}{}", certificate.pem(), self.certificate.pem()),
            key.serialize_pem(),
        )
    }

    fn pem(&self) -> String {
        self.certificate.pem()
    }
}

fn write(path: &Path, value: impl AsRef<[u8]>) {
    std::fs::write(path, value).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct Files {
    directory: TempDir,
    identity: ServerTlsFiles,
    roots: PathBuf,
}

impl Files {
    fn new(ca: &Ca, dns: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("tls.crt");
        let key = directory.path().join("tls.key");
        let roots = directory.path().join("ca.pem");
        let (chain, private_key) = ca.leaf(dns);
        write(&certificate, chain);
        write(&key, private_key);
        write(&roots, ca.pem());
        Self {
            directory,
            identity: ServerTlsFiles::new(certificate, key).unwrap(),
            roots,
        }
    }

    fn replace(&self, ca: &Ca, dns: &str) {
        let (chain, key) = ca.leaf(dns);
        write(&self.directory.path().join("tls.crt"), chain);
        write(&self.directory.path().join("tls.key"), key);
    }
}

struct Server {
    origin: String,
    address: std::net::SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start(files: ServerTlsFiles) -> Self {
        files.validate().await.unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let listener = TlsListener::new(socket, files).unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", route_get(|| async { "verified\n" })),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            origin: format!("https://localhost:{}", address.port()),
            address,
            stop,
            task,
        }
    }

    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(TEST_TIMEOUT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn get(server: &Server, ca: &Ca) -> Result<String, reqwest::Error> {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
        .timeout(TEST_TIMEOUT)
        .build()
        .unwrap()
        .get(&server.origin)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

#[test]
fn configuration_rejects_non_origins_and_redacts_all_inputs() {
    let root = PathBuf::from("/synthetic-private/ca.pem");
    for invalid in [
        "http://localhost",
        "https://user@localhost",
        "https://:pass@localhost",
        "https://localhost/path",
        "https://localhost/?x=1",
        "https://localhost/#fragment",
        "https://localhost:0",
        "https://localhost:",
        "https://127.0.0.1",
        "https://[::1]",
        "https://localhost/../",
        "https://localhost//",
        "https://localhost/%2f",
        "https://localhost\\bad",
    ] {
        assert_eq!(
            ClientTlsEndpoint::new(invalid.into(), root.clone()).unwrap_err(),
            TlsError::Configuration
        );
    }
    for valid in [
        "https://localhost",
        "https://localhost/",
        "https://broker.example:9443/",
    ] {
        ClientTlsEndpoint::new(valid.into(), root.clone()).unwrap();
    }
    assert!(ClientTlsEndpoint::new("https://localhost".into(), "relative.pem".into()).is_err());
    assert!(ServerTlsFiles::new("relative.pem".into(), root.clone()).is_err());
    assert!(ServerTlsFiles::new(root.clone(), root.clone()).is_err());
    assert!(ServerTlsFiles::new("/".into(), root.clone()).is_err());
    let server = ServerTlsFiles::new(
        "/synthetic-private/cert".into(),
        "/synthetic-private/key".into(),
    )
    .unwrap();
    let endpoint =
        ClientTlsEndpoint::new("https://synthetic-private.example".into(), root).unwrap();
    assert_eq!(format!("{server:?}"), "ServerTlsFiles([redacted])");
    assert_eq!(format!("{endpoint:?}"), "ClientTlsEndpoint([redacted])");
    for error in [
        TlsError::Configuration,
        TlsError::Files,
        TlsError::InvalidPem,
        TlsError::Timeout,
        TlsError::Handshake,
        TlsError::Connect,
    ] {
        assert!(error.source().is_none());
        assert!(!format!("{error} {error:?}").contains("synthetic-private"));
    }
}

#[tokio::test]
async fn real_tls_accepts_explicit_root_and_rejects_wrong_purpose_ca_and_dns() {
    let gateway_ca = Ca::new();
    let broker_ca = Ca::new();
    let files = Files::new(&broker_ca, "localhost");
    assert_eq!(
        files.identity.load(false).await.unwrap().alpn_protocols,
        vec![b"h2".to_vec()]
    );
    assert_eq!(
        files.identity.load(true).await.unwrap().alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    let server = Server::start(files.identity.clone()).await;
    assert_eq!(get(&server, &broker_ca).await.unwrap(), "verified\n");
    assert!(get(&server, &gateway_ca).await.is_err());
    let endpoint = ClientTlsEndpoint::new(server.origin.clone(), files.roots.clone()).unwrap();
    drop(endpoint.connect().await.unwrap());
    write(&files.roots, gateway_ca.pem());
    assert!(endpoint.connect().await.is_err());
    write(&files.roots, broker_ca.pem());
    files.replace(&broker_ca, "different-service.example");
    assert!(endpoint.connect().await.is_err());
    assert!(get(&server, &broker_ca).await.is_err());
    files.replace(&broker_ca, "localhost");
    drop(endpoint.connect().await.unwrap());
    server.stop().await;
}

#[tokio::test]
async fn malformed_missing_oversize_and_mixed_pem_inputs_fail_closed() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let endpoint =
        ClientTlsEndpoint::new("https://localhost:1".into(), files.roots.clone()).unwrap();
    endpoint.validate().await.unwrap();
    for bytes in [
        "not a certificate".to_owned(),
        format!(
            "{}-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
            ca.pem()
        ),
        format!("{}garbage", ca.pem()),
        format!("{}{}", ca.pem(), ca.key.serialize_pem()),
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".into(),
    ] {
        write(&files.roots, bytes);
        assert_eq!(endpoint.validate().await.unwrap_err(), TlsError::InvalidPem);
        assert_eq!(endpoint.connect().await.unwrap_err(), TlsError::InvalidPem);
    }
    write(&files.roots, vec![b'x'; files::MAX_CERTIFICATE_BYTES + 1]);
    assert_eq!(endpoint.validate().await.unwrap_err(), TlsError::Files);
    std::fs::remove_file(&files.roots).unwrap();
    assert_eq!(endpoint.validate().await.unwrap_err(), TlsError::Files);
    std::fs::create_dir(&files.roots).unwrap();
    assert_eq!(endpoint.validate().await.unwrap_err(), TlsError::Files);
    write(
        &files.directory.path().join("tls.key"),
        "invalid private-key canary",
    );
    assert_eq!(
        files.identity.validate().await.unwrap_err(),
        TlsError::InvalidPem
    );
    write(
        &files.directory.path().join("tls.key"),
        Ca::new().key.serialize_pem(),
    );
    assert_eq!(
        files.identity.validate().await.unwrap_err(),
        TlsError::InvalidPem
    );
    write(
        &files.directory.path().join("tls.key"),
        vec![b'x'; 64 * 1024 + 1],
    );
    assert_eq!(
        files.identity.validate().await.unwrap_err(),
        TlsError::Files
    );
}

#[tokio::test]
async fn changed_invalid_identity_or_trust_never_reuses_last_good_configuration() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let server = Server::start(files.identity.clone()).await;
    let endpoint = ClientTlsEndpoint::new(server.origin.clone(), files.roots.clone()).unwrap();
    drop(endpoint.connect().await.unwrap());
    write(
        &files.directory.path().join("tls.crt"),
        "malformed replacement",
    );
    assert!(endpoint.connect().await.is_err());
    files.replace(&ca, "localhost");
    drop(endpoint.connect().await.unwrap());
    write(&files.roots, "malformed replacement");
    assert_eq!(endpoint.connect().await.unwrap_err(), TlsError::InvalidPem);
    write(&files.roots, ca.pem());
    drop(endpoint.connect().await.unwrap());
    server.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn projected_symlink_rotation_a_to_overlap_to_b_applies_to_new_connections() {
    use std::os::unix::fs::symlink;
    let a = Ca::new();
    let b = Ca::new();
    let directory = tempfile::tempdir().unwrap();
    for (version, ca) in [("identity-a", &a), ("identity-b", &b)] {
        let path = directory.path().join(version);
        std::fs::create_dir(&path).unwrap();
        let (certificate, key) = ca.leaf("localhost");
        write(&path.join("tls.crt"), certificate);
        write(&path.join("tls.key"), key);
    }
    for (version, roots) in [
        ("trust-a", a.pem()),
        ("trust-ab", format!("{}{}", a.pem(), b.pem())),
        ("trust-b", b.pem()),
    ] {
        let path = directory.path().join(version);
        std::fs::create_dir(&path).unwrap();
        write(&path.join("ca.pem"), roots);
    }
    symlink("identity-a", directory.path().join("..identity")).unwrap();
    symlink("trust-a", directory.path().join("..trust")).unwrap();
    symlink("..identity/tls.crt", directory.path().join("tls.crt")).unwrap();
    symlink("..identity/tls.key", directory.path().join("tls.key")).unwrap();
    symlink("..trust/ca.pem", directory.path().join("ca.pem")).unwrap();
    let identity = ServerTlsFiles::new(
        directory.path().join("tls.crt"),
        directory.path().join("tls.key"),
    )
    .unwrap();
    let server = Server::start(identity).await;
    let endpoint =
        ClientTlsEndpoint::new(server.origin.clone(), directory.path().join("ca.pem")).unwrap();
    let switch = |target: &str, link: &str| {
        symlink(target, directory.path().join("..next")).unwrap();
        std::fs::rename(directory.path().join("..next"), directory.path().join(link)).unwrap();
    };
    drop(endpoint.connect().await.unwrap());
    switch("trust-ab", "..trust");
    drop(endpoint.connect().await.unwrap());
    switch("identity-b", "..identity");
    drop(endpoint.connect().await.unwrap());
    assert!(get(&server, &a).await.is_err());
    assert_eq!(get(&server, &b).await.unwrap(), "verified\n");
    switch("trust-b", "..trust");
    drop(endpoint.connect().await.unwrap());
    switch("identity-a", "..identity");
    assert!(endpoint.connect().await.is_err());
    switch("identity-b", "..identity");
    drop(endpoint.connect().await.unwrap());
    server.stop().await;
}

#[test]
fn connect_origins_are_exact_https_dns_origins_with_absolute_roots() {
    let roots = Path::new("/synthetic-private/ca.pem");
    let transport =
        ConnectOriginTransport::for_origin("https://orchestration.example:8088", roots).unwrap();
    assert_eq!(
        format!("{transport:?}"),
        "ConnectOriginTransport([redacted])"
    );
    for origin in [
        "http://orchestration.example:8085",
        "https://orchestration.example:8088/path",
        "https://127.0.0.1:8088",
        "orchestration.example:8088",
        "ftp://orchestration.example",
    ] {
        assert_eq!(
            ConnectOriginTransport::for_origin(origin, roots).unwrap_err(),
            TlsError::Configuration,
            "{origin}"
        );
    }
    assert_eq!(
        ConnectOriginTransport::for_origin(
            "https://orchestration.example:8088",
            Path::new("ca.pem")
        )
        .unwrap_err(),
        TlsError::Configuration
    );
}

async fn connect_get(transport: &ConnectOriginTransport, origin: &str) -> Result<String, String> {
    use connectrpc::client::ClientTransport as _;
    use http_body_util::BodyExt as _;
    let request = http::Request::get(format!("{origin}/"))
        .body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap();
    let response = tokio::time::timeout(TEST_TIMEOUT, transport.send(request))
        .await
        .unwrap()
        .map_err(|error| error.to_string())?;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Ok(String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn connect_transport_rereads_roots_per_call_and_verifies_the_origin_name() {
    let ca = Ca::new();
    let other = Ca::new();
    let files = Files::new(&ca, "localhost");
    let server = Server::start(files.identity.clone()).await;
    // One transport across every call below: each call applies current roots.
    let transport = ConnectOriginTransport::for_origin(&server.origin, &files.roots).unwrap();
    assert_eq!(
        connect_get(&transport, &server.origin).await.unwrap(),
        "verified\n"
    );
    write(&files.roots, other.pem());
    assert!(connect_get(&transport, &server.origin).await.is_err());
    write(&files.roots, "malformed replacement");
    let error = connect_get(&transport, &server.origin).await.unwrap_err();
    assert!(error.contains("internal TLS trust unavailable"), "{error}");
    assert!(
        !error.contains("synthetic") && !error.contains(".pem"),
        "{error}"
    );
    write(&files.roots, ca.pem());
    // A leaf from the right CA for another name is refused.
    files.replace(&ca, "different-service.example");
    assert!(connect_get(&transport, &server.origin).await.is_err());
    files.replace(&ca, "localhost");
    assert_eq!(
        connect_get(&transport, &server.origin).await.unwrap(),
        "verified\n"
    );
    server.stop().await;
}

#[tokio::test]
async fn connect_transport_refuses_plaintext_servers_and_other_origins() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    // An https transport against a plaintext listener never falls back.
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = plain.local_addr().unwrap().port();
    let plain_task = tokio::spawn(async move {
        axum::serve(
            plain,
            Router::new().route("/", route_get(|| async { "plaintext\n" })),
        )
        .await
    });
    let origin = format!("https://localhost:{port}");
    let transport = ConnectOriginTransport::for_origin(&origin, &files.roots).unwrap();
    let error = connect_get(&transport, &origin).await.unwrap_err();
    assert!(error.contains("HTTPS request failed"), "{error}");
    plain_task.abort();

    // A request for another origin is refused before any connection.
    let server = Server::start(files.identity.clone()).await;
    let transport = ConnectOriginTransport::for_origin(&server.origin, &files.roots).unwrap();
    for other in [
        server.origin.replacen("https://", "http://", 1),
        format!("https://localhost:{}", server.address.port() + 1),
        format!("https://127.0.0.1:{}", server.address.port()),
    ] {
        let error = connect_get(&transport, &other).await.unwrap_err();
        assert!(error.contains("configured origin"), "{other}: {error}");
    }
    assert_eq!(
        connect_get(&transport, &server.origin).await.unwrap(),
        "verified\n"
    );
    server.stop().await;
}

#[tokio::test]
async fn mounted_identity_is_verified_offline_against_published_roots() {
    let ca = Ca::new();
    let files = Files::new(&ca, "orchestration.example");
    let roots = ca.pem();
    files
        .identity
        .verify_against_roots(roots.as_bytes(), "orchestration.example")
        .await
        .unwrap();
    assert_eq!(
        files
            .identity
            .verify_against_roots(roots.as_bytes(), "other.example")
            .await
            .unwrap_err(),
        TlsError::Handshake
    );
    assert_eq!(
        files
            .identity
            .verify_against_roots(Ca::new().pem().as_bytes(), "orchestration.example")
            .await
            .unwrap_err(),
        TlsError::Handshake
    );
    assert_eq!(
        files
            .identity
            .verify_against_roots(b"not a certificate", "orchestration.example")
            .await
            .unwrap_err(),
        TlsError::InvalidPem
    );
}

#[tokio::test]
async fn plaintext_and_failed_handshakes_do_not_terminate_the_listener() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let server = Server::start(files.identity.clone()).await;
    let mut plain = TcpStream::connect(server.address).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(TEST_TIMEOUT, plain.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(!response.windows(5).any(|bytes| bytes == b"HTTP/"));
    for _ in 0..4 {
        let mut malformed = TcpStream::connect(server.address).await.unwrap();
        malformed.write_all(b"not a TLS client").await.unwrap();
        drop(malformed);
    }
    assert_eq!(get(&server, &ca).await.unwrap(), "verified\n");
    server.stop().await;
}

async fn fill_pending(incoming: &mut TlsIncoming, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while incoming.pending_handshakes() != count {
            assert!(poll!(incoming.next()).is_pending());
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_incoming_cancels_all_bounded_pending_handshakes() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut incoming = TlsIncoming::new(socket, files.identity).unwrap();
    let mut clients = Vec::new();
    for _ in 0..MAX_HANDSHAKES {
        clients.push(TcpStream::connect(address).await.unwrap());
    }
    fill_pending(&mut incoming, MAX_HANDSHAKES).await;
    let extra = TcpStream::connect(address).await.unwrap();
    assert!(poll!(incoming.next()).is_pending());
    assert_eq!(incoming.pending_handshakes(), MAX_HANDSHAKES);
    drop(incoming);
    drop(extra);
    for mut client in clients {
        let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0u8; 1]))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
}

#[tokio::test]
async fn slow_server_handshake_expires_without_retaining_a_worker() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut incoming = TlsIncoming::new(socket, files.identity).unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    fill_pending(&mut incoming, 1).await;
    tokio::time::timeout(TLS_TIMEOUT + Duration::from_secs(2), async {
        while incoming.pending_handshakes() != 0 {
            assert!(poll!(incoming.next()).is_pending());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn stalled_client_tls_exchange_has_a_whole_connect_deadline() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let endpoint =
        ClientTlsEndpoint::new(format!("https://localhost:{}", address.port()), files.roots)
            .unwrap();
    let connect = endpoint.connect();
    tokio::pin!(connect);
    let accepted = tokio::select! {
        result = &mut connect => panic!("unexpected early result: {result:?}"),
        result = socket.accept() => result.unwrap().0,
    };
    // Hold the accepted socket without replying to ClientHello, not a proxy or
    // endpoint override. Both timeout races produce the same closed boundary.
    let error = tokio::time::timeout(TLS_TIMEOUT + Duration::from_secs(2), connect)
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, TlsError::Timeout | TlsError::Connect));
    drop(accepted);
}

#[cfg(unix)]
#[tokio::test]
async fn nonregular_fifo_is_rejected_without_a_blocking_open() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("synthetic-fifo");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // Exact disposable synthetic path; libc is used only to create this FIFO.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let endpoint = ClientTlsEndpoint::new("https://localhost".into(), fifo).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), endpoint.validate())
            .await
            .unwrap()
            .unwrap_err(),
        TlsError::Files
    );
}

#[tokio::test]
async fn http1_only_handshakes_negotiate_http1_and_refuse_h2_only_clients() {
    let ca = Ca::new();
    let files = Files::new(&ca, "localhost");
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let identity = files.identity.clone();
    let server = tokio::spawn(async move {
        let mut outcomes = Vec::new();
        for _ in 0..2 {
            let (stream, _) = socket.accept().await.unwrap();
            outcomes.push(
                identity
                    .accept_http1_only(stream)
                    .await
                    .map(|tls| tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)),
            );
        }
        outcomes
    });
    let client = |alpn: Vec<Vec<u8>>| {
        let roots = ca.pem();
        async move {
            let mut store = rustls::RootCertStore::empty();
            for root in crate::files::certificates(roots.as_bytes()).unwrap() {
                store.add(root).unwrap();
            }
            let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth();
            config.alpn_protocols = alpn;
            let stream = TcpStream::connect(address).await.unwrap();
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    stream,
                )
                .await
                .map(|tls| tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec))
        }
    };
    let negotiated = client(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .await
        .unwrap();
    assert_eq!(negotiated.as_deref(), Some(&b"http/1.1"[..]));
    assert!(client(vec![b"h2".to_vec()]).await.is_err());
    let outcomes = tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcomes[0], Ok(Some(b"http/1.1".to_vec())));
    assert_eq!(outcomes[1], Err(TlsError::Handshake));
}

#[tokio::test]
async fn an_optional_trust_bundle_is_absent_valid_or_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.crt");
    // Not mounted: no extra trust, and no error.
    assert_eq!(crate::read_optional_roots(&path).await, Ok(None));
    // A valid bundle is returned whole.
    let bundle = format!("{}{}", Ca::new().pem(), Ca::new().pem());
    write(&path, &bundle);
    let roots = crate::read_optional_roots(&path).await.unwrap().unwrap();
    assert_eq!(roots.len(), 2);
    // A present but empty or malformed bundle fails closed.
    write(&path, b"");
    assert_eq!(
        crate::read_optional_roots(&path).await,
        Err(TlsError::Files)
    );
    write(
        &path,
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    );
    assert_eq!(
        crate::read_optional_roots(&path).await,
        Err(TlsError::InvalidPem)
    );
    let truncated = format!("{bundle}-----BEGIN CERTIFICATE-----\n");
    write(&path, truncated);
    assert!(crate::read_optional_roots(&path).await.is_err());
    // Only absolute paths name a mount.
    assert_eq!(
        crate::read_optional_roots(Path::new("ca.crt")).await,
        Err(TlsError::Configuration)
    );
}
