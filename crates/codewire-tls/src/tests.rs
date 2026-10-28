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
use crate::connect::AbsoluteNames;

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
async fn fixed_roots_verify_once_parsed_and_never_follow_a_file() {
    let broker_ca = Ca::new();
    let other_ca = Ca::new();
    let files = Files::new(&broker_ca, "localhost");
    let server = Server::start(files.identity.clone()).await;
    let pinned = broker_ca.pem();
    let endpoint =
        ClientTlsEndpoint::with_fixed_roots(server.origin.clone(), pinned.as_bytes()).unwrap();
    drop(endpoint.connect().await.unwrap());
    // Replacing the mounted file changes nothing for a fixed endpoint.
    write(&files.roots, other_ca.pem());
    drop(endpoint.connect().await.unwrap());
    // Other roots do not verify the server, and the DNS name still counts.
    let wrong =
        ClientTlsEndpoint::with_fixed_roots(server.origin.clone(), other_ca.pem().as_bytes())
            .unwrap();
    assert!(wrong.connect().await.is_err());
    files.replace(&broker_ca, "different-service.example");
    assert!(endpoint.connect().await.is_err());
    server.stop().await;

    // A malformed or oversized bundle is refused when built, never later.
    for bytes in [
        String::new(),
        "not a certificate".to_owned(),
        format!("{}garbage", broker_ca.pem()),
        format!("{}{}", broker_ca.pem(), broker_ca.key.serialize_pem()),
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".into(),
        format!(
            "{}{}",
            broker_ca.pem(),
            "A".repeat(crate::files::MAX_CERTIFICATE_BYTES)
        ),
    ] {
        assert_eq!(
            ClientTlsEndpoint::with_fixed_roots("https://localhost".into(), bytes.as_bytes())
                .unwrap_err(),
            TlsError::InvalidPem
        );
    }
    // The origin rules are the mounted endpoint's.
    assert_eq!(
        ClientTlsEndpoint::with_fixed_roots("https://127.0.0.1".into(), pinned.as_bytes())
            .unwrap_err(),
        TlsError::Configuration
    );
    assert!(
        crate::ConnectOriginTransport::for_origin_with_fixed_roots(
            "https://localhost:8087",
            pinned.as_bytes()
        )
        .is_ok()
    );
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

/// The workspace-binding host a Kind daemon dials: four dots, below the
/// Pod's `ndots:5`, so a relative lookup tries the search list first.
const BINDING_HOST: &str =
    "codewire-orchestration-workspace-binding.codewire-e2e.svc.cluster.local";

/// The system resolver as a static musl `cw` sees it in a Kind Sandbox Pod
/// on a Tailscale workstation (#2701): `ndots:5`, the Pod's search list, and
/// the node's inherited `example.invalid`, whose lookups answer SERVFAIL. musl
/// gives up the whole lookup on that answer; glibc would move on.
#[derive(Clone, Default)]
struct PodResolver {
    /// Every name the connector asked for.
    asked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Every DNS query those names produced.
    queries: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl PodResolver {
    const SEARCH: [&str; 4] = [
        "dev-sandboxes.svc.cluster.local",
        "svc.cluster.local",
        "cluster.local",
        "example.invalid",
    ];

    /// One query: an address, NXDOMAIN (`None`) or SERVFAIL (`Err`).
    fn query(&self, name: &str) -> std::io::Result<Option<std::net::SocketAddr>> {
        self.queries.lock().unwrap().push(name.to_owned());
        if name.ends_with(".example.invalid") {
            Err(std::io::Error::other("SERVFAIL"))
        } else if name == BINDING_HOST {
            Ok(Some(([127, 0, 0, 1], 0).into()))
        } else {
            Ok(None)
        }
    }

    fn lookup(&self, name: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        self.asked.lock().unwrap().push(name.to_owned());
        let (name, search) = match name.strip_suffix('.') {
            Some(absolute) => (absolute, false),
            None => (name, name.matches('.').count() < 5),
        };
        let candidates = Self::SEARCH
            .iter()
            .filter(|_| search)
            .map(|domain| format!("{name}.{domain}"))
            .chain([name.to_owned()]);
        for candidate in candidates {
            // A SERVFAIL ends the lookup, as in musl.
            if let Some(address) = self.query(&candidate)? {
                return Ok(vec![address]);
            }
        }
        Err(std::io::ErrorKind::NotFound.into())
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

impl tonic::codegen::Service<hyper_util::client::legacy::connect::dns::Name> for PodResolver {
    type Response = std::vec::IntoIter<std::net::SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<std::io::Result<Self::Response>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        std::future::ready(self.lookup(name.as_str()).map(Vec::into_iter))
    }
}

#[tokio::test]
async fn absolute_names_skip_a_search_domain_that_answers_servfail() {
    use tonic::codegen::Service as _;
    let name = || BINDING_HOST.parse().unwrap();

    // As given, the lookup fails the way musl failed on the workstation.
    let mut relative = PodResolver::default();
    let error = relative.call(name()).await.unwrap_err();
    assert_eq!(error.to_string(), "SERVFAIL");
    assert_eq!(
        relative.queries().last().unwrap(),
        &format!("{BINDING_HOST}.example.invalid")
    );
    assert!(!relative.queries().contains(&BINDING_HOST.to_owned()));

    // As an absolute name, it is one query for exactly the endpoint.
    let resolver = PodResolver::default();
    let mut absolute = AbsoluteNames(resolver.clone());
    std::future::poll_fn(|cx| absolute.poll_ready(cx))
        .await
        .unwrap();
    let addresses: Vec<_> = absolute.call(name()).await.unwrap().collect();
    assert_eq!(addresses, [std::net::SocketAddr::from(([127, 0, 0, 1], 0))]);
    assert_eq!(resolver.asked(), [format!("{BINDING_HOST}.")]);
    assert_eq!(resolver.queries(), [BINDING_HOST]);

    // Single-label and already absolute names are looked up as given.
    for host in ["localhost", "codewire.test.", "codewire-orchestration"] {
        let resolver = PodResolver::default();
        let _ = AbsoluteNames(resolver.clone())
            .call(host.parse().unwrap())
            .await;
        assert_eq!(resolver.asked(), [host]);
    }
}

/// The TLS server name and the HTTP authority a connection presented.
#[derive(Clone, Debug)]
struct PresentedNames(Option<String>);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for PresentedNames
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        Self(stream.io().get_ref().1.server_name().map(str::to_owned))
    }
}

#[tokio::test]
async fn the_binding_origin_is_looked_up_absolute_but_verified_and_addressed_as_configured() {
    let ca = Ca::new();
    // The leaf names the origin's host without a dot, as cert-manager issues
    // orchestration's internal leaf.
    let files = Files::new(&ca, BINDING_HOST);
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let listener = TlsListener::new(socket, files.identity.clone()).unwrap();
    let app = Router::new().route(
        "/",
        route_get(
            |axum::extract::ConnectInfo(PresentedNames(sni)): axum::extract::ConnectInfo<
                PresentedNames,
            >,
             headers: http::HeaderMap| async move {
                format!(
                    "sni={} host={}",
                    sni.unwrap_or_default(),
                    headers
                        .get(http::header::HOST)
                        .and_then(|host| host.to_str().ok())
                        .unwrap_or_default()
                )
            },
        ),
    );
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PresentedNames>(),
        )
        .await
    });

    let origin = format!("https://{BINDING_HOST}:{port}");
    // HTTP/1.1 like the daemon's binding client, so the authority is a Host
    // header.
    let transport = ConnectOriginTransport::for_origin(&origin, &files.roots)
        .unwrap()
        .http1_only();
    let resolver = PodResolver::default();
    let request = {
        use http_body_util::BodyExt as _;
        http::Request::get(format!("{origin}/"))
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    };
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        transport.send_resolving(resolver.clone(), request),
    )
    .await
    .unwrap()
    .unwrap();
    let body = {
        use http_body_util::BodyExt as _;
        response.into_body().collect().await.unwrap().to_bytes()
    };
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        format!("sni={BINDING_HOST} host={BINDING_HOST}:{port}")
    );
    assert_eq!(resolver.asked(), [format!("{BINDING_HOST}.")]);
    assert_eq!(resolver.queries(), [BINDING_HOST]);
    server.abort();
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
