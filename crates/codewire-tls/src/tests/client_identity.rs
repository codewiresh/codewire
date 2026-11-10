//! Client certificates: a listener that asks for one and tells its handler
//! who the verified client is, and an endpoint that presents one.

use axum::extract::ConnectInfo;

use super::*;

const CLIENT: &str = "codewire-orchestration.codewire.svc";

fn client_leaf(ca: &Ca, name: &str, usage: ExtendedKeyUsagePurpose) -> (String, String) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages = vec![usage];
    issue(ca, params)
}

fn issue(ca: &Ca, mut params: CertificateParams) -> (String, String) {
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, &ca.certificate, &ca.key).unwrap();
    (certificate.pem(), key.serialize_pem())
}

/// A server that trusts `client_ca` for clients and answers with what it
/// learned about the peer, plus the mounted files a client presents.
struct Mutual {
    directory: TempDir,
    server_roots: PathBuf,
    client_roots: PathBuf,
    origin: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Mutual {
    async fn start(server_ca: &Ca, client_ca: &Ca) -> Self {
        let files = Files::new(server_ca, "localhost");
        let client_roots = files.directory.path().join("client-ca.pem");
        write(&client_roots, client_ca.pem());
        let identity = files
            .identity
            .clone()
            .with_client_roots(client_roots.clone())
            .unwrap();
        identity.validate().await.unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let listener = PeerTlsListener::new(socket, identity).unwrap();
        let app = Router::new().route(
            "/",
            route_get(|ConnectInfo(peer): ConnectInfo<TlsPeer>| async move {
                match peer.client {
                    None => "anonymous",
                    Some(client) if client.is_named(CLIENT) => "orchestration",
                    Some(_) => "another client",
                }
            }),
        );
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<TlsPeer>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            server_roots: files.roots.clone(),
            directory: files.directory,
            client_roots,
            origin: format!("https://localhost:{port}"),
            stop,
            task,
        }
    }

    fn present(&self, (chain, key): (String, String)) {
        write(&self.directory.path().join("client.crt"), chain);
        write(&self.directory.path().join("client.key"), key);
    }

    fn anonymous(&self) -> ClientTlsEndpoint {
        ClientTlsEndpoint::new(self.origin.clone(), self.server_roots.clone()).unwrap()
    }

    fn identified(&self) -> ClientTlsEndpoint {
        self.anonymous()
            .with_client_identity(
                self.directory.path().join("client.crt"),
                self.directory.path().join("client.key"),
            )
            .unwrap()
    }

    /// One request on a fresh connection with the endpoint's current files.
    async fn get(&self, endpoint: &ClientTlsEndpoint) -> Result<String, String> {
        let config = endpoint
            .rustls_config()
            .await
            .map_err(|error| error.to_string())?;
        reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .use_preconfigured_tls(config)
            .timeout(TEST_TIMEOUT)
            .build()
            .unwrap()
            .get(&self.origin)
            .send()
            .await
            .map_err(|_| "request failed".to_owned())?
            .text()
            .await
            .map_err(|_| "body failed".to_owned())
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

#[tokio::test]
async fn a_handler_learns_which_verified_client_called_or_that_none_did() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server = Mutual::start(&server_ca, &client_ca).await;
    assert_eq!(server.get(&server.anonymous()).await.unwrap(), "anonymous");

    let endpoint = server.identified();
    server.present(client_leaf(
        &client_ca,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    endpoint.validate().await.unwrap();
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");

    // The same CA's leaf for another name is verified but is not that client.
    server.present(client_leaf(
        &client_ca,
        "codewire-mesh.codewire.svc",
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap(), "another client");
    server.stop().await;
}

#[tokio::test]
async fn an_offered_certificate_the_client_roots_do_not_trust_fails_the_handshake() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server = Mutual::start(&server_ca, &client_ca).await;
    let endpoint = server.identified();

    // The right name from the server's own CA, which is not a client root.
    server.present(client_leaf(
        &server_ca,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap_err(), "request failed");

    // The client CA's leaf, but issued for server authentication only.
    server.present(client_leaf(
        &client_ca,
        CLIENT,
        ExtendedKeyUsagePurpose::ServerAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap_err(), "request failed");

    // The right issuer, name and usage, but expired yesterday.
    let mut expired = CertificateParams::new(vec![CLIENT.to_owned()]).unwrap();
    expired.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let now = std::time::SystemTime::now();
    expired.not_before = (now - Duration::from_secs(2 * 86_400)).into();
    expired.not_after = (now - Duration::from_secs(86_400)).into();
    server.present(issue(&client_ca, expired));
    assert_eq!(server.get(&endpoint).await.unwrap_err(), "request failed");

    // None of these failures ended the listener.
    server.present(client_leaf(
        &client_ca,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");
    server.stop().await;
}

#[tokio::test]
async fn rotated_client_roots_and_identity_apply_to_the_next_connection() {
    let server_ca = Ca::new();
    let old = Ca::new();
    let new = Ca::new();
    let server = Mutual::start(&server_ca, &old).await;
    let endpoint = server.identified();
    server.present(client_leaf(
        &old,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");

    // The overlap bundle admits both issuers while the client still holds
    // its old leaf, then its new one.
    write(&server.client_roots, format!("{}{}", old.pem(), new.pem()));
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");
    server.present(client_leaf(
        &new,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");

    write(&server.client_roots, new.pem());
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");
    server.present(client_leaf(
        &old,
        CLIENT,
        ExtendedKeyUsagePurpose::ClientAuth,
    ));
    assert_eq!(server.get(&endpoint).await.unwrap_err(), "request failed");

    // Malformed client roots refuse every handshake rather than admit
    // clients unverified or reuse the last good roots.
    write(&server.client_roots, "malformed replacement");
    assert_eq!(
        server.get(&server.anonymous()).await.unwrap_err(),
        "request failed"
    );
    server.stop().await;
}

#[tokio::test]
async fn client_identity_configuration_fails_closed() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let files = Files::new(&server_ca, "localhost");
    let directory = files.directory.path();
    let certificate = directory.join("client.crt");
    let key = directory.join("client.key");
    let endpoint =
        || ClientTlsEndpoint::new("https://localhost:8443".into(), files.roots.clone()).unwrap();

    // Relative or shared paths are refused before anything is read.
    for (certificate, key) in [
        (PathBuf::from("client.crt"), key.clone()),
        (certificate.clone(), PathBuf::from("client.key")),
        (certificate.clone(), certificate.clone()),
    ] {
        assert_eq!(
            endpoint().with_client_identity(certificate, key).err(),
            Some(TlsError::Configuration)
        );
    }
    let identified = endpoint()
        .with_client_identity(certificate.clone(), key.clone())
        .unwrap();
    assert_eq!(format!("{identified:?}"), "ClientTlsEndpoint([redacted])");

    // Missing files, then a key that does not match the certificate.
    assert_eq!(identified.validate().await, Err(TlsError::Files));
    let (chain, _) = client_leaf(&client_ca, CLIENT, ExtendedKeyUsagePurpose::ClientAuth);
    let (_, other_key) = client_leaf(&client_ca, CLIENT, ExtendedKeyUsagePurpose::ClientAuth);
    write(&certificate, chain);
    write(&key, other_key);
    assert_eq!(identified.validate().await, Err(TlsError::InvalidPem));

    // The tonic channel cannot present the identity, so it never connects
    // without it.
    assert_eq!(
        identified.connect().await.err(),
        Some(TlsError::Configuration)
    );

    // A listener that reports peers needs client roots, apart from its own
    // identity files.
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(matches!(
        PeerTlsListener::new(socket, files.identity.clone()),
        Err(TlsError::Configuration)
    ));
    assert_eq!(
        files
            .identity
            .clone()
            .with_client_roots(directory.join("tls.crt"))
            .err(),
        Some(TlsError::Configuration)
    );
    assert_eq!(
        files
            .identity
            .clone()
            .with_client_roots(PathBuf::from("client-ca.pem"))
            .err(),
        Some(TlsError::Configuration)
    );
}

#[test]
fn a_verified_client_is_named_only_by_its_subject_alternative_dns_names() {
    let ca = Ca::new();
    let (chain, _) = client_leaf(&ca, CLIENT, ExtendedKeyUsagePurpose::ClientAuth);
    let leaf = crate::files::certificates(chain.as_bytes())
        .unwrap()
        .remove(0);
    let client = VerifiedClient::new(leaf);
    assert!(client.is_named(CLIENT));
    assert!(client.is_named(&CLIENT.to_uppercase()));
    for other in [
        "codewire-orchestration.codewire",
        "other.codewire-orchestration.codewire.svc",
        "rcgen self signed cert",
        "127.0.0.1",
        "",
    ] {
        assert!(!client.is_named(other), "{other}");
    }
    assert_eq!(format!("{client:?}"), "VerifiedClient([redacted])");
}

/// What verification does not establish, and why the client roots must
/// belong to an authority that signs only the intended clients by exact name.
#[tokio::test]
async fn a_wildcard_name_or_an_unrestricted_usage_is_accepted_from_a_trusted_issuer() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server = Mutual::start(&server_ca, &client_ca).await;
    let endpoint = server.identified();
    let wildcard = CertificateParams::new(vec!["*.codewire.svc".to_owned()]).unwrap();
    assert!(wildcard.extended_key_usages.is_empty());
    server.present(issue(&client_ca, wildcard));
    assert_eq!(server.get(&endpoint).await.unwrap(), "orchestration");
    server.stop().await;
}
