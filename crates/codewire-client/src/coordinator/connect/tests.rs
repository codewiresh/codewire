use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;

use super::*;

/// A name no resolver answers: a connection can reach it only without a
/// lookup.
const COORDINATOR_HOST: &str = "coordinator.codewire.invalid";

/// A TLS listener on loopback for `COORDINATOR_HOST` that offers HTTP/2, as
/// the public edge does, and the root a client trusts it by.
async fn coordinator_edge() -> (SocketAddr, rustls::RootCertStore) {
    let certified = rcgen::generate_simple_self_signed(vec![COORDINATOR_HOST.to_owned()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
    )
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The handshake is the whole of what this edge serves.
                if let Ok(tls) = acceptor.accept(tcp).await {
                    std::future::pending::<()>().await;
                    drop(tls);
                }
            });
        }
    });
    (address, roots)
}

#[tokio::test]
async fn a_platform_address_is_dialled_for_every_connection_and_the_url_host_verified() {
    let (address, roots) = coordinator_edge().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&dials);
    let dial: TcpDial = Arc::new(move |peer| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(tokio::net::TcpStream::connect(peer))
    });
    let config = coordinator_tls_config_with_roots(roots).unwrap();
    let uri: http::Uri = format!("https://{COORDINATOR_HOST}").parse().unwrap();
    // Each connection the HTTP/2 client opens, the first and a reconnect,
    // goes through the connector, so each must reach the edge by the dial.
    for connection in 1..=2 {
        let tls = connect_ring_tls(
            uri.clone(),
            Arc::clone(&config),
            HostLookup::Platform(address, Arc::clone(&dial)),
        )
        .await
        .unwrap();
        let (_, session) = tls.inner().get_ref();
        assert_eq!(session.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(dials.load(Ordering::SeqCst), connection);
    }

    // The URL's host is still the name verified: an edge for another name
    // is refused at the platform address too.
    let other: http::Uri = "https://elsewhere.codewire.invalid".parse().unwrap();
    assert!(
        connect_ring_tls(other, config, HostLookup::Platform(address, dial))
            .await
            .is_err()
    );
}

/// A dial that counts its calls and records each address.
fn recording_dial() -> (TcpDial, Arc<std::sync::Mutex<Vec<SocketAddr>>>) {
    let dialled = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&dialled);
    let dial: TcpDial = Arc::new(move |peer| {
        record.lock().unwrap().push(peer);
        Box::pin(tokio::net::TcpStream::connect(peer))
    });
    (dial, dialled)
}

#[tokio::test]
async fn a_platform_coordinator_or_mesh_is_reached_over_https_only() {
    use crate::{CoordinatorPeerSession, MeshCoordinateIdentity, MeshCoordinatorPeerSession};
    let (dial, dialled) = recording_dial();
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mesh = MeshCoordinatorPeerSession::connect_platform_with_setup_timeout(
        "http://mesh.codewire.invalid",
        "code",
        MeshCoordinateIdentity::peer("org-1", "net-1"),
        address,
        Arc::clone(&dial),
        std::time::Duration::from_secs(5),
    )
    .await;
    assert!(matches!(mesh, Err(Error::Url(_))));
    let primary = CoordinatorPeerSession::connect_public_edge_grpc_platform(
        "http://coordinator.codewire.invalid",
        "token",
        crate::PrimaryCoordinateIdentity::sidecar(uuid::Uuid::new_v4()),
        Vec::new(),
        std::time::Duration::from_secs(5),
        address,
        dial,
    )
    .await;
    assert!(matches!(primary, Err(Error::Url(_))));
    assert!(dialled.lock().unwrap().is_empty());
}

#[tokio::test]
async fn mesh_on_a_platform_address_dials_that_address() {
    use crate::{MeshCoordinateIdentity, MeshCoordinatorPeerSession};
    // An edge Mesh does not trust (it trusts WebPKI roots only): the session
    // fails at TLS, after the dial this test is about.
    let (address, _) = coordinator_edge().await;
    let (dial, dialled) = recording_dial();
    let mesh = MeshCoordinatorPeerSession::connect_platform_with_setup_timeout(
        &format!("https://{COORDINATOR_HOST}"),
        "code",
        MeshCoordinateIdentity::peer("org-1", "net-1"),
        address,
        dial,
        std::time::Duration::from_secs(5),
    )
    .await;
    assert!(mesh.is_err());
    assert_eq!(*dialled.lock().unwrap(), [address]);
}

#[tokio::test]
async fn a_platform_mesh_member_joins_through_its_configured_addresses_only() {
    use crate::member_tailnet::{MemberPlatform, MemberTailnet};
    let (address, _) = coordinator_edge().await;
    let (dial, dialled) = recording_dial();
    let platform = MemberPlatform {
        mesh: address,
        derp_host: "derp.codewire.invalid".to_owned(),
        derp: "127.0.0.1:9".parse().unwrap(),
        derp_extra_roots: Vec::new(),
        dial,
    };
    let join = |origin: String| {
        let platform = platform.clone();
        async move {
            MemberTailnet::peer_on_platform(
                &origin,
                "code",
                "org-1",
                "net-1",
                uuid::Uuid::new_v4(),
                codewire_tailnet::wg::StaticSecret::random_from_rng(rand::rngs::OsRng),
                &platform,
            )
            .await
        }
    };
    // A plaintext Mesh origin is refused before anything is dialled.
    assert!(
        join("http://mesh.codewire.invalid".to_owned())
            .await
            .is_err()
    );
    assert!(dialled.lock().unwrap().is_empty());
    // An https origin is dialled at the configured Mesh address, never looked
    // up; this edge is not one Mesh trusts, so the join then fails.
    assert!(join(format!("https://{COORDINATOR_HOST}")).await.is_err());
    assert_eq!(*dialled.lock().unwrap(), [address]);
}

/// A hang guard, never a proof: a dial that waits on the stalled address
/// never returns, and fails here instead.
const DIAL_GUARD: Duration = Duration::from_secs(30);

/// An address in the IPv6 documentation range: its attempt below never
/// answers, as on a network whose IPv6 route drops SYNs.
fn stalled_v6() -> SocketAddr {
    "[2001:db8::1]:443".parse().unwrap()
}

/// #5120: a family whose connects stall doesn't hold the dial. The IPv6
/// address is tried first, as the resolver ranked it, and never answers; the
/// IPv4 one starts after the attempt delay and wins.
#[tokio::test]
async fn a_family_whose_connects_stall_does_not_hold_the_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4 = listener.local_addr().unwrap();
    let addresses = [stalled_v6(), v4];
    let stream = tokio::time::timeout(
        DIAL_GUARD,
        connect_racing_with(&addresses, CONNECTION_ATTEMPT_DELAY, |address| async move {
            if address.is_ipv6() {
                std::future::pending::<io::Result<tokio::net::TcpStream>>().await
            } else {
                tokio::net::TcpStream::connect(address).await
            }
        }),
    )
    .await
    .expect("the dial waited on the stalled IPv6 address")
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), v4);
}

/// A failed attempt starts the next address at once, without waiting out the
/// attempt delay, here an hour.
#[tokio::test]
async fn a_failed_attempt_starts_the_next_address_at_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4 = listener.local_addr().unwrap();
    let refused: SocketAddr = "[::1]:9".parse().unwrap();
    let stream = tokio::time::timeout(
        DIAL_GUARD,
        connect_racing_with(
            &[refused, v4],
            Duration::from_secs(3600),
            |address| async move {
                if address == refused {
                    Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                } else {
                    tokio::net::TcpStream::connect(address).await
                }
            },
        ),
    )
    .await
    .expect("the next address waited for the attempt delay")
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), v4);
}

/// Every address failing returns the last error; no address is an error too.
#[tokio::test]
async fn every_address_failing_returns_the_last_error() {
    let addresses: [SocketAddr; 2] = ["[::1]:9".parse().unwrap(), "127.0.0.1:9".parse().unwrap()];
    let tried = Arc::new(AtomicUsize::new(0));
    let error = connect_racing_with(&addresses, Duration::from_secs(3600), |address| {
        let tried = Arc::clone(&tried);
        async move {
            tried.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                address.to_string(),
            ))
        }
    })
    .await
    .unwrap_err();
    assert_eq!(tried.load(Ordering::SeqCst), 2);
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(error.to_string(), "127.0.0.1:9");
    let none = connect_racing_with(&[], CONNECTION_ATTEMPT_DELAY, |_| async { Ok(()) })
        .await
        .unwrap_err();
    assert_eq!(none.kind(), io::ErrorKind::InvalidInput);
}

/// The families alternate from the first address's family, each in the
/// resolver's order.
#[test]
fn addresses_alternate_families_from_the_first() {
    let a: SocketAddr = "[2001:db8::a]:443".parse().unwrap();
    let b: SocketAddr = "[2001:db8::b]:443".parse().unwrap();
    let c: SocketAddr = "[2001:db8::c]:443".parse().unwrap();
    let x: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let y: SocketAddr = "192.0.2.11:443".parse().unwrap();
    assert_eq!(interleaved(&[a, b, x, y]), [a, x, b, y]);
    assert_eq!(interleaved(&[x, a, b, c]), [x, a, b, c]);
    assert_eq!(interleaved(&[a, b, c, x]), [a, x, b, c]);
    assert_eq!(interleaved(&[x, y]), [x, y]);
    assert_eq!(interleaved(&[]), Vec::<SocketAddr>::new());
}
