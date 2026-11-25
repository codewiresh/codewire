use std::net::Ipv4Addr;

use hyper_util::client::legacy::connect::HttpConnector;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};
use tokio::net::TcpListener;

use super::*;

#[test]
fn the_preference_list_keeps_its_order_and_refuses_bad_entries() {
    assert!(PreferredApiServers::parse("").unwrap().is_empty());
    assert_eq!(
        PreferredApiServers::parse(" 192.0.2.2:6443, 192.0.2.1:6443 ").unwrap(),
        PreferredApiServers(vec![
            "192.0.2.2:6443".parse().unwrap(),
            "192.0.2.1:6443".parse().unwrap()
        ])
    );
    assert_eq!(
        PreferredApiServers::parse("api.example.test:6443"),
        Err(PreferredAddrsError::Invalid("api.example.test:6443".into()))
    );
    assert_eq!(
        PreferredApiServers::parse("192.0.2.1"),
        Err(PreferredAddrsError::Invalid("192.0.2.1".into()))
    );
    assert_eq!(
        PreferredApiServers::parse("192.0.2.1:6443,192.0.2.1:6443"),
        Err(PreferredAddrsError::Duplicate(
            "192.0.2.1:6443".parse().unwrap()
        ))
    );
}

#[test]
fn only_endpoints_not_marked_unready_count() {
    let endpoint = |address: &str, ready: Option<bool>| Endpoint {
        addresses: vec![address.into()],
        conditions: Some(EndpointConditions {
            ready,
            ..Default::default()
        }),
        ..Default::default()
    };
    let slice = EndpointSlice {
        endpoints: Some(vec![
            endpoint("192.0.2.1", Some(true)),
            endpoint("192.0.2.2", None),
            endpoint("192.0.2.3", Some(false)),
        ]),
        ..Default::default()
    };
    // k8s-openapi 0.28 makes the list optional: an absent one has no address.
    assert!(ready_addresses(&EndpointSlice::default()).is_empty());
    let ready = ready_addresses(&slice);
    assert_eq!(ready.len(), 2);
    assert!(ready.contains(&"192.0.2.1".parse().unwrap()));
    assert!(ready.contains(&"192.0.2.2".parse().unwrap()));
}

/// A dialer whose connect bound is a hang guard, not the product's 2 s: on a
/// loaded runner a slow connect must not read as a down server.
fn dialer(preferred: PreferredApiServers) -> PreferredDialer {
    PreferredDialer::with_connect_timeout(preferred, Duration::from_secs(30))
}

/// A loopback listener standing in for one API server or the Service. The
/// kernel completes a connection to it without an accept, so it only has to
/// stay bound.
async fn listener(ip: Ipv4Addr) -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// A loopback address nothing listens on, so a connect is refused at once.
async fn refused(ip: Ipv4Addr) -> SocketAddr {
    let (listener, addr) = listener(ip).await;
    drop(listener);
    addr
}

/// Where a connection for the Service at `service` lands, by its peer address.
async fn connects_to(dialer: &PreferredDialer, service: SocketAddr) -> SocketAddr {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let stream = dialer
        .wrap(http)
        .call(format!("http://{service}/").parse().unwrap())
        .await
        .unwrap();
    stream.inner().peer_addr().unwrap()
}

#[tokio::test]
async fn new_connections_go_to_the_first_ready_near_server() {
    let (_first, first) = listener(Ipv4Addr::new(127, 0, 0, 1)).await;
    let (_second, second) = listener(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_service, service) = listener(Ipv4Addr::LOCALHOST).await;
    let dialer = dialer(PreferredApiServers(vec![first, second]));

    // Before the first EndpointSlice read, the first preferred server.
    assert_eq!(connects_to(&dialer, service).await, first);
    // The slice lists only the second as ready.
    dialer.state.set_ready(HashSet::from([second.ip()]));
    assert_eq!(connects_to(&dialer, service).await, second);
    // Neither is ready: the Service, as without a preference.
    dialer.state.set_ready(HashSet::new());
    assert_eq!(connects_to(&dialer, service).await, service);
}

#[tokio::test]
async fn a_failed_connect_moves_on_and_skips_that_server_for_a_while() {
    let down = refused(Ipv4Addr::new(127, 0, 0, 1)).await;
    let (_second, second) = listener(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_service, service) = listener(Ipv4Addr::LOCALHOST).await;
    let dialer = dialer(PreferredApiServers(vec![down, second]));

    assert_eq!(connects_to(&dialer, service).await, second);
    let now = Instant::now();
    assert_eq!(dialer.state.candidates(now), [second]);
    assert_eq!(dialer.state.candidates(now + DOWN_FOR), [down, second]);
}

#[tokio::test]
async fn with_both_near_servers_down_the_service_is_dialed() {
    let first = refused(Ipv4Addr::new(127, 0, 0, 1)).await;
    let second = refused(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_service, service) = listener(Ipv4Addr::LOCALHOST).await;
    let dialer = dialer(PreferredApiServers(vec![first, second]));

    assert_eq!(connects_to(&dialer, service).await, service);
    assert!(dialer.state.candidates(Instant::now()).is_empty());
}

#[tokio::test]
async fn without_a_preference_every_connection_dials_the_service() {
    let (_service, service) = listener(Ipv4Addr::LOCALHOST).await;
    let dialer = dialer(PreferredApiServers::default());
    assert_eq!(connects_to(&dialer, service).await, service);
}

/// TLS through the dialer verifies the Service's name, never the address it
/// dialed (#2238): the server is reachable only at the preferred address, and
/// the request URI names the Service, as in-cluster.
mod tls {
    use axum::{Router, routing::get};
    use base64::Engine as _;
    use codewire_tls::test_support::SyntheticPki;

    use super::*;

    const SERVICE: &str = "kubernetes.default.svc";

    /// The DER certificates in a PEM roots file, as kube's `root_cert` takes them.
    fn der_roots(pki: &SyntheticPki) -> Vec<Vec<u8>> {
        let pem = std::fs::read_to_string(&pki.roots).unwrap();
        pem.split("-----BEGIN CERTIFICATE-----")
            .skip(1)
            .map(|block| {
                let body: String = block
                    .split("-----END CERTIFICATE-----")
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .collect();
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .unwrap()
            })
            .collect()
    }

    async fn serve(server: &SyntheticPki) -> SocketAddr {
        server
            .serve(Router::new().route("/version", get(|| async { "{}" })))
            .await
    }

    /// `GET /version` through `dialer`, trusting `trusted`'s CA. The Service
    /// is the loopback server on `port`, verified as the Service's name: a
    /// fallback past every preferred server then fails on the same TLS check
    /// at once, rather than waiting out kube's 30 s connect timeout on a name
    /// no test resolves.
    async fn version_via(
        dialer: &PreferredDialer,
        port: u16,
        trusted: &SyntheticPki,
    ) -> kube::Result<String> {
        let mut config = kube::Config::new(format!("https://127.0.0.1:{port}").parse().unwrap());
        config.tls_server_name = Some(SERVICE.to_owned());
        config.root_cert = Some(der_roots(trusted));
        let client = crate::span_free::kube_client_dialing(config, dialer.clone())?;
        client
            .request_text(http::Request::get("/version").body(Vec::new()).unwrap())
            .await
    }

    /// `GET /version` from a server holding `server`'s identity, trusting
    /// `trusted`'s CA, through the near-API-server dialer.
    async fn version(server: &SyntheticPki, trusted: &SyntheticPki) -> kube::Result<String> {
        let addr = serve(server).await;
        let dialer = dialer(PreferredApiServers(vec![addr]));
        version_via(&dialer, addr.port(), trusted).await
    }

    #[tokio::test]
    async fn a_certificate_for_the_service_name_from_the_trusted_ca_passes() {
        let pki = SyntheticPki::new(SERVICE);
        assert_eq!(version(&pki, &pki).await.unwrap(), "{}");
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_from_the_same_ca_fails() {
        let pki = SyntheticPki::new("other.default.svc");
        assert!(version(&pki, &pki).await.is_err());
    }

    #[tokio::test]
    async fn the_service_name_from_another_ca_fails() {
        let server = SyntheticPki::new(SERVICE);
        let other = SyntheticPki::new(SERVICE);
        assert!(version(&server, &other).await.is_err());
    }

    /// A preferred server that completes TCP but fails TLS is skipped like a
    /// refused one, and the connection reaches the next.
    #[tokio::test]
    async fn a_server_that_fails_tls_is_skipped_and_the_next_is_used() {
        let trusted = SyntheticPki::new(SERVICE);
        let untrusted = SyntheticPki::new(SERVICE);
        let bad = serve(&untrusted).await;
        let good = serve(&trusted).await;
        let dialer = dialer(PreferredApiServers(vec![bad, good]));

        assert_eq!(
            version_via(&dialer, good.port(), &trusted).await.unwrap(),
            "{}"
        );
        assert_eq!(dialer.state.candidates(Instant::now()), [good]);
    }
}
