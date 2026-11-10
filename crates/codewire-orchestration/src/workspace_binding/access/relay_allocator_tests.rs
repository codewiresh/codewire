//! The relay allocator client against a relay that asks for a client
//! certificate, as `codewire-udp-relay` does on its TLS listener (#4011).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Bytes;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::routing::post;
use axum::{Json, Router};
use codewire_tls::test_support::SyntheticPki;
use codewire_tls::{PeerTlsListener, TlsPeer};
use serde_json::{Value, json};

use super::*;

const ORCHESTRATION: &str = "orchestration.udp-relay-allocator.codewire.internal";

fn request() -> RelayAllocationRequest {
    RelayAllocationRequest {
        client_disco: ["discokey:11".into(), "discokey:22".into()],
        generation: 7,
    }
}

/// The generation of an allocation request body.
fn generation(body: &[u8]) -> u32 {
    serde_json::from_slice::<Value>(body).unwrap()["generation"]
        .as_u64()
        .unwrap() as u32
}

fn allocation(generation: u32) -> Value {
    json!({
        "generation": generation,
        "endpoint": {
            "server_disco": "discokey:ee",
            "client_disco": ["discokey:11", "discokey:22"],
            "lamport_id": 1,
            "vni": 1,
            "bind_lifetime_ns": 1,
            "steady_state_lifetime_ns": 1,
            "addr_ports": ["203.0.113.10:41641"],
        }
    })
}

/// A relay allocator that allocates only for orchestration's certificate and
/// counts the bearer tokens it was sent. It answers every path, so this
/// service's sources register no allocator route of their own.
struct Relay {
    pki: SyntheticPki,
    url: String,
    bearers: Arc<AtomicUsize>,
}

impl Relay {
    async fn start() -> Self {
        let pki = SyntheticPki::new("localhost");
        let bearers = Arc::new(AtomicUsize::new(0));
        let seen = bearers.clone();
        let app =
            Router::new().fallback(post(
                    move |ConnectInfo(peer): ConnectInfo<TlsPeer>,
                          headers: HeaderMap,
                          body: Bytes| async move {
                        if headers.contains_key(AUTHORIZATION) {
                            seen.fetch_add(1, Ordering::SeqCst);
                        }
                        if peer
                            .client
                            .is_some_and(|client| client.is_named(ORCHESTRATION))
                        {
                            Ok(Json(allocation(generation(&body))))
                        } else {
                            Err(StatusCode::UNAUTHORIZED)
                        }
                    },
                ),
            );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let files = pki
            .files
            .clone()
            .with_client_roots(pki.roots.clone())
            .unwrap();
        let listener = PeerTlsListener::new(socket, files).unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<TlsPeer>(),
            )
            .await;
        });
        Self {
            pki,
            url: format!("https://localhost:{port}/internal/udp-relay/allocations"),
            bearers,
        }
    }

    fn client(&self, name: &str) -> HttpRelayAllocator {
        let (cert_chain, key) = self.pki.client_identity(name);
        HttpRelayAllocator::new(Some("allocator-token".into())).with_tls(RelayAllocatorTls {
            roots: self.pki.roots.clone(),
            cert_chain,
            key,
        })
    }
}

#[tokio::test]
async fn an_https_allocator_is_called_with_orchestrations_certificate_and_no_token() {
    let relay = Relay::start().await;
    let allocation = relay
        .client(ORCHESTRATION)
        .allocate(&relay.url, &request())
        .await
        .unwrap();
    assert_eq!(allocation.generation, 7);
    assert_eq!(allocation.endpoint.addr_ports, ["203.0.113.10:41641"]);
    // The static token belongs to the plain listener only.
    assert_eq!(relay.bearers.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_relay_that_does_not_know_the_certificate_refuses() {
    let relay = Relay::start().await;
    assert_eq!(
        relay
            .client("mesh.udp-relay-allocator.codewire.internal")
            .allocate(&relay.url, &request())
            .await,
        Err(RelayError::Refused)
    );
}

#[tokio::test]
async fn an_https_allocator_is_never_called_without_the_certificate_or_verified_roots() {
    let relay = Relay::start().await;
    // No client certificate configured: not attempted anonymously.
    assert_eq!(
        HttpRelayAllocator::new(Some("allocator-token".into()))
            .allocate(&relay.url, &request())
            .await,
        Err(RelayError::Unavailable)
    );

    // Roots that did not sign the relay's leaf.
    let other = SyntheticPki::new("localhost");
    let (cert_chain, key) = relay.pki.client_identity(ORCHESTRATION);
    let untrusting = HttpRelayAllocator::new(None).with_tls(RelayAllocatorTls {
        roots: other.roots.clone(),
        cert_chain: cert_chain.clone(),
        key,
    });
    assert_eq!(
        untrusting.allocate(&relay.url, &request()).await,
        Err(RelayError::Unavailable)
    );

    // A key file that is missing when the allocation is made.
    let missing = HttpRelayAllocator::new(None).with_tls(RelayAllocatorTls {
        roots: relay.pki.roots.clone(),
        cert_chain,
        key: relay.pki.roots.with_file_name("absent.key"),
    });
    assert_eq!(
        missing.allocate(&relay.url, &request()).await,
        Err(RelayError::Unavailable)
    );
    assert_eq!(relay.bearers.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_plain_allocator_is_still_called_with_the_token() {
    let bearer = Arc::new(std::sync::Mutex::new(None::<String>));
    let seen = bearer.clone();
    let app = Router::new().fallback(post(move |headers: HeaderMap, body: Bytes| async move {
        *seen.lock().unwrap() = headers
            .get(AUTHORIZATION)
            .map(|value| value.to_str().unwrap().to_owned());
        Json(allocation(generation(&body)))
    }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/internal/udp-relay/allocations",
        socket.local_addr().unwrap().port()
    );
    tokio::spawn(async move {
        let _ = axum::serve(socket, app).await;
    });
    let allocation = HttpRelayAllocator::new(Some(" allocator-token ".into()))
        .allocate(&url, &request())
        .await
        .unwrap();
    assert_eq!(allocation.generation, 7);
    assert_eq!(
        bearer.lock().unwrap().as_deref(),
        Some("Bearer allocator-token")
    );
}

#[tokio::test]
async fn an_https_allocator_url_with_credentials_or_a_redirect_goes_nowhere_else() {
    let relay = Relay::start().await;
    let client = relay.client(ORCHESTRATION);
    let with_credentials = relay.url.replace("https://", "https://user:secret@");
    assert_eq!(
        client.allocate(&with_credentials, &request()).await,
        Err(RelayError::Unavailable)
    );

    // A relay with the same trusted identity that redirects to the real one:
    // the redirect is not followed, so nothing is allocated.
    let target = relay.url.clone();
    let app = Router::new().fallback(post(move || {
        let target = target.clone();
        async move { axum::response::Redirect::temporary(&target) }
    }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let files = relay
        .pki
        .files
        .clone()
        .with_client_roots(relay.pki.roots.clone())
        .unwrap();
    let listener = PeerTlsListener::new(socket, files).unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<TlsPeer>(),
        )
        .await;
    });
    let redirecting = format!("https://localhost:{port}/internal/udp-relay/allocations");
    assert_eq!(
        client.allocate(&redirecting, &request()).await,
        Err(RelayError::Unavailable)
    );
}
