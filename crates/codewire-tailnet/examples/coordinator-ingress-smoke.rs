//! Disposable KIND smoke for coordinator public gRPC, direct Connect, and
//! WebSocket ingress.
//!
//! Built only with the `kind-e2e` feature and never copied into a runtime
//! image. The checked-in KIND script supplies the URL, bearer fixture, UUID
//! environment, and DER-encoded trust anchor.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use codewire_tailnet::coordinator::Handlers;
use codewire_tailnet::coordinator_connect::{CoordinatorConnectClient, HelloIdentity};
use codewire_tailnet::node::{prefix_from_uuid, DiscoPublic, Node, NodePublic};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use uuid::Uuid;

const DEFAULT_URL: &str = "https://localhost:10443";
const DEFAULT_DIRECT_URL: &str = "http://127.0.0.1:18092";
const DEFAULT_ORG: &str = "org_contract_1";
const DEFAULT_ENVIRONMENT: &str = "00000000-0000-4000-8000-000000000501";
// Opaque OIDC product bearer for the fixed non-admin contract user. The Kind
// billing fixture stores only its digest alongside the `codewire.api` scope.
const DEFAULT_TOKEN: &str = "at_kind_connect_oidc_codewire_api";
// HMAC-SHA256 sidecar token for the fixed environment, scope=coordinate,
// signed with support.yaml's disposable SESSION_SECRET.
const DEFAULT_SIDECAR_TOKEN: &str = "eyJlbnZpcm9ubWVudF9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDUwMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.QgWM7yPYYatgrwWm5GpQ5COmBfEqjIInpqo-trLVS1w";

fn smoke_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn sample_node(id: Uuid, marker: u8) -> Node {
    Node {
        id,
        as_of: "2026-07-12T12:00:00Z".parse().expect("fixed timestamp"),
        key: NodePublic::from_raw([marker; 32]),
        disco_key: DiscoPublic::from_raw([marker.wrapping_add(1); 32]),
        preferred_derp: i32::from(marker),
        derp_latency: None,
        endpoints: vec![],
        addresses: vec![prefix_from_uuid(&id)],
    }
}

fn websocket_tls_config(
    certificate_der: Vec<u8>,
) -> Result<Arc<rustls::ClientConfig>, Box<dyn Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls_pki_types::CertificateDer::from(certificate_der))?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn next_text<S>(websocket: &mut S) -> Result<serde_json::Value, Box<dyn Error>>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), websocket.next())
            .await
            .map_err(|_| std::io::Error::other("WebSocket receive timed out"))?
            .ok_or_else(|| std::io::Error::other("WebSocket closed unexpectedly"))??;
        if let Message::Text(text) = message {
            return Ok(serde_json::from_str(text.as_str())?);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base_url = std::env::var("KIND_COORDINATOR_URL").unwrap_or_else(|_| DEFAULT_URL.into());
    let direct_url =
        std::env::var("KIND_COORDINATOR_DIRECT_URL").unwrap_or_else(|_| DEFAULT_DIRECT_URL.into());
    let certificate_path = std::env::var("KIND_COORDINATOR_CA_DER")
        .map_err(|_| std::io::Error::other("KIND_COORDINATOR_CA_DER is required"))?;
    let certificate_der = std::fs::read(certificate_path)?;
    let org_id = std::env::var("KIND_COORDINATOR_ORG").unwrap_or_else(|_| DEFAULT_ORG.into());
    let environment_id = std::env::var("KIND_COORDINATOR_ENVIRONMENT")
        .unwrap_or_else(|_| DEFAULT_ENVIRONMENT.into())
        .parse::<Uuid>()?;
    let bearer_token =
        std::env::var("KIND_COORDINATOR_TOKEN").unwrap_or_else(|_| DEFAULT_TOKEN.into());
    let sidecar_token = std::env::var("KIND_COORDINATOR_SIDECAR_TOKEN")
        .unwrap_or_else(|_| DEFAULT_SIDECAR_TOKEN.into());

    let mut direct_connect = CoordinatorConnectClient::connect(
        &direct_url,
        &sidecar_token,
        HelloIdentity::sidecar(environment_id),
    )
    .await?;
    let mut public_grpc = CoordinatorConnectClient::connect_for_kind_e2e_grpc(
        &base_url,
        &bearer_token,
        HelloIdentity::client(org_id.clone(), environment_id),
        certificate_der.clone(),
    )
    .await?;

    let mut direct_connect_derp = false;
    direct_connect
        .run_for_kind_e2e(
            Duration::from_millis(250),
            Handlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| direct_connect_derp = true,
            },
        )
        .await?;
    let mut public_grpc_derp = false;
    public_grpc
        .run_for_kind_e2e(
            Duration::from_millis(250),
            Handlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| public_grpc_derp = true,
            },
        )
        .await?;
    if !direct_connect_derp || !public_grpc_derp {
        return Err(smoke_error(
            "public gRPC and direct Connect hello streams must receive derp_map first",
        ));
    }

    public_grpc
        .update_node(&sample_node(Uuid::new_v4(), 0x21))
        .await?;
    let mut direct_connect_peer_count = 0;
    direct_connect
        .run_for_kind_e2e(
            Duration::from_secs(2),
            Handlers {
                on_peers: |peers: &[Node]| direct_connect_peer_count = peers.len(),
                on_derp_map: |_: &serde_json::Value| {},
            },
        )
        .await?;
    if direct_connect_peer_count != 1 {
        return Err(smoke_error(format!(
            "public gRPC node must produce one direct Connect peer_update, got {direct_connect_peer_count} peers"
        )));
    }

    direct_connect
        .update_node(&sample_node(environment_id, 0x31))
        .await?;
    let mut public_grpc_peer_count = 0;
    public_grpc
        .run_for_kind_e2e(
            Duration::from_secs(2),
            Handlers {
                on_peers: |peers: &[Node]| public_grpc_peer_count = peers.len(),
                on_derp_map: |_: &serde_json::Value| {},
            },
        )
        .await?;
    if public_grpc_peer_count != 1 {
        return Err(smoke_error(format!(
            "direct Connect node must produce one public gRPC peer_update, got {public_grpc_peer_count} peers"
        )));
    }

    let heartbeat_stats = public_grpc
        .run_for_kind_e2e(
            Duration::from_secs(65),
            Handlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| {},
            },
        )
        .await?;
    if heartbeat_stats.sent < 4 || heartbeat_stats.received < 4 {
        return Err(smoke_error(format!(
            "typed heartbeat DATA did not cross the idle stream: {heartbeat_stats:?}"
        )));
    }

    let websocket_url = format!(
        "{}/api/v1/organizations/{org_id}/environments/{environment_id}/coordinate",
        base_url.replacen("https://", "wss://", 1)
    );
    let mut request = websocket_url.into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {bearer_token}"))?,
    );
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("coordinate"),
    );
    let connector = Connector::Rustls(websocket_tls_config(certificate_der)?);
    let (mut websocket, response) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, true, Some(connector))
            .await?;
    if response.status().as_u16() != 101 {
        return Err(smoke_error(format!(
            "WebSocket upgrade returned {}",
            response.status()
        )));
    }
    let websocket_derp = next_text(&mut websocket).await?;
    if websocket_derp.get("type").and_then(|value| value.as_str()) != Some("derp_map") {
        return Err(smoke_error(format!(
            "WebSocket first message was not derp_map: {websocket_derp}"
        )));
    }

    direct_connect
        .update_node(&sample_node(environment_id, 0x32))
        .await?;
    let websocket_update = next_text(&mut websocket).await?;
    if websocket_update
        .get("type")
        .and_then(|value| value.as_str())
        != Some("peer_update")
    {
        return Err(smoke_error(format!(
            "WebSocket did not receive the direct Connect peer update: {websocket_update}"
        )));
    }

    let websocket_node = sample_node(Uuid::new_v4(), 0x41);
    websocket
        .send(Message::Text(
            serde_json::json!({"type": "node", "node": websocket_node})
                .to_string()
                .into(),
        ))
        .await?;
    let mut mixed_peer_count = direct_connect_peer_count;
    direct_connect
        .run_for_kind_e2e(
            Duration::from_secs(2),
            Handlers {
                on_peers: |peers: &[Node]| mixed_peer_count = peers.len(),
                on_derp_map: |_: &serde_json::Value| {},
            },
        )
        .await?;
    if mixed_peer_count < 2 {
        return Err(smoke_error(format!(
            "direct Connect sidecar did not receive the WebSocket peer update, got {mixed_peer_count} peers"
        )));
    }
    websocket.close(None).await?;

    tokio::time::timeout(Duration::from_secs(10), public_grpc.finish_for_kind_e2e())
        .await
        .map_err(|_| std::io::Error::other("public gRPC stream did not close cleanly"))??;
    tokio::time::timeout(
        Duration::from_secs(10),
        direct_connect.finish_for_kind_e2e(),
    )
    .await
    .map_err(|_| std::io::Error::other("direct Connect stream did not close cleanly"))??;

    println!(
        "coordinator-ingress-smoke: public gRPC + direct-h2c Connect hello -> derp_map -> bidirectional node/peer_update; public gRPC typed heartbeat DATA sent={} received={} across 65s idle; WebSocket exchange; clean close: OK",
        heartbeat_stats.sent, heartbeat_stats.received
    );
    Ok(())
}
