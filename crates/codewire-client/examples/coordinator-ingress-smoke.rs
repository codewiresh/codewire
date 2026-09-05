//! Disposable KIND smoke for the generated primary coordinator service.
//!
//! Built only with the `kind-e2e` feature and never copied into a runtime
//! image. The checked-in KIND script supplies the service origins, bearer
//! fixtures, environment identity, and DER-encoded trust anchor.

use std::error::Error;
use std::time::Duration;

use codewire_client::{
    CoordinatorHandlers, CoordinatorPeerSession, MeshCoordinateIdentity,
    MeshCoordinatorPeerSession, PrimaryCoordinateIdentity,
};
use codewire_tailnet::node::{DiscoPublic, Node, NodePublic, prefix_from_uuid};
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
const DEFAULT_MESH_NETWORK: &str = "mesh-kind-owned";
const DEFAULT_MESH_API_KEY: &str =
    "cw_c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de";
const DEFAULT_RETIRED_MESH_ENVIRONMENT_TOKEN: &str = "mesh-kind-environment-token";

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

async fn direct_binding_probe(
    direct_url: &str,
    environment_id: Uuid,
    sidecar_token: &str,
) -> Result<(), Box<dyn Error>> {
    let mut session = CoordinatorPeerSession::connect(
        direct_url,
        sidecar_token,
        PrimaryCoordinateIdentity::sidecar(environment_id),
    )
    .await?;
    let mut received_derp = false;
    session
        .run_for_kind_e2e(
            Duration::from_millis(250),
            CoordinatorHandlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| received_derp = true,
            },
        )
        .await?;
    if !received_derp {
        return Err(smoke_error(
            "direct typed coordinator setup did not receive derp_map",
        ));
    }
    tokio::time::timeout(Duration::from_secs(10), session.finish_for_kind_e2e())
        .await
        .map_err(|_| std::io::Error::other("direct probe stream did not close cleanly"))??;
    println!("coordinator-ingress-smoke: direct binding token accepted: OK");
    Ok(())
}

async fn mesh_coordinate_probe(
    base_url: &str,
    certificate_der: Vec<u8>,
    org_id: &str,
) -> Result<(), Box<dyn Error>> {
    let network_id = std::env::var("KIND_MESH_COORDINATOR_NETWORK")
        .unwrap_or_else(|_| DEFAULT_MESH_NETWORK.into());
    let api_key = std::env::var("KIND_MESH_COORDINATOR_API_KEY")
        .unwrap_or_else(|_| DEFAULT_MESH_API_KEY.into());
    let retired_environment_token =
        std::env::var("KIND_MESH_COORDINATOR_RETIRED_ENVIRONMENT_TOKEN")
            .unwrap_or_else(|_| DEFAULT_RETIRED_MESH_ENVIRONMENT_TOKEN.into());
    let retired_environment = MeshCoordinatorPeerSession::connect_for_kind_e2e_grpc(
        base_url,
        &retired_environment_token,
        MeshCoordinateIdentity::peer(org_id, &network_id),
        certificate_der.clone(),
    )
    .await;
    if retired_environment.is_ok() {
        return Err(smoke_error(
            "Mesh accepted the retired raw platform environment bearer",
        ));
    }

    let mut dial = MeshCoordinatorPeerSession::connect_for_kind_e2e_grpc(
        base_url,
        &api_key,
        MeshCoordinateIdentity::dial(org_id, &network_id),
        certificate_der,
    )
    .await?;

    let mut dial_derp = false;
    dial.run_for_kind_e2e(
        Duration::from_millis(250),
        CoordinatorHandlers {
            on_peers: |_: &[Node]| {},
            on_derp_map: |_: &serde_json::Value| dial_derp = true,
        },
    )
    .await?;
    if !dial_derp {
        return Err(smoke_error("Mesh API-key dial must receive derp_map first"));
    }

    let heartbeat_stats = dial
        .run_for_kind_e2e(
            Duration::from_secs(16),
            CoordinatorHandlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| {},
            },
        )
        .await?;
    if heartbeat_stats.sent < 1 || heartbeat_stats.received < 1 {
        return Err(smoke_error(format!(
            "Mesh typed heartbeat DATA did not cross the idle stream: {heartbeat_stats:?}"
        )));
    }

    tokio::time::timeout(Duration::from_secs(10), dial.finish_for_kind_e2e())
        .await
        .map_err(|_| std::io::Error::other("Mesh dial stream did not close cleanly"))??;

    println!(
        "coordinator-ingress-smoke: Mesh rejected the retired raw environment bearer; API-key dial heartbeat DATA sent={} received={}: OK",
        heartbeat_stats.sent, heartbeat_stats.received
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base_url = std::env::var("KIND_COORDINATOR_URL").unwrap_or_else(|_| DEFAULT_URL.into());
    let direct_url =
        std::env::var("KIND_COORDINATOR_DIRECT_URL").unwrap_or_else(|_| DEFAULT_DIRECT_URL.into());
    let org_id = std::env::var("KIND_COORDINATOR_ORG").unwrap_or_else(|_| DEFAULT_ORG.into());
    let environment_id = std::env::var("KIND_COORDINATOR_ENVIRONMENT")
        .unwrap_or_else(|_| DEFAULT_ENVIRONMENT.into())
        .parse::<Uuid>()?;
    let bearer_token =
        std::env::var("KIND_COORDINATOR_TOKEN").unwrap_or_else(|_| DEFAULT_TOKEN.into());
    let sidecar_token = std::env::var("KIND_COORDINATOR_SIDECAR_TOKEN")
        .unwrap_or_else(|_| DEFAULT_SIDECAR_TOKEN.into());

    if std::env::var("KIND_COORDINATOR_BINDING_PROBE").as_deref() == Ok("1") {
        return direct_binding_probe(&direct_url, environment_id, &sidecar_token).await;
    }

    let certificate_path = std::env::var("KIND_COORDINATOR_CA_DER")
        .map_err(|_| std::io::Error::other("KIND_COORDINATOR_CA_DER is required"))?;
    let certificate_der = std::fs::read(certificate_path)?;
    let mut direct_connect = CoordinatorPeerSession::connect(
        &direct_url,
        &sidecar_token,
        PrimaryCoordinateIdentity::sidecar(environment_id),
    )
    .await?;
    let mut public_grpc = CoordinatorPeerSession::connect_for_kind_e2e_grpc(
        &base_url,
        &bearer_token,
        PrimaryCoordinateIdentity::client(&org_id, environment_id),
        certificate_der.clone(),
    )
    .await?;

    let mut direct_connect_derp = false;
    direct_connect
        .run_for_kind_e2e(
            Duration::from_millis(250),
            CoordinatorHandlers {
                on_peers: |_: &[Node]| {},
                on_derp_map: |_: &serde_json::Value| direct_connect_derp = true,
            },
        )
        .await?;
    let mut public_grpc_derp = false;
    public_grpc
        .run_for_kind_e2e(
            Duration::from_millis(250),
            CoordinatorHandlers {
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
            CoordinatorHandlers {
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
            CoordinatorHandlers {
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
            CoordinatorHandlers {
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

    tokio::time::timeout(Duration::from_secs(10), public_grpc.finish_for_kind_e2e())
        .await
        .map_err(|_| std::io::Error::other("public gRPC stream did not close cleanly"))??;
    tokio::time::timeout(
        Duration::from_secs(10),
        direct_connect.finish_for_kind_e2e(),
    )
    .await
    .map_err(|_| std::io::Error::other("direct Connect stream did not close cleanly"))??;

    mesh_coordinate_probe(&base_url, certificate_der, &org_id).await?;

    println!(
        "coordinator-ingress-smoke: public gRPC + direct-h2c generated service hello -> derp_map -> bidirectional node/peer_update; public gRPC typed heartbeat DATA sent={} received={} across 65s idle; clean close: OK",
        heartbeat_stats.sent, heartbeat_stats.received
    );
    Ok(())
}
