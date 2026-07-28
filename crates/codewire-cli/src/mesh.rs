use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use codewire_client as rpc;
use serde::Serialize;

use crate::CLI_VERSION;
use crate::config::ResolvedMeshConfig;

/// Thin CLI presentation adapter over the repository's one generated Rust
/// client façade. It owns no Mesh URL construction, HTTP policy, or auth.
#[derive(Clone)]
pub struct MeshClient {
    inner: rpc::CodewireClient,
}

impl MeshClient {
    pub fn new(config: &ResolvedMeshConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::new();
        Self::with_http(config, http)
    }

    pub fn with_http(config: &ResolvedMeshConfig, http: reqwest::Client) -> anyhow::Result<Self> {
        let client_config = rpc::ClientConfig::new(&config.mesh_url)?
            .with_mesh_url(&config.mesh_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
        Ok(Self {
            inner: rpc::CodewireClient::with_http_token_provider(
                client_config,
                config.token_provider(),
                http,
            )?,
        })
    }

    pub fn unauthenticated(base_url: &str) -> anyhow::Result<Self> {
        let client_config = rpc::ClientConfig::new(base_url)?
            .with_mesh_url(base_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
        Ok(Self {
            inner: rpc::CodewireClient::new(
                client_config,
                rpc::StaticTokenProvider::new("unused-enrollment-redemption")?,
            )?,
        })
    }

    pub async fn list_networks(&self, org_id: &str) -> anyhow::Result<Vec<Network>> {
        let response = self
            .inner
            .list_mesh_networks(rpc::ListMeshNetworksRequest {
                org_id: org_id.to_string(),
                ..Default::default()
            })
            .await?;
        Ok(response.networks.into_iter().map(network).collect())
    }

    pub async fn create_network(&self, org_id: &str, network_id: &str) -> anyhow::Result<()> {
        self.inner
            .create_mesh_network(rpc::CreateMeshNetworkRequest {
                org_id: org_id.to_string(),
                network_id: network_id.to_string(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    pub async fn list_nodes(
        &self,
        org_id: &str,
        network_id: Option<&str>,
        all: bool,
    ) -> anyhow::Result<Vec<Node>> {
        let response = self
            .inner
            .list_mesh_nodes(rpc::ListMeshNodesRequest {
                org_id: org_id.to_string(),
                network_id: if all {
                    String::new()
                } else {
                    network_id.unwrap_or_default().to_string()
                },
                ..Default::default()
            })
            .await?;
        Ok(response.nodes.into_iter().map(node).collect())
    }

    pub async fn create_invite(
        &self,
        org_id: &str,
        network_id: &str,
        ttl: &str,
    ) -> anyhow::Result<Invite> {
        let response = self
            .inner
            .create_mesh_invite(rpc::CreateMeshInviteRequest {
                org_id: org_id.to_string(),
                network_id: network_id.to_string(),
                ttl: Some(proto_ttl(ttl)?).into(),
                ..Default::default()
            })
            .await?;
        let invite = response
            .invite
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("CreateMeshInvite returned no invite"))?;
        Ok(created_invite(invite, response.invite_code))
    }

    pub async fn join_network(&self, invite_code: &str) -> anyhow::Result<NetworkJoin> {
        let response = self
            .inner
            .join_mesh_network(rpc::JoinMeshNetworkRequest {
                invite_code: invite_code.to_string(),
                ..Default::default()
            })
            .await?;
        let network = response
            .network
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("JoinMeshNetwork returned no network"))?;
        Ok(NetworkJoin {
            network_id: network.id,
        })
    }

    pub async fn revoke_node(
        &self,
        org_id: &str,
        network_id: &str,
        node_name: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .revoke_mesh_node(rpc::RevokeMeshNodeRequest {
                org_id: org_id.to_string(),
                network_id: network_id.to_string(),
                node_name: node_name.to_string(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    pub async fn create_node_enrollment(
        &self,
        org_id: &str,
        network_id: &str,
        node_name: &str,
        ttl: &str,
    ) -> anyhow::Result<NodeEnrollment> {
        let response = self
            .inner
            .create_mesh_node_enrollment(rpc::CreateMeshNodeEnrollmentRequest {
                org_id: org_id.to_string(),
                network_id: network_id.to_string(),
                node_name: node_name.to_string(),
                ttl: Some(proto_ttl(ttl)?).into(),
                ..Default::default()
            })
            .await?;
        let enrollment = response
            .enrollment
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("CreateMeshNodeEnrollment returned no enrollment"))?;
        Ok(created_enrollment(enrollment, response.enrollment_code))
    }

    pub async fn redeem_node_enrollment(
        &self,
        enrollment_code: &str,
        node_name: &str,
    ) -> anyhow::Result<RedeemedNodeEnrollment> {
        let redeemed = self
            .inner
            .redeem_transitional_mesh_node_enrollment(enrollment_code, node_name)
            .await?;
        Ok(RedeemedNodeEnrollment {
            status: redeemed.status,
            node_token: redeemed.node_token,
            node_name: redeemed.node_name,
            network_id: redeemed.network_id,
            enrollment_id: redeemed.enrollment_id,
        })
    }
}

fn proto_ttl(raw: &str) -> anyhow::Result<rpc::ProtoDuration> {
    let seconds = crate::commands::parse_go_duration_seconds(raw)
        .with_context(|| format!("invalid Mesh TTL {raw:?}"))?;
    Ok(rpc::ProtoDuration::from_secs(i64::from(seconds)))
}

fn network(value: rpc::MeshNetwork) -> Network {
    Network {
        id: value.id,
        org_id: value.org_id,
        created_at: timestamp(value.created_at.into_option()),
        node_count: value.node_count,
        invite_count: value.invite_count,
    }
}

fn node(value: rpc::MeshNode) -> Node {
    Node {
        network_id: value.network_id,
        name: value.name,
        peer_url: value.peer_url,
        connected: value.connected,
    }
}

fn created_invite(value: rpc::MeshInvite, invite_code: String) -> Invite {
    Invite {
        id: value.id,
        org_id: value.org_id,
        network_id: value.network_id,
        created_by_user_id: value.created_by_user_id,
        invite_code,
        expires_at: timestamp(value.expires_at.into_option()),
        created_at: timestamp(value.created_at.into_option()),
    }
}

fn created_enrollment(value: rpc::MeshNodeEnrollment, enrollment_code: String) -> NodeEnrollment {
    NodeEnrollment {
        id: value.id,
        org_id: value.org_id,
        network_id: value.network_id,
        node_name: value.node_name,
        owner_user_id: value.owner_user_id,
        issued_by_user_id: value.issued_by_user_id,
        enrollment_code,
        expires_at: timestamp(value.expires_at.into_option()),
        created_at: timestamp(value.created_at.into_option()),
        redeemed_at: timestamp(value.redeemed_at.into_option()),
    }
}

fn timestamp(value: Option<rpc::Timestamp>) -> String {
    value
        .and_then(|value| {
            let nanos = u32::try_from(value.nanos).ok()?;
            chrono::DateTime::<Utc>::from_timestamp(value.seconds, nanos)
        })
        .map(|value| value.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .unwrap_or_default()
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub org_id: String,
    pub created_at: String,
    pub node_count: i64,
    pub invite_count: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Node {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_url: String,
    pub connected: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Invite {
    pub id: String,
    pub org_id: String,
    pub network_id: String,
    pub created_by_user_id: String,
    pub invite_code: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NetworkJoin {
    pub network_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NodeEnrollment {
    pub id: String,
    pub org_id: String,
    pub network_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_name: String,
    pub owner_user_id: String,
    pub issued_by_user_id: String,
    pub enrollment_code: String,
    pub expires_at: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub redeemed_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemedNodeEnrollment {
    pub status: String,
    pub node_token: String,
    pub node_name: String,
    pub network_id: String,
    pub enrollment_id: String,
}

#[cfg(test)]
mod tests {
    use buffa::Message as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::{
        CODEWIRE_MESH_AUTH_TOKEN_ENV, CODEWIRE_MESH_URL_ENV, MapEnv, MeshResolveOptions,
        ResolvePaths,
    };

    fn resolved(base_url: &str, token: &str) -> ResolvedMeshConfig {
        let home = tempfile::tempdir().expect("temp home");
        let env = MapEnv::new([
            (CODEWIRE_MESH_URL_ENV, base_url),
            (CODEWIRE_MESH_AUTH_TOKEN_ENV, token),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        crate::config::resolve_mesh(MeshResolveOptions::default(), &paths, &env)
            .expect("resolved Mesh")
    }

    #[tokio::test]
    async fn generated_mesh_network_call_uses_mesh_origin_and_canonical_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNetworkService/ListMeshNetworks"))
            .and(header("authorization", "Bearer cw_exact_org_key"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::ListMeshNetworksRequest::decode(&mut body)
                    .expect("decode list networks request");
                assert_eq!(request.org_id, "org-alpha");
                let response = rpc::ListMeshNetworksResponse {
                    networks: vec![rpc::MeshNetwork {
                        id: "project-alpha".into(),
                        org_id: "org-alpha".into(),
                        node_count: 2,
                        invite_count: 1,
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;

        let client =
            MeshClient::new(&resolved(&server.uri(), "cw_exact_org_key")).expect("Mesh client");
        let networks = client.list_networks("org-alpha").await.expect("list");
        assert_eq!(networks[0].id, "project-alpha");
        assert_eq!(networks[0].org_id, "org-alpha");
    }

    #[tokio::test]
    async fn generated_mesh_calls_preserve_published_request_and_output_shapes() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNetworkService/CreateMeshNetwork"))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::CreateMeshNetworkRequest::decode(&mut body)
                    .expect("decode create network request");
                assert_eq!(request.org_id, "org-alpha");
                assert_eq!(request.network_id, "project-alpha");
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(rpc::CreateMeshNetworkResponse::default().encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNetworkService/JoinMeshNetwork"))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::JoinMeshNetworkRequest::decode(&mut body)
                    .expect("decode join network request");
                assert_eq!(request.invite_code, "cw_inv_secret");
                let response = rpc::JoinMeshNetworkResponse {
                    network: Some(rpc::MeshNetwork {
                        id: "project-alpha".into(),
                        org_id: "org-alpha".into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNodeService/ListMeshNodes"))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::ListMeshNodesRequest::decode(&mut body)
                    .expect("decode list nodes request");
                assert_eq!(request.org_id, "org-alpha");
                assert_eq!(request.network_id, "project-alpha");
                let response = rpc::ListMeshNodesResponse {
                    nodes: vec![rpc::MeshNode {
                        org_id: "org-alpha".into(),
                        network_id: "project-alpha".into(),
                        name: "builder".into(),
                        peer_url: "wss://builder.example.test".into(),
                        connected: true,
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNodeService/RevokeMeshNode"))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::RevokeMeshNodeRequest::decode(&mut body)
                    .expect("decode revoke node request");
                assert_eq!(request.org_id, "org-alpha");
                assert_eq!(request.network_id, "project-alpha");
                assert_eq!(request.node_name, "builder");
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(rpc::RevokeMeshNodeResponse::default().encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.MeshNodeService/CreateMeshNodeEnrollment",
            ))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::CreateMeshNodeEnrollmentRequest::decode(&mut body)
                    .expect("decode create enrollment request");
                assert_eq!(request.org_id, "org-alpha");
                assert_eq!(request.network_id, "project-alpha");
                assert_eq!(request.node_name, "builder");
                assert_eq!(
                    request.ttl.into_option().expect("enrollment TTL").seconds,
                    600
                );
                let response = rpc::CreateMeshNodeEnrollmentResponse {
                    enrollment: Some(rpc::MeshNodeEnrollment {
                        id: "enrollment-alpha".into(),
                        org_id: "org-alpha".into(),
                        network_id: "project-alpha".into(),
                        node_name: "builder".into(),
                        owner_user_id: "user-alpha".into(),
                        issued_by_user_id: "user-alpha".into(),
                        ..Default::default()
                    })
                    .into(),
                    enrollment_code: "cw_enr_secret".into(),
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;

        let client = MeshClient::new(&resolved(&server.uri(), "oauth-access"))
            .expect("generated Mesh client");
        client
            .create_network("org-alpha", "project-alpha")
            .await
            .expect("create network");
        let joined = client
            .join_network("cw_inv_secret")
            .await
            .expect("join network");
        assert_eq!(joined.network_id, "project-alpha");
        let nodes = client
            .list_nodes("org-alpha", Some("project-alpha"), false)
            .await
            .expect("list nodes");
        assert_eq!(
            nodes,
            vec![Node {
                network_id: "project-alpha".into(),
                name: "builder".into(),
                peer_url: "wss://builder.example.test".into(),
                connected: true,
            }]
        );
        client
            .revoke_node("org-alpha", "project-alpha", "builder")
            .await
            .expect("revoke node");
        let enrollment = client
            .create_node_enrollment("org-alpha", "project-alpha", "builder", "10m")
            .await
            .expect("create enrollment");
        assert_eq!(enrollment.id, "enrollment-alpha");
        assert_eq!(enrollment.enrollment_code, "cw_enr_secret");
        let json = serde_json::to_value(enrollment).expect("enrollment JSON");
        assert!(json.get("enrollment_token").is_none());
        assert!(json.get("uses_remaining").is_none());
    }

    #[tokio::test]
    async fn invitation_output_is_contract_native_without_legacy_fields() {
        let server = MockServer::start().await;
        let response = rpc::CreateMeshInviteResponse {
            invite: Some(rpc::MeshInvite {
                id: "invite-alpha".into(),
                org_id: "org-alpha".into(),
                network_id: "project-alpha".into(),
                created_by_user_id: "user-alpha".into(),
                ..Default::default()
            })
            .into(),
            invite_code: "cw_inv_secret".into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshInviteService/CreateMeshInvite"))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client =
            MeshClient::new(&resolved(&server.uri(), "oauth-access")).expect("Mesh client");
        let invite = client
            .create_invite("org-alpha", "project-alpha", "1h")
            .await
            .expect("create invite");
        let json = serde_json::to_value(invite).expect("JSON");
        assert_eq!(json["invite_code"], "cw_inv_secret");
        assert!(json.get("token").is_none());
        assert!(json.get("uses_remaining").is_none());
    }

    #[tokio::test]
    async fn transitional_redemption_is_facade_owned_and_sends_no_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/node-enrollments/redeem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "redeemed",
                "node_token": "node-secret",
                "node_name": "builder",
                "network_id": "project-alpha",
                "enrollment_id": "enrollment-alpha"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let redeemed = MeshClient::unauthenticated(&server.uri())
            .expect("client")
            .redeem_node_enrollment("cw_enr_secret", "builder")
            .await
            .expect("redeem");
        assert_eq!(redeemed.node_name, "builder");
        assert_eq!(redeemed.node_token, "node-secret");
    }
}
