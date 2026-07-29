use codewire_proto::codewire::v1::{
    CreateMeshInviteRequest, CreateMeshInviteResponse, CreateMeshNetworkRequest,
    CreateMeshNetworkResponse, CreateMeshNodeEnrollmentRequest, CreateMeshNodeEnrollmentResponse,
    JoinMeshNetworkRequest, JoinMeshNetworkResponse, ListMeshNetworksRequest,
    ListMeshNetworksResponse, ListMeshNodesRequest, ListMeshNodesResponse,
    RedeemMeshNodeEnrollmentRequest, RedeemMeshNodeEnrollmentResponse, RevokeMeshNodeRequest,
    RevokeMeshNodeResponse,
};
use connectrpc::client::CallOptions;

use crate::{ClientError, CodewireClient};

impl CodewireClient {
    pub async fn list_mesh_networks(
        &self,
        request: ListMeshNetworksRequest,
    ) -> Result<ListMeshNetworksResponse, ClientError> {
        self.mesh_networks
            .list_mesh_networks_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_mesh_network(
        &self,
        request: CreateMeshNetworkRequest,
    ) -> Result<CreateMeshNetworkResponse, ClientError> {
        self.mesh_networks
            .create_mesh_network_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn join_mesh_network(
        &self,
        request: JoinMeshNetworkRequest,
    ) -> Result<JoinMeshNetworkResponse, ClientError> {
        self.mesh_networks
            .join_mesh_network_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_mesh_nodes(
        &self,
        request: ListMeshNodesRequest,
    ) -> Result<ListMeshNodesResponse, ClientError> {
        self.mesh_nodes
            .list_mesh_nodes_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn revoke_mesh_node(
        &self,
        request: RevokeMeshNodeRequest,
    ) -> Result<RevokeMeshNodeResponse, ClientError> {
        self.mesh_nodes
            .revoke_mesh_node_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_mesh_node_enrollment(
        &self,
        request: CreateMeshNodeEnrollmentRequest,
    ) -> Result<CreateMeshNodeEnrollmentResponse, ClientError> {
        self.mesh_nodes
            .create_mesh_node_enrollment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_mesh_invite(
        &self,
        request: CreateMeshInviteRequest,
    ) -> Result<CreateMeshInviteResponse, ClientError> {
        self.mesh_invites
            .create_mesh_invite_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Redeem a one-use enrollment capability without sending a steady-state
    /// credential. The generated response contains registration metadata only.
    pub async fn redeem_mesh_node_enrollment(
        &self,
        request: RedeemMeshNodeEnrollmentRequest,
    ) -> Result<RedeemMeshNodeEnrollmentResponse, ClientError> {
        self.mesh_nodes
            .redeem_mesh_node_enrollment_with_options(
                request,
                CallOptions::default().with_timeout(self.config.unary_timeout()),
            )
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}

#[cfg(test)]
mod tests {
    use buffa::Message as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::{ClientConfig, MeshNetwork, StaticTokenProvider};

    #[tokio::test]
    async fn generated_mesh_handle_uses_mesh_origin_and_canonical_bearer() {
        let primary = MockServer::start().await;
        let mesh = MockServer::start().await;
        let response = ListMeshNetworksResponse {
            networks: vec![MeshNetwork {
                id: "network-alpha".into(),
                org_id: "org-alpha".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.MeshNetworkService/ListMeshNetworks"))
            .and(header("authorization", "Bearer cw_exact_org_key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&mesh)
            .await;

        let config = ClientConfig::new(primary.uri())
            .expect("primary origin")
            .with_mesh_url(mesh.uri())
            .expect("Mesh origin");
        let client = CodewireClient::new(
            config,
            StaticTokenProvider::new("cw_exact_org_key").expect("API key"),
        )
        .expect("client");
        let listed = client
            .list_mesh_networks(ListMeshNetworksRequest {
                org_id: "org-alpha".into(),
                ..Default::default()
            })
            .await
            .expect("list Mesh networks");

        assert_eq!(listed.networks[0].id, "network-alpha");
        assert!(
            primary
                .received_requests()
                .await
                .expect("request recording")
                .is_empty(),
            "Mesh RPC escaped to the primary origin"
        );
    }

    #[tokio::test]
    async fn generated_redemption_uses_only_the_one_use_code() {
        let mesh = MockServer::start().await;
        let response = RedeemMeshNodeEnrollmentResponse {
            node: Some(crate::MeshNode {
                org_id: "org-alpha".into(),
                network_id: "network-alpha".into(),
                name: "builder".into(),
                ..Default::default()
            })
            .into(),
            enrollment: Some(crate::MeshNodeEnrollment {
                id: "enrollment-alpha".into(),
                org_id: "org-alpha".into(),
                network_id: "network-alpha".into(),
                node_name: "builder".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.MeshNodeService/RedeemMeshNodeEnrollment",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&mesh)
            .await;

        let client = CodewireClient::new(
            ClientConfig::new(mesh.uri()).expect("Mesh origin"),
            StaticTokenProvider::new("must-not-be-sent").expect("unused bearer"),
        )
        .expect("client");
        let redeemed = client
            .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                enrollment_code: "cw_enr_secret".into(),
                node_name: "builder".into(),
                ..Default::default()
            })
            .await
            .expect("redeem");
        assert_eq!(redeemed.node.as_option().unwrap().name, "builder");

        let requests = mesh
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "enrollment redemption must not send a bearer"
        );
        let mut body = requests[0].body.as_slice();
        let request = RedeemMeshNodeEnrollmentRequest::decode(&mut body).expect("request body");
        assert_eq!(request.enrollment_code, "cw_enr_secret");
        assert_eq!(request.node_name, "builder");
    }
}
