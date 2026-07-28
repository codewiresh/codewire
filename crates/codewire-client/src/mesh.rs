use codewire_proto::codewire::v1::{
    CreateMeshInviteRequest, CreateMeshInviteResponse, CreateMeshNetworkRequest,
    CreateMeshNetworkResponse, CreateMeshNodeEnrollmentRequest, CreateMeshNodeEnrollmentResponse,
    JoinMeshNetworkRequest, JoinMeshNetworkResponse, ListMeshNetworksRequest,
    ListMeshNetworksResponse, ListMeshNodesRequest, ListMeshNodesResponse, RevokeMeshNodeRequest,
    RevokeMeshNodeResponse,
};
use connectrpc::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::{ClientError, CodewireClient};

/// Transitional result from the still-mounted enrollment-redemption endpoint.
///
/// WI-8A atomically replaces this with the generated redemption RPC and
/// removes the persistent node bearer. Keeping this one runtime seam inside
/// the shared façade prevents the CLI from owning a second transport.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransitionalMeshNodeEnrollmentRedemption {
    #[serde(default)]
    pub status: String,
    pub node_token: String,
    pub node_name: String,
    pub network_id: String,
    pub enrollment_id: String,
}

#[derive(Serialize)]
struct TransitionalMeshNodeEnrollmentRedeemRequest<'a> {
    #[serde(rename = "enrollment_token")]
    enrollment_code: &'a str,
    node_name: &'a str,
}

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

    /// Keep the pre-WI-8A runtime redemption call behind the one Rust façade.
    ///
    /// This method deliberately sends no bearer: the one-use enrollment code
    /// is the capability consumed by the endpoint. It does not log or include
    /// the code in an error.
    pub async fn redeem_transitional_mesh_node_enrollment(
        &self,
        enrollment_code: &str,
        node_name: &str,
    ) -> Result<TransitionalMeshNodeEnrollmentRedemption, ClientError> {
        let mut url = self.config.mesh_url().clone();
        let base = url.path().trim_end_matches('/');
        let path = "api/v1/node-enrollments/redeem";
        let joined = if base.is_empty() {
            format!("/{path}")
        } else {
            format!("{base}/{path}")
        };
        url.set_path(&joined);
        url.set_query(None);
        url.set_fragment(None);

        let response = self
            .http
            .post(url)
            .timeout(self.config.unary_timeout())
            .json(&TransitionalMeshNodeEnrollmentRedeemRequest {
                enrollment_code,
                node_name,
            })
            .send()
            .await
            .map_err(|_| {
                ClientError::new(
                    ErrorCode::Unavailable,
                    "redeem Mesh node enrollment request failed",
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::new(
                error_code_for_status(status),
                format!("redeem Mesh node enrollment failed: HTTP {status}"),
            ));
        }
        response.json().await.map_err(|_| {
            ClientError::new(
                ErrorCode::Internal,
                "decode Mesh node enrollment redemption response",
            )
        })
    }
}

fn error_code_for_status(status: reqwest::StatusCode) -> ErrorCode {
    match status {
        reqwest::StatusCode::BAD_REQUEST => ErrorCode::InvalidArgument,
        reqwest::StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
        reqwest::StatusCode::FORBIDDEN => ErrorCode::PermissionDenied,
        reqwest::StatusCode::NOT_FOUND => ErrorCode::NotFound,
        reqwest::StatusCode::CONFLICT => ErrorCode::Aborted,
        reqwest::StatusCode::TOO_MANY_REQUESTS => ErrorCode::ResourceExhausted,
        reqwest::StatusCode::BAD_GATEWAY
        | reqwest::StatusCode::SERVICE_UNAVAILABLE
        | reqwest::StatusCode::GATEWAY_TIMEOUT => ErrorCode::Unavailable,
        _ if status.is_server_error() => ErrorCode::Internal,
        _ => ErrorCode::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use buffa::Message as _;
    use serde_json::json;
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
    async fn transitional_redemption_uses_only_the_one_use_code() {
        let mesh = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/node-enrollments/redeem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "redeemed",
                "node_token": "node-secret",
                "node_name": "builder",
                "network_id": "network-alpha",
                "enrollment_id": "enrollment-alpha"
            })))
            .expect(1)
            .mount(&mesh)
            .await;

        let client = CodewireClient::new(
            ClientConfig::new(mesh.uri()).expect("Mesh origin"),
            StaticTokenProvider::new("must-not-be-sent").expect("unused bearer"),
        )
        .expect("client");
        let redeemed = client
            .redeem_transitional_mesh_node_enrollment("cw_enr_secret", "builder")
            .await
            .expect("redeem");
        assert_eq!(redeemed.node_name, "builder");

        let requests = mesh
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "enrollment redemption must not send a bearer"
        );
        assert_eq!(
            requests[0]
                .body_json::<serde_json::Value>()
                .expect("JSON request"),
            json!({
                "enrollment_token": "cw_enr_secret",
                "node_name": "builder"
            })
        );
    }
}
