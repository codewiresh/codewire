use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::ResolvedMeshConfig;
use crate::http_policy::{LEGACY_JSON_REQUEST_TIMEOUT, LegacyHttpCall, apply_legacy_http_policy};

#[derive(Clone, Debug)]
pub struct MeshClient {
    base_url: Url,
    auth_token: Option<String>,
    http: reqwest::Client,
    legacy_json_timeout: Duration,
}

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn default_http_client() -> anyhow::Result<reqwest::Client> {
    http_client_with_connect_timeout(DEFAULT_CONNECT_TIMEOUT)
}

fn http_client_with_connect_timeout(connect_timeout: Duration) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .build()
        .context("build Mesh HTTP client")
}

struct MeshHttpResponse {
    status: reqwest::StatusCode,
    body: Vec<u8>,
}

impl MeshClient {
    pub fn new(config: &ResolvedMeshConfig) -> anyhow::Result<Self> {
        Self::with_http(config, default_http_client()?)
    }

    pub fn with_http(config: &ResolvedMeshConfig, http: reqwest::Client) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: Url::parse(&config.mesh_url)?,
            auth_token: Some(config.auth_token.clone()),
            http,
            legacy_json_timeout: LEGACY_JSON_REQUEST_TIMEOUT,
        })
    }

    pub fn unauthenticated(base_url: &str) -> anyhow::Result<Self> {
        Self::unauthenticated_with_http(base_url, default_http_client()?)
    }

    pub fn unauthenticated_with_http(
        base_url: &str,
        http: reqwest::Client,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            auth_token: None,
            http,
            legacy_json_timeout: LEGACY_JSON_REQUEST_TIMEOUT,
        })
    }

    pub async fn list_networks(&self, org_id: &str) -> anyhow::Result<Vec<Network>> {
        self.get_json("api/v1/networks", &[("org_id", org_id)], "list networks")
            .await
    }

    pub async fn create_network(&self, org_id: &str, network_id: &str) -> anyhow::Result<()> {
        let response = self
            .send_request_bytes(
                self.http
                    .post(self.endpoint("api/v1/networks", &[])?)
                    .json(&NetworkCreateRequest { org_id, network_id }),
                "create network",
            )
            .await?;
        self.check_response_bytes(response, "create network")?;
        Ok(())
    }

    pub async fn list_nodes(
        &self,
        network_id: Option<&str>,
        all: bool,
    ) -> anyhow::Result<Vec<Node>> {
        let mut query = Vec::new();
        if all {
            query.push(("all", "true"));
        } else if let Some(network_id) = network_id {
            query.push(("network_id", network_id));
        }
        self.get_json("api/v1/nodes", &query, "list nodes").await
    }

    pub async fn create_invite(
        &self,
        network_id: &str,
        uses: i32,
        ttl: &str,
    ) -> anyhow::Result<Invite> {
        let response = self
            .send_request_bytes(
                self.http
                    .post(self.endpoint("api/v1/invites", &[])?)
                    .json(&InviteCreateRequest {
                        network_id,
                        uses,
                        ttl,
                    }),
                "create invite",
            )
            .await?;
        let body = self.check_response_bytes(response, "create invite")?;
        Ok(serde_json::from_slice::<Invite>(&body)?)
    }

    pub async fn join_network(&self, invite_token: &str) -> anyhow::Result<NetworkJoin> {
        let response = self
            .send_request_bytes(
                self.http
                    .post(self.endpoint("api/v1/networks/join", &[])?)
                    .json(&NetworkJoinRequest { invite_token }),
                "join network",
            )
            .await?;
        let body = self.check_response_bytes(response, "join network")?;
        Ok(serde_json::from_slice::<NetworkJoin>(&body)?)
    }

    pub async fn revoke_node(&self, network_id: &str, node_name: &str) -> anyhow::Result<()> {
        let query = [("network_id", network_id)];
        let path = format!("api/v1/nodes/{node_name}");
        let response = self
            .bounded_json_with_auth(self.http.delete(self.endpoint(&path, &query)?))
            .send()
            .await?;
        self.check_response(response, "revoke node").await?;
        Ok(())
    }

    async fn get_json<T>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        action: &str,
    ) -> anyhow::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self
            .send_request_bytes(self.http.get(self.endpoint(path, query)?), action)
            .await?;
        let body = self.check_response_bytes(response, action)?;
        Ok(serde_json::from_slice::<T>(&body)?)
    }

    pub async fn create_node_enrollment(
        &self,
        network_id: &str,
        node_name: &str,
        uses: i32,
        ttl: &str,
    ) -> anyhow::Result<NodeEnrollment> {
        let request = NodeEnrollmentCreateRequest {
            network_id,
            node_name,
            uses,
            ttl,
        };
        let response = self
            .send_request_bytes(
                self.http
                    .post(self.endpoint("api/v1/node-enrollments", &[])?)
                    .json(&request),
                "create enrollment",
            )
            .await?;
        let body = self.check_response_bytes(response, "create enrollment")?;
        Ok(serde_json::from_slice::<NodeEnrollment>(&body)?)
    }

    pub async fn redeem_node_enrollment(
        &self,
        enrollment_token: &str,
        node_name: &str,
    ) -> anyhow::Result<RedeemedNodeEnrollment> {
        let request = NodeEnrollmentRedeemRequest {
            enrollment_token,
            node_name,
        };
        let response = self
            .send_request_bytes(
                self.http
                    .post(self.endpoint("api/v1/node-enrollments/redeem", &[])?)
                    .json(&request),
                "redeem enrollment",
            )
            .await?;
        let body = self.check_response_bytes(response, "redeem enrollment")?;
        Ok(serde_json::from_slice::<RedeemedNodeEnrollment>(&body)?)
    }

    async fn send_request_bytes(
        &self,
        request: reqwest::RequestBuilder,
        action: &str,
    ) -> anyhow::Result<MeshHttpResponse> {
        let request = self.bounded_json_with_auth(request).build()?;
        let response = self
            .http
            .execute(request)
            .await
            .with_context(|| format!("{action}: send Mesh HTTP request"))?;
        let status = response.status();
        let body = response.bytes().await?.to_vec();
        Ok(MeshHttpResponse { status, body })
    }

    fn check_response_bytes(
        &self,
        response: MeshHttpResponse,
        action: &str,
    ) -> anyhow::Result<Vec<u8>> {
        if response.status.is_success() {
            return Ok(response.body);
        }
        let status = response.status;
        let body = String::from_utf8_lossy(&response.body);
        let body = body.trim();
        if body.is_empty() {
            anyhow::bail!("failed to {action}: HTTP {status}");
        }
        anyhow::bail!("failed to {action}: HTTP {status}: {body}");
    }

    async fn check_response(
        &self,
        response: reqwest::Response,
        action: &str,
    ) -> anyhow::Result<reqwest::Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let body = body.trim();
        if body.is_empty() {
            anyhow::bail!("failed to {action}: HTTP {status}");
        }
        anyhow::bail!("failed to {action}: {body}");
    }

    fn endpoint(&self, path: &str, query: &[(&str, &str)]) -> anyhow::Result<Url> {
        let mut url = self.base_url.clone();
        let base_path = url.path().trim_end_matches('/');
        let path = path.trim_start_matches('/');
        let joined = if base_path.is_empty() {
            format!("/{path}")
        } else {
            format!("{base_path}/{path}")
        };
        url.set_path(&joined);
        url.set_query(None);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (*key, *value)));
        }
        Ok(url)
    }

    fn classified_request_with_auth(
        &self,
        request: reqwest::RequestBuilder,
        class: LegacyHttpCall,
    ) -> reqwest::RequestBuilder {
        let request = match &self.auth_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        apply_legacy_http_policy(request, class, self.legacy_json_timeout)
    }

    fn bounded_json_with_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.classified_request_with_auth(request, LegacyHttpCall::BoundedJson)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub org_id: String,
    pub created_at: String,
    pub node_count: i64,
    pub invite_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Node {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_url: String,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Invite {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_id: String,
    pub token: String,
    pub uses_remaining: i32,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkJoin {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    pub network_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeEnrollment {
    pub id: String,
    pub network_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_name: String,
    pub enrollment_token: String,
    pub uses_remaining: i32,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RedeemedNodeEnrollment {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    pub node_token: String,
    pub node_name: String,
    pub network_id: String,
    pub enrollment_id: String,
}

#[derive(Serialize)]
struct NetworkCreateRequest<'a> {
    org_id: &'a str,
    network_id: &'a str,
}

#[derive(Serialize)]
struct InviteCreateRequest<'a> {
    network_id: &'a str,
    uses: i32,
    ttl: &'a str,
}

#[derive(Serialize)]
struct NetworkJoinRequest<'a> {
    invite_token: &'a str,
}

#[derive(Serialize)]
struct NodeEnrollmentCreateRequest<'a> {
    network_id: &'a str,
    node_name: &'a str,
    uses: i32,
    ttl: &'a str,
}

#[derive(Serialize)]
struct NodeEnrollmentRedeemRequest<'a> {
    enrollment_token: &'a str,
    node_name: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MeshAuthSource, ResolvedMeshConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn resolved(base_url: &str) -> ResolvedMeshConfig {
        ResolvedMeshConfig {
            mesh_url: base_url.to_string(),
            auth_token: "mesh-token".to_string(),
            selected_network: Some("project-alpha".to_string()),
            auth_source: MeshAuthSource::Explicit,
        }
    }

    #[tokio::test]
    async fn request_timeout_bounds_unresponsive_mesh() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let http = http_client_with_connect_timeout(Duration::from_millis(50)).unwrap();
        let mut client = MeshClient::with_http(&resolved(&format!("http://{addr}")), http).unwrap();
        client.legacy_json_timeout = Duration::from_millis(50);

        let err = client.list_networks("org-alpha").await.unwrap_err();
        server.abort();
        let message = format!("{err:#}");
        assert!(
            message.contains("timed out") || message.contains("deadline has elapsed"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn list_networks_sends_bearer_auth_and_parses_response() {
        let server = serve_once(
            serde_json::json!([
                {
                    "id": "project-alpha",
                    "org_id": "org-alpha",
                    "created_at": "2026-07-04T04:00:00Z",
                    "node_count": 2,
                    "invite_count": 1
                }
            ])
            .to_string(),
            |request| {
                assert!(request.starts_with("GET /api/v1/networks?org_id=org-alpha HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let networks = client.list_networks("org-alpha").await.unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, "project-alpha");
        assert_eq!(networks[0].node_count, 2);
    }

    #[tokio::test]
    async fn create_network_posts_go_compatible_body() {
        let server = serve_once(
            serde_json::json!({
                "status": "created",
                "network_id": "project-beta"
            })
            .to_string(),
            |request| {
                assert!(request.starts_with("POST /api/v1/networks HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
                assert!(request.contains(r#""org_id":"org-alpha""#));
                assert!(request.contains(r#""network_id":"project-beta""#));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();

        client
            .create_network("org-alpha", "project-beta")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_nodes_scopes_by_selected_network_unless_all_is_set() {
        let server = serve_once(
            serde_json::json!([
                {
                    "network_id": "project-alpha",
                    "name": "builder",
                    "peer_url": "wss://builder.example/ws",
                    "connected": true
                }
            ])
            .to_string(),
            |request| {
                assert!(request.starts_with("GET /api/v1/nodes?network_id=project-alpha HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let nodes = client
            .list_nodes(Some("project-alpha"), false)
            .await
            .unwrap();

        assert_eq!(nodes[0].name, "builder");
        assert!(nodes[0].connected);
    }

    #[tokio::test]
    async fn list_nodes_all_uses_all_query() {
        let server = serve_once(serde_json::json!([]).to_string(), |request| {
            assert!(request.starts_with("GET /api/v1/nodes?all=true HTTP/1.1"));
        })
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let nodes = client.list_nodes(None, true).await.unwrap();

        assert!(nodes.is_empty());
    }

    #[tokio::test]
    async fn create_invite_posts_go_compatible_body() {
        let server = serve_once(
            serde_json::json!({
                "network_id": "project-alpha",
                "token": "cw_inv_secret",
                "uses_remaining": 1,
                "expires_at": "2026-07-04T06:00:00Z",
                "created_at": "2026-07-04T05:00:00Z"
            })
            .to_string(),
            |request| {
                assert!(request.starts_with("POST /api/v1/invites HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
                assert!(request.contains(r#""network_id":"project-alpha""#));
                assert!(request.contains(r#""uses":1"#));
                assert!(request.contains(r#""ttl":"1h""#));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let invite = client
            .create_invite("project-alpha", 1, "1h")
            .await
            .unwrap();

        assert_eq!(invite.token, "cw_inv_secret");
        assert_eq!(invite.network_id, "project-alpha");
    }

    #[tokio::test]
    async fn join_network_posts_invite_token_with_bearer_auth() {
        let server = serve_once(
            serde_json::json!({
                "status": "joined",
                "network_id": "project-alpha"
            })
            .to_string(),
            |request| {
                assert!(request.starts_with("POST /api/v1/networks/join HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
                assert!(request.contains(r#""invite_token":"cw_inv_secret""#));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let joined = client.join_network("cw_inv_secret").await.unwrap();

        assert_eq!(joined.network_id, "project-alpha");
    }

    #[tokio::test]
    async fn revoke_node_deletes_scoped_node_with_bearer_auth() {
        let server =
            serve_once(
                serde_json::json!({
                    "status": "revoked",
                    "node": "builder"
                })
                .to_string(),
                |request| {
                    assert!(request.starts_with(
                        "DELETE /api/v1/nodes/builder?network_id=project-alpha HTTP/1.1"
                    ));
                    assert!(request.contains("authorization: Bearer mesh-token"));
                },
            )
            .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();

        client
            .revoke_node("project-alpha", "builder")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_node_enrollment_posts_go_compatible_body() {
        let server = serve_once(
            serde_json::json!({
                "id": "enr_123",
                "network_id": "project-alpha",
                "node_name": "builder",
                "enrollment_token": "cw_enr_secret",
                "uses_remaining": 1,
                "expires_at": "2026-07-04T05:00:00Z"
            })
            .to_string(),
            |request| {
                assert!(request.starts_with("POST /api/v1/node-enrollments HTTP/1.1"));
                assert!(request.contains("authorization: Bearer mesh-token"));
                assert!(request.contains(r#""network_id":"project-alpha""#));
                assert!(request.contains(r#""node_name":"builder""#));
                assert!(request.contains(r#""uses":1"#));
                assert!(request.contains(r#""ttl":"10m""#));
            },
        )
        .await;

        let client = MeshClient::new(&resolved(&server)).unwrap();
        let enrollment = client
            .create_node_enrollment("project-alpha", "builder", 1, "10m")
            .await
            .unwrap();

        assert_eq!(enrollment.id, "enr_123");
        assert_eq!(enrollment.enrollment_token, "cw_enr_secret");
    }

    #[tokio::test]
    async fn redeem_node_enrollment_posts_without_bearer_auth() {
        let server = serve_once(
            serde_json::json!({
                "status": "registered",
                "node_token": "node-token",
                "node_name": "builder",
                "network_id": "project-alpha",
                "enrollment_id": "enr_123"
            })
            .to_string(),
            |request| {
                assert!(request.starts_with("POST /api/v1/node-enrollments/redeem HTTP/1.1"));
                assert!(!request.contains("authorization:"));
                assert!(request.contains(r#""enrollment_token":"cw_enr_secret""#));
                assert!(request.contains(r#""node_name":"builder""#));
            },
        )
        .await;

        let client = MeshClient::unauthenticated(&server).unwrap();
        let redeemed = client
            .redeem_node_enrollment("cw_enr_secret", "builder")
            .await
            .unwrap();

        assert_eq!(redeemed.node_token, "node-token");
        assert_eq!(redeemed.network_id, "project-alpha");
    }

    async fn serve_once(
        body: String,
        assert_request: impl FnOnce(String) + Send + 'static,
    ) -> String {
        serve_raw(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            ),
            assert_request,
        )
        .await
    }

    async fn serve_raw(
        response: String,
        assert_request: impl FnOnce(String) + Send + 'static,
    ) -> String {
        serve_raw_delayed(response, Duration::ZERO, assert_request).await
    }

    async fn serve_raw_delayed(
        response: String,
        delay: Duration,
        assert_request: impl FnOnce(String) + Send + 'static,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert_request(request);
            tokio::time::sleep(delay).await;
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if request_complete(&buf) {
                break;
            }
        }
        String::from_utf8(buf).unwrap()
    }

    fn request_complete(buf: &[u8]) -> bool {
        let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let header = String::from_utf8_lossy(&buf[..header_end]);
        let content_length = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        buf.len() >= header_end + 4 + content_length
    }
}
