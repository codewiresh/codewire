//! The sandbox identity key in OpenBao transit. This process logs in with a
//! Pod-bound token under its own Kubernetes-auth role: the signer role for
//! orchestration, which may read the key, and the rotator role for the
//! rotation job, which may also rotate it and raise its minimum versions.
//! Neither may export, back up or reconfigure it otherwise; OpenBao's
//! policies enforce that, not this client.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

use codewire_protected_store::openbao_workload_identity::OpenBaoWorkloadIdentity;

use super::config::{TRANSIT_KEY_NAME, TransitKeyConfig};
use super::keys::{KeyRead, KeySet, KeySetError};
use crate::openbao::restricted_http_client;

/// A key read lists a few versions of a few hundred bytes each.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Which OpenBao call failed. Errors carry no response body or token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitStage {
    Authority,
    WorkloadIdentity,
    Login,
    ReadKey,
    Rotate,
    RaiseMinimums,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitError {
    #[error("OpenBao {0:?} is unavailable")]
    Unavailable(TransitStage),
    #[error("OpenBao refused {stage:?} with HTTP {status}")]
    Refused { stage: TransitStage, status: u16 },
    #[error("OpenBao answered {0:?} with an invalid response")]
    InvalidResponse(TransitStage),
    #[error("the sandbox identity key is unusable: {0}")]
    KeySet(#[from] KeySetError),
}

struct CachedToken {
    value: Zeroizing<String>,
    expires_at: Instant,
}

pub struct TransitKeyClient {
    config: TransitKeyConfig,
    identity: Arc<dyn OpenBaoWorkloadIdentity>,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: Zeroizing<String>,
    #[serde(default)]
    lease_duration: u64,
}

#[derive(Deserialize)]
struct HealthResponse {
    cluster_id: String,
}

#[derive(Deserialize)]
struct DataResponse<T> {
    data: T,
}

#[derive(Serialize)]
struct MinimumsRequest {
    min_decryption_version: u32,
    min_encryption_version: u32,
}

impl TransitKeyClient {
    pub fn new(
        config: TransitKeyConfig,
        identity: Arc<dyn OpenBaoWorkloadIdentity>,
    ) -> anyhow::Result<Self> {
        let https_only = config.address.scheme() == "https";
        Ok(Self {
            http: restricted_http_client(REQUEST_TIMEOUT, https_only, None)?,
            config,
            identity,
            token: Mutex::new(None),
        })
    }

    /// The key's published versions and custody settings, read now.
    pub async fn read_key(&self) -> Result<KeySet, TransitError> {
        let stage = TransitStage::ReadKey;
        let token = self.authenticate().await?;
        let response = self
            .http
            .get(self.key_endpoint(&[])?)
            .header("X-Vault-Token", token.as_str())
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        let read: DataResponse<KeyRead> = decode(checked(response, stage)?, stage).await?;
        Ok(KeySet::from_read(read.data)?)
    }

    /// Add a version. It is published at once and signs 24 hours later.
    pub async fn rotate(&self) -> Result<(), TransitError> {
        let stage = TransitStage::Rotate;
        let token = self.authenticate().await?;
        let response = self
            .http
            .post(self.key_endpoint(&["rotate"])?)
            .header("X-Vault-Token", token.as_str())
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        checked(response, stage).map(drop)
    }

    /// Retire every version below `version`: it no longer signs, verifies or
    /// appears in the key listing, so it leaves the JWKS.
    pub async fn raise_minimums(&self, version: u32) -> Result<(), TransitError> {
        let stage = TransitStage::RaiseMinimums;
        let token = self.authenticate().await?;
        let response = self
            .http
            .post(self.key_endpoint(&["config"])?)
            .header("X-Vault-Token", token.as_str())
            .json(&MinimumsRequest {
                min_decryption_version: version,
                min_encryption_version: version,
            })
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        checked(response, stage).map(drop)
    }

    fn endpoint(&self, segments: &[&str], stage: TransitStage) -> Result<Url, TransitError> {
        let mut url = self.config.address.clone();
        url.path_segments_mut()
            .map_err(|_| TransitError::InvalidResponse(stage))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    fn key_endpoint(&self, suffix: &[&str]) -> Result<Url, TransitError> {
        let mut segments = vec!["v1", &self.config.transit_mount, "keys", TRANSIT_KEY_NAME];
        segments.extend_from_slice(suffix);
        self.endpoint(&segments, TransitStage::ReadKey)
    }

    /// Bind every call to the configured cluster, then reuse a still-valid
    /// login.
    async fn authenticate(&self) -> Result<Zeroizing<String>, TransitError> {
        self.verify_authority().await?;
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && token.expires_at > Instant::now()
        {
            return Ok(Zeroizing::new(token.value.to_string()));
        }
        let jwt = self.identity.token().await.map_err(|error| {
            tracing::warn!(
                failure_class = error.failure_class(),
                "sandbox identity OpenBao workload identity request failed"
            );
            TransitError::Unavailable(TransitStage::WorkloadIdentity)
        })?;
        let stage = TransitStage::Login;
        let response = self
            .http
            .post(self.endpoint(&["v1", "auth", &self.config.auth_mount, "login"], stage)?)
            .json(&LoginRequest {
                role: &self.config.role,
                jwt: jwt.as_str(),
            })
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        let login: LoginResponse = decode(checked(response, stage)?, stage).await?;
        if login.auth.client_token.is_empty() {
            return Err(TransitError::InvalidResponse(stage));
        }
        let refresh_after = login.auth.lease_duration.saturating_sub(60).min(60 * 60);
        let result = Zeroizing::new(login.auth.client_token.to_string());
        *cached = Some(CachedToken {
            value: login.auth.client_token,
            expires_at: Instant::now() + Duration::from_secs(refresh_after),
        });
        Ok(result)
    }

    async fn verify_authority(&self) -> Result<(), TransitError> {
        let stage = TransitStage::Authority;
        let mut url = self.endpoint(&["v1", "sys", "health"], stage)?;
        url.query_pairs_mut()
            .append_pair("standbyok", "true")
            .append_pair("perfstandbyok", "true");
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        let health: HealthResponse = decode(checked(response, stage)?, stage).await?;
        if health.cluster_id != self.config.expected_cluster_id {
            return Err(TransitError::InvalidResponse(stage));
        }
        Ok(())
    }
}

fn checked(
    response: reqwest::Response,
    stage: TransitStage,
) -> Result<reqwest::Response, TransitError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(TransitError::Refused {
            stage,
            status: response.status().as_u16(),
        })
    }
}

async fn decode<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    stage: TransitStage,
) -> Result<T, TransitError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| TransitError::Unavailable(stage))?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(TransitError::InvalidResponse(stage));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| TransitError::InvalidResponse(stage))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;
    use serde_json::json;

    use super::*;
    use crate::identity::keys::tests::key_read;
    use codewire_protected_store::openbao_workload_identity::static_workload_identity;

    type Recorded = Arc<StdMutex<Vec<(String, String, String)>>>;

    /// An OpenBao that answers only the calls this client may make, and
    /// records each one as (method and path, token, body).
    async fn fake_openbao(cluster_id: &'static str) -> (Url, Recorded) {
        let recorded: Recorded = Arc::default();
        let captured = recorded.clone();
        let app = Router::new().fallback(move |request: Request| {
            let captured = captured.clone();
            async move {
                let call = format!("{} {}", request.method(), request.uri().path());
                let token = request
                    .headers()
                    .get("X-Vault-Token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let body = to_bytes(request.into_body(), 4096).await.unwrap();
                let body = String::from_utf8(body.to_vec()).unwrap();
                captured.lock().unwrap().push((call.clone(), token.clone(), body.clone()));
                let authorized = token == "bao-token";
                match call.as_str() {
                    "GET /v1/sys/health" => axum::Json(json!({"cluster_id": cluster_id})).into_response(),
                    "POST /v1/auth/cw-dev-k8s/login"
                        if serde_json::from_str::<serde_json::Value>(&body).unwrap()
                            == json!({"role": "sandbox-identity-signer-cw-dev", "jwt": "projected-jwt"}) =>
                    {
                        axum::Json(json!({"auth": {"client_token": "bao-token", "lease_duration": 300}}))
                            .into_response()
                    }
                    "GET /v1/codewire-identity-dev/keys/sandbox-identity" if authorized => axum::Json(
                        json!({"data": key_read(&[(4, "2026-11-01T00:00:00Z"), (5, "2026-11-13T00:00:00Z")], 4, 4)}),
                    )
                    .into_response(),
                    "POST /v1/codewire-identity-dev/keys/sandbox-identity/rotate"
                    | "POST /v1/codewire-identity-dev/keys/sandbox-identity/config"
                        if authorized =>
                    {
                        StatusCode::NO_CONTENT.into_response()
                    }
                    _ => StatusCode::FORBIDDEN.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        (Url::parse(&format!("http://{address}")).unwrap(), recorded)
    }

    fn client(address: Url) -> TransitKeyClient {
        TransitKeyClient::new(
            TransitKeyConfig {
                address,
                auth_mount: "cw-dev-k8s".to_owned(),
                role: "sandbox-identity-signer-cw-dev".to_owned(),
                transit_mount: "codewire-identity-dev".to_owned(),
                expected_cluster_id: "cluster-dev".to_owned(),
            },
            static_workload_identity("projected-jwt"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_client_reads_rotates_and_raises_minimums_on_its_own_key_only() {
        let (address, recorded) = fake_openbao("cluster-dev").await;
        let client = client(address);

        let key_set = client.read_key().await.unwrap();
        assert_eq!(
            serde_json::to_value(key_set.jwks()).unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        client.rotate().await.unwrap();
        client.raise_minimums(5).await.unwrap();

        let calls = recorded.lock().unwrap().clone();
        let without_health: Vec<_> = calls
            .iter()
            .filter(|(call, ..)| call != "GET /v1/sys/health")
            .map(|(call, token, body)| (call.as_str(), token.as_str(), body.as_str()))
            .collect();
        assert_eq!(
            without_health,
            [
                (
                    "POST /v1/auth/cw-dev-k8s/login",
                    "",
                    r#"{"role":"sandbox-identity-signer-cw-dev","jwt":"projected-jwt"}"#
                ),
                (
                    "GET /v1/codewire-identity-dev/keys/sandbox-identity",
                    "bao-token",
                    ""
                ),
                (
                    "POST /v1/codewire-identity-dev/keys/sandbox-identity/rotate",
                    "bao-token",
                    ""
                ),
                (
                    "POST /v1/codewire-identity-dev/keys/sandbox-identity/config",
                    "bao-token",
                    r#"{"min_decryption_version":5,"min_encryption_version":5}"#
                ),
            ],
            "one login, then exactly the key's own read, rotate and minimums"
        );
        // Every call first checks it is talking to the configured cluster.
        assert_eq!(calls.len() - without_health.len(), 3);
    }

    #[tokio::test]
    async fn another_cluster_is_refused_before_any_login() {
        let (address, recorded) = fake_openbao("some-other-cluster").await;
        let error = client(address).read_key().await.unwrap_err();
        assert!(matches!(
            error,
            TransitError::InvalidResponse(TransitStage::Authority)
        ));
        let calls: Vec<_> = recorded
            .lock()
            .unwrap()
            .iter()
            .map(|(call, ..)| call.clone())
            .collect();
        assert_eq!(calls, ["GET /v1/sys/health"]);
    }
}
