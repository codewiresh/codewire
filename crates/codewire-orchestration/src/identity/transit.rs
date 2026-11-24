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
use super::keys::{KeyRead, KeySet, KeySetError, SigningKey};
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
    Sign,
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

/// A transit sign request. `key_version` is not optional: an unversioned
/// request can't be built. The hash is OpenBao's default for an
/// `ecdsa-p256` key, SHA-256, which ES256 needs; the request never names
/// one, so OpenBao's policy may pin its parameters.
#[derive(Serialize)]
struct SignRequest<'a> {
    /// The JWS signing input, base64 as OpenBao takes it.
    input: String,
    key_version: u32,
    marshaling_algorithm: &'a str,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

/// An ES256 JWS signature: base64url of the 64-byte `r || s`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JwsSignature(String);

impl JwsSignature {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The signature from OpenBao's `vault:v<version>:<signature>`, made by
    /// exactly `version`.
    fn from_transit(value: &str, version: u32) -> Option<Self> {
        use base64::Engine as _;
        let signature = value.strip_prefix(&format!("vault:v{version}:"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .ok()?;
        (bytes.len() == 64).then(|| Self(signature.to_owned()))
    }
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

    /// Sign `input`, a JWS signing input, with exactly `key`'s version, in
    /// JWS marshaling.
    pub(crate) async fn sign(
        &self,
        key: SigningKey,
        input: &[u8],
    ) -> Result<JwsSignature, TransitError> {
        use base64::Engine as _;
        let stage = TransitStage::Sign;
        let token = self.authenticate().await?;
        let url = self.endpoint(
            &["v1", &self.config.transit_mount, "sign", TRANSIT_KEY_NAME],
            stage,
        )?;
        let response = self
            .http
            .post(url)
            .header("X-Vault-Token", token.as_str())
            .json(&SignRequest {
                input: base64::engine::general_purpose::STANDARD.encode(input),
                key_version: key.version(),
                marshaling_algorithm: "jws",
            })
            .send()
            .await
            .map_err(|_| TransitError::Unavailable(stage))?;
        let signed: DataResponse<SignResponse> = decode(checked(response, stage)?, stage).await?;
        JwsSignature::from_transit(&signed.data.signature, key.version())
            .ok_or(TransitError::InvalidResponse(stage))
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
pub(crate) mod tests;
