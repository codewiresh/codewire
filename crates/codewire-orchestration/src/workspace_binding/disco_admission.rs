//! Orchestration's question to the coordinator before it allocates a UDP
//! peer relay slot (#5962): how is each named disco key bound, as the calling
//! environment sees it? The coordinator answers on its closed 8097 listener,
//! which the site's policy opens to orchestration by service account. The
//! rules are in `docs/dev/DERP-STUN.md`.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use serde::Deserialize;

/// The coordinator's lookup, relative to its 8097 listener.
const CHECK_DISCO_KEY_PATH: &str = "/codewire.internal.v1.PeerRelayAdmissionService/CheckDiscoKey";
/// One lookup's bound; a slower coordinator costs the relay path, not the
/// connection, which stays on direct UDP or DERP.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// How a disco key is bound, as one environment sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoKeySeen {
    /// The environment's own daemon holds it in a live session.
    Here,
    /// Another live session holds it, the environment's clients included.
    Elsewhere,
    /// No live session holds it.
    Unbound,
}

/// The coordinator could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionUnavailable;

/// Asks how a disco key (`discokey:<hex>`) is bound, as `environment_id`
/// sees it.
#[async_trait]
pub trait DiscoKeyAdmission: Send + Sync {
    async fn check(
        &self,
        disco_key: &str,
        environment_id: &str,
    ) -> Result<DiscoKeySeen, AdmissionUnavailable>;
}

/// The coordinator's lookup over HTTP, at `CODEWIRE_PEER_RELAY_ADMISSION_URL`.
/// With no URL every lookup is unavailable, so a relay is never allocated
/// unchecked.
#[derive(Default)]
pub struct HttpDiscoKeyAdmission {
    endpoint: Option<url::Url>,
    client: reqwest::Client,
}

impl HttpDiscoKeyAdmission {
    /// A lookup at `base` (the coordinator's 8097 origin), or none.
    pub fn new(base: Option<&str>) -> anyhow::Result<Self> {
        let endpoint = base
            .map(str::trim)
            .filter(|base| !base.is_empty())
            .map(|base| -> anyhow::Result<url::Url> {
                let base = url::Url::parse(base)?;
                anyhow::ensure!(
                    matches!(base.scheme(), "http" | "https")
                        && base.username().is_empty()
                        && base.password().is_none(),
                    "the peer relay admission URL must be http or https, without credentials"
                );
                Ok(base.join(CHECK_DISCO_KEY_PATH)?)
            })
            .transpose()?;
        // The lookup goes straight to the coordinator: no redirect, and no
        // proxy from the environment.
        let client = reqwest::Client::builder()
            .timeout(CHECK_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { endpoint, client })
    }
}

/// The 32 bytes of a `discokey:<hex>` key the binding listener validated.
fn disco_key_bytes(disco_key: &str) -> Option<[u8; 32]> {
    let hex = disco_key.strip_prefix("discokey:")?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut raw = [0_u8; 32];
    let (pairs, _) = hex.as_chunks::<2>();
    for (out, [high, low]) in raw.iter_mut().zip(pairs) {
        *out = nibble(*high)? << 4 | nibble(*low)?;
    }
    Some(raw)
}

#[derive(Deserialize)]
struct CheckDiscoKeyResponse {
    #[serde(default)]
    binding: String,
}

#[async_trait]
impl DiscoKeyAdmission for HttpDiscoKeyAdmission {
    async fn check(
        &self,
        disco_key: &str,
        environment_id: &str,
    ) -> Result<DiscoKeySeen, AdmissionUnavailable> {
        let unavailable = |reason: &'static str| {
            tracing::warn!(reason, "peer relay admission lookup is unavailable");
            AdmissionUnavailable
        };
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| unavailable("no peer relay admission URL is configured"))?;
        let raw =
            disco_key_bytes(disco_key).ok_or_else(|| unavailable("the disco key is malformed"))?;
        let body = serde_json::json!({
            "discoKey": base64::engine::general_purpose::STANDARD.encode(raw),
            "environmentId": environment_id,
        });
        let response = self
            .client
            .post(endpoint)
            .header("connect-protocol-version", "1")
            .json(&body)
            .send()
            .await
            .map_err(|_| unavailable("the coordinator could not be reached"))?;
        if !response.status().is_success() {
            return Err(unavailable("the coordinator did not answer"));
        }
        let answer = response
            .json::<CheckDiscoKeyResponse>()
            .await
            .map_err(|_| unavailable("the coordinator's answer is not readable"))?;
        match answer.binding.as_str() {
            "DISCO_KEY_BINDING_BOUND_HERE" => Ok(DiscoKeySeen::Here),
            "DISCO_KEY_BINDING_BOUND_ELSEWHERE" => Ok(DiscoKeySeen::Elsewhere),
            "DISCO_KEY_BINDING_UNBOUND" => Ok(DiscoKeySeen::Unbound),
            _ => Err(unavailable("the coordinator's answer is unknown")),
        }
    }
}

#[cfg(test)]
mod tests;
