//! One OpenBao transit HMAC key used for one purpose (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The seal key"): the credential
//! service seals a local VM boot's record with it and verifies the record
//! when the boot carries it back.
//!
//! Only `hmac/<key>/sha2-256` and `verify/<key>/sha2-256` are called; the
//! hash algorithm is in the path, never a caller's. A seal is transit's
//! `vault:vN:` string, passed back to `verify` unchanged, so OpenBao refuses
//! a version below the key's `min_decryption_version` and compares in
//! constant time. The key itself is never read.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::{
    DEFAULT_TRANSIT_KEY, OpenBaoTransitProvider, decode_bao_response, parse_transit_version,
    valid_bao_segment,
};

/// Why a seal couldn't be made or checked. It names no key, input or seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransitHmacError {
    /// OpenBao didn't answer, refused the service, or answered in a shape
    /// it never gives: never a pass.
    #[error("the transit HMAC key is unavailable")]
    Unavailable,
}

/// A transit HMAC key.
#[async_trait]
pub trait TransitHmac: Send + Sync {
    /// The key's HMAC-SHA256 of `input`, as transit's `vault:vN:` string.
    async fn hmac(&self, input: &[u8]) -> Result<String, TransitHmacError>;

    /// Whether `seal`, passed to OpenBao unchanged, is the key's HMAC of
    /// `input` under a version it still verifies. A seal that isn't a
    /// `vault:vN:` string is refused without asking.
    async fn verify(&self, input: &[u8], seal: &str) -> Result<bool, TransitHmacError>;
}

/// [`TransitHmac`] on OpenBao, authenticated as `provider` is: the same
/// address, role and workload identity, on its own mount and key.
pub struct OpenBaoTransitHmac {
    provider: Arc<OpenBaoTransitProvider>,
    mount: String,
    key: String,
}

#[derive(Serialize)]
struct HmacRequest<'a> {
    input: &'a str,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    input: &'a str,
    hmac: &'a str,
}

#[derive(Deserialize)]
struct HmacData {
    hmac: String,
}

#[derive(Deserialize)]
struct VerifyData {
    valid: bool,
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

impl OpenBaoTransitHmac {
    /// The key `key` on `mount`. Both must be plain path segments, and the
    /// key is never the envelope key, which is used for nothing but DEKs.
    pub fn new(
        provider: Arc<OpenBaoTransitProvider>,
        mount: String,
        key: String,
    ) -> Result<Self, TransitHmacError> {
        if !valid_bao_segment(&mount) || !valid_bao_segment(&key) || key == DEFAULT_TRANSIT_KEY {
            return Err(TransitHmacError::Unavailable);
        }
        Ok(Self {
            provider,
            mount,
            key,
        })
    }

    /// One POST to `<operation>/<key>/sha2-256` with the service's token.
    async fn post(
        &self,
        operation: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, TransitHmacError> {
        let token = self
            .provider
            .authenticate()
            .await
            .map_err(|_| TransitHmacError::Unavailable)?;
        let url = self
            .provider
            .endpoint(&["v1", &self.mount, operation, &self.key, "sha2-256"])
            .map_err(|_| TransitHmacError::Unavailable)?;
        self.provider
            .http
            .post(url)
            .header("X-Vault-Token", token.as_str())
            .json(body)
            .send()
            .await
            .map_err(|_| TransitHmacError::Unavailable)
    }
}

#[async_trait]
impl TransitHmac for OpenBaoTransitHmac {
    async fn hmac(&self, input: &[u8]) -> Result<String, TransitHmacError> {
        let input = STANDARD.encode(input);
        let response = self.post("hmac", &HmacRequest { input: &input }).await?;
        if !response.status().is_success() {
            return Err(TransitHmacError::Unavailable);
        }
        let answer: Data<HmacData> = decode_bao_response(response, "openbao-hmac-failed")
            .await
            .map_err(|_| TransitHmacError::Unavailable)?;
        parse_transit_version(&answer.data.hmac).ok_or(TransitHmacError::Unavailable)?;
        Ok(answer.data.hmac)
    }

    async fn verify(&self, input: &[u8], seal: &str) -> Result<bool, TransitHmacError> {
        if parse_transit_version(seal).is_none() {
            return Ok(false);
        }
        let input = STANDARD.encode(input);
        let response = self
            .post(
                "verify",
                &VerifyRequest {
                    input: &input,
                    hmac: seal,
                },
            )
            .await?;
        // OpenBao answers 400 for a seal it won't verify, such as one from a
        // version below the key's minimum; anything else unexpected is the
        // authority failing, never a pass and never a refusal.
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            return Ok(false);
        }
        if !response.status().is_success() {
            return Err(TransitHmacError::Unavailable);
        }
        let answer: Data<VerifyData> = decode_bao_response(response, "openbao-verify-failed")
            .await
            .map_err(|_| TransitHmacError::Unavailable)?;
        Ok(answer.data.valid)
    }
}

/// An in-memory transit HMAC key for tests, with OpenBao's versions:
/// [`Self::rotate`] adds one and keeps `min_decryption_version` at the latest
/// minus one, as the operator helper does. Its MAC is a keyed SHA-256 per
/// version, not an HMAC, and protects nothing.
#[cfg(any(test, feature = "platform-test-support"))]
pub struct TestTransitHmac {
    state: std::sync::Mutex<TestKey>,
}

#[cfg(any(test, feature = "platform-test-support"))]
struct TestKey {
    latest: u32,
    min_decryption_version: u32,
    unavailable: bool,
}

#[cfg(any(test, feature = "platform-test-support"))]
impl Default for TestTransitHmac {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(TestKey {
                latest: 1,
                min_decryption_version: 1,
                unavailable: false,
            }),
        }
    }
}

#[cfg(any(test, feature = "platform-test-support"))]
impl TestTransitHmac {
    fn key(&self) -> std::sync::MutexGuard<'_, TestKey> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn rotate(&self) {
        let mut key = self.key();
        key.latest += 1;
        key.min_decryption_version = (key.latest - 1).max(1);
    }

    /// Every call fails as unavailable while this is set.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.key().unavailable = unavailable;
    }

    fn mac(version: u32, input: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"codewire/test-transit-hmac\0");
        hash.update(version.to_be_bytes());
        hash.update(input);
        format!("vault:v{version}:{}", STANDARD.encode(hash.finalize()))
    }
}

#[cfg(any(test, feature = "platform-test-support"))]
#[async_trait]
impl TransitHmac for TestTransitHmac {
    async fn hmac(&self, input: &[u8]) -> Result<String, TransitHmacError> {
        let key = self.key();
        if key.unavailable {
            return Err(TransitHmacError::Unavailable);
        }
        Ok(Self::mac(key.latest, input))
    }

    async fn verify(&self, input: &[u8], seal: &str) -> Result<bool, TransitHmacError> {
        let key = self.key();
        if key.unavailable {
            return Err(TransitHmacError::Unavailable);
        }
        let Some(version) = parse_transit_version(seal) else {
            return Ok(false);
        };
        if version < key.min_decryption_version || version > key.latest {
            return Ok(false);
        }
        Ok(Self::mac(version, input) == seal)
    }
}

#[cfg(test)]
mod tests;
