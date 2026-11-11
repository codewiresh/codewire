//! The bound daemon's tailnet and SSH access (Program #2238, daemon-hosted
//! access, design §3 and §5).
//!
//! Everything handed to the sandbox names only public endpoints and the
//! environment's own short-lived identity. The UDP peer-relay allocator and
//! its credential stay here: orchestration allocates on the daemon's behalf.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use codewire_tls::ClientTlsEndpoint;
use serde::{Deserialize, Serialize};

/// Public settings the access grant names.
#[derive(Clone, Debug, Default)]
pub struct AccessSettings {
    /// Public origin of the coordinator's `CoordinatorService` route.
    pub coordinator_url: String,
    /// Public https origin of the hosted Mesh service environments join
    /// networks on. Empty: this platform offers no hosted Mesh to them.
    pub mesh_url: String,
}

/// Length of an `ssh-ed25519` public key blob: the string "ssh-ed25519" and
/// the 32-byte key, each length-prefixed.
const ED25519_BLOB_LEN: usize = 4 + 11 + 4 + 32;

/// Whether `line` is exactly one OpenSSH Ed25519 public key: the algorithm,
/// one space and the canonical base64 blob, with no comment.
pub fn valid_host_key(line: &str) -> bool {
    let Some(("ssh-ed25519", blob)) = line.split_once(' ') else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(blob) else {
        return false;
    };
    bytes.len() == ED25519_BLOB_LEN
        && bytes[..4] == 11u32.to_be_bytes()
        && &bytes[4..15] == b"ssh-ed25519"
        && bytes[15..19] == 32u32.to_be_bytes()
        // Canonical encoding only, so one key has one spelling.
        && base64::engine::general_purpose::STANDARD.encode(&bytes) == blob
}

/// Whether `key` is one canonical tailnet disco public key.
pub fn valid_disco_key(key: &str) -> bool {
    key.strip_prefix("discokey:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The allocator wire request (`codewire-udp-relay` `AllocationRequest`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RelayAllocationRequest {
    pub client_disco: [String; 2],
    pub generation: u32,
}

/// The allocator wire response (`codewire-udp-relay` `AllocationResponse`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RelayAllocation {
    pub generation: u32,
    pub endpoint: RelayEndpoint,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub server_disco: String,
    pub client_disco: [String; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime_ns: u64,
    pub steady_state_lifetime_ns: u64,
    pub addr_ports: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// The allocator refused the request (for example an exhausted pool).
    Refused,
    /// The allocator could not be reached.
    Unavailable,
}

/// Calls the UDP peer-relay allocator with orchestration's own credential.
#[async_trait]
pub trait RelayAllocator: Send + Sync {
    async fn allocate(
        &self,
        allocator_url: &str,
        request: &RelayAllocationRequest,
    ) -> Result<RelayAllocation, RelayError>;
}

const ALLOCATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Orchestration's mounted client certificate for the relay allocator and
/// the public roots that verify the relay (#4011). The files are read again
/// for every allocation, so a rotated leaf needs no restart.
#[derive(Clone, Debug)]
pub struct RelayAllocatorTls {
    pub roots: PathBuf,
    pub cert_chain: PathBuf,
    pub key: PathBuf,
}

/// HTTP allocator client. The allocator is called over mutual TLS with
/// orchestration's client certificate only: an `https` URL and the
/// certificate, or no call at all (#4011).
#[derive(Default)]
pub struct HttpRelayAllocator {
    tls: Option<RelayAllocatorTls>,
}

impl HttpRelayAllocator {
    /// A client with no certificate, which allocates nothing until one is
    /// added with [`Self::with_tls`].
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tls(mut self, tls: RelayAllocatorTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// A client for one allocation at `allocator_url`'s origin, verifying
    /// the relay with the current roots and presenting the current leaf.
    async fn tls_client(&self, allocator_url: &url::Url) -> Result<reqwest::Client, RelayError> {
        let unavailable = |reason: &'static str| {
            tracing::warn!(reason, "UDP relay allocation over TLS is unavailable");
            RelayError::Unavailable
        };
        let tls = self
            .tls
            .as_ref()
            .ok_or_else(|| unavailable("no client certificate is configured"))?;
        // Credentials in the URL would be sent to the relay as Basic auth.
        if !allocator_url.username().is_empty() || allocator_url.password().is_some() {
            return Err(unavailable("the allocator URL carries credentials"));
        }
        let origin = allocator_url.origin().ascii_serialization();
        let config = ClientTlsEndpoint::new(origin, tls.roots.clone())
            .and_then(|endpoint| {
                endpoint.with_client_identity(tls.cert_chain.clone(), tls.key.clone())
            })
            .map_err(|_| unavailable("the allocator URL or TLS paths are invalid"))?
            .rustls_config()
            .await
            .map_err(|_| unavailable("the client certificate or relay roots cannot be read"))?;
        reqwest::Client::builder()
            .timeout(ALLOCATION_TIMEOUT)
            .https_only(true)
            // The certificate is for the configured relay only.
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(config)
            .build()
            .map_err(|_| unavailable("the TLS client could not be built"))
    }
}

#[async_trait]
impl RelayAllocator for HttpRelayAllocator {
    async fn allocate(
        &self,
        allocator_url: &str,
        request: &RelayAllocationRequest,
    ) -> Result<RelayAllocation, RelayError> {
        let url = url::Url::parse(allocator_url).map_err(|_| RelayError::Unavailable)?;
        // The transport-zone catalog refuses any other scheme when it is
        // loaded; this keeps a plain URL from ever being called.
        if url.scheme() != "https" {
            tracing::warn!("UDP relay allocation refused: the allocator URL is not https");
            return Err(RelayError::Unavailable);
        }
        let call = self.tls_client(&url).await?.post(url).json(request);
        let response = call.send().await.map_err(|error| {
            tracing::warn!(error = %error, "UDP relay allocation failed");
            RelayError::Unavailable
        })?;
        match response.status() {
            status if status.is_success() => response
                .json::<RelayAllocation>()
                .await
                .map_err(|_| RelayError::Unavailable),
            status if status.is_client_error() => Err(RelayError::Refused),
            _ => Err(RelayError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn only_one_canonical_ed25519_key_line_is_a_host_key() {
        assert!(valid_host_key(KEY));
        for bad in [
            "",
            "ssh-ed25519",
            &format!("{KEY} comment"),
            &KEY.replacen("ssh-ed25519", "ssh-rsa", 1),
            "ssh-ed25519 AAAA",
            // A valid base64 blob of another algorithm.
            "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0",
            // Non-canonical padding of the same bytes.
            &format!("{KEY}="),
        ] {
            assert!(!valid_host_key(bad), "{bad:?}");
        }
    }

    #[test]
    fn disco_keys_are_canonical_lowercase_hex() {
        let key = format!("discokey:{}", "ab".repeat(32));
        assert!(valid_disco_key(&key));
        assert!(!valid_disco_key(&key.to_uppercase()));
        assert!(!valid_disco_key(&format!("nodekey:{}", "ab".repeat(32))));
        assert!(!valid_disco_key("discokey:ab"));
    }
}

#[cfg(test)]
mod relay_allocator_tests;
