//! The interception CA and its leaves as this service serves them to
//! orchestration (#4001; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Hosted
//! interception leaves"). The CA and its key belong to the credential
//! service, behind [`InterceptionCas`]; this module authenticates, bounds
//! and records.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_daemon_proto::broker::v1::{
    EnsureInterceptionCaRequest, EnsureInterceptionCaResponse, InterceptionLeaf,
    SignInterceptionLeavesResponse,
};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tonic::Status;
use uuid::Uuid;

use crate::platform::{PlatformRuntimeSession, RuntimeIdentity};

/// Calls one Pod may make per [`WINDOW`], in each replica of this service.
const CALLS_PER_WINDOW: usize = 10;
/// Calls one relay Pod may make per [`WINDOW`]: every Sandbox admission that
/// orchestration replica serves shares it, so it is sized for a burst of
/// starts, not for one Pod (cw-security, #5170).
const CALLER_CALLS_PER_WINDOW: usize = 600;
const WINDOW: Duration = Duration::from_secs(60);
/// The most keys a limiter or the leaf cache holds at once.
const MAX_KEYS: usize = 4096;
/// The longest a leaf lives, whatever its epoch and CA allow.
pub(super) const MAX_LEAF_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_POD_NAME_BYTES: usize = 253;

/// The credential service's interception CAs: the only holder of their keys.
#[async_trait]
pub trait InterceptionCas: Send + Sync {
    /// The Pod's CA certificate, made at the first call after the Pod is
    /// checked live, and the same for the Pod's life.
    async fn ensure(&self, pod_uid: &str, pod_name: &str) -> Result<Vec<u8>, InterceptionCaError>;

    /// One leaf for `hosts`, under the CA attached to `pod_uid` in
    /// `environment_id`, ending at the earliest of `lifetime` and the CA's
    /// own end.
    async fn sign(&self, request: LeafRequest<'_>) -> Result<SignedLeaf, InterceptionCaError>;
}

/// What a leaf is signed for. Every field comes from the caller's
/// authentication or this service's own records, except the public key.
pub struct LeafRequest<'a> {
    pub pod_uid: &'a str,
    pub environment_id: &'a str,
    pub public_key: &'a [u8],
    pub hosts: &'a [&'a str],
    pub lifetime: Duration,
}

pub struct SignedLeaf {
    pub certificate_der: Vec<u8>,
    pub not_after_unix: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptionCaError {
    #[error("interception CA denied")]
    Denied,
    #[error("the leaf key is not an ECDSA P-256 public key")]
    InvalidKey,
    #[error("interception CA unavailable")]
    Unavailable,
}

impl InterceptionCaError {
    fn status(&self) -> Status {
        match self {
            Self::Denied => Status::permission_denied(self.to_string()),
            Self::InvalidKey => Status::invalid_argument(self.to_string()),
            Self::Unavailable => Status::unavailable(self.to_string()),
        }
    }
}

/// The interception half of the bridge service's state.
pub(super) struct Interception {
    cas: Arc<dyn InterceptionCas>,
    callers: Limiter<Uuid>,
    pods: Limiter<Uuid>,
    signing: Limiter<Uuid>,
    leaves: LeafCache,
}

impl Interception {
    pub(super) fn new(cas: Arc<dyn InterceptionCas>) -> Self {
        Self {
            cas,
            callers: Limiter::new(CALLER_CALLS_PER_WINDOW),
            pods: Limiter::new(CALLS_PER_WINDOW),
            signing: Limiter::new(CALLS_PER_WINDOW),
            leaves: LeafCache::default(),
        }
    }

    /// `EnsureInterceptionCa` after its relay-only authentication: the caller
    /// is orchestration's relay Pod.
    pub(super) async fn ensure(
        &self,
        caller: Uuid,
        request: &EnsureInterceptionCaRequest,
    ) -> Result<EnsureInterceptionCaResponse, Status> {
        let pod_uid = canonical_uid(&request.pod_uid)
            .ok_or_else(|| Status::invalid_argument("pod_uid must be a canonical UUID"))?;
        if request.pod_name.is_empty() || request.pod_name.len() > MAX_POD_NAME_BYTES {
            return Err(Status::invalid_argument("pod_name is not a Pod name"));
        }
        let now = Instant::now();
        if !self.callers.admit(&caller, now) || !self.pods.admit(&pod_uid, now) {
            return Err(Status::resource_exhausted(
                "interception CA requests are rate-limited",
            ));
        }
        let ca_certificate_der = self
            .cas
            .ensure(&request.pod_uid, &request.pod_name)
            .await
            .map_err(|error| error.status())?;
        Ok(EnsureInterceptionCaResponse { ca_certificate_der })
    }

    /// `SignInterceptionLeaves` after the full chain: `pod_uid`, the
    /// environment and the epoch come only from that authentication, and
    /// `hosts` only from the session's own grants.
    pub(super) async fn sign(
        &self,
        leaves: LeavesFor<'_>,
    ) -> Result<SignInterceptionLeavesResponse, Status> {
        let now_unix = unix_now()?;
        let remaining = leaves.epoch_expires_at_unix.saturating_sub(now_unix);
        if remaining == 0 {
            return Err(Status::unavailable("the epoch has ended"));
        }
        let key = CacheKey {
            pod_uid: leaves.pod_uid,
            generation: leaves.generation,
            epoch: leaves.epoch_digest,
            public_key: sha256(leaves.public_key),
            hosts: hosts_digest(leaves.hosts),
        };
        if let Some(response) = self.leaves.get(&key, now_unix) {
            return Ok(response);
        }
        if !self.signing.admit(&leaves.pod_uid, Instant::now()) {
            return Err(Status::resource_exhausted(
                "interception leaf requests are rate-limited",
            ));
        }
        let lifetime = MAX_LEAF_LIFETIME.min(Duration::from_secs(remaining));
        let (leaves_signed, not_after_unix) = if leaves.hosts.is_empty() {
            // Nothing this session may intercept: no leaf, asked again at
            // the same half-life.
            (Vec::new(), now_unix + lifetime.as_secs())
        } else {
            let pod_uid = leaves.pod_uid.to_string();
            let environment_id = leaves.environment_id.to_string();
            let hosts: Vec<&str> = leaves.hosts.iter().copied().collect();
            let signed = self
                .cas
                .sign(LeafRequest {
                    pod_uid: &pod_uid,
                    environment_id: &environment_id,
                    public_key: leaves.public_key,
                    hosts: &hosts,
                    lifetime,
                })
                .await
                .map_err(|error| error.status())?;
            tracing::info!(
                pod_uid = %leaves.pod_uid,
                key_sha256 = %hex(&key.public_key),
                hosts = ?hosts,
                expires_at_unix = signed.not_after_unix,
                "interception leaves issued"
            );
            let leaf = InterceptionLeaf {
                certificate_der: signed.certificate_der,
                hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            };
            (vec![leaf], signed.not_after_unix)
        };
        let renew_at_unix = now_unix + not_after_unix.saturating_sub(now_unix) / 2;
        let response = SignInterceptionLeavesResponse {
            leaves: leaves_signed,
            renew_at_unix: i64::try_from(renew_at_unix)
                .map_err(|_| Status::internal("leaf lifetime out of range"))?,
        };
        self.leaves
            .put(key, response.clone(), renew_at_unix, now_unix);
        Ok(response)
    }
}

/// One authenticated leaf request.
pub(super) struct LeavesFor<'a> {
    pub(super) pod_uid: Uuid,
    pub(super) environment_id: Uuid,
    pub(super) generation: u64,
    /// The epoch's handle, hashed: which epoch, without keeping its value.
    pub(super) epoch_digest: [u8; 32],
    pub(super) epoch_expires_at_unix: u64,
    pub(super) public_key: &'a [u8],
    pub(super) hosts: &'a BTreeSet<&'a str>,
}

/// At most `per_window` calls per key in any [`WINDOW`]. When it tracks
/// [`MAX_KEYS`] keys that are all still limited, a new key is refused.
struct Limiter<K> {
    calls: Mutex<HashMap<K, VecDeque<Instant>>>,
    per_window: usize,
}

impl<K: Hash + Eq + Clone> Limiter<K> {
    fn new(per_window: usize) -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
            per_window,
        }
    }

    fn admit(&self, key: &K, now: Instant) -> bool {
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        if calls.len() >= MAX_KEYS && !calls.contains_key(key) {
            calls.retain(|_, window| {
                window
                    .back()
                    .is_some_and(|last| now.duration_since(*last) < WINDOW)
            });
            if calls.len() >= MAX_KEYS {
                return false;
            }
        }
        let window = calls.entry(key.clone()).or_default();
        while window
            .front()
            .is_some_and(|first| now.duration_since(*first) >= WINDOW)
        {
            window.pop_front();
        }
        if window.len() >= self.per_window {
            return false;
        }
        window.push_back(now);
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    pod_uid: Uuid,
    generation: u64,
    epoch: [u8; 32],
    public_key: [u8; 32],
    /// The hosts the session's grants reach now: a grant removed mid-epoch
    /// misses the cache rather than keeping its host until renewal.
    hosts: [u8; 32],
}

/// One live set of leaves per Pod, epoch and key, until its renewal time.
#[derive(Default)]
struct LeafCache {
    sets: Mutex<HashMap<CacheKey, (SignInterceptionLeavesResponse, u64)>>,
}

impl LeafCache {
    fn get(&self, key: &CacheKey, now_unix: u64) -> Option<SignInterceptionLeavesResponse> {
        let sets = self.sets.lock().unwrap_or_else(PoisonError::into_inner);
        sets.get(key)
            .filter(|(_, renew_at)| now_unix < *renew_at)
            .map(|(response, _)| response.clone())
    }

    fn put(
        &self,
        key: CacheKey,
        response: SignInterceptionLeavesResponse,
        renew_at_unix: u64,
        now_unix: u64,
    ) {
        let mut sets = self.sets.lock().unwrap_or_else(PoisonError::into_inner);
        if sets.len() >= MAX_KEYS {
            sets.retain(|_, (_, renew_at)| *renew_at > now_unix);
        }
        if sets.len() < MAX_KEYS {
            sets.insert(key, (response, renew_at_unix));
        }
    }
}

fn canonical_uid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|uid| !uid.is_nil() && uid.hyphenated().to_string() == value)
}

/// The workspace Pod a hosted session authenticated, and no other: the only
/// Pod a leaf request speaks for.
pub(super) fn workspace_pod_uid(session: &PlatformRuntimeSession) -> Option<Uuid> {
    match &session.identity {
        RuntimeIdentity::Hosted { workspace, .. } => Some(workspace.uid),
        RuntimeIdentity::OwnerLocal { .. } => None,
    }
}

fn hosts_digest(hosts: &BTreeSet<&str>) -> [u8; 32] {
    let mut digest = Sha256::new();
    for host in hosts {
        digest.update(host.as_bytes());
        digest.update(b"\n");
    }
    digest.finalize().into()
}

pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| Status::unavailable("clock unavailable"))
}

#[cfg(test)]
mod tests;
