//! Node keys of live coordinator sessions, for DERP client admission (#2844).
//!
//! The public DERP relay serves only node keys a coordinator registered for
//! an authorized session. Each session records its current node key in a
//! shared NATS KV bucket while it lives, so any replica can answer for a
//! session another replica holds; without NATS the local registry answers.
//! DERP asks through the internal `codewire.internal.v1.DerpAdmissionService`
//! on a separate listener ([`router`]) that no edge route reaches. A bucket
//! that cannot be read is `unavailable`, never an answer.

use std::sync::Arc;
use std::time::Duration;

use async_nats::HeaderMap;
use async_nats::jetstream::stream::LastRawMessageErrorKind;
use bytes::Bytes;
use codewire_proto::codewire::internal::v1::{
    CheckNodeKeyRequest, CheckNodeKeyResponse, DerpAdmissionService,
};
use codewire_tailnet::node::NodePublic;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use super::{CoordinationPlane, CoordinatorState};

/// Shared bucket of registered node keys, keyed by lowercase hex.
pub(crate) const NODE_KEY_BUCKET: &str = "coordinator-node-keys";
/// A key a session stops refreshing (its replica died) expires after this.
pub(crate) const NODE_KEY_TTL: Duration = Duration::from_secs(15 * 60);
/// How often a live session rewrites its key.
const NODE_KEY_REFRESH: Duration = Duration::from_secs(5 * 60);

/// The DERP admission listener's only service.
pub fn router(state: CoordinatorState) -> axum::Router {
    codewire_server_core::connect::connect_router(
        connectrpc::Router::new().add_service(Arc::new(DerpAdmission { state })),
    )
}

struct DerpAdmission {
    state: CoordinatorState,
}

#[allow(refining_impl_trait)]
impl DerpAdmissionService for DerpAdmission {
    async fn check_node_key(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckNodeKeyRequest>,
    ) -> ServiceResult<CheckNodeKeyResponse> {
        let raw: [u8; 32] = request
            .view()
            .node_key
            .as_ref()
            .try_into()
            .map_err(|_| ConnectError::invalid_argument("node_key must be 32 bytes"))?;
        let registered = registered(&self.state, &NodePublic::from_raw(raw))
            .await
            .map_err(|error| {
                tracing::warn!(error = ?error, "coordinator node key lookup failed");
                ConnectError::unavailable("node key registry unavailable")
            })?;
        connectrpc::Response::ok(CheckNodeKeyResponse {
            registered,
            ..Default::default()
        })
    }
}

/// Whether a live session on any replica has sent a node with `key`.
async fn registered(state: &CoordinatorState, key: &NodePublic) -> anyhow::Result<bool> {
    if state.peers.knows_key(key) {
        return Ok(true);
    }
    match state.coordination.as_ref() {
        Some(coordination) => coordination.node_key_registered(key).await,
        None => Ok(false),
    }
}

pub(crate) fn key_hex(key: &NodePublic) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in key.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Whether a bucket's last message for a key holds a value: a put carries no
/// operation or `PUT`; a delete, purge or expiry marker says otherwise.
fn is_live_value(headers: &HeaderMap) -> bool {
    headers
        .get(async_nats::header::NATS_MARKER_REASON)
        .is_none()
        && headers
            .get("KV-Operation")
            .is_none_or(|operation| operation.as_str() == "PUT")
}

impl CoordinationPlane {
    /// Records `key` for the session `owner`.
    pub(crate) async fn put_node_key(&self, key: &NodePublic, owner: Uuid) -> anyhow::Result<()> {
        self.node_keys
            .put(key_hex(key), Bytes::from(owner.to_string()))
            .await?;
        Ok(())
    }

    /// Removes `key` while `owner` still holds it, so a session that ends
    /// after another session took over the same key leaves that one alone.
    pub(crate) async fn delete_node_key(
        &self,
        key: &NodePublic,
        owner: Uuid,
    ) -> anyhow::Result<()> {
        let name = key_hex(key);
        let Some(entry) = self.node_keys.entry(name.clone()).await? else {
            return Ok(());
        };
        if entry.value.as_ref() == owner.to_string().as_bytes() {
            // A concurrent rewrite moves the revision and the delete is
            // refused, which is the outcome wanted.
            let _ = self
                .node_keys
                .delete_expect_revision(name, Some(entry.revision))
                .await;
        }
        Ok(())
    }

    /// A replicated bucket answers reads from any replica, and a follower can
    /// trail a fresh write by milliseconds (#3542). So a key no replica has
    /// is asked of the stream's leader before DERP is told it is unknown.
    pub(crate) async fn node_key_registered(&self, key: &NodePublic) -> anyhow::Result<bool> {
        let name = key_hex(key);
        if self.node_keys.get(&name).await?.is_some() {
            return Ok(true);
        }
        let subject = format!("{}{name}", self.node_keys.prefix);
        match self
            .node_keys
            .stream
            .get_last_raw_message_by_subject(&subject)
            .await
        {
            Ok(message) => Ok(is_live_value(&message.headers)),
            Err(error) if error.kind() == LastRawMessageErrorKind::NoMessageFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// One session's registered node key: written when the session sends a node
/// with a new key, rewritten while it lives, removed when it ends.
pub(crate) struct SessionNodeKey {
    coordination: Option<Arc<CoordinationPlane>>,
    owner: Uuid,
    current: Arc<AsyncMutex<Option<NodePublic>>>,
    refresh: Option<tokio::task::JoinHandle<()>>,
}

impl SessionNodeKey {
    pub(crate) fn new(coordination: Option<Arc<CoordinationPlane>>, owner: Uuid) -> Self {
        let current = Arc::new(AsyncMutex::new(None::<NodePublic>));
        let refresh = coordination.clone().map(|coordination| {
            let current = current.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(NODE_KEY_REFRESH).await;
                    let key = *current.lock().await;
                    if let Some(key) = key
                        && let Err(error) = coordination.put_node_key(&key, owner).await
                    {
                        tracing::warn!(error = ?error, "coordinator node key refresh failed");
                    }
                }
            })
        });
        Self {
            coordination,
            owner,
            current,
            refresh,
        }
    }

    /// Records the key of a node the session just sent.
    pub(crate) async fn observe(&self, key: NodePublic) {
        let mut current = self.current.lock().await;
        if *current == Some(key) {
            return;
        }
        let previous = current.replace(key);
        let Some(coordination) = self.coordination.as_ref() else {
            return;
        };
        if let Err(error) = coordination.put_node_key(&key, self.owner).await {
            tracing::warn!(error = ?error, "coordinator node key put failed");
        }
        if let Some(previous) = previous
            && let Err(error) = coordination.delete_node_key(&previous, self.owner).await
        {
            tracing::warn!(error = ?error, "coordinator node key delete failed");
        }
    }

    /// Ends the record when the session ends.
    pub(crate) async fn close(mut self) {
        if let Some(refresh) = self.refresh.take() {
            refresh.abort();
        }
        let key = self.current.lock().await.take();
        if let (Some(key), Some(coordination)) = (key, self.coordination.as_ref())
            && let Err(error) = coordination.delete_node_key(&key, self.owner).await
        {
            tracing::warn!(error = ?error, "coordinator node key delete failed");
        }
    }
}

impl Drop for SessionNodeKey {
    fn drop(&mut self) {
        if let Some(refresh) = self.refresh.take() {
            refresh.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_is_lowercase_hex() {
        assert_eq!(key_hex(&NodePublic::from_raw([0x0f; 32])), "0f".repeat(32));
    }

    #[test]
    fn only_a_put_is_a_live_value() {
        let with = |name: &str, value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(name, value);
            headers
        };
        assert!(is_live_value(&HeaderMap::new()));
        assert!(is_live_value(&with("KV-Operation", "PUT")));
        assert!(!is_live_value(&with("KV-Operation", "DEL")));
        assert!(!is_live_value(&with("KV-Operation", "PURGE")));
        assert!(!is_live_value(&with("Nats-Marker-Reason", "MaxAge")));
    }

    /// An unknown key and a removed one both miss on the direct read and are
    /// answered by the leader: no message, and a delete marker.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_registered_key_is_found_and_an_unknown_or_removed_one_is_not() {
        let nats_url =
            std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
        let replicas = std::env::var("NATS_KV_REPLICAS").map_or(1, |raw| raw.parse().unwrap());
        let client = async_nats::connect(nats_url).await.unwrap();
        let plane = CoordinationPlane::setup(client, replicas).await.unwrap();
        let mut raw = [0_u8; 32];
        raw[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        raw[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let key = NodePublic::from_raw(raw);
        let owner = Uuid::new_v4();

        assert!(!plane.node_key_registered(&key).await.unwrap());
        plane.put_node_key(&key, owner).await.unwrap();
        assert!(plane.node_key_registered(&key).await.unwrap());
        plane.delete_node_key(&key, owner).await.unwrap();
        assert!(!plane.node_key_registered(&key).await.unwrap());
    }
}
