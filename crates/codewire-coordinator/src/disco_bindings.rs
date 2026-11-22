//! Disco keys bound to the principal and environment that announced them, and
//! the peer relay admission lookup orchestration asks before it allocates a
//! relay slot (#5962).
//!
//! The rules are in `docs/dev/DERP-STUN.md`, "Coordinator sessions and node
//! keys": a disco key is bound as a node key is, in its own bucket, and a
//! session that announces a new one releases its previous one at once. The
//! lookup answers only how a key is bound as seen from the asking
//! environment, never who holds it.

use std::sync::Arc;

use codewire_proto::codewire::internal::v1::{
    CheckDiscoKeyRequest, CheckDiscoKeyResponse, DiscoKeyBinding, PeerRelayAdmissionService,
};
use codewire_tailnet::node::DiscoPublic;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use uuid::Uuid;

use super::CoordinatorState;
use super::node_bindings::{BindingError, BindingStore, Principal};

/// Shared bucket of disco key bindings, keyed by lowercase hex. Its TTL and
/// refresh are the node key bindings'.
pub(crate) const DISCO_BINDING_BUCKET: &str = "coordinator-disco-bindings";

pub(crate) fn disco_hex(key: &DiscoPublic) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in key.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// How a disco key is bound, as seen from one environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Seen {
    /// The environment's own daemon holds it in a live session.
    Here,
    /// Any other live session holds it, the environment's clients included.
    Elsewhere,
    /// No live session holds it.
    Unbound,
}

/// How `key` is bound as `environment` sees it. A binding whose session has
/// ended, such as a key its node rotated away from, holds nothing.
pub(crate) async fn seen(
    store: &dyn BindingStore,
    key: &str,
    environment: Uuid,
) -> Result<Seen, BindingError> {
    let Some(stored) = store.get(key).await? else {
        return Ok(Seen::Unbound);
    };
    let binding = stored.binding;
    if binding.session.is_none() {
        return Ok(Seen::Unbound);
    }
    Ok(
        if binding.principal == Principal::Environment(environment)
            && binding.environment == environment
        {
            Seen::Here
        } else {
            Seen::Elsewhere
        },
    )
}

/// The peer relay admission service, served beside DERP admission on the
/// coordinator's closed 8097 listener.
pub(crate) struct PeerRelayAdmission {
    pub(crate) state: CoordinatorState,
}

#[allow(refining_impl_trait)]
impl PeerRelayAdmissionService for PeerRelayAdmission {
    async fn check_disco_key(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckDiscoKeyRequest>,
    ) -> ServiceResult<CheckDiscoKeyResponse> {
        let request = request.view();
        let raw: [u8; 32] = request
            .disco_key
            .as_ref()
            .try_into()
            .map_err(|_| ConnectError::invalid_argument("disco_key must be 32 bytes"))?;
        let environment = Uuid::parse_str(request.environment_id)
            .map_err(|_| ConnectError::invalid_argument("environment_id must be a UUID"))?;
        let store: Arc<dyn BindingStore> = match self.state.coordination.as_ref() {
            Some(coordination) => Arc::new(coordination.disco_bindings.clone()),
            None => self.state.peers.disco_bindings.clone(),
        };
        let key = disco_hex(&DiscoPublic::from_raw(raw));
        let binding = match seen(store.as_ref(), &key, environment).await {
            Ok(Seen::Here) => DiscoKeyBinding::BoundHere,
            Ok(Seen::Elsewhere) => DiscoKeyBinding::BoundElsewhere,
            Ok(Seen::Unbound) => DiscoKeyBinding::Unbound,
            Err(error) => {
                tracing::warn!(error = ?error, "coordinator disco key lookup failed");
                return Err(ConnectError::unavailable("disco key registry unavailable"));
            }
        };
        connectrpc::Response::ok(CheckDiscoKeyResponse {
            binding: binding.into(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests;
