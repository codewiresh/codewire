//! A client's tailnet session ends when the credential that admitted it is
//! lost, and every replica serving its environment drops it as a peer on its
//! own read of the revocation log (#3586, step 3;
//! `docs/dev/AUTH-POLICY.md`, "Account access revocation";
//! `docs/journeys/account-access.md`, `access-tailnet`).

use std::collections::{HashMap, HashSet};

use codewire_server_core::revocation::{
    Admitted, CarriedAdmission, Fence, Refused, Revocation, StreamSite, Watch, record_revoked,
};
use codewire_tailnet::node::Node;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// The process's fence and the database its log lives in.
#[derive(Clone)]
pub(crate) struct Revocations {
    pub(crate) fence: Fence,
    pub(crate) pool: PgPool,
}

/// A client session's admission, fenced on the replica that admitted it.
pub(crate) struct FencedClient {
    admitted: Admitted,
    watch: Watch,
}

impl FencedClient {
    pub(crate) fn new(admitted: Admitted, watch: Watch) -> Self {
        Self { admitted, watch }
    }
}

/// Completes when the session's credential is lost; never for a session
/// with none fenced.
pub(super) async fn revoked(fenced: &mut Option<FencedClient>) -> Revocation {
    match fenced {
        Some(fenced) => fenced.watch.revoked().await,
        None => std::future::pending().await,
    }
}

impl Revocations {
    /// The admission the other replicas fence this client's node under.
    pub(super) fn carry(&self, fenced: Option<&FencedClient>) -> Option<CarriedAdmission> {
        fenced.and_then(|fenced| self.fence.carry(&fenced.admitted, &fenced.watch))
    }

    pub(super) async fn record(&self, fenced: &FencedClient, revocation: Revocation, env_id: Uuid) {
        record_revoked(
            &self.pool,
            &fenced.admitted,
            revocation,
            &StreamSite {
                surface: "tailnet",
                environment_id: Some(env_id.to_string()),
            },
        )
        .await;
    }
}

/// A client node as published to the other replicas, with the admission
/// they fence it under. Older replicas read the node and skip the rest.
#[derive(Serialize, Deserialize)]
pub(crate) struct ClientNodeMessage {
    #[serde(flatten)]
    pub(crate) node: Node,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admission: Option<CarriedAdmission>,
}

/// The client peers from other replicas an environment session serves, each
/// fenced here, so dropping one never waits on a message from the replica
/// that admitted it.
#[derive(Default)]
pub(super) struct RemoteClients {
    fenced: HashMap<Uuid, Watch>,
    /// Peers this replica refused or dropped; their later nodes are not
    /// forwarded. Cleared as each peer's session is removed.
    refused: HashSet<Uuid>,
    /// Peers forwarded without an admission, each logged once, so their
    /// count shows when every replica sends one and they can be refused
    /// (cw-security's condition on #3586).
    unfenced: HashSet<Uuid>,
}

impl RemoteClients {
    /// Whether to hand `peer_id`'s node to the environment. A peer is
    /// admitted once and fenced from then on. A node without an admission
    /// comes from a replica that predates carrying one, and is forwarded until
    /// every replica sends it (AUTH-POLICY). A check that couldn't be read
    /// forwards nothing; the client's next node tries again.
    pub(super) async fn admit(
        &mut self,
        revocations: &Revocations,
        peer_id: Uuid,
        admission: Option<&CarriedAdmission>,
    ) -> bool {
        if self.refused.contains(&peer_id) {
            return false;
        }
        if self.fenced.contains_key(&peer_id) {
            return true;
        }
        let Some(admission) = admission else {
            if self.unfenced.insert(peer_id) {
                tracing::info!(
                    %peer_id,
                    unfenced_remote_client = true,
                    "coordinator forwarded a remote client node without an admission"
                );
            }
            return true;
        };
        match revocations
            .fence
            .admit_carried(&revocations.pool, admission)
            .await
        {
            Ok((_, watch)) => {
                self.fenced.insert(peer_id, watch);
                true
            }
            Err(Refused::Revoked | Refused::NotMember | Refused::OrganizationDeleting) => {
                self.refused.insert(peer_id);
                false
            }
            Err(Refused::Unavailable) => false,
        }
    }

    /// Forgets a peer whose session ended.
    pub(super) fn remove(&mut self, peer_id: Uuid) {
        self.fenced.remove(&peer_id);
        self.refused.remove(&peer_id);
        self.unfenced.remove(&peer_id);
    }

    /// The next fenced peer whose credential is lost, now refused; pending
    /// while none is.
    pub(super) async fn next_revoked(&mut self) -> Uuid {
        if self.fenced.is_empty() {
            return std::future::pending().await;
        }
        let (peer_id, _, _) =
            futures_util::future::select_all(self.fenced.iter_mut().map(|(peer_id, watch)| {
                let peer_id = *peer_id;
                Box::pin(async move {
                    watch.revoked().await;
                    peer_id
                })
            }))
            .await;
        self.fenced.remove(&peer_id);
        self.refused.insert(peer_id);
        peer_id
    }
}

#[cfg(test)]
mod tests;
