//! The host session's access calls (#3609, slice 3; private-docs
//! designs/2026-11-13-host-direct-access.md, §3): what the tailnet peer of
//! one running VM on the host asks for, as a hosted daemon does over its Pod
//! binding, authorized by the session instead.
//!
//! A call is admitted only on the host's current session, for an environment
//! placed on the host, whose VM the host last reported RUNNING with the local
//! ID and boot generation the call names. The authority it gets is bound to
//! the environment's operation generation, which orchestration assigns and
//! the host never names: the grant's peer token carries it, and the host key
//! is written once per environment and that generation.

use codewire_proto::codewire::v1::{
    HostAccessGrant, HostAccessRefresh, HostAccessRefusal, HostKeyRecord, HostKeyRecorded,
    HostPeerRelayAllocate, attach_host_response,
};
use codewire_server_core::peer_token::{self, PEER_TOKEN_LIFETIME_SECS};
use sqlx::PgPool;

use super::End;
use crate::workspace_binding::valid_host_key;

/// The host capability version from which a session carries access calls.
pub(super) const ACCESS_CAPABILITY: i32 = 3;

/// The longest request ID a host may send, which every answer echoes.
const MAX_REQUEST_ID_BYTES: usize = 64;

/// What the grants of this replica name and are signed with.
pub struct HostAccessSettings {
    /// Signs peer tokens through the key derived for them only.
    pub session_secret: String,
    /// The public coordinator origin a peer joins.
    pub coordinator_url: String,
}

/// The VM an access call names, as the host reported it.
struct Named<'a> {
    request_id: &'a str,
    environment_id: &'a str,
    local_environment_id: &'a str,
    generation: u64,
}

/// Why a call is not answered, as `HostAccessRefusal` carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// Not placed on this host, not this local environment, or asked on a
    /// session that is no longer the host's current one.
    NotHeld,
    /// Not running, or not yet reported running.
    NotRunning,
    /// The host's report is of another boot generation.
    StaleGeneration,
    KeyConflict,
    InvalidKey,
    Unsupported,
    Unavailable,
}

impl Refused {
    fn code(self) -> &'static str {
        match self {
            Refused::NotHeld => "not_held",
            Refused::NotRunning => "not_running",
            Refused::StaleGeneration => "stale_generation",
            Refused::KeyConflict => "key_conflict",
            Refused::InvalidKey => "invalid_key",
            Refused::Unsupported => "unsupported",
            Refused::Unavailable => "unavailable",
        }
    }

    /// Whether the same call may succeed later.
    fn retryable(self) -> bool {
        matches!(self, Refused::NotRunning | Refused::Unavailable)
    }
}

/// What the host, the environment and the host's report say, read together.
#[derive(sqlx::FromRow)]
struct Facts {
    current: bool,
    state: String,
    desired_state: String,
    operation_generation: i64,
    local_environment_id: Option<String>,
    reported_generation: Option<i64>,
    reported_state: Option<String>,
}

/// The facts behind one call: the host's session, the environment placed on
/// it and the host's last report of it. `FOR SHARE` in a transaction holds
/// the host and environment rows until the caller commits.
const FACTS: &str = "SELECT (h.session_generation = $2 AND h.revoked_at IS NULL) AS current, \
     e.state, e.desired_state, e.environment_operation_generation AS operation_generation, \
     he.local_environment_id::text AS local_environment_id, \
     he.generation AS reported_generation, he.state AS reported_state \
     FROM hosts h \
     JOIN environments e ON e.host_id = h.id AND e.id = $3 \
      AND e.runtime_backend = 'host' AND e.deletion_requested_at IS NULL \
     LEFT JOIN host_environments he ON he.host_id = h.id AND he.environment_id = e.id \
     WHERE h.id = $1";

/// The environment's operation generation when the call is admitted.
fn admitted(facts: Option<Facts>, named: &Named<'_>) -> Result<i64, Refused> {
    let Some(facts) = facts else {
        return Err(Refused::NotHeld);
    };
    if !facts.current {
        return Err(Refused::NotHeld);
    }
    match facts.local_environment_id.as_deref() {
        None => return Err(Refused::NotRunning),
        Some(local) if local != named.local_environment_id => return Err(Refused::NotHeld),
        Some(_) => {}
    }
    if facts.reported_generation != i64::try_from(named.generation).ok() {
        return Err(Refused::StaleGeneration);
    }
    if facts.reported_state.as_deref() != Some("running")
        || facts.state != "running"
        || facts.desired_state != "started"
    {
        return Err(Refused::NotRunning);
    }
    if facts.operation_generation <= 0 {
        return Err(Refused::Unavailable);
    }
    Ok(facts.operation_generation)
}

/// A request ID the answer can echo, or the end of a session that sent a
/// malformed one.
fn request_id(value: &str) -> Result<&str, End> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || uuid::Uuid::parse_str(value).is_err()
    {
        return Err(connectrpc::ConnectError::invalid_argument(
            "an access call's request_id is a UUID",
        )
        .into());
    }
    Ok(value)
}

fn refusal(request_id: &str, refused: Refused) -> attach_host_response::Output {
    attach_host_response::Output::AccessRefused(Box::new(HostAccessRefusal {
        request_id: request_id.to_owned(),
        code: refused.code().to_owned(),
        retryable: refused.retryable(),
        ..Default::default()
    }))
}

fn unix_now() -> Option<i64> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    )
    .ok()
}

impl HostAccessSettings {
    /// Answers `access_refresh`: a fresh grant for the VM's tailnet peer.
    pub(super) async fn refresh(
        &self,
        pool: &PgPool,
        host_id: &str,
        session_generation: i64,
        call: &HostAccessRefresh,
    ) -> Result<attach_host_response::Output, End> {
        let named = Named {
            request_id: request_id(&call.request_id)?,
            environment_id: &call.environment_id,
            local_environment_id: &call.local_environment_id,
            generation: call.generation,
        };
        let facts = match sqlx::query_as::<_, Facts>(FACTS)
            .bind(host_id)
            .bind(session_generation)
            .bind(named.environment_id)
            .fetch_optional(pool)
            .await
        {
            Ok(facts) => facts,
            Err(error) => {
                tracing::warn!(%error, "host access facts unavailable");
                return Ok(refusal(named.request_id, Refused::Unavailable));
            }
        };
        let operation_generation = match admitted(facts, &named) {
            Ok(generation) => generation,
            Err(refused) => return Ok(refusal(named.request_id, refused)),
        };
        let Some(expires_at) = unix_now().map(|now| now.saturating_add(PEER_TOKEN_LIFETIME_SECS))
        else {
            return Ok(refusal(named.request_id, Refused::Unavailable));
        };
        let Ok(peer_token) = peer_token::issue(
            &self.session_secret,
            named.environment_id,
            operation_generation,
            expires_at,
        ) else {
            return Ok(refusal(named.request_id, Refused::Unavailable));
        };
        tracing::info!(
            host_id,
            environment_id = named.environment_id,
            operation_generation,
            "host access grant issued"
        );
        Ok(attach_host_response::Output::AccessGrant(Box::new(
            HostAccessGrant {
                request_id: named.request_id.to_owned(),
                peer_token,
                peer_token_expires_at: expires_at,
                operation_generation,
                coordinator_url: self.coordinator_url.clone(),
                // The host's peers serve no application ports yet.
                app_ports: Vec::new(),
                ..Default::default()
            },
        )))
    }

    /// Answers `host_key_record`: the VM's SSH host key, written once per
    /// environment and operation generation.
    pub(super) async fn record_host_key(
        &self,
        pool: &PgPool,
        host_id: &str,
        session_generation: i64,
        call: &HostKeyRecord,
    ) -> Result<attach_host_response::Output, End> {
        let named = Named {
            request_id: request_id(&call.request_id)?,
            environment_id: &call.environment_id,
            local_environment_id: &call.local_environment_id,
            generation: call.generation,
        };
        if !valid_host_key(&call.public_key_openssh) {
            return Ok(refusal(named.request_id, Refused::InvalidKey));
        }
        let recorded = record_once(
            pool,
            host_id,
            session_generation,
            &named,
            &call.public_key_openssh,
        )
        .await;
        Ok(match recorded {
            Ok(operation_generation) => {
                tracing::info!(
                    host_id,
                    environment_id = named.environment_id,
                    operation_generation,
                    "host environment SSH host key recorded"
                );
                attach_host_response::Output::HostKeyRecorded(Box::new(HostKeyRecorded {
                    request_id: named.request_id.to_owned(),
                    ..Default::default()
                }))
            }
            Err(refused) => refusal(named.request_id, refused),
        })
    }
}

/// Answers `peer_relay_allocate`: this control plane has no peer relay for
/// hosts, so the peer uses DERP.
pub(super) fn allocate_peer_relay(
    call: &HostPeerRelayAllocate,
) -> Result<attach_host_response::Output, End> {
    Ok(refusal(request_id(&call.request_id)?, Refused::Unsupported))
}

/// The answer of a replica that issues no grants.
pub(super) fn unavailable(request_id_value: &str) -> Result<attach_host_response::Output, End> {
    Ok(refusal(request_id(request_id_value)?, Refused::Unavailable))
}

/// Records `public_key` for the named VM once per environment and operation
/// generation, in one transaction with the facts that admit it. The same key
/// again is accepted; another one is a conflict.
async fn record_once(
    pool: &PgPool,
    host_id: &str,
    session_generation: i64,
    named: &Named<'_>,
    public_key: &str,
) -> Result<i64, Refused> {
    let unavailable = |error: sqlx::Error| {
        tracing::warn!(%error, "host environment SSH host key storage failed");
        Refused::Unavailable
    };
    let mut transaction = pool.begin().await.map_err(unavailable)?;
    let facts = sqlx::query_as::<_, Facts>(&format!("{FACTS} FOR SHARE OF h, e"))
        .bind(host_id)
        .bind(session_generation)
        .bind(named.environment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
    let operation_generation = admitted(facts, named)?;
    sqlx::query(
        "INSERT INTO host_environment_ssh_host_keys \
         (environment_id, operation_generation, host_id, public_key) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (environment_id, operation_generation) DO NOTHING",
    )
    .bind(named.environment_id)
    .bind(operation_generation)
    .bind(host_id)
    .bind(public_key)
    .execute(&mut *transaction)
    .await
    .map_err(unavailable)?;
    let stored: String = sqlx::query_scalar(
        "SELECT public_key FROM host_environment_ssh_host_keys \
         WHERE environment_id = $1 AND operation_generation = $2",
    )
    .bind(named.environment_id)
    .bind(operation_generation)
    .fetch_one(&mut *transaction)
    .await
    .map_err(unavailable)?;
    transaction.commit().await.map_err(unavailable)?;
    if stored == public_key {
        Ok(operation_generation)
    } else {
        Err(Refused::KeyConflict)
    }
}

#[cfg(test)]
mod tests;
