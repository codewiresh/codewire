//! An admission made in one process and enforced in another (#3586, step 3;
//! `docs/dev/AUTH-POLICY.md`, "Account access revocation").
//!
//! The coordinator replica that admits a tailnet client publishes the
//! admission with the client's node; the replica serving the environment
//! fences that peer itself, so ending it never depends on a remove message
//! arriving. A carried admission holds ids and hashes, never a credential, and
//! can only take access away: the receiving replica reads the log itself, and
//! nothing carried admits a peer the receiver would otherwise refuse.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::{
    Admitted, AdmittedCredential, Fence, LogRow, Refused, Watch, current_snapshot,
    recheck_membership,
};

/// Longest id or hash a carried admission may hold. Users, sessions and keys
/// are 32-hex or UUID ids, token hashes 64 hex characters, client ids short
/// names.
const MAX_ID_LEN: usize = 128;

/// An admission as it travels between processes, with the log position the
/// admitting process had read through while the stream was still admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedAdmission {
    user_id: String,
    credential: CarriedCredential,
    /// The organization the stream's environment belongs to. Absent from an
    /// older process's admission, which then ends only on its credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    through: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CarriedCredential {
    Session {
        session_id: String,
    },
    OauthToken {
        token_hash: String,
        client_id: String,
    },
    ApiKey {
        key_id: String,
    },
}

impl CarriedAdmission {
    fn admitted(&self) -> Option<Admitted> {
        let credential = match &self.credential {
            CarriedCredential::Session { session_id } => AdmittedCredential::Session {
                session_id: bounded(session_id)?,
            },
            CarriedCredential::OauthToken {
                token_hash,
                client_id,
            } => AdmittedCredential::OAuthToken {
                token_hash: bounded(token_hash)?,
                client_id: bounded(client_id)?,
            },
            CarriedCredential::ApiKey { key_id } => AdmittedCredential::ApiKey {
                key_id: bounded(key_id)?,
            },
        };
        let organization = match &self.org_id {
            Some(org_id) => Some(bounded(org_id)?),
            None => None,
        };
        Some(Admitted {
            user_id: bounded(&self.user_id)?,
            credential,
            organization,
        })
    }
}

fn bounded(id: &str) -> Option<String> {
    (!id.is_empty() && id.len() <= MAX_ID_LEN).then(|| id.to_owned())
}

/// The log's extent when a carried admission is checked.
#[derive(Debug, sqlx::FromRow)]
struct LogExtent {
    oldest: Option<i64>,
    newest: Option<i64>,
}

impl LogExtent {
    /// Whether every row after `through` is still in the log: `through` is
    /// no newer than the newest row and no older than the row before the
    /// oldest. The writer removes old rows only as it adds one, so an empty
    /// log has never held a row.
    fn can_vouch_for(&self, through: i64) -> bool {
        match (self.oldest, self.newest) {
            (Some(oldest), Some(newest)) => {
                through <= newest && through >= oldest.saturating_sub(1)
            }
            _ => through == 0,
        }
    }
}

impl Fence {
    /// `admitted`, registered as `watch`, for another process to enforce.
    /// `None` before this process's listener has first read the log, and once
    /// `watch` has ended: the position is read first, and the listener ends
    /// streams before it advances the position, so a position past a row
    /// naming the stream is never vouched for.
    pub fn carry(&self, admitted: &Admitted, watch: &Watch) -> Option<CarriedAdmission> {
        let through = self.through.load(std::sync::atomic::Ordering::Acquire);
        if through < 0 || watch.revoked.borrow().is_some() {
            return None;
        }
        let credential = match &admitted.credential {
            AdmittedCredential::Session { session_id } => CarriedCredential::Session {
                session_id: session_id.clone(),
            },
            AdmittedCredential::OAuthToken {
                token_hash,
                client_id,
            } => CarriedCredential::OauthToken {
                token_hash: token_hash.clone(),
                client_id: client_id.clone(),
            },
            AdmittedCredential::ApiKey { key_id } => CarriedCredential::ApiKey {
                key_id: key_id.clone(),
            },
        };
        Some(CarriedAdmission {
            user_id: admitted.user_id.clone(),
            credential,
            org_id: admitted.organization.clone(),
            through,
        })
    }

    /// Fences a stream another process admitted: registers it, then refuses
    /// it if the log names its user, credential or organization after the
    /// carried position, or its user is no longer in that organization. The position comes from a message, so it is refused when it
    /// lies beyond the log's newest row or before its oldest, where rows may
    /// have been removed: an absent row is read as clean only where none can
    /// be missing. A registered stream is fenced from then on, as any other.
    pub async fn admit_carried(
        &self,
        pool: &PgPool,
        carried: &CarriedAdmission,
    ) -> Result<(Admitted, Watch), Refused> {
        let admitted = carried.admitted().ok_or(Refused::Revoked)?;
        let watch = self.register(&admitted, current_snapshot(pool).await?);
        let extent: LogExtent = sqlx::query_as(
            "SELECT min(seq) AS oldest, max(seq) AS newest FROM credential_revocations",
        )
        .fetch_one(pool)
        .await
        .map_err(unavailable)?;
        if !extent.can_vouch_for(carried.through) {
            return Err(Refused::Revoked);
        }
        let keys = admitted.keys();
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT seq, kind, credential_id, user_id, org_id, xact::text AS xact \
             FROM credential_revocations \
             WHERE seq > $1 AND (user_id = $2 OR (kind = 'organization' AND org_id = $3))",
        )
        .bind(carried.through)
        .bind(&admitted.user_id)
        .bind(admitted.organization.as_deref())
        .fetch_all(pool)
        .await
        .map_err(unavailable)?;
        let named = rows
            .iter()
            .filter_map(LogRow::entry)
            .any(|row| keys.contains(&row.key));
        if named {
            return Err(Refused::Revoked);
        }
        if let Some(org_id) = &admitted.organization {
            recheck_membership(pool, &admitted.user_id, org_id).await?;
        }
        Ok((admitted, watch))
    }
}

fn unavailable(error: sqlx::Error) -> Refused {
    tracing::warn!(%error, "a carried stream admission could not read the log");
    Refused::Unavailable
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
