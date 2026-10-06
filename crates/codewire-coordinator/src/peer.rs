//! Environment peer proofs (Program #2238, daemon-hosted access).
//!
//! An environment's in-sandbox daemon is its tailnet peer. It authenticates
//! with a short-lived peer token bound to the environment's operation
//! generation ([`codewire_server_core::peer_token`]), must re-prove in-band
//! before its last proven token expires, and loses its session as soon as
//! the generation moves on or the environment is being destroyed.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use codewire_server_core::peer_token::{self, PEER_TOKEN_LEEWAY_SECS, PeerClaims, PeerTokenError};
use sqlx::PgPool;
use uuid::Uuid;

/// How often a live environment-peer session re-checks its generation and
/// environment state, and its proof deadline.
pub(crate) const PEER_RECHECK_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What an environment-peer session has proven: its generation, and the
/// latest expiry among the tokens it presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerProof {
    pub(crate) generation: i64,
    pub(crate) expires_at: i64,
}

impl PeerProof {
    /// Order of competing sessions for one environment: a newer generation,
    /// then a later proven expiry, wins.
    pub(crate) fn rank(self) -> (i64, i64) {
        (self.generation, self.expires_at)
    }

    /// Whether the proof has lapsed at unix second `now`.
    pub(crate) fn lapsed(self, now: i64) -> bool {
        self.expires_at + PEER_TOKEN_LEEWAY_SECS < now
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofError {
    /// The token or the environment refuses this peer; end the session.
    Refused,
    /// The records could not be read; keep the session and retry later.
    Unavailable,
}

/// The checks an environment-peer session needs, behind a seam so sessions
/// are tested without a database.
pub(crate) trait PeerVerifier: Send + Sync {
    /// Validates a peer token for `env_id` and returns its proof: signature,
    /// claims and expiry window, then the environment's current generation
    /// and state.
    fn verify<'a>(
        &'a self,
        env_id: Uuid,
        token: &'a str,
    ) -> BoxFuture<'a, Result<PeerProof, ProofError>>;

    /// Whether `generation` is still the environment's current operation
    /// generation and the environment is not being destroyed.
    fn is_current<'a>(
        &'a self,
        env_id: Uuid,
        generation: i64,
    ) -> BoxFuture<'a, Result<bool, ProofError>>;
}

/// Unix seconds now.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default()
}

/// Production verifier over the shared session secret and database.
pub(crate) struct DbPeerVerifier {
    pool: PgPool,
    session_secret: std::sync::Arc<str>,
}

impl DbPeerVerifier {
    pub(crate) fn new(pool: PgPool, session_secret: std::sync::Arc<str>) -> Self {
        Self {
            pool,
            session_secret,
        }
    }

    async fn current_generation(&self, env_id: Uuid) -> Result<Option<i64>, ProofError> {
        sqlx::query_scalar::<_, i64>(
            r#"SELECT environment_operation_generation
                 FROM environments
                WHERE id = $1
                  AND type = 'sandbox'
                  AND state NOT IN ('destroyed', 'destroying')
                  AND deletion_requested_at IS NULL"#,
        )
        .bind(env_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, %env_id, "coordinator peer generation lookup failed");
            ProofError::Unavailable
        })
    }
}

/// Validates a token for `env_id` against `current` (the environment's
/// current generation, `None` when it is gone or being destroyed).
pub(crate) fn check_claims(
    claims: &PeerClaims,
    env_id: Uuid,
    current: Option<i64>,
) -> Result<PeerProof, ProofError> {
    if claims.environment_id != env_id.to_string() || current != Some(claims.generation) {
        return Err(ProofError::Refused);
    }
    Ok(PeerProof {
        generation: claims.generation,
        expires_at: claims.expires_at,
    })
}

impl PeerVerifier for DbPeerVerifier {
    fn verify<'a>(
        &'a self,
        env_id: Uuid,
        token: &'a str,
    ) -> BoxFuture<'a, Result<PeerProof, ProofError>> {
        Box::pin(async move {
            let claims = peer_token::validate(&self.session_secret, token, unix_now())
                .map_err(|_: PeerTokenError| ProofError::Refused)?;
            if claims.environment_id != env_id.to_string() {
                return Err(ProofError::Refused);
            }
            let current = self.current_generation(env_id).await?;
            check_claims(&claims, env_id, current)
        })
    }

    fn is_current<'a>(
        &'a self,
        env_id: Uuid,
        generation: i64,
    ) -> BoxFuture<'a, Result<bool, ProofError>> {
        Box::pin(async move { Ok(self.current_generation(env_id).await? == Some(generation)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn claims(generation: i64) -> PeerClaims {
        PeerClaims {
            environment_id: ENV.into(),
            generation,
            expires_at: 1_000,
        }
    }

    #[test]
    fn claims_must_name_the_environment_at_its_current_generation() {
        let env = Uuid::parse_str(ENV).unwrap();
        assert_eq!(
            check_claims(&claims(4), env, Some(4)),
            Ok(PeerProof {
                generation: 4,
                expires_at: 1_000
            })
        );
        // A stale generation, a destroyed environment or another environment.
        assert_eq!(
            check_claims(&claims(3), env, Some(4)),
            Err(ProofError::Refused)
        );
        assert_eq!(
            check_claims(&claims(4), env, None),
            Err(ProofError::Refused)
        );
        assert_eq!(
            check_claims(&claims(4), Uuid::new_v4(), Some(4)),
            Err(ProofError::Refused)
        );
    }

    #[test]
    fn rank_prefers_newer_generations_then_later_expiry() {
        let older = PeerProof {
            generation: 4,
            expires_at: 2_000,
        };
        let newer_generation = PeerProof {
            generation: 5,
            expires_at: 1_000,
        };
        let later = PeerProof {
            generation: 4,
            expires_at: 2_001,
        };
        assert!(newer_generation.rank() > older.rank());
        assert!(later.rank() > older.rank());
        assert!(older.lapsed(2_000 + PEER_TOKEN_LEEWAY_SECS + 1));
        assert!(!older.lapsed(2_000 + PEER_TOKEN_LEEWAY_SECS));
    }
}
