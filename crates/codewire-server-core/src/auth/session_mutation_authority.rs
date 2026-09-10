//! Exact browser-session authority retained for credential mutation publication.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use std::time::{Duration, Instant};

use super::{OAuthBearerAuthority, OAuthBearerAuthorityError};

const PUBLICATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Authority admitted specifically for `CredentialMutationService`.
///
/// It is process-local and nonserializable. The session variant retains only
/// the stored digest and exact row identity, never the browser cookie.
#[derive(Clone)]
pub struct CredentialMutationAuthority(CredentialMutationAuthorityKind);

#[derive(Clone)]
enum CredentialMutationAuthorityKind {
    Session(SessionCredentialMutationAuthority),
    OAuth(OAuthBearerAuthority),
}

impl std::fmt::Debug for CredentialMutationAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialMutationAuthority([redacted])")
    }
}

#[derive(Clone)]
pub(super) struct SessionCredentialMutationAuthority {
    session_id: String,
    digest: String,
    user_id: String,
    expires_at: DateTime<Utc>,
    monotonic_expires_at: Instant,
}

impl std::fmt::Debug for SessionCredentialMutationAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionCredentialMutationAuthority([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CredentialMutationAuthorityError {
    #[error("original credential-mutation authority is no longer valid")]
    Denied,
    #[error("credential-mutation publication admission unavailable")]
    Unavailable,
}

impl SessionCredentialMutationAuthority {
    pub(super) fn new(
        session_id: String,
        digest: String,
        user_id: String,
        expires_at: DateTime<Utc>,
        captured_monotonic: Instant,
        captured_wall: DateTime<Utc>,
    ) -> Option<Self> {
        let lifetime = (expires_at - captured_wall).to_std().ok()?;
        let authority = Self {
            session_id,
            digest,
            user_id,
            expires_at,
            monotonic_expires_at: captured_monotonic.checked_add(lifetime)?,
        };
        authority.remaining_lifetime().ok()?;
        Some(authority)
    }

    fn remaining_lifetime(&self) -> Result<Duration, CredentialMutationAuthorityError> {
        self.remaining_at(Instant::now(), Utc::now())
    }

    fn remaining_at(
        &self,
        monotonic: Instant,
        wall: DateTime<Utc>,
    ) -> Result<Duration, CredentialMutationAuthorityError> {
        let elapsed = self
            .monotonic_expires_at
            .saturating_duration_since(monotonic);
        let wall = (self.expires_at - wall)
            .to_std()
            .map_err(|_| CredentialMutationAuthorityError::Denied)?;
        let remaining = elapsed.min(wall);
        if remaining.is_zero() {
            Err(CredentialMutationAuthorityError::Denied)
        } else {
            Ok(remaining)
        }
    }

    async fn lock_for_publication(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), CredentialMutationAuthorityError> {
        let remaining = self.remaining_lifetime()?;
        let deadline = Instant::now() + remaining.min(PUBLICATION_LOCK_TIMEOUT);
        let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let millis = deadline.saturating_duration_since(Instant::now()).as_millis();
            if millis == 0 {
                return Err(CredentialMutationAuthorityError::Denied);
            }
            let settings: Vec<String> = sqlx::query_scalar(
                "SELECT pg_catalog.set_config(name, LEAST($1::bigint, CASE WHEN setting::bigint=0 THEN $1::bigint ELSE setting::bigint END)::text, true) FROM pg_catalog.pg_settings WHERE name IN ('statement_timeout','idle_in_transaction_session_timeout') AND unit='ms'",
            )
            .bind(millis as i64)
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| CredentialMutationAuthorityError::Unavailable)?;
            if settings.len() != 2 {
                return Err(CredentialMutationAuthorityError::Unavailable);
            }
            self.remaining_lifetime()?;
            let accepted: bool = sqlx::query_scalar(
                "SELECT public.codewire_lock_credential_session_authority($1::text,$2::text,$3::text,$4::timestamptz)",
            )
            .bind(&self.session_id)
            .bind(&self.digest)
            .bind(&self.user_id)
            .bind(self.expires_at)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| CredentialMutationAuthorityError::Unavailable)?;
            if accepted {
                Ok(())
            } else {
                Err(CredentialMutationAuthorityError::Denied)
            }
        })
        .await;
        self.remaining_lifetime()?;
        match outcome {
            Ok(result) => result,
            Err(_) if remaining <= PUBLICATION_LOCK_TIMEOUT => {
                Err(CredentialMutationAuthorityError::Denied)
            }
            Err(_) => Err(CredentialMutationAuthorityError::Unavailable),
        }
    }
}

impl CredentialMutationAuthority {
    pub(super) fn from_session(authority: SessionCredentialMutationAuthority) -> Self {
        Self(CredentialMutationAuthorityKind::Session(authority))
    }

    pub fn user_id(&self) -> &str {
        match &self.0 {
            CredentialMutationAuthorityKind::Session(authority) => &authority.user_id,
            CredentialMutationAuthorityKind::OAuth(authority) => authority.user_id(),
        }
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        match &self.0 {
            CredentialMutationAuthorityKind::Session(authority) => authority.expires_at,
            CredentialMutationAuthorityKind::OAuth(authority) => authority.expires_at(),
        }
    }

    pub fn remaining_lifetime(&self) -> Result<Duration, CredentialMutationAuthorityError> {
        match &self.0 {
            CredentialMutationAuthorityKind::Session(authority) => authority.remaining_lifetime(),
            CredentialMutationAuthorityKind::OAuth(authority) => {
                authority.remaining_lifetime().map_err(Into::into)
            }
        }
    }

    pub async fn lock_for_publication(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), CredentialMutationAuthorityError> {
        match &self.0 {
            CredentialMutationAuthorityKind::Session(authority) => {
                authority.lock_for_publication(tx).await
            }
            CredentialMutationAuthorityKind::OAuth(authority) => {
                authority.lock_for_publication(tx).await.map_err(Into::into)
            }
        }
    }
}

impl From<OAuthBearerAuthority> for CredentialMutationAuthority {
    fn from(authority: OAuthBearerAuthority) -> Self {
        Self(CredentialMutationAuthorityKind::OAuth(authority))
    }
}

impl From<OAuthBearerAuthorityError> for CredentialMutationAuthorityError {
    fn from(error: OAuthBearerAuthorityError) -> Self {
        match error {
            OAuthBearerAuthorityError::Denied => Self::Denied,
            OAuthBearerAuthorityError::Unavailable => Self::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_authority_is_redacted_and_has_a_fixed_deadline() {
        let monotonic = Instant::now();
        let wall = Utc::now();
        let authority = SessionCredentialMutationAuthority::new(
            "session-id-canary".into(),
            "digest-canary".into(),
            "user-canary".into(),
            wall + chrono::Duration::minutes(1),
            monotonic,
            wall,
        )
        .unwrap();
        assert_eq!(authority.user_id, "user-canary");
        let debug = format!(
            "{authority:?} {:?}",
            CredentialMutationAuthority::from_session(authority.clone())
        );
        assert!(!debug.contains("session-id-canary"));
        assert!(!debug.contains("digest-canary"));
        assert!(!debug.contains("user-canary"));
        assert_eq!(
            authority
                .remaining_at(
                    monotonic + Duration::from_secs(30),
                    wall + chrono::Duration::seconds(20)
                )
                .unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            authority.remaining_at(monotonic + Duration::from_secs(60), wall),
            Err(CredentialMutationAuthorityError::Denied)
        );
        assert_eq!(
            authority.remaining_at(monotonic, wall + chrono::Duration::seconds(60)),
            Err(CredentialMutationAuthorityError::Denied)
        );
    }
}
