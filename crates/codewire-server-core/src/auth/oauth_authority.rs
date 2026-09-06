//! Original OAuth authority retained without retaining or replaying its bearer.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use std::time::{Duration, Instant};

const PUBLICATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// A reference to exactly the OAuth token authenticated by the shared policy.
///
/// Only shared authentication constructs this value. It is process-local,
/// nonserializable and deliberately exposes neither its digest nor a bearer.
/// It is not a new credential, a refresh token, or authority to change owner.
#[derive(Clone)]
pub struct OAuthBearerAuthority {
    digest: String,
    user_id: String,
    client_id: String,
    expires_at: DateTime<Utc>,
    monotonic_expires_at: Instant,
}

impl std::fmt::Debug for OAuthBearerAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthBearerAuthority([redacted])")
    }
}

/// Closed publication-admission failures with no database or credential source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuthBearerAuthorityError {
    #[error("original OAuth authority is no longer valid")]
    Denied,
    #[error("OAuth publication admission unavailable")]
    Unavailable,
}

impl OAuthBearerAuthority {
    pub(super) fn new(
        digest: String,
        user_id: String,
        client_id: String,
        expires_at: DateTime<Utc>,
        captured_monotonic: Instant,
        captured_wall: DateTime<Utc>,
    ) -> Option<Self> {
        let lifetime = (expires_at - captured_wall).to_std().ok()?;
        let authority = Self {
            digest,
            user_id,
            client_id,
            expires_at,
            monotonic_expires_at: captured_monotonic.checked_add(lifetime)?,
        };
        authority.remaining_at(Instant::now(), Utc::now()).ok()?;
        Some(authority)
    }

    /// Immutable original token deadline. A stream must additionally retain its
    /// own original duration limit; receiving a challenge never extends either.
    /// This is not the stored provider credential's hard owner deadline.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The exact authenticated personal owner, never a caller-supplied ID.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Remaining original authority lifetime, bounded by both clocks.
    ///
    /// A long-running caller may derive its initial wait deadline from this
    /// value and must check it again immediately before issuing COMMIT. This
    /// does not reauthenticate, renew the token or replace the publication row
    /// locks; it only checks the exact authority captured by authentication.
    pub fn remaining_lifetime(&self) -> Result<Duration, OAuthBearerAuthorityError> {
        self.remaining_at(Instant::now(), Utc::now())
    }

    fn remaining_at(
        &self,
        monotonic: Instant,
        wall: DateTime<Utc>,
    ) -> Result<Duration, OAuthBearerAuthorityError> {
        let elapsed_remaining = self
            .monotonic_expires_at
            .saturating_duration_since(monotonic);
        let wall_remaining = (self.expires_at - wall)
            .to_std()
            .map_err(|_| OAuthBearerAuthorityError::Denied)?;
        let remaining = elapsed_remaining.min(wall_remaining);
        if remaining.is_zero() {
            Err(OAuthBearerAuthorityError::Denied)
        } else {
            Ok(remaining)
        }
    }

    /// Fence publication using the caller's short, READ COMMITTED transaction.
    ///
    /// The fixed helper locks user -> enabled client -> exact original token,
    /// requires unchanged coordinates/expiry and current `codewire.api` scope,
    /// and checks the database clock after lock waits. Prepare provider material
    /// before calling this method; never hold these locks during device login.
    ///
    /// Keep this same transaction through owner-fenced publication and commit;
    /// do not acquire another pool connection while it is held. Recheck the
    /// original enrollment/token deadlines and cancellation immediately before
    /// committing. Roll back on *every* error, including timeout. This method
    /// does not acknowledge publication: cancellation or lost acknowledgement
    /// after COMMIT is issued is an unknown outcome, never safe to auto-logout.
    ///
    /// Before the locking query, transaction-local statement and idle timeouts
    /// are clamped to this admission's remaining budget, preserving any shorter
    /// settings. Existing lock_timeout is untouched. These server bounds stop
    /// an abandoned statement/idle transaction; the Rust timeout alone would
    /// merely drop SQLx's future without cancelling its PostgreSQL statement.
    /// Network loss can still prevent observing rollback/commit acknowledgement:
    /// this is not a promise of five-second cleanup across a failed connection.
    pub async fn lock_for_publication(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), OAuthBearerAuthorityError> {
        let started = Instant::now();
        let remaining = self.remaining_at(started, Utc::now())?;
        let deadline = started + remaining.min(PUBLICATION_LOCK_TIMEOUT);
        let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let budget_ms = timeout_milliseconds(deadline.saturating_duration_since(Instant::now()))?;
            // A separate command installs the timeout before the locking
            // statement begins. pg_settings expresses these two GUCs in ms;
            // zero means unlimited, never a smaller budget. SET LOCAL semantics
            // prevent this clamp from leaking through a pooled connection.
            let settings: Vec<String> = sqlx::query_scalar(
                "SELECT pg_catalog.set_config(name, \
                 LEAST($1::bigint, CASE WHEN setting::bigint=0 THEN $1::bigint ELSE setting::bigint END)::text, true) \
                 FROM pg_catalog.pg_settings \
                 WHERE name IN ('statement_timeout','idle_in_transaction_session_timeout') AND unit='ms'",
            )
            .bind(budget_ms)
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| OAuthBearerAuthorityError::Unavailable)?;
            if settings.len() != 2 {
                return Err(OAuthBearerAuthorityError::Unavailable);
            }
            self.remaining_at(Instant::now(), Utc::now())?;
            let accepted: bool = sqlx::query_scalar(
                "SELECT public.codewire_lock_oauth_bearer_authority($1::text,$2::text,$3::text,$4::timestamptz)",
            )
            .bind(&self.digest)
            .bind(&self.user_id)
            .bind(&self.client_id)
            .bind(self.expires_at)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| OAuthBearerAuthorityError::Unavailable)?;
            if accepted {
                Ok(())
            } else {
                Err(OAuthBearerAuthorityError::Denied)
            }
        }).await;
        // Neither the original wall nor monotonic deadline is refreshed from
        // new rows, repeated calls, or a wall-clock rewind.
        self.remaining_at(Instant::now(), Utc::now())?;
        match outcome {
            Ok(result) => result,
            Err(_) if remaining <= PUBLICATION_LOCK_TIMEOUT => {
                Err(OAuthBearerAuthorityError::Denied)
            }
            Err(_) => Err(OAuthBearerAuthorityError::Unavailable),
        }
    }
}

fn timeout_milliseconds(remaining: Duration) -> Result<i64, OAuthBearerAuthorityError> {
    // Floor conservatively. PostgreSQL treats zero as "disabled", so a
    // sub-millisecond remaining budget must reject, not install zero or round up.
    let millis = remaining.min(PUBLICATION_LOCK_TIMEOUT).as_millis();
    if millis == 0 {
        Err(OAuthBearerAuthorityError::Denied)
    } else {
        Ok(millis as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_redacts_all_coordinates_and_preserves_original_expiry() {
        let monotonic = Instant::now();
        let wall = Utc::now();
        let expiry = wall + chrono::Duration::minutes(1);
        let authority = OAuthBearerAuthority::new(
            "synthetic-digest".into(),
            "synthetic-user".into(),
            "synthetic-client".into(),
            expiry,
            monotonic,
            wall,
        )
        .unwrap();
        assert_eq!(authority.clone().expires_at(), expiry);
        assert_eq!(authority.user_id(), "synthetic-user");
        assert_eq!(format!("{authority:?}"), "OAuthBearerAuthority([redacted])");
        let remaining = authority.remaining_lifetime().unwrap();
        assert!(!remaining.is_zero());
        assert!(remaining <= Duration::from_secs(60));
    }

    #[test]
    fn original_monotonic_deadline_survives_lookup_delay_rewind_and_repeated_checks() {
        let monotonic = Instant::now();
        let wall = Utc::now();
        let authority = OAuthBearerAuthority::new(
            "synthetic-digest".into(),
            "synthetic-user".into(),
            "synthetic-client".into(),
            wall + chrono::Duration::seconds(60),
            monotonic,
            wall,
        )
        .unwrap();
        // This includes time spent waiting for the original identity query.
        for elapsed in [10, 20, 59] {
            assert_eq!(
                authority
                    .remaining_at(
                        monotonic + Duration::from_secs(elapsed),
                        wall - chrono::Duration::hours(1)
                    )
                    .unwrap(),
                Duration::from_secs(60 - elapsed),
            );
        }
        assert_eq!(
            authority.remaining_at(
                monotonic + Duration::from_secs(60),
                wall - chrono::Duration::hours(1)
            ),
            Err(OAuthBearerAuthorityError::Denied)
        );
        // A forward wall-clock jump can revoke sooner, never extend the pin.
        assert_eq!(
            authority.remaining_at(monotonic, wall + chrono::Duration::seconds(60)),
            Err(OAuthBearerAuthorityError::Denied)
        );
    }

    #[test]
    fn timeout_floor_never_disables_or_extends_a_submillisecond_budget() {
        assert_eq!(
            timeout_milliseconds(Duration::ZERO),
            Err(OAuthBearerAuthorityError::Denied)
        );
        assert_eq!(
            timeout_milliseconds(Duration::from_nanos(999_999)),
            Err(OAuthBearerAuthorityError::Denied)
        );
        assert_eq!(timeout_milliseconds(Duration::from_micros(1_999)), Ok(1));
        assert_eq!(timeout_milliseconds(Duration::from_secs(10)), Ok(5_000));
    }

    #[test]
    fn publication_errors_have_no_source_or_sensitive_context() {
        for error in [
            OAuthBearerAuthorityError::Denied,
            OAuthBearerAuthorityError::Unavailable,
        ] {
            assert!(std::error::Error::source(&error).is_none());
            assert!(!format!("{error:?} {error}").contains("synthetic"));
        }
    }

    #[test]
    fn principal_or_credential_context_cannot_substitute_for_original_authority() {
        let mut extensions = http::Extensions::new();
        extensions.insert(super::super::AuthUser {
            user_id: "synthetic-user".into(),
            org_id: None,
            is_admin: true,
            via_api_key: false,
        });
        extensions.insert(super::super::CredentialContext::OidcAccessToken {
            client_id: "synthetic-client".into(),
            scopes: vec![super::super::PRODUCT_API_SCOPE.into()],
        });
        let context =
            connectrpc::RequestContext::new(http::HeaderMap::new()).with_extensions(extensions);
        assert!(crate::connect::oauth_bearer_authority(&context).is_err());
    }
}
