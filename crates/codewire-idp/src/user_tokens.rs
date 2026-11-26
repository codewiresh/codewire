//! [`UserTokenStore`] over `oidc_user_tokens` (#5688): `cw auth token`'s user
//! tokens, exchanged for a `cw` sign-in's access token.
//!
//! One transaction takes the user's hourly count, locks a live access token
//! of the parent sign-in, stores the token by digest and writes its audit
//! row. The lock orders the issue against a revoke of that sign-in: a revoke
//! that started first leaves no live access token to lock, so nothing is
//! issued; one that starts after waits for this commit, then deletes the new
//! token with the rest of the sign-in.

use async_trait::async_trait;
use codewire_oidc::{StoreError, StoreResult, UserTokenGrant, UserTokenIssue, UserTokenStore};
use codewire_server_core::auth::hash_oauth_token;
use codewire_server_core::rate_limit::{USER_TOKEN_ISSUE, take_fixed};
use rand::RngCore;
use serde_json::json;
use sqlx::PgPool;

/// `UserTokenStore` backed by Postgres.
#[derive(Clone)]
pub struct PgUserTokenStore {
    pool: PgPool,
}

impl PgUserTokenStore {
    /// Wrap a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// 16 random bytes, hex: the token's id, which Settings and the audit log
/// name. Not a credential.
fn token_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[async_trait]
impl UserTokenStore for PgUserTokenStore {
    async fn store_user_token(
        &self,
        token: &str,
        grant: UserTokenGrant,
    ) -> StoreResult<UserTokenIssue> {
        let user_id = grant.subject.0;
        let mut tx = self.pool.begin().await.map_err(StoreError::new)?;
        let decision = take_fixed(&mut tx, &USER_TOKEN_ISSUE, &user_id)
            .await
            .map_err(StoreError::new)?;
        if !decision.allowed {
            tx.commit().await.map_err(StoreError::new)?;
            tracing::warn!(%user_id, "user token refused by its rate limit");
            return Ok(UserTokenIssue::RateLimited);
        }
        let parent: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM oidc_access_tokens \
             WHERE sign_in_id = $1 AND user_id = $2 AND client_id = $3 AND expires_at > NOW() \
             LIMIT 1 FOR SHARE",
        )
        .bind(&grant.sign_in)
        .bind(&user_id)
        .bind(&grant.client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        if parent.is_none() {
            tx.commit().await.map_err(StoreError::new)?;
            return Ok(UserTokenIssue::SignInEnded);
        }
        sqlx::query("DELETE FROM oidc_user_tokens WHERE user_id = $1 AND expires_at <= NOW()")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::new)?;
        let id = token_id();
        let expires_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            r#"
            INSERT INTO oidc_user_tokens
                (id, token_hash, client_id, user_id, sign_in_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6,
                    NOW() + ($7::bigint * interval '1 second'))
            RETURNING expires_at
            "#,
        )
        .bind(&id)
        .bind(hash_oauth_token(token))
        .bind(&grant.client_id)
        .bind(&user_id)
        .bind(&grant.sign_in)
        .bind(&grant.scopes.0)
        .bind(grant.expires_in_secs.map(|secs| secs as i64))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        // Names the token by its id and its parent sign-in, never its value.
        sqlx::query(
            "INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity) \
             VALUES ($1, NOW(), 'user_token.issued', $2, $3, 'info')",
        )
        .bind(token_id())
        .bind(&user_id)
        .bind(json!({
            "user_token_id": id,
            "sign_in_id": grant.sign_in,
            "client_id": grant.client_id,
            "expires_at": expires_at,
        }))
        .execute(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        tx.commit().await.map_err(StoreError::new)?;
        Ok(UserTokenIssue::Issued)
    }
}
