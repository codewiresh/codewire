//! [`TokenStore`] over the Codewire token tables.
//!
//! The library's generic code→grant / access→grant / refresh→grant model is
//! mapped onto the existing schema:
//!
//! - **authorization codes** reuse `oidc_auth_requests`. The raw code is
//!   returned once; only its digest is stored, and `consume_code` is an atomic
//!   `DELETE … RETURNING` by digest.
//! - **refresh tokens** live in `oidc_refresh_tokens`; `consume_refresh`
//!   rotates via `DELETE … RETURNING` and records the digest in
//!   `oidc_consumed_refresh_tokens`, so a rotated token presented again
//!   revokes that user's tokens for the client. `get_refresh` reads
//!   non-destructively.
//! - **access tokens** are the source of truth in `oidc_access_tokens`
//!   (carrying scopes + client for userinfo/introspection). Product API
//!   auth resolves flavor-2 bearers against the same table
//!   (`codewire_server_core::auth::authenticate`); access tokens are never
//!   mirrored into `sessions` and keep the fixed expiry issued here.
//!
//! Access and refresh tokens are **hashed at rest**: durable rows store
//! only the SHA-256 hex digest ([`hash_oauth_token`]) of the raw opaque
//! token, so plaintext credentials never persist. The raw value exists
//! only in memory and in the one-time token response; every lookup hashes
//! the presented token first. `revoke` clears both tables by digest.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use codewire_oidc::{
    AccessGrant, AuthCodeGrant, RefreshGrant, Scopes, StoreError, StoreResult, Subject, TokenStore,
};
use codewire_server_core::auth::hash_oauth_token;
use rand::RngCore;
use sqlx::PgPool;

/// How long a consumed refresh token that never expires is remembered: the
/// native clients' refresh lifetime.
const CONSUMED_WITHOUT_EXPIRY: &str = "2160 hours";

/// `TokenStore` backed by Postgres.
#[derive(Clone)]
pub struct PgTokenStore {
    pool: PgPool,
    revoke_reused: bool,
}

impl PgTokenStore {
    /// Wrap a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            revoke_reused: false,
        }
    }

    /// Whether a rotated refresh token presented again revokes the user's
    /// tokens for its client, rather than only being refused and logged.
    pub fn with_reuse_revocation(mut self, revoke: bool) -> Self {
        self.revoke_reused = revoke;
        self
    }
}

/// 16 random bytes, lowercase hex — for synthetic row ids (sessions, refresh).
fn hex_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn epoch(t: DateTime<Utc>) -> i64 {
    t.timestamp()
}

#[async_trait]
impl TokenStore for PgTokenStore {
    async fn store_code(
        &self,
        code: &str,
        grant: AuthCodeGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()> {
        let auth_time = grant
            .auth_time
            .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0));
        let code_hash = hash_oauth_token(code);
        let id = hex_id();
        sqlx::query(
            r#"
            INSERT INTO oidc_auth_requests
                (id, client_id, scopes, redirect_uri, response_type,
                 code_challenge, nonce, user_id, auth_time, code_hash, done, expires_at)
            VALUES ($1, $2, $3, $4, 'code', $5, $6, $7, $8, $9, true,
                    NOW() + ($10::bigint * interval '1 second'))
            "#,
        )
        .bind(id)
        .bind(&grant.client_id)
        .bind(&grant.scopes.0)
        .bind(&grant.redirect_uri)
        .bind(&grant.code_challenge)
        .bind(&grant.nonce)
        .bind(&grant.subject.0)
        .bind(auth_time)
        .bind(code_hash)
        .bind(expires_in_secs as i64)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(())
    }

    async fn consume_code(&self, code: &str) -> StoreResult<Option<AuthCodeGrant>> {
        // Atomic single-use: delete-and-return the still-valid code row.
        let code_hash = hash_oauth_token(code);
        let row: Option<(
            String,
            String,
            Option<String>,
            Vec<String>,
            Option<String>,
            Option<String>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            r#"
                DELETE FROM oidc_auth_requests AS request
                USING users AS user_account
                WHERE request.code_hash = $1
                  AND request.expires_at > NOW()
                  AND request.user_id = user_account.id
                  AND user_account.enabled
                RETURNING request.client_id, request.redirect_uri,
                          request.user_id, request.scopes,
                          request.code_challenge, request.nonce,
                          request.auth_time
                "#,
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;

        Ok(row.and_then(
            |(client_id, redirect_uri, user_id, scopes, code_challenge, nonce, auth_time)| {
                // A code with no bound user is not a valid grant.
                let subject = Subject(user_id?);
                Some(AuthCodeGrant {
                    client_id,
                    redirect_uri,
                    subject,
                    scopes: Scopes(scopes),
                    code_challenge,
                    nonce,
                    auth_time: auth_time.map(epoch),
                })
            },
        ))
    }

    async fn store_access(
        &self,
        token: &str,
        grant: AccessGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()> {
        // Source of truth: scopes + client for userinfo/introspection and
        // for product-API bearer validation. Hashed at rest; the raw token
        // leaves this function only in the one-time token response. No
        // session mirror: access tokens keep this fixed expiry and never
        // ride the `sessions` sliding window.
        crate::expired_rows::access_tokens(&self.pool, &grant.subject.0)
            .await
            .map_err(StoreError::new)?;
        sqlx::query(
            r#"
            INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4, NOW() + ($5::bigint * interval '1 second'))
            "#,
        )
        .bind(hash_oauth_token(token))
        .bind(&grant.client_id)
        .bind(&grant.subject.0)
        .bind(&grant.scopes.0)
        .bind(expires_in_secs as i64)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(())
    }

    async fn get_access(&self, token: &str) -> StoreResult<Option<AccessGrant>> {
        let row: Option<(String, String, Vec<String>)> = sqlx::query_as(
            r#"
            SELECT token.client_id, token.user_id, token.scopes
            FROM oidc_access_tokens AS token
            JOIN users AS user_account ON user_account.id = token.user_id
            WHERE token.token_hash = $1
              AND token.expires_at > NOW()
              AND user_account.enabled
            "#,
        )
        .bind(hash_oauth_token(token))
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(row.map(|(client_id, user_id, scopes)| AccessGrant {
            subject: Subject(user_id),
            client_id,
            scopes: Scopes(scopes),
        }))
    }

    async fn store_refresh(
        &self,
        token: &str,
        grant: RefreshGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()> {
        crate::expired_rows::refresh_tokens(&self.pool, &grant.subject.0)
            .await
            .map_err(StoreError::new)?;
        crate::expired_rows::consumed_refresh_tokens(&self.pool)
            .await
            .map_err(StoreError::new)?;
        sqlx::query(
            r#"
            INSERT INTO oidc_refresh_tokens
                (id, token_hash, client_id, user_id, scopes, auth_time, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW(),
                    NOW() + ($6::bigint * interval '1 second'))
            "#,
        )
        .bind(hex_id())
        .bind(hash_oauth_token(token))
        .bind(&grant.client_id)
        .bind(&grant.subject.0)
        .bind(&grant.scopes.0)
        .bind(expires_in_secs as i64)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(())
    }

    async fn consume_refresh(&self, token: &str) -> StoreResult<Option<RefreshGrant>> {
        let token_hash = hash_oauth_token(token);
        let mut tx = self.pool.begin().await.map_err(StoreError::new)?;
        // Rotation: atomic single-use delete-and-return of a still-valid token.
        let row: Option<(String, String, Vec<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
            r#"
            DELETE FROM oidc_refresh_tokens AS token
            USING users AS user_account
            WHERE token.token_hash = $1
              AND (token.expires_at IS NULL OR token.expires_at > NOW())
              AND token.user_id = user_account.id
              AND user_account.enabled
            RETURNING token.client_id, token.user_id, token.scopes, token.expires_at
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        if let Some((client_id, user_id, scopes, expires_at)) = row {
            // Remembered until the token would have expired; one with no
            // expiry, as long as the native clients' refresh lifetime.
            sqlx::query(
                r#"
                INSERT INTO oidc_consumed_refresh_tokens
                    (token_hash, client_id, user_id, expires_at)
                VALUES ($1, $2, $3, COALESCE($4, NOW() + $5::interval))
                ON CONFLICT (token_hash) DO NOTHING
                "#,
            )
            .bind(&token_hash)
            .bind(&client_id)
            .bind(&user_id)
            .bind(expires_at)
            .bind(CONSUMED_WITHOUT_EXPIRY)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::new)?;
            tx.commit().await.map_err(StoreError::new)?;
            return Ok(Some(RefreshGrant {
                subject: Subject(user_id),
                client_id,
                scopes: Scopes(scopes),
            }));
        }
        // Not a live token. If it was rotated before, this is a copy of it.
        // It is refused either way; with revocation on, every token the user
        // holds for that client goes too (RFC 9700 section 4.14.2), since the
        // legitimate holder can't be told apart.
        let rotated: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT client_id, user_id, EXTRACT(EPOCH FROM NOW() - consumed_at)::bigint \
             FROM oidc_consumed_refresh_tokens \
             WHERE token_hash = $1 AND expires_at > NOW()",
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        if let Some((client_id, user_id, rotated_secs_ago)) = rotated {
            if self.revoke_reused {
                for statement in [
                    "DELETE FROM oidc_refresh_tokens WHERE user_id = $1 AND client_id = $2",
                    "DELETE FROM oidc_access_tokens WHERE user_id = $1 AND client_id = $2",
                ] {
                    sqlx::query(statement)
                        .bind(&user_id)
                        .bind(&client_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::new)?;
                }
            }
            tracing::warn!(
                %user_id,
                %client_id,
                rotated_secs_ago,
                revoked = self.revoke_reused,
                "a rotated refresh token was presented again"
            );
        }
        tx.commit().await.map_err(StoreError::new)?;
        Ok(None)
    }

    async fn get_refresh(&self, token: &str) -> StoreResult<Option<RefreshGrant>> {
        let row: Option<(String, String, Vec<String>)> = sqlx::query_as(
            r#"
            SELECT token.client_id, token.user_id, token.scopes
            FROM oidc_refresh_tokens AS token
            JOIN users AS user_account ON user_account.id = token.user_id
            WHERE token.token_hash = $1
              AND (token.expires_at IS NULL OR token.expires_at > NOW())
              AND user_account.enabled
            "#,
        )
        .bind(hash_oauth_token(token))
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(row.map(|(client_id, user_id, scopes)| RefreshGrant {
            subject: Subject(user_id),
            client_id,
            scopes: Scopes(scopes),
        }))
    }

    async fn revoke(&self, token: &str) -> StoreResult<()> {
        // The token could be an access token or a refresh token; clear
        // both by digest (no-op if absent). Sessions are untouched —
        // OAuth tokens never live there.
        let hash = hash_oauth_token(token);
        let mut tx = self.pool.begin().await.map_err(StoreError::new)?;
        for sql in [
            "DELETE FROM oidc_access_tokens WHERE token_hash = $1",
            "DELETE FROM oidc_refresh_tokens WHERE token_hash = $1",
        ] {
            sqlx::query(sql)
                .bind(&hash)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::new)?;
        }
        tx.commit().await.map_err(StoreError::new)?;
        Ok(())
    }
}
