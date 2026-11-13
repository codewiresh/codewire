//! Removal of expired OIDC rows as new ones are written.
//!
//! Authorization requests and device authorizations are created before
//! anyone signs in, so each new row first removes a bounded batch of expired
//! ones; the tables then hold about one lifetime's worth of rows at any
//! rate. Rows another writer is removing are skipped, not waited for. Tokens
//! are minted only for a signed-in user, so issuing one removes that user's
//! expired tokens through the per-user index.

use sqlx::PgPool;

/// Expired rows one write may remove. Each write adds one row, so removing
/// up to this many keeps the expired backlog from growing.
const BATCH: i64 = 100;

pub(crate) async fn auth_requests(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM oidc_auth_requests
        WHERE ctid IN (
            SELECT ctid FROM oidc_auth_requests
            WHERE expires_at <= NOW()
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        "#,
    )
    .bind(BATCH)
    .execute(pool)
    .await
    .map(|_| ())
}

pub(crate) async fn device_authorizations(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM oidc_device_authorizations
        WHERE ctid IN (
            SELECT ctid FROM oidc_device_authorizations
            WHERE expires_at <= NOW()
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        "#,
    )
    .bind(BATCH)
    .execute(pool)
    .await
    .map(|_| ())
}

pub(crate) async fn access_tokens(pool: &PgPool, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oidc_access_tokens WHERE user_id = $1 AND expires_at <= NOW()")
        .bind(user_id)
        .execute(pool)
        .await
        .map(|_| ())
}

pub(crate) async fn refresh_tokens(pool: &PgPool, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oidc_refresh_tokens WHERE user_id = $1 AND expires_at <= NOW()")
        .bind(user_id)
        .execute(pool)
        .await
        .map(|_| ())
}
