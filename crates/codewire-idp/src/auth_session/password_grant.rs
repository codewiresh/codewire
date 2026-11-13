//! What a verified password grants, issued only while that password is still
//! the account's.
//!
//! A password reset replaces the credential and deletes what the old one
//! minted in one transaction (#4481). Sign-in checks the hash before it mints,
//! so a sign-in that read the old hash just before a reset committed could
//! otherwise insert its session or second-factor challenge after the reset's
//! delete, and keep it. Each grant here locks the credential row `FOR SHARE`
//! and checks it still holds the hash sign-in verified. A reset that has
//! already updated the row makes the check fail; one that comes later waits
//! for the grant to commit, and then deletes it.

use sqlx::{PgPool, Postgres, Transaction};

use serde_json::json;

use super::{
    CreatedSession, TWO_FACTOR_TOKEN_TTL_SECS, create_session_in, hash_session_token, hex_id,
    hex_token, log_audit, unauthorized,
};
use codewire_server_core::AppError;

/// The answer to a password a reset replaced while sign-in was verifying it:
/// the same as a wrong password, and audited with its reason.
pub(super) async fn replaced(pool: &PgPool, user_id: &str, ip: &str, ua: &str) -> AppError {
    log_audit(
        pool,
        "user.signin.failed",
        user_id,
        ip,
        ua,
        json!({ "reason": "password_replaced" }),
        "warn",
    )
    .await;
    unauthorized("Invalid email or password")
}

/// A browser session for `user_id`, or `None` when its password is no longer
/// `verified_hash`.
pub(super) async fn session(
    pool: &PgPool,
    user_id: &str,
    verified_hash: &str,
    ip: &str,
    ua: &str,
) -> Result<Option<CreatedSession>, AppError> {
    let mut tx = pool.begin().await?;
    if !password_unchanged(&mut tx, user_id, verified_hash).await? {
        return Ok(None);
    }
    let created = create_session_in(&mut *tx, user_id, ip, ua).await?;
    tx.commit().await?;
    Ok(Some(created))
}

/// A second-factor challenge token for `user_id`, or `None` when its password
/// is no longer `verified_hash`.
pub(super) async fn challenge(
    pool: &PgPool,
    user_id: &str,
    verified_hash: &str,
) -> Result<Option<String>, AppError> {
    let failed = |e: sqlx::Error| {
        tracing::error!(error = %e, "failed to store 2FA token");
        AppError::InternalMsg("Failed to store 2FA token".into())
    };
    let mut tx = pool.begin().await.map_err(failed)?;
    if !password_unchanged(&mut tx, user_id, verified_hash).await? {
        return Ok(None);
    }
    let token = hex_token();
    sqlx::query(
        r#"
        INSERT INTO two_factor_tokens (id, user_id, token_hash, expires_at)
        VALUES ($1, $2, $3, NOW() + ($4::bigint * interval '1 second'))
        "#,
    )
    .bind(hex_id())
    .bind(user_id)
    .bind(hash_session_token(&token))
    .bind(TWO_FACTOR_TOKEN_TTL_SECS)
    .execute(&mut *tx)
    .await
    .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    Ok(Some(token))
}

async fn password_unchanged(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    verified_hash: &str,
) -> Result<bool, AppError> {
    let current: Option<String> = sqlx::query_scalar(
        "SELECT password FROM accounts \
         WHERE user_id = $1 AND provider_id = 'credential' FOR SHARE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(current.as_deref() == Some(verified_hash))
}
