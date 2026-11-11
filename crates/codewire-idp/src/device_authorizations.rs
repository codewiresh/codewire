//! Postgres persistence for the standard OAuth device-authorization grant.
//!
//! These records are the sole device-authorization state. The provider owns
//! creation, approval, denial, expiry, and single-use redemption.

use async_trait::async_trait;
use codewire_oidc::{
    DeviceAuthorization, DeviceAuthorizationStore, DeviceStatus, Scopes, StoreError, StoreResult,
    Subject,
};
use codewire_server_core::auth::hash_oauth_token;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use sqlx::PgPool;

use crate::auth_session::hex_lower;

const USER_CODE_DIGEST_DOMAIN: &[u8] = b"codewire/idp/device-user-code/v1\0";

/// `DeviceAuthorizationStore` backed by `oidc_device_authorizations`.
#[derive(Clone)]
pub struct PgDeviceAuthorizationStore {
    pool: PgPool,
    user_code_pepper: String,
}

impl PgDeviceAuthorizationStore {
    pub fn new(pool: PgPool, user_code_pepper: impl Into<String>) -> StoreResult<Self> {
        let user_code_pepper = user_code_pepper.into();
        if user_code_pepper.is_empty() {
            return Err(StoreError::new(
                "device user-code lookup requires a non-empty HMAC secret",
            ));
        }
        Ok(Self {
            pool,
            user_code_pepper,
        })
    }

    fn user_code_lookup_digest(&self, user_code: &str) -> String {
        user_code_lookup_digest(&self.user_code_pepper, user_code)
    }
}

fn user_code_lookup_digest(secret: &str, user_code: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every size");
    mac.update(USER_CODE_DIGEST_DOMAIN);
    mac.update(user_code.as_bytes());
    hex_lower(&mac.finalize().into_bytes())
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    client_id: String,
    scopes: Vec<String>,
    status: String,
    user_id: Option<String>,
    auth_time: Option<i64>,
}

fn decode(
    row: DeviceRow,
    device_code: String,
    user_code: String,
) -> StoreResult<DeviceAuthorization> {
    let status =
        match row.status.as_str() {
            "pending" => DeviceStatus::Pending,
            "denied" => DeviceStatus::Denied,
            "approved" => DeviceStatus::Approved {
                subject: Subject(row.user_id.ok_or_else(|| {
                    StoreError::new("approved device authorization lacks user_id")
                })?),
                auth_time: row.auth_time,
            },
            other => {
                return Err(StoreError::new(format!(
                    "invalid device authorization status: {other}"
                )));
            }
        };
    Ok(DeviceAuthorization {
        device_code,
        user_code,
        client_id: row.client_id,
        scopes: Scopes(row.scopes),
        status,
    })
}

const SELECT_BY_DEVICE_CODE: &str = r#"
    SELECT client_id, scopes, status, user_id, auth_time
    FROM oidc_device_authorizations
    WHERE device_code_hash = $1 AND expires_at > NOW()
"#;

const SELECT_BY_USER_CODE: &str = r#"
    SELECT client_id, scopes, status, user_id, auth_time
    FROM oidc_device_authorizations
    WHERE user_code_hash = $1 AND expires_at > NOW()
"#;

#[async_trait]
impl DeviceAuthorizationStore for PgDeviceAuthorizationStore {
    async fn store_device(
        &self,
        auth: DeviceAuthorization,
        expires_in_secs: u64,
    ) -> StoreResult<()> {
        let expires_in_secs = i64::try_from(expires_in_secs).map_err(|_| {
            StoreError::new("device authorization lifetime exceeds PostgreSQL range")
        })?;
        let device_code_hash = hash_oauth_token(&auth.device_code);
        let user_code_hash = self.user_code_lookup_digest(&auth.user_code);
        sqlx::query(
            r#"
            INSERT INTO oidc_device_authorizations
                (device_code_hash, user_code_hash, client_id, scopes, status, expires_at)
            VALUES ($1, $2, $3, $4, 'pending', NOW() + ($5::bigint * interval '1 second'))
            "#,
        )
        .bind(device_code_hash)
        .bind(user_code_hash)
        .bind(&auth.client_id)
        .bind(&auth.scopes.0)
        .bind(expires_in_secs)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(())
    }

    async fn get_by_user_code(&self, user_code: &str) -> StoreResult<Option<DeviceAuthorization>> {
        let user_code_hash = self.user_code_lookup_digest(user_code);
        sqlx::query_as::<_, DeviceRow>(SELECT_BY_USER_CODE)
            .bind(user_code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?
            .map(|row| decode(row, String::new(), user_code.to_owned()))
            .transpose()
    }

    async fn get_by_device_code(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        let device_code_hash = hash_oauth_token(device_code);
        sqlx::query_as::<_, DeviceRow>(SELECT_BY_DEVICE_CODE)
            .bind(device_code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?
            .map(|row| decode(row, device_code.to_owned(), String::new()))
            .transpose()
    }

    async fn consume_approved(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        // Atomic single-use: delete-and-return the still-valid approved row.
        // A concurrent poller gets no row and therefore cannot issue another
        // access/refresh pair from the same device code.
        //
        // The same statement records the account's first CLI sign-in, which
        // the dashboard's Get started checklist reads; it is set once and
        // never cleared. Writing the account row means taking its lock, so
        // the account is locked first, in the order account disablement
        // takes them (the account, then its device grants): a disablement
        // that wins leaves no enabled account here and nothing is redeemed.
        let device_code_hash = hash_oauth_token(device_code);
        sqlx::query_as::<_, DeviceRow>(
            r#"
            WITH account AS (
                SELECT user_account.id
                  FROM oidc_device_authorizations AS pending
                  JOIN users AS user_account ON user_account.id = pending.user_id
                 WHERE pending.device_code_hash = $1
                   AND pending.expires_at > NOW()
                   AND pending.status = 'approved'
                   AND user_account.enabled
                   FOR NO KEY UPDATE OF user_account
            ),
            consumed AS (
                DELETE FROM oidc_device_authorizations AS device_auth
                 USING account
                 WHERE device_auth.device_code_hash = $1
                   AND device_auth.expires_at > NOW()
                   AND device_auth.status = 'approved'
                   AND device_auth.user_id = account.id
                RETURNING device_auth.client_id, device_auth.scopes,
                          device_auth.status, device_auth.user_id,
                          device_auth.auth_time
            ),
            first_cli_sign_in AS (
                UPDATE users
                   SET cli_signed_in_at = NOW()
                 WHERE id IN (SELECT user_id FROM consumed)
                   AND cli_signed_in_at IS NULL
            )
            SELECT client_id, scopes, status, user_id, auth_time FROM consumed
            "#,
        )
        .bind(device_code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?
        .map(|row| decode(row, device_code.to_owned(), String::new()))
        .transpose()
    }

    async fn update(&self, auth: &DeviceAuthorization) -> StoreResult<()> {
        if auth.user_code.is_empty() {
            return Err(StoreError::new(
                "device authorization update requires the presented user code",
            ));
        }
        let (status, user_id, auth_time) = match &auth.status {
            DeviceStatus::Pending => ("pending", None, None),
            DeviceStatus::Denied => ("denied", None, None),
            DeviceStatus::Approved { subject, auth_time } => {
                ("approved", Some(subject.0.as_str()), *auth_time)
            }
        };
        let mut tx = self.pool.begin().await.map_err(StoreError::new)?;
        if let Some(user_id) = user_id {
            // Account disablement holds this same user lock before deleting
            // bound device grants. Take it before the pending grant row so a
            // browser approval and disablement serialize in one order.
            let enabled_user: Option<String> =
                sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND enabled FOR SHARE")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::new)?;
            if enabled_user.is_none() {
                tx.rollback().await.map_err(StoreError::new)?;
                return Err(StoreError::new(
                    "device authorization is expired or already resolved",
                ));
            }
        }
        let result = sqlx::query(
            r#"
            UPDATE oidc_device_authorizations
            SET status = $1, user_id = $2, auth_time = $3
            WHERE user_code_hash = $4
              AND expires_at > NOW()
              AND status = 'pending'
            "#,
        )
        .bind(status)
        .bind(user_id)
        .bind(auth_time)
        .bind(self.user_code_lookup_digest(&auth.user_code))
        .execute(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        if result.rows_affected() != 1 {
            tx.rollback().await.map_err(StoreError::new)?;
            return Err(StoreError::new(
                "device authorization is expired or already resolved",
            ));
        }
        tx.commit().await.map_err(StoreError::new)?;
        Ok(())
    }

    async fn delete(&self, device_code: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM oidc_device_authorizations WHERE device_code_hash = $1")
            .bind(hash_oauth_token(device_code))
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_digest_is_keyed_and_domain_separated() {
        let raw = "BCDF-GHJK";
        let first = user_code_lookup_digest("synthetic-session-secret-a", raw);
        let second = user_code_lookup_digest("synthetic-session-secret-b", raw);

        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')));
        assert_ne!(first, second);
        assert_ne!(first, hash_oauth_token(raw));
        assert!(!first.contains(raw));
    }
}
