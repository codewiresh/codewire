//! Postgres persistence for the standard OAuth device-authorization grant.
//!
//! These records are the sole device-authorization state. The provider owns
//! creation, approval, denial, expiry, and single-use redemption.

use async_trait::async_trait;
use codewire_oidc::{
    DeviceAuthorization, DeviceAuthorizationStore, DeviceStatus, Scopes, StoreError, StoreResult,
    Subject,
};
use sqlx::PgPool;

/// `DeviceAuthorizationStore` backed by `oidc_device_authorizations`.
#[derive(Clone)]
pub struct PgDeviceAuthorizationStore {
    pool: PgPool,
}

impl PgDeviceAuthorizationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    device_code: String,
    user_code: String,
    client_id: String,
    scopes: Vec<String>,
    status: String,
    user_id: Option<String>,
    auth_time: Option<i64>,
}

fn decode(row: DeviceRow) -> StoreResult<DeviceAuthorization> {
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
        device_code: row.device_code,
        user_code: row.user_code,
        client_id: row.client_id,
        scopes: Scopes(row.scopes),
        status,
    })
}

const SELECT_BY_DEVICE_CODE: &str = r#"
    SELECT device_code, user_code, client_id, scopes, status, user_id, auth_time
    FROM oidc_device_authorizations
    WHERE device_code = $1 AND expires_at > NOW()
"#;

const SELECT_BY_USER_CODE: &str = r#"
    SELECT device_code, user_code, client_id, scopes, status, user_id, auth_time
    FROM oidc_device_authorizations
    WHERE user_code = $1 AND expires_at > NOW()
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
        sqlx::query(
            r#"
            INSERT INTO oidc_device_authorizations
                (device_code, user_code, client_id, scopes, status, expires_at)
            VALUES ($1, $2, $3, $4, 'pending', NOW() + ($5::bigint * interval '1 second'))
            "#,
        )
        .bind(&auth.device_code)
        .bind(&auth.user_code)
        .bind(&auth.client_id)
        .bind(&auth.scopes.0)
        .bind(expires_in_secs)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(())
    }

    async fn get_by_user_code(&self, user_code: &str) -> StoreResult<Option<DeviceAuthorization>> {
        sqlx::query_as::<_, DeviceRow>(SELECT_BY_USER_CODE)
            .bind(user_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?
            .map(decode)
            .transpose()
    }

    async fn get_by_device_code(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        sqlx::query_as::<_, DeviceRow>(SELECT_BY_DEVICE_CODE)
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?
            .map(decode)
            .transpose()
    }

    async fn consume_approved(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        // Atomic single-use: delete-and-return the still-valid approved row.
        // A concurrent poller gets no row and therefore cannot issue another
        // access/refresh pair from the same device code.
        sqlx::query_as::<_, DeviceRow>(
            r#"
            DELETE FROM oidc_device_authorizations
            WHERE device_code = $1
              AND expires_at > NOW()
              AND status = 'approved'
            RETURNING device_code, user_code, client_id, scopes, status, user_id, auth_time
            "#,
        )
        .bind(device_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?
        .map(decode)
        .transpose()
    }

    async fn update(&self, auth: &DeviceAuthorization) -> StoreResult<()> {
        let (status, user_id, auth_time) = match &auth.status {
            DeviceStatus::Pending => ("pending", None, None),
            DeviceStatus::Denied => ("denied", None, None),
            DeviceStatus::Approved { subject, auth_time } => {
                ("approved", Some(subject.0.as_str()), *auth_time)
            }
        };
        let result = sqlx::query(
            r#"
            UPDATE oidc_device_authorizations
            SET status = $1, user_id = $2, auth_time = $3
            WHERE device_code = $4
              AND expires_at > NOW()
              AND status = 'pending'
            "#,
        )
        .bind(status)
        .bind(user_id)
        .bind(auth_time)
        .bind(&auth.device_code)
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::new(
                "device authorization is expired or already resolved",
            ));
        }
        Ok(())
    }

    async fn delete(&self, device_code: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM oidc_device_authorizations WHERE device_code = $1")
            .bind(device_code)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }
}
