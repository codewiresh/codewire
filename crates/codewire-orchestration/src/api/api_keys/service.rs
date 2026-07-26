//! Transport-independent API-key operations shared by REST and Connect.
//!
//! REST passes raw semantic values so authorization remains ahead of the
//! legacy `BadRequest` checks. Connect prevalidates the same predicates into
//! typed validation details, while these operations still reject invalid
//! direct calls defensively.

use axum::http::StatusCode;
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_server_core::auth::{AuthUser, api_key_prefix, generate_api_key, hash_api_key};
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult};
use sqlx::{PgPool, Row};

pub(crate) const MAX_API_KEY_EXPIRES_IN_DAYS: i32 = 3650;

const LIST_API_KEYS_QUERY: &str = r#"SELECT ak.id, ak.user_id, ak.org_id, ak.name, ak.key_prefix, ak.scopes,
              ak.last_used_at, ak.expires_at, ak.disabled_at, ak.created_at,
              COALESCE(u.name, '')  AS created_by_name,
              COALESCE(u.email, '') AS created_by_email
         FROM api_keys ak
         LEFT JOIN users u ON u.id = ak.user_id
        WHERE ak.org_id = $1
        ORDER BY ak.created_at DESC"#;

/// Transport-independent representation of an API-key row.
#[derive(Debug)]
pub(crate) struct ApiKeyRecord {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) org_id: String,
    pub(crate) name: String,
    pub(crate) key_prefix: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) last_used_at: Option<NaiveDateTime>,
    pub(crate) expires_at: Option<NaiveDateTime>,
    pub(crate) disabled_at: Option<NaiveDateTime>,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) created_by_name: String,
    pub(crate) created_by_email: String,
}

#[derive(Debug)]
pub(crate) struct CreatedApiKey {
    pub(crate) record: ApiKeyRecord,
    pub(crate) raw_key: String,
}

#[derive(Debug)]
pub(crate) struct CreateApiKeyParams {
    pub(crate) name: String,
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) expires_in_days: Option<i32>,
}

#[derive(Debug)]
pub(crate) struct UpdateApiKeyParams {
    pub(crate) disabled: Option<bool>,
}

/// Shared semantic predicate used by REST's legacy error path and Connect's
/// typed validation path.
pub(crate) fn name_is_valid(name: &str) -> bool {
    !name.trim().is_empty()
}

/// Shared semantic predicate used by REST's legacy error path and Connect's
/// typed validation path.
pub(crate) fn expires_in_days_is_valid(expires_in_days: Option<i32>) -> bool {
    expires_in_days.is_none_or(|days| (1..=MAX_API_KEY_EXPIRES_IN_DAYS).contains(&days))
}

/// Shared semantic predicate used by REST's legacy error path and Connect's
/// typed validation path.
pub(crate) fn disabled_is_present(disabled: Option<bool>) -> bool {
    disabled.is_some()
}

/// `getUserOrgRole` → `huma.Error404NotFound("organization not found")`.
/// Unlike the environments' `require_org_member`, the huma 404 carries no
/// machine-readable code.
async fn require_org_role(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

fn forbidden(detail: &'static str) -> AppError {
    // huma.Error403Forbidden(detail): status + detail, no code.
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "",
        detail: detail.into(),
    }
}

pub(crate) fn api_key_expires_at(expires_in_days: Option<i32>) -> AppResult<Option<NaiveDateTime>> {
    if !expires_in_days_is_valid(expires_in_days) {
        return Err(AppError::BadRequest(
            format!("expires_in_days must be between 1 and {MAX_API_KEY_EXPIRES_IN_DAYS}").into(),
        ));
    }
    let Some(days) = expires_in_days else {
        return Ok(None);
    };
    Utc::now()
        .checked_add_signed(Duration::days(i64::from(days)))
        .map(|t| Some(t.naive_utc()))
        .ok_or_else(|| AppError::BadRequest("expires_in_days is out of range".into()))
}

/// Scans the shared `APIKey` column list (the SELECT/RETURNING order is
/// identical across list/update).
fn scan_api_key(row: &sqlx::postgres::PgRow) -> Result<ApiKeyRecord, sqlx::Error> {
    Ok(ApiKeyRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        org_id: row.try_get("org_id")?,
        name: row.try_get("name")?,
        key_prefix: row.try_get("key_prefix")?,
        scopes: row.try_get("scopes")?,
        last_used_at: row.try_get("last_used_at")?,
        expires_at: row.try_get("expires_at")?,
        disabled_at: row.try_get("disabled_at")?,
        created_at: row.try_get("created_at")?,
        created_by_name: row.try_get("created_by_name").unwrap_or_default(),
        created_by_email: row.try_get("created_by_email").unwrap_or_default(),
    })
}

pub(crate) async fn create(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    params: CreateApiKeyParams,
) -> AppResult<CreatedApiKey> {
    require_org_role(pool, user, org_id).await?;

    let name = params.name.trim();
    if !name_is_valid(name) {
        return Err(AppError::BadRequest("name is required".into()));
    }

    let raw = generate_api_key();
    let key_hash = hash_api_key(&raw);
    let key_prefix = api_key_prefix(&raw).to_string();
    let scopes = params.scopes.unwrap_or_default();

    let expires_at = api_key_expires_at(params.expires_in_days)?;

    run_organization_database_mutation(pool, org_id, async {
        let row = sqlx::query(
            r#"INSERT INTO api_keys (user_id, org_id, name, key_hash, key_prefix, scopes, expires_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
               RETURNING id, created_at, expires_at"#,
        )
        .bind(&user.user_id)
        .bind(org_id)
        .bind(name)
        .bind(&key_hash)
        .bind(&key_prefix)
        .bind(&scopes)
        .bind(expires_at)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create api key failed");
            AppError::InternalMsg("failed to create api key".into())
        })?;

        let id: String = row.try_get("id").map_err(AppError::from)?;
        let created_at: NaiveDateTime = row.try_get("created_at").map_err(AppError::from)?;
        let stored_expires: Option<NaiveDateTime> =
            row.try_get("expires_at").map_err(AppError::from)?;

        // created_by_* come from the authenticated user's record, like Go's
        // user.Name/user.Email (loaded by the auth middleware).
        let (created_by_name, created_by_email): (String, String) = sqlx::query_as(
            "SELECT COALESCE(name, ''), COALESCE(email, '') FROM users WHERE id = $1",
        )
        .bind(&user.user_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)?
        .unwrap_or_default();

        Ok(CreatedApiKey {
            record: ApiKeyRecord {
                id,
                user_id: user.user_id.clone(),
                org_id: org_id.to_string(),
                name: name.to_string(),
                key_prefix,
                scopes,
                last_used_at: None,
                expires_at: stored_expires,
                disabled_at: None,
                created_at,
                created_by_name,
                created_by_email,
            },
            raw_key: raw,
        })
    })
    .await
}

pub(crate) async fn list(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<ApiKeyRecord>> {
    require_org_role(pool, user, org_id).await?;

    let rows = sqlx::query(LIST_API_KEYS_QUERY)
        .bind(org_id)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list api keys failed");
            AppError::InternalMsg("failed to list api keys".into())
        })?;

    rows.iter()
        .map(scan_api_key)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::error!(error = %e, "scan api key failed");
            AppError::InternalMsg("failed to scan api key".into())
        })
}

pub(crate) async fn update(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    key_id: &str,
    params: UpdateApiKeyParams,
) -> AppResult<ApiKeyRecord> {
    require_org_role(pool, user, org_id).await?;

    if !disabled_is_present(params.disabled) {
        return Err(AppError::BadRequest("disabled field is required".into()));
    }
    let disabled = params
        .disabled
        .expect("disabled presence checked by shared invariant");
    let disabled_at: Option<NaiveDateTime> = disabled.then(|| Utc::now().naive_utc());

    run_organization_database_mutation(pool, org_id, async {
        let row = sqlx::query(
            r#"UPDATE api_keys SET disabled_at = $1
                WHERE id = $2 AND org_id = $3
            RETURNING id, user_id, org_id, name, key_prefix, scopes,
                      last_used_at, expires_at, disabled_at, created_at,
                      '' AS created_by_name, '' AS created_by_email"#,
        )
        .bind(disabled_at)
        .bind(key_id)
        .bind(org_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::NotFound("api key not found".into()))?;

        scan_api_key(&row).map_err(|e| {
            tracing::error!(error = %e, "scan api key failed");
            AppError::InternalMsg("failed to scan api key".into())
        })
    })
    .await
}

pub(crate) async fn delete(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    key_id: &str,
) -> AppResult<()> {
    let role = require_org_role(pool, user, org_id).await?;
    let assignments = user_assignments(pool, org_id, &user.user_id)
        .await
        .unwrap_or_default();
    if !can_admin(&role, &assignments) {
        return Err(forbidden("only owner or admin can revoke api keys"));
    }
    run_organization_database_mutation(pool, org_id, async {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND org_id = $2")
            .bind(key_id)
            .bind(org_id)
            .execute(pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "delete api key failed");
                AppError::InternalMsg("failed to delete api key".into())
            })?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("api key not found".into()));
        }

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_create_predicates_preserve_rest_semantics() {
        assert!(!name_is_valid(""));
        assert!(!name_is_valid(" \t\n"));
        assert!(name_is_valid(" deploy "));

        assert!(expires_in_days_is_valid(None));
        assert!(expires_in_days_is_valid(Some(1)));
        assert!(expires_in_days_is_valid(Some(MAX_API_KEY_EXPIRES_IN_DAYS)));
        for days in [0, -1, MAX_API_KEY_EXPIRES_IN_DAYS + 1] {
            assert!(!expires_in_days_is_valid(Some(days)));
        }
    }

    #[test]
    fn shared_update_predicate_checks_presence_not_value() {
        assert!(!disabled_is_present(None));
        assert!(disabled_is_present(Some(false)));
        assert!(disabled_is_present(Some(true)));
    }

    #[test]
    fn shared_list_query_is_org_scoped_and_unbounded() {
        let normalized = LIST_API_KEYS_QUERY
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        assert!(normalized.contains("where ak.org_id = $1"));
        assert!(!normalized.contains(" limit "));
    }
}
