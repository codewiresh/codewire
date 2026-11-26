//! Settings' list and revoke of the account's user tokens (#5688;
//! docs/dev/AUTH-POLICY.md, "User tokens and the CLI"). The same boundary as
//! the session inventory: the browser-session cookie and never a bearer, so a
//! user token can't list or revoke tokens; an exact Origin on the revoke; the
//! owner locked before the actor; and a bounded, private transaction.
//!
//! A revoke deletes the row; the table's delete trigger ends the token's
//! streams and writes `user_token.revoked` to the audit log.

use axum::extract::{DefaultBodyLimit, Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use codewire_server_core::AppError;
use serde::{Deserialize, Serialize};

use super::SessionAuthState;
use super::session_inventory::{
    SessionInventoryBounds, actor, bounded_transaction_within, cookie_digest, database_unavailable,
    exact_origin, private, unavailable, valid_id, validate_actor,
};

const PAGE_SIZE: usize = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryQuery {
    account_id: String,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    account_id: String,
    token_id: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct UserTokenMetadata {
    id: String,
    #[serde(serialize_with = "utc_time")]
    created_at: DateTime<Utc>,
    /// Absent for a token that never expires.
    #[serde(serialize_with = "optional_utc_time")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(serialize_with = "optional_utc_time")]
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct Inventory {
    account_id: String,
    tokens: Vec<UserTokenMetadata>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct Revoked {
    revoked: bool,
}

pub(super) fn router() -> Router<SessionAuthState> {
    Router::new()
        .route("/api/auth/user-tokens", get(list))
        .route("/api/auth/user-tokens/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(2_048))
}

fn utc_time<S: serde::Serializer>(time: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn optional_utc_time<S: serde::Serializer>(
    time: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match time {
        Some(time) => utc_time(time, serializer),
        None => serializer.serialize_none(),
    }
}

fn budget_elapsed(route: &'static str) -> AppError {
    tracing::warn!(route, "user token request exceeded its budget");
    unavailable()
}

async fn list(
    State(state): State<SessionAuthState>,
    bounds: Option<Extension<SessionInventoryBounds>>,
    headers: HeaderMap,
    query: Result<Query<InventoryQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let bounds = bounds.map(|Extension(bounds)| bounds).unwrap_or_default();
    let result = async {
        let Query(query) =
            query.map_err(|_| AppError::BadRequest("Invalid user token query".into()))?;
        if !valid_id(&query.account_id) || query.cursor.as_deref().is_some_and(|id| !valid_id(id)) {
            return Err(AppError::BadRequest("Invalid user token query".into()));
        }
        let digest = cookie_digest(&headers)?;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(database_unavailable("begin"))?;
        bounded_transaction_within(&mut tx, bounds.statement).await?;
        let (account_id, _) = actor(&mut tx, &digest, &query.account_id, false).await?;
        let mut tokens: Vec<UserTokenMetadata> = sqlx::query_as(
            "SELECT id, created_at, expires_at, last_used_at FROM oidc_user_tokens \
             WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > clock_timestamp()) \
             AND ($2::text IS NULL OR id COLLATE \"C\" > $2 COLLATE \"C\") \
             ORDER BY id COLLATE \"C\" LIMIT $3",
        )
        .bind(&account_id)
        .bind(&query.cursor)
        .bind((PAGE_SIZE + 1) as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_unavailable("list user tokens"))?;
        if tokens.iter().any(|token| !valid_id(&token.id)) {
            return Err(unavailable());
        }
        validate_actor(&mut tx, &digest, &account_id).await?;
        let next_cursor = if tokens.len() > PAGE_SIZE {
            tokens.truncate(PAGE_SIZE);
            tokens.last().map(|token| token.id.clone())
        } else {
            None
        };
        tx.commit().await.map_err(database_unavailable("commit"))?;
        Ok::<_, AppError>(Inventory {
            account_id,
            tokens,
            next_cursor,
        })
    };
    match tokio::time::timeout(bounds.request, result).await {
        Ok(Ok(inventory)) => private(Json(inventory)),
        Ok(Err(error)) => private(error),
        Err(_) => private(budget_elapsed("list")),
    }
}

async fn revoke(
    State(state): State<SessionAuthState>,
    bounds: Option<Extension<SessionInventoryBounds>>,
    headers: HeaderMap,
    request: Result<Json<RevokeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let bounds = bounds.map(|Extension(bounds)| bounds).unwrap_or_default();
    let result = async {
        exact_origin(&headers, &state.frontend_url)?;
        let Json(request) =
            request.map_err(|_| AppError::BadRequest("Invalid user token request".into()))?;
        if !valid_id(&request.account_id) || !valid_id(&request.token_id) {
            return Err(AppError::BadRequest("Invalid user token request".into()));
        }
        let digest = cookie_digest(&headers)?;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(database_unavailable("begin"))?;
        bounded_transaction_within(&mut tx, bounds.statement).await?;
        let (account_id, _) = actor(&mut tx, &digest, &request.account_id, true).await?;
        let deleted = sqlx::query(
            "DELETE FROM oidc_user_tokens WHERE user_id = $1 AND id = $2 \
             AND (expires_at IS NULL OR expires_at > clock_timestamp())",
        )
        .bind(&account_id)
        .bind(&request.token_id)
        .execute(&mut *tx)
        .await
        .map_err(database_unavailable("delete user token"))?;
        validate_actor(&mut tx, &digest, &account_id).await?;
        if deleted.rows_affected() != 1 {
            // Another account's, an expired and a missing token answer alike.
            return Err(AppError::NotFound("Live user token not found".into()));
        }
        tx.commit().await.map_err(database_unavailable("commit"))?;
        Ok::<_, AppError>(())
    };
    match tokio::time::timeout(bounds.request, result).await {
        Ok(Ok(())) => private(Json(Revoked { revoked: true })),
        Ok(Err(error)) => private(error),
        Err(_) => private(budget_elapsed("revoke")),
    }
}
