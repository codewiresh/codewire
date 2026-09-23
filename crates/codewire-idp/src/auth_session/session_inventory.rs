//! Cookie-only, capability-free account session controls. Revalidation and
//! deletion share an owner-first transaction; middleware identity is not
//! sufficient authority to delete a session after the actor is revoked.

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::NaiveDateTime;
use codewire_server_core::AppError;
use codewire_server_core::auth::{SESSION_COOKIE_NAME, hash_session_token};
use serde::{Deserialize, Serialize, Serializer};
use sqlx::{Postgres, Transaction};
use std::time::Duration;

use super::{SessionAuthState, clear_cookie_string, format_time};

const PAGE_SIZE: usize = 50;
const REQUEST_BUDGET: Duration = Duration::from_secs(5);

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
    session_id: String,
}

#[derive(Serialize)]
struct CurrentSession {
    id: String,
    #[serde(serialize_with = "utc_time")]
    expires_at: NaiveDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
struct SessionMetadata {
    id: String,
    #[serde(serialize_with = "optional_utc_time")]
    created_at: Option<NaiveDateTime>,
    #[serde(serialize_with = "utc_time")]
    expires_at: NaiveDateTime,
}

#[derive(Serialize)]
struct Inventory {
    account_id: String,
    current_session: CurrentSession,
    sessions: Vec<SessionMetadata>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct Revoked {
    revoked: bool,
    current_session_revoked: bool,
}

pub(super) fn router() -> Router<SessionAuthState> {
    Router::new()
        .route("/api/auth/sessions", get(list))
        .route("/api/auth/sessions/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(2_048))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn cookie_digest(headers: &HeaderMap) -> Result<String, AppError> {
    // Never fall back to an API key, OAuth token, or bearer session token.
    // Mixed authority is rejected rather than silently selecting a credential.
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(AppError::Unauthorized);
    }
    let mut token = None;
    for cookie in headers.get_all(header::COOKIE) {
        let cookie = cookie.to_str().map_err(|_| AppError::Unauthorized)?;
        for pair in cookie.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != SESSION_COOKIE_NAME {
                continue;
            }
            if token.is_some()
                || value.is_empty()
                || value.len() > 256
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(AppError::Unauthorized);
            }
            token = Some(value);
        }
    }
    token.map(hash_session_token).ok_or(AppError::Unauthorized)
}

fn exact_origin(headers: &HeaderMap, frontend_url: &str) -> Result<(), AppError> {
    let url = reqwest::Url::parse(frontend_url).map_err(|_| unavailable())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(unavailable());
    }
    let origin =
        HeaderValue::from_str(&url.origin().ascii_serialization()).map_err(|_| unavailable())?;
    let mut actual = headers.get_all(header::ORIGIN).iter();
    if actual.next() != Some(&origin) || actual.next().is_some() {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn unavailable() -> AppError {
    AppError::ServiceUnavailable("Account session controls unavailable".into())
}

fn private(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

async fn list(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    query: Result<Query<InventoryQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let result = async {
        let Query(query) =
            query.map_err(|_| AppError::BadRequest("Invalid session query".into()))?;
        if !valid_id(&query.account_id) || query.cursor.as_deref().is_some_and(|id| !valid_id(id)) {
            return Err(AppError::BadRequest("Invalid session query".into()));
        }
        let digest = cookie_digest(&headers)?;
        let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
        bounded_transaction(&mut tx).await?;
        let (account_id, current_session) =
            actor(&mut tx, &digest, &query.account_id, false).await?;
        let mut sessions: Vec<SessionMetadata> = sqlx::query_as(
            "SELECT id,created_at,expires_at FROM sessions WHERE user_id=$1 \
             AND expires_at > clock_timestamp() AND ($2::text IS NULL OR id COLLATE \"C\" > $2 COLLATE \"C\") \
             ORDER BY id COLLATE \"C\" LIMIT $3",
        )
        .bind(&account_id)
        .bind(&query.cursor)
        .bind((PAGE_SIZE + 1) as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        if sessions.iter().any(|session| !valid_id(&session.id)) {
            return Err(unavailable());
        }
        validate_actor(&mut tx, &digest, &account_id).await?;
        let next_cursor = if sessions.len() > PAGE_SIZE {
            sessions.truncate(PAGE_SIZE);
            sessions.last().map(|s| s.id.clone())
        } else {
            None
        };
        tx.commit().await.map_err(|_| unavailable())?;
        Ok::<_, AppError>(Inventory {
            account_id,
            current_session,
            sessions,
            next_cursor,
        })
    };
    match tokio::time::timeout(REQUEST_BUDGET, result).await {
        Ok(Ok(inventory)) => private(Json(inventory)),
        Ok(Err(error)) => private(error),
        Err(_) => private(unavailable()),
    }
}

async fn revoke(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    request: Result<Json<RevokeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let result =
        async {
            exact_origin(&headers, &state.frontend_url)?;
            let Json(request) =
                request.map_err(|_| AppError::BadRequest("Invalid session request".into()))?;
            if !valid_id(&request.account_id) || !valid_id(&request.session_id) {
                return Err(AppError::BadRequest("Invalid session request".into()));
            }
            let digest = cookie_digest(&headers)?;
            let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
            bounded_transaction(&mut tx).await?;
            let (account_id, current) = actor(&mut tx, &digest, &request.account_id, true).await?;
            // Acquire the target before the final actor clock check.
            let target: Option<String> =
                sqlx::query_scalar("SELECT id FROM sessions WHERE user_id=$1 AND id=$2 FOR UPDATE")
                    .bind(&account_id)
                    .bind(&request.session_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| unavailable())?;
            validate_actor(&mut tx, &digest, &account_id).await?;
            if target.is_none() {
                return Err(AppError::NotFound("Active session not found".into()));
            }
            let deleted = sqlx::query(
            "DELETE FROM sessions WHERE user_id=$1 AND id=$2 AND expires_at > clock_timestamp() \
             AND EXISTS (SELECT 1 FROM sessions AS actor WHERE actor.token_hash=$3 \
             AND actor.user_id=$1 AND actor.expires_at > clock_timestamp())",
        ).bind(&account_id).bind(&request.session_id).bind(&digest)
            .execute(&mut *tx).await.map_err(|_| unavailable())?;
            if deleted.rows_affected() != 1 {
                // A foreign, expired, and missing target are indistinguishable.
                return Err(AppError::NotFound("Active session not found".into()));
            }
            let current_session_revoked = current.id == request.session_id;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok::<_, AppError>(current_session_revoked)
        };
    match tokio::time::timeout(REQUEST_BUDGET, result).await {
        Ok(Ok(current_session_revoked)) => {
            let mut response = private(Json(Revoked {
                revoked: true,
                current_session_revoked,
            }));
            if current_session_revoked {
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&clear_cookie_string(state.secure))
                        .expect("fixed cookie"),
                );
            }
            response
        }
        Ok(Err(error)) => private(error),
        Err(_) => private(unavailable()),
    }
}

/// Every operation locks the owner before the actor. In particular two
/// sessions concurrently revoking each other cannot form reciprocal locks.
async fn actor(
    tx: &mut Transaction<'_, Postgres>,
    digest: &str,
    expected_account: &str,
    mutating: bool,
) -> Result<(String, CurrentSession), AppError> {
    let account_id: String = sqlx::query_scalar("SELECT user_id FROM sessions WHERE token_hash=$1")
        .bind(digest)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?
        .ok_or(AppError::Unauthorized)?;
    if account_id != expected_account {
        return Err(AppError::Forbidden);
    }
    let query = if mutating {
        "SELECT enabled,COALESCE(two_factor_enabled,false) FROM users WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT enabled,COALESCE(two_factor_enabled,false) FROM users WHERE id=$1 FOR SHARE"
    };
    let (enabled, factor): (bool, bool) = sqlx::query_as(query)
        .bind(&account_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?
        .ok_or(AppError::Unauthorized)?;
    if !enabled {
        return Err(AppError::Forbidden);
    }
    // Use wall-clock time after any lock wait, not transaction-start NOW().
    let query = if mutating {
        "SELECT id,expires_at,two_factor_setup_skipped_at IS NOT NULL FROM sessions \
         WHERE token_hash=$1 AND user_id=$2 FOR UPDATE"
    } else {
        "SELECT id,expires_at,two_factor_setup_skipped_at IS NOT NULL FROM sessions \
         WHERE token_hash=$1 AND user_id=$2 FOR SHARE"
    };
    let (id, expires_at, setup_skipped): (String, NaiveDateTime, bool) = sqlx::query_as(query)
        .bind(digest)
        .bind(&account_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?
        .ok_or(AppError::Unauthorized)?;
    // The same two-factor boundary as the dashboard: an enabled factor, or
    // setup skipped by this browser session.
    if !factor && !setup_skipped {
        return Err(AppError::Forbidden);
    }
    if !valid_id(&id) {
        return Err(unavailable());
    }
    validate_actor(tx, digest, &account_id).await?;
    Ok((account_id, CurrentSession { id, expires_at }))
}

fn utc_time<S: Serializer>(time: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_time(*time))
}

fn optional_utc_time<S: Serializer>(
    time: &Option<NaiveDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match time {
        Some(time) => serializer.serialize_some(&format_time(*time)),
        None => serializer.serialize_none(),
    }
}

async fn validate_actor(
    tx: &mut Transaction<'_, Postgres>,
    digest: &str,
    account_id: &str,
) -> Result<(), AppError> {
    // A SELECT ... FOR UPDATE predicate can run before LockRows waits.
    // This statement runs after the exact actor row has been locked.
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE token_hash=$1 AND user_id=$2 \
         AND expires_at > clock_timestamp())",
    )
    .bind(digest)
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if active {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

async fn bounded_transaction(tx: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    // Cancellation alone does not end server-side lock waits. Honor stricter
    // configured limits and bound abandoned work/transactions on the server.
    let settings: Vec<String> = sqlx::query_scalar(
        "SELECT pg_catalog.set_config(name, LEAST(4000, CASE WHEN setting::bigint=0 \
         THEN 4000 ELSE setting::bigint END)::text, true) FROM pg_catalog.pg_settings \
         WHERE name IN ('statement_timeout','idle_in_transaction_session_timeout') AND unit='ms'",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    if settings.len() == 2 {
        Ok(())
    } else {
        Err(unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn database_failure_is_private_and_never_reports_success() {
        use tower::ServiceExt;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://synthetic:synthetic@127.0.0.1:9/synthetic")
            .unwrap();
        // Closing the lazy pool makes failure deterministic without networking.
        pool.close().await;
        let app = super::super::router_with_signup_delivery(
            pool,
            true,
            super::super::SignupInvitePolicy::open(),
            "https://app.codewire.test".into(),
            codewire_email::EmailClient::disabled(),
            String::new(),
            String::new(),
        );
        for (method, path, body) in [
            ("GET", "/api/auth/sessions?account_id=owner", "null"),
            (
                "POST",
                "/api/auth/sessions/revoke",
                r#"{"account_id":"owner","session_id":"session"}"#,
            ),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", "codewire.session_token=synthetic-cookie-canary")
                .header("origin", "https://app.codewire.test")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
            assert!(response.headers().get("set-cookie").is_none());
            let bytes = axum::body::to_bytes(response.into_body(), 2048)
                .await
                .unwrap();
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            for forbidden in [
                "synthetic-cookie-canary",
                "postgres://",
                "revoked",
                "PoolClosed",
            ] {
                assert!(!text.contains(forbidden));
            }
        }
    }

    #[test]
    fn cookie_authority_is_exact_and_has_no_bearer_fallback() {
        let mut headers = HeaderMap::new();
        assert!(cookie_digest(&headers).is_err());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; codewire.session_token=synthetic-token"),
        );
        assert_eq!(
            cookie_digest(&headers).unwrap(),
            hash_session_token("synthetic-token")
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=other-token"),
        );
        assert!(cookie_digest(&headers).is_err());
        headers.remove(header::COOKIE);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer synthetic-token"),
        );
        assert!(cookie_digest(&headers).is_err());
    }

    #[test]
    fn mutation_requires_one_exact_public_origin() {
        let mut headers = HeaderMap::new();
        assert!(exact_origin(&headers, "https://app.codewire.test/path").is_err());
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.codewire.test"),
        );
        assert!(exact_origin(&headers, "https://app.codewire.test/path").is_ok());
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://app.codewire.test"),
        );
        assert!(exact_origin(&headers, "https://app.codewire.test").is_err());
        headers.remove(header::ORIGIN);
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://foreign.test"),
        );
        assert!(exact_origin(&headers, "https://app.codewire.test").is_err());
    }

    #[test]
    fn closed_requests_and_capability_free_metadata() {
        assert!(
            serde_json::from_value::<RevokeRequest>(serde_json::json!({
                "account_id":"owner", "session_id":"id", "token":"must-not-be-accepted"
            }))
            .is_err()
        );
        assert!(valid_id("legacy_session-01"));
        assert!(!valid_id(""));
        assert!(!valid_id("../session"));
        let date =
            NaiveDateTime::parse_from_str("2026-09-16 19:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let value = serde_json::to_value(SessionMetadata {
            id: "id".into(),
            created_at: None,
            expires_at: date,
        })
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert!(value.get("token").is_none());
        assert!(value.get("token_hash").is_none());
        assert!(value.get("ip_address").is_none());
    }
}
