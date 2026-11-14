//! A global administrator deletes someone else's account (#4541).
//!
//! `POST /api/admin/accounts/{user_id}/delete` takes the account's address,
//! the admin's password and a fresh second factor: an authenticator code in
//! a later time step than any accepted, or an unused recovery code, which it
//! consumes. A failure counts against the admin's sign-in lockout. The proof
//! locks the admin's row; the deletion then locks the account's, so two
//! admins acting on each other wait rather than deadlock, and in the same
//! transaction it checks again that the actor is still an admin and the
//! account is not one. Each admin may ask for a fixed number of deletions an
//! hour, a count no setting can raise. The deletion itself is the account's
//! own deletion, recorded with the admin as its actor.

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use codewire_server_core::AppError;
use codewire_server_core::account_deletion::{
    DELETED_USER_ID, Initiator, begin_account_deletion_in,
};
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::rate_limit::{ADMIN_ACCOUNT_DELETE, take_fixed_for_user};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::auth_session::{
    cookie_digest, exact_origin, hex_id, private, request_info, unavailable, valid_id,
};
use crate::two_factor::{
    Proof, ProofKeys, ProofRequest, TwoFactorReplacementBounds, account_locked, fresh_proof,
    malformed, proof_rejected, validate_proof_request,
};

const BODY_LIMIT_BYTES: usize = 2_048;

#[derive(Clone)]
struct AdminDeleteState {
    pool: PgPool,
    session_secret: String,
    frontend_url: String,
}

/// The account's address, and the admin's password and second factor.
/// Deliberately not `Debug`: the password and the code are secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRequest {
    confirm_email: String,
    password: String,
    proof: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteResponse {
    operation_id: String,
}

pub fn router(
    pool: PgPool,
    session_secret: String,
    frontend_url: String,
    auth: AuthState,
) -> Router {
    Router::new()
        .route("/api/admin/accounts/{user_id}/delete", post(delete_account))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth))
        .with_state(AdminDeleteState {
            pool,
            session_secret,
            frontend_url,
        })
}

async fn delete_account(
    State(state): State<AdminDeleteState>,
    bounds: Option<Extension<TwoFactorReplacementBounds>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    actor: AuthUser,
    request: Result<Json<DeleteRequest>, JsonRejection>,
) -> Response {
    let bounds = bounds.map(|Extension(bounds)| bounds).unwrap_or_default();
    let result = tokio::time::timeout(
        bounds.request,
        request_deletion(&state, bounds, &user_id, &headers, &actor, request),
    )
    .await;
    match result {
        Ok(Ok(operation_id)) => private(Json(DeleteResponse { operation_id })),
        Ok(Err(error)) => private(error),
        Err(_) => private(unavailable()),
    }
}

async fn request_deletion(
    state: &AdminDeleteState,
    bounds: TwoFactorReplacementBounds,
    user_id: &str,
    headers: &HeaderMap,
    actor: &AuthUser,
    request: Result<Json<DeleteRequest>, JsonRejection>,
) -> Result<String, AppError> {
    actor.require_global_admin()?;
    exact_origin(headers, &state.frontend_url)?;
    let digest = cookie_digest(headers)?;
    let Json(request) = request.map_err(|_| malformed())?;
    if !valid_id(user_id) || user_id == DELETED_USER_ID {
        return Err(AppError::NotFound("Account not found".into()));
    }
    if user_id == actor.user_id {
        return Err(AppError::BadRequest(
            "delete your own account from Settings".into(),
        ));
    }
    if request.confirm_email.trim().is_empty() || request.confirm_email.len() > 320 {
        return Err(malformed());
    }
    let proof_request = ProofRequest {
        account_id: actor.user_id.clone(),
        password: request.password,
        proof: request.proof,
    };
    validate_proof_request(&proof_request)?;

    // The cap counts every attempt, before the password is checked.
    let mut connection = state.pool.acquire().await.map_err(|_| unavailable())?;
    let decision = take_fixed_for_user(&mut connection, &ADMIN_ACCOUNT_DELETE, &actor.user_id)
        .await
        .map_err(|_| unavailable())?;
    drop(connection);
    if !decision.allowed {
        return Err(AppError::Coded {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            detail: decision
                .refusal("account deletions", &ADMIN_ACCOUNT_DELETE)
                .into(),
        });
    }

    let keys = ProofKeys {
        pool: &state.pool,
        session_secret: &state.session_secret,
    };
    let (mut tx, proof) = fresh_proof(keys, bounds.statement, &digest, &proof_request).await?;
    let (ip, user_agent) = request_info(headers);
    let used_recovery_code = match proof {
        Proof::Accepted(account) => account.used_recovery_code,
        Proof::Rejected { now_locked, .. } => {
            audit(
                &mut tx,
                "admin.account.deletion_refused",
                &actor.user_id,
                user_id,
                (&ip, &user_agent),
                json!({ "reason": "proof_rejected" }),
            )
            .await?;
            tx.commit().await.map_err(|_| unavailable())?;
            return Err(if now_locked {
                account_locked()
            } else {
                proof_rejected()
            });
        }
        Proof::Locked { .. } => {
            tx.commit().await.map_err(|_| unavailable())?;
            return Err(account_locked());
        }
    };

    // Any refusal here rolls back the whole transaction, the proof included:
    // nothing was deleted, so the code stays unspent.
    let operation = begin_account_deletion_in(
        &mut tx,
        user_id,
        Initiator::Admin {
            actor_user_id: &actor.user_id,
            confirm_email: &request.confirm_email,
        },
    )
    .await?;
    audit(
        &mut tx,
        "admin.account.deletion_requested",
        &actor.user_id,
        user_id,
        (&ip, &user_agent),
        json!({
            "operation_id": operation.id,
            "proof": if used_recovery_code { "recovery_code" } else { "authenticator" },
        }),
    )
    .await?;
    tx.commit().await.map_err(|_| unavailable())?;
    Ok(operation.id)
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: &str,
    actor: &str,
    target: &str,
    (ip, user_agent): (&str, &str),
    metadata: serde_json::Value,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO audit_logs
               (id, timestamp, action, user_id, target_user_id, ip_address,
                user_agent, metadata, severity)
           VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, 'warn')"#,
    )
    .bind(hex_id())
    .bind(action)
    .bind(actor)
    .bind(target)
    .bind(ip)
    .bind(user_agent)
    .bind(metadata)
    .execute(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    Ok(())
}
