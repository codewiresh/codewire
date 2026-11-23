//! Sandbox identity's records (#4663; docs/dev/SANDBOX-IDENTITY.md), behind
//! `SandboxIdentityService`: each hosted Sandbox's identity groups
//! ([`groups`]), the audiences an organization registered ([`audiences`]),
//! and the switches that stop minting for one Sandbox or a whole
//! organization ([`stops`]).
//!
//! Only an organization owner or admin (`can_admin`) changes any of them; a
//! platform administrator may also stop and resume minting. Every change
//! writes its `audit_logs` row, with the organization's ID in its metadata,
//! in the transaction that makes it. Minting reads these tables and is not
//! here.

pub mod audiences;
pub mod groups;
pub mod stops;

#[cfg(test)]
mod audiences_database_tests;
#[cfg(test)]
mod database_test_support;
#[cfg(test)]
mod groups_database_tests;
#[cfg(test)]
mod stops_database_tests;

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::{AppError, AppResult};
use sqlx::{PgConnection, PgPool};

use super::environments::coded;

/// The caller's role in `org_id`, or `organization not found`, so a
/// non-member cannot tell an organization exists.
async fn member_role(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(pool, user, org_id).await?.ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        )
    })
}

/// Whether a member with `role` is an owner or admin of `org_id`.
pub(crate) async fn is_org_admin(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    role: &str,
) -> AppResult<bool> {
    Ok(can_admin(
        role,
        &user_assignments(pool, org_id, &user.user_id).await?,
    ))
}

/// A member who is an owner or admin of `org_id`, or the refusal.
async fn require_org_admin(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<()> {
    let role = member_role(pool, user, org_id).await?;
    if is_org_admin(pool, user, org_id, &role).await? {
        return Ok(());
    }
    Err(not_identity_admin())
}

fn not_identity_admin() -> AppError {
    coded(
        StatusCode::FORBIDDEN,
        "not_identity_admin",
        "only an organization owner or admin can change sandbox identity",
    )
}

fn environment_not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "env_not_found",
        "environment not found",
    )
}

/// `environment_id`'s creator, when it is a Sandbox of `org_id`, locked as
/// `lock` says.
async fn environment_in_org(
    connection: &mut PgConnection,
    org_id: &str,
    environment_id: &str,
    lock: &str,
) -> AppResult<Option<String>> {
    let creator: Option<Option<String>> = sqlx::query_scalar(&format!(
        "SELECT created_by FROM environments WHERE id = $1 AND org_id = $2 {lock}"
    ))
    .bind(environment_id)
    .bind(org_id)
    .fetch_optional(&mut *connection)
    .await?;
    creator.ok_or_else(environment_not_found)
}

/// One `audit_logs` row, in the caller's transaction. The organization's ID
/// is in every identity row's metadata.
async fn audit(
    connection: &mut PgConnection,
    action: &str,
    actor: &str,
    metadata: serde_json::Value,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, \
         metadata, severity) \
         VALUES (gen_random_uuid()::text, NOW(), $1, $2, '', '', $3, 'info')",
    )
    .bind(action)
    .bind(actor)
    .bind(metadata)
    .execute(&mut *connection)
    .await?;
    Ok(())
}
