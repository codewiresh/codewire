//! Organization membership checks shared by org-scoped endpoints.

use sqlx::PgPool;

use crate::auth::AuthUser;
use crate::error::AppError;

/// Returns the caller's role in `org_id`:
///
/// 1. An API key scoped to a different org never grants access, even if
///    the key's user is a member of `org_id`.
/// 2. Otherwise the role comes from `org_members`.
///
/// Callers usually translate `None` to `404 organization not found` so
/// non-members cannot probe organization IDs.
pub async fn user_org_role(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<Option<String>, AppError> {
    if !user.permits_organization(org_id) {
        return Ok(None);
    }

    let role: Option<String> =
        sqlx::query_scalar(r#"SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2"#)
            .bind(org_id)
            .bind(&user.user_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::from)?;

    Ok(role)
}

/// Convenience for the common handler pattern: membership or
/// `404 organization not found`.
pub async fn require_org_member(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<String, AppError> {
    user_org_role(pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

/// Per-member assignment strings.
pub async fn user_assignments(
    pool: &PgPool,
    org_id: &str,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        r#"SELECT a.assignment FROM org_member_assignments a
           JOIN org_members m ON m.id = a.org_member_id
           WHERE m.org_id = $1 AND m.user_id = $2"#,
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Mirrors `assignments.go::canAdmin`: owner/admin role, or the
/// `super_admin` assignment.
pub fn can_admin(role: &str, assignments: &[String]) -> bool {
    role == "owner" || role == "admin" || assignments.iter().any(|a| a == "super_admin")
}
