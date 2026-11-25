//! Organization membership checks shared by org-scoped endpoints.

use sqlx::PgPool;

use crate::auth::AuthUser;
use crate::error::AppError;

/// What a new stream into an organization whose deletion has started or
/// failed is refused with (AUTH-POLICY.md, "Account access revocation").
pub const ORGANIZATION_DELETING: &str = "organization is being deleted";

/// [`ORGANIZATION_DELETING`] as the error a request is refused with, and a
/// stream ended with when the deletion starts.
pub fn organization_deleting_error() -> AppError {
    AppError::Coded {
        status: axum::http::StatusCode::CONFLICT,
        code: "organization_deleting",
        detail: ORGANIZATION_DELETING.into(),
    }
}

/// Whether `org_id` admits a new stream or connection into its environments:
/// not once its deletion has started or failed, until it is retried to the
/// end. Callers ask after the caller's own access check, so only a caller who
/// would otherwise be admitted learns why. The organization's own pages keep
/// working while it is deleted, so [`user_org_role`] does not ask this.
pub async fn org_admits_streams(pool: &PgPool, org_id: &str) -> Result<bool, sqlx::Error> {
    let active: Option<bool> =
        sqlx::query_scalar("SELECT deletion_state = 'active' FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(pool)
            .await?;
    Ok(active == Some(true))
}

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

/// Clears the saved startup script of every environment `user_id` created in
/// `org_id`, as their membership there ends: a saved script runs only for
/// its creator (SPEC.md, "The rules for the startup script after create",
/// #5949). Call it in the transaction that ends the membership, after the
/// membership row is deleted: a change that already holds the membership
/// commits first and its script is cleared here, and a later one finds no
/// membership and is refused.
pub async fn clear_departed_creator_startup_scripts(
    conn: &mut sqlx::PgConnection,
    org_id: &str,
    user_id: &str,
) -> sqlx::Result<u64> {
    sqlx::query(
        "UPDATE environments SET project_spec = project_spec - 'startup_script' \
         WHERE org_id = $1 AND created_by = $2 AND project_spec ? 'startup_script'",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
}

/// Deletes every per-environment grant `user_id` holds on `org_id`'s
/// environments as their membership there ends, and writes one
/// `environment.access.removed_with_membership` audit row, by `actor`, naming
/// those environments, so a member invited back starts with their role's
/// defaults alone (#3586). A grant can mean terminal access, which reaches the
/// creator's delivered sign-ins; without this, only the membership check
/// (#3254) holds a stale grant back. Call it in the transaction that ends the
/// membership. Returns the environments whose grants it deleted, sorted; with
/// none it writes nothing.
pub async fn delete_departed_member_grants(
    conn: &mut sqlx::PgConnection,
    org_id: &str,
    user_id: &str,
    actor: &str,
) -> sqlx::Result<Vec<String>> {
    let mut environments: Vec<String> = sqlx::query_scalar(
        "DELETE FROM environment_access a USING environments e \
         WHERE a.environment_id = e.id AND e.org_id = $1 AND a.user_id = $2 \
         RETURNING a.environment_id",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    if environments.is_empty() {
        return Ok(environments);
    }
    environments.sort();
    sqlx::query(
        "INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity) \
         VALUES (gen_random_uuid()::text, NOW(), 'environment.access.removed_with_membership', $1, '', '', $2, 'info')",
    )
    .bind(actor)
    .bind(serde_json::json!({
        "org_id": org_id, "target_user_id": user_id, "environment_ids": environments,
    }))
    .execute(conn)
    .await?;
    Ok(environments)
}

/// An email address shown to someone who may not own it (#3840): the first
/// character of the local part, then "•••", then the domain, as in
/// "j•••@example.com". Comparing two masks can only say two addresses
/// differ, never that they match.
pub fn masked_email(email: &str) -> String {
    let (local, domain) = email.rsplit_once('@').unwrap_or(("", email));
    let first: String = local.chars().take(1).collect();
    format!("{first}\u{2022}\u{2022}\u{2022}@{domain}")
}

#[cfg(test)]
mod masked_email_tests {
    use super::masked_email;

    #[test]
    fn an_address_keeps_only_its_first_character_and_domain() {
        assert_eq!(
            masked_email("jane.doe@example.com"),
            "j\u{2022}\u{2022}\u{2022}@example.com"
        );
        assert_eq!(
            masked_email("j@example.com"),
            "j\u{2022}\u{2022}\u{2022}@example.com"
        );
        assert_eq!(
            masked_email("Élise@exemple.fr"),
            "É\u{2022}\u{2022}\u{2022}@exemple.fr"
        );
        assert_eq!(
            masked_email("not-an-address"),
            "\u{2022}\u{2022}\u{2022}@not-an-address"
        );
    }
}
