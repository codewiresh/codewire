//! `/organizations/{org_id}/members/{member_id}/assignments` (#38).
//!
//! Per-member assignment strings (the gradual role→assignment migration).
//! `GET` is readable by any org member; `PUT` is owner/admin (or
//! `super_admin` assignment) only, validates against the allowed set,
//! always keeps `viewer`, and replaces the rows in one transaction.
//!
//! huma handlers, so the error envelope is the bare `{status,title,detail}`
//! shape. Both responses are a bare JSON array (`Body []string`), which huma
//! serializes without a `$schema` member.

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult};
use schemars::JsonSchema;
use serde::Deserialize;

use super::ApiState;
use super::secrets::{forbidden, log_audit};

/// Mirrors `assignments.go::ValidAssignments` (order matters only for the
/// constant; membership is a set check).
const VALID_ASSIGNMENTS: [&str; 7] = [
    "viewer",
    "developer",
    "environments_admin",
    "sandboxes_admin",
    "billing_admin",
    "auditor",
    "super_admin",
];

pub(super) fn is_valid_assignment(s: &str) -> bool {
    VALID_ASSIGNMENTS.contains(&s)
}

/// `getUserOrgRole` failure → `huma.Error404NotFound("organization not
/// found")`, matching the Go handlers (non-members can't probe org IDs).
async fn require_org_role(state: &ApiState, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(&state.pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateMemberAssignmentsBody {
    pub assignments: Vec<String>,
}

pub(crate) async fn get_member_assignments_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    member_id: String,
) -> AppResult<Vec<String>> {
    require_org_role(&state, &user, &org_id).await?;

    let member_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM org_members WHERE id = $1 AND org_id = $2)",
    )
    .bind(&member_id)
    .bind(&org_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::from)?;
    if !member_exists {
        return Err(AppError::NotFound("member not found".into()));
    }

    let assignments: Vec<String> = sqlx::query_scalar(
        r#"SELECT a.assignment FROM org_member_assignments a
           WHERE a.org_member_id = $1
           ORDER BY a.assignment"#,
    )
    .bind(&member_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "assignments: list failed");
        AppError::InternalMsg("failed to list assignments".into())
    })?;

    Ok(assignments)
}

pub(crate) async fn update_member_assignments_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    member_id: String,
    body: UpdateMemberAssignmentsBody,
) -> AppResult<Vec<String>> {
    let caller_role = require_org_role(&state, &user, &org_id).await?;
    let caller_assignments = user_assignments(&state.pool, &org_id, &user.user_id)
        .await
        .unwrap_or_default();
    if !can_admin(&caller_role, &caller_assignments) {
        return Err(forbidden("only owner or admin can update assignments"));
    }
    for a in &body.assignments {
        if !is_valid_assignment(a) {
            return Err(AppError::BadRequest(
                format!("invalid assignment: {a}").into(),
            ));
        }
    }

    // Viewer is always included (prepended if the caller omitted it).
    let mut assignments = body.assignments;
    if !assignments.iter().any(|a| a == "viewer") {
        assignments.insert(0, "viewer".to_string());
    }

    run_organization_database_mutation(&state.pool, &org_id, async {
        // Target member must still exist after mutation admission.
        let target_role: Option<String> =
            sqlx::query_scalar(r#"SELECT role FROM org_members WHERE id = $1 AND org_id = $2"#)
                .bind(&member_id)
                .bind(&org_id)
                .fetch_optional(&state.pool)
                .await
                .map_err(AppError::from)?;
        let target_role =
            target_role.ok_or_else(|| AppError::NotFound("member not found".into()))?;

        if target_role == "owner" {
            return Err(AppError::BadRequest(
                "cannot modify owner's assignments".into(),
            ));
        }

        let mut tx = state.pool.begin().await.map_err(|e| {
            tracing::error!(error = %e, "assignments: begin tx failed");
            AppError::InternalMsg("failed to begin transaction".into())
        })?;

        sqlx::query("DELETE FROM org_member_assignments WHERE org_member_id = $1")
            .bind(&member_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "assignments: clear failed");
                AppError::InternalMsg("failed to clear assignments".into())
            })?;

        for a in &assignments {
            sqlx::query(
                r#"INSERT INTO org_member_assignments (org_member_id, assignment, granted_by)
                   VALUES ($1, $2, $3)"#,
            )
            .bind(&member_id)
            .bind(a)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "assignments: insert failed");
                AppError::InternalMsg("failed to insert assignment".into())
            })?;
        }

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "assignments: commit failed");
            AppError::InternalMsg("failed to commit transaction".into())
        })?;

        log_audit(
            &state,
            "member.assignments_updated",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id,
                "member_id": member_id,
                "assignments": assignments,
            }),
            "info",
        )
        .await;

        Ok(assignments)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn valid_assignment_set_matches_go() {
        assert!(is_valid_assignment("viewer"));
        assert!(is_valid_assignment("super_admin"));
        assert!(!is_valid_assignment("owner"));
        assert!(!is_valid_assignment(""));
        assert!(!is_valid_assignment("Viewer"));
    }

    #[test]
    fn viewer_prepended_when_missing() {
        let mut a = vec!["developer".to_string()];
        if !a.iter().any(|x| x == "viewer") {
            a.insert(0, "viewer".to_string());
        }
        assert_eq!(a, vec!["viewer".to_string(), "developer".to_string()]);
    }

    #[test]
    fn viewer_kept_in_place_when_present() {
        let mut a = vec!["developer".to_string(), "viewer".to_string()];
        if !a.iter().any(|x| x == "viewer") {
            a.insert(0, "viewer".to_string());
        }
        assert_eq!(a, vec!["developer".to_string(), "viewer".to_string()]);
    }

    #[test]
    fn update_member_assignments_schema_requires_go_required_fields() {
        let schema =
            serde_json::to_value(schemars::schema_for!(UpdateMemberAssignmentsBody)).unwrap();

        assert_eq!(schema["required"], serde_json::json!(["assignments"]));
    }

    #[test]
    fn update_member_assignments_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdateMemberAssignmentsBody>(serde_json::json!({}))
        else {
            panic!("expected missing assignments to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("assignments"));
    }

    #[test]
    fn update_member_assignments_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdateMemberAssignmentsBody>(serde_json::json!({
                "assignments": "developer"
            }))
        else {
            panic!("expected type-invalid assignments to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/assignments");
        assert!(errors[0].message.contains("array"));
    }

    #[test]
    fn update_member_assignments_validation_accepts_empty_array() {
        let parsed = validate_value::<UpdateMemberAssignmentsBody>(serde_json::json!({
            "assignments": []
        }))
        .expect("empty assignment list should stay handler-valid");

        assert!(parsed.assignments.is_empty());
    }
}
