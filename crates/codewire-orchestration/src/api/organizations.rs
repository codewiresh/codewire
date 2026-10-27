//! Shared organization service logic. Organization deletion is an asynchronous,
//! durable Temporal operation.

use codewire_server_core::auth::{AuthUser, hash_oauth_token};
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::org_deletion::{
    begin_organization_deletion, run_organization_database_mutation,
};
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::Row;

use super::ApiState;
use super::environments::format_time;
use super::secrets::{forbidden, log_audit};

#[derive(Debug)]
pub struct OrgMember {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub assignments: Vec<String>,
    pub created_at: String,
}

/// `GET /organizations/{org_id}/members` — mirrors `listMembers`.
///
/// Any member may read. Non-members get `404 organization not found`
/// (Go's literal detail; non-members can't probe org IDs).
pub(crate) async fn list_members_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
) -> AppResult<Vec<OrgMember>> {
    user_org_role(&state.pool, &user, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;

    let rows = sqlx::query(
        r#"SELECT m.id, m.org_id, m.user_id, m.role, u.email, u.name, u.image, m.created_at,
                  COALESCE(array_agg(a.assignment ORDER BY a.assignment)
                           FILTER (WHERE a.assignment IS NOT NULL), '{}') AS assignments
           FROM org_members m
           INNER JOIN users u ON u.id = m.user_id
           LEFT JOIN org_member_assignments a ON a.org_member_id = m.id
           WHERE m.org_id = $1
           GROUP BY m.id, m.org_id, m.user_id, m.role, u.email, u.name, u.image, m.created_at
           ORDER BY m.created_at ASC"#,
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: list members failed");
        AppError::InternalMsg("failed to list members".into())
    })?;

    let mut members = Vec::with_capacity(rows.len());
    for r in &rows {
        let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
        members.push(OrgMember {
            id: r.try_get("id").map_err(AppError::from)?,
            org_id: r.try_get("org_id").map_err(AppError::from)?,
            user_id: r.try_get("user_id").map_err(AppError::from)?,
            role: r.try_get("role").map_err(AppError::from)?,
            email: r.try_get("email").map_err(AppError::from)?,
            name: r.try_get("name").map_err(AppError::from)?,
            image: r.try_get("image").map_err(AppError::from)?,
            assignments: r.try_get("assignments").map_err(AppError::from)?,
            created_at: format_time(created_at),
        });
    }
    Ok(members)
}

/// Organization lifecycle state exposed while an asynchronous deletion is
/// retained. Successful deletion has no terminal enum value because the
/// organization then becomes `404 Not Found`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationDeletionState {
    Active,
    Deleting,
    DeleteFailed,
}

impl OrganizationDeletionState {
    fn from_database(value: &str) -> AppResult<Self> {
        match value {
            "active" => Ok(Self::Active),
            "deleting" => Ok(Self::Deleting),
            "delete_failed" => Ok(Self::DeleteFailed),
            other => Err(AppError::Internal(anyhow::anyhow!(
                "organization has unknown deletion state {other}"
            ))),
        }
    }
}

/// Accepted asynchronous organization deletion.
#[derive(Debug, PartialEq, Eq)]
pub struct OrganizationDeletionResponse {
    pub operation_id: String,
    pub state: OrganizationDeletionState,
}

/// Mirrors `api.OrgWithMembers` — the embedded `api.Organization`
/// fields flattened (Go struct embedding) plus the member list. The optional
/// deletion fields allow mixed-version consumers during the asynchronous
/// deletion rollout.
#[derive(Debug)]
pub struct OrgWithMembers {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub members: Vec<OrgMember>,
    pub deletion_state: Option<OrganizationDeletionState>,
    pub deletion_operation_id: Option<String>,
    pub deletion_failure_code: Option<String>,
}

pub(crate) async fn get_organization_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
) -> AppResult<OrgWithMembers> {
    user_org_role(&state.pool, &user, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;

    let org_row = sqlx::query(
        r#"SELECT id, name, slug, created_by, created_at, updated_at,
                  deletion_state, deletion_operation_id, deletion_failure_code
           FROM organizations WHERE id = $1"#,
    )
    .bind(&org_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: get organization failed");
        AppError::InternalMsg("failed to get organization".into())
    })?
    .ok_or_else(|| AppError::NotFound("organization not found".into()))?;

    let created_at: chrono::NaiveDateTime =
        org_row.try_get("created_at").map_err(AppError::from)?;
    let updated_at: chrono::NaiveDateTime =
        org_row.try_get("updated_at").map_err(AppError::from)?;

    let member_rows = sqlx::query(
        r#"SELECT m.id, m.org_id, m.user_id, m.role, u.email, u.name, u.image, m.created_at
           FROM org_members m
           INNER JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1
           ORDER BY m.created_at ASC"#,
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: list members failed");
        AppError::InternalMsg("failed to list members".into())
    })?;

    let mut members = Vec::with_capacity(member_rows.len());
    for r in &member_rows {
        let member_created_at: chrono::NaiveDateTime =
            r.try_get("created_at").map_err(AppError::from)?;
        members.push(OrgMember {
            id: r.try_get("id").map_err(AppError::from)?,
            org_id: r.try_get("org_id").map_err(AppError::from)?,
            user_id: r.try_get("user_id").map_err(AppError::from)?,
            role: r.try_get("role").map_err(AppError::from)?,
            email: r.try_get("email").map_err(AppError::from)?,
            name: r.try_get("name").map_err(AppError::from)?,
            image: r.try_get("image").map_err(AppError::from)?,
            assignments: Vec::new(),
            created_at: format_time(member_created_at),
        });
    }

    Ok(OrgWithMembers {
        id: org_row.try_get("id").map_err(AppError::from)?,
        name: org_row.try_get("name").map_err(AppError::from)?,
        slug: org_row.try_get("slug").map_err(AppError::from)?,
        created_by: org_row.try_get("created_by").map_err(AppError::from)?,
        created_at: format_time(created_at),
        updated_at: format_time(updated_at),
        members,
        deletion_state: Some(OrganizationDeletionState::from_database(
            &org_row
                .try_get::<String, _>("deletion_state")
                .map_err(AppError::from)?,
        )?),
        deletion_operation_id: org_row
            .try_get("deletion_operation_id")
            .map_err(AppError::from)?,
        deletion_failure_code: org_row
            .try_get("deletion_failure_code")
            .map_err(AppError::from)?,
    })
}

pub(crate) async fn delete_organization_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
) -> AppResult<OrganizationDeletionResponse> {
    let operation = begin_organization_deletion(&state.pool, &user, &org_id).await?;
    Ok(OrganizationDeletionResponse {
        operation_id: operation.id,
        state: OrganizationDeletionState::Deleting,
    })
}

/// Mirrors `isValidRole`.
fn is_valid_role(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "member")
}

/// Target member's role by `(org_id, user_id)`. Unlike `user_org_role`
/// this is not AuthUser-scoped: by the time it runs the caller has already
/// passed their own membership gate, so Go's `getUserOrgRole` api-key check
/// on the target is a no-op (the caller's key is nil or matches org_id).
async fn target_member_role(
    state: &ApiState,
    org_id: &str,
    user_id: &str,
) -> AppResult<Option<String>> {
    sqlx::query_scalar(r#"SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2"#)
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::from)
}

#[derive(Debug)]
pub struct UpdateRoleBody {
    pub role: String,
}

pub(crate) async fn update_member_role_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    user_id: String,
    body: UpdateRoleBody,
) -> AppResult<()> {
    let caller_role = user_org_role(&state.pool, &user, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    let caller_assignments = user_assignments(&state.pool, &org_id, &user.user_id)
        .await
        .unwrap_or_default();
    if !can_admin(&caller_role, &caller_assignments) {
        return Err(forbidden("only owner or admin can update member roles"));
    }
    if !is_valid_role(&body.role) {
        return Err(AppError::BadRequest(
            "role must be 'owner', 'admin', or 'member'".into(),
        ));
    }

    run_organization_database_mutation(&state.pool, &org_id, async {
        let target_role = target_member_role(&state, &org_id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("member not found".into()))?;

        if target_role == "owner" && body.role != "owner" {
            let owner_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'"#,
            )
            .bind(&org_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "organizations: count owners failed");
                AppError::InternalMsg("failed to count owners".into())
            })?;
            if owner_count <= 1 {
                return Err(AppError::BadRequest("cannot demote the last owner".into()));
            }
        }

        if caller_role == "admin" {
            if body.role == "owner" {
                return Err(forbidden("admins cannot promote to owner"));
            }
            if target_role == "owner" || target_role == "admin" {
                return Err(forbidden("admins cannot change owner or admin roles"));
            }
        }

        sqlx::query(
            r#"UPDATE org_members SET role = $1, updated_at = NOW() WHERE org_id = $2 AND user_id = $3"#,
        )
        .bind(&body.role)
        .bind(&org_id)
        .bind(&user_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: update role failed");
            AppError::InternalMsg("failed to update role".into())
        })?;

        log_audit(
            &state,
            "member.role_changed",
            &user.user_id,
            serde_json::json!({"org_id": org_id, "target_user_id": user_id, "new_role": body.role}),
            "info",
        )
        .await;
        Ok(())
    })
    .await
}

pub(crate) async fn remove_member_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    user_id: String,
) -> AppResult<()> {
    let caller_role = user_org_role(&state.pool, &user, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    let caller_assignments = user_assignments(&state.pool, &org_id, &user.user_id)
        .await
        .unwrap_or_default();

    if user.user_id != user_id && !can_admin(&caller_role, &caller_assignments) {
        return Err(forbidden("only owner or admin can remove members"));
    }
    run_organization_database_mutation(&state.pool, &org_id, async {
        let target_role = target_member_role(&state, &org_id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("member not found".into()))?;

        if target_role == "owner" {
            return Err(AppError::BadRequest("cannot remove the owner".into()));
        }
        if caller_role == "admin" && target_role == "admin" {
            return Err(forbidden("admins cannot remove other admins"));
        }

        delete_membership(&state.pool, &org_id, &user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "organizations: remove member failed");
                AppError::InternalMsg("failed to remove member".into())
            })?;

        log_audit(
            &state,
            "member.removed",
            &user.user_id,
            serde_json::json!({"org_id": org_id, "target_user_id": user_id}),
            "warn",
        )
        .await;
        Ok(())
    })
    .await
}

/// Deletes a membership and disables the member's API keys for that
/// organization in one transaction. A key bound to the organization must not
/// outlive the membership, and a later re-add does not revive it (#3254).
async fn delete_membership(pool: &sqlx::PgPool, org_id: &str, user_id: &str) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(r#"DELETE FROM org_members WHERE org_id = $1 AND user_id = $2"#)
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"UPDATE api_keys SET disabled_at = NOW()
           WHERE org_id = $1 AND user_id = $2 AND disabled_at IS NULL"#,
    )
    .bind(org_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

// ── Invitations (org-scoped CRUD) ────────────────────────────────────────

/// The invitation hand-off stays a permanent browser-facing JSON route.
#[derive(Debug, Serialize)]
pub struct OrgInvitation {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub inviter_name: Option<String>,
    pub status: String,
    pub expires_at: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

/// A newly created invitation plus the one-time bearer capability returned to
/// its creator. Stored and list/read invitation models never carry this value.
pub struct CreatedInvitation {
    pub invitation: OrgInvitation,
    pub token: String,
}

impl std::fmt::Debug for CreatedInvitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedInvitation")
            .field("invitation", &self.invitation)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub struct InviteMemberBody {
    pub email: String,
    pub role: String,
    pub assignments: Vec<String>,
}

/// owner/admin gate after membership; the 403 detail varies by route.
async fn require_org_admin(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    detail: &'static str,
) -> AppResult<String> {
    let role = user_org_role(&state.pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    let assignments = user_assignments(&state.pool, org_id, &user.user_id)
        .await
        .unwrap_or_default();
    if !can_admin(&role, &assignments) {
        return Err(forbidden(detail));
    }
    Ok(role)
}

fn invitation_row(r: &sqlx::postgres::PgRow) -> Result<OrgInvitation, AppError> {
    let expires_at: chrono::NaiveDateTime = r.try_get("expires_at").map_err(AppError::from)?;
    let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
    let accepted_at: Option<chrono::NaiveDateTime> =
        r.try_get("accepted_at").map_err(AppError::from)?;
    Ok(OrgInvitation {
        id: r.try_get("id").map_err(AppError::from)?,
        org_id: r.try_get("org_id").map_err(AppError::from)?,
        org_name: r
            .try_get::<Option<String>, _>("org_name")
            .map_err(AppError::from)?
            .unwrap_or_default(),
        email: r.try_get("email").map_err(AppError::from)?,
        role: r.try_get("role").map_err(AppError::from)?,
        invited_by: r.try_get("invited_by").map_err(AppError::from)?,
        inviter_name: r.try_get("inviter_name").map_err(AppError::from)?,
        status: r.try_get("status").map_err(AppError::from)?,
        expires_at: format_time(expires_at),
        created_at: format_time(created_at),
        accepted_at: accepted_at.map(format_time),
    })
}

pub(crate) async fn get_invitation_by_token_core(
    state: ApiState,
    token: String,
) -> AppResult<OrgInvitation> {
    let token_hash = hash_oauth_token(&token);
    let row = sqlx::query(
        r#"SELECT i.id, i.org_id, o.name AS org_name, i.email, i.role, i.invited_by,
                  u.name AS inviter_name, i.status, i.expires_at, i.created_at, i.accepted_at
           FROM org_invitations i
           LEFT JOIN users u ON u.id = i.invited_by
           LEFT JOIN organizations o ON o.id = i.org_id
           WHERE i.token_hash = $1"#,
    )
    .bind(token_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: get invitation by token failed");
        AppError::InternalMsg("failed to get invitation".into())
    })?
    .ok_or_else(|| AppError::NotFound("invitation not found".into()))?;
    invitation_row(&row)
}

/// `GET /organizations/{org_id}/invitations` — mirrors `listInvitations`.
pub(crate) async fn list_invitations_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
) -> AppResult<Vec<OrgInvitation>> {
    require_org_admin(
        &state,
        &user,
        &org_id,
        "only owner or admin can view invitations",
    )
    .await?;

    let rows = sqlx::query(
        r#"SELECT i.id, i.org_id, o.name AS org_name, i.email, i.role, i.invited_by,
                  u.name AS inviter_name, i.status, i.expires_at, i.created_at, i.accepted_at
           FROM org_invitations i
           LEFT JOIN users u ON u.id = i.invited_by
           LEFT JOIN organizations o ON o.id = i.org_id
           WHERE i.org_id = $1
           ORDER BY i.created_at DESC"#,
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: list invitations failed");
        AppError::InternalMsg("failed to list invitations".into())
    })?;

    let mut invitations = Vec::with_capacity(rows.len());
    for r in &rows {
        invitations.push(invitation_row(r)?);
    }
    Ok(invitations)
}

pub(crate) async fn create_invitation_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    body: InviteMemberBody,
) -> AppResult<CreatedInvitation> {
    let caller_role = require_org_admin(
        &state,
        &user,
        &org_id,
        "only owner or admin can invite members",
    )
    .await?;

    let email = body.email.to_lowercase();
    let email = email.trim();
    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".into()));
    }
    let role = if body.role.is_empty() {
        "member"
    } else {
        body.role.as_str()
    };
    if !is_valid_role(role) {
        return Err(AppError::BadRequest(
            "role must be 'owner', 'admin', or 'member'".into(),
        ));
    }
    if caller_role == "admin" && role == "owner" {
        return Err(forbidden("admins cannot invite as owner"));
    }

    run_organization_database_mutation(&state.pool, &org_id, async {
    let existing: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM org_members m INNER JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 AND u.email = $2"#,
    )
    .bind(&org_id)
    .bind(email)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: check membership failed");
        AppError::InternalMsg("failed to check existing membership".into())
    })?;
    if existing > 0 {
        return Err(AppError::Conflict(
            "user is already a member of this organization".into(),
        ));
    }

    let pending: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM org_invitations
           WHERE org_id = $1 AND email = $2 AND status = 'pending' AND expires_at > NOW()"#,
    )
    .bind(&org_id)
    .bind(email)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: check invitations failed");
        AppError::InternalMsg("failed to check existing invitations".into())
    })?;
    if pending > 0 {
        return Err(AppError::Conflict(
            "a pending invitation already exists for this email".into(),
        ));
    }

    let mut assignments = body.assignments;
    for a in &assignments {
        if !super::assignments::is_valid_assignment(a) {
            return Err(AppError::BadRequest(
                format!("invalid assignment: {a}").into(),
            ));
        }
    }
    if !assignments.iter().any(|a| a == "viewer") {
        assignments.insert(0, "viewer".to_string());
    }

    let inv_id = uuid::Uuid::new_v4().simple().to_string();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let token_hash = hash_oauth_token(&token);
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::days(7);

    sqlx::query(
        r#"INSERT INTO org_invitations
            (id, org_id, email, role, invited_by, token_hash, status, expires_at, created_at, assignments)
           VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)"#,
    )
    .bind(&inv_id)
    .bind(&org_id)
    .bind(email)
    .bind(role)
    .bind(&user.user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(now)
    .bind(&assignments)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: create invitation failed");
        AppError::InternalMsg("failed to create invitation".into())
    })?;

    let inviter_name: Option<String> =
        sqlx::query_scalar(r#"SELECT name FROM users WHERE id = $1"#)
            .bind(&user.user_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .flatten();

    log_audit(
        &state,
        "member.invited",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "email": email, "role": role}),
        "info",
    )
    .await;

    Ok(CreatedInvitation {
        invitation: OrgInvitation {
            id: inv_id,
            org_id: org_id.clone(),
            org_name: String::new(),
            email: email.to_string(),
            role: role.to_string(),
            invited_by: user.user_id.clone(),
            inviter_name,
            status: "pending".to_string(),
            expires_at: format_time(expires_at),
            created_at: format_time(now),
            accepted_at: None,
        },
        token,
    })
    })
    .await
}

pub(crate) async fn revoke_invitation_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    invitation_id: String,
) -> AppResult<()> {
    require_org_admin(
        &state,
        &user,
        &org_id,
        "only owner or admin can revoke invitations",
    )
    .await?;

    run_organization_database_mutation(&state.pool, &org_id, async {
        let result = sqlx::query(
            r#"UPDATE org_invitations SET status = 'revoked'
               WHERE id = $1 AND org_id = $2 AND status = 'pending'"#,
        )
        .bind(&invitation_id)
        .bind(&org_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: revoke invitation failed");
            AppError::InternalMsg("failed to revoke invitation".into())
        })?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(
                "invitation not found or already processed".into(),
            ));
        }
        Ok(())
    })
    .await
}

#[derive(Debug)]
pub struct AcceptInvitationResult {
    pub status: String,
    pub org_id: String,
}

pub(crate) async fn accept_invitation_core(
    state: ApiState,
    user: AuthUser,
    token: String,
) -> AppResult<AcceptInvitationResult> {
    let token_hash = hash_oauth_token(&token);
    let caller_email: String = sqlx::query_scalar(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(&user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: load caller email failed");
            AppError::InternalMsg("failed to load user".into())
        })?;

    // Resolve the organization only to enter its mutation barrier. The row is
    // claimed again, atomically, inside the database transaction below.
    let org_id: String =
        sqlx::query_scalar(r#"SELECT org_id FROM org_invitations WHERE token_hash = $1"#)
            .bind(&token_hash)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "organizations: load invitation failed");
                AppError::InternalMsg("failed to get invitation".into())
            })?
            .ok_or_else(|| AppError::NotFound("invitation not found".into()))?;

    run_organization_database_mutation(
        &state.pool,
        &org_id,
        accept_invitation_transaction(
            &state.pool,
            &org_id,
            &token_hash,
            &caller_email,
            &user.user_id,
        ),
    )
    .await
}

async fn accept_invitation_transaction(
    pool: &sqlx::PgPool,
    org_id: &str,
    token_hash: &str,
    caller_email: &str,
    user_id: &str,
) -> AppResult<AcceptInvitationResult> {
    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: accept begin tx failed");
        AppError::InternalMsg("failed to begin transaction".into())
    })?;

    // This update is the single-use claim. Membership and assignment writes
    // commit in this same transaction, so any later failure rolls the
    // invitation back to pending.
    let claimed = sqlx::query(
        r#"UPDATE org_invitations
           SET status = 'accepted', accepted_at = NOW()
           WHERE token_hash = $1
             AND status = 'pending'
             AND expires_at > NOW()
           RETURNING org_id, email, role, assignments"#,
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: claim invitation failed");
        AppError::InternalMsg("failed to accept invitation".into())
    })?;

    let Some(claimed) = claimed else {
        let state_row: Option<(String, chrono::NaiveDateTime)> = sqlx::query_as(
            r#"SELECT status, expires_at
               FROM org_invitations
               WHERE token_hash = $1
               FOR UPDATE"#,
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: inspect unclaimable invitation failed");
            AppError::InternalMsg("failed to accept invitation".into())
        })?;
        match state_row {
            Some((status, expires_at))
                if status == "pending" && chrono::Utc::now().naive_utc() > expires_at =>
            {
                sqlx::query(
                    r#"UPDATE org_invitations
                       SET status = 'expired'
                       WHERE token_hash = $1 AND status = 'pending'"#,
                )
                .bind(token_hash)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Err(AppError::BadRequest("invitation has expired".into()));
            }
            Some((status, _)) => {
                return Err(AppError::BadRequest(
                    format!("invitation is {status}").into(),
                ));
            }
            None => return Err(AppError::NotFound("invitation not found".into())),
        }
    };

    let claimed_org_id: String = claimed.try_get("org_id").map_err(AppError::from)?;
    let email: String = claimed.try_get("email").map_err(AppError::from)?;
    let role: String = claimed.try_get("role").map_err(AppError::from)?;
    let mut assignments: Vec<String> = claimed.try_get("assignments").map_err(AppError::from)?;
    if claimed_org_id != org_id {
        return Err(AppError::InternalMsg(
            "invitation organization changed during acceptance".into(),
        ));
    }
    if !caller_email.eq_ignore_ascii_case(&email) {
        return Err(forbidden(
            "invitation was sent to a different email address",
        ));
    }

    if assignments.is_empty() {
        assignments.push("viewer".to_string());
    }
    let member_id = uuid::Uuid::new_v4().simple().to_string();
    let now = chrono::Utc::now().naive_utc();

    let member = sqlx::query(
        r#"INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)
           ON CONFLICT (org_id, user_id) DO NOTHING"#,
    )
    .bind(&member_id)
    .bind(org_id)
    .bind(user_id)
    .bind(&role)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: add member failed");
        AppError::InternalMsg("failed to add member".into())
    })?;
    if member.rows_affected() == 0 {
        tx.commit().await?;
        return Err(AppError::Conflict(
            "you are already a member of this organization".into(),
        ));
    }
    for assignment in &assignments {
        sqlx::query(
            r#"INSERT INTO org_member_assignments (org_member_id, assignment)
               VALUES ($1, $2) ON CONFLICT DO NOTHING"#,
        )
        .bind(&member_id)
        .bind(assignment)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: accept insert assignment failed");
            AppError::InternalMsg("failed to insert assignment".into())
        })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: accept commit failed");
        AppError::InternalMsg("failed to commit transaction".into())
    })?;

    Ok(AcceptInvitationResult {
        status: "accepted".to_string(),
        org_id: claimed_org_id,
    })
}

// ── Org list / create (#38) ──────────────────────────────────────────────

#[derive(Debug)]
pub struct OrgWithRole {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub role: String,
    pub assignments: Vec<String>,
    pub billing_plan: String,
    pub billing_status: String,
    pub trial_ends_at: Option<String>,
}

#[derive(Debug)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug)]
pub struct CreateOrgBody {
    pub name: String,
    pub slug: String,
}

pub(crate) async fn list_organizations_core(
    state: ApiState,
    user: AuthUser,
) -> AppResult<Vec<OrgWithRole>> {
    list_memberships(&state.pool, &user).await
}

/// The caller's organizations with their role and assignments in each, read
/// in one statement: one database round trip whatever the number of
/// organizations.
async fn list_memberships(pool: &sqlx::PgPool, user: &AuthUser) -> AppResult<Vec<OrgWithRole>> {
    let scoped = user.via_api_key && user.org_id.as_deref().is_some_and(|o| !o.is_empty());

    let base = r#"SELECT o.id, o.name, o.slug, o.created_by, o.created_at, o.updated_at,
                         m.role, o.billing_plan, o.billing_status, o.trial_ends_at,
                         ARRAY(SELECT a.assignment FROM org_member_assignments a
                                WHERE a.org_member_id = m.id) AS assignments
                  FROM organizations o
                  INNER JOIN org_members m ON m.org_id = o.id
                  WHERE m.user_id = $1"#;
    let q = if scoped {
        format!("{base} AND o.id = $2 ORDER BY o.created_at DESC")
    } else {
        format!("{base} ORDER BY o.created_at DESC")
    };
    let mut query = sqlx::query(&q).bind(&user.user_id);
    if scoped {
        query = query.bind(user.org_id.as_deref().unwrap());
    }
    let rows = query.fetch_all(pool).await.map_err(|e| {
        tracing::error!(error = %e, "organizations: list failed");
        AppError::InternalMsg("failed to list organizations".into())
    })?;

    let mut result = Vec::with_capacity(rows.len());
    for r in &rows {
        let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
        let updated_at: chrono::NaiveDateTime = r.try_get("updated_at").map_err(AppError::from)?;
        let trial_ends_at: Option<chrono::NaiveDateTime> =
            r.try_get("trial_ends_at").map_err(AppError::from)?;
        result.push(OrgWithRole {
            id: r.try_get("id").map_err(AppError::from)?,
            name: r.try_get("name").map_err(AppError::from)?,
            slug: r.try_get("slug").map_err(AppError::from)?,
            created_by: r.try_get("created_by").map_err(AppError::from)?,
            created_at: format_time(created_at),
            updated_at: format_time(updated_at),
            role: r.try_get("role").map_err(AppError::from)?,
            assignments: r.try_get("assignments").map_err(AppError::from)?,
            billing_plan: r.try_get("billing_plan").map_err(AppError::from)?,
            billing_status: r.try_get("billing_status").map_err(AppError::from)?,
            trial_ends_at: trial_ends_at.map(format_time),
        });
    }
    Ok(result)
}

pub(crate) async fn create_organization_core(
    state: ApiState,
    user: AuthUser,
    body: CreateOrgBody,
) -> AppResult<Organization> {
    let name = body.name.trim();
    let slug = body.slug.trim().to_lowercase();
    let slug = slug.as_str();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if slug.is_empty() {
        return Err(AppError::BadRequest("slug is required".into()));
    }
    if !codewire_server_core::organization_slug::valid_organization_slug(slug) {
        return Err(AppError::BadRequest(
            "slug is reserved or does not match the canonical route-safe format".into(),
        ));
    }

    let org_id = uuid::Uuid::new_v4().simple().to_string();
    let member_id = uuid::Uuid::new_v4().simple().to_string();
    let now = chrono::Utc::now().naive_utc();

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: create begin tx failed");
        AppError::InternalMsg("failed to begin transaction".into())
    })?;
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)"#,
    )
    .bind(&org_id)
    .bind(name)
    .bind(slug)
    .bind(&user.user_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique constraint") {
            return AppError::Conflict("organization slug already exists".into());
        }
        tracing::error!(error = %e, "organizations: create failed");
        AppError::InternalMsg("failed to create organization".into())
    })?;
    sqlx::query(
        r#"INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
           VALUES ($1, $2, $3, 'owner', $4, $4)"#,
    )
    .bind(&member_id)
    .bind(&org_id)
    .bind(&user.user_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: add owner failed");
        AppError::InternalMsg("failed to add owner membership".into())
    })?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: create commit failed");
        AppError::InternalMsg("failed to commit transaction".into())
    })?;

    log_audit(
        &state,
        "org.created",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "name": name, "slug": slug}),
        "info",
    )
    .await;

    Ok(Organization {
        id: org_id,
        name: name.to_string(),
        slug: slug.to_string(),
        created_by: user.user_id.clone(),
        created_at: format_time(now),
        updated_at: format_time(now),
    })
}

#[cfg(test)]
mod membership_database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_invitation_debug_redacts_one_time_capability() {
        let created = CreatedInvitation {
            invitation: OrgInvitation {
                id: "invitation".into(),
                org_id: "org".into(),
                org_name: "Organization".into(),
                email: "invitee@example.test".into(),
                role: "member".into(),
                invited_by: "owner".into(),
                inviter_name: None,
                status: "pending".into(),
                expires_at: "2026-09-06T00:00:00Z".into(),
                created_at: "2026-09-05T00:00:00Z".into(),
                accepted_at: None,
            },
            token: "invitation-capability-marker".into(),
        };

        let diagnostic = format!("{created:?}");
        assert!(!diagnostic.contains("invitation-capability-marker"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn invitation_claim_is_digest_only_atomic_and_single_use() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping invitation capability DB test");
            return;
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        let suffix = std::process::id();
        let owner = format!("invitation_owner_{suffix}");
        let invitee = format!("invitation_invitee_{suffix}");
        let org = format!("invitation_org_{suffix}");
        let invitation = format!("invitation_{suffix}");
        let raw_token = format!("synthetic-invitation-capability-{suffix}");
        let token_hash = hash_oauth_token(&raw_token);
        let invitee_email = format!("invitation-invitee-{suffix}@example.test");

        let cleanup = |pool: sqlx::PgPool| {
            let owner = owner.clone();
            let invitee = invitee.clone();
            let org = org.clone();
            async move {
                let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
                    .bind(&org)
                    .execute(&pool)
                    .await;
                let _ = sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
                    .bind(&owner)
                    .bind(&invitee)
                    .execute(&pool)
                    .await;
            }
        };
        cleanup(pool.clone()).await;

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2), ($3, $4)")
            .bind(&owner)
            .bind(format!("invitation-owner-{suffix}@example.test"))
            .bind(&invitee)
            .bind(&invitee_email)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org)
        .bind("Invitation Test")
        .bind(format!("invitation-test-{suffix}"))
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO org_invitations \
             (id, org_id, email, role, invited_by, token_hash, expires_at, assignments) \
             VALUES ($1, $2, $3, 'member', $4, $5, NOW() + INTERVAL '1 hour', \
                     ARRAY['viewer'])",
        )
        .bind(&invitation)
        .bind(&org)
        .bind(&invitee_email)
        .bind(&owner)
        .bind(&token_hash)
        .execute(&pool)
        .await
        .unwrap();

        let persisted: String =
            sqlx::query_scalar("SELECT token_hash FROM org_invitations WHERE id = $1")
                .bind(&invitation)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(persisted, token_hash);
        assert_ne!(persisted, raw_token);

        let first =
            accept_invitation_transaction(&pool, &org, &token_hash, &invitee_email, &invitee);
        let second =
            accept_invitation_transaction(&pool, &org, &token_hash, &invitee_email, &invitee);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "exactly one concurrent invitation claimant succeeds"
        );

        let (status, member_count, assignment_count): (String, i64, i64) = sqlx::query_as(
            "SELECT i.status, \
                    (SELECT COUNT(*) FROM org_members m \
                     WHERE m.org_id = i.org_id AND m.user_id = $2), \
                    (SELECT COUNT(*) FROM org_member_assignments a \
                     JOIN org_members m ON m.id = a.org_member_id \
                     WHERE m.org_id = i.org_id AND m.user_id = $2) \
             FROM org_invitations i WHERE i.id = $1",
        )
        .bind(&invitation)
        .bind(&invitee)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "accepted");
        assert_eq!(member_count, 1);
        assert_eq!(assignment_count, 1);
        assert!(
            accept_invitation_transaction(&pool, &org, &token_hash, &invitee_email, &invitee,)
                .await
                .is_err(),
            "accepted invitation capability must reject replay"
        );

        cleanup(pool.clone()).await;
    }
}
