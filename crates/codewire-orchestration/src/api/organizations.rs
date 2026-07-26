//! Rust-owned organization REST compatibility surface. Organization deletion
//! is an asynchronous, durable Temporal operation; the REST routes remain only
//! for the planned Connect per-area dual-serving window.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::org_deletion::{
    begin_organization_deletion, run_organization_database_mutation,
};
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::ApiState;
use super::environments::format_time;
use super::secrets::{StatusResponse, forbidden, log_audit};

/// Mirrors `api.OrgMember`. `name`/`image` are Go `*string` with no
/// `omitempty` → serialize as `null` when absent (serde `Option` default).
/// `assignments` is `omitempty` → dropped when empty.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OrgMember {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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

pub async fn list_members(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<OrgMember>>> {
    Ok(Json(list_members_core(state, user, org_id).await?))
}

/// Organization lifecycle state exposed while an asynchronous deletion is
/// retained. Successful deletion has no terminal enum value because the
/// organization then becomes `404 Not Found`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct OrganizationDeletionResponse {
    pub operation_id: String,
    pub state: OrganizationDeletionState,
}

/// Mirrors `api.OrgWithMembers` — the embedded `api.Organization`
/// fields flattened (Go struct embedding) plus the member list. The optional
/// deletion fields allow mixed-version consumers during the asynchronous
/// deletion rollout.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OrgWithMembers {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub members: Vec<OrgMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_state: Option<OrganizationDeletionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_failure_code: Option<String>,
}

/// `GET /api/v1/organizations/{org_id}` — mirrors `getOrganization`.
///
/// Any member may read; non-members get `404 organization not found`.
/// The member list here omits `assignments` (the Go scan doesn't select
/// them and the field is `omitempty`), so the reused `OrgMember` carries
/// an empty `assignments` vec, which serde drops.
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

pub async fn get_organization(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<OrgWithMembers>> {
    Ok(Json(get_organization_core(state, user, org_id).await?))
}

/// `DELETE /api/v1/organizations/{org_id}` atomically fences the organization
/// and persists a recoverable Temporal start intent. The reconciler starts the
/// deterministic workflow; duplicate requests return the same accepted
/// operation instead of executing a second deletion.
pub async fn delete_organization(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<(StatusCode, Json<OrganizationDeletionResponse>)> {
    Ok((
        StatusCode::ACCEPTED,
        Json(delete_organization_core(state, user, org_id).await?),
    ))
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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateRoleBody {
    pub role: String,
}

/// `PUT /organizations/{org_id}/members/{user_id}` — mirrors
/// `updateMemberRole`. Owner/admin gate, role validation, last-owner +
/// admin-restriction rules, then `UPDATE` + audit.
pub async fn update_member_role(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, user_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<UpdateRoleBody>,
) -> AppResult<Json<StatusResponse>> {
    Ok(Json(
        update_member_role_core(state, user, org_id, user_id, body).await?,
    ))
}

pub(crate) async fn update_member_role_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    user_id: String,
    body: UpdateRoleBody,
) -> AppResult<StatusResponse> {
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
        Ok(StatusResponse { status: "updated" })
    })
    .await
}

/// `DELETE /organizations/{org_id}/members/{user_id}` — mirrors
/// `removeMember` (204). Self-removal allowed; otherwise owner/admin, with
/// the owner-protection + admin-cannot-remove-admin rules.
pub async fn remove_member(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, user_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    remove_member_core(state, user, org_id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
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

        sqlx::query(r#"DELETE FROM org_members WHERE org_id = $1 AND user_id = $2"#)
            .bind(&org_id)
            .bind(&user_id)
            .execute(&state.pool)
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

// ── Invitations (org-scoped CRUD) ────────────────────────────────────────

/// Mirrors `api.OrgInvitation`. `org_name`/`inviter_name` have no
/// `omitempty` (inviter_name is `*string` → `null`); `accepted_at` is
/// `omitempty`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OrgInvitation {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub inviter_name: Option<String>,
    pub token: String,
    pub status: String,
    pub expires_at: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InviteMemberBody {
    pub email: String,
    pub role: String,
    #[serde(default)]
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
        token: r.try_get("token").map_err(AppError::from)?,
        status: r.try_get("status").map_err(AppError::from)?,
        expires_at: format_time(expires_at),
        created_at: format_time(created_at),
        accepted_at: accepted_at.map(format_time),
    })
}

/// `GET /api/v1/invitations/{token}` — mirrors `getInvitationByToken`
/// (`registerPublicInvitationRoutes`). UNAUTHENTICATED: registered outside
/// `require_auth`, looks an invitation up by its opaque token. 404 when no
/// row matches. The companion `POST /invitations/{token}/accept` mints
/// membership and stays on Go, so the edge flip anchors this path
/// (`…/invitations/[^/]+$`) to avoid catching `…/accept`.
pub async fn get_invitation_by_token(
    State(state): State<ApiState>,
    Path(token): Path<String>,
) -> AppResult<Json<OrgInvitation>> {
    Ok(Json(get_invitation_by_token_core(state, token).await?))
}

pub(crate) async fn get_invitation_by_token_core(
    state: ApiState,
    token: String,
) -> AppResult<OrgInvitation> {
    let row = sqlx::query(
        r#"SELECT i.id, i.org_id, o.name AS org_name, i.email, i.role, i.invited_by,
                  u.name AS inviter_name, i.token, i.status, i.expires_at, i.created_at, i.accepted_at
           FROM org_invitations i
           LEFT JOIN users u ON u.id = i.invited_by
           LEFT JOIN organizations o ON o.id = i.org_id
           WHERE i.token = $1"#,
    )
    .bind(&token)
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
pub async fn list_invitations(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<OrgInvitation>>> {
    Ok(Json(list_invitations_core(state, user, org_id).await?))
}

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
                  u.name AS inviter_name, i.token, i.status, i.expires_at, i.created_at, i.accepted_at
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

/// `POST /organizations/{org_id}/invitations` — mirrors `createInvitation` (201).
pub async fn create_invitation(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(body): ValidatedJson<InviteMemberBody>,
) -> AppResult<(StatusCode, Json<OrgInvitation>)> {
    Ok((
        StatusCode::CREATED,
        Json(create_invitation_core(state, user, org_id, body).await?),
    ))
}

pub(crate) async fn create_invitation_core(
    state: ApiState,
    user: AuthUser,
    org_id: String,
    body: InviteMemberBody,
) -> AppResult<OrgInvitation> {
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
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::days(7);

    sqlx::query(
        r#"INSERT INTO org_invitations
            (id, org_id, email, role, invited_by, token, status, expires_at, created_at, assignments)
           VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)"#,
    )
    .bind(&inv_id)
    .bind(&org_id)
    .bind(email)
    .bind(role)
    .bind(&user.user_id)
    .bind(&token)
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

    Ok(OrgInvitation {
            id: inv_id,
            org_id: org_id.clone(),
            org_name: String::new(),
            email: email.to_string(),
            role: role.to_string(),
            invited_by: user.user_id.clone(),
            inviter_name,
            token,
            status: "pending".to_string(),
            expires_at: format_time(expires_at),
            created_at: format_time(now),
            accepted_at: None,
        })
    })
    .await
}

/// `DELETE /organizations/{org_id}/invitations/{invitation_id}` — mirrors
/// `revokeInvitation` (204). Only flips a still-`pending` row.
pub async fn revoke_invitation(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, invitation_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    revoke_invitation_core(state, user, org_id, invitation_id).await?;
    Ok(StatusCode::NO_CONTENT)
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

/// Mirrors `api.AcceptInvitationResult` — note `org_id` serializes as the
/// camelCase `orgId` (Go's json tag), unlike the snake_case elsewhere.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AcceptInvitationResult {
    pub status: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
}

/// `POST /invitations/{token}/accept` — mirrors `acceptInvitation`.
/// Authenticated (main router): the caller joins the org the invitation
/// targets, in one transaction. Mints membership + assignments and marks
/// the invitation accepted.
pub async fn accept_invitation(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(token): Path<String>,
) -> AppResult<Json<AcceptInvitationResult>> {
    Ok(Json(accept_invitation_core(state, user, token).await?))
}

pub(crate) async fn accept_invitation_core(
    state: ApiState,
    user: AuthUser,
    token: String,
) -> AppResult<AcceptInvitationResult> {
    let caller_email: String = sqlx::query_scalar(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(&user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: load caller email failed");
            AppError::InternalMsg("failed to load user".into())
        })?;

    let row = sqlx::query(
        r#"SELECT id, org_id, email, role, status, expires_at, assignments
           FROM org_invitations WHERE token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: load invitation failed");
        AppError::InternalMsg("failed to get invitation".into())
    })?
    .ok_or_else(|| AppError::NotFound("invitation not found".into()))?;

    let inv_id: String = row.try_get("id").map_err(AppError::from)?;
    let org_id: String = row.try_get("org_id").map_err(AppError::from)?;
    let email: String = row.try_get("email").map_err(AppError::from)?;
    let role: String = row.try_get("role").map_err(AppError::from)?;
    let status: String = row.try_get("status").map_err(AppError::from)?;
    let expires_at: chrono::NaiveDateTime = row.try_get("expires_at").map_err(AppError::from)?;
    let mut assignments: Vec<String> = row.try_get("assignments").map_err(AppError::from)?;

    if status != "pending" {
        return Err(AppError::BadRequest(
            format!("invitation is {status}").into(),
        ));
    }
    run_organization_database_mutation(&state.pool, &org_id, async {
        if chrono::Utc::now().naive_utc() > expires_at {
            let _ = sqlx::query(r#"UPDATE org_invitations SET status = 'expired' WHERE id = $1"#)
                .bind(&inv_id)
                .execute(&state.pool)
                .await;
            return Err(AppError::BadRequest("invitation has expired".into()));
        }
        if !caller_email.eq_ignore_ascii_case(&email) {
            return Err(forbidden(
                "invitation was sent to a different email address",
            ));
        }
        let existing: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND user_id = $2"#,
        )
        .bind(&org_id)
        .bind(&user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: check membership failed");
            AppError::InternalMsg("failed to check membership".into())
        })?;
        if existing > 0 {
            let _ = sqlx::query(
            r#"UPDATE org_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = $1"#,
        )
        .bind(&inv_id)
        .execute(&state.pool)
        .await;
            return Err(AppError::Conflict(
                "you are already a member of this organization".into(),
            ));
        }

        if assignments.is_empty() {
            assignments.push("viewer".to_string());
        }
        let member_id = uuid::Uuid::new_v4().simple().to_string();
        let now = chrono::Utc::now().naive_utc();

        let mut tx = state.pool.begin().await.map_err(|e| {
            tracing::error!(error = %e, "organizations: accept begin tx failed");
            AppError::InternalMsg("failed to begin transaction".into())
        })?;
        sqlx::query(
            r#"INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)"#,
        )
        .bind(&member_id)
        .bind(&org_id)
        .bind(&user.user_id)
        .bind(&role)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: add member failed");
            AppError::InternalMsg("failed to add member".into())
        })?;
        for a in &assignments {
            sqlx::query(
                r#"INSERT INTO org_member_assignments (org_member_id, assignment)
               VALUES ($1, $2) ON CONFLICT DO NOTHING"#,
            )
            .bind(&member_id)
            .bind(a)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "organizations: accept insert assignment failed");
                AppError::InternalMsg("failed to insert assignment".into())
            })?;
        }
        sqlx::query(
            r#"UPDATE org_invitations SET status = 'accepted', accepted_at = $1 WHERE id = $2"#,
        )
        .bind(now)
        .bind(&inv_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: mark invitation accepted failed");
            AppError::InternalMsg("failed to update invitation".into())
        })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "organizations: accept commit failed");
            AppError::InternalMsg("failed to commit transaction".into())
        })?;

        Ok(AcceptInvitationResult {
            status: "accepted".to_string(),
            org_id: org_id.clone(),
        })
    })
    .await
}

// ── Org list / create (#38) ──────────────────────────────────────────────

/// Mirrors `api.OrgWithRole` (Go embeds `Organization`, so the JSON is flat).
/// `assignments` is `omitempty`; `trial_ends_at` is `*string` with no
/// `omitempty` → `null` when absent.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OrgWithRole {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub role: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<String>,
    pub billing_plan: String,
    pub billing_status: String,
    pub trial_ends_at: Option<String>,
}

/// Mirrors `api.Organization` (the bare create response).
#[derive(Debug, Serialize, JsonSchema)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateOrgBody {
    pub name: String,
    pub slug: String,
}

/// `GET /organizations` — mirrors `listOrganizations`. Lists the orgs the
/// caller is a member of (an org-scoped API key narrows to its org).
pub async fn list_organizations(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<Vec<OrgWithRole>>> {
    Ok(Json(list_organizations_core(state, user).await?))
}

pub(crate) async fn list_organizations_core(
    state: ApiState,
    user: AuthUser,
) -> AppResult<Vec<OrgWithRole>> {
    let scoped = user.via_api_key && user.org_id.as_deref().is_some_and(|o| !o.is_empty());

    let base = r#"SELECT o.id, o.name, o.slug, o.created_by, o.created_at, o.updated_at,
                         m.role, o.billing_plan, o.billing_status, o.trial_ends_at
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
    let rows = query.fetch_all(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "organizations: list failed");
        AppError::InternalMsg("failed to list organizations".into())
    })?;

    let mut result = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: String = r.try_get("id").map_err(AppError::from)?;
        let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
        let updated_at: chrono::NaiveDateTime = r.try_get("updated_at").map_err(AppError::from)?;
        let trial_ends_at: Option<chrono::NaiveDateTime> =
            r.try_get("trial_ends_at").map_err(AppError::from)?;
        // Per-org assignments (Go ignores the error → empty on failure).
        let assignments = user_assignments(&state.pool, &id, &user.user_id)
            .await
            .unwrap_or_default();
        result.push(OrgWithRole {
            id,
            name: r.try_get("name").map_err(AppError::from)?,
            slug: r.try_get("slug").map_err(AppError::from)?,
            created_by: r.try_get("created_by").map_err(AppError::from)?,
            created_at: format_time(created_at),
            updated_at: format_time(updated_at),
            role: r.try_get("role").map_err(AppError::from)?,
            assignments,
            billing_plan: r.try_get("billing_plan").map_err(AppError::from)?,
            billing_status: r.try_get("billing_status").map_err(AppError::from)?,
            trial_ends_at: trial_ends_at.map(format_time),
        });
    }
    Ok(result)
}

/// `POST /organizations` — mirrors `createOrganization` (201). Creates the
/// org and the caller's owner membership in one transaction.
pub async fn create_organization(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<CreateOrgBody>,
) -> AppResult<(StatusCode, Json<Organization>)> {
    Ok((
        StatusCode::CREATED,
        Json(create_organization_core(state, user, body).await?),
    ))
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
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn valid_role_matches_go() {
        for r in ["owner", "admin", "member"] {
            assert!(is_valid_role(r));
        }
        assert!(!is_valid_role("superuser"));
        assert!(!is_valid_role(""));
    }

    #[test]
    fn member_shape_matches_go() {
        // name/image null when absent (no omitempty); assignments dropped
        // when empty (omitempty).
        let v = serde_json::to_value(OrgMember {
            id: "m1".into(),
            org_id: "o1".into(),
            user_id: "u1".into(),
            role: "owner".into(),
            email: "a@b.c".into(),
            name: None,
            image: None,
            assignments: vec![],
            created_at: "2026-01-10T00:00:00Z".into(),
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.get("name").unwrap().is_null());
        assert!(obj.get("image").unwrap().is_null());
        assert!(!obj.contains_key("assignments"));

        let v2 = serde_json::to_value(OrgMember {
            id: "m2".into(),
            org_id: "o1".into(),
            user_id: "u2".into(),
            role: "member".into(),
            email: "x@y.z".into(),
            name: Some("Nm".into()),
            image: None,
            assignments: vec!["developer".into(), "viewer".into()],
            created_at: "2026-01-11T00:00:00Z".into(),
        })
        .unwrap();
        assert_eq!(
            v2["assignments"],
            serde_json::json!(["developer", "viewer"])
        );
        assert_eq!(v2["name"], "Nm");
    }

    #[test]
    fn organization_deletion_wire_shapes_expose_active_and_accepted_states() {
        let active = serde_json::to_value(OrgWithMembers {
            id: "org_test".into(),
            name: "Test".into(),
            slug: "test".into(),
            created_by: "user_test".into(),
            created_at: "2026-07-19T00:00:00Z".into(),
            updated_at: "2026-07-19T00:00:00Z".into(),
            members: Vec::new(),
            deletion_state: Some(OrganizationDeletionState::Active),
            deletion_operation_id: None,
            deletion_failure_code: None,
        })
        .unwrap();
        let active = active.as_object().unwrap();
        assert_eq!(active["deletion_state"], "active");
        assert!(!active.contains_key("deletion_operation_id"));
        assert!(!active.contains_key("deletion_failure_code"));

        assert_eq!(
            serde_json::to_value(OrganizationDeletionResponse {
                operation_id: "op_test".into(),
                state: OrganizationDeletionState::Deleting,
            })
            .unwrap(),
            serde_json::json!({"operation_id": "op_test", "state": "deleting"})
        );

        assert!(matches!(
            OrganizationDeletionState::from_database("unexpected"),
            Err(AppError::Internal(_))
        ));
    }

    #[test]
    fn organization_request_schemas_require_go_required_fields() {
        let create_schema = serde_json::to_value(schemars::schema_for!(CreateOrgBody)).unwrap();
        assert_eq!(
            create_schema["required"],
            serde_json::json!(["name", "slug"])
        );

        let role_schema = serde_json::to_value(schemars::schema_for!(UpdateRoleBody)).unwrap();
        assert_eq!(role_schema["required"], serde_json::json!(["role"]));

        let invite_schema = serde_json::to_value(schemars::schema_for!(InviteMemberBody)).unwrap();
        assert_eq!(
            invite_schema["required"],
            serde_json::json!(["email", "role"])
        );
    }

    #[test]
    fn create_org_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateOrgBody>(serde_json::json!({
                "name": "Acme"
            }))
        else {
            panic!("expected missing slug to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("slug"));
    }

    #[test]
    fn update_role_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdateRoleBody>(serde_json::json!({
                "role": 7
            }))
        else {
            panic!("expected type-invalid role to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/role");
        assert!(errors[0].message.contains("string"));
    }

    #[test]
    fn invite_member_validation_defaults_missing_assignments() {
        let body = validate_value::<InviteMemberBody>(serde_json::json!({
            "email": "new@example.com",
            "role": "member"
        }))
        .expect("assignments should remain optional");

        assert!(body.assignments.is_empty());
    }
}
