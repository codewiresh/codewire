//! Accepting an invitation: by its token or its id, for the caller's own
//! verified (or, with no mail, vouched) address, inside the organization's
//! mutation barrier.

use super::*;

#[derive(Debug)]
pub struct AcceptInvitationResult {
    pub status: String,
    pub org_id: String,
}

/// How an AcceptInvitation names its invitation: the one-time token from the
/// emailed link, or an id from ListMyInvitations.
pub(crate) enum AcceptInvitationBy {
    Token(String),
    Id(String),
}

impl AcceptInvitationBy {
    /// Exactly one of the request's `token` and `invitation_id` is set.
    pub(crate) fn from_request(token: String, invitation_id: String) -> AppResult<Self> {
        match (token.is_empty(), invitation_id.is_empty()) {
            (false, true) => Ok(Self::Token(token)),
            (true, false) => Ok(Self::Id(invitation_id)),
            _ => Err(AppError::BadRequest(
                "set exactly one of token and invitation_id".into(),
            )),
        }
    }
}

/// The column and value that select one invitation row. Only the token's
/// digest is ever stored or compared.
pub(super) enum InvitationKey {
    TokenHash(String),
    Id(String),
}

impl InvitationKey {
    fn column(&self) -> &'static str {
        match self {
            Self::TokenHash(_) => "token_hash",
            Self::Id(_) => "id",
        }
    }

    pub(super) fn value(&self) -> &str {
        match self {
            Self::TokenHash(value) | Self::Id(value) => value,
        }
    }
}

pub(crate) async fn accept_invitation_core(
    state: ApiState,
    user: AuthUser,
    by: AcceptInvitationBy,
) -> AppResult<AcceptInvitationResult> {
    accept_invitation(&state.pool, &user, by).await
}

/// Accepts an invitation for the caller, who must use an account credential,
/// not an organization API key. In both forms the caller's email address must
/// equal the invitation's and must be verified; the transaction checks both
/// after its claim, so a refusal leaves the invitation pending. To a caller
/// at another address an invitation is not found, in every state, exactly as
/// an unknown id or token is.
pub(crate) async fn accept_invitation(
    pool: &sqlx::PgPool,
    user: &AuthUser,
    by: AcceptInvitationBy,
) -> AppResult<AcceptInvitationResult> {
    // Joining an organization acts for the account, in either form, so an
    // organization API key cannot accept (docs/dev/AUTH-POLICY.md).
    user.require_account_credential()?;
    let key = match by {
        AcceptInvitationBy::Token(token) => InvitationKey::TokenHash(hash_oauth_token(&token)),
        AcceptInvitationBy::Id(id) => InvitationKey::Id(id),
    };

    // Resolve the organization only to enter its mutation barrier. The row is
    // claimed again, atomically, inside the database transaction below.
    let org_id: String = sqlx::query_scalar(&format!(
        "SELECT org_id FROM org_invitations WHERE {} = $1",
        key.column()
    ))
    .bind(key.value())
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: load invitation failed");
        AppError::InternalMsg("failed to get invitation".into())
    })?
    .ok_or_else(invitation_not_found)?;

    run_organization_database_mutation(
        pool,
        &org_id,
        accept_invitation_transaction(pool, &org_id, &key, &user.user_id),
    )
    .await
}

pub(super) async fn accept_invitation_transaction(
    pool: &sqlx::PgPool,
    org_id: &str,
    key: &InvitationKey,
    user_id: &str,
) -> AppResult<AcceptInvitationResult> {
    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: accept begin tx failed");
        AppError::InternalMsg("failed to begin transaction".into())
    })?;

    // This update is the single-use claim. Membership and assignment writes
    // commit in this same transaction, so any later failure rolls the
    // invitation back to pending.
    let claimed = sqlx::query(&format!(
        r#"UPDATE org_invitations
           SET status = 'accepted', accepted_at = NOW()
           WHERE {} = $1
             AND status = 'pending'
             AND expires_at > NOW()
           RETURNING org_id, email, role, assignments,
                     created_at > NOW() - make_interval(hours => {}) AS issued_within_vouch_window"#,
        key.column(),
        VOUCHED_LINK_HOURS,
    ))
    .bind(key.value())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: claim invitation failed");
        AppError::InternalMsg("failed to accept invitation".into())
    })?;

    let Some(claimed) = claimed else {
        let state_row: Option<(String, chrono::NaiveDateTime, String)> = sqlx::query_as(&format!(
            r#"SELECT status, expires_at, email
                   FROM org_invitations
                   WHERE {} = $1
                   FOR UPDATE"#,
            key.column()
        ))
        .bind(key.value())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: inspect unclaimable invitation failed");
            AppError::InternalMsg("failed to accept invitation".into())
        })?;
        let Some((status, expires_at, email)) = state_row else {
            return Err(invitation_not_found());
        };
        // Only the invitee learns an invitation's state, and only the invitee's
        // attempt marks a lapsed one expired.
        if !caller_address(&mut tx, user_id, &email).await?.matches {
            return Err(invitation_not_found());
        }
        if status == "pending" && chrono::Utc::now().naive_utc() > expires_at {
            sqlx::query(&format!(
                r#"UPDATE org_invitations
                   SET status = 'expired'
                   WHERE {} = $1 AND status = 'pending'"#,
                key.column()
            ))
            .bind(key.value())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(AppError::BadRequest("invitation has expired".into()));
        }
        return Err(AppError::BadRequest(
            format!("invitation is {status}").into(),
        ));
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
    // To anyone but the invitee the invitation does not exist; returning here
    // drops the transaction, which rolls the claim back.
    let caller = caller_address(&mut tx, user_id, &email).await?;
    if !caller.matches {
        return Err(invitation_not_found());
    }
    // Anyone holding the link could otherwise register the invitee's address
    // without owning its mailbox and join with the invitation's role.
    if !caller.verified && !vouched_for_this_link(&caller, key, &claimed)? {
        return Err(AppError::Precondition(
            "verify your email address, then accept the invitation again".into(),
        ));
    }

    if assignments.is_empty() {
        assignments.push("viewer".to_string());
    }

    // Re-check plan team-member cap under the organization lock so pending
    // invitations issued before a plan downgrade (or while a subscription
    // became inactive) cannot bypass the current plan cap (#6659). Returning
    // an error rolls back the invitation claim above.
    let already_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: check existing member failed");
        AppError::InternalMsg("failed to accept invitation".into())
    })?;
    if !already_member {
        super::enforce_plan_team_member_cap_in(&mut tx, org_id, false).await?;
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

/// How long after its issue an invitation's own link admits a vouched account,
/// the same day the IdP gives that link's sign-up on a server with no mail.
pub(super) const VOUCHED_LINK_HOURS: i64 = 24;

/// On a server with no mail the admin vouches for an address instead of a
/// mailbox proving it (#4121): a vouched account accepts only by the
/// invitation's own token, within [`VOUCHED_LINK_HOURS`] of its issue. The
/// claim computes the window in SQL, on the database's clock, as it checks
/// `expires_at`.
pub(super) fn vouched_for_this_link(
    caller: &AddressProof,
    key: &InvitationKey,
    claimed: &sqlx::postgres::PgRow,
) -> AppResult<bool> {
    let within_window: Option<bool> = claimed
        .try_get("issued_within_vouch_window")
        .map_err(AppError::from)?;
    Ok(caller.vouched && matches!(key, InvitationKey::TokenHash(_)) && within_window == Some(true))
}

/// What a caller who is not the invitee sees, whatever the invitation's
/// state: the same answer as for an id or token that names nothing.
pub(super) fn invitation_not_found() -> AppError {
    AppError::NotFound("invitation not found".into())
}

/// Reads the caller's address against an invitation's inside `tx`
/// ([`address_proof::read`]), holding the caller's row until the membership
/// it admits commits.
pub(super) async fn caller_address(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    invitation_email: &str,
) -> AppResult<AddressProof> {
    address_proof::read(tx, user_id, Some(invitation_email))
        .await
        .and_then(|proof| proof.ok_or(sqlx::Error::RowNotFound))
        .map_err(|e| {
            tracing::error!(error = %e, "organizations: load caller email failed");
            AppError::InternalMsg("failed to load user".into())
        })
}
