//! Suspending an account and the organizations it alone owns (#3297 item 4):
//! an administrator's one-step response to abuse, in one transaction
//! (`private-docs: designs/2026-11-13-account-suspend.md`).
//!
//! Suspending disables the account (the `codewire_revoke_user_capabilities`
//! trigger revokes its sessions, OIDC tokens and API keys), marks each
//! organization it is the only owner of, narrows those organizations' public
//! and organization-wide ports to their creator, and audits each step. A
//! suspended organization refuses creates, starts and snapshots
//! (`environments::admission`), and the worker stops its running
//! environments. An organization with another owner is left to that owner and
//! returned for the administrator to act on, but what the account created in
//! it, as in any organization it doesn't alone own, is stopped and its ports
//! narrowed: an account invited into someone else's organization keeps
//! nothing running there.
//!
//! Unsuspending re-enables the account and clears the marks of the
//! organizations its suspension made (`organizations.suspended_for`).
//! It restores nothing that suspending revoked or stopped: sessions, API keys
//! and OIDC tokens stay revoked, environments stay stopped, ports stay with
//! their creator.

use codewire_server_core::account_deletion::DELETED_USER_ID;
use codewire_server_core::{AppError, AppResult, ValidationIssue};

/// The longest reason an administrator may record.
pub const MAX_SUSPENSION_REASON_CHARS: usize = 2_000;

/// What a suspension changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSuspension {
    /// Organizations the account alone owned, now suspended.
    pub suspended_organizations: Vec<String>,
    /// Organizations the account owns with someone else, left as they were.
    pub shared_organizations: Vec<String>,
    /// Environments the account created in organizations it doesn't alone own:
    /// stopped by the worker and their ports narrowed too, so an account
    /// invited into someone else's organization keeps nothing running there.
    pub created_environments: Vec<String>,
    /// Ports narrowed to their creator.
    pub ports_restricted: u64,
}

/// What an unsuspension changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUnsuspension {
    /// Organizations whose suspension was cleared.
    pub unsuspended_organizations: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct OwnedOrganization {
    org_id: String,
    owners: i64,
}

fn failure(action: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |error| {
        tracing::error!(error = %error, action, "admin: account suspension query failed");
        AppError::InternalMsg(format!("failed to {action}").into())
    }
}

fn invalid(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: path.into(),
            message: message.into(),
        }],
    }
}

/// Locks the account and says whether it is suspended now.
async fn lock_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> AppResult<bool> {
    if user_id == DELETED_USER_ID {
        return Err(AppError::NotFound("account not found".into()));
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT suspended_at IS NOT NULL FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(failure("lock account"))?
    .ok_or_else(|| AppError::NotFound("account not found".into()))
}

/// The organizations `user_id` owns, split into those it alone owns and those
/// it shares, each organization row locked in id order, the order admission
/// takes it in.
async fn owned_organizations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> AppResult<(Vec<String>, Vec<String>)> {
    let owned = sqlx::query_as::<_, OwnedOrganization>(
        r#"SELECT o.id AS org_id,
                  (SELECT count(*) FROM org_members owner
                    WHERE owner.org_id = o.id AND owner.role = 'owner') AS owners
           FROM organizations o
           JOIN org_members m ON m.org_id = o.id AND m.user_id = $1 AND m.role = 'owner'
           ORDER BY o.id
           FOR UPDATE OF o"#,
    )
    .bind(user_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(failure("read owned organizations"))?;
    let (mut sole, mut shared) = (Vec::new(), Vec::new());
    for organization in owned {
        if organization.owners == 1 {
            sole.push(organization.org_id);
        } else {
            shared.push(organization.org_id);
        }
    }
    Ok((sole, shared))
}

async fn audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: &str,
    admin_user_id: &str,
    target_user_id: &str,
    metadata: serde_json::Value,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, target_user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, $4, 'warn')"#,
    )
    .bind(action)
    .bind(admin_user_id)
    .bind(target_user_id)
    .bind(metadata)
    .execute(&mut **transaction)
    .await
    .map_err(failure("record account suspension audit"))?;
    Ok(())
}

/// Suspends `user_id` and the organizations it alone owns, recording `reason`.
pub(crate) async fn suspend_account_core(
    pool: &sqlx::PgPool,
    admin_user_id: &str,
    user_id: &str,
    reason: &str,
) -> AppResult<AccountSuspension> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > MAX_SUSPENSION_REASON_CHARS {
        return Err(invalid("/reason", "say why, in at most 2000 characters"));
    }
    if admin_user_id == user_id {
        return Err(AppError::BadRequest(
            "you cannot suspend your own account".into(),
        ));
    }
    let mut transaction = pool.begin().await.map_err(failure("begin suspension"))?;
    if lock_account(&mut transaction, user_id).await? {
        return Err(AppError::Conflict(
            "this account is already suspended".into(),
        ));
    }
    // An account being deleted is already disabled and on its way out; the
    // list offers no Suspend for it, and this refuses it too (#5769).
    // Order: `lock_account` holds the users row before this read, and a
    // deletion's start updates that row before inserting its operation, so
    // whichever comes second waits and then sees the other's commit.
    let deleting: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account_deletion_operations WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(failure("read account deletion"))?;
    if deleting {
        return Err(AppError::Conflict("this account is being deleted".into()));
    }
    sqlx::query(
        "UPDATE users SET enabled = false, suspended_at = NOW(), suspended_by = $2, \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(admin_user_id)
    .execute(&mut *transaction)
    .await
    .map_err(failure("suspend account"))?;

    let (sole, shared) = owned_organizations(&mut transaction, user_id).await?;
    sqlx::query(
        "UPDATE organizations SET suspended_at = NOW(), suspended_by = $2, suspended_for = $3 \
         WHERE id = ANY($1) AND suspended_at IS NULL",
    )
    .bind(&sole)
    .bind(admin_user_id)
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(failure("suspend organizations"))?;
    let created_environments: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM environments WHERE created_by = $1 AND NOT (org_id = ANY($2)) \
         AND state NOT IN ('destroyed', 'destroying', 'archived') ORDER BY id",
    )
    .bind(user_id)
    .bind(&sole)
    .fetch_all(&mut *transaction)
    .await
    .map_err(failure("read created environments"))?;
    let ports_restricted = sqlx::query(
        r#"UPDATE environment_ports p SET access = 'creator'
           FROM environments e
           WHERE p.environment_id = e.id AND p.access <> 'creator'
             AND (e.org_id = ANY($1) OR e.created_by = $2)"#,
    )
    .bind(&sole)
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(failure("restrict ports"))?
    .rows_affected();

    audit(
        &mut transaction,
        "admin.account.suspended",
        admin_user_id,
        user_id,
        serde_json::json!({
            "reason": reason,
            "suspended_organizations": sole,
            "shared_organizations": shared,
            "created_environments": created_environments,
            "ports_restricted": ports_restricted,
        }),
    )
    .await?;
    for organization_id in &sole {
        audit(
            &mut transaction,
            "admin.organization.suspended",
            admin_user_id,
            user_id,
            serde_json::json!({ "organization_id": organization_id, "reason": reason }),
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .map_err(failure("commit suspension"))?;
    Ok(AccountSuspension {
        suspended_organizations: sole,
        shared_organizations: shared,
        created_environments,
        ports_restricted,
    })
}

/// Re-enables a suspended `user_id` and clears the suspension of the
/// organizations its suspension marked, whoever owns them now. Revoked
/// credentials, stopped environments and narrowed ports stay as they are.
pub(crate) async fn unsuspend_account_core(
    pool: &sqlx::PgPool,
    admin_user_id: &str,
    user_id: &str,
) -> AppResult<AccountUnsuspension> {
    let mut transaction = pool.begin().await.map_err(failure("begin unsuspension"))?;
    if !lock_account(&mut transaction, user_id).await? {
        return Err(AppError::Conflict("this account is not suspended".into()));
    }
    let deleting: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_deletion_operations WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(failure("check account deletion"))?;
    if deleting {
        return Err(AppError::Conflict("this account is being deleted".into()));
    }
    sqlx::query(
        "UPDATE users SET enabled = true, suspended_at = NULL, suspended_by = NULL, \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(failure("unsuspend account"))?;
    let mut unsuspended: Vec<String> = sqlx::query_scalar(
        "UPDATE organizations SET suspended_at = NULL, suspended_by = NULL, \
         suspended_for = NULL WHERE suspended_for = $1 RETURNING id",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(failure("unsuspend organizations"))?;
    unsuspended.sort();
    audit(
        &mut transaction,
        "admin.account.unsuspended",
        admin_user_id,
        user_id,
        serde_json::json!({ "unsuspended_organizations": unsuspended }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(failure("commit unsuspension"))?;
    Ok(AccountUnsuspension {
        unsuspended_organizations: unsuspended,
    })
}
