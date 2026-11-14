//! The purge of email sign-ups that never verify their address (#4541).
//!
//! An email and password sign-up that is still unverified a set time after
//! it was created, and that no admin vouched for on a server with no mail
//! (#4121), is deleted through the ordinary account deletion, which
//! frees its address. The purge never deletes an account that holds anything
//! (an organization membership, a sandbox it created, an API key, a user
//! secret, or a GitHub or Google sign-in) and never an admin; it keeps such
//! an account and says why. Every condition is checked again in the deletion
//! transaction with the account's row locked, so an address verified between
//! the selection and the deletion keeps its account.

use sqlx::{PgPool, Postgres, Transaction};

use super::{
    AccountDeletionOperation, DELETED_USER_ID, InitiatorKind, existing_operation, lock_account,
    request_in,
};
use crate::AppError;

/// How long a sign-up has to verify before the purge deletes it: 7 days
/// (owner, 2026-11-13, #4541).
pub const UNVERIFIED_SIGNUP_LIFETIME_SECS: i64 = 7 * 24 * 60 * 60;

/// Whether the purge deletes, or only reports what it would delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeMode {
    /// Every check runs and the transaction is rolled back.
    Report,
    Enforce,
}

/// Why the purge kept an account it selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptReason {
    /// The account is gone, or its deletion already began.
    Gone,
    Verified,
    /// An admin vouched for the address on a server with no mail (#4121).
    Vouched,
    Admin,
    /// Younger than the lifetime it was selected with.
    Young,
    /// It has no password sign-in, so it isn't an email sign-up.
    NotEmailSignUp,
    /// It holds something the purge never deletes.
    Holds(Holding),
}

/// What an unverified account holds that keeps it from the purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holding {
    OrganizationMembership,
    Sandbox,
    ApiKey,
    UserSecret,
    ProviderSignIn,
}

impl Holding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationMembership => "organization_membership",
            Self::Sandbox => "sandbox",
            Self::ApiKey => "api_key",
            Self::UserSecret => "user_secret",
            Self::ProviderSignIn => "provider_sign_in",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// Deleted: the operation the workflow now advances.
    Deleted(Box<AccountDeletionOperation>),
    /// Report mode: every check passed and nothing was changed.
    WouldDelete,
    Kept(KeptReason),
}

/// The unverified email sign-ups older than `lifetime_secs` that hold
/// nothing and have no deletion, oldest first. This only selects; the purge
/// checks each again before deleting it.
pub async fn unverified_signup_candidates(
    pool: &PgPool,
    lifetime_secs: i64,
    limit: i64,
) -> Result<Vec<String>, AppError> {
    if !(1..=1_000).contains(&limit) {
        return Err(AppError::BadRequest(
            "limit must be between 1 and 1000".into(),
        ));
    }
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT u.id FROM users u
        WHERE NOT COALESCE(u.email_verified, false)
          AND u.email_vouched_by IS NULL
          AND NOT COALESCE(u.is_admin, false)
          AND u.id <> $1
          AND u.created_at < NOW()::timestamp - make_interval(secs => $2)
          AND EXISTS (SELECT 1 FROM accounts a
                      WHERE a.user_id = u.id AND a.provider_id = 'credential')
          AND NOT EXISTS (SELECT 1 FROM accounts a
                          WHERE a.user_id = u.id AND a.provider_id <> 'credential')
          AND NOT EXISTS (SELECT 1 FROM account_deletion_operations d WHERE d.user_id = u.id)
          AND NOT EXISTS (SELECT 1 FROM org_members m WHERE m.user_id = u.id)
          AND NOT EXISTS (SELECT 1 FROM environments e
                          WHERE e.created_by = u.id AND e.state <> 'destroyed')
          AND NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.user_id = u.id)
          AND NOT EXISTS (SELECT 1 FROM tenant_secrets s
                          WHERE s.scope = 'user' AND s.scope_id = u.id)
        ORDER BY u.created_at, u.id
        LIMIT $3
        "#,
    )
    .bind(DELETED_USER_ID)
    .bind(lifetime_secs as f64)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// How many unverified email sign-ups older than `lifetime_secs` the purge
/// keeps because they hold something. Reported, never deleted.
pub async fn unverified_signups_kept_for_holdings(
    pool: &PgPool,
    lifetime_secs: i64,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        r#"
        SELECT count(*) FROM users u
        WHERE NOT COALESCE(u.email_verified, false)
          AND u.email_vouched_by IS NULL
          AND NOT COALESCE(u.is_admin, false)
          AND u.id <> $1
          AND u.created_at < NOW()::timestamp - make_interval(secs => $2)
          AND EXISTS (SELECT 1 FROM accounts a
                      WHERE a.user_id = u.id AND a.provider_id = 'credential')
          AND NOT EXISTS (SELECT 1 FROM account_deletion_operations d WHERE d.user_id = u.id)
          AND (EXISTS (SELECT 1 FROM accounts a
                       WHERE a.user_id = u.id AND a.provider_id <> 'credential')
               OR EXISTS (SELECT 1 FROM org_members m WHERE m.user_id = u.id)
               OR EXISTS (SELECT 1 FROM environments e
                          WHERE e.created_by = u.id AND e.state <> 'destroyed')
               OR EXISTS (SELECT 1 FROM api_keys k WHERE k.user_id = u.id)
               OR EXISTS (SELECT 1 FROM tenant_secrets s
                          WHERE s.scope = 'user' AND s.scope_id = u.id))
        "#,
    )
    .bind(DELETED_USER_ID)
    .bind(lifetime_secs as f64)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)
}

/// Delete one unverified email sign-up older than `lifetime_secs`, checking
/// every condition again with its row locked. In report mode the checks run
/// and nothing changes.
pub async fn purge_unverified_signup(
    pool: &PgPool,
    user_id: &str,
    lifetime_secs: i64,
    mode: PurgeMode,
) -> Result<PurgeOutcome, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let outcome = purge_in(&mut tx, user_id, lifetime_secs, mode).await?;
    match outcome {
        PurgeOutcome::Deleted(_) => tx.commit().await.map_err(AppError::from)?,
        PurgeOutcome::WouldDelete | PurgeOutcome::Kept(_) => {
            tx.rollback().await.map_err(AppError::from)?
        }
    }
    Ok(outcome)
}

async fn purge_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    lifetime_secs: i64,
    mode: PurgeMode,
) -> Result<PurgeOutcome, AppError> {
    if user_id == DELETED_USER_ID {
        return Ok(PurgeOutcome::Kept(KeptReason::Gone));
    }
    let Some(account) = lock_account(tx, user_id).await? else {
        return Ok(PurgeOutcome::Kept(KeptReason::Gone));
    };
    if existing_operation(tx, user_id).await?.is_some() {
        return Ok(PurgeOutcome::Kept(KeptReason::Gone));
    }
    if account.email_verified {
        return Ok(PurgeOutcome::Kept(KeptReason::Verified));
    }
    if account.email_vouched {
        return Ok(PurgeOutcome::Kept(KeptReason::Vouched));
    }
    if account.is_admin {
        return Ok(PurgeOutcome::Kept(KeptReason::Admin));
    }
    let old_enough: bool = sqlx::query_scalar(
        "SELECT created_at < NOW()::timestamp - make_interval(secs => $2) FROM users WHERE id = $1",
    )
    .bind(user_id)
    .bind(lifetime_secs as f64)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    if !old_enough {
        return Ok(PurgeOutcome::Kept(KeptReason::Young));
    }
    let email_sign_up: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = 'credential')",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    if !email_sign_up {
        return Ok(PurgeOutcome::Kept(KeptReason::NotEmailSignUp));
    }
    if let Some(holding) = holding_in(tx, user_id).await? {
        return Ok(PurgeOutcome::Kept(KeptReason::Holds(holding)));
    }
    if mode == PurgeMode::Report {
        return Ok(PurgeOutcome::WouldDelete);
    }
    let operation = request_in(
        tx,
        user_id,
        &account.email,
        InitiatorKind::UnverifiedPurge,
        None,
        false,
    )
    .await?;
    Ok(PurgeOutcome::Deleted(Box::new(operation)))
}

/// The first thing the account holds that keeps it from the purge.
async fn holding_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Option<Holding>, AppError> {
    let checks = [
        (
            Holding::OrganizationMembership,
            "SELECT EXISTS(SELECT 1 FROM org_members WHERE user_id = $1)",
        ),
        (
            Holding::Sandbox,
            "SELECT EXISTS(SELECT 1 FROM environments WHERE created_by = $1 AND state <> 'destroyed')",
        ),
        (
            Holding::ApiKey,
            "SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1)",
        ),
        (
            Holding::UserSecret,
            "SELECT EXISTS(SELECT 1 FROM tenant_secrets WHERE scope = 'user' AND scope_id = $1)",
        ),
        (
            Holding::ProviderSignIn,
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id <> 'credential')",
        ),
    ];
    for (holding, sql) in checks {
        let held: bool = sqlx::query_scalar(sql)
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::from)?;
        if held {
            return Ok(Some(holding));
        }
    }
    Ok(None)
}
