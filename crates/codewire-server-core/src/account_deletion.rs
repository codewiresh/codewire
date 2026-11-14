//! Account deletion (#3679).
//!
//! A user deletes their own account in two parts. The request runs in one
//! transaction: it refuses while the user is the only owner of an
//! organization with other members, begins deleting each organization the
//! user is the only member of, removes their other memberships, disables the
//! account (the `codewire_revoke_user_capabilities` trigger revokes its
//! sessions, tokens and API keys) and records an operation. A durable
//! workflow then advances the operation one recorded phase at a time:
//!
//! 1. `organizations_deleted`: every personal organization's own deletion
//!    has completed. A deletion that failed is begun again.
//! 2. `stripe_customers_deleted`: the billing service deleted the personal
//!    organizations' Stripe customers, which removes their payment methods.
//! 3. `user_deleted`: rows that outlive the user are moved to the disabled
//!    "Deleted user", the user's own data is deleted, and the user row goes,
//!    which frees the email to sign up again.
//! 4. `completed`: the billing service sent the confirmation mail.
//!
//! Each phase is idempotent and the account stays disabled until the end, so
//! a failure at any point leaves a disabled account and a pending operation
//! that the next attempt resumes, never an enabled account with data gone.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::AppError;
use crate::org_deletion::begin_organization_deletion_in;

mod purge;

pub use purge::{
    Holding, KeptReason, PurgeMode, PurgeOutcome, UNVERIFIED_SIGNUP_LIFETIME_SECS,
    purge_unverified_signup, unverified_signup_candidates, unverified_signups_kept_for_holdings,
};

/// The disabled user that rows naming a deleted user are moved to. Created by
/// migration 0007; it has no credential and can never sign in.
pub const DELETED_USER_ID: &str = "deleted-user";

const DELETION_REQUESTED_ACTION: &str = "account.deletion_requested";
const DELETED_ACTION: &str = "account.deleted";

/// Audit metadata keys that carry an address. They, the IP address and the
/// user agent are removed from the entries that name a deleted user.
const AUDIT_EMAIL_KEYS: [&str; 5] = [
    "email",
    "user_email",
    "actor_email",
    "target_email",
    "target_user_email",
];

/// The input of the account deletion workflow and of each of its activities,
/// on both the orchestration and the billing task queues.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeletionWorkflowInput {
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountDeletionPhase {
    Requested,
    OrganizationsDeleted,
    StripeCustomersDeleted,
    UserDeleted,
    Completed,
}

impl AccountDeletionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::OrganizationsDeleted => "organizations_deleted",
            Self::StripeCustomersDeleted => "stripe_customers_deleted",
            Self::UserDeleted => "user_deleted",
            Self::Completed => "completed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "requested" => Self::Requested,
            "organizations_deleted" => Self::OrganizationsDeleted,
            "stripe_customers_deleted" => Self::StripeCustomersDeleted,
            "user_deleted" => Self::UserDeleted,
            "completed" => Self::Completed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct AccountDeletionOperation {
    pub id: String,
    pub user_id: Option<String>,
    pub workflow_id: String,
    pub state: String,
    pub phase: String,
    pub email: Option<String>,
    pub personal_organization_ids: Vec<String>,
    pub stripe_customer_ids: Vec<String>,
    pub start_attempts: i32,
    /// `self`, `admin` or `unverified_purge`.
    pub initiator: String,
    /// Whether the "your account was deleted" mail is sent: never to an
    /// address nobody verified.
    pub notify_email: bool,
    pub actor_user_id: Option<String>,
    pub actor_email: Option<String>,
}

impl AccountDeletionOperation {
    pub fn phase(&self) -> Result<AccountDeletionPhase, AppError> {
        AccountDeletionPhase::parse(&self.phase).ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "account deletion {} has unknown phase {}",
                self.id,
                self.phase
            ))
        })
    }
}

/// One organization the user belongs to, as the deletion treats it.
#[derive(Debug, Clone, FromRow, PartialEq, Eq, Serialize)]
pub struct AccountOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub role: String,
    pub member_count: i64,
    pub environment_count: i64,
    #[serde(skip)]
    other_owner_count: i64,
    #[serde(skip)]
    deletion_state: String,
    #[serde(skip)]
    stripe_customer_id: Option<String>,
}

/// What deleting the account would do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AccountDeletionPlan {
    /// Organizations the user is the only member of: deleted with the account.
    pub personal: Vec<AccountOrganization>,
    /// Organizations with other members: the user's membership is removed.
    pub shared: Vec<AccountOrganization>,
    /// Organizations the user is the only owner of while others are members.
    /// The account cannot be deleted until they are transferred or deleted.
    pub blocking: Vec<AccountOrganization>,
    /// Remaining credit of the personal organizations, forfeited.
    pub forfeited_credit_nano_eur: i64,
}

impl AccountDeletionPlan {
    fn classify(organizations: Vec<AccountOrganization>) -> Self {
        let mut plan = Self::default();
        for organization in organizations {
            if organization.member_count <= 1 {
                plan.personal.push(organization);
            } else if organization.role == "owner"
                && organization.other_owner_count == 0
                && organization.deletion_state != "deleting"
            {
                plan.blocking.push(organization);
            } else {
                plan.shared.push(organization);
            }
        }
        plan
    }
}

/// Read what deleting the user's account would delete, keep and refuse.
pub async fn account_deletion_plan(
    pool: &PgPool,
    user_id: &str,
) -> Result<AccountDeletionPlan, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let plan = plan_in(&mut tx, user_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(plan)
}

async fn plan_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<AccountDeletionPlan, AppError> {
    let organizations = sqlx::query_as::<_, AccountOrganization>(
        r#"
        SELECT o.id, o.name, o.slug, m.role, o.deletion_state, o.stripe_customer_id,
               (SELECT count(*) FROM org_members x WHERE x.org_id = o.id) AS member_count,
               (SELECT count(*) FROM org_members x
                 WHERE x.org_id = o.id AND x.role = 'owner' AND x.user_id <> $1)
                   AS other_owner_count,
               (SELECT count(*) FROM environments e
                 WHERE e.org_id = o.id AND e.state <> 'destroyed') AS environment_count
        FROM org_members m
        JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = $1
        ORDER BY lower(o.name), o.id
        "#,
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)?;
    let mut plan = AccountDeletionPlan::classify(organizations);
    let personal_ids: Vec<String> = plan.personal.iter().map(|o| o.id.clone()).collect();
    plan.forfeited_credit_nano_eur = sqlx::query_scalar::<_, i64>(
        r#"SELECT COALESCE(SUM(GREATEST(balance_nano_eur, 0)), 0)::bigint
           FROM billing_credit_balances WHERE organization_id = ANY($1)"#,
    )
    .bind(&personal_ids)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(plan)
}

/// Who asks for an account's deletion. Each goes through the same operation
/// and workflow; they differ in what they must prove and who is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiator<'a> {
    /// The account itself, confirming with its address.
    SelfService { confirm_email: &'a str },
    /// A platform admin, confirming with the account's address. The caller
    /// has already locked the admin's row and checked their second factor in
    /// the same transaction (#4541).
    Admin {
        actor_user_id: &'a str,
        confirm_email: &'a str,
    },
}

/// The stored kind of initiator, `account_deletion_operations.initiator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitiatorKind {
    SelfService,
    Admin,
    UnverifiedPurge,
}

impl InitiatorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SelfService => "self",
            Self::Admin => "admin",
            Self::UnverifiedPurge => "unverified_purge",
        }
    }
}

/// The admin who asked, as recorded on the operation and in the audit log.
pub(crate) struct Actor {
    pub(crate) user_id: String,
    pub(crate) email: String,
}

/// The account row, locked for the decision.
#[derive(FromRow)]
pub(crate) struct LockedAccount {
    pub(crate) email: String,
    pub(crate) enabled: bool,
    pub(crate) is_admin: bool,
    pub(crate) email_verified: bool,
    /// An admin vouched for the address on a server with no mail (#4121):
    /// proven another way, so never purged as unverified.
    pub(crate) email_vouched: bool,
}

pub(crate) async fn lock_account(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Option<LockedAccount>, AppError> {
    sqlx::query_as::<_, LockedAccount>(
        r#"SELECT email, enabled, COALESCE(is_admin, false) AS is_admin,
                  COALESCE(email_verified, false) AS email_verified,
                  email_vouched_by IS NOT NULL AS email_vouched
           FROM users WHERE id = $1 FOR UPDATE"#,
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub(crate) async fn existing_operation(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Option<AccountDeletionOperation>, AppError> {
    sqlx::query_as::<_, AccountDeletionOperation>(
        "SELECT * FROM account_deletion_operations WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

fn require_confirmation(confirm_email: &str, email: &str) -> Result<(), AppError> {
    if confirm_email.trim().eq_ignore_ascii_case(email) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "type the account's email address to confirm".into(),
        ))
    }
}

/// Request the deletion of the user's own account. `confirm_email` must be
/// the account's address. Repeating the request while one is in progress
/// returns that operation.
pub async fn begin_account_deletion(
    pool: &PgPool,
    user_id: &str,
    confirm_email: &str,
) -> Result<AccountDeletionOperation, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation =
        begin_account_deletion_in(&mut tx, user_id, Initiator::SelfService { confirm_email })
            .await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Request an account's deletion inside the caller's transaction. For an
/// admin, the admin's row is locked before the account's, so two admins
/// acting on each other wait rather than deadlock; an admin can't delete
/// their own account here (Settings does that) or another admin's (they are
/// demoted first). Repeating the request while one is in progress returns
/// that operation.
pub async fn begin_account_deletion_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    initiator: Initiator<'_>,
) -> Result<AccountDeletionOperation, AppError> {
    if user_id == DELETED_USER_ID {
        return Err(AppError::Forbidden);
    }
    let actor = match initiator {
        Initiator::SelfService { .. } => None,
        Initiator::Admin { actor_user_id, .. } => {
            if actor_user_id == user_id {
                return Err(AppError::BadRequest(
                    "delete your own account from Settings".into(),
                ));
            }
            match lock_account(tx, actor_user_id).await? {
                Some(admin) if admin.is_admin && admin.enabled => Some(Actor {
                    user_id: actor_user_id.to_owned(),
                    email: admin.email,
                }),
                _ => return Err(AppError::Forbidden),
            }
        }
    };
    let Some(account) = lock_account(tx, user_id).await? else {
        return Err(AppError::NotFound("account not found".into()));
    };
    if let Some(operation) = existing_operation(tx, user_id).await? {
        return Ok(operation);
    }
    let (kind, notify_email) = match initiator {
        Initiator::SelfService { confirm_email } => {
            if !account.enabled {
                return Err(AppError::Forbidden);
            }
            require_confirmation(confirm_email, &account.email)?;
            (InitiatorKind::SelfService, true)
        }
        Initiator::Admin { confirm_email, .. } => {
            if account.is_admin {
                return Err(AppError::Precondition(
                    "an admin is demoted before their account is deleted".into(),
                ));
            }
            require_confirmation(confirm_email, &account.email)?;
            (InitiatorKind::Admin, account.email_verified)
        }
    };
    request_in(
        tx,
        user_id,
        &account.email,
        kind,
        actor.as_ref(),
        notify_email,
    )
    .await
}

/// The request itself, once the initiator's checks passed: refuse while the
/// account is the only owner of an organization with other members, begin
/// deleting its personal organizations, end its other memberships, disable
/// it and record the operation and the audit entry.
pub(crate) async fn request_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    email: &str,
    kind: InitiatorKind,
    actor: Option<&Actor>,
    notify_email: bool,
) -> Result<AccountDeletionOperation, AppError> {
    // Lock every organization the user belongs to, in one order, so a
    // concurrent deletion or ownership change waits for this decision.
    sqlx::query(
        r#"SELECT o.id FROM organizations o
           JOIN org_members m ON m.org_id = o.id
           WHERE m.user_id = $1
           ORDER BY o.id
           FOR UPDATE OF o"#,
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    let plan = plan_in(tx, user_id).await?;
    if !plan.blocking.is_empty() {
        let names: Vec<&str> = plan.blocking.iter().map(|o| o.name.as_str()).collect();
        return Err(AppError::Precondition(
            format!(
                "transfer or delete these organizations first: {}",
                names.join(", ")
            )
            .into(),
        ));
    }

    let requested_by = actor.map_or(user_id, |actor| actor.user_id.as_str());
    let mut stripe_customer_ids = Vec::new();
    for organization in &plan.personal {
        begin_organization_deletion_in(tx, &organization.id, requested_by).await?;
        if let Some(customer) = &organization.stripe_customer_id {
            stripe_customer_ids.push(customer.clone());
        }
    }
    for organization in &plan.shared {
        if organization.deletion_state == "deleting" {
            continue;
        }
        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(&organization.id)
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;
    }

    // The trigger revokes sessions, OIDC tokens and grants, and disables
    // API keys, in this transaction.
    sqlx::query("UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    let operation_id = format!("account-deletion/{}", Uuid::new_v4().simple());
    let personal_ids: Vec<String> = plan.personal.iter().map(|o| o.id.clone()).collect();
    let operation = sqlx::query_as::<_, AccountDeletionOperation>(
        r#"
        INSERT INTO account_deletion_operations
            (id, user_id, workflow_id, email, personal_organization_ids, stripe_customer_ids,
             initiator, notify_email, actor_user_id, actor_email)
        VALUES ($1, $2, $1, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(&operation_id)
    .bind(user_id)
    .bind(email)
    .bind(&personal_ids)
    .bind(&stripe_customer_ids)
    .bind(kind.as_str())
    .bind(notify_email)
    .bind(actor.map(|actor| actor.user_id.as_str()))
    .bind(actor.map(|actor| actor.email.as_str()))
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;

    // The account's own request names it as the actor, as before; an admin's
    // names the admin and targets the account; the purge has no actor.
    let (audit_user, audit_target) = match kind {
        InitiatorKind::SelfService => (Some(user_id), None),
        InitiatorKind::Admin => (actor.map(|actor| actor.user_id.as_str()), Some(user_id)),
        InitiatorKind::UnverifiedPurge => (None, Some(user_id)),
    };
    insert_audit(
        tx,
        DELETION_REQUESTED_ACTION,
        audit_user,
        audit_target,
        serde_json::json!({
            "operation_id": operation_id,
            "initiator": kind.as_str(),
            "personal_organizations": plan.personal.len(),
            "shared_memberships": plan.shared.len(),
        }),
    )
    .await?;
    Ok(operation)
}

/// Operations whose workflow has not been acknowledged as started.
pub async fn pending_account_deletion_operations(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<AccountDeletionOperation>, AppError> {
    if !(1..=1_000).contains(&limit) {
        return Err(AppError::BadRequest(
            "limit must be between 1 and 1000".into(),
        ));
    }
    sqlx::query_as::<_, AccountDeletionOperation>(
        r#"SELECT * FROM account_deletion_operations
           WHERE state = 'pending_start'
           ORDER BY requested_at, id
           LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Record an attempt to start the workflow before Temporal is contacted.
pub async fn record_account_deletion_start_attempt(
    pool: &PgPool,
    operation_id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE account_deletion_operations
           SET start_attempts = start_attempts + 1,
               last_start_attempt_at = NOW(), updated_at = NOW()
           WHERE id = $1 AND state = 'pending_start'"#,
    )
    .bind(operation_id)
    .execute(pool)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Acknowledge that the operation's workflow has started.
pub async fn mark_account_deletion_started(
    pool: &PgPool,
    operation_id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE account_deletion_operations
           SET state = 'started', started_at = COALESCE(started_at, NOW()), updated_at = NOW()
           WHERE id = $1 AND state = 'pending_start'"#,
    )
    .bind(operation_id)
    .execute(pool)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

pub async fn account_deletion_operation(
    pool: &PgPool,
    operation_id: &str,
) -> Result<AccountDeletionOperation, AppError> {
    sqlx::query_as::<_, AccountDeletionOperation>(
        "SELECT * FROM account_deletion_operations WHERE id = $1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("account deletion operation not found".into()))
}

async fn lock_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
) -> Result<AccountDeletionOperation, AppError> {
    sqlx::query_as::<_, AccountDeletionOperation>(
        "SELECT * FROM account_deletion_operations WHERE id = $1 FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("account deletion operation not found".into()))
}

fn require_user_id(operation: &AccountDeletionOperation) -> Result<&str, AppError> {
    operation.user_id.as_deref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "account deletion {} has no user before the user is deleted",
            operation.id
        ))
    })
}

fn out_of_order(operation: &AccountDeletionOperation, expected: AccountDeletionPhase) -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "account deletion {} is in phase {}, expected {}",
        operation.id,
        operation.phase,
        expected.as_str()
    ))
}

/// Phase 1. Returns true once every personal organization is gone and the
/// phase is recorded. An organization whose deletion failed is begun again;
/// the caller retries until this returns true.
pub async fn advance_personal_organizations(
    pool: &PgPool,
    operation_id: &str,
) -> Result<bool, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation = lock_operation(&mut tx, operation_id).await?;
    match operation.phase()? {
        AccountDeletionPhase::Requested => {}
        _ => {
            tx.commit().await.map_err(AppError::from)?;
            return Ok(true);
        }
    }
    let user_id = require_user_id(&operation)?.to_string();
    let mut remaining = false;
    for organization_id in &operation.personal_organization_ids {
        let state: Option<String> =
            sqlx::query_scalar("SELECT deletion_state FROM organizations WHERE id = $1")
                .bind(organization_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::from)?;
        match state.as_deref() {
            None => {}
            Some("deleting") => remaining = true,
            Some(_) => {
                begin_organization_deletion_in(&mut tx, organization_id, &user_id).await?;
                remaining = true;
            }
        }
    }
    if !remaining {
        set_phase(
            &mut tx,
            operation_id,
            AccountDeletionPhase::OrganizationsDeleted,
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::from)?;
    Ok(!remaining)
}

/// The Stripe customers to delete in phase 2: the personal organizations'
/// customers at the request, and any their billing teardown recovered.
pub async fn account_stripe_customer_ids(
    pool: &PgPool,
    operation_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT customer FROM (
            SELECT unnest(stripe_customer_ids) AS customer
            FROM account_deletion_operations WHERE id = $1
            UNION
            SELECT b.stripe_customer_id
            FROM organization_deletion_billing_phases b
            JOIN account_deletion_operations a
              ON b.organization_id = ANY(a.personal_organization_ids)
            WHERE a.id = $1 AND b.stripe_customer_id IS NOT NULL
        ) customers
        ORDER BY customer
        "#,
    )
    .bind(operation_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Phase 2, recorded after the billing service deleted every customer.
pub async fn record_stripe_customers_deleted(
    pool: &PgPool,
    operation_id: &str,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation = lock_operation(&mut tx, operation_id).await?;
    match operation.phase()? {
        AccountDeletionPhase::OrganizationsDeleted => {
            set_phase(
                &mut tx,
                operation_id,
                AccountDeletionPhase::StripeCustomersDeleted,
            )
            .await?;
        }
        AccountDeletionPhase::Requested => {
            return Err(out_of_order(
                &operation,
                AccountDeletionPhase::OrganizationsDeleted,
            ));
        }
        _ => {}
    }
    tx.commit().await.map_err(AppError::from)
}

/// Phase 3, in one transaction: move the rows that outlive the user to the
/// "Deleted user", delete the user's own data and the user, and write the
/// `account.deleted` audit entry.
pub async fn finalize_account_deletion_database(
    pool: &PgPool,
    operation_id: &str,
) -> Result<AccountDeletionOperation, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation = lock_operation(&mut tx, operation_id).await?;
    match operation.phase()? {
        AccountDeletionPhase::StripeCustomersDeleted => {}
        AccountDeletionPhase::UserDeleted | AccountDeletionPhase::Completed => {
            tx.commit().await.map_err(AppError::from)?;
            return Ok(operation);
        }
        _ => {
            return Err(out_of_order(
                &operation,
                AccountDeletionPhase::StripeCustomersDeleted,
            ));
        }
    }
    let user_id = require_user_id(&operation)?.to_string();

    let personal_remaining: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = ANY($1))")
            .bind(&operation.personal_organization_ids)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::from)?;
    if personal_remaining {
        return Err(out_of_order(
            &operation,
            AccountDeletionPhase::OrganizationsDeleted,
        ));
    }

    // Rows that belong to someone else and name the user. Organizations come
    // first: their creator foreign key cascades, so a shared organization the
    // user created would otherwise be deleted with them.
    for statement in [
        "UPDATE organizations SET created_by = $2 WHERE created_by = $1",
        "UPDATE environments SET created_by = $2 WHERE created_by = $1",
        "UPDATE environment_access SET granted_by = $2 WHERE granted_by = $1",
        "UPDATE org_member_assignments SET granted_by = $2 WHERE granted_by = $1",
    ] {
        sqlx::query(statement)
            .bind(&user_id)
            .bind(DELETED_USER_ID)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from)?;
    }
    sqlx::query(
        r#"
        UPDATE audit_logs
        SET user_id = CASE WHEN user_id = $1 THEN $2 ELSE user_id END,
            target_user_id = CASE WHEN target_user_id = $1 THEN $2 ELSE target_user_id END,
            metadata = metadata - $3::text[],
            ip_address = NULL,
            user_agent = NULL
        WHERE user_id = $1 OR target_user_id = $1
        "#,
    )
    .bind(&user_id)
    .bind(DELETED_USER_ID)
    .bind(AUDIT_EMAIL_KEYS.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    // The user's own data. The user row's delete cascades to the rest:
    // password, sessions, OIDC grants, two-factor, memberships, invitations
    // they sent, environment access, platform credentials and profiles.
    for statement in [
        "DELETE FROM api_keys WHERE user_id = $1",
        "DELETE FROM data_deletion_requests WHERE user_id = $1",
        "DELETE FROM oidc_access_tokens WHERE user_id = $1",
        "DELETE FROM tenant_secrets WHERE scope = 'user' AND scope_id = $1",
        "DELETE FROM tenant_secret_deks WHERE scope = 'user' AND scope_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from)?;
    }
    // Verification and reset links are keyed by address or user id, with no
    // foreign key; none outlives the account, as its address is free again.
    sqlx::query("DELETE FROM verifications WHERE identifier = $1 OR lower(identifier) = lower($2)")
        .bind(&user_id)
        .bind(operation.email.as_deref().unwrap_or_default())
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    let removed = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    if removed.rows_affected() != 1 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "account deletion {operation_id} found no user to delete"
        )));
    }

    insert_audit(
        &mut tx,
        DELETED_ACTION,
        Some(DELETED_USER_ID),
        None,
        serde_json::json!({
            "operation_id": operation_id,
            "personal_organizations": operation.personal_organization_ids.len(),
        }),
    )
    .await?;
    let operation = sqlx::query_as::<_, AccountDeletionOperation>(
        r#"UPDATE account_deletion_operations
           SET phase = 'user_deleted', user_id = NULL, updated_at = NOW()
           WHERE id = $1
           RETURNING *"#,
    )
    .bind(operation_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Phase 4, recorded after the billing service sent the confirmation mail:
/// the address is cleared and the operation completes.
pub async fn complete_account_deletion(pool: &PgPool, operation_id: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation = lock_operation(&mut tx, operation_id).await?;
    match operation.phase()? {
        AccountDeletionPhase::UserDeleted => {
            sqlx::query(
                r#"UPDATE account_deletion_operations
                   SET phase = 'completed', state = 'completed', email = NULL,
                       completed_at = NOW(), updated_at = NOW()
                   WHERE id = $1"#,
            )
            .bind(operation_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from)?;
        }
        AccountDeletionPhase::Completed => {}
        _ => return Err(out_of_order(&operation, AccountDeletionPhase::UserDeleted)),
    }
    tx.commit().await.map_err(AppError::from)
}

async fn set_phase(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    phase: AccountDeletionPhase,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE account_deletion_operations SET phase = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(operation_id)
    .bind(phase.as_str())
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    user_id: Option<&str>,
    target_user_id: Option<&str>,
    metadata: serde_json::Value,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, target_user_id, metadata, severity)
           VALUES ($1, NOW(), $2, $3, $4, $5, 'warn')"#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(action)
    .bind(user_id)
    .bind(target_user_id)
    .bind(metadata)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization(id: &str, role: &str, members: i64, other_owners: i64) -> AccountOrganization {
        AccountOrganization {
            id: id.into(),
            name: id.into(),
            slug: id.into(),
            role: role.into(),
            member_count: members,
            environment_count: 0,
            other_owner_count: other_owners,
            deletion_state: "active".into(),
            stripe_customer_id: None,
        }
    }

    #[test]
    fn classify_separates_personal_shared_and_blocking() {
        let plan = AccountDeletionPlan::classify(vec![
            organization("alone", "owner", 1, 0),
            organization("sole-owner", "owner", 3, 0),
            organization("co-owner", "owner", 3, 1),
            organization("member", "member", 4, 1),
        ]);
        let ids = |list: &[AccountOrganization]| -> Vec<String> {
            list.iter().map(|o| o.id.clone()).collect()
        };
        assert_eq!(ids(&plan.personal), ["alone"]);
        assert_eq!(ids(&plan.blocking), ["sole-owner"]);
        assert_eq!(ids(&plan.shared), ["co-owner", "member"]);
    }

    #[test]
    fn an_organization_already_being_deleted_never_blocks() {
        let mut deleting = organization("deleting", "owner", 3, 0);
        deleting.deletion_state = "deleting".into();
        let plan = AccountDeletionPlan::classify(vec![deleting]);
        assert!(plan.blocking.is_empty());
        assert_eq!(plan.shared.len(), 1);
    }

    #[test]
    fn phases_round_trip() {
        for phase in [
            AccountDeletionPhase::Requested,
            AccountDeletionPhase::OrganizationsDeleted,
            AccountDeletionPhase::StripeCustomersDeleted,
            AccountDeletionPhase::UserDeleted,
            AccountDeletionPhase::Completed,
        ] {
            assert_eq!(AccountDeletionPhase::parse(phase.as_str()), Some(phase));
        }
        assert_eq!(AccountDeletionPhase::parse("deleted"), None);
    }
}
