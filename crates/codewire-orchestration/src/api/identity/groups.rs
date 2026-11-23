//! A Sandbox's identity groups (docs/dev/SANDBOX-IDENTITY.md, "Groups").
//!
//! Everyone who can run code in a Sandbox can use its groups, so setting one
//! delegates an admin's trust to all of them. That is why only an admin sets
//! them, why a fork keeps them only when an admin makes it, and why granting
//! `operator` or `owner` on a Sandbox with groups needs an admin.
//!
//! A groups row, once written, is never deleted while its Sandbox exists:
//! clearing leaves it empty with its version bumped, so a version is never
//! reused and the mint cache, keyed by it, always misses after a change.

use std::collections::HashSet;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult};
use sqlx::{PgConnection, PgPool};

use super::{audit, environment_in_org, is_org_admin, member_role, require_org_admin};
use crate::api::environments::{coded, coded_owned, require_environment_access};
use crate::identity::groups::GroupSet;

/// A Sandbox's groups, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupsView {
    pub environment_id: String,
    pub groups: Vec<String>,
    /// Zero, with no `updated_at`, for a Sandbox whose groups were never set.
    pub version: i64,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Why someone can run code in a Sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodeRunnerReason {
    Creator,
    OwnerGrant,
    OperatorGrant,
    OrganizationAdmin,
}

/// A member who can run code in a Sandbox, and so use its groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunner {
    pub user_id: String,
    pub email: String,
    pub reason: CodeRunnerReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetGroupsOutcome {
    pub groups: GroupsView,
    pub previous: Vec<String>,
    /// False when the new set equals the old: nothing was written.
    pub changed: bool,
    pub can_run_code: Vec<CodeRunner>,
}

#[derive(sqlx::FromRow)]
struct GroupsRow {
    groups: Vec<String>,
    version: i64,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct CodeRunnerRow {
    user_id: String,
    email: String,
    reason: String,
}

fn invalid_groups(error: crate::identity::groups::GroupError) -> AppError {
    coded_owned(
        StatusCode::BAD_REQUEST,
        "invalid_identity_group",
        error.to_string(),
    )
}

async fn stored(
    connection: &mut PgConnection,
    environment_id: &str,
    lock: &str,
) -> AppResult<Option<GroupsRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT groups, version, updated_at FROM environment_identity_groups \
         WHERE environment_id = $1 {lock}"
    ))
    .bind(environment_id)
    .fetch_optional(&mut *connection)
    .await?)
}

fn view(environment_id: &str, row: Option<GroupsRow>) -> GroupsView {
    match row {
        Some(row) => GroupsView {
            environment_id: environment_id.to_owned(),
            groups: row.groups,
            version: row.version,
            updated_at: Some(row.updated_at),
        },
        None => GroupsView {
            environment_id: environment_id.to_owned(),
            groups: Vec::new(),
            version: 0,
            updated_at: None,
        },
    }
}

/// A Sandbox's groups. An owner or admin reads any Sandbox's; anyone else
/// reads those they can access.
pub async fn get_groups(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<GroupsView> {
    let role = member_role(pool, user, org_id).await?;
    if !is_org_admin(pool, user, org_id, &role).await? {
        require_environment_access(
            pool,
            user,
            environment_id,
            org_id,
            "viewer",
            "you can't access this environment",
        )
        .await?;
    }
    let mut connection = pool.acquire().await?;
    environment_in_org(&mut connection, org_id, environment_id, "").await?;
    let row = stored(&mut connection, environment_id, "").await?;
    Ok(view(environment_id, row))
}

/// Replace a Sandbox's groups; an empty set removes them all.
pub async fn set_groups(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    names: &[String],
) -> AppResult<SetGroupsOutcome> {
    require_org_admin(pool, user, org_id).await?;
    let groups = GroupSet::parse(names).map_err(invalid_groups)?;
    run_organization_database_mutation(pool, org_id, async {
        let mut tx = pool.begin().await?;
        // Holds off a concurrent grant on this Sandbox, which reads its
        // groups under a share lock on the same row.
        environment_in_org(&mut tx, org_id, environment_id, "FOR NO KEY UPDATE").await?;
        let before = stored(&mut tx, environment_id, "FOR UPDATE").await?;
        let previous = before
            .as_ref()
            .map(|row| row.groups.clone())
            .unwrap_or_default();
        let after = groups.names();
        if previous == after {
            let can_run_code = code_runners(&mut tx, org_id, environment_id).await?;
            tx.commit().await?;
            return Ok(SetGroupsOutcome {
                groups: view(environment_id, before),
                previous,
                changed: false,
                can_run_code,
            });
        }
        let row: GroupsRow = sqlx::query_as(
            "INSERT INTO environment_identity_groups (environment_id, groups, version, updated_by) \
             VALUES ($1, $2, 1, $3) \
             ON CONFLICT (environment_id) DO UPDATE SET groups = EXCLUDED.groups, \
             version = environment_identity_groups.version + 1, \
             updated_by = EXCLUDED.updated_by, updated_at = now() \
             RETURNING groups, version, updated_at",
        )
        .bind(environment_id)
        .bind(&after)
        .bind(&user.user_id)
        .fetch_one(&mut *tx)
        .await?;
        audit(
            &mut tx,
            "identity.groups.changed",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id,
                "environment_id": environment_id,
                "before": previous,
                "after": after,
                "version": row.version,
            }),
        )
        .await?;
        let can_run_code = code_runners(&mut tx, org_id, environment_id).await?;
        tx.commit().await?;
        Ok(SetGroupsOutcome {
            groups: view(environment_id, Some(row)),
            previous,
            changed: true,
            can_run_code,
        })
    })
    .await
}

/// Everyone who can run code in the Sandbox: its creator, members granted
/// `operator` or `owner`, and the organization's admins as `can_admin` counts
/// them (an owner or admin role, or the `super_admin` assignment), each a
/// current member, once each for the first reason that applies.
async fn code_runners(
    connection: &mut PgConnection,
    org_id: &str,
    environment_id: &str,
) -> AppResult<Vec<CodeRunner>> {
    let rows: Vec<CodeRunnerRow> = sqlx::query_as(
        "SELECT u.id AS user_id, u.email, 'creator' AS reason \
           FROM environments e \
           JOIN org_members m ON m.org_id = e.org_id AND m.user_id = e.created_by \
           JOIN users u ON u.id = e.created_by \
          WHERE e.id = $1 AND e.org_id = $2 \
         UNION ALL \
         SELECT u.id, u.email, a.permission \
           FROM environment_access a \
           JOIN org_members m ON m.org_id = $2 AND m.user_id = a.user_id \
           JOIN users u ON u.id = a.user_id \
          WHERE a.environment_id = $1 AND a.permission IN ('owner', 'operator') \
         UNION ALL \
         SELECT u.id, u.email, 'organization_admin' \
           FROM org_members m JOIN users u ON u.id = m.user_id \
          WHERE m.org_id = $2 AND (m.role IN ('owner', 'admin') OR EXISTS ( \
                SELECT 1 FROM org_member_assignments a \
                 WHERE a.org_member_id = m.id AND a.assignment = 'super_admin'))",
    )
    .bind(environment_id)
    .bind(org_id)
    .fetch_all(&mut *connection)
    .await?;
    let mut runners = rows
        .into_iter()
        .map(|row| {
            let reason = match row.reason.as_str() {
                "creator" => CodeRunnerReason::Creator,
                "owner" => CodeRunnerReason::OwnerGrant,
                "operator" => CodeRunnerReason::OperatorGrant,
                _ => CodeRunnerReason::OrganizationAdmin,
            };
            CodeRunner {
                user_id: row.user_id,
                email: row.email,
                reason,
            }
        })
        .collect::<Vec<_>>();
    runners.sort_by(|a, b| (a.reason, &a.email).cmp(&(b.reason, &b.email)));
    let mut seen = HashSet::new();
    runners.retain(|runner| seen.insert(runner.user_id.clone()));
    Ok(runners)
}

/// A create from the hosted snapshot `snapshot_id` keeps its source
/// Sandbox's groups only when `actor` is an owner or admin of the
/// organization; otherwise the new Sandbox starts with none. In the create's
/// transaction, which already holds the snapshot under a share lock. `fork`
/// is the organization, the snapshot and the new Sandbox.
pub(crate) async fn inherit_on_fork(
    connection: &mut PgConnection,
    pool: &PgPool,
    actor: &AuthUser,
    (org_id, snapshot_id, environment_id): (&str, &str, &str),
) -> AppResult<()> {
    let role = member_role(pool, actor, org_id).await?;
    if !is_org_admin(pool, actor, org_id, &role).await? {
        return Ok(());
    }
    #[derive(sqlx::FromRow)]
    struct Inherited {
        groups: Vec<String>,
        source_environment_id: String,
    }
    let inherited: Option<Inherited> = sqlx::query_as(
        "WITH source AS ( \
             SELECT e.id, g.groups FROM hosted_snapshots s \
               JOIN environments e ON e.id = s.source_environment_id AND e.org_id = s.org_id \
               JOIN environment_identity_groups g ON g.environment_id = e.id \
              WHERE s.id = $3 AND s.org_id = $4 AND cardinality(g.groups) > 0), \
         inserted AS ( \
             INSERT INTO environment_identity_groups (environment_id, groups, version, updated_by) \
             SELECT $1, groups, 1, $2 FROM source RETURNING groups) \
         SELECT inserted.groups, source.id AS source_environment_id FROM inserted, source",
    )
    .bind(environment_id)
    .bind(&actor.user_id)
    .bind(snapshot_id)
    .bind(org_id)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(inherited) = inherited {
        audit(
            connection,
            "identity.groups.changed",
            &actor.user_id,
            serde_json::json!({
                "org_id": org_id,
                "environment_id": environment_id,
                "before": Vec::<String>::new(),
                "after": inherited.groups,
                "version": 1,
                "source_environment_id": inherited.source_environment_id,
            }),
        )
        .await?;
    }
    Ok(())
}

/// Whether a grant of `permission` on `environment_id` may proceed: one of
/// `operator` or `owner` on a Sandbox that has groups needs an owner or admin
/// of the organization. Answers whether the Sandbox has groups. Takes the
/// share lock that orders the grant after any concurrent change of groups.
pub(crate) async fn admit_grant(
    connection: &mut PgConnection,
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    permission: &str,
) -> AppResult<bool> {
    environment_in_org(connection, org_id, environment_id, "FOR SHARE").await?;
    let grouped = stored(connection, environment_id, "")
        .await?
        .is_some_and(|row| !row.groups.is_empty());
    if grouped && matches!(permission, "operator" | "owner") {
        let role = member_role(pool, user, org_id).await?;
        if !is_org_admin(pool, user, org_id, &role).await? {
            return Err(coded(
                StatusCode::FORBIDDEN,
                "identity_groups_need_admin",
                "this environment has identity groups, so only an organization owner or admin \
                 can grant operator or owner on it",
            ));
        }
    }
    Ok(grouped)
}
