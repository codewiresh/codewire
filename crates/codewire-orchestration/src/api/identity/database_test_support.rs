//! Fixtures shared by the identity records' database tests: an organization
//! with an owner, an admin, a `super_admin` member and two plain members, its
//! Sandboxes, and reads of the audit rows each change writes.

use std::future::Future;
use std::time::Duration;

use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;

pub(crate) use crate::test_database_support::TestDatabase;

/// Bounds a hang in one database call; every call ends on its own result.
const HANG_GUARD: Duration = Duration::from_secs(60);

/// `future`, failing the test instead of hanging past [`HANG_GUARD`].
pub(crate) async fn bounded<T>(future: impl Future<Output = T>) -> anyhow::Result<T> {
    tokio::time::timeout(HANG_GUARD, future)
        .await
        .map_err(|_| anyhow::anyhow!("a database call took longer than {HANG_GUARD:?}"))
}

pub(crate) fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

/// An API key bound to `org_id`, for `user_id`.
pub(crate) fn api_key(user_id: &str, org_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: Some(org_id.to_owned()),
        is_admin: false,
        via_api_key: true,
    }
}

pub(crate) async fn user(db: &TestDatabase, user_id: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) async fn member(
    db: &TestDatabase,
    user_id: &str,
    org_id: &str,
    role: &str,
) -> anyhow::Result<()> {
    user(db, user_id).await?;
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// `{org}-owner`, `{org}-admin`, `{org}-super` (a member with the
/// `super_admin` assignment), `{org}-alice` and `{org}-bob`. The fixture
/// creates every organization with its own owner, `fixture-admin`, too.
pub(crate) async fn organization(db: &TestDatabase, org_id: &str) -> anyhow::Result<()> {
    db.organization(org_id).await?;
    member(db, &format!("{org_id}-owner"), org_id, "owner").await?;
    member(db, &format!("{org_id}-admin"), org_id, "admin").await?;
    member(db, &format!("{org_id}-super"), org_id, "member").await?;
    member(db, &format!("{org_id}-alice"), org_id, "member").await?;
    member(db, &format!("{org_id}-bob"), org_id, "member").await?;
    sqlx::query(
        "INSERT INTO org_member_assignments (org_member_id, assignment) \
         SELECT id, 'super_admin' FROM org_members WHERE org_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(format!("{org_id}-super"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// A running Sandbox `created_by` made in `org_id`.
pub(crate) async fn environment(
    db: &TestDatabase,
    id: &str,
    org_id: &str,
    created_by: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ($1, $2, 'Preset', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(format!("{org_id}-preset"))
    .bind(org_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
         VALUES ($1, $2, $3, $4, 'sandbox', $1, 'running', 'started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(id)
    .bind(org_id)
    .bind(created_by)
    .bind(format!("{org_id}-preset"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(crate) async fn grant(
    db: &TestDatabase,
    environment_id: &str,
    user_id: &str,
    permission: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO environment_access (environment_id, user_id, permission, granted_by) \
         VALUES ($1, $2, $3, 'fixture-admin')",
    )
    .bind(environment_id)
    .bind(user_id)
    .bind(permission)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// One audit row: who acted, and its metadata.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub(crate) struct AuditRow {
    pub user_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// The rows written for `action`, oldest first.
pub(crate) async fn audits(db: &TestDatabase, action: &str) -> anyhow::Result<Vec<AuditRow>> {
    Ok(sqlx::query_as(
        "SELECT user_id, metadata FROM audit_logs WHERE action = $1 ORDER BY timestamp, id",
    )
    .bind(action)
    .fetch_all(&db.pool)
    .await?)
}

/// The error's machine-readable code, or the variant.
pub(crate) fn code(error: AppError) -> String {
    match error {
        AppError::Coded { code, .. } => code.to_owned(),
        other => format!("{other:?}"),
    }
}

/// The error's text.
pub(crate) fn detail(error: &AppError) -> String {
    match error {
        AppError::Coded { detail, .. } => detail.to_string(),
        other => format!("{other:?}"),
    }
}
