//! Each organization's Sandboxes for Admin → Organizations (#6086), defined
//! on `SandboxCounts` in `proto/codewire/admin/v1/admin.proto`. The
//! environments table keeps a deleted Sandbox's row, so one grouped query
//! reads every organization's counts at once, never one query per row.

use codewire_server_core::{AppError, AppResult};
use sqlx::{PgPool, Row};

/// Running, or on its way there.
const RUNNING_STATES: [&str; 9] = [
    "pending",
    "pending_build",
    "building",
    "pulling_snapshot",
    "creating",
    "starting",
    "running",
    "restoring",
    "resizing",
];
/// Nothing runs and the disk is kept.
const STOPPED_STATES: [&str; 4] = ["stopping", "stopped", "archiving", "archived"];
/// Being deleted or deleted.
const DELETED_STATES: [&str; 2] = ["destroying", "destroyed"];

/// Every Sandbox is in exactly one of running, stopped, failed and deleted,
/// so they add up to created. Failed is every state the other three don't
/// name: error, build_failed and unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SandboxCounts {
    pub created: i64,
    pub running: i64,
    pub stopped: i64,
    pub failed: i64,
    pub deleted: i64,
}

impl SandboxCounts {
    fn add(&mut self, other: Self) {
        self.created += other.created;
        self.running += other.running;
        self.stopped += other.stopped;
        self.failed += other.failed;
        self.deleted += other.deleted;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OrganizationSandboxCounts {
    pub organization_id: String,
    pub counts: SandboxCounts,
    pub last_created_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdminSandboxCounts {
    /// Only organizations that have created a Sandbox, by id.
    pub organizations: Vec<OrganizationSandboxCounts>,
    pub totals: SandboxCounts,
}

pub(crate) async fn list_organization_sandbox_counts_core(
    pool: &PgPool,
) -> AppResult<AdminSandboxCounts> {
    let rows = sqlx::query(
        r#"SELECT e.org_id,
                  COUNT(*) AS created,
                  COUNT(*) FILTER (WHERE e.state = ANY($1)) AS running,
                  COUNT(*) FILTER (WHERE e.state = ANY($2)) AS stopped,
                  COUNT(*) FILTER (WHERE e.state = ANY($3)) AS deleted,
                  MAX(e.created_at) AS last_created_at
           FROM environments e
           JOIN organizations o ON o.id = e.org_id
           GROUP BY e.org_id
           ORDER BY e.org_id"#,
    )
    .bind(&RUNNING_STATES[..])
    .bind(&STOPPED_STATES[..])
    .bind(&DELETED_STATES[..])
    .fetch_all(pool)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "admin: count organization sandboxes failed");
        AppError::InternalMsg("failed to count organization sandboxes".into())
    })?;

    let mut totals = SandboxCounts::default();
    let mut organizations = Vec::with_capacity(rows.len());
    for row in &rows {
        let created: i64 = row.try_get("created").map_err(AppError::from)?;
        let running: i64 = row.try_get("running").map_err(AppError::from)?;
        let stopped: i64 = row.try_get("stopped").map_err(AppError::from)?;
        let deleted: i64 = row.try_get("deleted").map_err(AppError::from)?;
        let counts = SandboxCounts {
            created,
            running,
            stopped,
            failed: created - running - stopped - deleted,
            deleted,
        };
        totals.add(counts);
        organizations.push(OrganizationSandboxCounts {
            organization_id: row.try_get("org_id").map_err(AppError::from)?,
            counts,
            last_created_at: row.try_get("last_created_at").map_err(AppError::from)?,
        });
    }
    Ok(AdminSandboxCounts {
        organizations,
        totals,
    })
}
