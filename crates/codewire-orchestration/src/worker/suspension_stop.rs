//! Running sandboxes of a suspended organization, and those a suspended
//! account created anywhere, are stopped at once (#3297 item 4). The administrator's suspension marks the organization
//! (`organizations.suspended_at`); the reconciler stops what is still running.
//! Storage is kept, and nothing restarts on unsuspension.

use sqlx::PgPool;

/// Environments to stop: started, not stopping already, in a suspended
/// organization or created by a suspended account, in whatever organization.
/// A protected environment is stopped too: protection guards against
/// deletion, and stopping keeps its storage.
pub async fn suspended_environment_ids(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT e.id FROM environments e
           JOIN organizations o ON o.id = e.org_id
           LEFT JOIN users creator ON creator.id = e.created_by
           WHERE (o.suspended_at IS NOT NULL OR creator.suspended_at IS NOT NULL)
             AND e.desired_state = 'started'
             AND e.state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')
           ORDER BY e.id"#,
    )
    .fetch_all(pool)
    .await
}
