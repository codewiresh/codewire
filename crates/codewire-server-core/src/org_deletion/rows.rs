//! The organization's own rows, deleted by the database finalizer in its
//! transaction once every external cleanup is done, before the organization
//! row itself. Each statement binds the organization ID as `$1`.

use sqlx::PgConnection;

const STATEMENTS: [&str; 11] = [
    "DELETE FROM repo_configs WHERE org_id = $1",
    "DELETE FROM environments WHERE org_id = $1",
    "DELETE FROM environment_presets WHERE org_id = $1",
    "DELETE FROM api_keys WHERE org_id = $1",
    "DELETE FROM environment_quotas WHERE org_id = $1",
    "DELETE FROM environment_usage_billing WHERE org_id = $1",
    "DELETE FROM environment_usage_billing_tiers WHERE org_id = $1",
    "DELETE FROM secret_projects WHERE org_id = $1",
    "DELETE FROM org_invitations WHERE org_id = $1",
    "DELETE FROM org_members WHERE org_id = $1",
    // Sandbox identity's mint log has no foreign key, so a deleted Sandbox's
    // rows outlive it; they go with their organization.
    "DELETE FROM identity_mints WHERE org_id = $1",
];

pub(super) async fn delete_organization_rows(
    connection: &mut PgConnection,
    organization_id: &str,
) -> Result<(), sqlx::Error> {
    for statement in STATEMENTS {
        sqlx::query(statement)
            .bind(organization_id)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}
