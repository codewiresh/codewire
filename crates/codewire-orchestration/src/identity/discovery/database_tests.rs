//! Disposable-PostgreSQL proof that an issuer is served only for an existing,
//! active org's exact ID. Only synthetic rows in an isolated test database are
//! used.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const ACTIVE: &str = "0e3c5a1f9b2d4c6e8a0b1c2d3e4f5a6b";
const DELETING: &str = "7b1f00aa11bb22cc33dd44ee55ff6677";
const REMOVED: &str = "a1560db3889940c9b521500f223b04fb";

// A deletion in progress sets every deletion field, as
// begin_organization_deletion does.
const MARK_DELETING: &str = "UPDATE public.organizations \
    SET deletion_state='deleting', deletion_generation=1, \
        deletion_requested_by='fixture-admin', deletion_requested_at=clock_timestamp(), \
        deletion_operation_id='organization-deletion/' || id || '/1', \
        deletion_workflow_id='organization-deletion/' || id || '/1', \
        deletion_phase='write_fenced', updated_at=clock_timestamp() WHERE id=$1";

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_an_active_orgs_exact_id_has_an_issuer() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        for org in [ACTIVE, DELETING, REMOVED] {
            db.organization(org).await?;
        }
        sqlx::query(MARK_DELETING)
            .bind(DELETING)
            .execute(&db.pool)
            .await?;
        sqlx::query("DELETE FROM org_members WHERE org_id = $1")
            .bind(REMOVED)
            .execute(&db.pool)
            .await?;
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(REMOVED)
            .execute(&db.pool)
            .await?;

        let orgs = PgOrgDirectory {
            pool: db.pool.clone(),
        };
        ensure!(orgs.is_active(ACTIVE).await?, "an active org has an issuer");
        ensure!(
            !orgs.is_active(&ACTIVE.to_uppercase()).await?,
            "an upper-case spelling of a real ID is no org"
        );
        ensure!(
            !orgs.is_active(DELETING).await?,
            "an org being deleted stops answering"
        );
        ensure!(
            !orgs.is_active(REMOVED).await?,
            "a deleted org has no issuer"
        );
        ensure!(!orgs.is_active("unknown").await?, "an unknown ID is no org");
        Ok(())
    }
    .await;
    db.finish(result).await
}
