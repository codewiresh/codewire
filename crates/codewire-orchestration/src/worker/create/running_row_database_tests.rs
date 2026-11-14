//! Disposable-PostgreSQL proof that the runtime a create remembers after its
//! own `mark_running` equals the row the next pass loads (#2238): any field
//! the environment query derives from the state, such as `never_ran`, must
//! follow it, or every create reconciles its runtime a second time.

use anyhow::{Result, ensure};
use serde_json::to_value;

use super::*;

use crate::test_database_support::TestDatabase;

const CREATOR: &str = "running-row-creator";
const ENVIRONMENT: &str = "6d2e9b41-3c7a-4f58-a0e1-8b4c5d7f9a26";
const ORGANIZATION: &str = "running-row-organization";
const PRESET: &str = "running-row-preset";

/// A first-attempt create, as `create_claim` leaves it.
async fn seed_creating(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Running row','running-row',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'creating','started',$5)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_runtime_remembered_after_mark_running_equals_the_next_load() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_creating(&db).await?;
        let pool = &db.pool;
        let backend = BackendRow::default();
        let probe = RuntimeProbe::default();
        let creating = load_environment(pool, ENVIRONMENT).await?;
        ensure!(creating.never_ran, "a first-attempt create has never run");
        let mut remembered = ReconciledRuntime::observe(&creating, &backend, &probe);

        // What `mark_running` commits, then records.
        let svc = Service::for_pool(pool.clone());
        svc.transition(ENVIRONMENT, "creating", "running").await?;
        svc.mark_started(ENVIRONMENT).await?;
        remembered.entered_running();

        let running = load_environment(pool, ENVIRONMENT).await?;
        ensure!(
            remembered == ReconciledRuntime::observe(&running, &backend, &probe),
            "the remembered runtime differs from the reloaded row: {:?} against {:?}",
            remembered.environment,
            running
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
