//! Disposable-PostgreSQL proof that an environment's own idle stop is
//! recorded and read back, and that a gone environment refuses one (#3384).

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use crate::api::environments::{ENV_SELECT_COLS, ENV_SELECT_JOINS, Environment, scan_environment};
use crate::lifecycle::Service;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "idle-stop-creator";
const ORGANIZATION: &str = "idle-stop-organization";
const PRESET: &str = "idle-stop-preset";
const ENVIRONMENT: &str = "7c41a9e2-5b3d-4f08-9a6e-2d8b1c4f6e93";

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Idle stop','idle-stop',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'running','started',$5)",
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

/// The environment as the API reads it.
async fn read(pool: &PgPool) -> Result<Environment> {
    let row = sqlx::query(&format!(
        "SELECT {ENV_SELECT_COLS} FROM environments e {ENV_SELECT_JOINS} WHERE e.id = $1"
    ))
    .bind(ENVIRONMENT)
    .fetch_one(pool)
    .await?;
    Ok(scan_environment(&row)?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_idle_stop_is_recorded_without_touching_the_lifecycle() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // An environment created without one is off.
        ensure!(read(pool).await?.idle_stop_seconds == 0);

        for seconds in [1800, 0] {
            ensure!(svc.set_idle_stop(ENVIRONMENT, seconds).await?);
            let environment = read(pool).await?;
            ensure!(
                environment.idle_stop_seconds == seconds,
                "{:?}",
                environment.idle_stop_seconds
            );
            // Recording it starts, stops and restarts nothing.
            ensure!(environment.state == "running" && environment.desired_state == "started");
        }

        sqlx::query("UPDATE environments SET state = 'destroyed' WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(pool)
            .await?;
        ensure!(!svc.set_idle_stop(ENVIRONMENT, 1800).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}
