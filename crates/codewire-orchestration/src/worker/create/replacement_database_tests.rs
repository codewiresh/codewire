//! Disposable-PostgreSQL proof of the order a terminal Pod is replaced in
//! (#4084): a confidential environment's measured runtime is published, then
//! seen on exactly that incarnation with exactly the value the publish
//! returned, and only then is the incarnation replaced (B2c).

use std::sync::Mutex;

use anyhow::{Result, ensure};
use serde_json::to_value;

use super::*;

use crate::runtime::MemberReplacement;
use crate::runtime::fake::FakeRuntimeDriver;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "replacement-creator";
const ENVIRONMENT: &str = "5d2e8c41-7a93-4f60-b1d4-9e3c2a7f6b08";
const GENERATION: i64 = 4;
const ORGANIZATION: &str = "replacement-organization";
const PRESET: &str = "replacement-preset";
const SUPPORT_IMAGE: &str = "registry.example.invalid/codewire/support@sha256:1111";

async fn seed_creating(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Replacement','replacement',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         environment_operation_generation,isolation_tier,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'creating','started',$5,'confidential',$6)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(GENERATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// The measured rendering the publish fence accepts for the seeded row.
async fn measured_rendering(db: &TestDatabase) -> Result<TemplateOpts> {
    let env = load_environment(&db.pool, ENVIRONMENT).await?;
    Ok(TemplateOpts {
        name: format!("workspace-{ENVIRONMENT}"),
        environment_id: env.id.clone(),
        organization_id: env.org_id.clone(),
        operation_generation: GENERATION,
        managed_credential_clients: *env
            .managed_credential_clients
            .as_ref()
            .map_err(|_| anyhow::anyhow!("managed clients unreadable"))?,
        ..Default::default()
    })
}

fn stale() -> WorkspacePodIdentity {
    WorkspacePodIdentity {
        name: "sandbox-stale".into(),
        uid: "uid-stale".into(),
    }
}

fn scripted(measured: &str) -> FakeRuntimeDriver {
    FakeRuntimeDriver {
        measured_runtime: Mutex::new(Some(measured.into())),
        replacement: Mutex::new(Some(MemberReplacement::Replaced)),
        replaced: Mutex::new(Some(WorkspacePodIdentity {
            name: "sandbox-stale".into(),
            uid: "uid-new".into(),
        })),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_confidential_replacement_publishes_then_sees_it_on_that_incarnation_then_replaces()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_creating(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        let rendering = measured_rendering(&db).await?;
        let runtime = scripted("init-data-a");
        let placement = Placement::new("dev-sandboxes");
        let stale = stale();
        replace_stale_member(
            &runtime,
            &authority,
            CREATE_MUTATION_STATES,
            &StaleReplacement {
                placement: &placement,
                stale: &stale,
                confidential: true,
                measured: Some(&rendering),
                support_image: SUPPORT_IMAGE,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await?;
        let calls = runtime.replacement_calls.lock().unwrap().clone();
        ensure!(
            calls
                == [
                    format!("publish {ENVIRONMENT} sandbox-stale workspace-{ENVIRONMENT}"),
                    "wait-measured sandbox-stale uid-stale init-data-a".to_string(),
                    format!("replace {ENVIRONMENT} sandbox-stale uid-stale {SUPPORT_IMAGE}"),
                    "wait sandbox-stale uid-stale".to_string(),
                ],
            "{calls:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A rendering the environment row no longer matches is refused at the
/// publish fence, and nothing is published, awaited or replaced.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stale_rendering_publishes_and_replaces_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_creating(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        let mut rendering = measured_rendering(&db).await?;
        rendering.organization_id = "another-organization".into();
        let runtime = scripted("init-data-a");
        let placement = Placement::new("dev-sandboxes");
        let stale = stale();
        let outcome = replace_stale_member(
            &runtime,
            &authority,
            CREATE_MUTATION_STATES,
            &StaleReplacement {
                placement: &placement,
                stale: &stale,
                confidential: true,
                measured: Some(&rendering),
                support_image: SUPPORT_IMAGE,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await;
        ensure!(outcome.is_err(), "a mismatched rendering is refused");
        let calls = runtime.replacement_calls.lock().unwrap().clone();
        ensure!(calls.is_empty(), "{calls:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Any other environment is replaced without a measured runtime.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_commodity_replacement_only_replaces_and_waits() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_creating(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        let runtime = scripted("unused");
        let placement = Placement::new("dev-sandboxes");
        let stale = stale();
        replace_stale_member(
            &runtime,
            &authority,
            CREATE_MUTATION_STATES,
            &StaleReplacement {
                placement: &placement,
                stale: &stale,
                confidential: false,
                measured: None,
                support_image: SUPPORT_IMAGE,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await?;
        let calls = runtime.replacement_calls.lock().unwrap().clone();
        ensure!(
            calls
                == [
                    format!("replace {ENVIRONMENT} sandbox-stale uid-stale {SUPPORT_IMAGE}"),
                    "wait sandbox-stale uid-stale".to_string(),
                ],
            "{calls:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A confidential replacement without a measured runtime is refused before
/// anything is published, awaited or replaced, so no caller can skip B2c.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_confidential_replacement_without_a_measured_runtime_writes_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_creating(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        let runtime = scripted("init-data-a");
        let placement = Placement::new("dev-sandboxes");
        let stale = stale();
        let outcome = replace_stale_member(
            &runtime,
            &authority,
            CREATE_MUTATION_STATES,
            &StaleReplacement {
                placement: &placement,
                stale: &stale,
                confidential: true,
                measured: None,
                support_image: SUPPORT_IMAGE,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await;
        ensure!(
            outcome.is_err(),
            "a confidential replacement needs its measured runtime"
        );
        let calls = runtime.replacement_calls.lock().unwrap().clone();
        ensure!(calls.is_empty(), "{calls:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
