//! Disposable-PostgreSQL proof that billing opens at bind (Program #2238 C3,
//! owner decision 2026-10-02). Only synthetic rows in an isolated test
//! database are used.

use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, SubsecRound, Utc};
use sqlx::PgPool;

use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::activity_authority::ActivityAuthority;
use crate::worker::environment_auth::WorkspaceCredentialScope;
use crate::worker::workspace_binding::{BindingRecord, write_binding};

const CREATOR: &str = "billing-bind-creator";
const ORGANIZATION: &str = "billing-bind-organization";
const PRESET: &str = "billing-bind-preset";
const NAMESPACE: &str = "billing-sandboxes";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";
const CLAIM: &str = "c0ffee00-e29b-41d4-a716-446655440000";
const SANDBOX: &str = "5a4db0c5-e29b-41d4-a716-446655440000";
const OTHER_SANDBOX: &str = "5a4db0c5-9dad-11d1-80b4-00c04fd430c8";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const GENERATION: i64 = 3;

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Billing','billing', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
          environment_operation_generation) \
         VALUES ($1,$2,$3,$4,'sandbox','creating','started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
    )
    .bind(ENV)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(GENERATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid) VALUES ($1,$2,$3,$4)",
    )
    .bind(ENV)
    .bind(NAMESPACE)
    .bind(format!("sandbox-{ENV}"))
    .bind(CLAIM)
    .execute(&db.pool)
    .await?;
    Ok(())
}

fn identity(runtime_uid: &str) -> Identity {
    Identity {
        environment_id: ENV.into(),
        org_id: ORGANIZATION.into(),
        runtime_tier: "standard".into(),
        runtime_uid: runtime_uid.into(),
        runtime_name: "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p".into(),
        namespace: NAMESPACE.into(),
    }
}

fn resources() -> Resources {
    Resources {
        cpu_millicores: 1500,
        memory_mib: 5120,
        disk_gib: 10,
        runtime_class: Some("commodity".into()),
    }
}

/// The recorder's fenced write of a Pod-scope binding of `SANDBOX`.
async fn bind(pool: &PgPool) -> Result<DateTime<Utc>> {
    let authority = ActivityAuthority::capture(pool, ENV, GENERATION).await?;
    let mut guard = authority.begin_external_mutation(&["creating"]).await?;
    write_binding(
        guard.transaction(),
        &BindingRecord {
            environment_id: ENV.into(),
            organization_id: ORGANIZATION.into(),
            pod_uid: POD.into(),
            namespace: NAMESPACE.into(),
            pod_name: "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p".into(),
            claim_uid: CLAIM.into(),
            sandbox_uid: SANDBOX.into(),
            workspace_pvc_uid: None,
            operation_generation: GENERATION,
            projection_selection_sha256: None,
            managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                .encode()
                .to_owned(),
            credential_scope: WorkspaceCredentialScope::Pod,
        },
    )
    .await?;
    guard.commit().await?;
    Ok(
        sqlx::query_scalar("SELECT bound_at FROM sandbox_workspace_bindings WHERE pod_uid = $1")
            .bind(POD)
            .fetch_one(pool)
            .await?,
    )
}

async fn release(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
          WHERE pod_uid = $1 AND released_at IS NULL",
    )
    .bind(POD)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid = NULL, bound_at = NULL \
          WHERE environment_id = $1",
    )
    .bind(ENV)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// (started_at, last_observed_at, ended_at) of each session, oldest first.
type SessionTimes = (DateTime<Utc>, DateTime<Utc>, Option<DateTime<Utc>>);

async fn sessions(pool: &PgPool) -> Result<Vec<SessionTimes>> {
    Ok(sqlx::query_as(
        "SELECT started_at, last_observed_at, ended_at FROM sandbox_running_sessions \
          WHERE environment_id = $1 ORDER BY started_at, id",
    )
    .bind(ENV)
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_billing_opens_at_bind_and_never_before() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // A Ready, adopted but unbound Sandbox is not billed.
        let observed = Utc::now();
        let write = open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), observed).await?;
        ensure!(write == SessionWrite::AwaitingBind, "{write:?}");
        ensure!(sessions(&db.pool).await?.is_empty());

        // The bind opens the session at bound_at, even when the poll comes later.
        let bound_at = bind(&db.pool).await?;
        let later = bound_at + Duration::seconds(45);
        let write = open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), later).await?;
        ensure!(write == SessionWrite::Opened, "{write:?}");
        let rows = sessions(&db.pool).await?;
        ensure!(rows.len() == 1);
        ensure!(
            rows[0].0 == bound_at,
            "started at {} not {bound_at}",
            rows[0].0
        );
        ensure!(rows[0].1 == later && rows[0].2.is_none());

        // The next poll is a heartbeat of the same row.
        let next = later + Duration::seconds(60);
        let write = open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), next).await?;
        ensure!(write == SessionWrite::Heartbeat, "{write:?}");
        let rows = sessions(&db.pool).await?;
        ensure!(rows.len() == 1 && rows[0].0 == bound_at && rows[0].1 == next);
        let (cpu, memory, disk, tier): (i32, i32, i32, String) = sqlx::query_as(
            "SELECT cpu_millicores, memory_mib, disk_gib, runtime_tier \
               FROM sandbox_running_sessions WHERE environment_id = $1",
        )
        .bind(ENV)
        .fetch_one(&db.pool)
        .await?;
        ensure!((cpu, memory, disk, tier.as_str()) == (1500, 5120, 10, "standard"));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_billing_needs_a_live_binding_of_this_exact_sandbox() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        // Another Sandbox of the same environment (a stale member, a racing
        // cold create) is never billed through this binding.
        let write =
            open_or_heartbeat(&db.pool, &identity(OTHER_SANDBOX), &resources(), Utc::now()).await?;
        ensure!(write == SessionWrite::AwaitingBind, "{write:?}");

        // A released binding opens nothing.
        release(&db.pool).await?;
        let write =
            open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), Utc::now()).await?;
        ensure!(write == SessionWrite::AwaitingBind, "{write:?}");
        ensure!(sessions(&db.pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_reopened_session_never_overlaps_the_previous_one() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let bound_at = bind(&db.pool).await?;
        let opened = bound_at + Duration::seconds(30);
        ensure!(
            open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), opened).await?
                == SessionWrite::Opened
        );
        // A terminal Ready condition closed the row while the binding stayed
        // live; Ready again reopens no earlier than that close.
        let closed = bound_at + Duration::seconds(90);
        close_by_uid(&db.pool, SANDBOX, "PodFailed", closed).await?;
        let reopened = bound_at + Duration::seconds(150);
        ensure!(
            open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), reopened).await?
                == SessionWrite::Opened
        );
        let rows = sessions(&db.pool).await?;
        ensure!(rows.len() == 2);
        ensure!(rows[0].0 == bound_at && rows[0].2 == Some(closed));
        ensure!(
            rows[1].0 == closed,
            "reopened at {} not {closed}",
            rows[1].0
        );
        ensure!(rows[1].2.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_open_session_keeps_its_heartbeat_across_a_rebind() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // A session opened before this release (no binding yet) is not
        // dropped: it keeps its heartbeat, so a Pod replaced while running
        // is billed without a gap.
        let started = (Utc::now() - Duration::minutes(10)).trunc_subsecs(6);
        sqlx::query(
            "INSERT INTO sandbox_running_sessions \
             (environment_id, organization_id, runtime_type, runtime_uid, runtime_name, \
              runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_tier, \
              started_at, last_observed_at, updated_at) \
             VALUES ($1, $2, 'sandbox', $3, 'sandbox-legacy', $4, 1000, 4096, 10, 'standard', \
                     $5, $5, $5)",
        )
        .bind(ENV)
        .bind(ORGANIZATION)
        .bind(SANDBOX)
        .bind(NAMESPACE)
        .bind(started)
        .execute(&db.pool)
        .await?;
        let now = Utc::now().trunc_subsecs(6);
        ensure!(
            open_or_heartbeat(&db.pool, &identity(SANDBOX), &resources(), now).await?
                == SessionWrite::Heartbeat
        );
        let rows = sessions(&db.pool).await?;
        ensure!(rows.len() == 1 && rows[0].0 == started && rows[0].1 == now);
        Ok(())
    }
    .await;
    db.finish(result).await
}
