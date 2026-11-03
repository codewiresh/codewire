//! Disposable-PostgreSQL proof that billing opens at bind (Program #2238 C3,
//! owner decision 2026-10-02). Only synthetic rows in an isolated test
//! database are used.

use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, SubsecRound, Utc};
use sqlx::PgPool;

use super::*;
use crate::runtime::fake::FakeRuntimeDriver;
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

/// A Sandbox of `ENV`, known only by its claim, as the driver lists it.
fn member(phase: Phase, phase_reason: &str) -> RuntimeMember {
    RuntimeMember {
        namespace: NAMESPACE.into(),
        name: "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p".into(),
        uid: SANDBOX.into(),
        environment_id: String::new(),
        organization_id: String::new(),
        claim_uid: CLAIM.into(),
        snapshot_clearing: false,
        phase,
        phase_reason: phase_reason.into(),
        declared: resources(),
        workspace: Resources {
            cpu_millicores: 1000,
            memory_mib: 4096,
            disk_gib: 10,
            runtime_class: None,
        },
    }
}

fn runtime_listing(members: Vec<RuntimeMember>) -> FakeRuntimeDriver {
    FakeRuntimeDriver {
        members: members.into(),
        ..FakeRuntimeDriver::default()
    }
}

/// The session's times, billed resources and organization.
type SessionRow = (
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    i32,
    i32,
    i32,
    String,
);

async fn session_row(pool: &PgPool) -> Result<SessionRow> {
    Ok(sqlx::query_as(
        "SELECT started_at, last_observed_at, ended_at, cpu_millicores, memory_mib, disk_gib, \
                organization_id \
           FROM sandbox_running_sessions WHERE environment_id = $1",
    )
    .bind(ENV)
    .fetch_one(pool)
    .await?)
}

/// (cpu_millicores, memory_mib, disk_gib) billed on the session.
async fn billed(pool: &PgPool) -> Result<(i32, i32, i32)> {
    let row = session_row(pool).await?;
    Ok((row.3, row.4, row.5))
}

/// The same Sandbox after it was resized: it now declares more.
fn resized_member() -> RuntimeMember {
    RuntimeMember {
        declared: Resources {
            cpu_millicores: 2500,
            memory_mib: 9216,
            disk_gib: 20,
            runtime_class: Some("commodity".into()),
        },
        workspace: Resources {
            cpu_millicores: 2000,
            memory_mib: 8192,
            disk_gib: 20,
            runtime_class: None,
        },
        ..member(Phase::Running, "")
    }
}

/// A resize operation in `state`, created `age_secs` ago, whose last-applied
/// shape is (2000m, 2048 MiB, 30 GiB).
async fn resize_operation(pool: &PgPool, id: &str, state: &str, age_secs: i32) -> Result<()> {
    let terminal = matches!(state, "completed" | "failed");
    let failed = state == "failed";
    sqlx::query(
        "INSERT INTO environment_resize_operations (
             id, org_id, environment_id, request_id,
             previous_cpu_millicores, previous_memory_mb, previous_disk_gb,
             desired_cpu_millicores, desired_memory_mb, desired_disk_gb,
             last_applied_cpu_millicores, last_applied_memory_mb, last_applied_disk_gb,
             previous_state, previous_desired_state, state, planned_mode, applied_mode,
             failure_code, failure_message, created_at, completed_at)
         VALUES ($1, $2, $3, $1, 1000, 4096, 10, 4000, 8192, 40, 2000, 2048, 30,
                 'running', 'started', $4, 'in_place',
                 CASE WHEN $4 = 'completed' THEN 'in_place' END,
                 CASE WHEN $5 THEN 'synthetic_failure' END,
                 CASE WHEN $5 THEN 'synthetic failure' END,
                 NOW() - make_interval(secs => $6),
                 CASE WHEN $7 THEN NOW() END)",
    )
    .bind(id)
    .bind(ORGANIZATION)
    .bind(ENV)
    .bind(state)
    .bind(failed)
    .bind(f64::from(age_secs))
    .bind(terminal)
    .execute(pool)
    .await?;
    Ok(())
}

async fn end_reason(pool: &PgPool) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT end_reason FROM sandbox_running_sessions WHERE environment_id = $1",
    )
    .bind(ENV)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_listed_member_is_billed_until_it_vanishes() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let bound_at = bind(&db.pool).await?;
        let runtime = runtime_listing(vec![member(Phase::Running, "")]);

        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        let rows = sessions(&db.pool).await?;
        ensure!(rows.len() == 1 && rows[0].0 == bound_at && rows[0].2.is_none());
        let (cpu, memory): (i32, i32) = sqlx::query_as(
            "SELECT cpu_millicores, memory_mib FROM sandbox_running_sessions \
              WHERE environment_id = $1",
        )
        .bind(ENV)
        .fetch_one(&db.pool)
        .await?;
        ensure!((cpu, memory) == (1500, 5120), "{cpu} {memory}");

        // A failed listing proves nothing about the member, and changes nothing.
        let before_failure = session_row(&db.pool).await?;
        *runtime.members_error.lock().unwrap() = Some("list refused".into());
        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        ensure!(session_row(&db.pool).await? == before_failure);

        // A vanished member stopped being billable when it was last observed.
        *runtime.members_error.lock().unwrap() = None;
        runtime.members.lock().unwrap().clear();
        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        ensure!(sessions(&db.pool).await?[0].2 == Some(before_failure.1));
        ensure!(end_reason(&db.pool).await?.as_deref() == Some("controller_lost_track"));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_terminated_member_closes_with_its_reason() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        let runtime = runtime_listing(vec![member(Phase::Running, "")]);
        run_cycle(&db.pool, &runtime, NAMESPACE).await;

        // Unlike a vanished member, a terminated one was seen: it closes now.
        *runtime.members.lock().unwrap() = vec![member(Phase::Terminated, "PodFailed")];
        let before_close = Utc::now().trunc_subsecs(6);
        run_cycle(&db.pool, &runtime, NAMESPACE).await;

        ensure!(sessions(&db.pool).await?[0].2 >= Some(before_close));
        ensure!(end_reason(&db.pool).await?.as_deref() == Some("PodFailed"));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_member_without_an_identity_changes_no_session() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;

        // A snapshot's clearing runtime bills nothing, whatever its claim says.
        let clearing = RuntimeMember {
            snapshot_clearing: true,
            ..member(Phase::Running, "")
        };
        run_cycle(&db.pool, &runtime_listing(vec![clearing]), NAMESPACE).await;
        ensure!(sessions(&db.pool).await?.is_empty());

        // A member the driver listed but couldn't read keeps its open session
        // exactly as it was: it isn't heartbeated or taken for a vanished one.
        let runtime = runtime_listing(vec![member(Phase::Running, "")]);
        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        let before = session_row(&db.pool).await?;
        let sandbox: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1",
            "kind": "Sandbox",
            "metadata": {
                "name": member(Phase::Running, "").name,
                "namespace": NAMESPACE,
                "uid": SANDBOX
            }
        }))?;
        *runtime.members.lock().unwrap() =
            vec![crate::runtime::kubernetes::members::unread_member(&sandbox)];
        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        ensure!(session_row(&db.pool).await? == before);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_member_of_another_organization_is_never_billed() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        let foreign = RuntimeMember {
            environment_id: ENV.into(),
            organization_id: "another-organization".into(),
            ..member(Phase::Running, "")
        };

        // It opens nothing, though the environment has a live binding.
        let reconciled = reconcile(&db.pool, &foreign).await;
        ensure!(reconciled.unbillable, "{reconciled:?}");
        ensure!(sessions(&db.pool).await?.is_empty());

        // And it doesn't move an open session to that organization.
        reconcile(&db.pool, &member(Phase::Running, "")).await;
        let before = session_row(&db.pool).await?;
        ensure!(before.6 == ORGANIZATION, "{}", before.6);
        let reconciled = reconcile(&db.pool, &foreign).await;
        ensure!(reconciled.unbillable, "{reconciled:?}");
        ensure!(session_row(&db.pool).await? == before);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_active_resize_freezes_the_open_session() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        reconcile(&db.pool, &member(Phase::Running, "")).await;
        ensure!(billed(&db.pool).await? == (1500, 5120, 10));

        resize_operation(&db.pool, "resize-active", "pending", 0).await?;
        for state in ["pending", "applying", "restarting"] {
            sqlx::query("UPDATE environment_resize_operations SET state = $1 WHERE id = $2")
                .bind(state)
                .bind("resize-active")
                .execute(&db.pool)
                .await?;
            reconcile(&db.pool, &resized_member()).await;
            let frozen = billed(&db.pool).await?;
            ensure!(frozen == (1500, 5120, 10), "{state}: {frozen:?}");
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_failed_resize_bills_last_applied_and_keeps_the_sidecars() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        reconcile(&db.pool, &member(Phase::Running, "")).await;

        resize_operation(&db.pool, "resize-failed", "failed", 0).await?;
        reconcile(&db.pool, &resized_member()).await;

        // The sidecars' 500m and 1024 MiB stay; the workspace is last-applied,
        // whatever the Sandbox declares while its rollback converges.
        let got = billed(&db.pool).await?;
        ensure!(got == (2500, 3072, 30), "{got:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_later_completed_resize_supersedes_a_failure() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        reconcile(&db.pool, &member(Phase::Running, "")).await;

        resize_operation(&db.pool, "resize-failed", "failed", 60).await?;
        resize_operation(&db.pool, "resize-completed", "completed", 0).await?;
        reconcile(&db.pool, &resized_member()).await;

        // What the Sandbox declares now, not the failure's last-applied shape.
        let got = billed(&db.pool).await?;
        ensure!(got.0 == 2500 && got.1 == 9216, "{got:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_grown_disk_bills_the_environments_applied_size() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        sqlx::query("UPDATE environments SET disk_gb = 120 WHERE id = $1")
            .bind(ENV)
            .execute(&db.pool)
            .await?;

        // The member still declares the 10 GiB it was created with.
        reconcile(&db.pool, &member(Phase::Running, "")).await;

        let got = billed(&db.pool).await?;
        ensure!(got == (1500, 5120, 120), "{got:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_listing_and_sweep_share_one_namespace() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        reconcile(&db.pool, &member(Phase::Running, "")).await;

        // A namespace that lists nothing doesn't reach this one's sessions.
        let runtime = FakeRuntimeDriver::default();
        run_cycle(&db.pool, &runtime, "another-namespace").await;
        ensure!(sessions(&db.pool).await?[0].2.is_none());
        ensure!(*runtime.placements.lock().unwrap() == [Placement::new("another-namespace")]);

        run_cycle(&db.pool, &runtime, NAMESPACE).await;
        ensure!(sessions(&db.pool).await?[0].2.is_some());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_session_opening_during_a_resize_bills_last_applied() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;

        // No open row to freeze at, so the last-applied shape is all there is.
        resize_operation(&db.pool, "resize-active", "applying", 0).await?;
        reconcile(&db.pool, &resized_member()).await;

        let got = billed(&db.pool).await?;
        ensure!(got == (2500, 3072, 30), "{got:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_running_member_that_resolves_to_no_environment_is_unbillable() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        bind(&db.pool).await?;
        let unknown_claim = RuntimeMember {
            claim_uid: "00000000-e29b-41d4-a716-446655440000".into(),
            ..member(Phase::Running, "")
        };
        let unknown_environment = RuntimeMember {
            environment_id: "00000000-e29b-41d4-a716-446655440001".into(),
            ..member(Phase::Running, "")
        };

        for (running, expected) in [
            (unknown_claim, "claim_not_found"),
            (unknown_environment, "environment_not_found"),
        ] {
            match resolve_identity(&db.pool, &running).await? {
                IdentityResolution::Unresolved(reason) => ensure!(reason == expected, "{reason}"),
                other => anyhow::bail!("{expected}: {other:?}"),
            }
            let reconciled = reconcile(&db.pool, &running).await;
            ensure!(reconciled.unbillable, "{expected}: {reconciled:?}");
            ensure!(sessions(&db.pool).await?.is_empty(), "{expected}");

            // Only a running one counts: a pending one isn't owed a bill yet.
            let pending = RuntimeMember {
                phase: Phase::Pending,
                ..running
            };
            let reconciled = reconcile(&db.pool, &pending).await;
            ensure!(!reconciled.unbillable, "{expected}: {reconciled:?}");
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
