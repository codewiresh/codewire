//! Disposable-PostgreSQL proof for the binding writer and its readers
//! (design §5.5, §6 and §16). Only synthetic rows in an isolated test
//! database are used.

use std::time::Duration;

use anyhow::{Result, ensure};
use sqlx::PgPool;
use sqlx::postgres::PgListener;

use super::*;
use crate::api::internal::gateway_daemon_authority;
use crate::test_database_support::TestDatabase;
use crate::workspace_binding::{BindingStore, PgBindingStore, WORKSPACE_BINDINGS_CHANNEL};

const CREATOR: &str = "workspace-binding-creator";
const ORGANIZATION: &str = "workspace-binding-organization";
const PRESET: &str = "workspace-binding-preset";
const NAMESPACE: &str = "binding-sandboxes";
const ENV_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const ENV_B: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const POD_1: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const POD_2: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const PVC: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const OTHER_PVC: &str = "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d";
const GENERATION: i64 = 3;

fn claim_uid(environment: &str) -> String {
    format!("c0ffee00{}", &environment[8..])
}

fn sandbox_uid(environment: &str) -> String {
    format!("5a4db0c5{}", &environment[8..])
}

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Binding','binding', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    for environment in [ENV_A, ENV_B] {
        sqlx::query(
            "INSERT INTO environments \
             (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
              environment_operation_generation) \
             VALUES ($1,$2,$3,$4,'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
        )
        .bind(environment)
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .bind(PRESET)
        .bind(GENERATION)
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO sandbox_environment_backend \
             (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(environment)
        .bind(NAMESPACE)
        .bind(format!("sandbox-{environment}"))
        .bind(claim_uid(environment))
        .execute(&db.pool)
        .await?;
    }
    Ok(())
}

fn record(environment: &str, pod: &str) -> BindingRecord {
    BindingRecord {
        environment_id: environment.into(),
        organization_id: ORGANIZATION.into(),
        pod_uid: pod.into(),
        namespace: NAMESPACE.into(),
        pod_name: format!("sandbox-{environment}"),
        claim_uid: claim_uid(environment),
        sandbox_uid: sandbox_uid(environment),
        workspace_pvc_uid: Some(PVC.into()),
        operation_generation: GENERATION,
        projection_selection_sha256: None,
        managed_credential_clients: codewire_access::ManagedCredentialClients::default()
            .encode()
            .to_owned(),
        credential_scope: WorkspaceCredentialScope::Environment,
    }
}

/// The recorder's exact fence: authority at the current generation, the
/// environment row locked for `running`, then the writer, then commit.
async fn fenced_write(pool: &PgPool, record: &BindingRecord) -> Result<WriteOutcome> {
    let authority = ActivityAuthority::capture(pool, &record.environment_id, GENERATION).await?;
    let mut guard = authority.begin_external_mutation(&RUNNING).await?;
    let outcome = write_binding(guard.transaction(), record).await?;
    guard.commit().await?;
    Ok(outcome)
}

async fn pointer(
    pool: &PgPool,
    environment: &str,
) -> Result<(Option<String>, bool, Option<String>)> {
    Ok(sqlx::query_as(
        "SELECT pod_uid, bound_at IS NOT NULL, workspace_pvc_uid \
           FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(environment)
    .fetch_one(pool)
    .await?)
}

async fn bindings(pool: &PgPool) -> Result<Vec<(String, String, bool)>> {
    Ok(sqlx::query_as(
        "SELECT pod_uid, environment_id, released_at IS NOT NULL \
           FROM sandbox_workspace_bindings ORDER BY bound_at, pod_uid",
    )
    .fetch_all(pool)
    .await?)
}

fn refused(error: &anyhow::Error) -> Option<WriteRefused> {
    error.downcast_ref::<WriteRefused>().copied()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_first_write_records_the_binding_and_pointer_and_notifies_at_commit() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let mut listener = PgListener::connect_with(&db.pool).await?;
        listener.listen(WORKSPACE_BINDINGS_CHANNEL).await?;

        let authority = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;
        let mut guard = authority.begin_external_mutation(&RUNNING).await?;
        ensure!(write_binding(guard.transaction(), &record(ENV_A, POD_1)).await? == WriteOutcome::Recorded);
        // NOTIFY inside the transaction is delivered only at commit.
        ensure!(
            tokio::time::timeout(Duration::from_millis(300), listener.recv())
                .await
                .is_err(),
            "notification escaped before commit"
        );
        guard.commit().await?;
        let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv()).await??;
        ensure!(notification.payload() == POD_1);

        ensure!(pointer(&db.pool, ENV_A).await? == (Some(POD_1.into()), true, Some(PVC.into())));
        ensure!(bindings(&db.pool).await? == vec![(POD_1.into(), ENV_A.into(), false)]);
        let stored: (String, String, String, String, i64, String) = sqlx::query_as(
            "SELECT namespace, pod_name, claim_uid, sandbox_uid, operation_generation, credential_scope \
               FROM sandbox_workspace_bindings WHERE pod_uid = $1",
        )
        .bind(POD_1)
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            stored
                == (
                    NAMESPACE.into(),
                    format!("sandbox-{ENV_A}"),
                    claim_uid(ENV_A),
                    sandbox_uid(ENV_A),
                    GENERATION,
                    "environment".into()
                )
        );

        // A rolled-back write announces nothing.
        let authority = ActivityAuthority::capture(&db.pool, ENV_B, GENERATION).await?;
        let mut guard = authority.begin_external_mutation(&RUNNING).await?;
        write_binding(guard.transaction(), &record(ENV_B, POD_2)).await?;
        drop(guard);
        ensure!(
            tokio::time::timeout(Duration::from_millis(500), listener.recv())
                .await
                .is_err(),
            "a rolled-back binding was announced"
        );
        ensure!(pointer(&db.pool, ENV_B).await?.0.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_rewriting_the_same_pod_is_idempotent() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        ensure!(fenced_write(&db.pool, &record(ENV_A, POD_1)).await? == WriteOutcome::Recorded);
        let first: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT bound_at FROM sandbox_environment_backend WHERE environment_id = $1",
        )
        .bind(ENV_A)
        .fetch_one(&db.pool)
        .await?;
        ensure!(fenced_write(&db.pool, &record(ENV_A, POD_1)).await? == WriteOutcome::Unchanged);
        let second: (chrono::DateTime<chrono::Utc>,) = sqlx::query_as(
            "SELECT bound_at FROM sandbox_environment_backend WHERE environment_id = $1",
        )
        .bind(ENV_A)
        .fetch_one(&db.pool)
        .await?;
        ensure!(first == second, "an unchanged re-record moved bound_at");
        ensure!(bindings(&db.pool).await?.len() == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pod_bound_to_another_environment_is_never_taken() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        let error = fenced_write(&db.pool, &record(ENV_B, POD_1))
            .await
            .expect_err("a second environment took a bound Pod");
        ensure!(refused(&error) == Some(WriteRefused::BoundElsewhere));
        ensure!(pointer(&db.pool, ENV_B).await? == (None, false, None));
        ensure!(pointer(&db.pool, ENV_A).await?.0.as_deref() == Some(POD_1));
        ensure!(bindings(&db.pool).await? == vec![(POD_1.into(), ENV_A.into(), false)]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_replacement_pod_releases_the_previous_binding() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        ensure!(fenced_write(&db.pool, &record(ENV_A, POD_2)).await? == WriteOutcome::Recorded);
        ensure!(pointer(&db.pool, ENV_A).await?.0.as_deref() == Some(POD_2));
        let rows = bindings(&db.pool).await?;
        ensure!(rows.contains(&(POD_1.into(), ENV_A.into(), true)));
        ensure!(rows.contains(&(POD_2.into(), ENV_A.into(), false)));
        // A released binding never comes back.
        let error = fenced_write(&db.pool, &record(ENV_A, POD_1))
            .await
            .expect_err("a released binding was revived");
        ensure!(refused(&error) == Some(WriteRefused::Released));
        ensure!(pointer(&db.pool, ENV_A).await?.0.as_deref() == Some(POD_2));

        // A binding stamped ahead of this transaction's clock is still
        // released, at its own bind time, never before it.
        let ahead = "0c1d2e3f-4a5b-4c6d-8e7f-8091a2b3c4d5";
        let mut tx = db.pool.begin().await?;
        sqlx::query(
            "INSERT INTO sandbox_workspace_bindings \
             (pod_uid, environment_id, namespace, pod_name, claim_uid, sandbox_uid, \
              operation_generation, managed_credential_clients, credential_scope, bound_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'environment', now() + interval '1 hour')",
        )
        .bind(ahead)
        .bind(ENV_B)
        .bind(NAMESPACE)
        .bind(format!("sandbox-{ENV_B}"))
        .bind(claim_uid(ENV_B))
        .bind(sandbox_uid(ENV_B))
        .bind(GENERATION)
        .bind(codewire_access::ManagedCredentialClients::default().encode())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE sandbox_environment_backend SET pod_uid = $2, bound_at = now() \
              WHERE environment_id = $1",
        )
        .bind(ENV_B)
        .bind(ahead)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut replacement = record(ENV_B, POD_1);
        replacement.pod_uid = "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into();
        replacement.workspace_pvc_uid = None;
        ensure!(fenced_write(&db.pool, &replacement).await? == WriteOutcome::Recorded);
        let released: bool = sqlx::query_scalar(
            "SELECT released_at = bound_at FROM sandbox_workspace_bindings WHERE pod_uid = $1",
        )
        .bind(ahead)
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            released,
            "a future-stamped binding was not released at its bind time"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stale_or_non_running_authority_writes_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let stale = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;
        sqlx::query("UPDATE environments SET environment_operation_generation = $2 WHERE id = $1")
            .bind(ENV_A)
            .bind(GENERATION + 1)
            .execute(&db.pool)
            .await?;
        let error = match stale.begin_external_mutation(&RUNNING).await {
            Ok(_) => anyhow::bail!("a stale authority locked the environment"),
            Err(error) => error,
        };
        ensure!(is_authority_lost(&error));

        sqlx::query("UPDATE environments SET state = 'stopping' WHERE id = $1")
            .bind(ENV_B)
            .execute(&db.pool)
            .await?;
        let error = fenced_write(&db.pool, &record(ENV_B, POD_2))
            .await
            .expect_err("a non-running environment was bound");
        ensure!(is_authority_lost(&error));
        ensure!(pointer(&db.pool, ENV_A).await?.0.is_none());
        ensure!(pointer(&db.pool, ENV_B).await?.0.is_none());
        ensure!(bindings(&db.pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_backend_changes_and_pvc_substitution_are_refused() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let mut replaced_claim = record(ENV_A, POD_1);
        replaced_claim.claim_uid = claim_uid(ENV_B);
        let error = fenced_write(&db.pool, &replaced_claim).await.expect_err("claim");
        ensure!(refused(&error) == Some(WriteRefused::BackendChanged));

        let mut other_namespace = record(ENV_A, POD_1);
        other_namespace.namespace = "other-sandboxes".into();
        let error = fenced_write(&db.pool, &other_namespace).await.expect_err("namespace");
        ensure!(refused(&error) == Some(WriteRefused::BackendChanged));

        sqlx::query(
            "UPDATE sandbox_environment_backend SET workspace_pvc_uid = $2 WHERE environment_id = $1",
        )
        .bind(ENV_A)
        .bind(OTHER_PVC)
        .execute(&db.pool)
        .await?;
        let error = fenced_write(&db.pool, &record(ENV_A, POD_1))
            .await
            .expect_err("a substituted PVC was bound");
        ensure!(refused(&error) == Some(WriteRefused::PvcMismatch));
        ensure!(pointer(&db.pool, ENV_A).await? == (None, false, Some(OTHER_PVC.into())));
        ensure!(bindings(&db.pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_first_workspace_pvc_uid_is_recorded_once() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        sqlx::query(
            "UPDATE environments SET state = 'stopped', desired_state = 'stopped' WHERE id = $1",
        )
        .bind(ENV_A)
        .execute(&db.pool)
        .await?;
        let write = |pvc: &'static str, claim: String| {
            let pool = db.pool.clone();
            async move {
                let authority = ActivityAuthority::capture(&pool, ENV_A, GENERATION).await?;
                let mut guard = authority.begin_external_mutation(&["stopped"]).await?;
                let outcome =
                    write_first_workspace_pvc(guard.transaction(), ENV_A, &claim, pvc).await?;
                guard.commit().await?;
                Ok::<_, anyhow::Error>(outcome)
            }
        };
        ensure!(write(PVC, claim_uid(ENV_B)).await? == WriteOutcome::Unchanged);
        ensure!(pointer(&db.pool, ENV_A).await?.2.is_none());
        ensure!(write(PVC, claim_uid(ENV_A)).await? == WriteOutcome::Recorded);
        // Only the restore adoption path may move a recorded UID.
        ensure!(write(OTHER_PVC, claim_uid(ENV_A)).await? == WriteOutcome::Unchanged);
        ensure!(pointer(&db.pool, ENV_A).await?.2.as_deref() == Some(PVC));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_bind_lookup_applies_every_bindability_condition() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let store = PgBindingStore::from_pool(db.pool.clone());
        let pod_name = format!("sandbox-{ENV_A}");
        ensure!(
            store
                .live_binding(POD_1, NAMESPACE, &pod_name)
                .await?
                .is_none()
        );
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        let binding = store
            .live_binding(POD_1, NAMESPACE, &pod_name)
            .await?
            .expect("recorded binding");
        ensure!(binding.environment_id == ENV_A && binding.sandbox_uid == sandbox_uid(ENV_A));
        ensure!(
            binding.claim_uid == claim_uid(ENV_A) && binding.operation_generation == GENERATION
        );
        ensure!(binding.credential_scope == WorkspaceCredentialScope::Environment);

        // The reviewed coordinates must match exactly.
        ensure!(
            store
                .live_binding(POD_1, "other", &pod_name)
                .await?
                .is_none()
        );
        ensure!(
            store
                .live_binding(POD_1, NAMESPACE, "other")
                .await?
                .is_none()
        );

        // An environment that is not bindable reads as nothing recorded.
        for (column, value) in [
            ("state", "'stopping'"),
            ("desired_state", "'stopped'"),
            ("deletion_requested_at", "now()"),
        ] {
            sqlx::query(&format!(
                "UPDATE environments SET {column} = {value} WHERE id = $1"
            ))
            .bind(ENV_A)
            .execute(&db.pool)
            .await?;
            ensure!(
                store
                    .live_binding(POD_1, NAMESPACE, &pod_name)
                    .await?
                    .is_none(),
                "{column}"
            );
            sqlx::query(
                "UPDATE environments SET state = 'running', desired_state = 'started', \
                 deletion_requested_at = NULL WHERE id = $1",
            )
            .bind(ENV_A)
            .execute(&db.pool)
            .await?;
        }
        ensure!(
            store
                .live_binding(POD_1, NAMESPACE, &pod_name)
                .await?
                .is_some()
        );

        // A replacement releases the old binding and moves the pointer.
        fenced_write(&db.pool, &record(ENV_A, POD_2)).await?;
        ensure!(
            store
                .live_binding(POD_1, NAMESPACE, &pod_name)
                .await?
                .is_none()
        );
        ensure!(
            store
                .live_binding(POD_2, NAMESPACE, &pod_name)
                .await?
                .is_some()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_gateway_credential_authority_reads_the_live_binding() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let before = gateway_daemon_authority(&db.pool, ENV_A)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .expect("bindable environment");
        ensure!(before.binding.is_none() && before.operation_generation == GENERATION);
        ensure!(before.organization_id == ORGANIZATION && before.namespace == NAMESPACE);

        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        let after = gateway_daemon_authority(&db.pool, ENV_A)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .expect("bindable environment");
        let binding = after.binding.expect("live binding");
        ensure!(binding.pod_uid == POD_1);
        ensure!(binding.credential_scope == WorkspaceCredentialScope::Environment);

        // Creating and starting environments are served too; others are not.
        for (state, served) in [("creating", true), ("starting", true), ("stopping", false)] {
            sqlx::query("UPDATE environments SET state = $2 WHERE id = $1")
                .bind(ENV_A)
                .bind(state)
                .execute(&db.pool)
                .await?;
            let authority = gateway_daemon_authority(&db.pool, ENV_A)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            ensure!(authority.is_some() == served, "{state}");
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_backfill_rotation_reaches_every_environment() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // Twenty more unbound running environments than one batch holds.
        let ids: Vec<String> = (0..20)
            .map(|index| format!("7a3b0c1d-0000-4000-8000-{index:012}"))
            .collect();
        for id in &ids {
            sqlx::query(
                "INSERT INTO environments \
                 (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
                  environment_operation_generation) \
                 VALUES ($1,$2,$3,$4,'sandbox','running','started', \
                 '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,1)",
            )
            .bind(id)
            .bind(ORGANIZATION)
            .bind(CREATOR)
            .bind(PRESET)
            .execute(&db.pool)
            .await?;
            sqlx::query(
                "INSERT INTO sandbox_environment_backend \
                 (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid) VALUES ($1,$2,$3,$4)",
            )
            .bind(id)
            .bind(NAMESPACE)
            .bind(format!("sandbox-{id}"))
            .bind(claim_uid(id))
            .execute(&db.pool)
            .await?;
        }
        // ENV_A and ENV_B are unbound too: 22 in all. Taking every turn in
        // batches of 16 reaches all 22 before any environment repeats, even
        // when every one of them keeps failing.
        let mut cursor = None;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..2 {
            for id in rotate(&db.pool, UNBOUND_RUNNING, &mut cursor, BACKFILL_BATCH).await? {
                ensure!(seen.insert(id.clone()), "{id} repeated before every environment had a turn");
                cursor = Some(id);
            }
        }
        ensure!(seen.len() == 22, "{} environments reached", seen.len());
        // Then it wraps to the start.
        let again = rotate(&db.pool, UNBOUND_RUNNING, &mut cursor, BACKFILL_BATCH).await?;
        ensure!(again.first().map(String::as_str) == seen.iter().next().map(String::as_str));

        // A bound environment leaves the unbound rotation and joins the bound one.
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        let mut unbound_cursor = None;
        let mut bound_cursor = None;
        let unbound = rotate(&db.pool, UNBOUND_RUNNING, &mut unbound_cursor, 64).await?;
        let bound = rotate(&db.pool, BOUND_RUNNING, &mut bound_cursor, 64).await?;
        ensure!(unbound.len() == 21 && !unbound.contains(&ENV_A.to_owned()));
        ensure!(bound == vec![ENV_A.to_owned()]);
        Ok(())
    }
    .await;
    db.finish(result).await
}
