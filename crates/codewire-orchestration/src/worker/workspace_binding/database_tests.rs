//! Disposable-PostgreSQL proof for the binding writer and its readers
//! (design §5.5, §6 and §16). Only synthetic rows in an isolated test
//! database are used.

use std::time::Duration;

use anyhow::{Result, ensure};
use serde_json::json;
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

        // Retried (pending), creating and starting environments are served
        // too; others are not.
        for (state, served) in [
            ("pending", true),
            ("creating", true),
            ("starting", true),
            ("resizing", true),
            ("stopping", false),
            ("stopped", false),
            ("error", false),
        ] {
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
        // A resize that replaces the Pod runs under desired `resized`; any
        // other non-started intent is never served.
        for (state, desired, served) in [
            ("resizing", "resized", true),
            ("running", "resized", false),
            ("running", "stopped", false),
            ("creating", "destroyed", false),
        ] {
            sqlx::query("UPDATE environments SET state = $2, desired_state = $3 WHERE id = $1")
                .bind(ENV_A)
                .bind(state)
                .bind(desired)
                .execute(&db.pool)
                .await?;
            let authority = gateway_daemon_authority(&db.pool, ENV_A)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            ensure!(authority.is_some() == served, "{state}/{desired}");
            let store = PgBindingStore::from_pool(db.pool.clone());
            let live = store
                .live_binding(POD_1, NAMESPACE, &format!("sandbox-{ENV_A}"))
                .await?;
            ensure!(live.is_some() == served, "listener {state}/{desired}");
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

// ------------------------------------------------- enforced recorder (B2)

/// A path-routed synthetic Kubernetes API holding the exact objects one
/// binding attempt reads. It records every request and serves a DELETE by
/// removing the object, so tests observe the UID-preconditioned deletion.
#[derive(Clone, Default)]
struct FakeKube {
    objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, serde_json::Value>>>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>,
}

const SANDBOXES_API: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces";
const CLAIMS_API: &str = "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces";
const CORE_API: &str = "/api/v1/namespaces";
const WORKSPACE_IMAGE: &str = "registry.example.test/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const DIND_IMAGE: &str = "docker.io/library/docker:28-dind";

fn pod_path(environment: &str) -> String {
    format!("{CORE_API}/{NAMESPACE}/pods/sandbox-{environment}")
}

fn pvc_path(environment: &str) -> String {
    format!("{CORE_API}/{NAMESPACE}/persistentvolumeclaims/workspace-sandbox-{environment}")
}

impl FakeKube {
    fn put(&self, path: String, object: serde_json::Value) {
        self.objects.lock().unwrap().insert(path, object);
    }

    fn update(&self, path: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        edit(
            self.objects
                .lock()
                .unwrap()
                .get_mut(path)
                .expect("fixture object"),
        );
    }

    fn deletes(&self) -> Vec<(String, serde_json::Value)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _, _)| method == "DELETE")
            .map(|(_, path, body)| (path.clone(), body.clone()))
            .collect()
    }

    fn client(&self) -> kube::Client {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, Response, StatusCode};
        let fake = self.clone();
        let service = axum::Router::new().fallback(move |request: Request<Body>| {
            let fake = fake.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
                let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                fake.requests
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone(), body));
                let found = match method.as_str() {
                    "GET" => fake.objects.lock().unwrap().get(&path).cloned(),
                    "DELETE" => fake.objects.lock().unwrap().remove(&path),
                    _ => None,
                };
                let (status, body) = match found {
                    Some(object) => (StatusCode::OK, object),
                    None => (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure",
                               "reason":"NotFound","code":404}),
                    ),
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        kube::Client::new(service, "default")
    }

    /// A converged, Ready Claim → Sandbox → Pod chain with a Bound PVC for
    /// `environment`. `scope` picks how the Pod was rendered.
    fn runtime(environment: &str, pod_uid: &str, scope: WorkspaceCredentialScope) -> Self {
        let fake = Self::default();
        let name = format!("sandbox-{environment}");
        let sandbox_labels = crate::sandbox::runtime_identity_labels(
            environment,
            ORGANIZATION,
            GENERATION,
            "sandbox",
        );
        let workspace_labels = crate::sandbox::runtime_identity_labels(
            environment,
            ORGANIZATION,
            GENERATION,
            "workspace",
        );
        fake.put(
            format!("{CLAIMS_API}/{NAMESPACE}/sandboxclaims/{name}"),
            json!({
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                "metadata": {"name": name, "namespace": NAMESPACE, "uid": claim_uid(environment),
                    "resourceVersion": "5", "labels": sandbox_labels},
                "spec": {"additionalPodMetadata": {"labels": workspace_labels}},
                "status": {"sandbox": {"name": name},
                    "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 2}]},
            }),
        );
        fake.put(
            format!("{SANDBOXES_API}/{NAMESPACE}/sandboxes/{name}"),
            json!({
                "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": name, "namespace": NAMESPACE, "uid": sandbox_uid(environment),
                    "generation": 2,
                    "ownerReferences": [{"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxClaim", "name": name, "uid": claim_uid(environment),
                        "controller": true}]},
                "spec": {
                    "podTemplate": {"metadata": {"labels": workspace_labels},
                        "spec": {"containers": [
                            {"name": "workspace", "image": WORKSPACE_IMAGE},
                            {"name": "dind", "image": DIND_IMAGE}]}},
                    "volumeClaimTemplates": [{"metadata": {"name": "workspace"}}]},
                "status": {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": 2}]},
            }),
        );
        let (workspace_env, extra_volume) = match scope {
            WorkspaceCredentialScope::Environment => (
                json!([{"name": "CODEWIRE_DAEMON_AUTH_TOKEN", "value": "synthetic-environment-token"}]),
                json!(null),
            ),
            WorkspaceCredentialScope::Pod => (
                json!([]),
                json!({"name": WORKSPACE_BINDING_VOLUME, "projected": {"sources": [
                    {"serviceAccountToken": {"audience": WORKSPACE_BINDING_TOKEN_AUDIENCE,
                        "expirationSeconds": 600, "path": "token"}}]}}),
            ),
        };
        let mut volumes = vec![json!({"name": "workspace",
            "persistentVolumeClaim": {"claimName": format!("workspace-{name}")}})];
        if !extra_volume.is_null() {
            volumes.push(extra_volume);
        }
        fake.put(
            pod_path(environment),
            json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": NAMESPACE, "uid": pod_uid,
                    "labels": workspace_labels,
                    "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "name": name, "uid": sandbox_uid(environment), "controller": true}]},
                "spec": {"serviceAccountName": "codewire-sandbox",
                    "containers": [
                        {"name": "workspace", "image": WORKSPACE_IMAGE, "env": workspace_env},
                        {"name": "dind", "image": DIND_IMAGE}],
                    "volumes": volumes},
                "status": {"phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [
                        {"name": "workspace", "image": WORKSPACE_IMAGE, "imageID":
                            "registry.example.test/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                         "ready": true, "started": true, "restartCount": 0},
                        {"name": "dind", "image": DIND_IMAGE, "imageID": "docker.io/library/docker@sha256:aaaa",
                         "ready": true, "started": true, "restartCount": 0}]},
            }),
        );
        fake.put(
            pvc_path(environment),
            json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": format!("workspace-{name}"), "namespace": NAMESPACE, "uid": PVC,
                    "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "name": name, "uid": sandbox_uid(environment), "controller": true}]},
                "spec": {"accessModes": ["ReadWriteOnce"]},
                "status": {"phase": "Bound"},
            }),
        );
        fake
    }
}

fn observed(environment: &str, pod_uid: &str) -> RuntimeIdentityObservation {
    RuntimeIdentityObservation::for_test(
        &sandbox_uid(environment),
        &format!("sandbox-{environment}"),
        pod_uid,
    )
}

async fn set_state(pool: &PgPool, environment: &str, state: &str) -> Result<()> {
    sqlx::query("UPDATE environments SET state = $2 WHERE id = $1")
        .bind(environment)
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

async fn enforced(
    pool: &PgPool,
    fake: &FakeKube,
    environment: &str,
    pod_uid: &str,
    states: &[&str],
) -> Result<WriteOutcome> {
    let env = load_environment(pool, environment).await?;
    let backend = crate::worker::env_data::load_backend_row(pool, environment).await?;
    let authority = ActivityAuthority::capture(pool, environment, GENERATION).await?;
    record_workspace_binding(
        &fake.client(),
        &env,
        &backend,
        &authority,
        states,
        &observed(environment, pod_uid),
    )
    .await
}

fn bind_refused(error: &anyhow::Error) -> Option<BindRefused> {
    error.downcast_ref::<BindRefused>().copied()
}

/// Design §10 and §16: the enforced recorder binds the exact observed Pod on
/// create (`creating`) and start (`starting`), records the PVC on first
/// resolution, and is idempotent for the same Pod. A legacy Pod records its
/// environment scope; an identity-free Pod records `pod` with the captured
/// environment row.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_enforced_recorder_binds_the_observed_pod_on_create_and_start() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        set_state(&db.pool, ENV_A, "creating").await?;
        let legacy = FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Environment);
        ensure!(
            enforced(&db.pool, &legacy, ENV_A, POD_1, &["creating"]).await?
                == WriteOutcome::Recorded
        );
        ensure!(pointer(&db.pool, ENV_A).await? == (Some(POD_1.into()), true, Some(PVC.into())));
        ensure!(
            enforced(&db.pool, &legacy, ENV_A, POD_1, &["creating"]).await?
                == WriteOutcome::Unchanged
        );
        ensure!(legacy.deletes().is_empty());

        set_state(&db.pool, ENV_B, "starting").await?;
        let identity_free = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        ensure!(
            enforced(&db.pool, &identity_free, ENV_B, POD_2, &["starting"]).await?
                == WriteOutcome::Recorded
        );
        let scope: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT credential_scope, operation_generation, projection_selection_sha256 \
               FROM sandbox_workspace_bindings WHERE pod_uid = $1",
        )
        .bind(POD_2)
        .fetch_one(&db.pool)
        .await?;
        ensure!(scope == ("pod".into(), GENERATION, None));
        let live = live_environment_binding(&db.pool, ENV_B).await?;
        ensure!(
            live.as_ref().is_some_and(|live| live.pod_uid == POD_2
                && live.credential_scope == WorkspaceCredentialScope::Pod)
        );

        // Only lifecycle states can bind: a stopped environment refuses.
        set_state(&db.pool, ENV_B, "stopped").await?;
        let error = enforced(&db.pool, &identity_free, ENV_B, POD_2, &["running"])
            .await
            .expect_err("a stopped environment was bound");
        ensure!(is_authority_lost(&error), "{error:#}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Design §5.6: a failed check fails the activity. An unbound identity-free
/// Pod is deleted with a UID precondition so it never serves; a legacy Pod
/// keeps its rendered token and is never deleted here.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_failed_check_deletes_only_an_unbound_identity_free_pod() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        set_state(&db.pool, ENV_A, "creating").await?;
        let identity_free = FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        identity_free.update(&pod_path(ENV_A), |pod| {
            pod["status"]["containerStatuses"][0]["imageID"] =
                json!("registry.example.test/codewire/workspace@sha256:9999999999999999999999999999999999999999999999999999999999999999");
        });
        let error = enforced(&db.pool, &identity_free, ENV_A, POD_1, &["creating"])
            .await
            .expect_err("a digest mismatch was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::Denied("images")));
        let deletes = identity_free.deletes();
        ensure!(deletes.len() == 1, "{deletes:?}");
        ensure!(deletes[0].0 == pod_path(ENV_A));
        ensure!(deletes[0].1["preconditions"]["uid"] == POD_1, "{:?}", deletes[0].1);
        ensure!(bindings(&db.pool).await?.is_empty());
        ensure!(pointer(&db.pool, ENV_A).await?.0.is_none());

        set_state(&db.pool, ENV_B, "creating").await?;
        let legacy = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Environment);
        legacy.update(&pod_path(ENV_B), |pod| {
            pod["spec"]["containers"][1]["image"] = json!("docker.io/library/docker:other");
        });
        let error = enforced(&db.pool, &legacy, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("an image mismatch was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::Denied("images")));
        ensure!(legacy.deletes().is_empty(), "a legacy Pod was deleted");

        // A PVC substitute under the same name fails the PVC check.
        let substitute = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        sqlx::query("UPDATE sandbox_environment_backend SET workspace_pvc_uid = $2 WHERE environment_id = $1")
            .bind(ENV_B)
            .bind(OTHER_PVC)
            .execute(&db.pool)
            .await?;
        let error = enforced(&db.pool, &substitute, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("a substituted PVC was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::Denied("workspace PVC")));
        // A resolution error may be an API failure: refused, never deleted.
        ensure!(substitute.deletes().is_empty());
        // A Pod that mounts another claim than the resolved PVC is deleted.
        let mounts_other = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        sqlx::query("UPDATE sandbox_environment_backend SET workspace_pvc_uid = NULL WHERE environment_id = $1")
            .bind(ENV_B)
            .execute(&db.pool)
            .await?;
        mounts_other.update(&pod_path(ENV_B), |pod| {
            pod["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = json!("workspace-other");
        });
        let error = enforced(&db.pool, &mounts_other, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("a Pod mounting another claim was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::Denied("workspace volume")));
        ensure!(mounts_other.deletes().len() == 1);
        // An unreadable chain (here: no Claim at all) refuses without deleting.
        let unreadable = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        unreadable
            .objects
            .lock()
            .unwrap()
            .retain(|path, _| !path.contains("sandboxclaims"));
        let error = enforced(&db.pool, &unreadable, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("an unreadable chain was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::ChainUnverified));
        ensure!(unreadable.deletes().is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// §14 "Double bind" and "Adoption lag": a Pod bound to another environment
/// is never taken or deleted; a Pod whose labels have not converged, or that
/// was replaced since the observation, is refused without a write or delete.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pod_bound_elsewhere_or_not_converged_is_never_bound_or_deleted() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // POD_1 is already ENV_A's.
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        set_state(&db.pool, ENV_B, "creating").await?;
        let stolen = FakeKube::runtime(ENV_B, POD_1, WorkspaceCredentialScope::Pod);
        let error = enforced(&db.pool, &stolen, ENV_B, POD_1, &["creating"])
            .await
            .expect_err("a Pod bound elsewhere was taken");
        ensure!(
            bind_refused(&error) == Some(BindRefused::BoundElsewhere),
            "{error:#}"
        );
        ensure!(
            stolen.deletes().is_empty(),
            "another environment's Pod was deleted"
        );
        ensure!(pointer(&db.pool, ENV_B).await?.0.is_none());

        let lagging = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        lagging.update(&pod_path(ENV_B), |pod| {
            pod["metadata"]["labels"]["codewire.sh/environment-operation-generation"] = json!("2");
        });
        let error = enforced(&db.pool, &lagging, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("a Pod with stale labels was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::NotConverged));
        ensure!(lagging.deletes().is_empty());

        let replaced = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        let error = enforced(
            &db.pool,
            &replaced,
            ENV_B,
            "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6",
            &["creating"],
        )
        .await
        .expect_err("a replaced Pod was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::PodChanged));
        ensure!(replaced.deletes().is_empty());

        let terminating = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        terminating.update(&pod_path(ENV_B), |pod| {
            pod["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z");
        });
        let error = enforced(&db.pool, &terminating, ENV_B, POD_2, &["creating"])
            .await
            .expect_err("a terminating Pod was bound");
        ensure!(bind_refused(&error) == Some(BindRefused::ChainUnverified));
        ensure!(terminating.deletes().is_empty());
        ensure!(bindings(&db.pool).await? == vec![(POD_1.into(), ENV_A.into(), false)]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Stop, a restart before resume and destroy release the binding only once
/// its Pod is observed absent, and clear the pointer; the lookups the
/// listener, gateway and daemon credential use then find nothing live.
/// Release is idempotent and fenced.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_release_clears_the_pointer_and_every_live_lookup() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let mut pod_scope = record(ENV_A, POD_1);
        pod_scope.credential_scope = WorkspaceCredentialScope::Pod;
        fenced_write(&db.pool, &pod_scope).await?;
        let secret = "synthetic-session-secret";
        ensure!(
            environment_daemon_credential(&db.pool, None, secret, ENV_A).await?
                == crate::worker::gatewayauth::issue_workspace_daemon_credential(
                    secret, ENV_A, POD_1
                )?
        );

        set_state(&db.pool, ENV_A, "stopping").await?;
        let authority = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;
        // Design §10: never while the bound Pod is present, even terminating.
        let present = FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        present.update(&pod_path(ENV_A), |pod| {
            pod["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z");
        });
        let error = release_workspace_binding(&present.client(), &authority, &["stopping"])
            .await
            .expect_err("a binding was released while its Pod was present");
        ensure!(
            error.downcast_ref::<BoundPodPresent>().is_some(),
            "{error:#}"
        );
        ensure!(pointer(&db.pool, ENV_A).await?.0.as_deref() == Some(POD_1));
        ensure!(live_environment_binding(&db.pool, ENV_A).await?.is_some());
        // The same name on another Pod UID means the bound Pod is gone.
        let replaced = FakeKube::runtime(ENV_A, POD_2, WorkspaceCredentialScope::Pod);
        ensure!(release_workspace_binding(&replaced.client(), &authority, &["stopping"]).await?);
        let absent = FakeKube::default().client();
        ensure!(!release_workspace_binding(&absent, &authority, &["stopping"]).await?);
        ensure!(present.deletes().is_empty() && replaced.deletes().is_empty());
        ensure!(pointer(&db.pool, ENV_A).await? == (None, false, Some(PVC.into())));
        ensure!(bindings(&db.pool).await? == vec![(POD_1.into(), ENV_A.into(), true)]);
        ensure!(live_environment_binding(&db.pool, ENV_A).await?.is_none());
        // With no live binding only a legacy current Pod receives the
        // environment token (review L4). An unbound identity-free Pod, an
        // unreadable Pod, or no Kubernetes client gets no credential at all.
        let legacy = FakeKube::runtime(ENV_A, POD_2, WorkspaceCredentialScope::Environment);
        ensure!(
            environment_daemon_credential(&db.pool, Some(&legacy.client()), secret, ENV_A).await?
                == crate::worker::gatewayauth::issue_token(
                    secret,
                    ENV_A,
                    crate::worker::gatewayauth::SCOPE_DAEMON
                )?
        );
        let unbound = FakeKube::runtime(ENV_A, POD_2, WorkspaceCredentialScope::Pod);
        for kube in [
            Some(unbound.client()),
            Some(FakeKube::default().client()),
            None,
        ] {
            let error = environment_daemon_credential(&db.pool, kube.as_ref(), secret, ENV_A)
                .await
                .expect_err("an unbound non-legacy Pod received the environment token");
            ensure!(
                error.downcast_ref::<DaemonNotBound>().is_some(),
                "{error:#}"
            );
        }
        let store = PgBindingStore::from_pool(db.pool.clone());
        ensure!(
            store
                .live_binding(POD_1, NAMESPACE, &format!("sandbox-{ENV_A}"))
                .await?
                .is_none()
        );

        // A stale authority releases nothing.
        fenced_write(&db.pool, &record(ENV_B, POD_2)).await?;
        let stale = ActivityAuthority::capture(&db.pool, ENV_B, GENERATION).await?;
        sqlx::query("UPDATE environments SET environment_operation_generation = $2 WHERE id = $1")
            .bind(ENV_B)
            .bind(GENERATION + 1)
            .execute(&db.pool)
            .await?;
        let error = release_workspace_binding(&absent, &stale, &RUNNING)
            .await
            .expect_err("a stale authority released a binding");
        ensure!(is_authority_lost(&error));
        ensure!(pointer(&db.pool, ENV_B).await?.0.as_deref() == Some(POD_2));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Design §12: a restore adoption is the one path that moves the recorded
/// PVC UID. It needs no live binding, a PVC that resolves by the new UID
/// through the adoption window, and the generation fence.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_restore_adoption_moves_the_pvc_uid_only_when_unbound_and_resolvable() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        sqlx::query("UPDATE sandbox_environment_backend SET workspace_pvc_uid = $2 WHERE environment_id = $1")
            .bind(ENV_A)
            .bind(PVC)
            .execute(&db.pool)
            .await?;
        set_state(&db.pool, ENV_A, "starting").await?;
        let fake = FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        let sandbox_name = format!("sandbox-{ENV_A}");
        let restored = |labels: serde_json::Value| {
            json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": format!("workspace-{sandbox_name}"), "namespace": NAMESPACE,
                    "uid": OTHER_PVC, "labels": labels},
                "spec": {"accessModes": ["ReadWriteOnce"],
                    "dataSource": {"apiGroup": "snapshot.storage.k8s.io",
                        "kind": "VolumeSnapshot", "name": "workspace-backup"}},
                "status": {"phase": "Pending"},
            })
        };
        let backend = crate::worker::env_data::load_backend_row(&db.pool, ENV_A).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;

        // A same-name PVC without this Sandbox's tracking label never adopts.
        fake.put(pvc_path(ENV_A), restored(json!({"agents.x-k8s.io/sandbox-name-hash": "0123abcd"})));
        let error = adopt_restored_workspace_pvc(&fake.client(), &authority, &["starting"], &backend, OTHER_PVC)
            .await
            .expect_err("an untracked PVC was adopted");
        ensure!(error.downcast_ref::<AdoptionRefused>() == Some(&AdoptionRefused::NotResolvable));
        let error = adopt_restored_workspace_pvc(&fake.client(), &authority, &["starting"], &backend, "not-a-uid")
            .await
            .expect_err("a malformed UID was adopted");
        ensure!(error.downcast_ref::<AdoptionRefused>() == Some(&AdoptionRefused::InvalidUid));

        let tracked = restored(json!({
            "agents.x-k8s.io/sandbox-name-hash": crate::sandbox::client::sandbox_name_hash(&sandbox_name),
        }));
        fake.put(pvc_path(ENV_A), tracked);
        // A live binding blocks adoption: the PVC changes only between stop
        // and resume.
        set_state(&db.pool, ENV_A, "running").await?;
        fenced_write(&db.pool, &record(ENV_A, POD_1)).await?;
        set_state(&db.pool, ENV_A, "starting").await?;
        let error = adopt_restored_workspace_pvc(&fake.client(), &authority, &["starting"], &backend, OTHER_PVC)
            .await
            .expect_err("a bound environment adopted a PVC");
        ensure!(error.downcast_ref::<AdoptionRefused>() == Some(&AdoptionRefused::Bound));
        // Stopped: the Pod is gone, so its binding is released.
        fake.objects.lock().unwrap().remove(&pod_path(ENV_A));
        ensure!(release_workspace_binding(&fake.client(), &authority, &["starting"]).await?);
        adopt_restored_workspace_pvc(&fake.client(), &authority, &["starting"], &backend, OTHER_PVC).await?;
        ensure!(pointer(&db.pool, ENV_A).await? == (None, false, Some(OTHER_PVC.into())));
        // The resolver now accepts the restored PVC by its adopted UID.
        let anchor = crate::worker::env_data::workspace_pvc_anchor(
            &crate::worker::env_data::load_backend_row(&db.pool, ENV_A).await?,
        );
        let resolved = SandboxClient::new(fake.client(), NAMESPACE)
            .resolve_anchored_workspace_pvc(&anchor)
            .await?;
        ensure!(matches!(resolved, Some((_, WorkspacePvc::Claim { ref uid, .. })) if uid == OTHER_PVC));

        // A stale authority adopts nothing.
        sqlx::query("UPDATE environments SET environment_operation_generation = $2 WHERE id = $1")
            .bind(ENV_A)
            .bind(GENERATION + 1)
            .execute(&db.pool)
            .await?;
        let error = adopt_restored_workspace_pvc(&fake.client(), &authority, &["starting"], &backend, OTHER_PVC)
            .await
            .expect_err("a stale authority adopted a PVC");
        ensure!(is_authority_lost(&error));
        ensure!(pointer(&db.pool, ENV_A).await?.2.as_deref() == Some(OTHER_PVC));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Design §10's release rule in the backfill: a live binding whose
/// environment is not stably running (destroyed, stopped) is released once
/// its Pod is observed absent, which also frees bindings an earlier binary
/// left live. A present or terminating Pod keeps its binding, a running
/// environment is left to its liveness rebind, and nothing is ever deleted.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_release_sweep_frees_only_bindings_whose_pod_is_absent() -> Result<()> {
    const ENV_C: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";
    const POD_3: &str = "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901";
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        sqlx::query(
            "INSERT INTO environments \
             (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
              environment_operation_generation) \
             VALUES ($1,$2,$3,$4,'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
        )
        .bind(ENV_C)
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
        .bind(ENV_C)
        .bind(NAMESPACE)
        .bind(format!("sandbox-{ENV_C}"))
        .bind(claim_uid(ENV_C))
        .execute(&db.pool)
        .await?;
        for (environment, pod) in [(ENV_A, POD_1), (ENV_B, POD_2), (ENV_C, POD_3)] {
            fenced_write(&db.pool, &record(environment, pod)).await?;
        }
        // A destroyed environment whose cleanup removed its backend row, as
        // on Dev before B2, and a stopped one whose Pod is still present.
        sqlx::query(
            "UPDATE environments SET state='destroyed', desired_state='destroyed' WHERE id=$1",
        )
        .bind(ENV_A)
        .execute(&db.pool)
        .await?;
        sqlx::query("DELETE FROM sandbox_environment_backend WHERE environment_id = $1")
            .bind(ENV_A)
            .execute(&db.pool)
            .await?;
        sqlx::query("UPDATE environments SET state='stopped', desired_state='stopped' WHERE id=$1")
            .bind(ENV_B)
            .execute(&db.pool)
            .await?;

        // The running environment is not a sweep candidate even with no Pod.
        let mut cursor = None;
        let candidates = rotate(&db.pool, UNRELEASED_INACTIVE, &mut cursor, 64).await?;
        let mut expected = vec![POD_1.to_owned(), POD_2.to_owned()];
        expected.sort();
        ensure!(candidates == expected, "{candidates:?}");

        let kube = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Pod);
        kube.update(&pod_path(ENV_B), |pod| {
            pod["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z");
        });
        let client = kube.client();
        ensure!(
            release_binding_if_pod_absent(&db.pool, &client, POD_1).await?
                == RecordResult::Recorded
        );
        ensure!(
            release_binding_if_pod_absent(&db.pool, &client, POD_2).await?
                == RecordResult::Unchanged
        );
        ensure!(
            release_binding_if_pod_absent(&db.pool, &client, POD_1).await?
                == RecordResult::Unchanged
        );
        ensure!(live_environment_binding(&db.pool, ENV_A).await?.is_none());
        ensure!(pointer(&db.pool, ENV_B).await?.0.as_deref() == Some(POD_2));

        // The stopped environment's Pod is replaced under the same name.
        let replaced = FakeKube::runtime(ENV_B, POD_3, WorkspaceCredentialScope::Pod);
        ensure!(
            release_binding_if_pod_absent(&db.pool, &replaced.client(), POD_2).await?
                == RecordResult::Recorded
        );
        ensure!(pointer(&db.pool, ENV_B).await? == (None, false, Some(PVC.into())));

        let rows = bindings(&db.pool).await?;
        ensure!(rows.len() == 3, "a binding row was deleted: {rows:?}");
        ensure!(rows.contains(&(POD_1.into(), ENV_A.into(), true)));
        ensure!(rows.contains(&(POD_2.into(), ENV_B.into(), true)));
        ensure!(rows.contains(&(POD_3.into(), ENV_C.into(), false)));
        ensure!(kube.deletes().is_empty() && replaced.deletes().is_empty());
        let mut cursor = None;
        ensure!(
            rotate(&db.pool, UNRELEASED_INACTIVE, &mut cursor, 64)
                .await?
                .is_empty()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Review M1: the backfill never records a Pod-scope binding, which the 8087
/// listener and the gateway RPC would serve without the enforced path's
/// locked re-check. It leaves an identity-free Pod `NotReady`, unbound and
/// undeleted, and still records a legacy Pod's environment scope.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_backfill_never_records_a_pod_scope_binding() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let identity_free = FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        ensure!(
            record_backfill(&db.pool, &identity_free.client(), ENV_A).await?
                == RecordResult::NotReady
        );
        ensure!(bindings(&db.pool).await?.is_empty());
        ensure!(pointer(&db.pool, ENV_A).await?.0.is_none());
        ensure!(identity_free.deletes().is_empty());

        let legacy = FakeKube::runtime(ENV_B, POD_2, WorkspaceCredentialScope::Environment);
        ensure!(
            record_backfill(&db.pool, &legacy.client(), ENV_B).await? == RecordResult::Recorded
        );
        let scope: String = sqlx::query_scalar(
            "SELECT credential_scope FROM sandbox_workspace_bindings WHERE pod_uid = $1",
        )
        .bind(POD_2)
        .fetch_one(&db.pool)
        .await?;
        ensure!(scope == "environment");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A Claim → Sandbox → Pod chain that is bind-ready but not Ready: DinD's
/// Docker daemon is still starting, so the DinD container has started but is
/// not ready, the Pod is not Ready, and neither the Sandbox nor the Claim is
/// Ready, while the Sandbox status reports its current generation.
fn dind_starting(environment: &str, pod_uid: &str, scope: WorkspaceCredentialScope) -> FakeKube {
    let fake = FakeKube::runtime(environment, pod_uid, scope);
    let name = format!("sandbox-{environment}");
    fake.update(
        &format!("{CLAIMS_API}/{NAMESPACE}/sandboxclaims/{name}"),
        |claim| {
            claim["status"]["conditions"][0]["status"] = json!("False");
        },
    );
    fake.update(
        &format!("{SANDBOXES_API}/{NAMESPACE}/sandboxes/{name}"),
        |sandbox| {
            sandbox["status"]["conditions"][0]["status"] = json!("False");
        },
    );
    fake.update(&pod_path(environment), |pod| {
        pod["status"]["conditions"][0]["status"] = json!("False");
        pod["status"]["containerStatuses"][1]["ready"] = json!(false);
        pod["status"]["containerStatuses"][1]["state"] = json!({"running": {}});
    });
    fake
}

/// Design §10 (amended): an identity-free Pod is bound while DinD is still
/// starting, before any Claim, Sandbox or Pod readiness, through the same
/// enforced recorder. A legacy Pod is left to the post-ready path.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_bind_happens_while_dind_is_still_starting() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        set_state(&db.pool, ENV_A, "creating").await?;
        let starting = dind_starting(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        let authority = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;
        let bound = tokio::time::timeout(
            Duration::from_secs(5),
            bind_before_ready(&starting.client(), &authority, &["creating"]),
        )
        .await??;
        ensure!(bound.is_some(), "the early bind did not record");
        ensure!(pointer(&db.pool, ENV_A).await?.0.as_deref() == Some(POD_1));
        let live = live_environment_binding(&db.pool, ENV_A).await?;
        ensure!(live.is_some_and(|live| live.credential_scope == WorkspaceCredentialScope::Pod));
        // Already bound: the post-ready bind and a second early bind change nothing.
        ensure!(
            enforced(
                &db.pool,
                &FakeKube::runtime(ENV_A, POD_1, WorkspaceCredentialScope::Pod),
                ENV_A,
                POD_1,
                &["creating"]
            )
            .await?
                == WriteOutcome::Unchanged
        );
        ensure!(
            tokio::time::timeout(
                Duration::from_secs(5),
                bind_before_ready(&starting.client(), &authority, &["creating"]),
            )
            .await??
            .is_none()
        );
        ensure!(starting.deletes().is_empty());

        set_state(&db.pool, ENV_B, "starting").await?;
        let legacy = dind_starting(ENV_B, POD_2, WorkspaceCredentialScope::Environment);
        let authority = ActivityAuthority::capture(&db.pool, ENV_B, GENERATION).await?;
        ensure!(
            tokio::time::timeout(
                Duration::from_secs(5),
                bind_before_ready(&legacy.client(), &authority, &["starting"]),
            )
            .await??
            .is_none()
        );
        ensure!(pointer(&db.pool, ENV_B).await?.0.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Design §10 (amended): each bind-ready condition, missing on its own,
/// refuses the bind and records nothing. The chain and readiness conditions
/// refuse without deleting; a definitive check failure on the unbound
/// identity-free Pod deletes it, as before.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_each_missing_bind_condition_refuses_the_bind() -> Result<()> {
    type Mutation = Box<dyn Fn(&FakeKube)>;
    let name = format!("sandbox-{ENV_A}");
    let claim = format!("{CLAIMS_API}/{NAMESPACE}/sandboxclaims/{name}");
    let sandbox = format!("{SANDBOXES_API}/{NAMESPACE}/sandboxes/{name}");
    let pod = pod_path(ENV_A);
    let pvc = pvc_path(ENV_A);
    let edit = |path: &String, change: fn(&mut serde_json::Value)| -> Mutation {
        let path = path.clone();
        Box::new(move |fake: &FakeKube| fake.update(&path, change))
    };
    let cases: Vec<(&str, Mutation, BindRefused, bool)> = vec![
        (
            "Claim labels",
            edit(&claim, |o| {
                o["metadata"]["labels"]["codewire.sh/environment-operation-generation"] = json!("2")
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "Claim Pod labels",
            edit(&claim, |o| {
                o["spec"]["additionalPodMetadata"]["labels"]["codewire.sh/environment-operation-generation"] =
                    json!("2")
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "Sandbox template labels",
            edit(&sandbox, |o| {
                o["spec"]["podTemplate"]["metadata"]["labels"]["codewire.sh/environment-operation-generation"] =
                    json!("2")
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "Pod labels",
            edit(&pod, |o| {
                o["metadata"]["labels"]["codewire.sh/environment-operation-generation"] = json!("2")
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "stale Sandbox status",
            edit(&sandbox, |o| {
                o["status"]["conditions"][0]["observedGeneration"] = json!(1)
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "no Sandbox condition",
            edit(&sandbox, |o| o["status"]["conditions"] = json!([])),
            BindRefused::NotConverged,
            false,
        ),
        (
            "Pod not Running",
            edit(&pod, |o| o["status"]["phase"] = json!("Pending")),
            BindRefused::NotConverged,
            false,
        ),
        (
            "container not started",
            edit(&pod, |o| {
                o["status"]["containerStatuses"][1]["started"] = json!(false)
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "container without imageID",
            edit(&pod, |o| {
                o["status"]["containerStatuses"][1]["imageID"] = json!("")
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "container without status",
            edit(&pod, |o| {
                o["status"]["containerStatuses"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "init container not finished",
            edit(&pod, |o| {
                o["spec"]["initContainers"] = json!([{"name": "daemon-init", "image": DIND_IMAGE}]);
                o["status"]["initContainerStatuses"] = json!([{"name": "daemon-init", "image": DIND_IMAGE,
                "imageID": "docker.io/library/docker@sha256:aaaa", "ready": false, "started": false,
                "restartCount": 0, "state": {"waiting": {"reason": "PodInitializing"}}}]);
            }),
            BindRefused::NotConverged,
            false,
        ),
        (
            "Claim deleting",
            edit(&claim, |o| {
                o["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Sandbox deleting",
            edit(&sandbox, |o| {
                o["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Pod deleting",
            edit(&pod, |o| {
                o["metadata"]["deletionTimestamp"] = json!("2026-10-02T00:00:00Z")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Claim not bound to the Sandbox",
            edit(&claim, |o| {
                o["status"]["sandbox"]["name"] = json!("sandbox-other")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Sandbox controlled by another Claim",
            edit(&sandbox, |o| {
                o["metadata"]["ownerReferences"][0]["uid"] =
                    json!("3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Pod controlled by another Sandbox",
            edit(&pod, |o| {
                o["metadata"]["ownerReferences"][0]["uid"] =
                    json!("3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d")
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "Pod with a second controller",
            edit(&pod, |o| {
                o["metadata"]["ownerReferences"].as_array_mut().unwrap().push(json!({"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "other", "uid": "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d", "controller": true}));
            }),
            BindRefused::ChainUnverified,
            false,
        ),
        (
            "image digest",
            edit(&pod, |o| {
                o["status"]["containerStatuses"][0]["imageID"] = json!(
                    "registry.example.test/codewire/workspace@sha256:9999999999999999999999999999999999999999999999999999999999999999"
                )
            }),
            BindRefused::Denied("images"),
            true,
        ),
        (
            "PVC not Bound",
            edit(&pvc, |o| o["status"]["phase"] = json!("Pending")),
            BindRefused::Denied("workspace volume"),
            true,
        ),
        (
            "ambiguous credential scope",
            edit(
                &pod,
                |o| {
                    o["spec"]["containers"][0]["env"] =
                        json!([{"name": "CODEWIRE_DAEMON_AUTH_TOKEN", "value": "synthetic"}])
                },
            ),
            BindRefused::Denied("credential scope"),
            true,
        ),
    ];
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        set_state(&db.pool, ENV_A, "creating").await?;
        for (label, mutate, expected, deletes) in &cases {
            let fake = dind_starting(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
            mutate(&fake);
            let error = enforced(&db.pool, &fake, ENV_A, POD_1, &["creating"])
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("{label}: the bind was recorded"))?;
            ensure!(
                bind_refused(&error) == Some(*expected),
                "{label}: {error:#}"
            );
            ensure!(
                bindings(&db.pool).await?.is_empty(),
                "{label}: a binding was recorded"
            );
            ensure!(
                fake.deletes().is_empty() != *deletes,
                "{label}: deletes {:?}",
                fake.deletes()
            );
        }

        // The environment must be authoritative: a non-bindable state.
        set_state(&db.pool, ENV_A, "stopped").await?;
        let fake = dind_starting(ENV_A, POD_1, WorkspaceCredentialScope::Pod);
        let error = enforced(&db.pool, &fake, ENV_A, POD_1, &["running"])
            .await
            .expect_err("a stopped environment was bound");
        ensure!(is_authority_lost(&error), "{error:#}");
        set_state(&db.pool, ENV_A, "creating").await?;

        // A changed backend row.
        let env = load_environment(&db.pool, ENV_A).await?;
        let mut backend = crate::worker::env_data::load_backend_row(&db.pool, ENV_A).await?;
        backend.claim_uid = OTHER_PVC.into();
        let authority = ActivityAuthority::capture(&db.pool, ENV_A, GENERATION).await?;
        let error = record_workspace_binding(
            &fake.client(),
            &env,
            &backend,
            &authority,
            &["creating"],
            &observed(ENV_A, POD_1),
        )
        .await
        .expect_err("a changed backend row was bound");
        ensure!(
            error.to_string().contains("backend association changed"),
            "{error:#}"
        );

        // Pod-scope values captured before the lock must still match the
        // environment row the fenced transaction locked.
        let mut stale = load_environment(&db.pool, ENV_A).await?;
        stale.managed_credential_clients =
            Ok(codewire_access::ManagedCredentialClients::from_profile_slots(["codex"])?);
        let backend = crate::worker::env_data::load_backend_row(&db.pool, ENV_A).await?;
        let error = record_workspace_binding(
            &fake.client(),
            &stale,
            &backend,
            &authority,
            &["creating"],
            &observed(ENV_A, POD_1),
        )
        .await
        .expect_err("a stale Pod-scope capture was bound");
        ensure!(is_authority_lost(&error), "{error:#}");
        ensure!(bindings(&db.pool).await?.is_empty());

        // With every condition present it binds.
        ensure!(
            enforced(&db.pool, &fake, ENV_A, POD_1, &["creating"]).await? == WriteOutcome::Recorded
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
