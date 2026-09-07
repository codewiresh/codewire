//! Terminal lifecycle cleanup releases metadata references, not credentials.

use anyhow::{Result, ensure};
use codewire_orchestration::lifecycle::{PgLifecycleStore, Service, Snapshot};
use serde_json::{Value, json};

use super::support::*;

const UNRELATED_ENV: &str = "synthetic-unrelated-environment";

async fn bind_profile(h: &Harness, name: &str, environment: &str) -> Result<Value> {
    let profile = h.rpc.create(name, CREDENTIAL).await?;
    let mut selected = binding(&profile);
    selected["environmentId"] = json!(environment);
    h.rpc
        .ok(
            "SetEnvironmentAccessProfile",
            Auth::Alice,
            set(&selected, None, true),
        )
        .await?;
    Ok(profile)
}

async fn seed_runtime(h: &Harness, environment: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,pod_name) \
         VALUES ($1,'synthetic-sandboxes',$1,$1)",
    )
    .bind(environment)
    .execute(&h.db)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_running_sessions \
         (environment_id,organization_id,runtime_uid,runtime_name,runtime_namespace, \
          cpu_millicores,memory_mib,disk_gib,started_at,last_observed_at) \
         VALUES ($1,$2,$1,$1,'synthetic-sandboxes',1000,1024,10,now(),now())",
    )
    .bind(environment)
    .bind(ORG)
    .execute(&h.db)
    .await?;
    Ok(())
}

async fn snapshot(h: &Harness, environment: &str) -> Result<Value> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object( \
         'environment',to_jsonb(e), \
         'binding',(SELECT to_jsonb(b) FROM platform_environment_access_bindings b \
                    WHERE b.environment_id=e.id), \
         'backend',(SELECT to_jsonb(b) FROM sandbox_environment_backend b \
                    WHERE b.environment_id=e.id), \
         'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM sandbox_running_sessions s \
                     WHERE s.environment_id=e.id), \
         'logs',(SELECT jsonb_agg(to_jsonb(l) ORDER BY l.id) FROM environment_logs l \
                 WHERE l.environment_id=e.id), \
         'journal',(SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM environment_lifecycle_journal j \
                    WHERE j.environment_id=e.id)) \
         FROM environments e WHERE e.id=$1",
    )
    .bind(environment)
    .fetch_one(&h.db)
    .await?)
}

async fn credential_snapshot(h: &Harness) -> Result<Value> {
    Ok(
        sqlx::query_scalar("SELECT to_jsonb(c) FROM platform_credentials c WHERE id=$1")
            .bind(CREDENTIAL)
            .fetch_one(&h.db)
            .await?,
    )
}

async fn failed_cleanup_preserves(h: &Harness) -> Result<()> {
    let before = snapshot(h, ENV).await?;
    ensure!(
        Service::<PgLifecycleStore>::for_pool(h.db.clone())
            .complete_external_cleanup(ENV, false)
            .await
            .is_err(),
        "cleanup unexpectedly passed its guard"
    );
    ensure!(
        snapshot(h, ENV).await? == before,
        "failed cleanup changed its binding, runtime or durable checkpoint"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn terminal_cleanup_unbinds_only_target_and_releases_public_profile_deletion() -> Result<()> {
    // The destroyed case is replay of an incomplete terminal checkpoint, not
    // permission to sweep bindings from unrelated or already-completed rows.
    for already_destroyed in [false, true] {
        let h = Harness::create().await?;
        let result = async {
            let profile = bind_profile(&h, "destroy-target", ENV).await?;
            seed_runtime(&h, ENV).await?;
            sqlx::query(
                "INSERT INTO environments \
                 (id,org_id,created_by,type,preset_id,state,desired_state, \
                  environment_operation_generation,project_spec) \
                 SELECT $2,org_id,created_by,type,preset_id,state,desired_state, \
                        environment_operation_generation,project_spec \
                 FROM environments WHERE id=$1",
            )
            .bind(ENV)
            .bind(UNRELATED_ENV)
            .execute(&h.db)
            .await?;
            let unrelated = bind_profile(&h, "destroy-unrelated", UNRELATED_ENV).await?;
            seed_runtime(&h, UNRELATED_ENV).await?;
            let unrelated_before = snapshot(&h, UNRELATED_ENV).await?;
            let credential_before = credential_snapshot(&h).await?;

            sqlx::query(
                "UPDATE environments SET desired_state='destroyed',state=$2, \
                 destroyed_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE id=$1",
            )
            .bind(ENV)
            .bind(if already_destroyed {
                "destroyed"
            } else {
                "destroying"
            })
            .bind(already_destroyed)
            .execute(&h.db)
            .await?;
            // This is the user-visible orphan: neither public clearing nor
            // profile deletion can remove the reference before final cleanup.
            h.rpc
                .error(
                    "ClearEnvironmentAccessProfile",
                    Auth::Alice,
                    json!({"expectedBinding":binding(&profile)}),
                    "not_found",
                )
                .await?;
            h.rpc
                .error(
                    "DeleteAccessProfile",
                    Auth::Alice,
                    json!({"accessProfileId":id(&profile)?,"expectedRevision":"1"}),
                    "failed_precondition",
                )
                .await?;

            let lifecycle = Service::<PgLifecycleStore>::for_pool(h.db.clone());
            lifecycle
                .complete_external_cleanup(ENV, already_destroyed)
                .await?;
            let after = snapshot(&h, ENV).await?;
            ensure!(after["binding"].is_null() && after["backend"].is_null());
            ensure!(after["environment"]["state"] == "destroyed");
            ensure!(after["environment"]["desired_state"] == "destroyed");
            ensure!(!after["environment"]["destroyed_at"].is_null());
            ensure!(!after["environment"]["external_cleanup_completed_at"].is_null());
            ensure!(after["sessions"][0]["end_reason"] == "environment_destroyed");
            ensure!(!after["sessions"][0]["ended_at"].is_null());
            ensure!(snapshot(&h, UNRELATED_ENV).await? == unrelated_before);
            ensure!(credential_snapshot(&h).await? == credential_before);
            let retained = h
                .rpc
                .ok(
                    "GetAccessProfile",
                    Auth::Alice,
                    json!({"accessProfileId":id(&profile)?}),
                )
                .await?;
            ensure!(
                retained["accessProfile"] == profile,
                "cleanup changed the personal profile"
            );

            // The regular worker skips an already-completed terminal replay.
            ensure!(
                !lifecycle
                    .prepare_destroy(&Snapshot {
                        id: ENV.into(),
                        state: "destroyed".into(),
                        desired_state: "destroyed".into(),
                        external_cleanup_complete: true,
                    })
                    .await?
            );
            ensure!(snapshot(&h, ENV).await? == after);
            h.rpc
                .ok(
                    "DeleteAccessProfile",
                    Auth::Alice,
                    json!({"accessProfileId":id(&profile)?,"expectedRevision":"1"}),
                )
                .await?;
            h.rpc
                .error(
                    "GetAccessProfile",
                    Auth::Alice,
                    json!({"accessProfileId":id(&profile)?}),
                    "not_found",
                )
                .await?;
            h.rpc
                .error(
                    "DeleteAccessProfile",
                    Auth::Alice,
                    json!({"accessProfileId":id(&unrelated)?,"expectedRevision":"1"}),
                    "failed_precondition",
                )
                .await?;
            ensure!(snapshot(&h, UNRELATED_ENV).await? == unrelated_before);
            ensure!(credential_snapshot(&h).await? == credential_before);
            Ok(())
        }
        .await;
        h.finish(result).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn failed_cleanup_guards_and_journal_rollback_preserve_binding_atomically() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = bind_profile(&h, "guarded-destroy", ENV).await?;
        seed_runtime(&h, ENV).await?;
        let credential_before = credential_snapshot(&h).await?;

        // A live environment is never a terminal-cleanup target.
        failed_cleanup_preserves(&h).await?;
        sqlx::query(
            "UPDATE environments SET state='destroying',desired_state='destroyed' WHERE id=$1",
        )
        .bind(ENV)
        .execute(&h.db)
        .await?;
        sqlx::query(
            "INSERT INTO organization_mutation_leases \
             (id,organization_id,mutation_class,deadline_at) \
             VALUES ('synthetic-cleanup-lease',$1,'environment_runtime_dispatch', \
                     now()+interval '60 seconds')",
        )
        .bind(ORG)
        .execute(&h.db)
        .await?;
        failed_cleanup_preserves(&h).await?;
        sqlx::query(
            "UPDATE organization_mutation_leases SET state='released',released_at=now(), \
             updated_at=now() WHERE id='synthetic-cleanup-lease'",
        )
        .execute(&h.db)
        .await?;
        sqlx::query(
            "INSERT INTO environment_ports(environment_id,port,label,access,dns_record_id) \
             VALUES ($1,8080,'synthetic-cleanup','creator','synthetic-retained-dns')",
        )
        .bind(ENV)
        .execute(&h.db)
        .await?;
        failed_cleanup_preserves(&h).await?;
        sqlx::query("UPDATE environment_ports SET dns_record_id=NULL WHERE environment_id=$1")
            .bind(ENV)
            .execute(&h.db)
            .await?;
        failed_cleanup_preserves(&h).await?;
        sqlx::query("DELETE FROM environment_ports WHERE environment_id=$1")
            .bind(ENV)
            .execute(&h.db)
            .await?;

        // The journal is written AFTER the target mutation. A forced failure
        // therefore proves rollback restores the binding, backend and sessions
        // alongside the environment checkpoint and its preceding log entry.
        sqlx::query(
            "CREATE FUNCTION public.synthetic_fail_cleanup_journal() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'synthetic cleanup journal rejection'; END; $$",
        )
        .execute(&h.db)
        .await?;
        sqlx::query(
            "CREATE TRIGGER synthetic_fail_cleanup_journal BEFORE INSERT \
             ON public.environment_lifecycle_journal FOR EACH ROW \
             EXECUTE FUNCTION public.synthetic_fail_cleanup_journal()",
        )
        .execute(&h.db)
        .await?;
        let before = snapshot(&h, ENV).await?;
        let lifecycle = Service::<PgLifecycleStore>::for_pool(h.db.clone());
        let error = lifecycle
            .complete_external_cleanup(ENV, false)
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("cleanup ignored the failing journal"))?;
        ensure!(
            format!("{error:#}").contains("synthetic cleanup journal rejection"),
            "fixture did not reach its post-mutation journal barrier"
        );
        ensure!(
            snapshot(&h, ENV).await? == before,
            "journal rollback left a partial cleanup"
        );
        ensure!(credential_snapshot(&h).await? == credential_before);
        h.rpc
            .error(
                "DeleteAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":id(&profile)?,"expectedRevision":"1"}),
                "failed_precondition",
            )
            .await?;

        sqlx::query(
            "DROP TRIGGER synthetic_fail_cleanup_journal ON public.environment_lifecycle_journal",
        )
        .execute(&h.db)
        .await?;
        sqlx::query("DROP FUNCTION public.synthetic_fail_cleanup_journal()")
            .execute(&h.db)
            .await?;
        lifecycle.complete_external_cleanup(ENV, false).await?;
        let after = snapshot(&h, ENV).await?;
        ensure!(after["binding"].is_null() && after["backend"].is_null());
        ensure!(!after["environment"]["external_cleanup_completed_at"].is_null());
        ensure!(credential_snapshot(&h).await? == credential_before);
        Ok(())
    }
    .await;
    h.finish(result).await
}
