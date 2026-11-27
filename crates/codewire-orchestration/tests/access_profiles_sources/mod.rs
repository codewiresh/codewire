//! Binding authorization now belongs to complete source admission, not a
//! competing public binding-only RPC. These are explicit helper/SQL proofs;
//! public profile CRUD and authentication remain in access_profiles.rs.

use anyhow::{Context, Result, ensure};
use codewire_server_core::AppError;
use serde_json::json;

use super::support::*;

async fn stopped(h: &Harness) -> Result<()> {
    sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
        .bind(ENV)
        .execute(&h.db)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn source_binding_requires_exact_consent_creator_member_and_active_generation() -> Result<()>
{
    let h = Harness::create().await?;
    let result = async {
        stopped(&h).await?;
        let alice = source_actor(ALICE);
        let profile = h.rpc.create("binding", CREDENTIAL).await?;
        let first = source_binding(&profile);
        let mut request = source_replacement(Default::default(), first.clone());
        request.confirm_personal_credentials = false;
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Precondition(_))));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
            .fetch_one(&h.db).await?;
        ensure!(count == 0);
        request.confirm_personal_credentials = true;
        let mut machine = alice.clone();
        machine.via_api_key = true;
        machine.org_id = Some(ORG.into());
        ensure!(admit_sources(&h.db, &machine, ENV, &request).await.unwrap_err().is_forbidden());

        // Explicit owner ACL and global administrator status still cannot
        // borrow the immutable creator's personal identity or same-name profile.
        sqlx::query("INSERT INTO environment_access(environment_id,user_id,permission,granted_by) VALUES ($1,$2,'owner',$3)")
            .bind(ENV).bind(BOB).bind(ALICE).execute(&h.db).await?;
        let bob = h.rpc.ok("CreateAccessProfile", Auth::Bob,
            json!({"name":"bob-binding","entries":entries(OTHER_CREDENTIAL)})).await?;
        let foreign = source_replacement(Default::default(), source_binding(&bob["accessProfile"]));
        for (actor, body) in [(source_actor(BOB), &foreign), (alice.clone(), &foreign)] {
            ensure!(matches!(admit_sources(&h.db, &actor, ENV, body).await, Err(AppError::NotFound(_))));
        }
        admit_sources(&h.db, &alice, ENV, &request).await?;
        let confirmed: Option<String> = sqlx::query_scalar("SELECT personal_owner_confirmed_by FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(confirmed.as_deref() == Some(ALICE));
        let metadata = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Cookie, json!({"environmentId":ENV})).await?;
        ensure!(metadata["binding"] == binding(&profile) && metadata["personalCredentialsConfirmed"] == true);
        h.rpc.error("GetEnvironmentAccessProfile", Auth::Bob, json!({"environmentId":ENV}), "not_found").await?;
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Conflict(_))));

        let updated = h.rpc.ok("UpdateAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":[]})).await?;
        let second = source_binding(&updated["accessProfile"]);
        let metadata = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Alice, json!({"environmentId":ENV})).await?;
        ensure!(metadata["binding"] == binding(&profile), "profile edit silently rebound environment");
        h.rpc.error("DeleteAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"2"}), "failed_precondition").await?;
        request = source_replacement(first.clone(), second.clone());
        request.confirm_personal_credentials = false;
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Precondition(_))));
        request.confirm_personal_credentials = true;
        request.expected = second.clone();
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Conflict(_))));
        request.expected = first.clone();
        admit_sources(&h.db, &alice, ENV, &request).await?;
        let mut clear = source_replacement(first.clone(), Default::default());
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &clear).await, Err(AppError::Conflict(_))));
        clear.expected = second.clone();
        ensure!(matches!(admit_sources(&h.db, &source_actor(BOB), ENV, &clear).await, Err(AppError::NotFound(_))));
        admit_sources(&h.db, &alice, ENV, &clear).await?;
        h.rpc.error("GetEnvironmentAccessProfile", Auth::Alice, json!({"environmentId":ENV}), "not_found").await?;

        // A newly selected stale revision now fails; only an already-pinned
        // revision may survive an application-only edit. No legacy fallback.
        request = source_replacement(Default::default(), first);
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Conflict(_))));
        request.replacement = second.clone();
        admit_sources(&h.db, &alice, ENV, &request).await?;
        sqlx::query("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=NULL WHERE environment_id=$1")
            .bind(ENV).execute(&h.db).await?;
        let metadata = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Alice, json!({"environmentId":ENV})).await?;
        ensure!(!metadata["personalCredentialsConfirmed"].as_bool().unwrap_or(false));
        // Inspecting or clearing cannot synthesize fresh personal confirmation.
        clear.confirm_personal_credentials = false;
        admit_sources(&h.db, &alice, ENV, &clear).await?;

        sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
            .bind(ALICE).bind(ORG).execute(&h.db).await?;
        ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::NotFound(_))));
        h.member().await?;
        for generation in [0, 8] {
            sqlx::query("UPDATE environments SET environment_operation_generation=$2 WHERE id=$1")
                .bind(ENV).bind(generation).execute(&h.db).await?;
            ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::Conflict(_))));
        }
        sqlx::query("UPDATE environments SET environment_operation_generation=7 WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        for (state, desired, deletion) in [("destroying", "started", false), ("running", "destroyed", false), ("running", "started", true)] {
            sqlx::query("UPDATE environments SET state=$2,desired_state=$3,deletion_requested_at=CASE WHEN $4 THEN now() ELSE NULL END WHERE id=$1")
                .bind(ENV).bind(state).bind(desired).bind(deletion).execute(&h.db).await?;
            ensure!(matches!(admit_sources(&h.db, &alice, ENV, &request).await, Err(AppError::NotFound(_))));
        }
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped',deletion_requested_at=NULL WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        admit_sources(&h.db, &alice, ENV, &request).await?;
        sqlx::query("UPDATE organizations SET deletion_state='deleting',deletion_generation=1,deletion_requested_by=$2,deletion_requested_at=now(),deletion_operation_id='synthetic-delete',deletion_workflow_id='synthetic-delete',deletion_phase='write_fenced' WHERE id=$1")
            .bind(ORG).bind(ALICE).execute(&h.db).await?;
        h.rpc.error("GetEnvironmentAccessProfile", Auth::Alice, json!({"environmentId":ENV}), "not_found").await?;
        for body in [source_replacement(second.clone(), second), clear] {
            ensure!(matches!(admit_sources(&h.db, &alice, ENV, &body).await, Err(AppError::NotFound(_))));
        }
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn source_binding_membership_and_exact_cas_are_one_transaction() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        stopped(&h).await?;
        let role: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&h.db).await?;
        let profile = h.rpc.create("races", CREDENTIAL).await?;
        let selection = source_binding(&profile);
        let request = source_replacement(Default::default(), selection.clone());

        let mut removal = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *removal).await?;
        sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
            .bind(ALICE).bind(ORG).execute(&mut *removal).await?;
        let pool = h.db.clone();
        let body = request.clone();
        let pending = spawn(async move { Ok(admit_sources(&pool, &source_actor(ALICE), ENV, &body).await) });
        let barrier = blocked_service(&h.db, &role, holder, 1).await;
        removal.commit().await?;
        let response = joined(pending).await?;
        barrier?;
        ensure!(matches!(response, Err(AppError::NotFound(_))));
        h.member().await?;

        let mut credential = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *credential).await?;
        sqlx::query("SELECT id FROM platform_credentials WHERE id=$1 FOR UPDATE")
            .bind(CREDENTIAL).fetch_one(&mut *credential).await?;
        let pool = h.db.clone();
        let body = request.clone();
        let pending = spawn(async move { Ok(admit_sources(&pool, &source_actor(ALICE), ENV, &body).await) });
        let waiting = blocked_service(&h.db, &role, holder, 1).await?;
        let writer = *waiting.first().context("missing source writer")?;
        let mut removal = h.db.begin().await?;
        let remover: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *removal).await?;
        let remove = spawn(async move {
            sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
                .bind(ALICE).bind(ORG).execute(&mut *removal).await?;
            removal.commit().await?;
            Ok(())
        });
        let barrier = blocked_pid(&h.db, remover, writer).await;
        credential.commit().await?;
        let response = joined(pending).await?;
        let removed = joined(remove).await;
        barrier?;
        removed?;
        response?;
        let confirmed: Option<String> = sqlx::query_scalar("SELECT personal_owner_confirmed_by FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(confirmed.as_deref() == Some(ALICE));
        h.rpc.error("GetEnvironmentAccessProfile", Auth::Alice, json!({"environmentId":ENV}), "not_found").await?;
        h.member().await?;
        admit_sources(&h.db, &source_actor(ALICE), ENV, &source_replacement(selection, Default::default())).await?;

        let mut environment = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *environment).await?;
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE").bind(ENV).fetch_one(&mut *environment).await?;
        let mut pending = Vec::new();
        for _ in 0..2 {
            let pool = h.db.clone();
            let body = request.clone();
            pending.push(spawn(async move { Ok(admit_sources(&pool, &source_actor(ALICE), ENV, &body).await) }));
        }
        let barrier = blocked_service(&h.db, &role, holder, 2).await;
        environment.commit().await?;
        let mut responses = Vec::new();
        for task in pending { responses.push(joined(task).await?); }
        barrier?;
        ensure!(responses.iter().filter(|result| result.is_ok()).count() == 1);
        ensure!(responses.iter().filter(|result| matches!(result, Err(AppError::Conflict(_)))).count() == 1);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings").fetch_one(&h.db).await?;
        ensure!(count == 1);
        Ok(())
    }.await;
    h.finish(result).await
}
