//! Admission-helper proof only: no selected-source production endpoint or
//! runtime delivery claim. All state is isolated synthetic PostgreSQL metadata.

#[allow(dead_code)]
#[path = "access_profiles_support/mod.rs"]
mod support;

use anyhow::{Result, ensure};
use codewire_access::{
    AccessProfileId, EnvironmentId, GrantContext, GrantPlacement, OwnerId, builtin_provider_catalog,
};
use codewire_orchestration::api::create::CreateEnvironmentBody;
use codewire_orchestration::api::environment_sources::{
    EnvironmentSourceSelection, EnvironmentSourcesUpdateOutcome as Outcome,
    UpdateEnvironmentSourcesBody, admit_create_sources_in, replace_environment_sources_in,
};
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformProfileError};
use codewire_project::{CredentialBinding, ProjectSpec, SecretBindings, StoragePlacement};
use codewire_server_core::{AppError, auth::AuthUser};
use support::*;

fn alice() -> AuthUser {
    AuthUser {
        user_id: ALICE.into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn update(replacement: EnvironmentSourceSelection) -> UpdateEnvironmentSourcesBody {
    UpdateEnvironmentSourcesBody {
        expected_operation_generation: 7,
        expected: EnvironmentSourceSelection::default(),
        replacement,
        allow_restart: false,
        confirm_personal_credentials: false,
        confirm_personal_secrets: false,
    }
}

async fn project(h: &Harness) -> Result<String> {
    Ok(sqlx::query_scalar(
        "INSERT INTO secret_projects(org_id,name) VALUES ($1,'development') RETURNING id",
    )
    .bind(ORG)
    .fetch_one(&h.db)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn concurrent_source_replacements_have_one_winner_without_incrementing_generation()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        project(&h).await?;
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(ENV)
            .execute(&h.db)
            .await?;
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        let first = update(EnvironmentSourceSelection {
            secrets: SecretBindings {
                organization: true,
                ..Default::default()
            },
            ..Default::default()
        });
        let second = update(EnvironmentSourceSelection {
            secrets: SecretBindings {
                project: "development".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        let publish = async |request: &UpdateEnvironmentSourcesBody| -> Result<_, AppError> {
            let mut tx = profiles
                .begin_transaction()
                .await
                .map_err(|_| AppError::ServiceUnavailable("synthetic transaction failed".into()))?;
            let result =
                replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, request)
                    .await;
            match result {
                Ok(result) => {
                    tx.commit().await?;
                    Ok(result)
                }
                Err(error) => {
                    tx.rollback().await?;
                    Err(error)
                }
            }
        };
        let (first, second) = tokio::join!(publish(&first), publish(&second));
        let winner = match (first, second) {
            (Ok(winner), Err(AppError::Conflict(_))) | (Err(AppError::Conflict(_)), Ok(winner)) => {
                winner
            }
            _ => anyhow::bail!("source CAS did not have exactly one winner"),
        };
        ensure!(winner.outcome == Outcome::Stored && winner.operation_generation == 7);
        let generation: i64 = sqlx::query_scalar(
            "SELECT environment_operation_generation FROM environments WHERE id=$1",
        )
        .bind(ENV)
        .fetch_one(&h.db)
        .await?;
        ensure!(generation == 7);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn pending_create_publishes_canonical_sources_profile_and_creator_acl_atomically()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("create-sources", CREDENTIAL).await?;
        let profile_id = id(&profile)?;
        let project_id = project(&h).await?;
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        sqlx::query("UPDATE environments SET state='pending',environment_operation_generation=0 WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        let body = CreateEnvironmentBody {
            project_spec: ProjectSpec {
                secrets: SecretBindings { project: "platform:development".into(), organization: true, user: Some(StoragePlacement::Platform) },
                credentials: Some(CredentialBinding { profile: "platform:user/create-sources".into() }),
                ..Default::default()
            },
            expected_profile_revision: Some(1),
            confirm_personal_credentials: true,
            confirm_personal_secrets: true,
            ..Default::default()
        };
        for (confirm_secrets, confirm_credentials, revision) in [(false,true,1), (true,false,1), (true,true,2)] {
            let mut invalid = body.clone();
            invalid.confirm_personal_secrets = confirm_secrets;
            invalid.confirm_personal_credentials = confirm_credentials;
            invalid.expected_profile_revision = Some(revision);
            let mut tx = profiles.begin_transaction().await?;
            ensure!(admit_create_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &mut invalid).await.is_err());
            tx.rollback().await?;
        }
        let mut tx = profiles.begin_transaction().await?;
        let mut selected = body.clone();
        admit_create_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &mut selected).await?;
        ensure!(selected.project_spec.secrets.project == format!("platform:id:{project_id}"));
        ensure!(selected.project_spec.credentials.as_ref().unwrap().profile == format!("platform:id:{profile_id}"));
        tx.rollback().await?;
        let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM platform_environment_access_bindings), (SELECT count(*) FROM environment_access)")
            .fetch_one(&h.db).await?;
        ensure!(counts == (0,0));

        // Failure at the final ACL INSERT must undo the earlier source and
        // binding writes too. A duplicate is a real SQL error, not a mocked path.
        sqlx::query("INSERT INTO environment_access(environment_id,user_id,permission,granted_by) VALUES ($1,$2,'owner',$2)")
            .bind(ENV).bind(ALICE).execute(&h.db).await?;
        let mut tx = profiles.begin_transaction().await?;
        let mut selected = body.clone();
        ensure!(admit_create_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &mut selected).await.is_err());
        tx.rollback().await?;
        let stored: serde_json::Value = sqlx::query_scalar("SELECT project_spec FROM environments WHERE id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(stored.get("secrets").is_none() && stored.get("credentials").is_none());
        let bindings: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings").fetch_one(&h.db).await?;
        ensure!(bindings == 0);
        sqlx::query("DELETE FROM environment_access WHERE environment_id=$1 AND user_id=$2")
            .bind(ENV).bind(ALICE).execute(&h.db).await?;

        let mut tx = profiles.begin_transaction().await?;
        let mut selected = body;
        admit_create_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &mut selected).await?;
        tx.commit().await?;
        let actual: (String, i64, String) = sqlx::query_as("SELECT profile_id,profile_revision,personal_owner_confirmed_by FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(actual == (profile_id.into(),1,ALICE.into()));
        let state: (String, i64) = sqlx::query_as("SELECT state,environment_operation_generation FROM environments WHERE id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(state == ("pending".into(),0));
        let context = GrantContext {
            environment_id: EnvironmentId::parse(ENV)?, environment_generation: 0,
            placement: GrantPlacement::Platform, user_id: OwnerId::parse(ALICE)?,
            organization_id: Some(OwnerId::parse(ORG)?), allow_personal_credentials: true,
            authorized_credentials: Default::default(),
        };
        ensure!(profiles.evaluate_grants(&context).await == Err(PlatformProfileError::InvalidInput));
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn empty_profile_selection_commits_an_exact_revision_for_runtime_capture() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h
            .rpc
            .ok(
                "CreateAccessProfile",
                Auth::Alice,
                serde_json::json!({"name":"empty-runtime-profile","entries":[]}),
            )
            .await?["accessProfile"]
            .clone();
        let profile_id = id(&profile)?;
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(ENV)
            .execute(&h.db)
            .await?;
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        let mut request = update(EnvironmentSourceSelection {
            credentials: Some(CredentialBinding {
                profile: format!("platform:id:{profile_id}"),
            }),
            profile_revision: Some(1),
            ..Default::default()
        });
        request.confirm_personal_credentials = true;
        let mut tx = profiles.begin_transaction().await?;
        let selected =
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await?;
        tx.commit().await?;
        ensure!(selected.outcome == Outcome::Stored);
        ensure!(selected.selection.profile_revision == Some(1));
        let stored: (String, i64) = sqlx::query_as(
            "SELECT profile_id,profile_revision FROM platform_environment_access_bindings WHERE environment_id=$1",
        )
        .bind(ENV)
        .fetch_one(&h.db)
        .await?;
        ensure!(stored == (profile_id.to_owned(), 1));
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn source_replacement_cas_is_exact_stopped_noop_and_running_restart_are_distinct()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let project_id = project(&h).await?;
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        let mut request = update(EnvironmentSourceSelection {
            secrets: SecretBindings { project: "development".into(), organization: true, user: None },
            ..Default::default()
        });
        let mut tx = profiles.begin_transaction().await?;
        ensure!(matches!(replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await, Err(AppError::Precondition(_))));
        tx.rollback().await?;
        request.allow_restart = true;
        sqlx::query("INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name,pod_name,setup_complete) VALUES ($1,'synthetic-sandboxes',$1,$1,true)")
            .bind(ENV).execute(&h.db).await?;
        let mut tx = profiles.begin_transaction().await?;
        let restarting = replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await?;
        ensure!(restarting.outcome == Outcome::RestartRequired && restarting.operation_generation == 7);
        let state: (String, String, i64) = sqlx::query_as("SELECT state,desired_state,environment_operation_generation FROM environments WHERE id=$1")
            .bind(ENV).fetch_one(&mut *tx).await?;
        ensure!(state == ("stopping".into(),"started".into(),7));
        // This helper proof does not install workflow recovery; consequently it
        // must not publish the running restart intent by itself.
        tx.rollback().await?;
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        let mut tx = profiles.begin_transaction().await?;
        let stored = replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await?;
        ensure!(stored.outcome == Outcome::Stored && stored.operation_generation == 7);
        ensure!(stored.selection.secrets.project == format!("platform:id:{project_id}"));
        tx.commit().await?;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(matches!(replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await, Err(AppError::Conflict(_))));
        tx.rollback().await?;
        request.expected = stored.selection.clone();
        request.replacement = stored.selection.clone();
        let mut tx = profiles.begin_transaction().await?;
        let unchanged = replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await?;
        ensure!(unchanged.outcome == Outcome::Unchanged);
        tx.commit().await?;
        request.expected_operation_generation = 8;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(matches!(replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await, Err(AppError::Conflict(_))));
        tx.rollback().await?;
        request.expected_operation_generation = 7;
        request.replacement = EnvironmentSourceSelection::default();
        let mut tx = profiles.begin_transaction().await?;
        let cleared = replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await?;
        ensure!(cleared.outcome == Outcome::Stored && cleared.selection == EnvironmentSourceSelection::default());
        tx.commit().await?;
        let state: (String, String, i64) = sqlx::query_as("SELECT state,desired_state,environment_operation_generation FROM environments WHERE id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(state == ("stopped".into(),"stopped".into(),7));
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn running_source_edits_require_completed_unowned_setup_and_preserve_failed_admission()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        let mut request = update(EnvironmentSourceSelection {
            secrets: SecretBindings { organization: true, ..Default::default() },
            ..Default::default()
        });
        request.allow_restart = true;
        let baseline: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(e) FROM environments e WHERE id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        let reject = async || -> Result<()> {
            let mut tx = profiles.begin_transaction().await?;
            ensure!(matches!(replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await,
                Err(AppError::Precondition(_))));
            tx.rollback().await?;
            let actual: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(e) FROM environments e WHERE id=$1")
                .bind(ENV).fetch_one(&h.db).await?;
            ensure!(actual == baseline, "rejected source edit changed environment authority");
            Ok(())
        };
        reject().await?; // missing backend is not completed setup
        sqlx::query("INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name,pod_name) VALUES ($1,'synthetic-sandboxes',$1,$1)")
            .bind(ENV).execute(&h.db).await?;
        reject().await?; // initial setup in progress
        sqlx::query("UPDATE sandbox_environment_backend SET setup_complete=true WHERE environment_id=$1")
            .bind(ENV).execute(&h.db).await?;
        // The schema accepts only complete ownership records. Each live status,
        // including cleanup/reaping, must block without stealing ownership.
        for (status, uid) in [("claimed", None), ("running", Some("synthetic-old-pod")), ("reaping", Some("synthetic-old-pod"))] {
            sqlx::query("UPDATE sandbox_environment_backend SET setup_owner_generation=7,setup_owner_activity_id='synthetic-setup',setup_owner_attempt=1,setup_owner_phase=1,setup_owner_status=$2,setup_owner_pod_uid=$3 WHERE environment_id=$1")
                .bind(ENV).bind(status).bind(uid).execute(&h.db).await?;
            let before: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(b) FROM sandbox_environment_backend b WHERE environment_id=$1")
                .bind(ENV).fetch_one(&h.db).await?;
            reject().await?;
            let after: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(b) FROM sandbox_environment_backend b WHERE environment_id=$1")
                .bind(ENV).fetch_one(&h.db).await?;
            ensure!(before == after, "rejected source edit stole setup ownership");
        }
        sqlx::query("UPDATE sandbox_environment_backend SET setup_owner_generation=NULL,setup_owner_activity_id=NULL,setup_owner_attempt=NULL,setup_owner_phase=NULL,setup_owner_status=NULL,setup_owner_pod_uid=NULL WHERE environment_id=$1")
            .bind(ENV).execute(&h.db).await?;
        let mut tx = profiles.begin_transaction().await?;
        let accepted = replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request).await?;
        ensure!(accepted.outcome == Outcome::RestartRequired);
        let actual: (bool,i32,i64) = sqlx::query_as("SELECT b.setup_complete,b.setup_phase,e.environment_operation_generation FROM environments e JOIN sandbox_environment_backend b ON b.environment_id=e.id WHERE e.id=$1")
            .bind(ENV).fetch_one(&mut *tx).await?;
        ensure!(actual == (true,0,7));
        tx.rollback().await?; // helper-only fixture cannot dispatch a real restart
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn source_replacement_revalidates_owner_membership_credential_and_pinned_revision()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("edit-sources", CREDENTIAL).await?;
        let profile_id = id(&profile)?;
        let profiles = PlatformAccessProfileStore::new(h.db.clone(), builtin_provider_catalog());
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(ENV)
            .execute(&h.db)
            .await?;
        let mut request = update(EnvironmentSourceSelection {
            credentials: Some(CredentialBinding {
                profile: format!("platform:id:{profile_id}"),
            }),
            profile_revision: Some(1),
            ..Default::default()
        });
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await
                .is_err()
        );
        tx.rollback().await?;
        request.confirm_personal_credentials = true;
        let mut tx = profiles.begin_transaction().await?;
        let selected =
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await?;
        tx.commit().await?;
        let owner = codewire_access::Owner::User(OwnerId::parse(ALICE)?);
        profiles
            .update(
                &owner,
                &AccessProfileId::parse(profile_id)?,
                1,
                Default::default(),
            )
            .await?;
        request.expected = selected.selection.clone();
        request.replacement.secrets.organization = true;
        let mut tx = profiles.begin_transaction().await?;
        let updated =
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await?;
        ensure!(
            updated.selection.profile_revision == Some(1),
            "application edit silently advanced pinned profile"
        );
        tx.commit().await?;
        request.expected = updated.selection;
        request.replacement.secrets.organization = false;
        sqlx::query("UPDATE platform_credentials SET status='revoked' WHERE id=$1")
            .bind(CREDENTIAL)
            .execute(&h.db)
            .await?;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await
                .is_err()
        );
        tx.rollback().await?;
        // Revocation does not prevent explicitly clearing the old reference.
        request.replacement = EnvironmentSourceSelection::default();
        let mut bob = alice();
        bob.user_id = BOB.into();
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            replace_environment_sources_in(&mut tx, &profiles, &bob, ORG, ENV, &request)
                .await
                .is_err()
        );
        tx.rollback().await?;
        sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
            .bind(ALICE)
            .bind(ORG)
            .execute(&h.db)
            .await?;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await
                .is_err()
        );
        tx.rollback().await?;
        h.member().await?;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            replace_environment_sources_in(&mut tx, &profiles, &alice(), ORG, ENV, &request)
                .await?
                .outcome
                == Outcome::Stored
        );
        tx.commit().await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}
