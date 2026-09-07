//! Public generated Connect contract over an actual synthetic restricted login.
//! Each ignored case owns and removes one exact disposable PostgreSQL database.

#[path = "access_profiles_support/mod.rs"]
mod support;

#[path = "access_profiles_timeout/mod.rs"]
mod timeout;

#[path = "access_profiles_destroy/mod.rs"]
mod destroy;

use anyhow::{Context, Result, ensure};
use reqwest::StatusCode;
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_profiles_auth_owner_pagination_and_immutable_revision_cas() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        for auth in [Auth::Missing, Auth::Expired] {
            h.rpc.error("ListAccessProfiles", auth, json!({}), "unauthenticated").await?;
        }
        // Real API-key authentication succeeds but the account policy rejects
        // every operation, even though this fixture's owning user is an admin.
        for method in ["ListAccessProfiles", "GetAccessProfile", "CreateAccessProfile",
            "UpdateAccessProfile", "DeleteAccessProfile", "GetEnvironmentAccessProfile",
            "SetEnvironmentAccessProfile", "ClearEnvironmentAccessProfile"] {
            h.rpc.error(method, Auth::ApiKey, json!({}), "permission_denied").await?;
        }
        let cookie = h.rpc.ok("CreateAccessProfile", Auth::Cookie,
            json!({"name":"cookie-owned","entries":[]})).await?;
        let profile = h.rpc.create("work", CREDENTIAL).await?;
        let third = h.rpc.create("another", CREDENTIAL).await?;
        h.rpc.error("CreateAccessProfile", Auth::Alice,
            json!({"name":"work","entries":[]}), "already_exists").await?;
        h.rpc.error("CreateAccessProfile", Auth::Alice,
            json!({"name":"WORK","entries":[]}), "invalid_argument").await?;
        h.rpc.error("CreateAccessProfile", Auth::Alice,
            json!({"name":"duplicates","entries":[
                {"capabilitySlot":"codex","credentialId":CREDENTIAL},
                {"capabilitySlot":"codex","credentialId":OTHER_CREDENTIAL}]}), "invalid_argument").await?;
        h.rpc.error("CreateAccessProfile", Auth::Alice,
            json!({"name":"wrong-owner","entries":entries(OTHER_CREDENTIAL)}), "not_found").await?;
        h.rpc.error("CreateAccessProfile", Auth::Alice,
            json!({"name":"unsupported","entries":[{"capabilitySlot":"unknown","credentialId":CREDENTIAL}]}),
            "failed_precondition").await?;
        let bob = h.rpc.ok("CreateAccessProfile", Auth::Bob,
            json!({"name":"work","entries":entries(OTHER_CREDENTIAL)})).await?;
        let bob_id = id(&bob["accessProfile"])?;
        h.rpc.error("GetAccessProfile", Auth::Bob,
            json!({"accessProfileId":id(&profile)?}), "not_found").await?;
        h.rpc.error("UpdateAccessProfile", Auth::Bob,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":[]}), "not_found").await?;
        h.rpc.error("DeleteAccessProfile", Auth::Bob,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1"}), "not_found").await?;

        let mut seen = Vec::new();
        let mut token = String::new();
        for index in 0..3 {
            let page = h.rpc.ok("ListAccessProfiles", Auth::Alice,
                json!({"pageSize":1,"pageToken":token})).await?;
            let profiles = page["accessProfiles"].as_array().context("missing profile page")?;
            ensure!(profiles.len() == 1);
            seen.push(id(&profiles[0])?.to_owned());
            token = page["nextPageToken"].as_str().unwrap_or_default().to_owned();
            ensure!(token.is_empty() == (index == 2), "page cursor did not terminate exactly");
        }
        let mut expected = vec![id(&cookie["accessProfile"] )?.to_owned(), id(&profile)?.to_owned(), id(&third)?.to_owned()];
        expected.sort();
        ensure!(seen == expected && !seen.iter().any(|value| value == bob_id));
        for request in [json!({"pageSize":-1}), json!({"pageSize":101}), json!({"pageToken":"not a cursor"})] {
            h.rpc.error("ListAccessProfiles", Auth::Alice, request, "invalid_argument").await?;
        }

        let updated = h.rpc.ok("UpdateAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":[]})).await?;
        ensure!(updated["accessProfile"]["revision"] == "2");
        let historical = h.rpc.ok("GetAccessProfile", Auth::Cookie,
            json!({"accessProfileId":id(&profile)?,"revision":"1"})).await?;
        ensure!(historical["accessProfile"] == profile, "historical revision was rewritten");
        h.rpc.error("GetAccessProfile", Auth::Alice, json!({"name":"WORK"}), "invalid_argument").await?;
        let current = h.rpc.ok("GetAccessProfile", Auth::Alice, json!({"name":"work"})).await?;
        ensure!(current == updated);
        for revision in ["0", "18446744073709551615"] {
            h.rpc.error("GetAccessProfile", Auth::Alice,
                json!({"accessProfileId":id(&profile)?,"revision":revision}), "invalid_argument").await?;
        }
        h.rpc.error("GetAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"revision":"3"}), "not_found").await?;
        h.rpc.error("UpdateAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":entries(CREDENTIAL)}), "already_exists").await?;
        h.rpc.error("DeleteAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1"}), "already_exists").await?;
        h.rpc.ok("DeleteAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"2"})).await?;
        h.rpc.error("GetAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"revision":"1"}), "not_found").await?;

        // Both account transports observe deletion on the next request.
        sqlx::query("DELETE FROM oidc_access_tokens WHERE user_id=$1").bind(ALICE).execute(&h.db).await?;
        h.rpc.error("ListAccessProfiles", Auth::Alice, json!({}), "unauthenticated").await?;
        h.rpc.ok("ListAccessProfiles", Auth::Cookie, json!({})).await?;
        sqlx::query("DELETE FROM sessions WHERE id='profile-session'").execute(&h.db).await?;
        h.rpc.error("ListAccessProfiles", Auth::Cookie, json!({}), "unauthenticated").await?;
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_binding_requires_exact_consent_creator_member_and_active_generation() -> Result<()>
{
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("binding", CREDENTIAL).await?;
        let first = binding(&profile);
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, None, false), "failed_precondition").await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
            .fetch_one(&h.db).await?;
        ensure!(count == 0, "missing consent persisted a binding");

        // Having an explicit owner ACL and current membership is still not the
        // environment's authenticated creator. Global admin is no shortcut.
        sqlx::query("INSERT INTO environment_access(environment_id,user_id,permission,granted_by) \
            VALUES ($1,$2,'owner',$3)").bind(ENV).bind(BOB).bind(ALICE).execute(&h.db).await?;
        let bob = h.rpc.ok("CreateAccessProfile", Auth::Bob,
            json!({"name":"bob-binding","entries":entries(OTHER_CREDENTIAL)})).await?;
        let bob_binding = binding(&bob["accessProfile"]);
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Bob,
            set(&bob_binding, None, true), "not_found").await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&bob_binding, None, true), "not_found").await?;
        h.rpc.ok("SetEnvironmentAccessProfile", Auth::Alice, set(&first, None, true)).await?;
        let confirmed: Option<String> = sqlx::query_scalar("SELECT personal_owner_confirmed_by \
            FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(ENV).fetch_one(&h.db).await?;
        ensure!(confirmed.as_deref() == Some(ALICE));
        let metadata = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Cookie,
            json!({"environmentId":ENV})).await?;
        ensure!(metadata["binding"] == first && metadata["personalCredentialsConfirmed"] == true);
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, None, true), "already_exists").await?;

        let update = h.rpc.ok("UpdateAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":[]})).await?;
        let second = binding(&update["accessProfile"]);
        let pinned = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Alice,
            json!({"environmentId":ENV})).await?;
        ensure!(pinned["binding"] == first, "profile edit silently rebound environment");
        h.rpc.error("DeleteAccessProfile", Auth::Alice,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"2"}), "failed_precondition").await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&second, Some(&first), false), "failed_precondition").await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&second, Some(&second), true), "already_exists").await?;
        h.rpc.ok("SetEnvironmentAccessProfile", Auth::Alice,
            set(&second, Some(&first), true)).await?;
        h.rpc.error("ClearEnvironmentAccessProfile", Auth::Alice,
            json!({"expectedBinding":first}), "already_exists").await?;
        h.rpc.error("ClearEnvironmentAccessProfile", Auth::Bob,
            json!({"expectedBinding":second}), "not_found").await?;
        h.rpc.ok("ClearEnvironmentAccessProfile", Auth::Alice,
            json!({"expectedBinding":second})).await?;
        h.rpc.error("GetEnvironmentAccessProfile", Auth::Alice,
            json!({"environmentId":ENV}), "not_found").await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, None, false), "failed_precondition").await?;

        // Current metadata without confirmation remains inspectable/clearable,
        // but membership/enrollment cannot synthesize consent on a replacement.
        sqlx::query("INSERT INTO platform_environment_access_bindings(environment_id,profile_id,profile_revision) VALUES ($1,$2,1)")
            .bind(ENV).bind(id(&profile)?).execute(&h.db).await?;
        let missing = h.rpc.ok("GetEnvironmentAccessProfile", Auth::Alice,
            json!({"environmentId":ENV})).await?;
        ensure!(missing["binding"] == first);
        ensure!(!missing["personalCredentialsConfirmed"].as_bool().unwrap_or(false));
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, Some(&first), false), "failed_precondition").await?;
        h.rpc.ok("ClearEnvironmentAccessProfile", Auth::Cookie,
            json!({"expectedBinding":first})).await?;

        sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
            .bind(ALICE).bind(ORG).execute(&h.db).await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, None, true), "not_found").await?;
        h.member().await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=0 WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
            set(&first, None, true), "failed_precondition").await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=8 WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        for (state, desired, deletion) in [("destroying", "started", false),
            ("running", "destroyed", false), ("running", "started", true)] {
            sqlx::query("UPDATE environments SET state=$2,desired_state=$3, \
                deletion_requested_at=CASE WHEN $4 THEN now() ELSE NULL END WHERE id=$1")
                .bind(ENV).bind(state).bind(desired).bind(deletion).execute(&h.db).await?;
            h.rpc.error("SetEnvironmentAccessProfile", Auth::Alice,
                set(&first, None, true), "not_found").await?;
        }
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped',deletion_requested_at=NULL WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        h.rpc.ok("SetEnvironmentAccessProfile", Auth::Alice, set(&first, None, true)).await?;
        // Active-owner state is checked for metadata inspection and writes,
        // not only when a broker later attempts to consume a grant.
        sqlx::query("UPDATE organizations SET deletion_state='deleting',deletion_generation=1, \
            deletion_requested_by=$2,deletion_requested_at=now(),deletion_operation_id='synthetic-delete', \
            deletion_workflow_id='synthetic-delete',deletion_phase='write_fenced' WHERE id=$1")
            .bind(ORG).bind(ALICE).execute(&h.db).await?;
        for (method, body) in [("GetEnvironmentAccessProfile", json!({"environmentId":ENV})),
            ("SetEnvironmentAccessProfile", set(&first, Some(&first), true)),
            ("ClearEnvironmentAccessProfile", json!({"expectedBinding":first}))] {
            h.rpc.error(method, Auth::Alice, body, "not_found").await?;
        }
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_profile_login_cannot_read_material_or_mutate_lifecycle_authority() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let login: (String, String) = sqlx::query_as("SELECT current_user::text,session_user::text")
            .fetch_one(&h.service_pool).await?;
        ensure!(login == (h.role.clone(), h.role.clone()));
        let owner: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&h.db).await?;
        ensure!(owner != h.role);
        denied(&h.service_pool, &format!("SET ROLE {}", quote(&owner))).await?;
        sqlx::query("RESET ROLE").execute(&h.service_pool).await?;
        for sql in [
            "SELECT * FROM public.platform_credential_material LIMIT 0",
            "SELECT * FROM public.platform_credential_refresh_material LIMIT 0",
            "SELECT * FROM public.platform_credential_refresh_attempts LIMIT 0",
            "SELECT * FROM public.tenant_secrets LIMIT 0",
            "SELECT * FROM public.tenant_secret_deks LIMIT 0",
            "SELECT * FROM public.tenant_secret_kek_canary LIMIT 0",
            "SELECT * FROM public.confidential_storage_keys LIMIT 0",
            "SELECT * FROM public.oidc_refresh_tokens LIMIT 0",
            "SELECT * FROM public.jwks LIMIT 0",
            "SELECT secret FROM public.oidc_clients LIMIT 0",
            "SELECT email FROM public.users LIMIT 0",
            "UPDATE public.platform_credentials SET status='active' WHERE false",
            "DELETE FROM public.platform_credentials WHERE false",
            "UPDATE public.environments SET environment_operation_generation=99 WHERE false",
            "UPDATE public.environments SET created_by='other' WHERE false",
            "UPDATE public.environments SET desired_state='started' WHERE false",
            "UPDATE public.org_members SET user_id='other' WHERE false",
            "DELETE FROM public.org_members WHERE false",
            "UPDATE public.organizations SET deletion_state='active' WHERE false",
            "UPDATE public.users SET is_admin=true WHERE false",
            "ALTER FUNCTION public.codewire_platform_lock_credential(text,text,text) SECURITY INVOKER",
        ] { denied(&h.service_pool, sql).await?; }
        let has_credential_update: bool = sqlx::query_scalar("SELECT pg_catalog.has_any_column_privilege(current_user, \
            'public.platform_credentials','UPDATE')").fetch_one(&h.service_pool).await?;
        ensure!(!has_credential_update, "profile admission gained credential lifecycle locks");
        let p = h.rpc.create("least-authority", CREDENTIAL).await?;
        h.rpc.ok("SetEnvironmentAccessProfile", Auth::Alice, set(&binding(&p), None, true)).await?;
        // This actual mount contains only the generated material-free service,
        // never a generic secret read, KEK route or credential enrollment hop.
        for path in ["/codewire.v1.AccessProfileService/ReadCredentialMaterial",
            "/codewire.v1.AccessProfileService/UnwrapDek", "/v1/transit/decrypt/credential"] {
            h.rpc.absent_route(path).await?;
        }
        let material: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_credential_material")
            .fetch_one(&h.db).await?;
        ensure!(material == 0, "metadata-only fixture unexpectedly manufactured material");
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_binding_membership_and_exact_cas_are_one_transaction() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("races", CREDENTIAL).await?;
        let selection = binding(&profile);

        // Removal wins first: admission blocks on that exact membership row,
        // then rechecks the committed absence and publishes nothing.
        let mut removal = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *removal)
            .await?;
        sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
            .bind(ALICE)
            .bind(ORG)
            .execute(&mut *removal)
            .await?;
        let rpc = h.rpc.clone();
        let body = set(&selection, None, true);
        let request = spawn(async move {
            rpc.call("SetEnvironmentAccessProfile", Auth::Alice, body)
                .await
        });
        let barrier = blocked_service(&h.db, &h.role, holder, 1).await;
        removal.commit().await?;
        let response = joined(request).await?;
        barrier?;
        ensure!(response.1["code"] == "not_found");
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
                .fetch_one(&h.db)
                .await?;
        ensure!(count == 0);
        h.member().await?;

        // Admission wins first: pause on credential metadata after membership
        // SHARE is held. Removal must remain blocked until binding COMMIT.
        let mut material_fence = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *material_fence)
            .await?;
        sqlx::query("SELECT id FROM platform_credentials WHERE id=$1 FOR UPDATE")
            .bind(CREDENTIAL)
            .fetch_one(&mut *material_fence)
            .await?;
        let rpc = h.rpc.clone();
        let body = set(&selection, None, true);
        let request = spawn(async move {
            rpc.call("SetEnvironmentAccessProfile", Auth::Alice, body)
                .await
        });
        let waiting = blocked_service(&h.db, &h.role, holder, 1).await;
        let tested = async {
            let service_pid = *waiting?.first().context("missing blocked profile writer")?;
            let mut removal = h.db.begin().await?;
            let remover: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                .fetch_one(&mut *removal)
                .await?;
            let remove = spawn(async move {
                sqlx::query("DELETE FROM org_members WHERE user_id=$1 AND org_id=$2")
                    .bind(ALICE)
                    .bind(ORG)
                    .execute(&mut *removal)
                    .await?;
                removal.commit().await?;
                Ok(())
            });
            let barrier = blocked_pid(&h.db, remover, service_pid).await;
            material_fence.commit().await?;
            let response = joined(request).await?;
            let removed = joined(remove).await;
            barrier?;
            removed?;
            ensure!(response.0 == StatusCode::OK);
            let confirmed: Option<String> = sqlx::query_scalar(
                "SELECT personal_owner_confirmed_by \
                FROM platform_environment_access_bindings WHERE environment_id=$1",
            )
            .bind(ENV)
            .fetch_one(&h.db)
            .await?;
            ensure!(confirmed.as_deref() == Some(ALICE));
            Ok::<_, anyhow::Error>(())
        }
        .await;
        tested?;
        h.rpc
            .error(
                "GetEnvironmentAccessProfile",
                Auth::Alice,
                json!({"environmentId":ENV}),
                "not_found",
            )
            .await?;
        h.member().await?;
        h.rpc
            .ok(
                "ClearEnvironmentAccessProfile",
                Auth::Alice,
                json!({"expectedBinding":selection}),
            )
            .await?;

        // Two real requests with the same absent-binding expectation cannot
        // both publish after waiting on the current environment generation.
        let mut environment = h.db.begin().await?;
        let holder: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *environment)
            .await?;
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE")
            .bind(ENV)
            .fetch_one(&mut *environment)
            .await?;
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let rpc = h.rpc.clone();
            let body = set(&selection, None, true);
            tasks.push(spawn(async move {
                rpc.call("SetEnvironmentAccessProfile", Auth::Alice, body)
                    .await
            }));
        }
        let barrier = blocked_service(&h.db, &h.role, holder, 2).await;
        environment.commit().await?;
        let mut responses = Vec::new();
        for task in tasks {
            responses.push(joined(task).await?);
        }
        barrier?;
        ensure!(
            responses
                .iter()
                .filter(|response| response.0 == StatusCode::OK)
                .count()
                == 1
        );
        ensure!(
            responses
                .iter()
                .filter(|response| response.1["code"] == "already_exists")
                .count()
                == 1
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
                .fetch_one(&h.db)
                .await?;
        ensure!(count == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}
