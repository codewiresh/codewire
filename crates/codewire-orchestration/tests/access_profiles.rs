//! Public generated Connect contract over an actual synthetic restricted login.
//! Each ignored case owns and removes one exact disposable PostgreSQL database.

#[path = "access_profiles_support/mod.rs"]
mod support;

#[path = "access_profiles_timeout/mod.rs"]
mod timeout;

#[path = "access_profiles_destroy/mod.rs"]
mod destroy;

#[path = "access_profiles_sources/mod.rs"]
mod sources;

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
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
            "UpdateAccessProfile", "RenameAccessProfile", "DeleteAccessProfile",
            "GetEnvironmentAccessProfile"] {
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
        h.rpc.error("RenameAccessProfile", Auth::Bob,
            json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","name":"taken"}), "not_found").await?;

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
async fn public_profile_rename_keeps_the_revision_and_uses_create_name_rules() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("work", CREDENTIAL).await?;
        h.rpc.create("other", CREDENTIAL).await?;
        // Bob's own profile name never collides with Alice's.
        h.rpc
            .ok(
                "CreateAccessProfile",
                Auth::Bob,
                json!({"name":"personal","entries":entries(OTHER_CREDENTIAL)}),
            )
            .await?;
        let rename = |revision: &str, name: &str| -> Result<Value> {
            Ok(json!({"accessProfileId":id(&profile)?,"expectedRevision":revision,"name":name}))
        };
        // The same name rules as CreateAccessProfile, checked before any write.
        for name in [
            "",
            "WORK",
            "work profile",
            "-work",
            "work.",
            &"a".repeat(129),
        ] {
            h.rpc
                .error(
                    "RenameAccessProfile",
                    Auth::Alice,
                    rename("1", name)?,
                    "invalid_argument",
                )
                .await?;
        }
        for revision in ["0", "18446744073709551615"] {
            h.rpc
                .error(
                    "RenameAccessProfile",
                    Auth::Alice,
                    rename(revision, "personal")?,
                    "invalid_argument",
                )
                .await?;
        }
        h.rpc
            .error(
                "RenameAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":"not an id","expectedRevision":"1","name":"personal"}),
                "invalid_argument",
            )
            .await?;
        // A taken name conflicts as it does on create; so does a stale view.
        h.rpc
            .error(
                "RenameAccessProfile",
                Auth::Alice,
                rename("1", "other")?,
                "already_exists",
            )
            .await?;
        h.rpc
            .error(
                "RenameAccessProfile",
                Auth::Alice,
                rename("2", "personal")?,
                "already_exists",
            )
            .await?;
        let unchanged = h
            .rpc
            .ok(
                "GetAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":id(&profile)?}),
            )
            .await?;
        ensure!(
            unchanged["accessProfile"] == profile,
            "a rejected rename changed the profile"
        );

        let renamed = h
            .rpc
            .ok(
                "RenameAccessProfile",
                Auth::Cookie,
                rename("1", "personal")?,
            )
            .await?;
        let mut expected = profile.clone();
        expected["name"] = json!("personal");
        ensure!(
            renamed["accessProfile"] == expected,
            "rename changed more than the name"
        );
        ensure!(
            renamed["accessProfile"]["revision"] == "1",
            "rename published a revision"
        );
        let current = h
            .rpc
            .ok("GetAccessProfile", Auth::Alice, json!({"name":"personal"}))
            .await?;
        ensure!(current == renamed);
        let historical = h
            .rpc
            .ok(
                "GetAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":id(&profile)?,"revision":"1"}),
            )
            .await?;
        ensure!(historical == renamed, "the label is not part of a revision");
        h.rpc
            .error(
                "GetAccessProfile",
                Auth::Alice,
                json!({"name":"work"}),
                "not_found",
            )
            .await?;
        h.rpc
            .error(
                "GetAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":id(&profile)?,"revision":"2"}),
                "not_found",
            )
            .await?;
        let revisions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_access_profile_revisions WHERE profile_id=$1",
        )
        .bind(id(&profile)?)
        .fetch_one(&h.db)
        .await?;
        ensure!(revisions == 1);

        // Editing advances from the preserved revision; the old name is free.
        let updated = h
            .rpc
            .ok(
                "UpdateAccessProfile",
                Auth::Alice,
                json!({"accessProfileId":id(&profile)?,"expectedRevision":"1","entries":[]}),
            )
            .await?;
        ensure!(
            updated["accessProfile"]["revision"] == "2"
                && updated["accessProfile"]["name"] == "personal"
        );
        h.rpc
            .error(
                "RenameAccessProfile",
                Auth::Alice,
                rename("1", "later")?,
                "already_exists",
            )
            .await?;
        h.rpc.create("work", CREDENTIAL).await?;
        let later = h
            .rpc
            .ok("RenameAccessProfile", Auth::Alice, rename("2", "later")?)
            .await?;
        ensure!(
            later["accessProfile"]["revision"] == "2" && later["accessProfile"]["name"] == "later"
        );
        Ok(())
    }
    .await;
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
        h.rpc.create("least-authority", CREDENTIAL).await?;
        // This actual mount contains only the generated material-free service,
        // never a generic secret read, KEK route or credential enrollment hop.
        for path in ["/codewire.v1.AccessProfileService/SetEnvironmentAccessProfile",
            "/codewire.v1.AccessProfileService/ClearEnvironmentAccessProfile",
            "/codewire.v1.AccessProfileService/ReadCredentialMaterial",
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
