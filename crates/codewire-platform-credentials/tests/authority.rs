//! Real restricted-login PostgreSQL proof for fixed metadata lock helpers.
//! Explicit --ignored execution requires an isolated TEST_DATABASE_URL; all
//! credentials, envelopes, roles and databases are generated synthetic fixtures.

#[allow(dead_code)]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use codewire_access::{
    AccessProfile, AccessProfileName, CapabilitySlot, CredentialAuthKind as Kind, CredentialId,
    EnvironmentAccessBinding, EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId,
    builtin_provider_catalog,
};
use codewire_platform_credentials::{
    CredentialMetadataReader, CredentialRecord, OAuthRefreshState, PlatformAccessProfileStore,
    PlatformCredentialError as CredentialError, PlatformCredentialStore,
    PlatformProfileError as ProfileError,
};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

use support::*;

type ProfileRow = (Option<String>, Option<String>, String, i64);

// Row-lock fixture for the canonical write fence. A lifecycle transition must
// carry the complete metadata required by organizations_deletion_metadata_check,
// as begin_organization_deletion does; changing only deletion_state is invalid.
const MARK_ORGANIZATION_DELETING: &str = "UPDATE public.organizations \
    SET deletion_state='deleting', deletion_generation=1, \
        deletion_requested_by='fixture-admin', deletion_requested_at=clock_timestamp(), \
        deletion_operation_id='organization-deletion/' || id || '/1', \
        deletion_workflow_id='organization-deletion/' || id || '/1', \
        deletion_phase='write_fenced', deletion_failure_code=NULL, \
        updated_at=clock_timestamp() WHERE id=$1";

const RESTORE_ORGANIZATION: &str = "UPDATE public.organizations \
    SET deletion_state='active', deletion_requested_by=NULL, deletion_requested_at=NULL, \
        deletion_operation_id=NULL, deletion_workflow_id=NULL, deletion_phase=NULL, \
        deletion_failure_code=NULL, updated_at=clock_timestamp() WHERE id=$1";

fn profiles(pool: &PgPool) -> PlatformAccessProfileStore {
    PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog())
}

fn store(pool: &PgPool, provider: Arc<SyntheticKek>) -> Arc<PlatformCredentialStore> {
    Arc::new(PlatformCredentialStore::new(
        pool.clone(),
        provider,
        builtin_provider_catalog(),
    ))
}

fn name(value: &str) -> AccessProfileName {
    AccessProfileName::parse(value).expect("synthetic profile name")
}

fn entries(id: &CredentialId) -> BTreeMap<CapabilitySlot, CredentialId> {
    BTreeMap::from([(CapabilitySlot::codex(), id.clone())])
}

fn binding(context: &GrantContext, profile: &AccessProfile) -> EnvironmentAccessBinding {
    EnvironmentAccessBinding {
        environment_id: context.environment_id.clone(),
        profile_id: profile.id.clone(),
        profile_revision: profile.revision,
    }
}

async fn environment(
    db: &TestDatabase,
    user: &Owner,
    org: &Owner,
    id: &str,
    credential: &CredentialId,
) -> Result<GrantContext> {
    sqlx::query(
        r#"INSERT INTO environment_presets(id,org_id,name,slug,project_spec)
           VALUES ($1,$2,$1,$1,'{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(format!("preset-{id}"))
    .bind(org.id().as_str())
    .execute(&db.pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,
           environment_operation_generation,project_spec)
           VALUES ($1,$2,$3,'sandbox',$4,'running','started',7,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(id)
    .bind(org.id().as_str())
    .bind(user.id().as_str())
    .bind(format!("preset-{id}"))
    .execute(&db.pool)
    .await?;
    Ok(GrantContext {
        environment_id: EnvironmentId::parse(id)?,
        environment_generation: 7,
        placement: GrantPlacement::Platform,
        user_id: user.id().clone(),
        organization_id: Some(org.id().clone()),
        allow_personal_credentials: true,
        authorized_credentials: [credential.clone()].into_iter().collect(),
    })
}

async fn lock_owner(tx: &mut Transaction<'_, Postgres>, owner: &Owner) -> Result<bool> {
    let kind = match owner {
        Owner::User(_) => "user",
        Owner::Organization(_) => "organization",
    };
    Ok(
        sqlx::query_scalar("SELECT public.codewire_platform_lock_owner($1::text,$2::text)")
            .bind(kind)
            .bind(owner.id().as_str())
            .fetch_one(&mut **tx)
            .await?,
    )
}

async fn denied(pool: &PgPool, sql: &str) -> Result<()> {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .err()
        .context("restricted login unexpectedly acquired forbidden authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501"),
        "expected insufficient_privilege, not a syntax or fixture failure"
    );
    Ok(())
}

async fn wait_blocked(pool: &PgPool, waiter: i32, holder: i32) -> Result<()> {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
            )
            .bind(waiter)
            .bind(holder)
            .fetch_one(pool)
            .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("exact synthetic backend did not wait for the expected row lock")?
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn restricted_broker_enrolls_refreshes_and_uses_exact_bound_grants() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("broker-user").await?;
        let org = db.organization("broker-org").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let broker = store(&pool, provider.clone());
        let initial = broker
            .create(&user, registration("Work", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let context = environment(&db, &user, &org, "broker-env", &initial.metadata.id).await?;
        let manager = profiles(&db.pool);
        let profile = manager
            .create(&user, name("work"), entries(&initial.metadata.id))
            .await?;
        manager
            .create_binding(
                &context,
                binding(&context, &profile),
                Some(&context.user_id),
            )
            .await?;
        // Metadata management stays orchestration-owned. A new current revision
        // must not silently replace the environment's exact immutable binding.
        manager
            .update(&user, &profile.id, 1, BTreeMap::new())
            .await?;
        let runtime = profiles(&pool);
        let unwrap_before = provider.unwrap_calls.load(Ordering::SeqCst);
        let grants = runtime.evaluate_grants(&context).await?.grants;
        ensure!(
            grants.len() == 1
                && grants[0]
                    .profile
                    .as_ref()
                    .is_some_and(|profile| profile.revision == 1)
        );
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == unwrap_before);
        ensure!(runtime.get_revision(&user, &profile.id, 1).await? == profile);
        ensure!(
            broker
                .read_for_broker(&user, &initial.metadata.id, initial.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );

        let attempt = Uuid::new_v4();
        let prepared = broker
            .begin_oauth_refresh(&user, &initial.metadata.id, initial.version, attempt)
            .await?;
        let started = broker.start_oauth_refresh(prepared).await?;
        broker
            .stage_oauth_refresh(&started.prepare_result(&value(NEW_VALUE))?)
            .await?;
        // Recovery runs on a separately authenticated pool, not an admin session
        // or the caller's original in-memory start permit.
        let replica_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let replica = store(&replica_pool, provider.clone());
        let discovered = replica
            .current_oauth_refresh_attempt(&user, &initial.metadata.id)
            .await?
            .context("staged attempt must be discoverable by the replica")?;
        ensure!(discovered.attempt_id == attempt && discovered.state == OAuthRefreshState::Staged);
        let published = replica
            .promote_oauth_refresh(
                &user,
                &initial.metadata.id,
                initial.version,
                discovered.attempt_id,
            )
            .await?;
        ensure!(
            replica
                .promote_oauth_refresh(&user, &initial.metadata.id, initial.version, attempt)
                .await?
                == published
        );
        ensure!(
            replica
                .read_for_broker(&user, &initial.metadata.id, published)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        let replaced = broker
            .replace(
                &user,
                &initial.metadata.id,
                published,
                &value(OLD_VALUE),
                None,
            )
            .await?;
        let revoked = broker
            .revoke(&user, &initial.metadata.id, replaced.version)
            .await?;
        // Revocation withholds this capability (and only it); nothing is granted.
        let admitted = runtime.evaluate_grants(&context).await?;
        ensure!(admitted.grants.is_empty());
        ensure!(
            admitted.reconnect_required
                == BTreeMap::from([(CapabilitySlot::codex(), initial.metadata.id.clone())])
        );
        ensure!(
            broker
                .delete_revoked(&user, &initial.metadata.id, revoked.version)
                .await
                == Err(CredentialError::CredentialInUse)
        );
        // Only the metadata authority may remove the binding. Historical,
        // unbound references do not prevent the enrollment authority's deletion.
        manager
            .delete_binding(&context, &binding(&context, &profile))
            .await?;
        broker
            .delete_revoked(&user, &initial.metadata.id, revoked.version)
            .await?;
        ensure!(broker.record(&user, &initial.metadata.id).await == Err(CredentialError::NotFound));
        // Organization-owned enrollment uses the same restricted authority.
        let shared = broker
            .create(
                &org,
                registration("Shared", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let shared = broker
            .revoke(&org, &shared.metadata.id, shared.version)
            .await?;
        broker
            .delete_revoked(&org, &shared.metadata.id, shared.version)
            .await?;
        replica_pool.close().await;
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn restricted_broker_cannot_mutate_or_lock_unowned_metadata_or_escalate() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let (pool, role) = db.broker_pool().await?;
        let owner: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&db.pool).await?;
        let identities: (String, String) = sqlx::query_as("SELECT current_user::text,session_user::text")
            .fetch_one(&pool).await?;
        ensure!(identities == (role.clone(), role.clone()) && role != owner);
        for sql in [
            "UPDATE public.users SET id=id WHERE false",
            "UPDATE public.organizations SET deletion_state='deleting' WHERE false",
            "UPDATE public.environments SET environment_operation_generation=1 WHERE false",
            "UPDATE public.platform_access_profiles SET current_revision=1 WHERE false",
            "DELETE FROM public.users WHERE false",
            "DELETE FROM public.organizations WHERE false",
            "DELETE FROM public.environments WHERE false",
            "DELETE FROM public.platform_access_profiles WHERE false",
            "UPDATE public.platform_environment_access_bindings SET profile_revision=1 WHERE false",
            "UPDATE public.platform_environment_access_bindings SET personal_owner_confirmed_by=NULL WHERE false",
            "SELECT id FROM public.users FOR SHARE",
            "SELECT id FROM public.organizations FOR SHARE",
            "SELECT id FROM public.environments FOR SHARE",
            "SELECT id FROM public.platform_access_profiles FOR SHARE",
            "SELECT email FROM public.users LIMIT 0",
            "SELECT * FROM public.tenant_secrets LIMIT 0",
            "SELECT * FROM public.tenant_secret_deks LIMIT 0",
            "SELECT * FROM public.tenant_secret_kek_canary LIMIT 0",
            "SELECT * FROM public.confidential_storage_keys LIMIT 0",
            "CREATE TABLE public.broker_must_not_create (id integer)",
            "CREATE SCHEMA broker_must_not_create",
            "ALTER TABLE public.platform_credentials ADD COLUMN broker_must_not_create integer",
            "ALTER FUNCTION public.codewire_platform_lock_owner(text,text) SECURITY INVOKER",
            "ALTER FUNCTION public.codewire_platform_lock_credential(text,text,text) SECURITY INVOKER",
            "CREATE OR REPLACE FUNCTION public.codewire_platform_lock_owner(text,text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        ] {
            denied(&pool, sql).await?;
        }
        denied(&pool, &format!("SET ROLE {}", quote_ident(&owner))).await?;
        denied(&pool, &format!("SET SESSION AUTHORIZATION {}", quote_ident(&owner))).await?;
        // GRANT without grant option may either error or warn without granting.
        // Its observable security contract is the absence of new authority.
        let _ = sqlx::query("GRANT UPDATE ON public.users TO CURRENT_USER").execute(&pool).await;
        let gained_update: bool = sqlx::query_scalar(
            "SELECT pg_catalog.has_any_column_privilege(current_user,'public.users','UPDATE')",
        ).fetch_one(&pool).await?;
        ensure!(!gained_update);
        sqlx::query("RESET ROLE").execute(&pool).await?;
        let reset: (String, String) = sqlx::query_as("SELECT current_user::text,session_user::text")
            .fetch_one(&pool).await?;
        ensure!(reset == (role.clone(), role));
        let runtime = profiles(&pool);
        let user = db.user("not-profile-manager").await?;
        ensure!(runtime.resolve(&user, &name("missing")).await == Err(ProfileError::DatabaseUnavailable));
        ensure!(runtime.list(&user, None, 1).await == Err(ProfileError::DatabaseUnavailable));
        pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn metadata_reader_and_public_have_no_lock_helper_authority() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("metadata-user").await?;
        let record = db.store(Arc::new(SyntheticKek::default()))
            .create(&user, registration("Read only", Kind::OAuth), &value(OLD_VALUE)).await?;
        let (pool, _) = db.metadata_pool().await?;
        let reader = CredentialMetadataReader::new(pool.clone(), builtin_provider_catalog());
        ensure!(reader.get(&user, &record.metadata.id).await? == record.metadata);
        for sql in [
            "SELECT public.codewire_platform_lock_owner('user'::text,'metadata-user'::text)",
            "SELECT * FROM public.codewire_platform_lock_environment('missing'::text,'metadata-user'::text,'missing'::text)",
            "SELECT * FROM public.codewire_platform_lock_profile('missing'::text,'metadata-user'::text,NULL::text)",
            "SELECT * FROM public.codewire_platform_lock_credential('missing'::text,'metadata-user'::text,NULL::text)",
            "SELECT * FROM public.platform_credential_material LIMIT 0",
            "SELECT * FROM public.platform_credential_refresh_material LIMIT 0",
        ] {
            denied(&pool, sql).await?;
        }
        // Inspect actual ACLs, including the default ACL expansion: a NULL
        // proacl would implicitly allow PUBLIC and is not a safe empty ACL.
        let public_grants: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
             CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a \
             WHERE n.nspname='public' AND p.proname IN \
             ('codewire_platform_lock_owner','codewire_platform_lock_environment','codewire_platform_lock_profile','codewire_platform_lock_credential') \
             AND a.grantee=0 AND a.privilege_type='EXECUTE'",
        ).fetch_one(&db.pool).await?;
        ensure!(public_grants == 0);
        pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn lock_helpers_preserve_exact_owner_and_environment_scope() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result =
        async {
            let user = db.user("same-scope-text").await?;
            let org = db.organization("same-scope-text").await?;
            let stranger = db.user("other-scope").await?;
            let (pool, _) = db.broker_pool().await?;
            let broker = store(&pool, Arc::new(SyntheticKek::default()));
            let personal = broker
                .create(
                    &user,
                    registration("Personal", Kind::OAuth),
                    &value(OLD_VALUE),
                )
                .await?;
            let shared = broker
                .create(
                    &org,
                    registration("Shared", Kind::ApiKey),
                    &value(NEW_VALUE),
                )
                .await?;
            let manager = profiles(&db.pool);
            let user_profile = manager
                .create(&user, name("same-name"), entries(&personal.metadata.id))
                .await?;
            let org_profile = manager
                .create(&org, name("same-name"), entries(&shared.metadata.id))
                .await?;
            let runtime = profiles(&pool);
            ensure!(runtime.get(&user, &user_profile.id).await? == user_profile);
            ensure!(runtime.get(&org, &org_profile.id).await? == org_profile);
            ensure!(runtime.get(&org, &user_profile.id).await == Err(ProfileError::NotFound));
            ensure!(runtime.get(&user, &org_profile.id).await == Err(ProfileError::NotFound));
            let context = environment(&db, &user, &org, "scope-env", &personal.metadata.id).await?;
            manager
                .create_binding(
                    &context,
                    binding(&context, &user_profile),
                    Some(&context.user_id),
                )
                .await?;
            ensure!(runtime.evaluate_grants(&context).await?.grants.len() == 1);
            let mut wrong = context.clone();
            wrong.user_id = stranger.id().clone();
            ensure!(runtime.evaluate_grants(&wrong).await == Err(ProfileError::NotFound));
            wrong = context.clone();
            wrong.environment_generation += 1;
            ensure!(runtime.evaluate_grants(&wrong).await == Err(ProfileError::StaleEnvironment));
            for kind in [None, Some("invalid"), Some("user; SELECT true")] {
                let found: bool = sqlx::query_scalar(
                    "SELECT public.codewire_platform_lock_owner($1::text,$2::text)",
                )
                .bind(kind)
                .bind(user.id().as_str())
                .fetch_one(&pool)
                .await?;
                ensure!(!found);
            }
            let unscoped: Option<ProfileRow> = sqlx::query_as(
            "SELECT * FROM public.codewire_platform_lock_profile($1::text,NULL::text,NULL::text)",
        ).bind(user_profile.id.as_str()).fetch_optional(&pool).await?;
            ensure!(unscoped.is_none());
            sqlx::query(MARK_ORGANIZATION_DELETING)
                .bind(org.id().as_str())
                .execute(&db.pool)
                .await?;
            ensure!(runtime.evaluate_grants(&context).await == Err(ProfileError::NotFound));
            ensure!(runtime.get(&org, &org_profile.id).await == Err(ProfileError::NotFound));
            ensure!(
                broker
                    .read_for_broker(&org, &shared.metadata.id, shared.version)
                    .await
                    .err()
                    == Some(CredentialError::NotFound)
            );
            pool.close().await;
            Ok(())
        }
        .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn lock_helpers_ignore_hostile_search_paths_and_temporary_objects() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("real-user").await?;
        let org = db.organization("real-org").await?;
        let record = db.store(Arc::new(SyntheticKek::default()))
            .create(&user, registration("Real", Kind::OAuth), &value(OLD_VALUE)).await?;
        let profile = profiles(&db.pool).create(&user, name("real-profile"), entries(&record.metadata.id)).await?;
        environment(&db, &user, &org, "real-env", &record.metadata.id).await?;
        let (pool, _) = db.broker_pool().await?;
        let mut connection = pool.acquire().await?;
        for sql in [
            "CREATE TEMP TABLE users(id text)",
            "CREATE TEMP TABLE organizations(id text,deletion_state text)",
            "CREATE TEMP TABLE environments(id text,created_by text,org_id text,environment_operation_generation bigint,desired_state text,state text)",
            "CREATE TEMP TABLE platform_access_profiles(id text,user_id text,organization_id text,name text,current_revision bigint)",
            "CREATE TEMP TABLE platform_credentials(id text,user_id text,organization_id text,provider text,authentication_kind text,display_name text,account_hint text,status text,expires_at_unix bigint,revocation_generation bigint)",
            "INSERT INTO pg_temp.users VALUES ('fake-user')",
            "INSERT INTO pg_temp.organizations VALUES ('fake-org','active')",
            "INSERT INTO pg_temp.environments VALUES ('fake-env','real-user','real-org',999,'started','running')",
            "SET search_path = pg_temp, public, pg_catalog",
        ] {
            sqlx::query(sql).execute(&mut *connection).await?;
        }
        sqlx::query("INSERT INTO pg_temp.platform_access_profiles VALUES ($1,'real-user',NULL,'forged',999)")
            .bind(profile.id.as_str()).execute(&mut *connection).await?;
        sqlx::query("INSERT INTO pg_temp.platform_credentials VALUES ($1,'real-user',NULL,'forged','oauth','Forged',NULL,'active',NULL,999)")
            .bind(record.metadata.id.as_str()).execute(&mut *connection).await?;
        for (kind, id, expected) in [
            ("user", "real-user", true), ("user", "fake-user", false),
            ("organization", "real-org", true), ("organization", "fake-org", false),
        ] {
            let found: bool = sqlx::query_scalar("SELECT public.codewire_platform_lock_owner($1::text,$2::text)")
                .bind(kind).bind(id).fetch_one(&mut *connection).await?;
            ensure!(found == expected);
        }
        for (id, expected) in [("real-env", Some(7_i64)), ("fake-env", None)] {
            let generation: Option<i64> = sqlx::query_scalar(
                "SELECT environment_operation_generation FROM public.codewire_platform_lock_environment($1::text,'real-user'::text,'real-org'::text)",
            ).bind(id).fetch_optional(&mut *connection).await?;
            ensure!(generation == expected);
        }
        let selected: ProfileRow = sqlx::query_as(
            "SELECT * FROM public.codewire_platform_lock_profile($1::text,'real-user'::text,NULL::text)",
        ).bind(profile.id.as_str()).fetch_one(&mut *connection).await?;
        ensure!(selected == (Some("real-user".into()), None, "real-profile".into(), 1));
        let credential: (String, i64) = sqlx::query_as(
            "SELECT provider,revocation_generation FROM public.codewire_platform_lock_credential($1::text,'real-user'::text,NULL::text)",
        ).bind(record.metadata.id.as_str()).fetch_one(&mut *connection).await?;
        ensure!(credential == ("openai".into(), 1));
        for (user_scope, org_scope) in [(None, None), (Some("other-user"), None), (None, Some("real-user"))] {
            let denied: Option<String> = sqlx::query_scalar(
                "SELECT provider FROM public.codewire_platform_lock_credential($1::text,$2::text,$3::text)",
            ).bind(record.metadata.id.as_str()).bind(user_scope).bind(org_scope)
                .fetch_optional(&mut *connection).await?;
            ensure!(denied.is_none());
        }
        // Function SET must restore, not overwrite, the caller's hostile path.
        let path: String = sqlx::query_scalar("SHOW search_path").fetch_one(&mut *connection).await?;
        ensure!(path == "pg_temp, public, pg_catalog");
        drop(connection);
        pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_helper_locks_survive_return_and_fence_deletion_in_both_orders() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let (pool, _) = db.broker_pool().await?;
        for organization in [false, true] {
            for deletion_first in [false, true] {
                let id = format!("owner-{organization}-{deletion_first}");
                let owner = if organization {
                    db.organization(&id).await?
                } else {
                    db.user(&id).await?
                };
                let mutation = if organization {
                    MARK_ORGANIZATION_DELETING
                } else {
                    "DELETE FROM public.users WHERE id=$1"
                };
                let mut holder = if deletion_first {
                    db.pool.begin().await?
                } else {
                    pool.begin().await?
                };
                let holder_pid: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                    .fetch_one(&mut *holder)
                    .await?;
                if deletion_first {
                    sqlx::query(mutation)
                        .bind(&id)
                        .execute(&mut *holder)
                        .await?;
                    let mut waiting = pool.begin().await?;
                    let waiter: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                        .fetch_one(&mut *waiting)
                        .await?;
                    let attempt =
                        tokio::spawn(async move { lock_owner(&mut waiting, &owner).await });
                    wait_blocked(&db.pool, waiter, holder_pid).await.with_context(|| {
                        format!("owner lock matrix organization={organization} deletion_first={deletion_first}")
                    })?;
                    holder.commit().await?;
                    ensure!(!tokio::time::timeout(HANG_GUARD, attempt).await???);
                } else {
                    ensure!(lock_owner(&mut holder, &owner).await?);
                    // The helper call has returned. Its lock must still prevent
                    // a different connection from changing the protected row.
                    let mut waiting = db.pool.acquire().await?;
                    let waiter: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                        .fetch_one(&mut *waiting)
                        .await?;
                    let attempt = tokio::spawn(async move {
                        sqlx::query(mutation).bind(id).execute(&mut *waiting).await
                    });
                    wait_blocked(&db.pool, waiter, holder_pid).await.with_context(|| {
                        format!("owner lock matrix organization={organization} deletion_first={deletion_first}")
                    })?;
                    holder.commit().await?;
                    ensure!(
                        tokio::time::timeout(HANG_GUARD, attempt)
                            .await???
                            .rows_affected()
                            == 1
                    );
                    let mut after = pool.begin().await?;
                    ensure!(!lock_owner(&mut after, &owner).await?);
                    after.rollback().await?;
                }
            }
        }
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn environment_and_profile_helpers_fence_binding_and_revision_changes() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("fenced-user").await?;
        let org = db.organization("fenced-org").await?;
        let (pool, _) = db.broker_pool().await?;
        let broker = store(&pool, Arc::new(SyntheticKek::default()));
        let record = broker.create(&user, registration("Fenced", Kind::OAuth), &value(OLD_VALUE)).await?;
        let context = environment(&db, &user, &org, "fenced-env", &record.metadata.id).await?;
        let manager = profiles(&db.pool);
        let profile = manager.create(&user, name("fenced"), entries(&record.metadata.id)).await?;
        manager.create_binding(&context, binding(&context, &profile), Some(&context.user_id)).await?;
        let alternate = manager.create(&user, name("alternate"), BTreeMap::new()).await?;
        for change in ["environment", "binding", "profile"] {
            let mut holder = pool.begin().await?;
            ensure!(lock_owner(&mut holder, &user).await?);
            ensure!(lock_owner(&mut holder, &org).await?);
            let holder_pid: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                .fetch_one(&mut *holder).await?;
            let environment_row: (i64, String, String) = sqlx::query_as(
                "SELECT * FROM public.codewire_platform_lock_environment($1::text,$2::text,$3::text)",
            ).bind(context.environment_id.as_str()).bind(user.id().as_str()).bind(org.id().as_str())
                .fetch_one(&mut *holder).await?;
            ensure!(environment_row.0 == 7);
            if change == "profile" {
                let row: ProfileRow = sqlx::query_as(
                    "SELECT * FROM public.codewire_platform_lock_profile($1::text,$2::text,NULL::text)",
                ).bind(profile.id.as_str()).bind(user.id().as_str()).fetch_one(&mut *holder).await?;
                ensure!(row.3 == 1);
            }
            // One connection identifies the exact backend while exercising
            // real profile/binding mutation APIs, not a stand-in row update.
            let writer_pool = PgPoolOptions::new().max_connections(1)
                .connect_with(db.pool.connect_options().as_ref().clone()).await?;
            let waiter: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                .fetch_one(&writer_pool).await?;
            let writer = writer_pool.clone();
            let write_context = context.clone();
            let write_owner = user.clone();
            let write_profile = profile.clone();
            let write_alternate = alternate.clone();
            let attempt = tokio::spawn(async move {
                match change {
                    "environment" => {
                        sqlx::query("UPDATE public.environments SET desired_state='stopped' WHERE id=$1")
                            .bind(write_context.environment_id.as_str()).execute(&writer).await?;
                    }
                    "binding" => {
                        profiles(&writer).replace_binding(&write_context,
                            &binding(&write_context, &write_profile), binding(&write_context, &write_alternate), Some(&write_context.user_id)).await?;
                    }
                    "profile" => {
                        profiles(&writer).update(&write_owner, &write_profile.id, 1, BTreeMap::new()).await?;
                    }
                    _ => unreachable!("fixed synthetic mutation matrix"),
                }
                Ok::<_, anyhow::Error>(())
            });
            wait_blocked(&db.pool, waiter, holder_pid).await?;
            // Rollback, as well as commit, must release locks without any helper
            // writing row data or leaving an autonomous transaction behind.
            holder.rollback().await?;
            tokio::time::timeout(HANG_GUARD, attempt).await???;
            writer_pool.close().await;
            if change == "environment" {
                ensure!(profiles(&pool).evaluate_grants(&context).await == Err(ProfileError::StaleEnvironment));
                sqlx::query("UPDATE public.environments SET desired_state='started' WHERE id=$1")
                    .bind(context.environment_id.as_str()).execute(&db.pool).await?;
            } else if change == "binding" {
                ensure!(profiles(&pool).evaluate_grants(&context).await?.grants.is_empty());
                manager.replace_binding(&context, &binding(&context, &alternate), binding(&context, &profile), Some(&context.user_id)).await?;
            }
        }
        // The still-pinned revision is not replaced by a metadata edit.
        ensure!(manager.get(&user, &profile.id).await?.revision == 2);
        let grants = profiles(&pool).evaluate_grants(&context).await?.grants;
        ensure!(grants.len() == 1 && grants[0].profile.as_ref().is_some_and(|profile| profile.revision == 1));
        pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn restricted_binding_metadata_waits_for_atomic_rebind_and_clear() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("atomic-consent-user").await?;
        let org = db.organization("atomic-consent-org").await?;
        let credential = db.store(Arc::new(SyntheticKek::default()))
            .create(&user, registration("Personal", Kind::OAuth), &value(OLD_VALUE)).await?;
        let context = environment(&db, &user, &org, "atomic-consent-env", &credential.metadata.id).await?;
        let manager = profiles(&db.pool);
        let personal = manager.create(&user, name("personal"), entries(&credential.metadata.id)).await?;
        let shared = manager.create(&org, name("shared"), BTreeMap::new()).await?;
        manager.create_binding(&context, binding(&context, &personal), Some(user.id())).await?;
        let (broker, _) = db.broker_pool().await?;
        let reader = PgPoolOptions::new().max_connections(1)
            .connect_with(broker.connect_options().as_ref().clone()).await?;
        // The separate binding read, and the two runtime authority reads that
        // merge it into fewer statements, each wait behind the same writers.
        for reading in ["binding metadata", "binding metadata and revision", "grants"] {
            for clear in [false, true] {
                // Each case starts from the personal binding and its one grant.
                sqlx::query("DELETE FROM public.platform_environment_access_bindings WHERE environment_id=$1")
                    .bind(context.environment_id.as_str()).execute(&db.pool).await?;
                manager.create_binding(&context, binding(&context, &personal), Some(user.id())).await?;
                ensure!(profiles(&reader).evaluate_grants(&context).await?.grants.len() == 1);
                let mut writer = db.pool.begin().await?;
                let holder: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                    .fetch_one(&mut *writer).await?;
                sqlx::query("SELECT id FROM public.environments WHERE id=$1 FOR UPDATE")
                    .bind(context.environment_id.as_str()).execute(&mut *writer).await?;
                if clear {
                    sqlx::query("DELETE FROM public.platform_environment_access_bindings WHERE environment_id=$1")
                        .bind(context.environment_id.as_str()).execute(&mut *writer).await?;
                } else {
                    sqlx::query("UPDATE public.platform_environment_access_bindings SET profile_id=$2, \
                        profile_revision=$3,personal_owner_confirmed_by=NULL WHERE environment_id=$1")
                        .bind(context.environment_id.as_str()).bind(shared.id.as_str()).bind(1_i64)
                        .execute(&mut *writer).await?;
                }
                let waiter: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                    .fetch_one(&reader).await?;
                let runtime = profiles(&reader);
                let reading_context = context.clone();
                let reading_org = org.clone();
                let read = tokio::spawn(async move {
                    match reading {
                        "binding metadata" => runtime.get_binding_metadata(&reading_context).await
                            .map(|metadata| (Some(metadata), None, None)),
                        "binding metadata and revision" => runtime
                            .get_binding_metadata_and_revision(&reading_context, &reading_org).await
                            .map(|(metadata, revision)| (Some(metadata), Some(revision), None)),
                        _ => runtime.evaluate_grants(&reading_context).await
                            .map(|grants| (None, None, Some(grants.grants.len()))),
                    }
                });
                wait_blocked(&db.pool, waiter, holder).await?;
                writer.commit().await?;
                let observed = tokio::time::timeout(HANG_GUARD, read).await??;
                match (reading, clear) {
                    // Without a binding, grants fall back to the account's
                    // GitHub connection, which this account does not have.
                    ("grants", _) => ensure!(observed == Ok((None, None, Some(0))), "{reading} {clear}"),
                    (_, true) => ensure!(observed.err() == Some(ProfileError::NotFound), "{reading}"),
                    (_, false) => {
                        let (metadata, revision, _) = observed?;
                        let metadata = metadata.context("binding metadata")?;
                        ensure!(metadata.binding == binding(&context, &shared));
                        ensure!(metadata.personal_owner_confirmed_by.is_none());
                        if let Some(revision) = revision {
                            ensure!(revision? == shared, "{reading}");
                        }
                    }
                }
            }
        }
        reader.close().await;
        broker.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn restricted_broker_final_admission_rejects_revoke_and_owner_deletion_during_unwrap()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let (pool, _) = db.broker_pool().await?;
        for deletion in [false, true] {
            let owner = db.organization(&format!("unwrap-org-{deletion}")).await?;
            let provider = Arc::new(SyntheticKek::default());
            let broker = store(&pool, provider.clone());
            let record: CredentialRecord = broker
                .create(
                    &owner,
                    registration("Work", Kind::ApiKey),
                    &value(OLD_VALUE),
                )
                .await?;
            provider.unwrap_gate.arm();
            let read_store = broker.clone();
            let read_owner = owner.clone();
            let read_id = record.metadata.id.clone();
            let read = tokio::spawn(async move {
                read_store
                    .read_for_broker(&read_owner, &read_id, record.version)
                    .await
            });
            provider.unwrap_gate.wait().await?;
            if deletion {
                sqlx::query("DELETE FROM public.organizations WHERE id=$1")
                    .bind(owner.id().as_str())
                    .execute(&db.pool)
                    .await?;
            } else {
                broker
                    .revoke(&owner, &record.metadata.id, record.version)
                    .await?;
            }
            provider.unwrap_gate.release();
            let outcome = tokio::time::timeout(HANG_GUARD, read).await??;
            ensure!(
                outcome.err()
                    == Some(if deletion {
                        CredentialError::NotFound
                    } else {
                        CredentialError::StaleVersion
                    })
            );
            ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
        }
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_environment_without_a_profile_is_granted_only_the_creators_authorized_github()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("account-github-user").await?;
        let org = db.organization("account-github-org").await?;
        let (pool, _) = db.broker_pool().await?;
        let broker = store(&pool, Arc::new(SyntheticKek::default()));
        let mut github = registration("GitHub", Kind::OAuth);
        github.provider = codewire_access::ProviderId::parse("github")?;
        let connection = broker.create(&user, github, &value(OLD_VALUE)).await?;
        let other = broker
            .create(&user, registration("Codex", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        // No binding and no personal-profile confirmation: selecting a GitHub
        // repository is the creator's consent, which launch authority checks.
        let mut context = environment(
            &db,
            &user,
            &org,
            "account-github-env",
            &connection.metadata.id,
        )
        .await?;
        context.allow_personal_credentials = false;
        context
            .authorized_credentials
            .insert(other.metadata.id.clone());
        let runtime = profiles(&pool);
        let grants = runtime.evaluate_grants(&context).await?.grants;
        ensure!(grants.len() == 1, "only the GitHub connection is granted");
        ensure!(grants[0].capability_slot == CapabilitySlot::github());
        ensure!(grants[0].credential_id == connection.metadata.id);
        ensure!(grants[0].profile.is_none());
        // Not authorized by launch authority: GitHub is omitted, not denied.
        context.authorized_credentials.clear();
        ensure!(runtime.evaluate_grants(&context).await?.grants.is_empty());
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Statement round trips of one runtime grant evaluation, counted at the wire
/// after a warm-up evaluation has prepared every statement on the one pooled
/// connection. Each count is exact: a change must update it deliberately.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn each_grant_evaluation_takes_a_fixed_number_of_statement_round_trips() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("round-trip-user").await?;
        let org = db.organization("round-trip-org").await?;
        let (broker, _) = db.broker_pool().await?;
        let credentials = store(&broker, Arc::new(SyntheticKek::default()));
        let codex = credentials
            .create(&user, registration("Codex", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let api_key = credentials
            .create(
                &user,
                registration("OpenAI", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let mut github = registration("GitHub", Kind::OAuth);
        github.provider = codewire_access::ProviderId::parse("github")?;
        let github = credentials.create(&user, github, &value(OLD_VALUE)).await?;
        let shared = credentials
            .create(
                &org,
                registration("Shared", Kind::ApiKey),
                &value(NEW_VALUE),
            )
            .await?;
        let manager = profiles(&db.pool);
        let personal = manager
            .create(&user, name("personal"), entries(&codex.metadata.id))
            .await?;
        let two = manager
            .create(
                &user,
                name("two-entries"),
                BTreeMap::from([
                    (CapabilitySlot::codex(), codex.metadata.id.clone()),
                    (CapabilitySlot::openai(), api_key.metadata.id.clone()),
                ]),
            )
            .await?;
        let organization = manager
            .create(&org, name("organization"), entries(&shared.metadata.id))
            .await?;
        let mut cases = Vec::new();
        // BEGIN, timeouts, owner and environment locks, binding and profile,
        // the profile's credentials, the GitHub connection read and its lock,
        // COMMIT. With one statement per lock and read these were 16, 18, 13
        // and 10.
        for (case, profile, confirmation, expected_grants, statements) in [
            ("round-trip-personal", Some(&personal), true, 2, 8),
            ("round-trip-two", Some(&two), true, 3, 8),
            ("round-trip-organization", Some(&organization), false, 1, 6),
            ("round-trip-unbound", None, false, 1, 7),
        ] {
            let mut context = environment(&db, &user, &org, case, &codex.metadata.id).await?;
            context.authorized_credentials = [
                &codex.metadata.id,
                &api_key.metadata.id,
                &github.metadata.id,
                &shared.metadata.id,
            ]
            .into_iter()
            .cloned()
            .collect();
            if let Some(profile) = profile {
                manager
                    .create_binding(
                        &context,
                        binding(&context, profile),
                        confirmation.then_some(&context.user_id),
                    )
                    .await?;
            }
            cases.push((case, context, expected_grants, statements));
        }
        let (counter, pool) = StatementCounter::pool(&broker, 1).await?;
        let runtime = profiles(&pool);
        let mut observed = Vec::new();
        for (case, context, expected_grants, statements) in &cases {
            // The first evaluation prepares this path's statements.
            ensure!(runtime.evaluate_grants(context).await?.grants.len() == *expected_grants);
            let (grants, counted) = counter.count(runtime.evaluate_grants(context)).await;
            ensure!(grants?.grants.len() == *expected_grants);
            observed.push((*case, counted, *statements));
        }
        ensure!(
            observed
                .iter()
                .all(|(_, counted, expected)| counted == expected),
            "statement round trips per grant evaluation (case, observed, expected): {observed:?}"
        );
        // No statement on the path is planned large enough to be JIT-compiled.
        ensure_cheap_plans(&db.pool, &counter.texts()).await?;
        pool.close().await;
        broker.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A pool of one connection for `pool`'s login, and that connection's backend.
async fn single_backend(pool: &PgPool) -> Result<(PgPool, i32)> {
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let pid = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
        .fetch_one(&single)
        .await?;
    Ok((single, pid))
}

/// One runtime grant and the exact binding, as admitted before any change.
async fn admitted(
    runtime: &PlatformAccessProfileStore,
    context: &GrantContext,
    profile: &AccessProfile,
) -> Result<()> {
    ensure!(runtime.evaluate_grants(context).await?.grants.len() == 1);
    ensure!(runtime.get_binding_metadata(context).await?.binding == binding(context, profile));
    let (metadata, revision) = runtime
        .get_binding_metadata_and_revision(context, &profile.owner)
        .await?;
    ensure!(metadata.binding == binding(context, profile) && revision? == *profile);
    Ok(())
}

/// The runtime binding read (merged statements) for the context's user, with
/// its outer result only, to compare with `get_binding_metadata`.
async fn runtime_binding(
    runtime: &PlatformAccessProfileStore,
    context: &GrantContext,
) -> std::result::Result<(), ProfileError> {
    runtime
        .get_binding_metadata_and_revision(context, &Owner::User(context.user_id.clone()))
        .await
        .map(|_| ())
}

/// An administrator transaction holding `sql`'s row locks, and its backend.
async fn hold(
    db: &TestDatabase,
    sql: &str,
    id: &str,
) -> Result<(Transaction<'static, Postgres>, i32)> {
    let mut holder = db.pool.begin().await?;
    let pid = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await?;
    sqlx::query(sql).bind(id).execute(&mut *holder).await?;
    Ok((holder, pid))
}

/// The one-statement environment fence: each condition it decides denies on
/// its own, with the error the separate statements returned, and a failed
/// owner lock takes no environment lock after it.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn environment_fence_denies_each_condition_alone_and_stops_at_the_first() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("fence-user").await?;
        let org = db.organization("fence-org").await?;
        let other_org = db.organization("fence-other-org").await?;
        let stranger = db.user("fence-stranger").await?;
        let (pool, _) = db.broker_pool().await?;
        let credentials = store(&pool, Arc::new(SyntheticKek::default()));
        let codex = credentials
            .create(&user, registration("Codex", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let context = environment(&db, &user, &org, "fence-env", &codex.metadata.id).await?;
        let manager = profiles(&db.pool);
        let profile = manager
            .create(&user, name("fence"), entries(&codex.metadata.id))
            .await?;
        manager
            .create_binding(
                &context,
                binding(&context, &profile),
                Some(&context.user_id),
            )
            .await?;
        let runtime = profiles(&pool);
        admitted(&runtime, &context, &profile).await?;
        // Conditions of the caller's context.
        let mut unknown = context.clone();
        unknown.user_id = OwnerId::parse("fence-unknown-user")?;
        let mut not_creator = context.clone();
        not_creator.user_id = stranger.id().clone();
        let mut other_organization = context.clone();
        other_organization.organization_id = Some(other_org.id().clone());
        let mut stale = context.clone();
        stale.environment_generation += 1;
        for (case, changed, expected) in [
            ("unknown user", &unknown, ProfileError::NotFound),
            ("not the creator", &not_creator, ProfileError::NotFound),
            (
                "other organization",
                &other_organization,
                ProfileError::NotFound,
            ),
            ("stale generation", &stale, ProfileError::StaleEnvironment),
        ] {
            ensure!(
                runtime.evaluate_grants(changed).await == Err(expected),
                "{case}"
            );
            ensure!(
                runtime.get_binding_metadata(changed).await == Err(expected),
                "{case}"
            );
            ensure!(
                runtime_binding(&runtime, changed).await == Err(expected),
                "{case}"
            );
        }
        // Conditions of the database, each restored before the next. Binding
        // metadata does not require a running runtime; grants do.
        let environment_id = context.environment_id.as_str();
        for (case, change, restore, id, grants, metadata) in [
            (
                "organization deleting",
                MARK_ORGANIZATION_DELETING,
                RESTORE_ORGANIZATION,
                org.id().as_str(),
                ProfileError::NotFound,
                Some(ProfileError::NotFound),
            ),
            (
                "stop requested",
                "UPDATE environments SET desired_state='stopped' WHERE id=$1",
                "UPDATE environments SET desired_state='started' WHERE id=$1",
                environment_id,
                ProfileError::StaleEnvironment,
                None,
            ),
            (
                "not running",
                "UPDATE environments SET state='stopped' WHERE id=$1",
                "UPDATE environments SET state='running' WHERE id=$1",
                environment_id,
                ProfileError::StaleEnvironment,
                None,
            ),
            (
                "destroy requested",
                "UPDATE environments SET desired_state='destroyed' WHERE id=$1",
                "UPDATE environments SET desired_state='started' WHERE id=$1",
                environment_id,
                ProfileError::StaleEnvironment,
                Some(ProfileError::StaleEnvironment),
            ),
            (
                "destroyed",
                "UPDATE environments SET state='destroyed' WHERE id=$1",
                "UPDATE environments SET state='running' WHERE id=$1",
                environment_id,
                ProfileError::StaleEnvironment,
                Some(ProfileError::StaleEnvironment),
            ),
            (
                "operation advanced",
                "UPDATE environments SET environment_operation_generation=8 WHERE id=$1",
                "UPDATE environments SET environment_operation_generation=7 WHERE id=$1",
                environment_id,
                ProfileError::StaleEnvironment,
                Some(ProfileError::StaleEnvironment),
            ),
        ] {
            sqlx::query(change).bind(id).execute(&db.pool).await?;
            ensure!(
                runtime.evaluate_grants(&context).await == Err(grants),
                "{case}"
            );
            let observed = runtime.get_binding_metadata(&context).await.map(|_| ());
            ensure!(observed == metadata.map_or(Ok(()), Err), "{case}");
            ensure!(
                runtime_binding(&runtime, &context).await == observed,
                "{case} runtime"
            );
            sqlx::query(restore).bind(id).execute(&db.pool).await?;
            admitted(&runtime, &context, &profile).await.context(case)?;
        }
        // A writer holding the environment row delays the fence when both
        // owners lock, and the fence then reads the committed row.
        let (reader, waiter) = single_backend(&pool).await?;
        let lock_environment = "SELECT id FROM environments WHERE id=$1 FOR UPDATE";
        let (holder, holder_pid) = hold(&db, lock_environment, environment_id).await?;
        let waiting_context = context.clone();
        let waiting_runtime = profiles(&reader);
        let waiting =
            tokio::spawn(async move { waiting_runtime.evaluate_grants(&waiting_context).await });
        wait_blocked(&db.pool, waiter, holder_pid).await?;
        holder.rollback().await?;
        ensure!(
            tokio::time::timeout(HANG_GUARD, waiting)
                .await???
                .grants
                .len()
                == 1
        );
        // With the organization lock failing, the same held row is never
        // waited for: the denial returns at once, not at the statement timeout.
        sqlx::query(MARK_ORGANIZATION_DELETING)
            .bind(org.id().as_str())
            .execute(&db.pool)
            .await?;
        let (holder, _) = hold(&db, lock_environment, environment_id).await?;
        let denied = tokio::time::timeout(
            Duration::from_secs(2),
            profiles(&reader).evaluate_grants(&context),
        )
        .await
        .context("a failed owner lock waited for the environment lock")?;
        ensure!(denied == Err(ProfileError::NotFound));
        holder.rollback().await?;
        reader.close().await;
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The one-statement binding and profile read, the batched credential locks
/// and the GitHub connection read: each condition they decide changes runtime
/// grants on its own, as the separate statements did, and the credential
/// locks stop at the first credential not found.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn bound_profile_and_credential_reads_decide_each_condition_alone() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("bound-user").await?;
        let org = db.organization("bound-org").await?;
        let stranger = db.user("bound-stranger").await?;
        let (pool, _) = db.broker_pool().await?;
        let credentials = store(&pool, Arc::new(SyntheticKek::default()));
        let codex = credentials
            .create(&user, registration("Codex", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let api_key = credentials
            .create(&user, registration("OpenAI", Kind::ApiKey), &value(OLD_VALUE))
            .await?;
        let mut context = environment(&db, &user, &org, "bound-env", &codex.metadata.id).await?;
        context.authorized_credentials.insert(api_key.metadata.id.clone());
        let manager = profiles(&db.pool);
        // The user's first profile is their default, whose owner never
        // changes; the bound profile is an ordinary one, so a case below can
        // move it to another owner.
        manager.create(&user, name("default"), BTreeMap::new()).await?;
        let profile = manager
            .create(
                &user,
                name("bound"),
                BTreeMap::from([
                    (CapabilitySlot::codex(), codex.metadata.id.clone()),
                    (CapabilitySlot::openai(), api_key.metadata.id.clone()),
                ]),
            )
            .await?;
        let bound = binding(&context, &profile);
        manager.create_binding(&context, bound.clone(), Some(&context.user_id)).await?;
        let runtime = profiles(&pool);
        let slots = |grants: &codewire_access::AvailableGrants| {
            grants.grants.iter().map(|grant| grant.capability_slot.to_string()).collect::<BTreeSet<_>>()
        };
        let both = BTreeSet::from(["codex".to_string(), "openai".to_string()]);
        ensure!(slots(&runtime.evaluate_grants(&context).await?) == both);
        // Runtime authority's two profile reads, together.
        let (metadata, revision) =
            runtime.get_binding_metadata_and_revision(&context, &user).await?;
        ensure!(metadata.binding == bound && metadata.personal_owner_confirmed_by.as_ref() == Some(user.id()));
        ensure!(revision? == runtime.get_revision(&user, &profile.id, profile.revision).await?);
        // The bound profile belongs to the user, so the organization's
        // revision read alone finds nothing; the binding read still succeeds.
        let (_, revision) = runtime.get_binding_metadata_and_revision(&context, &org).await?;
        ensure!(revision == Err(ProfileError::NotFound));
        ensure!(
            runtime.get_binding_metadata_and_revision(&context, &stranger).await.err()
                == Some(ProfileError::InvalidInput)
        );
        // Conditions of the stored binding, profile and credentials, each
        // restored before the next.
        let profile_id = profile.id.as_str();
        for (case, change, restore, id, grants) in [
            ("profile of another owner",
             "UPDATE platform_access_profiles SET user_id='bound-stranger' WHERE id=$1",
             "UPDATE platform_access_profiles SET user_id='bound-user' WHERE id=$1",
             profile_id, Err(ProfileError::NotFound)),
            ("confirmation cleared",
             "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=NULL WHERE profile_id=$1",
             "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by='bound-user' WHERE profile_id=$1",
             profile_id, Err(ProfileError::UnsupportedEntry)),
            ("credential of another owner",
             "UPDATE platform_credentials SET user_id='bound-stranger' WHERE id=$1",
             "UPDATE platform_credentials SET user_id='bound-user' WHERE id=$1",
             codex.metadata.id.as_str(), Err(ProfileError::NotFound)),
            ("credential revoked",
             "UPDATE platform_credentials SET status='revoked' WHERE id=$1",
             "UPDATE platform_credentials SET status='active' WHERE id=$1",
             api_key.metadata.id.as_str(), Ok(BTreeSet::from(["codex".to_string()]))),
        ] {
            sqlx::query(change).bind(id).execute(&db.pool).await?;
            let observed = runtime.evaluate_grants(&context).await.map(|grants| slots(&grants));
            ensure!(observed == grants, "{case}: {observed:?}");
            sqlx::query(restore).bind(id).execute(&db.pool).await?;
            ensure!(slots(&runtime.evaluate_grants(&context).await?) == both, "{case} restored");
        }
        ensure!(
            runtime.get_binding_metadata_and_revision(&context, &user).await?.1?.revision
                == profile.revision
        );
        let mut personal_disallowed = context.clone();
        personal_disallowed.allow_personal_credentials = false;
        ensure!(runtime.evaluate_grants(&personal_disallowed).await == Err(ProfileError::UnsupportedEntry));
        // The GitHub connection: absent, connected, expired, revoked.
        let mut github = registration("GitHub", Kind::OAuth);
        github.provider = codewire_access::ProviderId::parse("github")?;
        let github = credentials.create(&user, github, &value(OLD_VALUE)).await?;
        context.authorized_credentials.insert(github.metadata.id.clone());
        let all = BTreeSet::from(["codex".to_string(), "github".to_string(), "openai".to_string()]);
        ensure!(slots(&runtime.evaluate_grants(&context).await?) == all);
        for change in ["expires_at_unix=1", "status='revoked'"] {
            sqlx::query(&format!("UPDATE platform_credentials SET {change} WHERE id=$1"))
                .bind(github.metadata.id.as_str()).execute(&db.pool).await?;
            ensure!(slots(&runtime.evaluate_grants(&context).await?) == both, "{change}");
            sqlx::query("UPDATE platform_credentials SET expires_at_unix=NULL,status='active' WHERE id=$1")
                .bind(github.metadata.id.as_str()).execute(&db.pool).await?;
            ensure!(slots(&runtime.evaluate_grants(&context).await?) == all, "{change} restored");
        }
        // No binding: only the account's GitHub connection.
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        ensure!(slots(&runtime.evaluate_grants(&context).await?) == BTreeSet::from(["github".to_string()]));
        ensure!(runtime.get_binding_metadata(&context).await == Err(ProfileError::NotFound));
        ensure!(
            runtime.get_binding_metadata_and_revision(&context, &user).await.err()
                == Some(ProfileError::NotFound)
        );
        manager.create_binding(&context, bound.clone(), Some(&context.user_id)).await?;
        ensure!(slots(&runtime.evaluate_grants(&context).await?) == all);
        // The credential locks run in ID order. When the first is no longer
        // the owner's, the second is never locked, so a writer holding it does
        // not delay the denial. With the first restored, the same writer does.
        let (first, second) = if codex.metadata.id < api_key.metadata.id {
            (&codex.metadata.id, &api_key.metadata.id)
        } else {
            (&api_key.metadata.id, &codex.metadata.id)
        };
        let (reader, waiter) = single_backend(&pool).await?;
        let lock_credential = "SELECT id FROM platform_credentials WHERE id=$1 FOR UPDATE";
        sqlx::query("UPDATE platform_credentials SET user_id='bound-stranger' WHERE id=$1")
            .bind(first.as_str()).execute(&db.pool).await?;
        let (holder, holder_pid) = hold(&db, lock_credential, second.as_str()).await?;
        let denied = tokio::time::timeout(Duration::from_secs(2), profiles(&reader).evaluate_grants(&context))
            .await
            .context("a missing first credential waited for the second one's lock")?;
        ensure!(denied == Err(ProfileError::NotFound));
        sqlx::query("UPDATE platform_credentials SET user_id='bound-user' WHERE id=$1")
            .bind(first.as_str()).execute(&db.pool).await?;
        let waiting_context = context.clone();
        let waiting_runtime = profiles(&reader);
        let waiting =
            tokio::spawn(async move { waiting_runtime.evaluate_grants(&waiting_context).await });
        wait_blocked(&db.pool, waiter, holder_pid).await?;
        holder.rollback().await?;
        ensure!(slots(&tokio::time::timeout(HANG_GUARD, waiting).await???) == all);
        reader.close().await;
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}
