//! Owner-authenticated platform selections for local execution. Every database,
//! login, OAuth token and protected value is an isolated synthetic fixture.

#[allow(dead_code)]
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use codewire_access::{
    AccessProfile, AccessProfileName, CapabilitySlot, CredentialAuthKind, DerivedGrant,
    EnvironmentAccessBinding, EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId,
    builtin_provider_catalog,
};
use codewire_platform_credentials::{
    CredentialRecord, PlatformAccessProfileStore, PlatformProfileError as Error,
};
use codewire_server_core::auth::{
    AuthState, OAuthBearerAuthority, OAuthBearerAuthorityError, authenticate_product_credential,
    hash_oauth_token,
};
use sqlx::PgPool;

use support::*;

const TOKEN: &str = "synthetic-owner-source-oauth-only";

struct Selection {
    user: Owner,
    organization: Owner,
    credential: CredentialRecord,
    profile: AccessProfile,
    context: GrantContext,
    authority: OAuthBearerAuthority,
    provider: Arc<SyntheticKek>,
}

fn profiles(pool: &PgPool) -> PlatformAccessProfileStore {
    PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog())
}

fn binding(selection: &Selection) -> EnvironmentAccessBinding {
    EnvironmentAccessBinding {
        environment_id: selection.context.environment_id.clone(),
        profile_id: selection.profile.id.clone(),
        profile_revision: selection.profile.revision,
    }
}

async fn seed(db: &TestDatabase) -> Result<Selection> {
    let user = db.user("owner-source-user").await?;
    let organization = db.organization("owner-source-org").await?;
    sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES('owner-source-member',$1,$2,'member')")
        .bind(organization.id().as_str()).bind(user.id().as_str()).execute(&db.pool).await?;
    let provider = Arc::new(SyntheticKek::default());
    let credential = db
        .store(provider.clone())
        .create(
            &user,
            registration("Owner source", CredentialAuthKind::OAuth),
            &value(OLD_VALUE),
        )
        .await?;
    let profile = profiles(&db.pool)
        .create(
            &user,
            AccessProfileName::parse("owner-source")?,
            BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await?;
    sqlx::query("INSERT INTO oidc_clients(id,name,redirect_uris,scopes) VALUES('owner-source-client','Synthetic owner source',ARRAY['http://127.0.0.1/callback'],ARRAY['codewire.api'])")
        .execute(&db.pool).await?;
    sqlx::query("INSERT INTO oidc_access_tokens(token_hash,client_id,user_id,scopes,expires_at) VALUES($1,'owner-source-client',$2,ARRAY['codewire.api'],clock_timestamp()+interval '10 minutes')")
        .bind(hash_oauth_token(TOKEN)).bind(user.id().as_str()).execute(&db.pool).await?;
    // Exercise the real original-token authority, not a fabricated principal or
    // a test-only constructor. This bearer never leaves this disposable test.
    let authentication = authenticate_product_credential(
        &AuthState {
            pool: db.pool.clone(),
        },
        None,
        Some(TOKEN),
    )
    .await?;
    let authority = authentication
        .oauth_bearer_authority()
        .context("original OAuth authority absent")?
        .clone();
    ensure!(authority.user_id() == user.id().as_str());
    Ok(Selection {
        context: GrantContext {
            environment_id: EnvironmentId::parse(uuid::Uuid::new_v4().to_string())?,
            environment_generation: 7,
            placement: GrantPlacement::PlatformToLocal,
            user_id: user.id().clone(),
            organization_id: Some(organization.id().clone()),
            allow_personal_credentials: true,
            authorized_credentials: [credential.metadata.id.clone()].into_iter().collect(),
        },
        user,
        organization,
        credential,
        profile,
        authority,
        provider,
    })
}

async fn evaluate(
    pool: &PgPool,
    selection: &Selection,
    context: &GrantContext,
    binding: &EnvironmentAccessBinding,
    confirmation: Option<&OwnerId>,
) -> Result<Result<Vec<DerivedGrant>, Error>> {
    let store = profiles(pool);
    let mut tx = store.begin_transaction().await?;
    selection.authority.lock_for_publication(&mut tx).await?;
    let result = store
        .evaluate_owner_selection_in(&mut tx, context, binding, confirmation)
        .await;
    tx.rollback().await?;
    Ok(result)
}

async fn no_platform_runtime_rows(pool: &PgPool) -> Result<()> {
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM environments),(SELECT count(*) FROM platform_environment_access_bindings)",
    ).fetch_one(pool).await?;
    ensure!(
        counts == (0, 0),
        "owner-local admission created a platform runtime or binding"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_selection_is_restricted_material_free_and_pins_exact_immutable_profile() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let selection = seed(&db).await?;
        let second = db.store(selection.provider.clone()).create(
            &selection.user, registration("New selection", CredentialAuthKind::OAuth), &value(NEW_VALUE),
        ).await?;
        let current = profiles(&db.pool).update(
            &selection.user, &selection.profile.id, selection.profile.revision,
            BTreeMap::from([(CapabilitySlot::codex(), second.metadata.id)]),
        ).await?;
        ensure!(current.revision == 2);
        let (reader, role) = db.metadata_pool().await?;
        let result = async {
            for grant in [
                "SELECT (profile_id,revision,include_github) ON public.platform_access_profile_revisions",
                "SELECT ON public.platform_access_profile_entries",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_platform_lock_owner_source_authority(text,text,text)",
                "EXECUTE ON FUNCTION public.codewire_lock_oauth_bearer_authority(text,text,text,timestamptz)",
            ] {
                sqlx::query(&format!("GRANT {grant} TO {}", quote_ident(&role))).execute(&db.pool).await?;
            }
            let grants = evaluate(&reader, &selection, &selection.context, &binding(&selection), Some(selection.user.id())).await??;
            ensure!(grants.len() == 1);
            let grant = &grants[0];
            ensure!(grant.environment_id == selection.context.environment_id);
            ensure!(grant.environment_generation == 7 && grant.profile_revision == 1);
            ensure!(grant.profile_id == selection.profile.id && grant.credential_id == selection.credential.metadata.id);
            ensure!(grant.credential_revocation_generation == selection.credential.metadata.revocation_generation);
            for sql in ["SELECT * FROM public.platform_credential_material", "SELECT * FROM public.environments", "SELECT * FROM public.org_members", "UPDATE public.platform_credentials SET status='revoked'"] {
                let error = sqlx::query(sql).execute(&reader).await.err().context("metadata authority gained forbidden access")?;
                ensure!(error.as_database_error().and_then(|error| error.code()).as_deref() == Some("42501"));
            }
            ensure!(selection.provider.unwrap_calls.load(Ordering::SeqCst) == 0);
            no_platform_runtime_rows(&db.pool).await
        }.await;
        reader.close().await;
        result
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_selection_rejects_wrong_placement_generation_binding_and_personal_consent()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let selection = seed(&db).await?;
        let selected = binding(&selection);
        for placement in [GrantPlacement::Local, GrantPlacement::Platform] {
            let mut context = selection.context.clone();
            context.placement = placement;
            ensure!(
                evaluate(
                    &db.pool,
                    &selection,
                    &context,
                    &selected,
                    Some(selection.user.id())
                )
                .await?
                    == Err(Error::InvalidInput)
            );
        }
        for generation in [0, i64::MAX as u64 + 1] {
            let mut context = selection.context.clone();
            context.environment_generation = generation;
            ensure!(
                evaluate(
                    &db.pool,
                    &selection,
                    &context,
                    &selected,
                    Some(selection.user.id())
                )
                .await?
                    == Err(Error::InvalidInput)
            );
            let mut changed = selected.clone();
            changed.profile_revision = generation;
            ensure!(
                evaluate(
                    &db.pool,
                    &selection,
                    &selection.context,
                    &changed,
                    Some(selection.user.id())
                )
                .await?
                    == Err(Error::InvalidInput)
            );
        }
        let mut wrong_binding = selected.clone();
        wrong_binding.environment_id = EnvironmentId::parse(uuid::Uuid::new_v4().to_string())?;
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &selection.context,
                &wrong_binding,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::InvalidInput)
        );
        let mut no_org = selection.context.clone();
        no_org.organization_id = None;
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &no_org,
                &selected,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::InvalidInput)
        );
        let stranger = OwnerId::parse("not-the-confirmed-owner")?;
        for confirmation in [None, Some(&stranger)] {
            ensure!(
                evaluate(
                    &db.pool,
                    &selection,
                    &selection.context,
                    &selected,
                    confirmation
                )
                .await?
                    == Err(Error::UnsupportedEntry)
            );
        }
        let mut denied_personal = selection.context.clone();
        denied_personal.allow_personal_credentials = false;
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &denied_personal,
                &selected,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::UnsupportedEntry)
        );
        let mut unauthorized = selection.context.clone();
        unauthorized.authorized_credentials.clear();
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &unauthorized,
                &selected,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::UnsupportedEntry)
        );

        // Existing hosted entrypoints must not accept the new execution target,
        // even though its credential storage placement is still Platform.
        let store = profiles(&db.pool);
        ensure!(store.evaluate_grants(&selection.context).await == Err(Error::InvalidInput));
        ensure!(store.get_binding_metadata(&selection.context).await == Err(Error::InvalidInput));
        ensure!(
            store
                .create_binding(
                    &selection.context,
                    selected.clone(),
                    Some(selection.user.id())
                )
                .await
                == Err(Error::InvalidInput)
        );
        ensure!(
            store
                .replace_binding(
                    &selection.context,
                    &selected,
                    selected.clone(),
                    Some(selection.user.id())
                )
                .await
                == Err(Error::InvalidInput)
        );
        ensure!(
            store.delete_binding(&selection.context, &selected).await == Err(Error::InvalidInput)
        );
        let mut pending = selection.context.clone();
        pending.environment_generation = 0;
        let mut tx = store.begin_transaction().await?;
        ensure!(
            store
                .create_pending_binding_in(&mut tx, &pending, selected, Some(selection.user.id()))
                .await
                == Err(Error::InvalidInput)
        );
        tx.rollback().await?;
        no_platform_runtime_rows(&db.pool).await
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_selection_rechecks_current_credential_status_expiry_revocation_and_owner()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let selection = seed(&db).await?;
        let selected = binding(&selection);
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &selection.context,
                &selected,
                Some(selection.user.id())
            )
            .await??
            .len()
                == 1
        );
        for (status, expires, expected) in [
            ("refresh_failed", None, Error::InactiveCredential),
            ("expired", None, Error::ExpiredCredential),
            ("active", Some(0_i64), Error::ExpiredCredential),
        ] {
            sqlx::query("UPDATE platform_credentials SET status=$2,expires_at_unix=$3 WHERE id=$1")
                .bind(selection.credential.metadata.id.as_str())
                .bind(status)
                .bind(expires)
                .execute(&db.pool)
                .await?;
            ensure!(
                evaluate(
                    &db.pool,
                    &selection,
                    &selection.context,
                    &selected,
                    Some(selection.user.id())
                )
                .await?
                    == Err(expected)
            );
        }
        sqlx::query(
            "UPDATE platform_credentials SET status='active',expires_at_unix=NULL WHERE id=$1",
        )
        .bind(selection.credential.metadata.id.as_str())
        .execute(&db.pool)
        .await?;
        let stranger = db.user("owner-source-stranger").await?;
        sqlx::query("UPDATE platform_credentials SET user_id=$2 WHERE id=$1")
            .bind(selection.credential.metadata.id.as_str())
            .bind(stranger.id().as_str())
            .execute(&db.pool)
            .await?;
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &selection.context,
                &selected,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::NotFound)
        );
        sqlx::query("UPDATE platform_credentials SET user_id=$2 WHERE id=$1")
            .bind(selection.credential.metadata.id.as_str())
            .bind(selection.user.id().as_str())
            .execute(&db.pool)
            .await?;
        // Use actual atomic store revocation; never violate the immediate
        // material-generation FK to manufacture the stale authority case.
        let revoked = db
            .store(selection.provider.clone())
            .revoke(
                &selection.user,
                &selection.credential.metadata.id,
                selection.credential.version,
            )
            .await?;
        ensure!(
            revoked.metadata.revocation_generation
                == selection.credential.metadata.revocation_generation + 1
        );
        ensure!(
            evaluate(
                &db.pool,
                &selection,
                &selection.context,
                &selected,
                Some(selection.user.id())
            )
            .await?
                == Err(Error::InactiveCredential)
        );
        ensure!(selection.provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        no_platform_runtime_rows(&db.pool).await
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_selection_rechecks_organization_profile_owner_membership_and_deletion() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let selection = seed(&db).await?;
        let record = db.store(selection.provider.clone()).create(
            &selection.organization, registration("Organization source", CredentialAuthKind::OAuth), &value(OLD_VALUE),
        ).await?;
        let profile = profiles(&db.pool).create(
            &selection.organization, AccessProfileName::parse("organization-source")?,
            BTreeMap::from([(CapabilitySlot::codex(), record.metadata.id.clone())]),
        ).await?;
        let selected = EnvironmentAccessBinding { environment_id: selection.context.environment_id.clone(), profile_id: profile.id.clone(), profile_revision: profile.revision };
        let mut context = selection.context.clone();
        context.authorized_credentials = [record.metadata.id].into_iter().collect();
        context.allow_personal_credentials = false;
        ensure!(evaluate(&db.pool, &selection, &context, &selected, None).await??.len() == 1);
        ensure!(evaluate(&db.pool, &selection, &context, &selected, Some(selection.user.id())).await? == Err(Error::UnsupportedEntry));
        let other_org = db.organization("owner-source-other-org").await?;
        sqlx::query("UPDATE platform_access_profiles SET organization_id=$2 WHERE id=$1")
            .bind(profile.id.as_str()).bind(other_org.id().as_str()).execute(&db.pool).await?;
        ensure!(evaluate(&db.pool, &selection, &context, &selected, None).await? == Err(Error::NotFound));
        sqlx::query("UPDATE platform_access_profiles SET organization_id=$2 WHERE id=$1")
            .bind(profile.id.as_str()).bind(selection.organization.id().as_str()).execute(&db.pool).await?;
        sqlx::query("UPDATE org_members SET role='' WHERE id='owner-source-member'").execute(&db.pool).await?;
        ensure!(evaluate(&db.pool, &selection, &context, &selected, None).await? == Err(Error::NotFound));
        sqlx::query("UPDATE org_members SET role='member' WHERE id='owner-source-member'").execute(&db.pool).await?;
        sqlx::query("UPDATE organizations SET deletion_state='deleting',deletion_generation=1, \
            deletion_requested_by='fixture-admin',deletion_requested_at=clock_timestamp(), \
            deletion_operation_id='owner-source-delete',deletion_workflow_id='owner-source-delete',deletion_phase='write_fenced' WHERE id=$1")
            .bind(selection.organization.id().as_str()).execute(&db.pool).await?;
        ensure!(evaluate(&db.pool, &selection, &context, &selected, None).await? == Err(Error::NotFound));
        ensure!(selection.provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        no_platform_runtime_rows(&db.pool).await
    }.await;
    db.finish(result).await
}

async fn wait_blocked(pool: &PgPool, waiter: i32, holder: i32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))",
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
    .context("exact synthetic writer did not wait for retained admission")?
}

async fn writer_waits(db: &TestDatabase, selection: &Selection, sql: &str) -> Result<()> {
    let store = profiles(&db.pool);
    let mut tx = store.begin_transaction().await?;
    selection.authority.lock_for_publication(&mut tx).await?;
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        store
            .evaluate_owner_selection_in(
                &mut tx,
                &selection.context,
                &binding(selection),
                Some(selection.user.id())
            )
            .await?
            .len()
            == 1
    );
    let mut writer = db.pool.acquire().await?;
    sqlx::query("SET statement_timeout='5s'")
        .execute(&mut *writer)
        .await?;
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    let (write, release) = tokio::join!(sqlx::query(sql).execute(&mut *writer), async {
        let observed = wait_blocked(&db.pool, waiter, holder).await;
        tx.rollback().await?;
        observed
    });
    release?;
    ensure!(write?.rows_affected() == 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_selection_retains_original_oauth_and_profile_credential_membership_locks()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let selection = seed(&db).await?;
        writer_waits(&db, &selection, "UPDATE platform_access_profiles SET name='renamed' WHERE name='owner-source'").await?;
        writer_waits(&db, &selection, "UPDATE platform_credentials SET account_hint='Changed public metadata' WHERE display_name='Owner source'").await?;
        writer_waits(&db, &selection, "UPDATE org_members SET role='owner' WHERE id='owner-source-member'").await?;
        writer_waits(&db, &selection, "DELETE FROM oidc_access_tokens WHERE client_id='owner-source-client'").await?;
        // The original object cannot substitute a newly authenticated token or
        // bypass original-token deletion on the next transaction.
        let store = profiles(&db.pool);
        let mut tx = store.begin_transaction().await?;
        ensure!(selection.authority.lock_for_publication(&mut tx).await == Err(OAuthBearerAuthorityError::Denied));
        tx.rollback().await?;
        ensure!(selection.provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        no_platform_runtime_rows(&db.pool).await
    }.await;
    db.finish(result).await
}
