//! Synthetic PostgreSQL acceptance for material-free profile and binding authority.
//! Run explicitly with --ignored; an absent TEST_DATABASE_URL is a failure.

#[allow(dead_code)]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, ensure};
use codewire_access::{
    AccessProfile, AccessProfileName, CapabilitySlot, CredentialAuthKind as Kind, CredentialId,
    EnvironmentAccessBinding, EnvironmentId, GrantContext, GrantPlacement, Owner, Placement,
    ProviderCatalog, builtin_provider_catalog,
};
use codewire_platform_credentials::{
    PlatformAccessProfileStore, PlatformCredentialError as CredentialError,
    PlatformProfileError as Error,
};
use codewire_server_core::org_deletion::begin_organization_deletion;
use support::*;

fn name(value: &str) -> AccessProfileName {
    AccessProfileName::parse(value).expect("synthetic profile name")
}

fn entries(id: &CredentialId) -> BTreeMap<CapabilitySlot, CredentialId> {
    BTreeMap::from([(CapabilitySlot::codex(), id.clone())])
}

fn profiles(db: &TestDatabase) -> PlatformAccessProfileStore {
    PlatformAccessProfileStore::new(db.pool.clone(), builtin_provider_catalog())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn pending_binding_admission_is_metadata_only_atomic_and_cannot_derive_runtime_grants()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("pending-user").await?;
        let org = db.organization("pending-org").await?;
        let provider = Arc::new(SyntheticKek::default());
        let record = db.store(provider.clone()).create(&user, registration("Pending", Kind::OAuth), &value(OLD_VALUE)).await?;
        let mut context = environment(&db, &user, &org, "pending-environment", std::slice::from_ref(&record.metadata.id)).await?;
        sqlx::query("UPDATE environments SET state='pending', environment_operation_generation=0 WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        context.environment_generation = 0;
        let profiles = profiles(&db);
        let profile = profiles.create(&user, name("pending"), entries(&record.metadata.id)).await?;
        let selected = binding(&context, &profile);

        let mut tx = profiles.begin_transaction().await?;
        ensure!(profiles.resolve_in(&mut tx, &user, &name("pending")).await? == profile);
        ensure!(profiles.get_in(&mut tx, &user, &profile.id, Some(1)).await? == profile);
        ensure!(profiles.create_pending_binding_in(&mut tx, &context, selected.clone(), None).await == Err(Error::UnsupportedEntry));
        tx.rollback().await?;

        // A caller failure after the binding write must roll back every composed
        // write; the helper neither commits nor creates a separate generation.
        let mut tx = profiles.begin_transaction().await?;
        profiles.create_pending_binding_in(&mut tx, &context, selected.clone(), Some(user.id())).await?;
        sqlx::query("INSERT INTO environment_access(environment_id,user_id,permission,granted_by) VALUES ($1,$2,'owner',$2)")
            .bind(context.environment_id.as_str()).bind(user.id().as_str()).execute(&mut *tx).await?;
        tx.rollback().await?;
        let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM platform_environment_access_bindings), (SELECT count(*) FROM environment_access)")
            .fetch_one(&db.pool).await?;
        ensure!(counts == (0,0));

        let mut tx = profiles.begin_transaction().await?;
        profiles.create_pending_binding_in(&mut tx, &context, selected.clone(), Some(user.id())).await?;
        tx.commit().await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::InvalidInput));
        ensure!(profiles.create_binding(&context, selected.clone(), Some(user.id())).await == Err(Error::InvalidInput));
        let mut future = context.clone(); future.environment_generation = 1;
        ensure!(profiles.evaluate_grants(&future).await == Err(Error::StaleEnvironment));
        let mut tx = profiles.begin_transaction().await?;
        ensure!(profiles.create_pending_binding_in(&mut tx, &future, selected.clone(), Some(user.id())).await == Err(Error::InvalidInput));
        tx.rollback().await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=1 WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&future).await == Err(Error::StaleEnvironment));
        sqlx::query("UPDATE environments SET state='running' WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&future).await?.grants.len() == 1);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0, "metadata admission unwrapped protected material");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn pending_binding_rechecks_credential_policy_owner_and_exact_pending_state() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("pending-policy-user").await?;
        let org = db.organization("pending-policy-org").await?;
        let stranger = db.user("pending-stranger").await?;
        let record = db.store(Arc::new(SyntheticKek::default())).create(&user, registration("Pending policy", Kind::OAuth), &value(OLD_VALUE)).await?;
        let mut context = environment(&db, &user, &org, "pending-policy-environment", std::slice::from_ref(&record.metadata.id)).await?;
        context.environment_generation = 0;
        sqlx::query("UPDATE environments SET state='pending', environment_operation_generation=0 WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        let profiles = profiles(&db);
        let profile = profiles.create(&user, name("policy"), entries(&record.metadata.id)).await?;
        let selected = binding(&context, &profile);
        // A selected credential that needs Reconnect does not block creation:
        // only its capability is unavailable until the owner reconnects it.
        for (status, expires) in [
            ("revoked", None), ("refresh_failed", None), ("expired", None), ("active", Some(0_i64)),
        ] {
            sqlx::query("UPDATE platform_credentials SET status=$2,expires_at_unix=$3 WHERE id=$1")
                .bind(record.metadata.id.as_str()).bind(status).bind(expires).execute(&db.pool).await?;
            let mut tx = profiles.begin_transaction().await?;
            ensure!(profiles.create_pending_binding_in(&mut tx, &context, selected.clone(), Some(user.id())).await? == selected);
            tx.rollback().await?;
        }
        sqlx::query("UPDATE platform_credentials SET status='active',expires_at_unix=NULL WHERE id=$1")
            .bind(record.metadata.id.as_str()).execute(&db.pool).await?;
        for (changed, expected) in [
            { let mut changed = context.clone(); changed.authorized_credentials.clear(); (changed, Error::UnsupportedEntry) },
            { let mut changed = context.clone(); changed.allow_personal_credentials = false; (changed, Error::UnsupportedEntry) },
            { let mut changed = context.clone(); changed.user_id = stranger.id().clone(); (changed, Error::NotFound) },
        ] {
            let mut tx = profiles.begin_transaction().await?;
            ensure!(profiles.create_pending_binding_in(&mut tx, &changed, selected.clone(), Some(user.id())).await == Err(expected));
            tx.rollback().await?;
        }
        for (state, desired) in [("running","started"), ("stopped","stopped"), ("pending","destroyed")] {
            sqlx::query("UPDATE environments SET state=$2,desired_state=$3 WHERE id=$1")
                .bind(context.environment_id.as_str()).bind(state).bind(desired).execute(&db.pool).await?;
            let mut tx = profiles.begin_transaction().await?;
            ensure!(profiles.create_pending_binding_in(&mut tx, &context, selected.clone(), Some(user.id())).await == Err(Error::StaleEnvironment));
            tx.rollback().await?;
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings").fetch_one(&db.pool).await?;
        ensure!(count == 0);
        Ok(())
    }.await;
    db.finish(result).await
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
    organization: &Owner,
    id: &str,
    credentials: &[CredentialId],
) -> Result<GrantContext> {
    sqlx::query(
        r#"INSERT INTO environment_presets(id,org_id,name,slug,project_spec)
           VALUES ($1,$2,$1,$1,'{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(format!("preset-{id}"))
    .bind(organization.id().as_str())
    .execute(&db.pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,
         environment_operation_generation,project_spec)
         VALUES ($1,$2,$3,'sandbox',$4,'running','started',7,
                 '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(id)
    .bind(organization.id().as_str())
    .bind(user.id().as_str())
    .bind(format!("preset-{id}"))
    .execute(&db.pool)
    .await?;
    Ok(GrantContext {
        environment_id: EnvironmentId::parse(id)?,
        environment_generation: 7,
        placement: GrantPlacement::Platform,
        user_id: user.id().clone(),
        organization_id: Some(organization.id().clone()),
        allow_personal_credentials: true,
        authorized_credentials: credentials.iter().cloned().collect(),
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn profiles_are_exact_owner_scoped_and_use_only_explicit_catalog_metadata() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("same-owner-text").await?;
        let org = db.organization("same-owner-text").await?;
        let stranger = db.user("stranger").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let personal = store
            .create(
                &user,
                registration("Personal", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let shared = store
            .create(
                &org,
                registration("Shared", Kind::ApiKey),
                &value(NEW_VALUE),
            )
            .await?;
        let profiles = profiles(&db);
        let first = profiles
            .create(&user, name("work"), entries(&personal.metadata.id))
            .await?;
        let organization = profiles
            .create(&org, name("work"), entries(&shared.metadata.id))
            .await?;
        ensure!(first.owner == user && organization.owner == org);
        ensure!(first.placement == Placement::Platform && first.revision == 1);
        ensure!(profiles.resolve(&user, &name("work")).await? == first);
        ensure!(profiles.resolve(&org, &name("work")).await? == organization);
        ensure!(
            profiles.create(&user, name("work"), BTreeMap::new()).await
                == Err(Error::AlreadyExists)
        );
        for wrong in [&org, &stranger] {
            ensure!(profiles.get(wrong, &first.id).await == Err(Error::NotFound));
            ensure!(profiles.get_revision(wrong, &first.id, 1).await == Err(Error::NotFound));
            ensure!(
                profiles.update(wrong, &first.id, 1, BTreeMap::new()).await == Err(Error::NotFound)
            );
            ensure!(profiles.delete(wrong, &first.id, 1).await == Err(Error::NotFound));
        }
        // Shared validation permits some cross-owner platform cases; this first
        // platform flow deliberately admits only exact same-owner selections.
        ensure!(
            profiles
                .create(&user, name("cross-owner"), entries(&shared.metadata.id))
                .await
                == Err(Error::NotFound)
        );
        ensure!(
            profiles
                .create(&org, name("cross-owner"), entries(&personal.metadata.id))
                .await
                == Err(Error::NotFound)
        );
        ensure!(
            profiles
                .create(
                    &stranger,
                    name("cross-user"),
                    entries(&personal.metadata.id)
                )
                .await
                == Err(Error::NotFound)
        );
        let bad_slot = BTreeMap::from([(CapabilitySlot::github(), personal.metadata.id.clone())]);
        ensure!(
            profiles.create(&user, name("wrong-slot"), bad_slot).await
                == Err(Error::UnsupportedEntry)
        );
        let empty_catalog =
            PlatformAccessProfileStore::new(db.pool.clone(), ProviderCatalog::default());
        ensure!(
            empty_catalog
                .create(&user, name("disabled"), entries(&personal.metadata.id))
                .await
                == Err(Error::UnsupportedEntry)
        );
        let second = profiles
            .create(&user, name("empty"), BTreeMap::new())
            .await?;
        let page = profiles.list(&user, None, 1).await?;
        let next = profiles.list(&user, Some(&page[0].id), 1).await?;
        ensure!(next.len() == 1 && next[0].id > page[0].id);
        ensure!(profiles.list(&user, Some(&next[0].id), 1).await?.is_empty());
        ensure!(profiles.list(&stranger, None, 10).await?.is_empty());
        ensure!(profiles.list(&user, None, 0).await == Err(Error::InvalidInput));
        ensure!(profiles.list(&user, None, 1001).await == Err(Error::InvalidInput));
        ensure!(profiles.get_revision(&user, &second.id, 0).await == Err(Error::InvalidInput));
        ensure!(
            profiles
                .update(&user, &second.id, i64::MAX as u64, BTreeMap::new())
                .await
                == Err(Error::InvalidInput)
        );
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        for profile in [&first, &organization, &second] {
            let serialized = serde_json::to_string(profile)?;
            let debug = format!("{profile:?}");
            for forbidden in [
                "ciphertext",
                "wrapped_dek",
                "material_generation",
                "protected_entry",
                std::str::from_utf8(OLD_VALUE)?,
            ] {
                ensure!(!serialized.contains(forbidden) && !debug.contains(forbidden));
            }
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn concurrent_profile_cas_preserves_immutable_bound_revision_until_explicit_rebind()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("revision-user").await?;
        let org = db.organization("revision-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let first = store
            .create(&user, registration("First", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let second = store
            .create(
                &user,
                registration("Second", Kind::OAuth),
                &value(NEW_VALUE),
            )
            .await?;
        let context = environment(
            &db,
            &user,
            &org,
            "revision-env",
            &[first.metadata.id.clone(), second.metadata.id.clone()],
        )
        .await?;
        let profiles = profiles(&db);
        let original = profiles
            .create(&user, name("work"), entries(&first.metadata.id))
            .await?;
        let selected = profiles
            .create_binding(
                &context,
                binding(&context, &original),
                Some(&context.user_id),
            )
            .await?;
        let (left, right) = tokio::join!(
            profiles.update(&user, &original.id, 1, entries(&second.metadata.id)),
            profiles.update(&user, &original.id, 1, BTreeMap::new()),
        );
        ensure!(left.is_ok() != right.is_ok());
        let updated = match (left, right) {
            (Ok(profile), Err(Error::StaleRevision)) | (Err(Error::StaleRevision), Ok(profile)) => {
                profile
            }
            _ => anyhow::bail!("profile CAS did not have exactly one winner"),
        };
        ensure!(updated.revision == 2);
        ensure!(profiles.get(&user, &original.id).await? == updated);
        ensure!(profiles.get_revision(&user, &original.id, 1).await? == original);
        ensure!(profiles.get_revision(&user, &original.id, 3).await == Err(Error::NotFound));
        ensure!(profiles.get_binding(&context).await? == selected);
        let old_grants = profiles.evaluate_grants(&context).await?.grants;
        ensure!(
            old_grants.len() == 1
                && old_grants[0].credential_id == first.metadata.id
                && old_grants[0]
                    .profile
                    .as_ref()
                    .is_some_and(|profile| profile.revision == 1)
        );
        let replacement = binding(&context, &updated);
        profiles
            .replace_binding(
                &context,
                &selected,
                replacement.clone(),
                Some(&context.user_id),
            )
            .await?;
        ensure!(profiles.get_binding(&context).await? == replacement);
        let new_grants = profiles.evaluate_grants(&context).await?.grants;
        ensure!(new_grants.len() == updated.entries.len());
        ensure!(new_grants.iter().all(|grant| {
            grant
                .profile
                .as_ref()
                .is_some_and(|profile| profile.revision == 2)
                && grant.credential_id == second.metadata.id
        }));
        ensure!(
            profiles
                .replace_binding(
                    &context,
                    &selected,
                    selected.clone(),
                    Some(&context.user_id)
                )
                .await
                == Err(Error::StaleBinding)
        );
        ensure!(profiles.delete_binding(&context, &selected).await == Err(Error::StaleBinding));
        profiles.delete_binding(&context, &replacement).await?;
        // An explicit old revision selection is supported, never an implicit rebind.
        profiles
            .create_binding(&context, selected.clone(), Some(&context.user_id))
            .await?;
        ensure!(profiles.evaluate_grants(&context).await?.grants == old_grants);
        let generations: (i64, i64) = sqlx::query_as(
            "SELECT environment_operation_generation, \
             (SELECT count(*) FROM platform_access_profile_revisions WHERE profile_id=$2) \
             FROM environments WHERE id=$1",
        )
        .bind(context.environment_id.as_str())
        .bind(original.id.as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(generations == (7, 2));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn binding_requires_exact_authorized_scope_operation_and_running_runtime() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("scope-user").await?;
        let other_user = db.user("other-user").await?;
        let org = db.organization("scope-org").await?;
        let other_org = db.organization("other-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let credential = store.create(&user, registration("Scope", Kind::OAuth), &value(OLD_VALUE)).await?;
        let context = environment(&db, &user, &org, "scope-env", std::slice::from_ref(&credential.metadata.id)).await?;
        let profiles = profiles(&db);
        let profile = profiles.create(&user, name("work"), entries(&credential.metadata.id)).await?;
        let selected = binding(&context, &profile);
        let mut bad = context.clone();
        bad.user_id = other_user.id().clone();
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::NotFound));
        bad = context.clone(); bad.organization_id = Some(other_org.id().clone());
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::NotFound));
        bad = context.clone(); bad.environment_generation = 6;
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::StaleEnvironment));
        bad.environment_generation = 0;
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::InvalidInput));
        bad = context.clone(); bad.placement = GrantPlacement::Local;
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::InvalidInput));
        bad = context.clone(); bad.organization_id = None;
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::InvalidInput));
        bad = context.clone(); bad.authorized_credentials.clear();
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::UnsupportedEntry));
        bad = context.clone(); bad.allow_personal_credentials = false;
        ensure!(profiles.create_binding(&bad, selected.clone(), Some(&bad.user_id)).await == Err(Error::UnsupportedEntry));
        let mut wrong_binding = selected.clone();
        wrong_binding.environment_id = EnvironmentId::parse("other-environment")?;
        ensure!(profiles.create_binding(&context, wrong_binding, Some(&context.user_id)).await == Err(Error::InvalidInput));
        let foreign_profile = profiles.create(&other_org, name("foreign"), BTreeMap::new()).await?;
        ensure!(profiles.create_binding(&context, binding(&context, &foreign_profile), Some(&context.user_id)).await == Err(Error::NotFound));
        // Configuration is allowed while stopped, but cannot authorize runtime use.
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        profiles.create_binding(&context, selected.clone(), Some(&context.user_id)).await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::StaleEnvironment));
        sqlx::query("UPDATE environments SET state='running',desired_state='started',environment_operation_generation=8 WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::StaleEnvironment));
        ensure!(profiles.delete_binding(&context, &selected).await == Err(Error::StaleEnvironment));
        let mut current = context.clone(); current.environment_generation = 8;
        ensure!(profiles.evaluate_grants(&current).await?.grants[0].environment_generation == 8);
        sqlx::query("UPDATE environments SET desired_state='destroyed' WHERE id=$1")
            .bind(context.environment_id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&current).await == Err(Error::StaleEnvironment));
        ensure!(profiles.replace_binding(&current, &selected, selected.clone(), Some(&current.user_id)).await == Err(Error::StaleEnvironment));
        ensure!(profiles.get_binding(&current).await == Err(Error::StaleEnvironment));
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn binding_cas_and_each_runtime_admission_recheck_credentials_and_catalog() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("admission-user").await?;
        let org = db.organization("admission-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let credential = store.create(&org, registration("Shared", Kind::ApiKey), &value(OLD_VALUE)).await?;
        let mut context = environment(&db, &user, &org, "admission-env", std::slice::from_ref(&credential.metadata.id)).await?;
        context.allow_personal_credentials = false;
        let profiles = profiles(&db);
        let profile = profiles.create(&org, name("work"), entries(&credential.metadata.id)).await?;
        let empty_a = profiles.create(&org, name("empty-a"), BTreeMap::new()).await?;
        let empty_b = profiles.create(&org, name("empty-b"), BTreeMap::new()).await?;
        let selected = profiles.create_binding(&context, binding(&context, &profile), None).await?;
        ensure!(profiles.create_binding(&context, selected.clone(), None).await == Err(Error::AlreadyExists));
        let initial = profiles.evaluate_grants(&context).await?.grants;
        ensure!(initial.len() == 1 && initial[0].credential_revocation_generation == 1);
        let (left, right) = tokio::join!(
            profiles.replace_binding(&context, &selected, binding(&context, &empty_a), None),
            profiles.replace_binding(&context, &selected, binding(&context, &empty_b), None),
        );
        let winner = match (left, right) {
            (Ok(binding), Err(Error::StaleBinding)) | (Err(Error::StaleBinding), Ok(binding)) => binding,
            _ => anyhow::bail!("binding CAS did not have exactly one winner"),
        };
        profiles.replace_binding(&context, &winner, selected.clone(), None).await?;
        let no_catalog = PlatformAccessProfileStore::new(db.pool.clone(), ProviderCatalog::default());
        ensure!(no_catalog.evaluate_grants(&context).await == Err(Error::UnsupportedEntry));
        let mut unauthorized = context.clone(); unauthorized.authorized_credentials = BTreeSet::new();
        ensure!(profiles.evaluate_grants(&unauthorized).await == Err(Error::UnsupportedEntry));
        // A credential needing Reconnect withholds only its own capability: the
        // admission names that slot, grants nothing for it, and rebinding the
        // same selection stays possible. No lifecycle state reaches a grant.
        for (status, expires) in [
            ("revoked", None), ("refresh_failed", None), ("expired", None), ("active", Some(0_i64)),
        ] {
            sqlx::query("UPDATE platform_credentials SET status=$2,expires_at_unix=$3 WHERE id=$1")
                .bind(credential.metadata.id.as_str()).bind(status).bind(expires).execute(&db.pool).await?;
            let admitted = profiles.evaluate_grants(&context).await?;
            ensure!(admitted.grants.is_empty());
            ensure!(admitted.reconnect_required
                == BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]));
            ensure!(profiles.replace_binding(&context, &selected, selected.clone(), None).await? == selected);
        }
        sqlx::query("UPDATE platform_credentials SET status='active',expires_at_unix=NULL,revocation_generation=2 WHERE id=$1")
            .bind(credential.metadata.id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&context).await?.grants[0].credential_revocation_generation == 2);
        // Simulate corruption outside the authority API: reads still fail closed.
        sqlx::query("DELETE FROM platform_credentials WHERE id=$1")
            .bind(credential.metadata.id.as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::NotFound));
        ensure!(profiles.get_revision(&org, &profile.id, 1).await? == profile);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn credential_deletion_fences_current_and_bound_revisions_but_not_unused_history()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("deletion-user").await?;
        let org = db.organization("deletion-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let credential = store
            .create(
                &user,
                registration("Selected", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let context = environment(
            &db,
            &user,
            &org,
            "deletion-env",
            std::slice::from_ref(&credential.metadata.id),
        )
        .await?;
        let profiles = profiles(&db);
        let profile = profiles
            .create(&user, name("work"), entries(&credential.metadata.id))
            .await?;
        let selected = profiles
            .create_binding(
                &context,
                binding(&context, &profile),
                Some(&context.user_id),
            )
            .await?;
        let revoked = store
            .revoke(&user, &credential.metadata.id, credential.version)
            .await?;
        ensure!(
            store
                .delete_revoked(&user, &credential.metadata.id, revoked.version)
                .await
                == Err(CredentialError::CredentialInUse)
        );
        let empty = profiles
            .update(&user, &profile.id, 1, BTreeMap::new())
            .await?;
        ensure!(
            store
                .delete_revoked(&user, &credential.metadata.id, revoked.version)
                .await
                == Err(CredentialError::CredentialInUse)
        );
        ensure!(profiles.delete(&user, &profile.id, 1).await == Err(Error::StaleRevision));
        ensure!(profiles.delete(&user, &profile.id, 2).await == Err(Error::ProfileInUse));
        profiles.delete_binding(&context, &selected).await?;
        store
            .delete_revoked(&user, &credential.metadata.id, revoked.version)
            .await?;
        ensure!(profiles.get_revision(&user, &profile.id, 1).await? == profile);
        ensure!(
            profiles
                .create_binding(&context, selected, Some(&context.user_id))
                .await
                == Err(Error::NotFound)
        );
        profiles
            .create_binding(&context, binding(&context, &empty), Some(&context.user_id))
            .await?;
        ensure!(profiles.evaluate_grants(&context).await?.grants.is_empty());
        profiles
            .delete_binding(&context, &binding(&context, &empty))
            .await?;
        profiles.delete(&user, &profile.id, 2).await?;
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM platform_access_profile_revisions), \
             (SELECT count(*) FROM platform_access_profile_entries)",
        )
        .fetch_one(&db.pool)
        .await?;
        ensure!(counts == (0, 0));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn profile_publication_holds_credential_and_owner_fences_against_deletion() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        const BARRIER: i32 = 19_220_019;
        let org = db.organization("publication-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let credential = store.create(&org, registration("Revoked selection", Kind::ApiKey), &value(OLD_VALUE)).await?;
        let revoked = store.revoke(&org, &credential.metadata.id, credential.version).await?;
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION pause_profile_publication() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_advisory_xact_lock({BARRIER}::bigint); RETURN NEW; END $$; \
             CREATE TRIGGER pause_profile_publication BEFORE INSERT ON platform_access_profile_entries \
             FOR EACH ROW EXECUTE FUNCTION pause_profile_publication();"
        )).execute(&db.pool).await?;
        let mut blocker = db.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)").bind(i64::from(BARRIER)).execute(&mut *blocker).await?;
        let task = {
            let profiles = profiles(&db); let org = org.clone(); let id = credential.metadata.id.clone();
            tokio::spawn(async move { profiles.create(&org, name("work"), entries(&id)).await })
        };
        wait_for_advisory_waiter(&db.pool, BARRIER).await?;
        for statement in [
            "UPDATE organizations SET name=name WHERE id=$1",
            "UPDATE platform_credentials SET status=status WHERE organization_id=$1",
        ] {
            let mut contender = db.pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='150ms'").execute(&mut *contender).await?;
            let error = sqlx::query(statement).bind(org.id().as_str()).execute(&mut *contender).await.err()
                .context("profile publication released an authority fence before commit")?;
            ensure!(error.as_database_error().and_then(|error| error.code()).as_deref() == Some("55P03"));
            contender.rollback().await?;
        }
        let deleting = {
            let store = store.clone(); let org = org.clone(); let id = credential.metadata.id.clone();
            tokio::spawn(async move { store.delete_revoked(&org, &id, revoked.version).await })
        };
        blocker.commit().await?;
        let profile = tokio::time::timeout(HANG_GUARD, task).await???;
        ensure!(tokio::time::timeout(HANG_GUARD, deleting).await?? == Err(CredentialError::CredentialInUse));
        begin_organization_deletion(&db.pool, &admin_user(), org.id().as_str()).await?;
        let profiles = profiles(&db);
        ensure!(profiles.get(&org, &profile.id).await == Err(Error::NotFound));
        ensure!(profiles.create(&org, name("late"), BTreeMap::new()).await == Err(Error::NotFound));
        ensure!(profiles.update(&org, &profile.id, 1, BTreeMap::new()).await == Err(Error::NotFound));
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn profile_authority_role_cannot_read_material_or_call_a_provider() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("material-blind-user").await?;
        let org = db.organization("material-blind-org").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let credential = store.create(&user, registration("Metadata only", Kind::OAuth), &value(OLD_VALUE)).await?;
        let context = environment(&db, &user, &org, "material-blind-env", std::slice::from_ref(&credential.metadata.id)).await?;
        let (pool, role) = db.metadata_pool().await?;
        for statement in [
            format!("GRANT SELECT,INSERT,UPDATE,DELETE ON platform_access_profiles,platform_access_profile_revisions,platform_access_profile_entries,platform_environment_access_bindings TO {}", quote_ident(&role)),
            format!("GRANT SELECT(id,created_by,org_id,environment_operation_generation,desired_state,state),UPDATE(id) ON environments TO {}", quote_ident(&role)),
            format!("GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text) TO {}", quote_ident(&role)),
            format!("GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text) TO {}", quote_ident(&role)),
            format!("GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text) TO {}", quote_ident(&role)),
            format!("GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text) TO {}", quote_ident(&role)),
        ] {
            sqlx::query(&statement).execute(&db.pool).await?;
        }
        let authority = PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog());
        let can_edit_owners: bool = sqlx::query_scalar(
            "SELECT pg_catalog.has_any_column_privilege(current_user,'public.users','UPDATE') \
             OR pg_catalog.has_any_column_privilege(current_user,'public.organizations','UPDATE') \
             OR pg_catalog.has_any_column_privilege(current_user,'public.platform_credentials','UPDATE')",
        ).fetch_one(&pool).await?;
        ensure!(!can_edit_owners);
        let original = authority.create(&user, name("work"), entries(&credential.metadata.id)).await?;
        let selected = authority.create_binding(&context, binding(&context, &original), Some(&context.user_id)).await?;
        ensure!(authority.evaluate_grants(&context).await?.grants.len() == 1);
        ensure!(authority.get(&user, &original.id).await? == original);
        let empty = authority.update(&user, &original.id, 1, BTreeMap::new()).await?;
        ensure!(authority.get_revision(&user, &original.id, 1).await? == original);
        authority.replace_binding(&context, &selected, binding(&context, &empty), Some(&context.user_id)).await?;
        authority.delete_binding(&context, &binding(&context, &empty)).await?;
        authority.delete(&user, &original.id, 2).await?;
        for sql in [
            "SELECT ciphertext FROM public.platform_credential_material",
            "SELECT ciphertext FROM public.platform_credential_refresh_material",
            "UPDATE public.platform_credentials SET id=id WHERE false",
            "UPDATE public.platform_credentials SET status='revoked' WHERE false",
            "DELETE FROM public.platform_credentials WHERE false",
            "INSERT INTO public.platform_credentials(id) VALUES ('forbidden')",
            "SELECT id FROM public.platform_credentials FOR SHARE",
            "ALTER FUNCTION public.codewire_platform_lock_credential(text,text,text) SECURITY INVOKER",
        ] {
            let denied = sqlx::query(sql).execute(&pool).await.err()
                .context("profile authority gained credential lifecycle or material authority")?;
            ensure!(denied.as_database_error().and_then(|error| error.code()).as_deref() == Some("42501"));
        }
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == 1);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_and_environment_deletion_cascade_profile_history_without_cross_scope_effects()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("cascade-profile-user").await?;
        let org = db.organization("cascade-profile-org").await?;
        let survivor = db.user("survivor-profile-user").await?;
        let profiles = profiles(&db);
        let personal = profiles
            .create(&user, name("personal"), BTreeMap::new())
            .await?;
        let shared = profiles
            .create(&org, name("shared"), BTreeMap::new())
            .await?;
        let retained = profiles
            .create(&survivor, name("retained"), BTreeMap::new())
            .await?;
        let personal_context = environment(&db, &user, &org, "cascade-personal-env", &[]).await?;
        let shared_context = environment(&db, &user, &org, "cascade-shared-env", &[]).await?;
        profiles
            .create_binding(
                &personal_context,
                binding(&personal_context, &personal),
                Some(&personal_context.user_id),
            )
            .await?;
        profiles
            .create_binding(&shared_context, binding(&shared_context, &shared), None)
            .await?;
        let denied = sqlx::query("DELETE FROM platform_access_profiles WHERE id=$1")
            .bind(shared.id.as_str())
            .execute(&db.pool)
            .await
            .err()
            .context("database allowed deletion of a bound profile")?;
        ensure!(
            denied
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23503")
        );
        // Existing organization teardown deletes environments and presets
        // first. Their canonical NO ACTION owner FKs are not new cascades.
        for context in [&personal_context, &shared_context] {
            sqlx::query("DELETE FROM environments WHERE id=$1")
                .bind(context.environment_id.as_str())
                .execute(&db.pool)
                .await?;
            sqlx::query("DELETE FROM environment_presets WHERE id=$1")
                .bind(format!("preset-{}", context.environment_id.as_str()))
                .execute(&db.pool)
                .await?;
        }
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org.id().as_str())
            .execute(&db.pool)
            .await?;
        ensure!(profiles.get(&org, &shared.id).await == Err(Error::NotFound));
        ensure!(profiles.get(&user, &personal.id).await? == personal);
        let bindings: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
                .fetch_one(&db.pool)
                .await?;
        ensure!(bindings == 0);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id().as_str())
            .execute(&db.pool)
            .await?;
        ensure!(profiles.get(&user, &personal.id).await == Err(Error::NotFound));
        ensure!(profiles.get(&survivor, &retained.id).await? == retained);
        let histories: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_access_profile_revisions")
                .fetch_one(&db.pool)
                .await?;
        ensure!(histories == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn personal_binding_requires_explicit_owner_confirmation_and_current_policy() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("consent-user").await?;
        let other = db.user("consent-other").await?;
        let org = db.organization("consent-org").await?;
        let record = db.store(Arc::new(SyntheticKek::default()))
            .create(&user, registration("Personal", Kind::OAuth), &value(OLD_VALUE)).await?;
        let context = environment(&db, &user, &org, "consent-env", std::slice::from_ref(&record.metadata.id)).await?;
        let profiles = profiles(&db);
        let profile = profiles.create(&user, name("work"), entries(&record.metadata.id)).await?;
        let selected = binding(&context, &profile);
        // Enrollment and the existing allow-personal policy are not consent.
        for confirmation in [None, Some(other.id())] {
            ensure!(profiles.create_binding(&context, selected.clone(), confirmation).await == Err(Error::UnsupportedEntry));
            ensure!(profiles.get_binding_metadata(&context).await == Err(Error::NotFound));
        }
        // A valid profile can be inspected/cleared without retroactively granting
        // it access. This models absent or externally corrupted confirmation.
        sqlx::query("INSERT INTO platform_environment_access_bindings(environment_id,profile_id,profile_revision) VALUES ($1,$2,$3)")
            .bind(context.environment_id.as_str()).bind(profile.id.as_str()).bind(1_i64).execute(&db.pool).await?;
        let metadata = profiles.get_binding_metadata(&context).await?;
        ensure!(metadata.binding == selected && metadata.personal_owner_confirmed_by.is_none());
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::UnsupportedEntry));
        sqlx::query("UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by=$2 WHERE environment_id=$1")
            .bind(context.environment_id.as_str()).bind(other.id().as_str()).execute(&db.pool).await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::UnsupportedEntry));
        profiles.replace_binding(&context, &selected, selected.clone(), Some(user.id())).await?;
        let metadata = profiles.get_binding_metadata(&context).await?;
        ensure!(metadata.personal_owner_confirmed_by.as_ref() == Some(user.id()));
        ensure!(profiles.evaluate_grants(&context).await?.grants.len() == 1);
        let mut denied = context.clone();
        denied.allow_personal_credentials = false;
        ensure!(profiles.evaluate_grants(&denied).await == Err(Error::UnsupportedEntry));
        ensure!(profiles.replace_binding(&denied, &selected, selected.clone(), Some(user.id())).await == Err(Error::UnsupportedEntry));
        denied = context.clone();
        denied.authorized_credentials.clear();
        ensure!(profiles.evaluate_grants(&denied).await == Err(Error::UnsupportedEntry));
        // Inspection and clear are metadata management, not material admission.
        profiles.delete_binding(&denied, &selected).await?;
        ensure!(profiles.get_binding_metadata(&context).await == Err(Error::NotFound));
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn personal_confirmation_is_exact_to_each_rebind_and_disappears_on_clear() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("reconfirm-user").await?;
        let org = db.organization("reconfirm-org").await?;
        let context = environment(&db, &user, &org, "reconfirm-env", &[]).await?;
        let profiles = profiles(&db);
        let personal = profiles
            .create(&user, name("personal"), BTreeMap::new())
            .await?;
        let shared = profiles
            .create(&org, name("shared"), BTreeMap::new())
            .await?;
        let selected = profiles
            .create_binding(&context, binding(&context, &personal), Some(user.id()))
            .await?;
        let old_metadata = profiles.get_binding_metadata(&context).await?;
        let next = profiles
            .update(&user, &personal.id, 1, BTreeMap::new())
            .await?;
        ensure!(profiles.get_binding_metadata(&context).await? == old_metadata);
        for replacement in [selected.clone(), binding(&context, &next)] {
            ensure!(
                profiles
                    .replace_binding(&context, &selected, replacement, None)
                    .await
                    == Err(Error::UnsupportedEntry)
            );
            ensure!(profiles.get_binding_metadata(&context).await? == old_metadata);
        }
        let current = profiles
            .replace_binding(
                &context,
                &selected,
                binding(&context, &next),
                Some(user.id()),
            )
            .await?;
        ensure!(
            profiles
                .replace_binding(&context, &selected, selected.clone(), Some(user.id()))
                .await
                == Err(Error::StaleBinding)
        );
        let shared_binding = binding(&context, &shared);
        // Organization access cannot inherit or manufacture personal consent.
        ensure!(
            profiles
                .replace_binding(&context, &current, shared_binding.clone(), Some(user.id()))
                .await
                == Err(Error::UnsupportedEntry)
        );
        profiles
            .replace_binding(&context, &current, shared_binding.clone(), None)
            .await?;
        let shared_metadata = profiles.get_binding_metadata(&context).await?;
        ensure!(
            shared_metadata.binding == shared_binding
                && shared_metadata.personal_owner_confirmed_by.is_none()
        );
        ensure!(
            profiles
                .replace_binding(&context, &shared_binding, selected.clone(), None)
                .await
                == Err(Error::UnsupportedEntry)
        );
        profiles
            .replace_binding(&context, &shared_binding, selected.clone(), Some(user.id()))
            .await?;
        profiles.delete_binding(&context, &selected).await?;
        ensure!(
            profiles.create_binding(&context, selected, None).await == Err(Error::UnsupportedEntry)
        );
        ensure!(profiles.get_binding_metadata(&context).await == Err(Error::NotFound));
        let generation: i64 = sqlx::query_scalar(
            "SELECT environment_operation_generation FROM environments WHERE id=$1",
        )
        .bind(context.environment_id.as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(generation == 7);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[test]
fn profile_errors_have_no_value_or_upstream_source() {
    for error in [
        Error::InvalidInput,
        Error::NotFound,
        Error::AlreadyExists,
        Error::StaleRevision,
        Error::StaleBinding,
        Error::StaleEnvironment,
        Error::UnsupportedEntry,
        Error::InactiveCredential,
        Error::ExpiredCredential,
        Error::ProfileInUse,
        Error::CorruptRecord,
        Error::DatabaseUnavailable,
        Error::ClockUnavailable,
    ] {
        assert!(error.source().is_none());
        let display = error.to_string();
        let debug = format!("{error:?}");
        for forbidden in [OLD_VALUE, NEW_VALUE] {
            let forbidden = std::str::from_utf8(forbidden).expect("synthetic UTF-8 canary");
            assert!(!display.contains(forbidden) && !debug.contains(forbidden));
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn personal_profiles_include_github_without_ever_pinning_it() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("github-owner").await?;
        let org = db.organization("github-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let codex = store
            .create(&user, registration("Codex", Kind::OAuth), &value(OLD_VALUE))
            .await?;
        let profiles = profiles(&db);
        let personal = profiles
            .create(&user, name("work"), entries(&codex.metadata.id))
            .await?;
        ensure!(personal.includes_github() && personal.revision == 1);
        let empty = profiles
            .update(&user, &personal.id, 1, BTreeMap::new())
            .await?;
        ensure!(empty.includes_github() && empty.entries.is_empty() && empty.revision == 2);
        let shared = profiles
            .create(&org, name("shared"), BTreeMap::new())
            .await?;
        ensure!(!shared.includes_github());
        // GitHub is the account's one connection, never a pinned entry.
        ensure!(
            profiles
                .create(
                    &user,
                    name("pinned"),
                    BTreeMap::from([(CapabilitySlot::github(), codex.metadata.id.clone())]),
                )
                .await
                == Err(Error::UnsupportedEntry)
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn rename_relabels_the_profile_without_a_revision_or_rebinding() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("rename-user").await?;
        let org = db.organization("rename-org").await?;
        let stranger = db.user("rename-stranger").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let codex = store
            .create(
                &user,
                registration("Rename", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let context = environment(
            &db,
            &user,
            &org,
            "rename-env",
            std::slice::from_ref(&codex.metadata.id),
        )
        .await?;
        let profiles = profiles(&db);
        let original = profiles
            .create(&user, name("work"), entries(&codex.metadata.id))
            .await?;
        let other = profiles
            .create(&user, name("other"), BTreeMap::new())
            .await?;
        // Another owner's name never collides with this owner's profiles.
        profiles
            .create(&org, name("personal"), BTreeMap::new())
            .await?;
        let selected = profiles
            .create_binding(
                &context,
                binding(&context, &original),
                Some(&context.user_id),
            )
            .await?;
        let grants = profiles.evaluate_grants(&context).await?.grants;

        let work = name("work");
        // A name the owner already uses conflicts exactly as on create.
        ensure!(
            profiles
                .rename(&user, &original.id, 1, &work, name("other"))
                .await
                == Err(Error::AlreadyExists)
        );
        for wrong in [&org, &stranger] {
            ensure!(
                profiles
                    .rename(wrong, &original.id, 1, &work, name("taken"))
                    .await
                    == Err(Error::NotFound)
            );
        }
        ensure!(
            profiles
                .rename(&user, &original.id, 0, &work, name("personal"))
                .await
                == Err(Error::InvalidInput)
        );
        // A stale revision or a stale observed name is the same stale view.
        ensure!(
            profiles
                .rename(&user, &original.id, 2, &work, name("personal"))
                .await
                == Err(Error::StaleRevision)
        );
        ensure!(
            profiles
                .rename(&user, &original.id, 1, &name("other"), name("personal"))
                .await
                == Err(Error::StaleRevision)
        );
        ensure!(profiles.get(&user, &original.id).await? == original);
        // Renaming to the current name is a no-op.
        ensure!(
            profiles
                .rename(&user, &original.id, 1, &work, work.clone())
                .await?
                == original
        );

        let renamed = profiles
            .rename(&user, &original.id, 1, &work, name("personal"))
            .await?;
        ensure!(
            renamed
                == AccessProfile {
                    name: name("personal"),
                    ..original.clone()
                }
        );
        // A second rename prepared from the same view cannot overwrite it.
        ensure!(
            profiles
                .rename(&user, &original.id, 1, &work, name("team"))
                .await
                == Err(Error::StaleRevision)
        );
        ensure!(profiles.get(&user, &original.id).await? == renamed);
        ensure!(profiles.resolve(&user, &name("personal")).await? == renamed);
        ensure!(profiles.resolve(&user, &work).await == Err(Error::NotFound));
        // The name labels the profile, not a revision: history reads show it,
        // and the bound revision, its binding and its grants are unchanged.
        ensure!(profiles.get_revision(&user, &original.id, 1).await? == renamed);
        ensure!(profiles.get_binding(&context).await? == selected);
        ensure!(profiles.evaluate_grants(&context).await?.grants == grants);
        let revisions: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM platform_access_profile_revisions WHERE profile_id=$1), \
             (SELECT current_revision FROM platform_access_profiles WHERE id=$1)",
        )
        .bind(original.id.as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(revisions == (1, 1), "rename published a revision");
        ensure!(profiles.get(&user, &other.id).await? == other);

        // The old name is free again, and an edit still advances from the
        // revision the rename preserved; a rename then needs that new revision.
        profiles
            .create(&user, work.clone(), BTreeMap::new())
            .await?;
        let updated = profiles
            .update(&user, &original.id, 1, BTreeMap::new())
            .await?;
        ensure!(updated.revision == 2 && updated.name == name("personal"));
        let personal = name("personal");
        ensure!(
            profiles
                .rename(&user, &original.id, 1, &personal, name("later"))
                .await
                == Err(Error::StaleRevision)
        );
        // Two concurrent renames from one view: the row lock admits exactly one.
        let (left, right) = tokio::join!(
            profiles.rename(&user, &original.id, 2, &personal, name("alpha")),
            profiles.rename(&user, &original.id, 2, &personal, name("beta")),
        );
        let later = match (left, right) {
            (Ok(profile), Err(Error::StaleRevision)) | (Err(Error::StaleRevision), Ok(profile)) => {
                profile
            }
            _ => anyhow::bail!("profile rename did not have exactly one winner"),
        };
        ensure!(later.revision == 2 && later.entries.is_empty());
        ensure!(profiles.get(&user, &original.id).await? == later);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn no_organization_profile_selects_binds_or_admits_an_organization_oauth_credential()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("org-oauth-user").await?;
        let org = db.organization("org-oauth-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let api_key = store
            .create(&org, registration("Shared key", Kind::ApiKey), &value(OLD_VALUE))
            .await?;
        // A row written before organizations were refused OAuth; the store
        // itself no longer registers one.
        let legacy = store
            .create(&org, registration("Legacy login", Kind::ApiKey), &value(OLD_VALUE))
            .await?;
        sqlx::query("UPDATE platform_credentials SET authentication_kind='oauth' WHERE id=$1")
            .bind(legacy.metadata.id.as_str())
            .execute(&db.pool)
            .await?;
        let mut context = environment(
            &db,
            &user,
            &org,
            "org-oauth-env",
            &[api_key.metadata.id.clone(), legacy.metadata.id.clone()],
        )
        .await?;
        context.allow_personal_credentials = false;
        let profiles = profiles(&db);

        // Editing: no profile revision may select it.
        ensure!(
            profiles
                .create(&org, name("login"), entries(&legacy.metadata.id))
                .await
                == Err(Error::UnsupportedEntry)
        );
        let profile = profiles
            .create(&org, name("work"), entries(&api_key.metadata.id))
            .await?;
        ensure!(
            profiles
                .update(&org, &profile.id, 1, entries(&legacy.metadata.id))
                .await
                == Err(Error::UnsupportedEntry)
        );
        let selected = profiles
            .create_binding(&context, binding(&context, &profile), None)
            .await?;
        ensure!(profiles.evaluate_grants(&context).await?.grants.len() == 1);

        // A bound revision whose credential is an organization OAuth login is
        // refused as a whole at Sandbox creation, rebinding and runtime
        // admission. It is never a per-capability Reconnect.
        sqlx::query(
            "UPDATE platform_access_profile_entries SET credential_id=$2 WHERE profile_id=$1",
        )
        .bind(profile.id.as_str())
        .bind(legacy.metadata.id.as_str())
        .execute(&db.pool)
        .await?;
        ensure!(profiles.evaluate_grants(&context).await == Err(Error::UnsupportedEntry));
        ensure!(
            profiles
                .replace_binding(&context, &selected, selected.clone(), None)
                .await
                == Err(Error::UnsupportedEntry)
        );
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(context.environment_id.as_str())
            .execute(&db.pool)
            .await?;
        sqlx::query(
            "UPDATE environments SET state='pending', environment_operation_generation=0 WHERE id=$1",
        )
        .bind(context.environment_id.as_str())
        .execute(&db.pool)
        .await?;
        let mut pending = context.clone();
        pending.environment_generation = 0;
        let mut tx = profiles.begin_transaction().await?;
        ensure!(
            profiles
                .create_pending_binding_in(&mut tx, &pending, selected.clone(), None)
                .await
                == Err(Error::UnsupportedEntry)
        );
        tx.rollback().await?;
        let bindings: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_environment_access_bindings")
                .fetch_one(&db.pool)
                .await?;
        ensure!(bindings == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}
