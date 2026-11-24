//! Hosted placeholder keys (#4001) on synthetic PostgreSQL, as the restricted
//! broker role: one sealed key per environment, created once, never changed,
//! deleted with the environment, and bound to it. Then owner-local placeholder
//! roots (#6191): a local VM on a platform profile has no environments row, so
//! its key is derived from its owner's one sealed root, created once, never
//! changed, deleted with the user, and bound to that user and purpose. Run
//! explicitly with --ignored; an absent TEST_DATABASE_URL is a failure.

#[allow(dead_code)]
mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Result, ensure};
use codewire_access::{
    CapabilitySlot, CredentialId, CredentialPlaceholder, EnvironmentId, OwnerId, PlaceholderKey,
    builtin_provider_catalog,
};
use codewire_platform_credentials::{PlatformCredentialError as Error, PlatformCredentialStore};
use sqlx::PgPool;
use support::*;

async fn environment(db: &TestDatabase, org: &str, id: &str) -> Result<EnvironmentId> {
    sqlx::query(
        r#"INSERT INTO environment_presets(id,org_id,name,slug,project_spec)
           VALUES ($1,$2,$1,$1,'{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(format!("preset-{id}"))
    .bind(org)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,
           environment_operation_generation,project_spec)
           VALUES ($1,$2,'fixture-admin','sandbox',$3,'running','started',7,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(id)
    .bind(org)
    .bind(format!("preset-{id}"))
    .execute(&db.pool)
    .await?;
    Ok(EnvironmentId::parse(id)?)
}

/// What a lease in `environment` derives under `key` for one fixed credential.
fn derived(key: &PlaceholderKey, environment: &EnvironmentId) -> Result<CredentialPlaceholder> {
    Ok(CredentialPlaceholder::derive(
        key,
        environment,
        7,
        &CapabilitySlot::parse("anthropic")?,
        &CredentialId::parse("anthropic-sign-in")?,
    ))
}

async fn key_rows(pool: &PgPool, environment: &EnvironmentId) -> Result<i64> {
    Ok(
        sqlx::query_scalar(
            "SELECT count(*) FROM platform_placeholder_keys WHERE environment_id=$1",
        )
        .bind(environment.as_str())
        .fetch_one(pool)
        .await?,
    )
}

async fn broker_store(
    db: &TestDatabase,
    kek: &Arc<SyntheticKek>,
) -> Result<(PlatformCredentialStore, PgPool)> {
    let (pool, _) = db.broker_pool().await?;
    let store = PlatformCredentialStore::new(pool.clone(), kek.clone(), builtin_provider_catalog());
    Ok((store, pool))
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_environment_key_is_created_once_and_then_only_read() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        let a = environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let first = store.environment_placeholder_key(&a).await?;
        let second = store.environment_placeholder_key(&a).await?;
        ensure!(derived(&first, &a)?.ct_eq(&derived(&second, &a)?));
        ensure!(key_rows(&db.pool, &a).await? == 1);
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 1);
        // A missing environment has no key, and none is made for it.
        let missing = EnvironmentId::parse("env-missing")?;
        ensure!(matches!(
            store.environment_placeholder_key(&missing).await,
            Err(Error::NotFound)
        ));
        ensure!(key_rows(&db.pool, &missing).await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

// A first use that loses the insert opens the stored key, never its own.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn two_first_uses_derive_under_the_one_stored_key() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        let a = environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let store = Arc::new(store);
        // The first use stops after finding no row, before it inserts.
        kek.generate_gate.arm();
        let first = tokio::spawn({
            let (store, a) = (store.clone(), a.clone());
            async move { store.environment_placeholder_key(&a).await }
        });
        kek.generate_gate.wait().await?;
        let winner = store.environment_placeholder_key(&a).await?;
        kek.generate_gate.release();
        let loser = first.await??;
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 2);
        ensure!(key_rows(&db.pool, &a).await? == 1);
        ensure!(derived(&loser, &a)?.ct_eq(&derived(&winner, &a)?));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn each_environment_has_its_own_key_and_loses_it_with_the_environment() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        let a = environment(&db, "org-a", "env-a").await?;
        let b = environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let key_a = store.environment_placeholder_key(&a).await?;
        let key_b = store.environment_placeholder_key(&b).await?;
        // Only the environment's own key derives its placeholders.
        ensure!(!derived(&key_a, &b)?.ct_eq(&derived(&key_b, &b)?));
        ensure!(!derived(&key_a, &a)?.ct_eq(&derived(&key_b, &b)?));
        sqlx::query("DELETE FROM environments WHERE id=$1")
            .bind(a.as_str())
            .execute(&db.pool)
            .await?;
        ensure!(key_rows(&db.pool, &a).await? == 0);
        ensure!(key_rows(&db.pool, &b).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_key_sealed_for_one_environment_does_not_open_in_another() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        let a = environment(&db, "org-a", "env-a").await?;
        let b = environment(&db, "org-a", "env-b").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.environment_placeholder_key(&a).await?;
        store.environment_placeholder_key(&b).await?;
        // The schema owner copies env-a's sealed row over env-b's.
        sqlx::query(
            "UPDATE platform_placeholder_keys b SET (kek_provider, key_name, key_version, \
             wrapped_dek, wrapped_format, ciphertext, nonce, format) = \
             (SELECT kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
              ciphertext, nonce, format FROM platform_placeholder_keys WHERE environment_id=$1) \
             WHERE b.environment_id=$2",
        )
        .bind(a.as_str())
        .bind(b.as_str())
        .execute(&db.pool)
        .await?;
        ensure!(matches!(
            store.environment_placeholder_key(&b).await,
            Err(Error::CorruptRecord)
        ));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_broker_role_can_neither_change_nor_delete_a_key() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("org-a").await?;
        let a = environment(&db, "org-a", "env-a").await?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, broker) = broker_store(&db, &kek).await?;
        store.environment_placeholder_key(&a).await?;
        for statement in [
            "UPDATE platform_placeholder_keys SET nonce=nonce",
            "DELETE FROM platform_placeholder_keys",
            "TRUNCATE platform_placeholder_keys",
        ] {
            let refused = sqlx::query(statement).execute(&broker).await.unwrap_err();
            ensure!(
                refused
                    .as_database_error()
                    .and_then(|error| error.code())
                    .is_some_and(|code| code == "42501"),
                "{statement} was not refused for its privilege"
            );
        }
        ensure!(key_rows(&db.pool, &a).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

async fn root_rows(pool: &PgPool, user: &OwnerId) -> Result<i64> {
    Ok(
        sqlx::query_scalar(
            "SELECT count(*) FROM platform_local_placeholder_roots WHERE user_id=$1",
        )
        .bind(user.as_str())
        .fetch_one(pool)
        .await?,
    )
}

/// A local VM's environment: an ID with no row anywhere.
fn local_vm(id: &str) -> Result<EnvironmentId> {
    Ok(EnvironmentId::parse(id)?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_root_is_created_once_and_each_local_vm_gets_its_own_key() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("user-a").await?.id().clone();
        let (a, b) = (local_vm("local-vm-a")?, local_vm("local-vm-b")?);
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let first = store.owner_local_placeholder_key(&user, &a).await?;
        let second = store.owner_local_placeholder_key(&user, &a).await?;
        ensure!(derived(&first, &a)?.ct_eq(&derived(&second, &a)?));
        let other = store.owner_local_placeholder_key(&user, &b).await?;
        ensure!(!derived(&first, &a)?.ct_eq(&derived(&other, &a)?));
        ensure!(root_rows(&db.pool, &user).await? == 1);
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 1);
        // Nothing is stored per local VM, and no hosted key is made.
        let hosted: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_placeholder_keys")
            .fetch_one(&db.pool)
            .await?;
        ensure!(hosted == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn another_owner_naming_the_same_local_vm_gets_another_key() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let a = db.user("user-a").await?.id().clone();
        let b = db.user("user-b").await?.id().clone();
        let vm = local_vm("local-vm-a")?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let key_a = store.owner_local_placeholder_key(&a, &vm).await?;
        let key_b = store.owner_local_placeholder_key(&b, &vm).await?;
        ensure!(!derived(&key_a, &vm)?.ct_eq(&derived(&key_b, &vm)?));
        // A user with no row has no root, and none is made for it.
        let missing = OwnerId::parse("user-missing")?;
        ensure!(
            store
                .owner_local_placeholder_key(&missing, &vm)
                .await
                .is_err()
        );
        ensure!(root_rows(&db.pool, &missing).await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

// A first use that loses the insert opens the stored root, never its own.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn two_first_uses_derive_under_the_one_stored_root() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("user-a").await?.id().clone();
        let vm = local_vm("local-vm-a")?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        let store = Arc::new(store);
        kek.generate_gate.arm();
        let first = tokio::spawn({
            let (store, user, vm) = (store.clone(), user.clone(), vm.clone());
            async move { store.owner_local_placeholder_key(&user, &vm).await }
        });
        kek.generate_gate.wait().await?;
        let winner = store.owner_local_placeholder_key(&user, &vm).await?;
        kek.generate_gate.release();
        let loser = first.await??;
        ensure!(kek.generate_calls.load(Ordering::SeqCst) == 2);
        ensure!(root_rows(&db.pool, &user).await? == 1);
        ensure!(derived(&loser, &vm)?.ct_eq(&derived(&winner, &vm)?));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_root_sealed_for_one_user_does_not_open_for_another_and_goes_with_its_user() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let a = db.user("user-a").await?.id().clone();
        let b = db.user("user-b").await?.id().clone();
        let vm = local_vm("local-vm-a")?;
        let kek = Arc::new(SyntheticKek::default());
        let (store, _) = broker_store(&db, &kek).await?;
        store.owner_local_placeholder_key(&a, &vm).await?;
        store.owner_local_placeholder_key(&b, &vm).await?;
        // The schema owner copies user-a's sealed row over user-b's.
        sqlx::query(
            "UPDATE platform_local_placeholder_roots b SET (kek_provider, key_name, key_version, \
             wrapped_dek, wrapped_format, ciphertext, nonce, format) = \
             (SELECT kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
              ciphertext, nonce, format FROM platform_local_placeholder_roots WHERE user_id=$1) \
             WHERE b.user_id=$2",
        )
        .bind(a.as_str())
        .bind(b.as_str())
        .execute(&db.pool)
        .await?;
        ensure!(matches!(
            store.owner_local_placeholder_key(&b, &vm).await,
            Err(Error::CorruptRecord)
        ));
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(a.as_str())
            .execute(&db.pool)
            .await?;
        ensure!(root_rows(&db.pool, &a).await? == 0);
        ensure!(root_rows(&db.pool, &b).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_broker_role_can_neither_change_nor_delete_a_root() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("user-a").await?.id().clone();
        let kek = Arc::new(SyntheticKek::default());
        let (store, broker) = broker_store(&db, &kek).await?;
        store
            .owner_local_placeholder_key(&user, &local_vm("local-vm-a")?)
            .await?;
        for statement in [
            "UPDATE platform_local_placeholder_roots SET nonce=nonce",
            "DELETE FROM platform_local_placeholder_roots",
            "TRUNCATE platform_local_placeholder_roots",
        ] {
            let refused = sqlx::query(statement).execute(&broker).await.unwrap_err();
            ensure!(
                refused
                    .as_database_error()
                    .and_then(|error| error.code())
                    .is_some_and(|code| code == "42501"),
                "{statement} was not refused for its privilege"
            );
        }
        ensure!(root_rows(&db.pool, &user).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}
