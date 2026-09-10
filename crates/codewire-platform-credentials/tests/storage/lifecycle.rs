//! Exact-owner metadata rename and explicit write-only API-key rotation.

use super::*;
use codewire_access::{AccessProfileName, CapabilitySlot};
use codewire_platform_credentials::{
    CredentialRecord, PlatformAccessProfileStore, PlatformCredentialStore,
};

async fn material_row(pool: &sqlx::PgPool, id: &CredentialId) -> Result<Option<serde_json::Value>> {
    Ok(sqlx::query_scalar(
        "SELECT to_jsonb(m) FROM platform_credential_material m WHERE credential_id=$1",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn rename_is_metadata_only_owner_scoped_and_transaction_bound() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rename-owner").await?;
        let other = db.user("rename-other").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let original = store
            .create(
                &owner,
                registration("Original", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        store
            .create(
                &other,
                registration("Renamed", Kind::OAuth),
                &value(NEW_VALUE),
            )
            .await?;
        let profiles = PlatformAccessProfileStore::new(db.pool.clone(), builtin_provider_catalog());
        let profile = profiles
            .create(
                &owner,
                AccessProfileName::parse("rename-profile")?,
                std::collections::BTreeMap::from([(
                    CapabilitySlot::codex(),
                    original.metadata.id.clone(),
                )]),
            )
            .await?;
        let ciphertext = material_row(&db.pool, &original.metadata.id).await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        let mut expected = original.clone();
        expected.metadata.display_name = "Renamed".into();

        let mut tx = pool.begin().await?;
        ensure!(
            store
                .rename_in(
                    &mut tx,
                    &owner,
                    &original.metadata.id,
                    1,
                    "Original",
                    "Renamed".into()
                )
                .await?
                == expected
        );
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        tx.rollback().await?;
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        ensure!(material_row(&db.pool, &original.metadata.id).await? == ciphertext);

        let mut tx = pool.begin().await?;
        let renamed = store
            .rename_in(
                &mut tx,
                &owner,
                &original.metadata.id,
                1,
                "Original",
                "Renamed".into(),
            )
            .await?;
        tx.commit().await?;
        ensure!(
            renamed == expected && store.record(&owner, &original.metadata.id).await? == expected
        );
        ensure!(material_row(&db.pool, &original.metadata.id).await? == ciphertext);
        ensure!(profiles.get(&owner, &profile.id).await? == profile);
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        let reader = CredentialMetadataReader::new(pool.clone(), builtin_provider_catalog());
        ensure!(reader.resolve(&owner, "original").await == Err(Error::NotFound));
        ensure!(reader.resolve(&owner, "RENAMED").await? == renamed.metadata);
        ensure!(
            store
                .read_for_broker(&owner, &renamed.metadata.id, renamed.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );

        // Rename never reactivates a revoked identity or invents material.
        let revoked = store
            .revoke(&owner, &renamed.metadata.id, renamed.version)
            .await?;
        let mut tx = pool.begin().await?;
        let renamed = store
            .rename_in(
                &mut tx,
                &owner,
                &revoked.metadata.id,
                revoked.version.revocation_generation,
                "Renamed",
                "Revoked name".into(),
            )
            .await?;
        tx.commit().await?;
        let mut expected = revoked;
        expected.metadata.display_name = "Revoked name".into();
        ensure!(
            renamed == expected
                && material_row(&db.pool, &renamed.metadata.id)
                    .await?
                    .is_none()
        );
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn rename_rejects_owner_name_revision_and_unique_name_conflicts_without_material_work()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rename-cas-owner").await?;
        let other = db.user("rename-cas-other").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let original = store
            .create(
                &owner,
                registration("Original", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        store
            .create(
                &owner,
                registration("Taken", Kind::ApiKey),
                &value(NEW_VALUE),
            )
            .await?;
        let before = material_row(&db.pool, &original.metadata.id).await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        for (selected_owner, generation, old_name, new_name, error) in [
            (&other, 1, "Original", "Next", Error::NotFound),
            (&owner, 0, "Original", "Next", Error::InvalidInput),
            (&owner, u64::MAX, "Original", "Next", Error::InvalidInput),
            (&owner, 2, "Original", "Next", Error::StaleVersion),
            (&owner, 1, "original", "Next", Error::StaleVersion),
            (&owner, 1, "Original", "tAkEn", Error::AlreadyExists),
            (&owner, 1, "Original", "", Error::InvalidInput),
            (&owner, 1, "Original", "bad\nname", Error::InvalidInput),
        ] {
            let mut tx = pool.begin().await?;
            ensure!(
                store
                    .rename_in(
                        &mut tx,
                        selected_owner,
                        &original.metadata.id,
                        generation,
                        old_name,
                        new_name.into()
                    )
                    .await
                    == Err(error)
            );
            tx.rollback().await?;
            ensure!(store.record(&owner, &original.metadata.id).await? == original);
            ensure!(material_row(&db.pool, &original.metadata.id).await? == before);
        }
        let mut tx = pool.begin().await?;
        let renamed = store
            .rename_in(
                &mut tx,
                &owner,
                &original.metadata.id,
                1,
                "Original",
                "Next".into(),
            )
            .await?;
        tx.commit().await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store
                .rename_in(
                    &mut tx,
                    &owner,
                    &original.metadata.id,
                    1,
                    "Original",
                    "Lost update".into()
                )
                .await
                == Err(Error::StaleVersion)
        );
        tx.rollback().await?;
        ensure!(store.record(&owner, &original.metadata.id).await? == renamed);
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

async fn publish_key(
    store: &PlatformCredentialStore,
    pool: &sqlx::PgPool,
    owner: &Owner,
    original: &CredentialRecord,
    expiry: Option<u64>,
) -> Result<CredentialRecord> {
    let prepared = store
        .prepare_api_key_replacement(owner, original, &value(NEW_VALUE), expiry)
        .await?;
    let mut tx = pool.begin().await?;
    let next = store.replace_prepared_in(&mut tx, owner, prepared).await?;
    tx.commit().await?;
    Ok(next)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn api_key_rotation_preserves_identity_and_profiles_with_explicit_expiry_and_reactivation()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rotation-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let profiles = PlatformAccessProfileStore::new(db.pool.clone(), builtin_provider_catalog());
        for (provider_name, slot) in [
            ("openai", CapabilitySlot::openai()),
            ("anthropic", CapabilitySlot::anthropic()),
        ] {
            let mut input = registration(provider_name, Kind::ApiKey);
            input.provider = ProviderId::parse(provider_name)?;
            input.expires_at_unix = Some(4_000_000_000);
            let original = store.create(&owner, input, &value(OLD_VALUE)).await?;
            let profile = profiles
                .create(
                    &owner,
                    AccessProfileName::parse(format!("{provider_name}-profile"))?,
                    std::collections::BTreeMap::from([(slot, original.metadata.id.clone())]),
                )
                .await?;
            let before = material_row(&db.pool, &original.metadata.id).await?;
            let prepared = store
                .prepare_api_key_replacement(&owner, &original, &value(NEW_VALUE), None)
                .await?;
            let calls = provider.generate_calls.load(Ordering::SeqCst);
            let mut tx = pool.begin().await?;
            let staged = store.replace_prepared_in(&mut tx, &owner, prepared).await?;
            ensure!(staged.metadata.expires_at_unix.is_none());
            ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
            ensure!(store.record(&owner, &original.metadata.id).await? == original);
            tx.rollback().await?;
            ensure!(material_row(&db.pool, &original.metadata.id).await? == before);

            let next = publish_key(&store, &pool, &owner, &original, None).await?;
            let mut expected = original.clone();
            expected.version = CredentialVersion {
                revocation_generation: 2,
                material_generation: 2,
            };
            expected.metadata.revocation_generation = 2;
            expected.metadata.expires_at_unix = None;
            ensure!(next == expected);
            ensure!(material_row(&db.pool, &original.metadata.id).await? != before);
            ensure!(
                store
                    .read_for_broker(&owner, &original.metadata.id, original.version)
                    .await
                    .err()
                    == Some(Error::StaleVersion)
            );
            ensure!(
                store
                    .read_for_broker(&owner, &next.metadata.id, next.version)
                    .await?
                    .expose_secret()
                    == NEW_VALUE
            );
            let next = publish_key(&store, &pool, &owner, &next, Some(4_000_000_000)).await?;
            ensure!(next.metadata.expires_at_unix == Some(4_000_000_000));
            let revoked = store
                .revoke(&owner, &next.metadata.id, next.version)
                .await?;
            ensure!(material_row(&db.pool, &next.metadata.id).await?.is_none());
            let next = publish_key(&store, &pool, &owner, &revoked, None).await?;
            let mut expected = revoked.clone();
            expected.version.revocation_generation += 1;
            expected.version.material_generation += 1;
            expected.metadata.revocation_generation = expected.version.revocation_generation;
            expected.metadata.expires_at_unix = None;
            expected.metadata.status = CredentialStatus::Active;
            ensure!(next == expected);
            ensure!(
                store
                    .read_for_broker(&owner, &next.metadata.id, next.version)
                    .await?
                    .expose_secret()
                    == NEW_VALUE
            );
            ensure!(profiles.get(&owner, &profile.id).await? == profile);
        }
        let mut expired = registration("Expired", Kind::ApiKey);
        expired.expires_at_unix = Some(1);
        let expired = store.create(&owner, expired, &value(OLD_VALUE)).await?;
        ensure!(
            store
                .read_for_broker(&owner, &expired.metadata.id, expired.version)
                .await
                .err()
                == Some(Error::Expired)
        );
        let next = publish_key(&store, &pool, &owner, &expired, None).await?;
        ensure!(
            store
                .read_for_broker(&owner, &next.metadata.id, next.version)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn api_key_rotation_rejects_invalid_preparation_and_concurrent_record_changes() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rotation-cas-owner").await?;
        let other = db.user("rotation-cas-other").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let original = store
            .create(
                &owner,
                registration("Original", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        for expiry in [Some(0), Some(1), Some(u64::MAX)] {
            ensure!(
                store
                    .prepare_api_key_replacement(&owner, &original, &value(NEW_VALUE), expiry)
                    .await
                    .err()
                    == Some(Error::InvalidInput)
            );
        }
        for kind in [Kind::OAuth, Kind::SshKey, Kind::AccessToken] {
            let mut wrong = original.clone();
            wrong.metadata.authentication_kind = kind;
            ensure!(
                store
                    .prepare_api_key_replacement(&owner, &wrong, &value(NEW_VALUE), None)
                    .await
                    .err()
                    == Some(Error::UnsupportedCredential)
            );
        }
        let mut wrong_provider = original.clone();
        wrong_provider.metadata.provider = ProviderId::parse("github")?;
        ensure!(
            store
                .prepare_api_key_replacement(&owner, &wrong_provider, &value(NEW_VALUE), None)
                .await
                .err()
                == Some(Error::UnsupportedCredential)
        );
        ensure!(
            store
                .prepare_api_key_replacement(&other, &original, &value(NEW_VALUE), None)
                .await
                .err()
                == Some(Error::InvalidInput)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);

        let before = material_row(&db.pool, &original.metadata.id).await?;
        provider.fail_generate.store(true, Ordering::SeqCst);
        ensure!(
            store
                .prepare_api_key_replacement(&owner, &original, &value(NEW_VALUE), None)
                .await
                .err()
                == Some(Error::ProviderUnavailable)
        );
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        ensure!(material_row(&db.pool, &original.metadata.id).await? == before);

        let prepared = store
            .prepare_api_key_replacement(&owner, &original, &value(NEW_VALUE), None)
            .await?;
        let mut tx = pool.begin().await?;
        let renamed = store
            .rename_in(
                &mut tx,
                &owner,
                &original.metadata.id,
                1,
                "Original",
                "Changed".into(),
            )
            .await?;
        tx.commit().await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store.replace_prepared_in(&mut tx, &owner, prepared).await == Err(Error::CorruptRecord)
        );
        tx.rollback().await?;
        ensure!(store.record(&owner, &original.metadata.id).await? == renamed);
        ensure!(material_row(&db.pool, &original.metadata.id).await? == before);

        let prepared = store
            .prepare_api_key_replacement(&owner, &renamed, &value(NEW_VALUE), None)
            .await?;
        let revoked = store
            .revoke(&owner, &renamed.metadata.id, renamed.version)
            .await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store.replace_prepared_in(&mut tx, &owner, prepared).await == Err(Error::StaleVersion)
        );
        tx.rollback().await?;
        ensure!(store.record(&owner, &original.metadata.id).await? == revoked);
        ensure!(
            material_row(&db.pool, &original.metadata.id)
                .await?
                .is_none()
        );
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        ensure!(
            store
                .prepare_api_key_replacement(&owner, &renamed, &value(NEW_VALUE), None)
                .await
                .err()
                == Some(Error::StaleVersion)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn api_key_expiry_is_rechecked_after_preparation_before_publication() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rotation-expiry-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let original = store
            .create(
                &owner,
                registration("Original", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        let before = material_row(&db.pool, &original.metadata.id).await?;
        let unix_now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_secs())
        };
        let expiry = unix_now()? + 2;
        let prepared = store
            .prepare_api_key_replacement(&owner, &original, &value(NEW_VALUE), Some(expiry))
            .await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        // The production deadline is wall time. Wait only for this synthetic
        // two-second expiry, outside any transaction and under a finite bound.
        tokio::time::timeout(TIMEOUT, async {
            while unix_now()? < expiry {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        let mut tx = pool.begin().await?;
        ensure!(
            store.replace_prepared_in(&mut tx, &owner, prepared).await == Err(Error::InvalidInput)
        );
        tx.rollback().await?;
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        ensure!(material_row(&db.pool, &original.metadata.id).await? == before);
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}
