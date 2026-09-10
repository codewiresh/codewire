use super::*;
use codewire_platform_credentials::PlatformCredentialStore;
use codewire_protected_store::ssh_material::{decode_protected_material, generate_ed25519};

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn ssh_prepared_creation_is_atomic_owner_scoped_and_public_readable() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("ssh-owner").await?;
        let other = db.user("ssh-other").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let key = generate_ed25519()?;
        let expected_public = key.public_key().clone();
        let prepared = store
            .prepare_ssh_creation(&owner, "SSH Work".into(), Some(4_000_000_000), key)
            .await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        let mut tx = pool.begin().await?;
        let record = store.create_prepared_in(&mut tx, &owner, prepared).await?;
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));
        tx.rollback().await?;
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));
        ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);

        let prepared = store
            .prepare_ssh_creation(&owner, "Wrong owner".into(), None, generate_ed25519()?)
            .await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store.create_prepared_in(&mut tx, &other, prepared).await == Err(Error::InvalidInput)
        );
        tx.rollback().await?;

        let key = generate_ed25519()?;
        let public = key.public_key().clone();
        ensure!(public != expected_public);
        let prepared = store
            .prepare_ssh_creation(&owner, "SSH Work".into(), Some(4_000_000_000), key)
            .await?;
        let mut tx = pool.begin().await?;
        let record = store.create_prepared_in(&mut tx, &owner, prepared).await?;
        tx.commit().await?;
        let metadata = &record.metadata;
        let stored = metadata
            .ssh_public_key
            .as_ref()
            .context("SSH public metadata")?;
        ensure!(
            metadata.provider.as_str() == "ssh" && metadata.authentication_kind == Kind::SshKey
        );
        ensure!(metadata.account_hint.is_none() && metadata.expires_at_unix == Some(4_000_000_000));
        ensure!(stored.openssh == public.openssh() && stored.fingerprint == public.fingerprint());
        let material = store
            .read_for_broker(&owner, &metadata.id, record.version)
            .await?;
        ensure!(decode_protected_material(material)?.public_key() == &public);
        let (reader_pool, _) = db.metadata_pool().await?;
        let reader = CredentialMetadataReader::new(reader_pool.clone(), builtin_provider_catalog());
        ensure!(reader.get(&owner, &metadata.id).await? == *metadata);
        ensure!(reader.get(&other, &metadata.id).await == Err(Error::NotFound));
        ensure!(
            sqlx::query("SELECT ciphertext FROM platform_credential_material LIMIT 0")
                .execute(&reader_pool)
                .await
                .is_err()
        );
        // Create-only enrollment needs no new UPDATE privileges. Public key
        // tampering remains denied even though INSERT carries the new pair.
        for column in ["ssh_public_key", "ssh_fingerprint"] {
            ensure!(
                sqlx::query(&format!(
                    "UPDATE public.platform_credentials SET {column}=NULL WHERE false"
                ))
                .execute(&pool)
                .await
                .is_err()
            );
        }
        let revoked = store.revoke(&owner, &metadata.id, record.version).await?;
        ensure!(revoked.metadata.ssh_public_key == metadata.ssh_public_key);
        reader_pool.close().await;
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn ssh_generic_creation_and_replacement_cannot_bypass_typed_preparation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("ssh-bypass-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let mut input = registration("Opaque SSH", Kind::SshKey);
        input.provider = ProviderId::parse("ssh")?;
        ensure!(
            store
                .prepare_creation(&owner, input, &value(OLD_VALUE))
                .await
                .err()
                == Some(Error::UnsupportedCredential)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == 0);
        let prepared = store
            .prepare_ssh_creation(&owner, "Typed SSH".into(), None, generate_ed25519()?)
            .await?;
        let mut tx = db.pool.begin().await?;
        let record = store.create_prepared_in(&mut tx, &owner, prepared).await?;
        tx.commit().await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        ensure!(
            store
                .prepare_replacement(&owner, &record, &value(NEW_VALUE), None)
                .await
                .err()
                == Some(Error::UnsupportedCredential)
        );
        ensure!(
            store
                .replace(
                    &owner,
                    &record.metadata.id,
                    record.version,
                    &value(NEW_VALUE),
                    None
                )
                .await
                == Err(Error::UnsupportedCredential)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(store.record(&owner, &record.metadata.id).await? == record);
        // The V1 SSH signer now admits a profile identity. This does not
        // permit opaque private-key creation/replacement above.
        let profiles = codewire_platform_credentials::PlatformAccessProfileStore::new(
            db.pool.clone(),
            builtin_provider_catalog(),
        );
        let entries = std::collections::BTreeMap::from([(
            codewire_access::CapabilitySlot::parse("ssh")?,
            record.metadata.id.clone(),
        )]);
        let profile = profiles
            .create(
                &owner,
                codewire_access::AccessProfileName::parse("ssh-profile")?,
                entries.clone(),
            )
            .await?;
        ensure!(profile.entries == entries);
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == calls);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        ensure!(store.record(&owner, &record.metadata.id).await? == record);
        Ok(())
    }
    .await;
    db.finish(result).await
}
