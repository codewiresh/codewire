//! Synthetic PostgreSQL acceptance for the typed platform storage boundary.
//! Run explicitly with --ignored; an absent TEST_DATABASE_URL is a failure.
//! These tests prove storage CAS, not external OAuth refresh serialization.

mod support;

use std::error::Error as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, ensure};
use codewire_access::{
    CredentialAuthKind as Kind, CredentialId, CredentialStatus, Owner, OwnerId, Placement,
    ProviderId, builtin_provider_catalog,
};
use codewire_platform_credentials::{
    CredentialMetadataReader, CredentialVersion, PlatformCredentialError as Error,
};
use codewire_server_core::org_deletion::begin_organization_deletion;
use support::*;

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn prepared_creation_retains_exact_owner_and_caller_transaction_atomicity() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("prepared-owner").await?;
        let other = db.user("prepared-other").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (pool, _) = db.broker_pool().await?;
        let store = codewire_platform_credentials::PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        let prepared = store
            .prepare_creation(
                &owner,
                registration("Rollback", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let calls = provider.generate_calls.load(Ordering::SeqCst);
        let mut tx = pool.begin().await?;
        let record = store.create_prepared_in(&mut tx, &owner, prepared).await?;
        ensure!(
            provider.generate_calls.load(Ordering::SeqCst) == calls,
            "publication called the KEK provider under locks"
        );
        ensure!(
            store.record(&owner, &record.metadata.id).await == Err(Error::NotFound),
            "uncommitted metadata became visible"
        );
        let material_visible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM platform_credential_material WHERE credential_id=$1)",
        )
        .bind(record.metadata.id.as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(!material_visible, "uncommitted material became visible");
        tx.rollback().await?;
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));

        let prepared = store
            .prepare_creation(
                &owner,
                registration("Wrong owner", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let mut tx = pool.begin().await?;
        ensure!(
            store.create_prepared_in(&mut tx, &other, prepared).await == Err(Error::InvalidInput)
        );
        tx.rollback().await?;
        let empty: bool =
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM platform_credentials)")
                .fetch_one(&db.pool)
                .await?;
        ensure!(empty);

        let prepared = store
            .prepare_creation(
                &owner,
                registration("Committed", Kind::OAuth),
                &value(NEW_VALUE),
            )
            .await?;
        let mut tx = pool.begin().await?;
        let record = store.create_prepared_in(&mut tx, &owner, prepared).await?;
        tx.commit().await?;
        ensure!(store.record(&owner, &record.metadata.id).await? == record);
        ensure!(
            store
                .read_for_broker(&owner, &record.metadata.id, record.version)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        let published: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM platform_credential_material WHERE credential_id=$1)",
        )
        .bind(record.metadata.id.as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(published);

        let mut tx = pool.begin().await?;
        let current = store
            .record_for_update_in(&mut tx, &owner, &record.metadata.id)
            .await?;
        ensure!(current == record);
        store
            .revoke_in(&mut tx, &owner, &record.metadata.id, current.version)
            .await?;
        tx.rollback().await?;
        ensure!(store.record(&owner, &record.metadata.id).await? == record);
        ensure!(
            store
                .read_for_broker(&owner, &record.metadata.id, record.version)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        let mut tx = pool.begin().await?;
        let revoked = store
            .revoke_in(&mut tx, &owner, &record.metadata.id, record.version)
            .await?;
        tx.commit().await?;
        ensure!(revoked.metadata.status == CredentialStatus::Revoked);
        let mut tx = pool.begin().await?;
        store
            .delete_revoked_in(&mut tx, &owner, &record.metadata.id, revoked.version)
            .await?;
        tx.rollback().await?;
        ensure!(store.record(&owner, &record.metadata.id).await? == revoked);
        let mut tx = pool.begin().await?;
        store
            .delete_revoked_in(&mut tx, &owner, &record.metadata.id, revoked.version)
            .await?;
        tx.commit().await?;
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));

        let prepared = store
            .prepare_creation(
                &other,
                registration("Deleted owner", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(other.id().as_str())
            .execute(&db.pool)
            .await?;
        let mut tx = pool.begin().await?;
        ensure!(store.create_prepared_in(&mut tx, &other, prepared).await == Err(Error::NotFound));
        tx.rollback().await?;
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn metadata_reader_works_with_select_only_role_without_material_access() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("metadata-owner").await?;
        let org = db.organization("metadata-org").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let first = store
            .create(
                &owner,
                registration("First", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let second = store
            .create(
                &owner,
                registration("Second", Kind::ApiKey),
                &value(NEW_VALUE),
            )
            .await?;
        let org_record = store
            .create(
                &org,
                registration("Organization", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let (pool, role) = db.metadata_pool().await?;
        let admin_role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&db.pool)
            .await?;
        let identities: (String, String) =
            sqlx::query_as("SELECT current_user::text,session_user::text")
                .fetch_one(&pool)
                .await?;
        ensure!(identities == (role.clone(), role.clone()) && role != admin_role);
        let escalation = sqlx::query(&format!("SET ROLE {}", quote_ident(&admin_role)))
            .execute(&pool)
            .await
            .err()
            .context("metadata login could assume its fixture administrator")?;
        ensure!(
            escalation
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("42501")
        );
        sqlx::query("RESET ROLE").execute(&pool).await?;
        let reset_identities: (String, String) =
            sqlx::query_as("SELECT current_user::text,session_user::text")
                .fetch_one(&pool)
                .await?;
        ensure!(reset_identities == (role.clone(), role));
        let reader = CredentialMetadataReader::new(pool.clone(), builtin_provider_catalog());
        let read = reader.get(&owner, &first.metadata.id).await?;
        ensure!(read == first.metadata && read.placement == Placement::Platform);
        ensure!(reader.get(&org, &org_record.metadata.id).await? == org_record.metadata);
        let page = reader.list(&owner, None, 1).await?;
        ensure!(page.len() == 1);
        let remaining = reader.list(&owner, Some(&page[0].id), 1).await?;
        ensure!(remaining.len() == 1 && remaining[0].id > page[0].id);
        ensure!(
            reader
                .list(&owner, Some(&remaining[0].id), 1)
                .await?
                .is_empty()
        );
        ensure!(reader.list(&owner, None, 0).await == Err(Error::InvalidInput));
        ensure!(reader.list(&owner, None, 1001).await == Err(Error::InvalidInput));
        ensure!(reader.list(&owner, None, 1000).await?.len() == 2);
        let serialized = serde_json::to_string(&read)?;
        let debug = format!("{read:?}");
        for forbidden in [
            OLD_VALUE,
            NEW_VALUE,
            b"wrapped_dek",
            b"ciphertext",
            b"material_generation",
            b"protected_entry",
        ] {
            let forbidden = std::str::from_utf8(forbidden)?;
            ensure!(
                !serialized.contains(forbidden) && !debug.contains(forbidden),
                "metadata disclosed a protected field"
            );
        }
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        for query in [
            "SELECT ciphertext FROM platform_credential_material",
            "UPDATE platform_credentials SET display_name='unauthorized'",
            "SELECT id FROM users FOR SHARE",
            "SELECT email FROM users",
        ] {
            let error = sqlx::query(query)
                .execute(&pool)
                .await
                .err()
                .context("metadata role unexpectedly had authority privileges")?;
            ensure!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref()
                    == Some("42501")
            );
        }
        ensure!(
            store
                .record(&owner, &second.metadata.id)
                .await?
                .metadata
                .display_name
                == "Second"
        );
        begin_organization_deletion(&db.pool, &admin_user(), org.id().as_str()).await?;
        ensure!(reader.get(&org, &org_record.metadata.id).await == Err(Error::NotFound));
        ensure!(reader.list(&org, None, 10).await?.is_empty());
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_isolation_includes_equal_text_user_and_organization_ids() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("same-identity").await?;
        let organization = db.organization("same-identity").await?;
        let other = db.user("other-identity").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let personal = store
            .create(
                &user,
                registration("Same name", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let organizational = store
            .create(
                &organization,
                registration("Same name", Kind::OAuth),
                &value(NEW_VALUE),
            )
            .await?;
        let reader = CredentialMetadataReader::new(db.pool.clone(), builtin_provider_catalog());
        for wrong in [&organization, &other] {
            ensure!(reader.get(wrong, &personal.metadata.id).await == Err(Error::NotFound));
            ensure!(store.record(wrong, &personal.metadata.id).await == Err(Error::NotFound));
            ensure!(
                store
                    .read_for_broker(wrong, &personal.metadata.id, personal.version)
                    .await
                    .err()
                    == Some(Error::NotFound)
            );
            ensure!(
                store
                    .replace(
                        wrong,
                        &personal.metadata.id,
                        personal.version,
                        &value(NEW_VALUE),
                        None
                    )
                    .await
                    == Err(Error::NotFound)
            );
            ensure!(
                store
                    .revoke(wrong, &personal.metadata.id, personal.version)
                    .await
                    == Err(Error::NotFound)
            );
            ensure!(
                store
                    .delete_revoked(wrong, &personal.metadata.id, personal.version)
                    .await
                    == Err(Error::NotFound)
            );
        }
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        ensure!(reader.list(&user, None, 10).await? == vec![personal.metadata.clone()]);
        ensure!(
            reader.list(&organization, None, 10).await? == vec![organizational.metadata.clone()]
        );
        ensure!(reader.list(&other, None, 10).await?.is_empty());
        let unknown = Owner::User(OwnerId::parse("missing-owner")?);
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        ensure!(
            store
                .create(
                    &unknown,
                    registration("Absent", Kind::OAuth),
                    &value(OLD_VALUE)
                )
                .await
                == Err(Error::NotFound)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated);
        ensure!(
            store
                .read_for_broker(&user, &personal.metadata.id, personal.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );
        ensure!(
            store
                .read_for_broker(
                    &organization,
                    &organizational.metadata.id,
                    organizational.version
                )
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn concurrent_replacement_cas_revocation_and_deliberate_reactivation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("replacement-owner").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let original = store
            .create(
                &owner,
                registration("Replace", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let a = value(b"synthetic-competing-replacement-a");
        let b = value(b"synthetic-competing-replacement-b");
        let original_envelope = envelope_bytes(&db.pool, original.metadata.id.as_str()).await?;
        let (left, right) = tokio::join!(
            store.replace(&owner, &original.metadata.id, original.version, &a, None),
            store.replace(&owner, &original.metadata.id, original.version, &b, None),
        );
        let (current, winning_value) = match (left, right) {
            (Ok(record), Err(Error::StaleVersion)) => (record, a.expose_secret()),
            (Err(Error::StaleVersion), Ok(record)) => (record, b.expose_secret()),
            _ => anyhow::bail!("exactly one concurrent replacement must win"),
        };
        ensure!(current.metadata.id == original.metadata.id);
        let replaced_envelope = envelope_bytes(&db.pool, current.metadata.id.as_str()).await?;
        ensure!(
            replaced_envelope.0 != original_envelope.0,
            "replacement reused its predecessor's DEK"
        );
        ensure!(
            current.version
                == CredentialVersion {
                    revocation_generation: 2,
                    material_generation: 2
                }
        );
        ensure!(
            store
                .read_for_broker(&owner, &current.metadata.id, current.version)
                .await?
                .expose_secret()
                == winning_value
        );
        ensure!(
            store
                .read_for_broker(&owner, &current.metadata.id, original.version)
                .await
                .err()
                == Some(Error::StaleVersion)
        );
        ensure!(
            store
                .revoke(&owner, &current.metadata.id, original.version)
                .await
                == Err(Error::StaleVersion)
        );
        let revoked = store
            .revoke(&owner, &current.metadata.id, current.version)
            .await?;
        ensure!(revoked.metadata.status == CredentialStatus::Revoked);
        ensure!(
            revoked.version
                == CredentialVersion {
                    revocation_generation: 3,
                    material_generation: 2
                }
        );
        ensure!(material_count(&db.pool, current.metadata.id.as_str()).await? == 0);
        ensure!(
            store
                .revoke(&owner, &current.metadata.id, current.version)
                .await?
                == revoked
        );
        ensure!(
            store
                .revoke(&owner, &current.metadata.id, revoked.version)
                .await?
                == revoked
        );
        ensure!(
            store
                .publish_oauth_refresh(
                    &owner,
                    &current.metadata.id,
                    revoked.version,
                    &value(NEW_VALUE)
                )
                .await
                == Err(Error::Inactive)
        );
        ensure!(
            store
                .replace(
                    &owner,
                    &current.metadata.id,
                    current.version,
                    &value(NEW_VALUE),
                    None
                )
                .await
                == Err(Error::StaleVersion)
        );
        let revived = store
            .replace(
                &owner,
                &current.metadata.id,
                revoked.version,
                &value(NEW_VALUE),
                None,
            )
            .await?;
        ensure!(
            revived.version
                == CredentialVersion {
                    revocation_generation: 4,
                    material_generation: 3
                }
        );
        ensure!(revived.metadata.status == CredentialStatus::Active);
        ensure!(
            store
                .read_for_broker(&owner, &revived.metadata.id, revived.version)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        ensure!(
            store
                .revoke(&owner, &revived.metadata.id, current.version)
                .await
                == Err(Error::StaleVersion)
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn oauth_refresh_preserves_hard_deadline_and_requires_active_unexpired_exact_oauth_version()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("refresh-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let mut input = registration("Expired hard deadline", Kind::OAuth);
        input.expires_at_unix = Some(0);
        let expired = store.create(&owner, input, &value(OLD_VALUE)).await?;
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        ensure!(
            store
                .read_for_broker(&owner, &expired.metadata.id, expired.version)
                .await
                .err()
                == Some(Error::Expired)
        );
        ensure!(
            store
                .read_for_oauth_refresh(&owner, &expired.metadata.id, expired.version)
                .await
                .err()
                == Some(Error::Expired)
        );
        ensure!(
            store
                .publish_oauth_refresh(
                    &owner,
                    &expired.metadata.id,
                    expired.version,
                    &value(NEW_VALUE)
                )
                .await
                == Err(Error::Expired)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated);
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 0);
        ensure!(store.record(&owner, &expired.metadata.id).await? == expired);

        // The owner deadline is metadata; provider access-token expiry belongs
        // inside the opaque protected bundle and grants no deadline override.
        let hard_deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .checked_add(3600)
            .context("synthetic hard deadline overflow")?;
        let mut input = registration("Unexpired hard deadline", Kind::OAuth);
        input.expires_at_unix = Some(hard_deadline);
        let original = store.create(&owner, input, &value(OLD_VALUE)).await?;
        ensure!(
            store
                .read_for_oauth_refresh(&owner, &original.metadata.id, original.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );
        let a = value(b"synthetic-refresh-result-a");
        let b = value(b"synthetic-refresh-result-b");
        // These are already-obtained results: this deliberately makes no claim
        // that concurrent external provider refreshes have been serialized.
        let (a_result, b_result) = tokio::join!(
            store.publish_oauth_refresh(&owner, &original.metadata.id, original.version, &a),
            store.publish_oauth_refresh(&owner, &original.metadata.id, original.version, &b),
        );
        let refreshed = match (a_result, b_result) {
            (Ok(record), Err(Error::StaleVersion)) | (Err(Error::StaleVersion), Ok(record)) => {
                record
            }
            _ => anyhow::bail!("only one refresh result may publish for a version"),
        };
        ensure!(
            refreshed.version
                == CredentialVersion {
                    revocation_generation: 2,
                    material_generation: 2
                }
        );
        ensure!(refreshed.metadata.id == original.metadata.id);
        ensure!(
            refreshed.metadata.expires_at_unix == Some(hard_deadline),
            "refresh changed the owner's hard deadline"
        );
        ensure!(
            store
                .record(&owner, &refreshed.metadata.id)
                .await?
                .metadata
                .expires_at_unix
                == Some(hard_deadline)
        );
        let api_key = store
            .create(
                &owner,
                registration("Not OAuth", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        ensure!(
            store
                .read_for_oauth_refresh(&owner, &api_key.metadata.id, api_key.version)
                .await
                .err()
                == Some(Error::UnsupportedCredential)
        );
        ensure!(
            store
                .publish_oauth_refresh(
                    &owner,
                    &api_key.metadata.id,
                    api_key.version,
                    &value(NEW_VALUE)
                )
                .await
                == Err(Error::UnsupportedCredential)
        );
        for status in ["expired", "refresh_failed", "revoked"] {
            sqlx::query("UPDATE platform_credentials SET status=$2 WHERE id=$1")
                .bind(refreshed.metadata.id.as_str())
                .bind(status)
                .execute(&db.pool)
                .await?;
            ensure!(
                store
                    .read_for_oauth_refresh(&owner, &refreshed.metadata.id, refreshed.version)
                    .await
                    .err()
                    == Some(Error::Inactive)
            );
            ensure!(
                store
                    .publish_oauth_refresh(
                        &owner,
                        &refreshed.metadata.id,
                        refreshed.version,
                        &value(NEW_VALUE)
                    )
                    .await
                    == Err(Error::Inactive)
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn failed_prepare_and_publication_roll_back_to_the_usable_old_pair() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("failure-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let original = store.create(&owner, registration("Atomic", Kind::OAuth), &value(OLD_VALUE)).await?;
        let original_envelope = envelope_bytes(&db.pool, original.metadata.id.as_str()).await?;
        provider.fail_generate.store(true, Ordering::SeqCst);
        let error = store.replace(&owner, &original.metadata.id, original.version, &value(NEW_VALUE), None).await.err().context("provider failure was ignored")?;
        ensure!(error == Error::ProviderUnavailable);
        assert_value_blind(error, &["synthetic-provider-error-input-never-public"])?;
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        ensure!(store.read_for_broker(&owner, &original.metadata.id, original.version).await?.expose_secret() == OLD_VALUE);
        sqlx::raw_sql(
            "CREATE FUNCTION reject_credential_publication() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'synthetic-db-input-never-public'; END $$; \
             CREATE TRIGGER reject_credential_publication BEFORE INSERT ON platform_credential_material \
             FOR EACH ROW EXECUTE FUNCTION reject_credential_publication();"
        ).execute(&db.pool).await?;
        let error = store.replace(&owner, &original.metadata.id, original.version, &value(NEW_VALUE), None).await.err().context("publication failure was ignored")?;
        ensure!(error == Error::DatabaseUnavailable);
        assert_value_blind(error, &["synthetic-db-input-never-public"])?;
        ensure!(store.record(&owner, &original.metadata.id).await? == original);
        ensure!(material_count(&db.pool, original.metadata.id.as_str()).await? == 1);
        ensure!(envelope_bytes(&db.pool, original.metadata.id.as_str()).await? == original_envelope, "failed publication changed the persisted envelope");
        ensure!(store.read_for_broker(&owner, &original.metadata.id, original.version).await?.expose_secret() == OLD_VALUE);
        let failed_create = store.create(&owner, registration("Never committed", Kind::OAuth), &value(NEW_VALUE)).await;
        ensure!(failed_create == Err(Error::DatabaseUnavailable));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_credentials").fetch_one(&db.pool).await?;
        ensure!(count == 1, "failed create left metadata behind");
        sqlx::query("DROP TRIGGER reject_credential_publication ON platform_credential_material").execute(&db.pool).await?;
        let next = store.replace(&owner, &original.metadata.id, original.version, &value(NEW_VALUE), None).await?;
        ensure!(store.read_for_broker(&owner, &next.metadata.id, next.version).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

fn assert_value_blind(error: Error, extra: &[&str]) -> Result<()> {
    let display = error.to_string();
    let debug = format!("{error:?}");
    ensure!(
        error.source().is_none(),
        "error retained an unsafe source chain"
    );
    for bytes in [OLD_VALUE, NEW_VALUE] {
        let marker = std::str::from_utf8(bytes)?;
        ensure!(!display.contains(marker) && !debug.contains(marker));
    }
    for marker in extra {
        ensure!(
            !display.contains(marker) && !debug.contains(marker),
            "error disclosed an input"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn ciphertext_nonce_and_wrapped_dek_substitution_fail_closed() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("envelope-owner").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let donor = store.create(&owner, registration("Donor", Kind::OAuth), &value(NEW_VALUE)).await?;
        for (name, statement, expected) in [
            ("ciphertext", "UPDATE platform_credential_material SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0) # 1) WHERE credential_id=$1", Error::CorruptRecord),
            ("nonce", "UPDATE platform_credential_material SET nonce=set_byte(nonce,0,get_byte(nonce,0) # 1) WHERE credential_id=$1", Error::CorruptRecord),
            ("wrapped DEK", "UPDATE platform_credential_material SET wrapped_dek=(SELECT wrapped_dek FROM platform_credential_material WHERE credential_id=$2) WHERE credential_id=$1", Error::CorruptRecord),
            ("whole envelope", "UPDATE platform_credential_material t SET wrapped_dek=d.wrapped_dek,ciphertext=d.ciphertext,nonce=d.nonce FROM platform_credential_material d WHERE t.credential_id=$1 AND d.credential_id=$2", Error::CorruptRecord),
            ("malformed wrapper", "UPDATE platform_credential_material SET wrapped_dek=convert_to('synthetic-invalid-wrapper-never-public','UTF8') WHERE credential_id=$1", Error::ProviderUnavailable),
        ] {
            let target = store.create(&owner, registration(name, Kind::OAuth), &value(OLD_VALUE)).await?;
            let mut query = sqlx::query(statement).bind(target.metadata.id.as_str());
            if statement.contains("$2") { query = query.bind(donor.metadata.id.as_str()); }
            query.execute(&db.pool).await?;
            let error = store.read_for_broker(&owner, &target.metadata.id, target.version).await.err().context("tampered envelope was accepted")?;
            ensure!(error == expected, "unexpected envelope failure class");
            assert_value_blind(error, &["synthetic-invalid-wrapper-never-public", target.metadata.id.as_str()])?;
        }
        ensure!(store.read_for_broker(&owner, &donor.metadata.id, donor.version).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn aead_binds_provider_authentication_owner_kind_and_material_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("coordinate-owner").await?;
        let same_text_org = db.organization("coordinate-owner").await?;
        let other = db.user("coordinate-other").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        for (name, statement, reading_owner) in [
            ("provider", "UPDATE platform_credentials SET provider='github' WHERE id=$1", &owner),
            ("authentication", "UPDATE platform_credentials SET authentication_kind='api_key' WHERE id=$1", &owner),
            ("owner kind", "UPDATE platform_credentials SET user_id=NULL,organization_id='coordinate-owner' WHERE id=$1", &same_text_org),
            ("owner identity", "UPDATE platform_credentials SET user_id='coordinate-other' WHERE id=$1", &other),
        ] {
            let target = store.create(&owner, registration(name, Kind::OAuth), &value(OLD_VALUE)).await?;
            sqlx::query(statement).bind(target.metadata.id.as_str()).execute(&db.pool).await?;
            ensure!(store.read_for_broker(reading_owner, &target.metadata.id, target.version).await.err() == Some(Error::CorruptRecord), "AEAD accepted changed credential coordinates");
        }
        let target = store.create(&owner, registration("material generation", Kind::OAuth), &value(OLD_VALUE)).await?;
        // Preserve the old encrypted bytes while changing both relational
        // generations. The FK is satisfied, but AEAD must still reject them.
        let mut tx = db.pool.begin().await?;
        let old: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "DELETE FROM platform_credential_material WHERE credential_id=$1 RETURNING wrapped_dek,ciphertext,nonce"
        ).bind(target.metadata.id.as_str()).fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE platform_credentials SET material_generation=2 WHERE id=$1")
            .bind(target.metadata.id.as_str()).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO platform_credential_material \
             (credential_id,material_generation,kek_provider,key_name,key_version,wrapped_dek,wrapped_format,ciphertext,nonce,format) \
             VALUES ($1,2,'openbao-transit','tenant-dek',1,$2,1,$3,$4,1)"
        ).bind(target.metadata.id.as_str()).bind(old.0).bind(old.1).bind(old.2).execute(&mut *tx).await?;
        tx.commit().await?;
        let changed = CredentialVersion { material_generation: 2, ..target.version };
        ensure!(store.read_for_broker(&owner, &target.metadata.id, changed).await.err() == Some(Error::CorruptRecord));
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn paused_unwrap_rechecks_revoke_replace_expiry_and_owner_deletion() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        for (case, expected) in [
            ("revoke", Error::StaleVersion),
            ("replace", Error::StaleVersion),
            ("expiry", Error::Expired),
            ("refresh-expiry", Error::Expired),
            ("owner-delete", Error::NotFound),
        ] {
            let owner = db.user(&format!("unwrap-{case}")).await?;
            let provider = Arc::new(SyntheticKek::default());
            let store = db.store(provider.clone());
            let record = store
                .create(&owner, registration(case, Kind::OAuth), &value(OLD_VALUE))
                .await?;
            provider.unwrap_gate.arm();
            let task = {
                let store = store.clone();
                let owner = owner.clone();
                let record = record.clone();
                tokio::spawn(async move {
                    if case == "refresh-expiry" {
                        store
                            .read_for_oauth_refresh(&owner, &record.metadata.id, record.version)
                            .await
                    } else {
                        store
                            .read_for_broker(&owner, &record.metadata.id, record.version)
                            .await
                    }
                })
            };
            provider.unwrap_gate.wait().await?;
            ensure!(
                !task.is_finished(),
                "unwrap barrier did not suspend the read"
            );
            match case {
                "revoke" => {
                    store
                        .revoke(&owner, &record.metadata.id, record.version)
                        .await?;
                }
                "replace" => {
                    store
                        .replace(
                            &owner,
                            &record.metadata.id,
                            record.version,
                            &value(NEW_VALUE),
                            None,
                        )
                        .await?;
                }
                "expiry" | "refresh-expiry" => {
                    sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
                        .bind(record.metadata.id.as_str())
                        .execute(&db.pool)
                        .await?;
                }
                "owner-delete" => {
                    sqlx::query("DELETE FROM users WHERE id=$1")
                        .bind(owner.id().as_str())
                        .execute(&db.pool)
                        .await?;
                }
                _ => unreachable!(),
            }
            provider.unwrap_gate.release();
            let outcome = tokio::time::timeout(TIMEOUT, task).await??;
            ensure!(
                outcome.err() == Some(expected),
                "material escaped a changed final admission fence"
            );
            ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == 1);
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn paused_preparation_cannot_resurrect_after_revoke_or_organization_deletion() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("prepare-revoke-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let original = store
            .create(
                &owner,
                registration("Pending replacement", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        provider.generate_gate.arm();
        let task = {
            let store = store.clone();
            let owner = owner.clone();
            let original = original.clone();
            tokio::spawn(async move {
                store
                    .replace(
                        &owner,
                        &original.metadata.id,
                        original.version,
                        &value(NEW_VALUE),
                        None,
                    )
                    .await
            })
        };
        provider.generate_gate.wait().await?;
        let revoked = store
            .revoke(&owner, &original.metadata.id, original.version)
            .await?;
        provider.generate_gate.release();
        ensure!(tokio::time::timeout(TIMEOUT, task).await?? == Err(Error::StaleVersion));
        ensure!(store.record(&owner, &original.metadata.id).await? == revoked);
        ensure!(material_count(&db.pool, original.metadata.id.as_str()).await? == 0);

        let mut refresh_input = registration("Pending refresh expiry", Kind::OAuth);
        refresh_input.expires_at_unix = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
                .checked_add(3600)
                .context("synthetic hard deadline overflow")?,
        );
        let refresh = store
            .create(&owner, refresh_input, &value(OLD_VALUE))
            .await?;
        let prior_envelope = envelope_bytes(&db.pool, refresh.metadata.id.as_str()).await?;
        provider.generate_gate.arm();
        let task = {
            let store = store.clone();
            let owner = owner.clone();
            let refresh = refresh.clone();
            tokio::spawn(async move {
                store
                    .publish_oauth_refresh(
                        &owner,
                        &refresh.metadata.id,
                        refresh.version,
                        &value(NEW_VALUE),
                    )
                    .await
            })
        };
        provider.generate_gate.wait().await?;
        sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
            .bind(refresh.metadata.id.as_str())
            .execute(&db.pool)
            .await?;
        provider.generate_gate.release();
        ensure!(tokio::time::timeout(TIMEOUT, task).await?? == Err(Error::Expired));
        let after_expiry = store.record(&owner, &refresh.metadata.id).await?;
        ensure!(after_expiry.version == refresh.version);
        ensure!(
            after_expiry.metadata.expires_at_unix == Some(0),
            "late refresh cleared the hard deadline"
        );
        ensure!(
            envelope_bytes(&db.pool, refresh.metadata.id.as_str()).await? == prior_envelope,
            "expired refresh changed the old envelope"
        );

        let org = db.organization("prepare-deletion-org").await?;
        provider.generate_gate.arm();
        let task = {
            let store = store.clone();
            let org = org.clone();
            tokio::spawn(async move {
                store
                    .create(
                        &org,
                        registration("Never published", Kind::OAuth),
                        &value(OLD_VALUE),
                    )
                    .await
            })
        };
        provider.generate_gate.wait().await?;
        // Production deletion entrypoint completes while provider preparation
        // is paused: no database lock/lease is held across provider work.
        tokio::time::timeout(
            TIMEOUT,
            begin_organization_deletion(&db.pool, &admin_user(), org.id().as_str()),
        )
        .await??;
        provider.generate_gate.release();
        ensure!(tokio::time::timeout(TIMEOUT, task).await?? == Err(Error::NotFound));
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_credentials WHERE organization_id=$1",
        )
        .bind(org.id().as_str())
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            count == 0,
            "preparation recreated a deleting organization's credential"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn publication_holds_owner_share_fence_until_commit_then_deletion_wins() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        const BARRIER: i32 = 19_220_018;
        let org = db.organization("publication-first-org").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        // The trigger only suspends the exact synthetic publication. It does
        // not change product assertions or substitute a production topology.
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION pause_credential_publication() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_advisory_xact_lock({BARRIER}::bigint); RETURN NEW; END $$; \
             CREATE TRIGGER pause_credential_publication BEFORE INSERT ON platform_credential_material \
             FOR EACH ROW EXECUTE FUNCTION pause_credential_publication();"
        )).execute(&db.pool).await?;
        let mut blocker = db.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)").bind(i64::from(BARRIER)).execute(&mut *blocker).await?;
        let task = {
            let store = store.clone(); let org = org.clone();
            tokio::spawn(async move { store.create(&org, registration("Published first", Kind::OAuth), &value(OLD_VALUE)).await })
        };
        wait_for_advisory_waiter(&db.pool, BARRIER).await?;
        // A non-key UPDATE conflicts with SHARE, but would incorrectly pass
        // through KEY SHARE. This verifies the actual store transaction.
        let mut contender = db.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='150ms'").execute(&mut *contender).await?;
        let blocked = sqlx::query("UPDATE organizations SET name=name WHERE id=$1")
            .bind(org.id().as_str()).execute(&mut *contender).await.err()
            .context("publication did not retain the owner SHARE fence")?;
        ensure!(blocked.as_database_error().and_then(|error| error.code()).as_deref() == Some("55P03"));
        contender.rollback().await?;
        blocker.commit().await?;
        let published = tokio::time::timeout(TIMEOUT, task).await???;
        ensure!(material_count(&db.pool, published.metadata.id.as_str()).await? == 1);
        begin_organization_deletion(&db.pool, &admin_user(), org.id().as_str()).await?;
        ensure!(store.record(&org, &published.metadata.id).await == Err(Error::NotFound));
        ensure!(store.read_for_broker(&org, &published.metadata.id, published.version).await.err() == Some(Error::NotFound));
        ensure!(store.create(&org, registration("Too late", Kind::OAuth), &value(NEW_VALUE)).await == Err(Error::NotFound));
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn exact_tombstone_deletion_and_owner_cascades_preserve_unrelated_storage() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let user = db.user("cascade-user").await?;
        let org = db.organization("cascade-org").await?;
        let retained = db.user("retained-owner").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let personal = store.create(&user, registration("Personal", Kind::OAuth), &value(OLD_VALUE)).await?;
        let organizational = store.create(&org, registration("Organization", Kind::OAuth), &value(OLD_VALUE)).await?;
        let survivor = store.create(&retained, registration("Retained", Kind::OAuth), &value(NEW_VALUE)).await?;
        let removable = store.create(&retained, registration("Exact deletion", Kind::OAuth), &value(OLD_VALUE)).await?;
        // Existing generic workload-secret storage is a separate lifecycle.
        sqlx::query(
            "INSERT INTO tenant_secret_deks (dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek) \
             VALUES ('retained-generic-dek','user','retained-owner','openbao-transit','tenant-dek',1,'vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')"
        ).execute(&db.pool).await?;
        let generic_before: (String, String) = sqlx::query_as("SELECT dek_id,wrapped_dek FROM tenant_secret_deks WHERE dek_id='retained-generic-dek'")
            .fetch_one(&db.pool).await?;
        ensure!(store.delete_revoked(&retained, &removable.metadata.id, removable.version).await == Err(Error::Inactive));
        let revoked = store.revoke(&retained, &removable.metadata.id, removable.version).await?;
        ensure!(material_count(&db.pool, removable.metadata.id.as_str()).await? == 0);
        ensure!(store.delete_revoked(&retained, &removable.metadata.id, removable.version).await == Err(Error::StaleVersion));
        store.delete_revoked(&retained, &removable.metadata.id, revoked.version).await?;
        ensure!(store.record(&retained, &removable.metadata.id).await == Err(Error::NotFound));
        sqlx::query("DELETE FROM users WHERE id=$1").bind(user.id().as_str()).execute(&db.pool).await?;
        sqlx::query("DELETE FROM organizations WHERE id=$1").bind(org.id().as_str()).execute(&db.pool).await?;
        for id in [&personal.metadata.id, &organizational.metadata.id] {
            ensure!(material_count(&db.pool, id.as_str()).await? == 0);
            let metadata: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_credentials WHERE id=$1")
                .bind(id.as_str()).fetch_one(&db.pool).await?;
            ensure!(metadata == 0);
        }
        ensure!(store.read_for_broker(&retained, &survivor.metadata.id, survivor.version).await?.expose_secret() == NEW_VALUE);
        let generic_after: (String, String) = sqlx::query_as("SELECT dek_id,wrapped_dek FROM tenant_secret_deks WHERE dek_id='retained-generic-dek'")
            .fetch_one(&db.pool).await?;
        ensure!(generic_after == generic_before);
        ensure!(material_count(&db.pool, survivor.metadata.id.as_str()).await? == 1);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn invalid_registration_versions_and_database_inputs_are_value_blind() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("validation-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let mut input = registration("\nsynthetic-invalid-label-never-public", Kind::OAuth);
        ensure!(
            store.create(&owner, input.clone(), &value(OLD_VALUE)).await
                == Err(Error::InvalidInput)
        );
        input.display_name = "Unsupported".into();
        input.provider = ProviderId::parse("synthetic-unsupported-provider")?;
        let error = store
            .create(&owner, input, &value(OLD_VALUE))
            .await
            .err()
            .context("unsupported provider was accepted")?;
        ensure!(error == Error::UnsupportedCredential);
        assert_value_blind(error, &["synthetic-unsupported-provider"])?;
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == 0);
        let current = store
            .create(
                &owner,
                registration("Unique", Kind::OAuth),
                &value(OLD_VALUE),
            )
            .await?;
        let error = store
            .create(
                &owner,
                registration("uNiQuE", Kind::OAuth),
                &value(NEW_VALUE),
            )
            .await
            .err()
            .context("case-insensitive duplicate was accepted")?;
        ensure!(error == Error::AlreadyExists);
        assert_value_blind(error, &[owner.id().as_str(), "uNiQuE"])?;
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        for version in [
            CredentialVersion {
                revocation_generation: 0,
                material_generation: 1,
            },
            CredentialVersion {
                revocation_generation: 1,
                material_generation: 0,
            },
            CredentialVersion {
                revocation_generation: u64::MAX,
                material_generation: 1,
            },
        ] {
            ensure!(
                store
                    .replace(
                        &owner,
                        &current.metadata.id,
                        version,
                        &value(NEW_VALUE),
                        None
                    )
                    .await
                    == Err(Error::InvalidInput)
            );
            ensure!(
                store.revoke(&owner, &current.metadata.id, version).await
                    == Err(Error::InvalidInput)
            );
        }
        // Saturated persisted revocation generations must fail before provider
        // work, not overflow or wrap back to a previously admitted generation.
        sqlx::query("UPDATE platform_credentials SET revocation_generation=$2 WHERE id=$1")
            .bind(current.metadata.id.as_str())
            .bind(i64::MAX)
            .execute(&db.pool)
            .await?;
        let saturated = CredentialVersion {
            revocation_generation: i64::MAX as u64,
            material_generation: 1,
        };
        ensure!(
            store
                .replace(
                    &owner,
                    &current.metadata.id,
                    saturated,
                    &value(NEW_VALUE),
                    None
                )
                .await
                == Err(Error::InvalidInput)
        );
        ensure!(
            store.revoke(&owner, &current.metadata.id, saturated).await == Err(Error::InvalidInput)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated);
        ensure!(
            store
                .read_for_broker(&owner, &current.metadata.id, saturated)
                .await?
                .expose_secret()
                == OLD_VALUE
        );
        let missing = CredentialId::parse("missing-credential")?;
        assert_value_blind(
            store
                .record(&owner, &missing)
                .await
                .err()
                .context("missing credential was found")?,
            &[missing.as_str()],
        )?;
        Ok(())
    }
    .await;
    db.finish(result).await
}
