use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, Owner, OwnerId,
    Placement, ProviderCatalog, ProviderId,
};
use codewire_protected_store::ProtectedValue;
use codewire_protected_store::secret_envelope::{
    EncryptedTenantSecret, KekProvider, KekProviderKind, SECRET_FORMAT_V1, SecretCoordinates,
    SecretEnvelopeError, WRAPPED_DEK_FORMAT_V1, WrappedDek, decrypt_secret, encrypt_secret,
};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::model::{auth_kind, parse_auth_kind, parse_ssh_public_key, parse_status};
use crate::{
    CredentialRecord, CredentialRegistration, CredentialVersion, PlatformCredentialError as Error,
};

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_METADATA_PAGE: u32 = 1000;
const METADATA_COLUMNS: &str = "c.id, c.user_id, c.organization_id, c.provider, \
    c.authentication_kind, c.display_name, c.account_hint, c.status, \
    c.expires_at_unix, c.revocation_generation, c.material_generation, \
    c.ssh_public_key, c.ssh_fingerprint";
const OWNER_PREDICATE: &str = "((
    $1 = 'user' AND c.user_id = $2
    AND EXISTS (SELECT 1 FROM users u WHERE u.id = c.user_id)
) OR (
    $1 = 'organization' AND c.organization_id = $2
    AND EXISTS (SELECT 1 FROM organizations o
                WHERE o.id = c.organization_id AND o.deletion_state = 'active')
))";

/// This handle needs only SELECT on credential metadata and the owner identity/
/// deletion-state columns. It never queries material or calls a KEK provider.
/// Its database role is supplied by deployment, not established by this type.
#[derive(Clone)]
pub struct CredentialMetadataReader {
    pool: PgPool,
    catalog: ProviderCatalog,
}

impl CredentialMetadataReader {
    pub fn new(pool: PgPool, catalog: ProviderCatalog) -> Self {
        Self { pool, catalog }
    }

    pub async fn get(&self, owner: &Owner, id: &CredentialId) -> Result<CredentialMetadata, Error> {
        Ok(load_record(&self.pool, owner, id, false, &self.catalog)
            .await?
            .metadata)
    }

    /// Exact case-insensitive name lookup in one active owner namespace,
    /// matching the existing lower(display_name) unique indexes. No fuzzy,
    /// cross-owner or material lookup, and no row locks are acquired.
    pub async fn resolve(&self, owner: &Owner, name: &str) -> Result<CredentialMetadata, Error> {
        if name.is_empty()
            || name.len() > 256
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput);
        }
        let sql = format!(
            "SELECT {METADATA_COLUMNS} FROM platform_credentials c \
             WHERE {OWNER_PREDICATE} AND lower(c.display_name)=lower($3)"
        );
        let row: MetadataRow = sqlx::query_as(&sql)
            .bind(owner_kind(owner))
            .bind(owner.id().as_str())
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(Error::NotFound)?;
        Ok(row.record(&self.catalog)?.metadata)
    }

    /// Stable ID cursor, bounded independently of the caller. A missing or
    /// deleting owner returns an empty page, without revealing other owners.
    pub async fn list(
        &self,
        owner: &Owner,
        after: Option<&CredentialId>,
        limit: u32,
    ) -> Result<Vec<CredentialMetadata>, Error> {
        if limit == 0 || limit > MAX_METADATA_PAGE {
            return Err(Error::InvalidInput);
        }
        let sql = format!(
            "SELECT {METADATA_COLUMNS} FROM platform_credentials c \
             WHERE {OWNER_PREDICATE} AND ($3::text IS NULL OR c.id > $3) \
             ORDER BY c.id LIMIT $4"
        );
        let rows: Vec<MetadataRow> = sqlx::query_as(&sql)
            .bind(owner_kind(owner))
            .bind(owner.id().as_str())
            .bind(after.map(CredentialId::as_str))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(database_error)?;
        rows.into_iter()
            .map(|row| row.record(&self.catalog).map(|record| record.metadata))
            .collect()
    }
}

/// Trusted enrollment/broker authority. Do not install this handle or its
/// provider in a supervisor, workspace daemon, metadata API, or guest gateway.
pub struct PlatformCredentialStore {
    reader: CredentialMetadataReader,
    provider: Arc<dyn KekProvider>,
}

/// An owner-bound encrypted creation prepared outside a publication
/// transaction. No plaintext or public wire representation is retained here.
/// Consume it once using the same trusted store after authenticating its owner.
pub struct PreparedCredentialCreation {
    record: CredentialRecord,
    material: PreparedMaterial,
}

/// Ciphertext-only replacement bound to one exact authority-side record. No
/// plaintext, Debug implementation, or public wire representation is retained.
pub struct PreparedCredentialReplacement {
    original: CredentialRecord,
    next: CredentialRecord,
    material: PreparedMaterial,
    refresh: bool,
}

impl PlatformCredentialStore {
    pub(crate) fn pool(&self) -> &PgPool {
        &self.reader.pool
    }

    pub(crate) fn catalog(&self) -> &ProviderCatalog {
        &self.reader.catalog
    }

    pub(crate) fn provider(&self) -> &Arc<dyn KekProvider> {
        &self.provider
    }

    pub fn new(pool: PgPool, provider: Arc<dyn KekProvider>, catalog: ProviderCatalog) -> Self {
        Self {
            reader: CredentialMetadataReader::new(pool, catalog),
            provider,
        }
    }

    /// Authority-side metadata plus the internal CAS token; still no material.
    pub async fn record(
        &self,
        owner: &Owner,
        id: &CredentialId,
    ) -> Result<CredentialRecord, Error> {
        load_record(&self.reader.pool, owner, id, false, &self.reader.catalog).await
    }

    /// Lock the current exact-owner record in an already-authorized caller
    /// transaction. Internal material versions stay authority-side; a public
    /// lifecycle command may compare its observed metadata revision here, then
    /// pass this exact version to a mutation without releasing these locks.
    pub async fn record_for_update_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        id: &CredentialId,
    ) -> Result<CredentialRecord, Error> {
        check_owner(&mut **tx, owner, true).await?;
        load_record(&mut **tx, owner, id, true, &self.reader.catalog).await
    }

    /// Rename metadata under the caller's original authentication transaction.
    /// Names do not advance either credential counter, so the exact previous
    /// display name is part of this comparison. Material and profile references
    /// are unchanged; the caller owns final deadline checks and COMMIT/rollback.
    pub async fn rename_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        id: &CredentialId,
        expected_revocation_generation: u64,
        expected_display_name: &str,
        new_display_name: String,
    ) -> Result<CredentialRecord, Error> {
        generation(expected_revocation_generation)?;
        let mut current = self.record_for_update_in(tx, owner, id).await?;
        if current.metadata.revocation_generation != expected_revocation_generation
            || current.metadata.display_name != expected_display_name
        {
            return Err(Error::StaleVersion);
        }
        current.metadata.display_name = new_display_name;
        current.validate(&self.reader.catalog)?;
        sqlx::query(
            "UPDATE platform_credentials SET display_name=$2, updated_at=now() WHERE id=$1",
        )
        .bind(id.as_str())
        .bind(&current.metadata.display_name)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        load_record(&mut **tx, owner, id, false, &self.reader.catalog).await
    }

    pub async fn create(
        &self,
        owner: &Owner,
        registration: CredentialRegistration,
        material: &ProtectedValue,
    ) -> Result<CredentialRecord, Error> {
        let prepared = self.prepare_creation(owner, registration, material).await?;
        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        let record = self.create_prepared_in(&mut tx, owner, prepared).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }

    /// Prepare protected material before taking any publication or identity
    /// locks. This creates no durable credential or authorization grant.
    pub async fn prepare_creation(
        &self,
        owner: &Owner,
        registration: CredentialRegistration,
        material: &ProtectedValue,
    ) -> Result<PreparedCredentialCreation, Error> {
        let record = CredentialRecord::registered(owner, registration, &self.reader.catalog)?;
        check_owner(&self.reader.pool, owner, false).await?;
        let prepared = self.prepare(&record, material).await?;
        Ok(PreparedCredentialCreation {
            record,
            material: prepared,
        })
    }

    /// Create-only SSH admission. The private-field preparation type can only
    /// come from the pure, cryptographically verified generation/import helpers.
    /// No caller-supplied public metadata or arbitrary opaque bundle is accepted.
    /// Crypto must run in an authority-owned blocking worker before this call.
    pub async fn prepare_ssh_creation(
        &self,
        owner: &Owner,
        name: String,
        expires_at_unix: Option<u64>,
        prepared: codewire_protected_store::ssh_material::PreparedSshCredential,
    ) -> Result<PreparedCredentialCreation, Error> {
        let (public_key, material) = prepared.into_parts();
        let record = CredentialRecord::registered_ssh(
            owner,
            name,
            expires_at_unix,
            &public_key,
            &self.reader.catalog,
        )?;
        check_owner(&self.reader.pool, owner, false).await?;
        let material = self.prepare(&record, &material).await?;
        Ok(PreparedCredentialCreation { record, material })
    }

    /// Publish in the caller's transaction so original authentication locks
    /// and credential creation share one commit boundary. The caller must
    /// authorize this exact owner, retain its fences, recheck deadlines after
    /// awaited work, then commit or roll back. An uncertain commit ACK must
    /// never trigger automatic logout/revocation or blind enrollment retry.
    pub async fn create_prepared_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        prepared: PreparedCredentialCreation,
    ) -> Result<CredentialRecord, Error> {
        let PreparedCredentialCreation { record, material } = prepared;
        if record.metadata.owner != *owner {
            return Err(Error::InvalidInput);
        }
        record.validate(&self.reader.catalog)?;
        validate_wrapper(&material.wrapped, self.provider.kind())?;
        check_owner(&mut **tx, owner, true).await?;
        let (user_id, organization_id) = owner_columns(owner);
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id, user_id, organization_id, provider, authentication_kind, display_name, \
              account_hint, status, expires_at_unix, revocation_generation, material_generation, \
              ssh_public_key, ssh_fingerprint) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,1,1,$9,$10)",
        )
        .bind(record.metadata.id.as_str())
        .bind(user_id)
        .bind(organization_id)
        .bind(record.metadata.provider.as_str())
        .bind(auth_kind(record.metadata.authentication_kind))
        .bind(&record.metadata.display_name)
        .bind(&record.metadata.account_hint)
        .bind(optional_time(record.metadata.expires_at_unix)?)
        .bind(
            record
                .metadata
                .ssh_public_key
                .as_ref()
                .map(|key| key.openssh.as_str()),
        )
        .bind(
            record
                .metadata
                .ssh_public_key
                .as_ref()
                .map(|key| key.fingerprint.as_str()),
        )
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        insert_material(tx, &record, material).await?;
        Ok(record)
    }

    /// Deliberate owner replacement may reactivate a revoked identity, but
    /// only with its current comparison token. It never changes provider/owner.
    pub async fn replace(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        material: &ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, Error> {
        self.replace_inner(owner, id, expected, material, expires_at_unix, false)
            .await
    }

    /// Prepare an explicitly reconnected identity before publication locks.
    /// Preserve its canonical name and hard expiry; only the verified account
    /// hint and protected material change. The captured full version must still
    /// match after device login and again in the publication transaction.
    pub async fn prepare_replacement(
        &self,
        owner: &Owner,
        expected: &CredentialRecord,
        material: &ProtectedValue,
        account_hint: Option<String>,
    ) -> Result<PreparedCredentialReplacement, Error> {
        if expected.metadata.authentication_kind == CredentialAuthKind::SshKey {
            return Err(Error::UnsupportedCredential);
        }
        if expected.metadata.owner != *owner {
            return Err(Error::InvalidInput);
        }
        expected.validate(&self.reader.catalog)?;
        let current = self.record(owner, &expected.metadata.id).await?;
        compare_version(&current, expected.version)?;
        if current != *expected {
            return Err(Error::CorruptRecord);
        }
        let mut next = expected.clone();
        next.version = expected.version.replaced()?;
        next.metadata.revocation_generation = next.version.revocation_generation;
        next.metadata.status = CredentialStatus::Active;
        next.metadata.account_hint = account_hint;
        next.validate(&self.reader.catalog)?;
        let material = self.prepare(&next, material).await?;
        Ok(PreparedCredentialReplacement {
            original: expected.clone(),
            next,
            material,
            refresh: false,
        })
    }

    /// Prepare an explicit owner-requested API-key rotation, not an automatic
    /// refresh. Only OpenAI/Anthropic API-key identities are admitted. Like local
    /// rotation, this may reactivate a revoked/expired identity; an omitted hard
    /// expiry clears it. The exact original record remains fenced at publication.
    /// Payload grammar is validated by the isolated provider enrollment adapter.
    /// No transaction is committed and no old protected value is read here.
    pub async fn prepare_api_key_replacement(
        &self,
        owner: &Owner,
        expected: &CredentialRecord,
        value: &ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<PreparedCredentialReplacement, Error> {
        if expected.metadata.authentication_kind != CredentialAuthKind::ApiKey
            || !matches!(expected.metadata.provider.as_str(), "openai" | "anthropic")
        {
            return Err(Error::UnsupportedCredential);
        }
        if expected.metadata.owner != *owner {
            return Err(Error::InvalidInput);
        }
        expected.validate(&self.reader.catalog)?;
        validate_api_key_replacement_expiry(expires_at_unix)?;
        let current = self.record(owner, &expected.metadata.id).await?;
        compare_version(&current, expected.version)?;
        if current != *expected {
            return Err(Error::CorruptRecord);
        }
        let mut next = expected.clone();
        next.version = expected.version.replaced()?;
        next.metadata.revocation_generation = next.version.revocation_generation;
        next.metadata.status = CredentialStatus::Active;
        next.metadata.expires_at_unix = expires_at_unix;
        next.validate(&self.reader.catalog)?;
        let material = self.prepare(&next, value).await?;
        Ok(PreparedCredentialReplacement {
            original: expected.clone(),
            next,
            material,
            refresh: false,
        })
    }

    /// Publish an already obtained OAuth refresh result, not a provider refresh
    /// operation or a cross-replica refresh lock. A broker must serialize its
    /// external refresh operation separately. Stale results never reactivate a
    /// revoked identity or replace a newer owner-selected value. Refresh keeps
    /// the owner's hard credential deadline; only explicit replacement can
    /// change it. Access-token expiry is private to the protected OAuth bundle.
    pub async fn publish_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        material: &ProtectedValue,
    ) -> Result<CredentialRecord, Error> {
        self.replace_inner(owner, id, expected, material, None, true)
            .await
    }

    async fn replace_inner(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        material: &ProtectedValue,
        expires_at_unix: Option<u64>,
        refresh: bool,
    ) -> Result<CredentialRecord, Error> {
        expected.validate()?;
        let original = self.record(owner, id).await?;
        compare_version(&original, expected)?;
        if original.metadata.authentication_kind == CredentialAuthKind::SshKey {
            return Err(Error::UnsupportedCredential);
        }
        let mut next = original.clone();
        if refresh {
            require_oauth_refresh(&next)?;
        }
        next.version = expected.replaced()?;
        next.metadata.revocation_generation = next.version.revocation_generation;
        next.metadata.status = CredentialStatus::Active;
        if !refresh {
            next.metadata.expires_at_unix = expires_at_unix;
        }
        next.validate(&self.reader.catalog)?;
        let material = self.prepare(&next, material).await?;
        let prepared = PreparedCredentialReplacement {
            original,
            next,
            material,
            refresh,
        };
        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        let published = self.replace_prepared_in(&mut tx, owner, prepared).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(published)
    }

    /// Publish under the caller's original authentication/deadline fences. No
    /// KEK/provider operation or second connection is acquired under these locks.
    /// The caller owns rollback/COMMIT and uncertain acknowledgement handling.
    pub async fn replace_prepared_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        prepared: PreparedCredentialReplacement,
    ) -> Result<CredentialRecord, Error> {
        let PreparedCredentialReplacement {
            original,
            next,
            material,
            refresh,
        } = prepared;
        if original.metadata.authentication_kind == CredentialAuthKind::SshKey
            || next.metadata.authentication_kind == CredentialAuthKind::SshKey
        {
            return Err(Error::UnsupportedCredential);
        }
        if original.metadata.owner != *owner || next.metadata.owner != *owner {
            return Err(Error::InvalidInput);
        }
        // Reconnecting or replacing is enrollment: an organization never holds
        // an OAuth login. Refreshing an existing one is not enrollment.
        if !refresh && !owner.may_hold(next.metadata.authentication_kind) {
            return Err(Error::UnsupportedCredential);
        }
        original.validate(&self.reader.catalog)?;
        next.validate(&self.reader.catalog)?;
        validate_wrapper(&material.wrapped, self.provider.kind())?;
        let id = &original.metadata.id;
        let current = self.record_for_update_in(tx, owner, id).await?;
        compare_version(&current, original.version)?;
        if current != original {
            return Err(Error::CorruptRecord);
        }
        if refresh {
            require_oauth_refresh(&current)?;
        }
        if next.metadata.authentication_kind == CredentialAuthKind::ApiKey {
            // A valid future expiry at preparation may elapse while waiting
            // for publication locks. Runtime use still rechecks wall expiry;
            // this does not promise it cannot elapse during COMMIT itself.
            validate_api_key_replacement_expiry(next.metadata.expires_at_unix)?;
        }
        // Publication CAS alone must not bypass another replica's durable
        // provider operation. Owner replacement can clear only terminal or
        // never-started, expired attempts, within this same transaction.
        crate::refresh::fence_refresh_mutation(tx, id).await?;
        // These coordinates are immutable through this API. Reject corruption
        // or an unexpected writer instead of publishing under a changed key.
        if current.metadata.provider != next.metadata.provider
            || current.metadata.authentication_kind != next.metadata.authentication_kind
        {
            return Err(Error::CorruptRecord);
        }
        delete_material(tx, id).await?;
        sqlx::query(
            "UPDATE platform_credentials SET status='active', expires_at_unix=$2, \
             revocation_generation=$3, material_generation=$4, account_hint=$5, updated_at=now() WHERE id=$1",
        )
        .bind(id.as_str())
        .bind(optional_time(next.metadata.expires_at_unix)?)
        .bind(generation(next.version.revocation_generation)?)
        .bind(generation(next.version.material_generation)?)
        .bind(&next.metadata.account_hint)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        insert_material(tx, &next, material).await?;
        load_record(&mut **tx, owner, id, false, &self.reader.catalog).await
    }

    /// Revoke exactly the observed version and remove its active encrypted
    /// material atomically. Repeating that same successful revoke is harmless.
    pub async fn revoke(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<CredentialRecord, Error> {
        expected.validate()?;
        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        let record = self.revoke_in(&mut tx, owner, id, expected).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }

    /// Revoke within the caller's authentication-fenced transaction. The caller
    /// owns final deadline checks and commit/rollback, including uncertain ACKs.
    pub async fn revoke_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<CredentialRecord, Error> {
        expected.validate()?;
        let current = self.record_for_update_in(tx, owner, id).await?;
        if current.metadata.status == CredentialStatus::Revoked {
            if current.version != expected && Some(current.version) != expected.revoked().ok() {
                return Err(Error::StaleVersion);
            }
            crate::refresh::delete_refresh_attempt(tx, id).await?;
            return Ok(current);
        }
        compare_version(&current, expected)?;
        let next = expected.revoked()?;
        crate::refresh::delete_refresh_attempt(tx, id).await?;
        delete_material(tx, id).await?;
        sqlx::query("UPDATE platform_credentials SET status='revoked', revocation_generation=$2, updated_at=now() WHERE id=$1")
            .bind(id.as_str()).bind(generation(next.revocation_generation)?)
            .execute(&mut **tx).await.map_err(database_error)?;
        load_record(&mut **tx, owner, id, false, &self.reader.catalog).await
    }

    /// Forget one already revoked record. This is not a namespace sweep or a
    /// shared Transit-key deletion. Owner deletion uses exact database FKs.
    pub async fn delete_revoked(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<(), Error> {
        expected.validate()?;
        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        self.delete_revoked_in(&mut tx, owner, id, expected).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    /// Delete one already-revoked record while retaining the caller's original
    /// authentication fence through its final commit. Not a provider logout.
    pub async fn delete_revoked_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<(), Error> {
        expected.validate()?;
        let current = self.record_for_update_in(tx, owner, id).await?;
        compare_version(&current, expected)?;
        if current.metadata.status != CredentialStatus::Revoked {
            return Err(Error::Inactive);
        }
        // Profile writes hold credential SHARE while selecting references.
        // This UPDATE lock makes deletion and current/bound references atomic;
        // historical unbound revisions deliberately remain metadata-only.
        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM platform_access_profile_entries e \
             WHERE e.credential_id=$1 AND ( \
               EXISTS (SELECT 1 FROM platform_access_profiles p \
                       WHERE p.id=e.profile_id AND p.current_revision=e.revision) \
               OR EXISTS (SELECT 1 FROM platform_environment_access_bindings b \
                          WHERE b.profile_id=e.profile_id AND b.profile_revision=e.revision)))",
        )
        .bind(id.as_str())
        .fetch_one(&mut **tx)
        .await
        .map_err(database_error)?;
        if referenced {
            return Err(Error::CredentialInUse);
        }
        sqlx::query("DELETE FROM platform_credentials WHERE id=$1")
            .bind(id.as_str())
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    /// Return protected material to the trusted broker for an exact version.
    /// This store retains no material or DEK; the platform broker may reuse the
    /// returned value within one epoch only for this exact record. The final
    /// fence rejects revocation, expiry, replacement or owner deletion that
    /// occurred during unwrap.
    pub async fn read_for_broker(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<ProtectedValue, Error> {
        self.read_material(owner, id, expected, false).await
    }

    /// Read active OAuth material for the trusted, grant-checking refresh
    /// authority. The hard credential deadline still applies before and after
    /// unwrap; access-token expiry is private to the protected OAuth bundle.
    pub async fn read_for_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<ProtectedValue, Error> {
        self.read_material(owner, id, expected, true).await
    }

    async fn read_material(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        refresh: bool,
    ) -> Result<ProtectedValue, Error> {
        expected.validate()?;
        let record = self.record(owner, id).await?;
        compare_version(&record, expected)?;
        if refresh {
            require_oauth_refresh(&record)?;
        } else {
            record.active(unix_now()?)?;
        }
        let row: MaterialRow = sqlx::query_as(
            "SELECT kek_provider, key_name, key_version, wrapped_dek, wrapped_format, \
             ciphertext, nonce, format FROM platform_credential_material \
             WHERE credential_id=$1 AND material_generation=$2",
        )
        .bind(id.as_str())
        .bind(generation(expected.material_generation)?)
        .fetch_optional(&self.reader.pool)
        .await
        .map_err(database_error)?
        .ok_or(Error::StaleVersion)?;
        let prepared = row.prepared(self.provider.kind())?;
        let context = record.context();
        let dek = provider_call(self.provider.unwrap(&context, &prepared.wrapped)).await?;
        let value = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &record.path(),
                key: &record.key(),
            },
            &prepared.envelope,
        )
        .map_err(|_| Error::CorruptRecord)?;
        let protected = ProtectedValue::from_slice(&value).map_err(|_| Error::CorruptRecord)?;
        drop(value);
        drop(dek);

        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        check_owner(&mut *tx, owner, true).await?;
        let current = load_record(&mut *tx, owner, id, true, &self.reader.catalog).await?;
        compare_version(&current, expected)?;
        if current.metadata.provider != record.metadata.provider
            || current.metadata.authentication_kind != record.metadata.authentication_kind
        {
            return Err(Error::CorruptRecord);
        }
        if refresh {
            require_oauth_refresh(&current)?;
        } else {
            current.active(unix_now()?)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(protected)
    }

    async fn prepare(
        &self,
        record: &CredentialRecord,
        value: &ProtectedValue,
    ) -> Result<PreparedMaterial, Error> {
        let context = record.context();
        let generated = provider_call(self.provider.generate(&context)).await?;
        validate_wrapper(&generated.wrapped, self.provider.kind())?;
        let envelope = encrypt_secret(
            &generated.plaintext,
            &SecretCoordinates {
                context: &context,
                path: &record.path(),
                key: &record.key(),
            },
            value.expose_secret(),
        )
        .map_err(|_| Error::CorruptRecord)?;
        Ok(PreparedMaterial {
            envelope,
            wrapped: generated.wrapped,
        })
    }
}

#[derive(sqlx::FromRow)]
struct MetadataRow {
    id: String,
    user_id: Option<String>,
    organization_id: Option<String>,
    provider: String,
    authentication_kind: String,
    display_name: String,
    account_hint: Option<String>,
    ssh_public_key: Option<String>,
    ssh_fingerprint: Option<String>,
    status: String,
    expires_at_unix: Option<i64>,
    revocation_generation: i64,
    material_generation: i64,
}

impl MetadataRow {
    fn record(self, catalog: &ProviderCatalog) -> Result<CredentialRecord, Error> {
        let owner = match (self.user_id, self.organization_id) {
            (Some(id), None) => Owner::User(OwnerId::parse(id).map_err(|_| Error::CorruptRecord)?),
            (None, Some(id)) => {
                Owner::Organization(OwnerId::parse(id).map_err(|_| Error::CorruptRecord)?)
            }
            _ => return Err(Error::CorruptRecord),
        };
        let version = CredentialVersion {
            revocation_generation: u64::try_from(self.revocation_generation)
                .map_err(|_| Error::CorruptRecord)?,
            material_generation: u64::try_from(self.material_generation)
                .map_err(|_| Error::CorruptRecord)?,
        };
        let record = CredentialRecord {
            metadata: CredentialMetadata {
                id: CredentialId::parse(self.id).map_err(|_| Error::CorruptRecord)?,
                owner,
                placement: Placement::Platform,
                provider: ProviderId::parse(self.provider).map_err(|_| Error::CorruptRecord)?,
                authentication_kind: parse_auth_kind(&self.authentication_kind)?,
                display_name: self.display_name,
                account_hint: self.account_hint,
                ssh_public_key: parse_ssh_public_key(self.ssh_public_key, self.ssh_fingerprint)?,
                status: parse_status(&self.status)?,
                expires_at_unix: self
                    .expires_at_unix
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| Error::CorruptRecord)?,
                revocation_generation: version.revocation_generation,
            },
            version,
        };
        record.validate(catalog).map_err(|_| Error::CorruptRecord)?;
        Ok(record)
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct MaterialRow {
    kek_provider: String,
    key_name: String,
    key_version: i64,
    wrapped_dek: Vec<u8>,
    wrapped_format: i16,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    format: i16,
}

pub(crate) struct PreparedMaterial {
    pub(crate) envelope: EncryptedTenantSecret,
    pub(crate) wrapped: WrappedDek,
}

impl MaterialRow {
    pub(crate) fn prepared(self, provider: KekProviderKind) -> Result<PreparedMaterial, Error> {
        let wrapped = WrappedDek {
            provider: KekProviderKind::from_persisted(&self.kek_provider)
                .ok_or(Error::CorruptRecord)?,
            key_name: self.key_name,
            key_version: u32::try_from(self.key_version).map_err(|_| Error::CorruptRecord)?,
            ciphertext: self.wrapped_dek,
            nonce: None,
            format: self.wrapped_format,
        };
        validate_wrapper(&wrapped, provider)?;
        Ok(PreparedMaterial {
            wrapped,
            envelope: EncryptedTenantSecret {
                ciphertext: self.ciphertext,
                nonce: self.nonce,
                format: self.format,
            },
        })
    }
}

pub(crate) fn validate_wrapper(
    wrapped: &WrappedDek,
    provider: KekProviderKind,
) -> Result<(), Error> {
    if wrapped.provider != provider
        || wrapped.key_version == 0
        || wrapped.format != WRAPPED_DEK_FORMAT_V1
        || wrapped.nonce.is_some()
        || wrapped.ciphertext.is_empty()
        || wrapped.ciphertext.len() > 65_536
        || wrapped.key_name.is_empty()
        || wrapped.key_name.len() > 256
        || wrapped.key_name.chars().any(char::is_control)
    {
        return Err(Error::CorruptRecord);
    }
    Ok(())
}

/// The account's one GitHub App OAuth connection, when it can be used now.
///
/// Every personal profile includes GitHub and never stores its credential ID.
/// Launch authority resolves the connection at use time: a missing, revoked or
/// expired connection yields `None`, so the profile's choice is omitted rather
/// than fabricated, and a later reconnect restores it without a new revision.
/// Organizations never hold a GitHub connection.
pub async fn active_github_connection<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    owner: &Owner,
) -> Result<Option<CredentialId>, Error> {
    let Owner::User(user_id) = owner else {
        return Ok(None);
    };
    let ids: Vec<String> = sqlx::query_scalar(active_github_connection_ids!())
        .bind(user_id.as_str())
        .fetch_all(executor)
        .await
        .map_err(database_error)?;
    github_connection(ids)
}

/// The connection among the rows `active_github_connection_ids!` read.
pub(crate) fn github_connection(ids: Vec<String>) -> Result<Option<CredentialId>, Error> {
    match ids.as_slice() {
        [] => Ok(None),
        [id] => CredentialId::parse(id.as_str())
            .map(Some)
            .map_err(|_| Error::CorruptRecord),
        // The singleton index forbids this; never pick a winner.
        _ => Err(Error::CorruptRecord),
    }
}

/// The account's GitHub connection, read exactly as `active_github_connection`
/// reads it, and which of `ids` and that connection exist and belong to
/// `owner`.
pub struct OwnedCredentials {
    /// The connection, or why none could be chosen. Always `Ok(None)` when it
    /// was not requested or `owner` is an organization.
    pub github: Result<Option<CredentialId>, Error>,
    /// The requested IDs and the connection that belong to `owner`.
    pub owned: BTreeSet<String>,
}

/// One statement for two reads that runtime authority makes back to back:
/// the owner's GitHub connection (only when `github` is set) and the
/// ownership of `ids` plus that connection. Neither read locks a row. Both now
/// share one snapshot, which is the original sequence when nothing commits
/// between them. A caller must check `github` before `owned`, as it did when
/// the ownership read could only follow a usable connection.
///
/// The statement always names the GitHub filter columns (`provider`,
/// `authentication_kind`, `status`, `expires_at_unix`), even when `github` is
/// false and the filter matches nothing, and PostgreSQL checks SELECT on every
/// named column. The caller's role therefore needs those columns where the
/// separate ownership read needed only `id`, `user_id` and `organization_id`.
/// Runtime authority's role has them: it read them for the GitHub connection.
pub async fn owned_credentials_and_github_connection<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    owner: &Owner,
    ids: &[String],
    github: bool,
) -> Result<OwnedCredentials, Error> {
    let (user_id, organization_id) = match owner {
        Owner::User(id) => (Some(id.as_str()), None),
        Owner::Organization(id) => (None, Some(id.as_str())),
    };
    let (connection, owned): (Vec<String>, Vec<String>) =
        sqlx::query_as(OWNED_WITH_GITHUB_CONNECTION)
            .bind(user_id.filter(|_| github))
            .bind(user_id)
            .bind(organization_id)
            .bind(ids)
            .fetch_one(executor)
            .await
            .map_err(database_error)?;
    Ok(OwnedCredentials {
        github: github_connection(connection),
        owned: owned.into_iter().collect(),
    })
}

const OWNED_WITH_GITHUB_CONNECTION: &str = concat!(
    "WITH github AS (",
    active_github_connection_ids!(),
    ") SELECT ARRAY(SELECT id FROM github ORDER BY id) AS github, \
     ARRAY(SELECT id FROM public.platform_credentials WHERE \
     ((user_id=$2 AND organization_id IS NULL) OR (organization_id=$3 AND user_id IS NULL)) \
     AND (id=ANY($4) OR id IN (SELECT id FROM github))) AS owned"
);

pub(crate) async fn load_record<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    owner: &Owner,
    id: &CredentialId,
    lock: bool,
    catalog: &ProviderCatalog,
) -> Result<CredentialRecord, Error> {
    let suffix = if lock { " FOR UPDATE OF c" } else { "" };
    let sql = format!(
        "SELECT {METADATA_COLUMNS} FROM platform_credentials c WHERE {OWNER_PREDICATE} AND c.id=$3{suffix}"
    );
    let row: MetadataRow = sqlx::query_as(&sql)
        .bind(owner_kind(owner))
        .bind(owner.id().as_str())
        .bind(id.as_str())
        .fetch_optional(executor)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
    row.record(catalog)
}

pub(crate) async fn check_owner<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    owner: &Owner,
    lock: bool,
) -> Result<(), Error> {
    if lock {
        // The fixed definer helper retains SHARE until this transaction ends,
        // without giving enrollment/broker UPDATE authority over an owner.
        let found: bool =
            sqlx::query_scalar("SELECT public.codewire_platform_lock_owner($1::text,$2::text)")
                .bind(owner_kind(owner))
                .bind(owner.id().as_str())
                .fetch_one(executor)
                .await
                .map_err(database_error)?;
        return if found { Ok(()) } else { Err(Error::NotFound) };
    }
    // The metadata reader remains SELECT-only, with no helper EXECUTE grant.
    let sql = match owner {
        Owner::User(_) => "SELECT id FROM users WHERE id=$1",
        Owner::Organization(_) => {
            "SELECT id FROM organizations WHERE id=$1 AND deletion_state='active'"
        }
    };
    sqlx::query_scalar::<_, String>(sql)
        .bind(owner.id().as_str())
        .fetch_optional(executor)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
    Ok(())
}

pub(crate) async fn insert_material(
    tx: &mut Transaction<'_, Postgres>,
    record: &CredentialRecord,
    prepared: PreparedMaterial,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO platform_credential_material \
         (credential_id, material_generation, kek_provider, key_name, key_version, \
          wrapped_dek, wrapped_format, ciphertext, nonce, format) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(record.metadata.id.as_str())
    .bind(generation(record.version.material_generation)?)
    .bind(prepared.wrapped.provider.as_str())
    .bind(prepared.wrapped.key_name)
    .bind(i64::from(prepared.wrapped.key_version))
    .bind(prepared.wrapped.ciphertext)
    .bind(prepared.wrapped.format)
    .bind(prepared.envelope.ciphertext)
    .bind(prepared.envelope.nonce)
    .bind(SECRET_FORMAT_V1)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}

pub(crate) async fn delete_material(
    tx: &mut Transaction<'_, Postgres>,
    id: &CredentialId,
) -> Result<(), Error> {
    sqlx::query("DELETE FROM platform_credential_material WHERE credential_id=$1")
        .bind(id.as_str())
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

fn owner_kind(owner: &Owner) -> &'static str {
    match owner {
        Owner::User(_) => "user",
        Owner::Organization(_) => "organization",
    }
}

fn owner_columns(owner: &Owner) -> (Option<&str>, Option<&str>) {
    match owner {
        Owner::User(id) => (Some(id.as_str()), None),
        Owner::Organization(id) => (None, Some(id.as_str())),
    }
}

pub(crate) fn compare_version(
    record: &CredentialRecord,
    expected: CredentialVersion,
) -> Result<(), Error> {
    if record.version == expected {
        Ok(())
    } else {
        Err(Error::StaleVersion)
    }
}

pub(crate) fn require_oauth_refresh(record: &CredentialRecord) -> Result<(), Error> {
    if record.metadata.authentication_kind != CredentialAuthKind::OAuth {
        return Err(Error::UnsupportedCredential);
    }
    record.active(unix_now()?)
}

pub(crate) fn generation(value: u64) -> Result<i64, Error> {
    if value == 0 {
        return Err(Error::InvalidInput);
    }
    i64::try_from(value).map_err(|_| Error::InvalidInput)
}

fn optional_time(value: Option<u64>) -> Result<Option<i64>, Error> {
    value
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::InvalidInput)
}

fn validate_api_key_replacement_expiry(expiry: Option<u64>) -> Result<(), Error> {
    optional_time(expiry)?;
    if let Some(expiry) = expiry
        && expiry <= unix_now()?
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::ClockUnavailable)
}

pub(crate) fn database_error(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "23505")
    {
        Error::AlreadyExists
    } else {
        Error::DatabaseUnavailable
    }
}

pub(crate) async fn provider_call<T>(
    operation: impl Future<Output = Result<T, SecretEnvelopeError>>,
) -> Result<T, Error> {
    tokio::time::timeout(PROVIDER_TIMEOUT, operation)
        .await
        .map_err(|_| Error::ProviderTimedOut)?
        .map_err(|_| Error::ProviderUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn provider_deadline_is_bounded_and_drops_the_pending_operation() {
        struct PendingGuard(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for PendingGuard {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = PendingGuard(dropped.clone());
        let operation = async move {
            let _guard = guard;
            std::future::pending::<Result<(), SecretEnvelopeError>>().await
        };
        let started = tokio::time::Instant::now();
        assert_eq!(provider_call(operation).await, Err(Error::ProviderTimedOut));
        assert_eq!(started.elapsed(), PROVIDER_TIMEOUT);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn opaque_database_error_source_is_discarded() {
        use std::error::Error as _;
        let error = database_error(sqlx::Error::Io(std::io::Error::other(
            "synthetic-untrusted-database-payload",
        )));
        assert_eq!(error, Error::DatabaseUnavailable);
        assert!(error.source().is_none());
        for output in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!output.contains("synthetic-untrusted-database-payload"));
        }
    }
}
