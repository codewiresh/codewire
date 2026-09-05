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

use crate::model::{auth_kind, parse_auth_kind, parse_status};
use crate::{
    CredentialRecord, CredentialRegistration, CredentialVersion, PlatformCredentialError as Error,
};

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_METADATA_PAGE: u32 = 1000;
const METADATA_COLUMNS: &str = "c.id, c.user_id, c.organization_id, c.provider, \
    c.authentication_kind, c.display_name, c.account_hint, c.status, \
    c.expires_at_unix, c.revocation_generation, c.material_generation";
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

impl PlatformCredentialStore {
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

    pub async fn create(
        &self,
        owner: &Owner,
        registration: CredentialRegistration,
        material: &ProtectedValue,
    ) -> Result<CredentialRecord, Error> {
        let record = CredentialRecord::registered(owner, registration, &self.reader.catalog)?;
        check_owner(&self.reader.pool, owner, false).await?;
        let prepared = self.prepare(&record, material).await?;
        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        check_owner(&mut *tx, owner, true).await?;
        let (user_id, organization_id) = owner_columns(owner);
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id, user_id, organization_id, provider, authentication_kind, display_name, \
              account_hint, status, expires_at_unix, revocation_generation, material_generation) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,1,1)",
        )
        .bind(record.metadata.id.as_str())
        .bind(user_id)
        .bind(organization_id)
        .bind(record.metadata.provider.as_str())
        .bind(auth_kind(record.metadata.authentication_kind))
        .bind(&record.metadata.display_name)
        .bind(&record.metadata.account_hint)
        .bind(optional_time(record.metadata.expires_at_unix)?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        insert_material(&mut tx, &record, prepared).await?;
        tx.commit().await.map_err(database_error)?;
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

    /// Publish an already obtained OAuth refresh result, not a provider refresh
    /// operation or a cross-replica refresh lock. A broker must serialize its
    /// external refresh operation separately. Stale results never reactivate a
    /// revoked identity or replace a newer owner-selected value.
    pub async fn publish_oauth_refresh(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
        material: &ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, Error> {
        self.replace_inner(owner, id, expected, material, expires_at_unix, true)
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
        let mut next = self.record(owner, id).await?;
        compare_version(&next, expected)?;
        if refresh {
            require_oauth_refresh(&next)?;
        }
        next.version = expected.replaced()?;
        next.metadata.revocation_generation = next.version.revocation_generation;
        next.metadata.status = CredentialStatus::Active;
        next.metadata.expires_at_unix = expires_at_unix;
        next.validate(&self.reader.catalog)?;
        let prepared = self.prepare(&next, material).await?;

        let mut tx = self.reader.pool.begin().await.map_err(database_error)?;
        check_owner(&mut *tx, owner, true).await?;
        let current = load_record(&mut *tx, owner, id, true, &self.reader.catalog).await?;
        compare_version(&current, expected)?;
        if refresh {
            require_oauth_refresh(&current)?;
        }
        // These coordinates are immutable through this API. Reject corruption
        // or an unexpected writer instead of publishing under a changed key.
        if current.metadata.provider != next.metadata.provider
            || current.metadata.authentication_kind != next.metadata.authentication_kind
        {
            return Err(Error::CorruptRecord);
        }
        delete_material(&mut tx, id).await?;
        sqlx::query(
            "UPDATE platform_credentials SET status='active', expires_at_unix=$2, \
             revocation_generation=$3, material_generation=$4, updated_at=now() WHERE id=$1",
        )
        .bind(id.as_str())
        .bind(optional_time(expires_at_unix)?)
        .bind(generation(next.version.revocation_generation)?)
        .bind(generation(next.version.material_generation)?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        insert_material(&mut tx, &next, prepared).await?;
        let published = load_record(&mut *tx, owner, id, false, &self.reader.catalog).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(published)
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
        check_owner(&mut *tx, owner, true).await?;
        let current = load_record(&mut *tx, owner, id, true, &self.reader.catalog).await?;
        if current.metadata.status == CredentialStatus::Revoked {
            if current.version != expected && Some(current.version) != expected.revoked().ok() {
                return Err(Error::StaleVersion);
            }
            tx.commit().await.map_err(database_error)?;
            return Ok(current);
        }
        compare_version(&current, expected)?;
        let next = expected.revoked()?;
        delete_material(&mut tx, id).await?;
        sqlx::query("UPDATE platform_credentials SET status='revoked', revocation_generation=$2, updated_at=now() WHERE id=$1")
            .bind(id.as_str()).bind(generation(next.revocation_generation)?)
            .execute(&mut *tx).await.map_err(database_error)?;
        let revoked = load_record(&mut *tx, owner, id, false, &self.reader.catalog).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(revoked)
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
        check_owner(&mut *tx, owner, true).await?;
        let current = load_record(&mut *tx, owner, id, true, &self.reader.catalog).await?;
        compare_version(&current, expected)?;
        if current.metadata.status != CredentialStatus::Revoked {
            return Err(Error::Inactive);
        }
        sqlx::query("DELETE FROM platform_credentials WHERE id=$1")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    /// Return protected material to the trusted broker for an exact version.
    /// No material/DEK cache is retained. The final fence rejects revocation,
    /// expiry, replacement or owner deletion that occurred during unwrap.
    pub async fn read_for_broker(
        &self,
        owner: &Owner,
        id: &CredentialId,
        expected: CredentialVersion,
    ) -> Result<ProtectedValue, Error> {
        self.read_material(owner, id, expected, false).await
    }

    /// Access-token expiry does not invalidate the OAuth refresh token. Only
    /// the trusted, grant-checking refresh authority may use this operation.
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
struct MaterialRow {
    kek_provider: String,
    key_name: String,
    key_version: i64,
    wrapped_dek: Vec<u8>,
    wrapped_format: i16,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    format: i16,
}

struct PreparedMaterial {
    envelope: EncryptedTenantSecret,
    wrapped: WrappedDek,
}

impl MaterialRow {
    fn prepared(self, provider: KekProviderKind) -> Result<PreparedMaterial, Error> {
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

fn validate_wrapper(wrapped: &WrappedDek, provider: KekProviderKind) -> Result<(), Error> {
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

async fn load_record<'e, E: Executor<'e, Database = Postgres>>(
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

async fn check_owner<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    owner: &Owner,
    lock: bool,
) -> Result<(), Error> {
    // SHARE, not KEY SHARE: organization deletion changes a non-key column.
    // Metadata-only reads use plain SELECT and do not require UPDATE rights.
    let sql = match (owner, lock) {
        (Owner::User(_), false) => "SELECT id FROM users WHERE id=$1",
        (Owner::User(_), true) => "SELECT id FROM users WHERE id=$1 FOR SHARE",
        (Owner::Organization(_), false) => {
            "SELECT id FROM organizations WHERE id=$1 AND deletion_state='active'"
        }
        (Owner::Organization(_), true) => {
            "SELECT id FROM organizations WHERE id=$1 AND deletion_state='active' FOR SHARE"
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

async fn insert_material(
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

async fn delete_material(
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

fn compare_version(record: &CredentialRecord, expected: CredentialVersion) -> Result<(), Error> {
    if record.version == expected {
        Ok(())
    } else {
        Err(Error::StaleVersion)
    }
}

fn require_oauth_refresh(record: &CredentialRecord) -> Result<(), Error> {
    if record.metadata.authentication_kind != CredentialAuthKind::OAuth {
        return Err(Error::UnsupportedCredential);
    }
    if record.metadata.status != CredentialStatus::Active {
        return Err(Error::Inactive);
    }
    Ok(())
}

fn generation(value: u64) -> Result<i64, Error> {
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

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::ClockUnavailable)
}

fn database_error(error: sqlx::Error) -> Error {
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

async fn provider_call<T>(
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
