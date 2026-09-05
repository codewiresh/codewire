//! AES-GCM tenant-secret storage backed by PostgreSQL and OpenBao Transit.
//!
//! Every mutation holds a transaction-scoped per-tenant lock. The application
//! has one storage authority: encrypted envelopes in PostgreSQL whose DEKs are
//! wrapped by OpenBao Transit.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use codewire_workload_secrets::validate_workload_secret_value;

use super::secrets::{StoredSecret, StoredSecretMetadata, is_valid_secret_key};
use codewire_protected_store::openbao_workload_identity::KubernetesOpenBaoWorkloadIdentity;
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, EncryptedTenantSecret, GeneratedDek, KekProvider, KekProviderKind,
    OpenBaoTransitConfig, OpenBaoTransitProvider, SecretCoordinates, SecretEnvelopeError,
    WrappedDek, decrypt_secret, dek_fingerprint, encrypt_secret, verify_dek_fingerprint,
};

const MAX_CACHED_DEKS: usize = 4096;
const CANARY_LOCK_KEY: i64 = 0x4357_5453_4341_4e31;
const SCOPE_LOCK_DOMAIN: &[u8] = b"codewire/tenant-secret-scope-lock/v1\0";

fn store_error(class: &'static str) -> anyhow::Error {
    anyhow::anyhow!("tenant-secret-store failure_class={class}")
}

fn envelope_error(error: SecretEnvelopeError) -> anyhow::Error {
    anyhow::anyhow!(error)
}

#[derive(sqlx::FromRow)]
struct DekRow {
    dek_id: String,
    scope: String,
    scope_id: String,
    provider: String,
    key_name: String,
    key_version: i64,
    wrapped_dek: String,
    format: i16,
}

#[derive(sqlx::FromRow)]
struct SecretRow {
    key: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    format: i16,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct SecretMetadataRow {
    key: String,
    scope: String,
    scope_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RenameRow {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    format: i16,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct CanaryRow {
    provider: String,
    key_name: String,
    key_version: i64,
    wrapped_dek: String,
    format: i16,
    expected_authority_id: Option<String>,
    plaintext_sha256: Vec<u8>,
}

struct CachedDek {
    value: Zeroizing<[u8; DEK_BYTES]>,
    last_used: u64,
}

#[derive(Default)]
struct DekCache {
    entries: HashMap<String, CachedDek>,
    clock: u64,
}

impl DekCache {
    fn next_clock(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn get(&mut self, dek_id: &str) -> Option<Zeroizing<[u8; DEK_BYTES]>> {
        let now = self.next_clock();
        let entry = self.entries.get_mut(dek_id)?;
        entry.last_used = now;
        Some(entry.value.clone())
    }

    fn insert(&mut self, dek_id: String, value: Zeroizing<[u8; DEK_BYTES]>) {
        let now = self.next_clock();
        if let Some(entry) = self.entries.get_mut(&dek_id) {
            entry.value = value;
            entry.last_used = now;
            return;
        }
        if self.entries.len() >= MAX_CACHED_DEKS
            && let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(dek_id, _)| dek_id.clone())
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(
            dek_id,
            CachedDek {
                value,
                last_used: now,
            },
        );
    }

    fn remove(&mut self, dek_id: &str) {
        self.entries.remove(dek_id);
    }
}

pub struct PostgresSecretStore {
    pool: PgPool,
    provider: Arc<dyn KekProvider>,
    cache: Mutex<DekCache>,
}

impl PostgresSecretStore {
    pub fn new(pool: PgPool, provider: Arc<dyn KekProvider>) -> Self {
        Self {
            pool,
            provider,
            cache: Mutex::new(DekCache::default()),
        }
    }

    pub fn from_env(pool: PgPool, kube: kube::Client) -> anyhow::Result<Self> {
        let identity = Arc::new(KubernetesOpenBaoWorkloadIdentity::from_env(
            kube,
            "TENANT_SECRET_BAO_AUDIENCE",
        )?);
        let provider: Arc<dyn KekProvider> = Arc::new(
            OpenBaoTransitProvider::new(
                OpenBaoTransitConfig::from_env().map_err(envelope_error)?,
                identity,
            )
            .map_err(envelope_error)?,
        );
        Ok(Self::new(pool, provider))
    }

    async fn lock_scope(
        tx: &mut Transaction<'_, Postgres>,
        context: &DekContext,
    ) -> anyhow::Result<()> {
        let mut digest = Sha256::new();
        digest.update(SCOPE_LOCK_DOMAIN);
        digest.update((context.scope.as_str().len() as u64).to_be_bytes());
        digest.update(context.scope.as_str().as_bytes());
        digest.update((context.scope_id.len() as u64).to_be_bytes());
        digest.update(context.scope_id.as_bytes());
        let lock_key = i64::from_be_bytes(digest.finalize()[..8].try_into().expect("sha256 width"));
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| store_error("scope-lock-failed"))?;
        Ok(())
    }

    async fn fetch_dek_pool(&self, context: &DekContext) -> anyhow::Result<Option<DekRow>> {
        sqlx::query_as(
            "SELECT dek_id, scope, scope_id, provider, key_name, key_version, \
                    wrapped_dek, format \
             FROM tenant_secret_deks WHERE scope = $1 AND scope_id = $2",
        )
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| store_error("dek-query-failed"))
    }

    async fn fetch_dek_locked(
        tx: &mut Transaction<'_, Postgres>,
        context: &DekContext,
    ) -> anyhow::Result<Option<DekRow>> {
        sqlx::query_as(
            "SELECT dek_id, scope, scope_id, provider, key_name, key_version, \
                    wrapped_dek, format \
             FROM tenant_secret_deks WHERE scope = $1 AND scope_id = $2 FOR UPDATE",
        )
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| store_error("dek-lock-failed"))
    }

    fn wrapped_from_row(row: &DekRow) -> anyhow::Result<WrappedDek> {
        let provider = KekProviderKind::from_persisted(&row.provider)
            .ok_or_else(|| store_error("invalid-persisted-provider"))?;
        let key_version = u32::try_from(row.key_version)
            .map_err(|_| store_error("invalid-persisted-key-version"))?;
        let ciphertext = row.wrapped_dek.as_bytes().to_vec();
        Ok(WrappedDek {
            provider,
            key_name: row.key_name.clone(),
            key_version,
            ciphertext,
            nonce: None,
            format: row.format,
        })
    }

    fn wrapped_field(wrapped: &WrappedDek) -> anyhow::Result<String> {
        if wrapped.nonce.is_some() {
            return Err(store_error("invalid-provider-wrapper"));
        }
        Ok(std::str::from_utf8(&wrapped.ciphertext)
            .map_err(|_| store_error("invalid-provider-wrapper"))?
            .to_owned())
    }

    fn validate_row_context(row: &DekRow, context: &DekContext) -> anyhow::Result<()> {
        if row.scope != context.scope.as_str() || row.scope_id != context.scope_id {
            return Err(store_error("dek-scope-mismatch"));
        }
        Ok(())
    }

    async fn unwrap_dek(
        &self,
        context: &DekContext,
        row: &DekRow,
    ) -> anyhow::Result<Zeroizing<[u8; DEK_BYTES]>> {
        Self::validate_row_context(row, context)?;
        if let Some(dek) = self.cache.lock().await.get(&row.dek_id) {
            return Ok(dek);
        }
        let wrapped = Self::wrapped_from_row(row)?;
        if wrapped.provider != self.provider.kind() {
            return Err(store_error("provider-authority-mismatch"));
        }
        let dek = self
            .provider
            .unwrap(context, &wrapped)
            .await
            .map_err(envelope_error)?;
        self.cache
            .lock()
            .await
            .insert(row.dek_id.clone(), dek.clone());
        Ok(dek)
    }

    async fn insert_generated_dek(
        tx: &mut Transaction<'_, Postgres>,
        context: &DekContext,
        generated: &GeneratedDek,
    ) -> anyhow::Result<String> {
        let dek_id = uuid::Uuid::new_v4().to_string();
        let wrapped_dek = Self::wrapped_field(&generated.wrapped)?;
        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek, format) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&dek_id)
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .bind(generated.wrapped.provider.as_str())
        .bind(&generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(wrapped_dek)
        .bind(generated.wrapped.format)
        .execute(&mut **tx)
        .await
        .map_err(|_| store_error("dek-insert-failed"))?;
        Ok(dek_id)
    }

    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        let Some(dek_row) = self.fetch_dek_pool(&context).await? else {
            return Ok(Vec::new());
        };
        let dek = self.unwrap_dek(&context, &dek_row).await?;
        let rows: Vec<SecretRow> = sqlx::query_as(
            "SELECT key, ciphertext, nonce, format, created_at, updated_at \
             FROM tenant_secrets WHERE path = $1 AND dek_id = $2 ORDER BY key",
        )
        .bind(secret_path)
        .bind(&dek_row.dek_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| store_error("secret-query-failed"))?;
        rows.into_iter()
            .map(|row| {
                let envelope = EncryptedTenantSecret {
                    ciphertext: row.ciphertext,
                    nonce: row.nonce,
                    format: row.format,
                };
                let coordinates = SecretCoordinates {
                    context: &context,
                    path: secret_path,
                    key: &row.key,
                };
                let plaintext =
                    decrypt_secret(&dek, &coordinates, &envelope).map_err(envelope_error)?;
                let value = String::from_utf8(plaintext.to_vec())
                    .map_err(|_| store_error("secret-plaintext-invalid"))?;
                Ok(StoredSecret {
                    key: row.key,
                    value,
                    created_at: row.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    updated_at: row.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                })
            })
            .collect()
    }

    pub async fn get_secret_metadata_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        let rows: Vec<SecretMetadataRow> = sqlx::query_as(
            "SELECT key, scope, scope_id, created_at, updated_at \
             FROM tenant_secrets WHERE path = $1 ORDER BY key",
        )
        .bind(secret_path)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| store_error("secret-metadata-query-failed"))?;
        Self::metadata_rows(&context, rows)
    }

    pub async fn get_secret_metadata_at_path_bounded(
        &self,
        secret_path: &str,
        maximum_rows: usize,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        let maximum_rows = i64::try_from(maximum_rows)
            .map_err(|_| store_error("secret-metadata-limit-invalid"))?;
        let rows: Vec<SecretMetadataRow> = sqlx::query_as(
            "SELECT key, scope, scope_id, created_at, updated_at \
             FROM tenant_secrets WHERE path = $1 ORDER BY key LIMIT $2",
        )
        .bind(secret_path)
        .bind(maximum_rows)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| store_error("secret-metadata-query-failed"))?;
        Self::metadata_rows(&context, rows)
    }

    fn metadata_rows(
        context: &DekContext,
        rows: Vec<SecretMetadataRow>,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        rows.into_iter()
            .map(|row| {
                if row.scope != context.scope.as_str() || row.scope_id != context.scope_id {
                    return Err(store_error("secret-metadata-scope-mismatch"));
                }
                if !is_valid_secret_key(&row.key) {
                    return Err(store_error("invalid-persisted-secret-key"));
                }
                Ok(StoredSecretMetadata {
                    key: row.key,
                    created_at: row.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    updated_at: row.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                })
            })
            .collect()
    }

    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if !is_valid_secret_key(key) {
            return Err(store_error("invalid-secret-key"));
        }
        validate_workload_secret_value(value.as_bytes())
            .map_err(|_| store_error("invalid-secret-value"))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_scope(&mut tx, &context).await?;

        let existing = Self::fetch_dek_locked(&mut tx, &context).await?;
        let (dek_id, dek, generated) = if let Some(row) = existing {
            let dek = self.unwrap_dek(&context, &row).await?;
            (row.dek_id, dek, false)
        } else {
            let generated = self
                .provider
                .generate(&context)
                .await
                .map_err(envelope_error)?;
            let dek_id = Self::insert_generated_dek(&mut tx, &context, &generated).await?;
            (dek_id, generated.plaintext, true)
        };
        let coordinates = SecretCoordinates {
            context: &context,
            path: secret_path,
            key,
        };
        let encrypted =
            encrypt_secret(&dek, &coordinates, value.as_bytes()).map_err(envelope_error)?;
        sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, storage_contract_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1) \
             ON CONFLICT (path, key) DO UPDATE SET \
               dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, scope_id = EXCLUDED.scope_id, \
               ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce, \
               format = EXCLUDED.format, updated_at = now()",
        )
        .bind(secret_path)
        .bind(key)
        .bind(&dek_id)
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .bind(encrypted.ciphertext)
        .bind(encrypted.nonce)
        .bind(encrypted.format)
        .execute(&mut *tx)
        .await
        .map_err(|_| store_error("secret-upsert-failed"))?;
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        if generated {
            self.cache.lock().await.insert(dek_id, dek);
        }
        Ok(())
    }

    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if !is_valid_secret_key(key) {
            return Err(store_error("invalid-secret-key"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_scope(&mut tx, &context).await?;
        let Some(row) = Self::fetch_dek_locked(&mut tx, &context).await? else {
            tx.commit()
                .await
                .map_err(|_| store_error("transaction-commit-failed"))?;
            return Ok(());
        };
        sqlx::query("DELETE FROM tenant_secrets WHERE path = $1 AND key = $2 AND dek_id = $3")
            .bind(secret_path)
            .bind(key)
            .bind(&row.dek_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| store_error("secret-delete-failed"))?;
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM tenant_secrets WHERE dek_id = $1")
                .bind(&row.dek_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| store_error("secret-count-failed"))?;
        if remaining == 0 {
            sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = $1")
                .bind(&row.dek_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| store_error("dek-delete-failed"))?;
        }
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        if remaining == 0 {
            self.cache.lock().await.remove(&row.dek_id);
        }
        Ok(())
    }

    /// Remove one complete product path atomically. Organization teardown can
    /// safely retry after any database error: it never observes a half-deleted
    /// path, and the shared scope DEK remains until its final path is empty.
    pub async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_scope(&mut tx, &context).await?;
        let Some(row) = Self::fetch_dek_locked(&mut tx, &context).await? else {
            tx.commit()
                .await
                .map_err(|_| store_error("transaction-commit-failed"))?;
            return Ok(());
        };
        sqlx::query("DELETE FROM tenant_secrets WHERE path = $1 AND dek_id = $2")
            .bind(secret_path)
            .bind(&row.dek_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| store_error("path-delete-failed"))?;
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM tenant_secrets WHERE dek_id = $1")
                .bind(&row.dek_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| store_error("secret-count-failed"))?;
        if remaining == 0 {
            sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = $1")
                .bind(&row.dek_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| store_error("dek-delete-failed"))?;
        }
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        if remaining == 0 {
            self.cache.lock().await.remove(&row.dek_id);
        }
        Ok(())
    }

    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if [old_key, new_key]
            .into_iter()
            .any(|key| !is_valid_secret_key(key))
        {
            return Err(store_error("invalid-secret-key"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_scope(&mut tx, &context).await?;
        let row = Self::fetch_dek_locked(&mut tx, &context)
            .await?
            .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
        let old: RenameRow = sqlx::query_as(
            "SELECT ciphertext, nonce, format, created_at FROM tenant_secrets \
             WHERE path = $1 AND key = $2 AND dek_id = $3 FOR UPDATE",
        )
        .bind(secret_path)
        .bind(old_key)
        .bind(&row.dek_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| store_error("secret-query-failed"))?
        .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tenant_secrets WHERE path = $1 AND key = $2)",
        )
        .bind(secret_path)
        .bind(new_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| store_error("secret-query-failed"))?;
        if target_exists {
            return Err(anyhow::anyhow!("secret already exists"));
        }
        let dek = self.unwrap_dek(&context, &row).await?;
        let old_coordinates = SecretCoordinates {
            context: &context,
            path: secret_path,
            key: old_key,
        };
        let plaintext = decrypt_secret(
            &dek,
            &old_coordinates,
            &EncryptedTenantSecret {
                ciphertext: old.ciphertext,
                nonce: old.nonce,
                format: old.format,
            },
        )
        .map_err(envelope_error)?;
        let new_coordinates = SecretCoordinates {
            context: &context,
            path: secret_path,
            key: new_key,
        };
        let encrypted =
            encrypt_secret(&dek, &new_coordinates, &plaintext).map_err(envelope_error)?;
        sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, created_at, storage_contract_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1)",
        )
        .bind(secret_path)
        .bind(new_key)
        .bind(&row.dek_id)
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .bind(encrypted.ciphertext)
        .bind(encrypted.nonce)
        .bind(encrypted.format)
        .bind(old.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| store_error("secret-rename-failed"))?;
        sqlx::query("DELETE FROM tenant_secrets WHERE path = $1 AND key = $2 AND dek_id = $3")
            .bind(secret_path)
            .bind(old_key)
            .bind(&row.dek_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| store_error("secret-rename-failed"))?;
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        Ok(())
    }

    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT DISTINCT split_part(substring(path FROM char_length($1) + 2), '/', 1) \
             FROM tenant_secrets \
             WHERE left(path, char_length($1) + 1) = $1 || '/' \
               AND substring(path FROM char_length($1) + 2) <> '' \
             ORDER BY 1",
        )
        .bind(parent_path)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| store_error("folder-query-failed"))
    }

    pub async fn verify_canary(&self) -> anyhow::Result<()> {
        let row: CanaryRow = sqlx::query_as(
            "SELECT provider, key_name, key_version, wrapped_dek, format, \
                    expected_authority_id, plaintext_sha256 \
             FROM tenant_secret_kek_canary WHERE singleton = true",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| store_error("canary-unavailable"))?;
        let dek_row = DekRow {
            dek_id: "canary".into(),
            scope: "canary".into(),
            scope_id: "tenant-secret".into(),
            provider: row.provider,
            key_name: row.key_name,
            key_version: row.key_version,
            wrapped_dek: row.wrapped_dek,
            format: row.format,
        };
        let wrapped = Self::wrapped_from_row(&dek_row)?;
        if wrapped.provider != self.provider.kind() {
            return Err(store_error("canary-provider-mismatch"));
        }
        let authority = self.provider.authority_id().await.map_err(envelope_error)?;
        if authority.as_deref() != row.expected_authority_id.as_deref() {
            return Err(store_error("canary-authority-mismatch"));
        }
        let dek = self
            .provider
            .unwrap(&DekContext::canary(), &wrapped)
            .await
            .map_err(envelope_error)?;
        verify_dek_fingerprint(&dek, &row.plaintext_sha256, wrapped.provider)
            .map_err(envelope_error)
    }

    /// Initialize the persisted readiness canary once, or verify the existing
    /// canary when another operator already initialized it.
    pub async fn initialize_canary(&self) -> anyhow::Result<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CANARY_LOCK_KEY)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| store_error("canary-lock-failed"))?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tenant_secret_kek_canary WHERE singleton = true)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| store_error("canary-query-failed"))?;
        if exists {
            tx.commit()
                .await
                .map_err(|_| store_error("transaction-commit-failed"))?;
            self.verify_canary().await?;
            return Ok(false);
        }
        let authority = self.provider.authority_id().await.map_err(envelope_error)?;
        let generated = self
            .provider
            .generate(&DekContext::canary())
            .await
            .map_err(envelope_error)?;
        let wrapped_dek = Self::wrapped_field(&generated.wrapped)?;
        let fingerprint = dek_fingerprint(&generated.plaintext);
        sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, format, \
              expected_authority_id, plaintext_sha256) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(generated.wrapped.provider.as_str())
        .bind(&generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(wrapped_dek)
        .bind(generated.wrapped.format)
        .bind(authority)
        .bind(fingerprint.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| store_error("canary-insert-failed"))?;
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        Ok(true)
    }

    #[cfg(test)]
    async fn cached_dek_count(&self) -> usize {
        self.cache.lock().await.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_protected_store::secret_envelope::TestKekProvider;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn dek_cache_is_bounded_and_evicts_the_least_recently_used_entry() {
        let mut cache = DekCache::default();
        for index in 0..MAX_CACHED_DEKS {
            cache.insert(
                format!("dek-{index}"),
                Zeroizing::new([index as u8; DEK_BYTES]),
            );
        }
        assert!(cache.get("dek-0").is_some());
        cache.insert("dek-overflow".into(), Zeroizing::new([0xff; DEK_BYTES]));
        assert_eq!(cache.entries.len(), MAX_CACHED_DEKS);
        assert!(cache.get("dek-0").is_some());
        assert!(cache.get("dek-1").is_none());
    }

    #[tokio::test]
    async fn invalid_workload_secret_values_fail_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool");
        let store = PostgresSecretStore::new(pool, Arc::new(TestKekProvider));
        for invalid in [
            String::new(),
            "synthetic\0value".to_string(),
            "x".repeat(codewire_workload_secrets::MAX_WORKLOAD_SECRET_VALUE_BYTES + 1),
        ] {
            let error = store
                .set_secret_at_path("/users/synthetic", "SAFE_KEY", &invalid)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("failure_class=invalid-secret-value")
            );
            if !invalid.is_empty() {
                assert!(!error.to_string().contains(&invalid));
            }
        }
    }

    #[tokio::test]
    async fn invalid_workload_secret_keys_fail_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool");
        let store = PostgresSecretStore::new(pool, Arc::new(TestKekProvider));
        for key in [
            "1DIGIT_FIRST".to_owned(),
            format!(
                "A{}",
                "_".repeat(codewire_workload_secrets::MAX_WORKLOAD_SECRET_KEY_BYTES)
            ),
        ] {
            let error = store
                .set_secret_at_path("/users/synthetic", &key, "synthetic")
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("failure_class=invalid-secret-key")
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn encrypted_store_reencrypts_renames_and_deletes_final_dek() -> anyhow::Result<()> {
        const TEST_LOCK: i64 = 0x4357_5453_4f50_5431;
        let database_url = std::env::var("TEST_DATABASE_URL")?;
        codewire_server_core::migrate::ensure_schema(&database_url).await?;
        let pool = PgPool::connect(&database_url).await?;
        let mut isolation = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(TEST_LOCK)
            .fetch_one(&mut *isolation)
            .await?;
        let fixture_id = uuid::Uuid::new_v4().simple().to_string();
        let org_id = format!("org_{fixture_id}");
        let project_id = format!("project_{fixture_id}");
        let project_path = format!("/projects/{org_id}/{project_id}");
        let org_path = format!("/org-secrets/{org_id}");

        let provider = Arc::new(TestKekProvider);
        let store = PostgresSecretStore::new(pool.clone(), provider);
        sqlx::query("DELETE FROM tenant_secret_kek_canary")
            .execute(&pool)
            .await?;
        assert!(store.initialize_canary().await?);
        assert!(!store.initialize_canary().await?);
        store.verify_canary().await?;

        let canary = "tenant-secret-value-must-never-render";
        store
            .set_secret_at_path(&project_path, "OLD_KEY", canary)
            .await?;
        let inserted: (Vec<u8>, i16) = sqlx::query_as(
            "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
             WHERE path = $1 AND key = 'OLD_KEY'",
        )
        .bind(&project_path)
        .fetch_one(&pool)
        .await?;
        store
            .set_secret_at_path(&project_path, "OLD_KEY", canary)
            .await?;
        let upserted: (Vec<u8>, i16) = sqlx::query_as(
            "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
             WHERE path = $1 AND key = 'OLD_KEY'",
        )
        .bind(&project_path)
        .fetch_one(&pool)
        .await?;
        assert_eq!((inserted.1, upserted.1), (1, 1));
        assert_ne!(
            inserted.0, upserted.0,
            "current upsert must produce a fresh authenticated envelope"
        );
        store
            .set_secret_at_path(&org_path, "ORG_KEY", "org-private-value")
            .await?;

        let metadata_store = PostgresSecretStore::new(pool.clone(), Arc::new(TestKekProvider));
        assert_eq!(metadata_store.cached_dek_count().await, 0);
        let metadata = metadata_store
            .get_secret_metadata_at_path(&project_path)
            .await?;
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].key, "OLD_KEY");
        assert!(!metadata[0].created_at.is_empty());
        assert!(!metadata[0].updated_at.is_empty());
        assert_eq!(
            metadata_store.cached_dek_count().await,
            0,
            "metadata listing must not unwrap or cache a DEK"
        );
        let before = upserted.0;
        let deks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tenant_secret_deks WHERE scope = 'org' AND scope_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(deks, 1, "project and organization paths must share one DEK");

        let listed = store.get_secrets_raw_at_path(&project_path).await?;
        assert!(listed.len() == 1 && listed[0].value == canary);

        store
            .rename_secret_at_path(&project_path, "OLD_KEY", "NEW_KEY")
            .await?;
        let after: (Vec<u8>, i16) = sqlx::query_as(
            "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
             WHERE path = $1 AND key = 'NEW_KEY'",
        )
        .bind(&project_path)
        .fetch_one(&pool)
        .await?;
        assert_eq!(after.1, 1, "rename must write the current storage contract");
        assert!(
            before != after.0,
            "rename must produce a fresh authenticated envelope"
        );
        let renamed = store.get_secrets_raw_at_path(&project_path).await?;
        assert!(renamed.len() == 1 && renamed[0].key == "NEW_KEY" && renamed[0].value == canary);
        let debug = format!("{:?}", renamed[0]);
        assert!(!debug.contains("NEW_KEY"));
        assert!(!debug.contains(canary));

        store
            .delete_secret_at_path(&project_path, "NEW_KEY")
            .await?;
        let deks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tenant_secret_deks WHERE scope = 'org' AND scope_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(deks, 1, "a DEK with another live path must remain");
        assert_eq!(store.cached_dek_count().await, 1);
        store.delete_secret_at_path(&org_path, "ORG_KEY").await?;
        let deks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tenant_secret_deks WHERE scope = 'org' AND scope_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            deks, 0,
            "the final live secret deletion must remove its DEK"
        );
        assert_eq!(store.cached_dek_count().await, 0);

        sqlx::query("DELETE FROM tenant_secret_kek_canary")
            .execute(&pool)
            .await?;
        isolation.rollback().await?;
        pool.close().await;
        Ok(())
    }
}
