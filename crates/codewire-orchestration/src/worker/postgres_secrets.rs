//! AES-GCM tenant-secret storage backed by Postgres and a pluggable KEK.
//!
//! Every mutation holds the durable authority fence and a transaction-scoped
//! per-tenant lock. Reads are admitted only after the cutover reaches a
//! Postgres read state; writes require the final `postgres` state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::secret_envelope::{
    DEK_BYTES, DekContext, EncryptedTenantSecret, GeneratedDek, KekProvider, KekProviderKind,
    OpenBaoTransitConfig, OpenBaoTransitProvider, SecretCoordinates, TenantSecretScope, WrappedDek,
    decrypt_secret, encrypt_secret, load_keyring_provider, verify_dek_fingerprint,
};
use super::secrets::{StoredSecret, is_valid_secret_key};

const MAX_CACHED_DEKS: usize = 4096;
const CANARY_LOCK_KEY: i64 = 0x4357_5453_4341_4e31;
const SCOPE_LOCK_DOMAIN: &[u8] = b"codewire/tenant-secret-scope-lock/v1\0";

fn store_error(class: &'static str) -> anyhow::Error {
    anyhow::anyhow!("tenant-secret-store failure_class={class}")
}

fn envelope_error(error: super::secret_envelope::SecretEnvelopeError) -> anyhow::Error {
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
    wrapped_nonce: Option<Vec<u8>>,
    format: i16,
    revision: i64,
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
    wrapped_nonce: Option<Vec<u8>>,
    format: i16,
    expected_authority_id: Option<String>,
    plaintext_sha256: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ValidationSecretRow {
    path: String,
    key: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    format: i16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ValidationSummary {
    pub scopes: usize,
    pub secrets: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RewrapSummary {
    pub scanned: usize,
    pub rewrapped: usize,
    pub canary_rewrapped: bool,
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

    pub fn from_env(pool: PgPool) -> anyhow::Result<Self> {
        let provider = std::env::var("TENANT_SECRET_KEK_PROVIDER")
            .map_err(|_| store_error("missing-kek-provider"))?;
        let provider: Arc<dyn KekProvider> = match provider.as_str() {
            "openbao-transit" => Arc::new(
                OpenBaoTransitProvider::new(
                    OpenBaoTransitConfig::from_env().map_err(envelope_error)?,
                )
                .map_err(envelope_error)?,
            ),
            "keyring" => {
                let directory = std::env::var_os("TENANT_SECRET_KEYRING_DIR")
                    .map(PathBuf::from)
                    .ok_or_else(|| store_error("missing-keyring-configuration"))?;
                let active_id = std::env::var("TENANT_SECRET_KEYRING_ACTIVE_ID")
                    .map_err(|_| store_error("missing-keyring-configuration"))?;
                Arc::new(load_keyring_provider(&directory, &active_id).map_err(envelope_error)?)
            }
            _ => return Err(store_error("unknown-kek-provider")),
        };
        Ok(Self::new(pool, provider))
    }

    async fn require_read_authority(&self) -> anyhow::Result<()> {
        let state: String =
            sqlx::query_scalar("SELECT state FROM tenant_secret_control WHERE singleton = true")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| store_error("authority-query-failed"))?;
        if !matches!(state.as_str(), "postgres-readonly" | "postgres") {
            return Err(store_error("read-authority-unavailable"));
        }
        Ok(())
    }

    pub async fn verify_active_authority(&self) -> anyhow::Result<()> {
        let state: String =
            sqlx::query_scalar("SELECT state FROM tenant_secret_control WHERE singleton = true")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| store_error("authority-query-failed"))?;
        if state != "postgres" {
            return Err(store_error("write-authority-unavailable"));
        }
        Ok(())
    }

    async fn lock_write_authority(
        tx: &mut Transaction<'_, Postgres>,
        expected: &'static str,
    ) -> anyhow::Result<()> {
        let state: String = sqlx::query_scalar(
            "SELECT state FROM tenant_secret_control WHERE singleton = true FOR SHARE",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| store_error("authority-lock-failed"))?;
        if state != expected {
            return Err(store_error("write-authority-unavailable"));
        }
        Ok(())
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
                    wrapped_dek, wrapped_nonce, format, revision \
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
                    wrapped_dek, wrapped_nonce, format, revision \
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
        let ciphertext = match provider {
            KekProviderKind::Keyring => STANDARD
                .decode(&row.wrapped_dek)
                .map_err(|_| store_error("invalid-persisted-wrapper"))?,
            KekProviderKind::OpenBaoTransit => row.wrapped_dek.as_bytes().to_vec(),
        };
        Ok(WrappedDek {
            provider,
            key_name: row.key_name.clone(),
            key_version,
            ciphertext,
            nonce: row.wrapped_nonce.clone(),
            format: row.format,
        })
    }

    fn wrapped_fields(wrapped: &WrappedDek) -> anyhow::Result<(String, Option<Vec<u8>>)> {
        let value = match wrapped.provider {
            KekProviderKind::Keyring => STANDARD.encode(&wrapped.ciphertext),
            KekProviderKind::OpenBaoTransit => std::str::from_utf8(&wrapped.ciphertext)
                .map_err(|_| store_error("invalid-provider-wrapper"))?
                .to_owned(),
        };
        Ok((value, wrapped.nonce.clone()))
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
        let (wrapped_dek, wrapped_nonce) = Self::wrapped_fields(&generated.wrapped)?;
        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek, \
              wrapped_nonce, format) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&dek_id)
        .bind(context.scope.as_str())
        .bind(&context.scope_id)
        .bind(generated.wrapped.provider.as_str())
        .bind(&generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(wrapped_dek)
        .bind(wrapped_nonce)
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
        self.get_secrets_at_path(secret_path, true).await
    }

    pub async fn get_imported_secrets_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        self.get_secrets_at_path(secret_path, false).await
    }

    async fn get_secrets_at_path(
        &self,
        secret_path: &str,
        require_authority: bool,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        if require_authority {
            self.require_read_authority().await?;
        }
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

    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.set_secret_with_authority(secret_path, key, value, "postgres")
            .await
    }

    pub async fn import_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.set_secret_with_authority(secret_path, key, value, "importing")
            .await
    }

    async fn set_secret_with_authority(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
        authority: &'static str,
    ) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if !is_valid_secret_key(key) || key.len() > 255 {
            return Err(store_error("invalid-secret-key"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_write_authority(&mut tx, authority).await?;
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
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, format) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
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
        self.delete_secret_with_authority(secret_path, key, "postgres")
            .await
    }

    pub async fn delete_imported_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
    ) -> anyhow::Result<()> {
        self.delete_secret_with_authority(secret_path, key, "importing")
            .await
    }

    async fn delete_secret_with_authority(
        &self,
        secret_path: &str,
        key: &str,
        authority: &'static str,
    ) -> anyhow::Result<()> {
        let context = DekContext::from_secret_path(secret_path).map_err(envelope_error)?;
        if !is_valid_secret_key(key) || key.len() > 255 {
            return Err(store_error("invalid-secret-key"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_write_authority(&mut tx, authority).await?;
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

    pub async fn imported_paths(&self) -> anyhow::Result<Vec<String>> {
        sqlx::query_scalar("SELECT DISTINCT path FROM tenant_secrets ORDER BY path")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| store_error("path-query-failed"))
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
            .any(|key| !is_valid_secret_key(key) || key.len() > 255)
        {
            return Err(store_error("invalid-secret-key"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        Self::lock_write_authority(&mut tx, "postgres").await?;
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
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
        self.require_read_authority().await?;
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
            "SELECT provider, key_name, key_version, wrapped_dek, wrapped_nonce, format, \
                    expected_authority_id, plaintext_sha256 \
             FROM tenant_secret_kek_canary WHERE singleton = true",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| store_error("canary-unavailable"))?;
        let dek_row = DekRow {
            dek_id: "canary".into(),
            scope: TenantSecretScope::Canary.as_str().into(),
            scope_id: "tenant-secret".into(),
            provider: row.provider,
            key_name: row.key_name,
            key_version: row.key_version,
            wrapped_dek: row.wrapped_dek,
            wrapped_nonce: row.wrapped_nonce,
            format: row.format,
            revision: 1,
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
        let (wrapped_dek, wrapped_nonce) = Self::wrapped_fields(&generated.wrapped)?;
        let fingerprint = super::secret_envelope::dek_fingerprint(&generated.plaintext);
        sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, wrapped_nonce, format, \
              expected_authority_id, plaintext_sha256) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(generated.wrapped.provider.as_str())
        .bind(&generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(wrapped_dek)
        .bind(wrapped_nonce)
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

    fn context_from_row(row: &DekRow) -> anyhow::Result<DekContext> {
        let path = match row.scope.as_str() {
            "org" => format!("/org-secrets/{}", row.scope_id),
            "user" => format!("/users/{}", row.scope_id),
            _ => return Err(store_error("invalid-persisted-scope")),
        };
        let context = DekContext::from_secret_path(&path).map_err(envelope_error)?;
        Self::validate_row_context(row, &context)?;
        Ok(context)
    }

    pub async fn validate_all(&self) -> anyhow::Result<ValidationSummary> {
        self.verify_canary().await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| store_error("validation-snapshot-failed"))?;
        let deks: Vec<DekRow> = sqlx::query_as(
            "SELECT dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek, \
                    wrapped_nonce, format, revision FROM tenant_secret_deks ORDER BY dek_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| store_error("dek-query-failed"))?;
        let mut secret_count = 0_usize;
        for row in &deks {
            let context = Self::context_from_row(row)?;
            let dek = self.unwrap_dek(&context, row).await?;
            let secrets: Vec<ValidationSecretRow> = sqlx::query_as(
                "SELECT path, key, ciphertext, nonce, format FROM tenant_secrets \
                 WHERE dek_id = $1 ORDER BY path, key",
            )
            .bind(&row.dek_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| store_error("secret-query-failed"))?;
            if secrets.is_empty() {
                return Err(store_error("orphan-dek"));
            }
            for secret in secrets {
                let persisted_context =
                    DekContext::from_secret_path(&secret.path).map_err(envelope_error)?;
                if persisted_context != context {
                    return Err(store_error("secret-scope-mismatch"));
                }
                decrypt_secret(
                    &dek,
                    &SecretCoordinates {
                        context: &context,
                        path: &secret.path,
                        key: &secret.key,
                    },
                    &EncryptedTenantSecret {
                        ciphertext: secret.ciphertext,
                        nonce: secret.nonce,
                        format: secret.format,
                    },
                )
                .map_err(envelope_error)?;
                secret_count = secret_count.saturating_add(1);
            }
        }
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        Ok(ValidationSummary {
            scopes: deks.len(),
            secrets: secret_count,
        })
    }

    pub async fn rewrap_all(&self) -> anyhow::Result<RewrapSummary> {
        self.verify_canary().await?;
        let dek_ids: Vec<String> =
            sqlx::query_scalar("SELECT dek_id FROM tenant_secret_deks ORDER BY dek_id")
                .fetch_all(&self.pool)
                .await
                .map_err(|_| store_error("dek-query-failed"))?;
        let mut rewrapped_count = 0_usize;
        for dek_id in &dek_ids {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|_| store_error("transaction-start-failed"))?;
            let row: DekRow = sqlx::query_as(
                "SELECT dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek, \
                        wrapped_nonce, format, revision FROM tenant_secret_deks \
                 WHERE dek_id = $1 FOR UPDATE",
            )
            .bind(dek_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| store_error("dek-lock-failed"))?;
            let context = Self::context_from_row(&row)?;
            let wrapped = Self::wrapped_from_row(&row)?;
            if wrapped.provider != self.provider.kind() {
                return Err(store_error("provider-authority-mismatch"));
            }
            let replacement = self
                .provider
                .rewrap(&context, &wrapped)
                .await
                .map_err(envelope_error)?;
            if replacement.key_version < wrapped.key_version {
                return Err(store_error("provider-version-regressed"));
            }
            if replacement.key_version > wrapped.key_version {
                let (wrapped_dek, wrapped_nonce) = Self::wrapped_fields(&replacement)?;
                let updated = sqlx::query(
                    "UPDATE tenant_secret_deks SET provider = $1, key_name = $2, key_version = $3, \
                            wrapped_dek = $4, wrapped_nonce = $5, format = $6, \
                            revision = revision + 1, updated_at = now() \
                     WHERE dek_id = $7 AND revision = $8",
                )
                .bind(replacement.provider.as_str())
                .bind(&replacement.key_name)
                .bind(i64::from(replacement.key_version))
                .bind(wrapped_dek)
                .bind(wrapped_nonce)
                .bind(replacement.format)
                .bind(&row.dek_id)
                .bind(row.revision)
                .execute(&mut *tx)
                .await
                .map_err(|_| store_error("dek-rewrap-update-failed"))?;
                if updated.rows_affected() != 1 {
                    return Err(store_error("dek-rewrap-collision"));
                }
                rewrapped_count = rewrapped_count.saturating_add(1);
            }
            tx.commit()
                .await
                .map_err(|_| store_error("transaction-commit-failed"))?;
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| store_error("transaction-start-failed"))?;
        let canary: CanaryRow = sqlx::query_as(
            "SELECT provider, key_name, key_version, wrapped_dek, wrapped_nonce, format, \
                    expected_authority_id, plaintext_sha256 FROM tenant_secret_kek_canary \
             WHERE singleton = true FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| store_error("canary-unavailable"))?;
        let canary_row = DekRow {
            dek_id: "canary".into(),
            scope: TenantSecretScope::Canary.as_str().into(),
            scope_id: "tenant-secret".into(),
            provider: canary.provider,
            key_name: canary.key_name,
            key_version: canary.key_version,
            wrapped_dek: canary.wrapped_dek,
            wrapped_nonce: canary.wrapped_nonce,
            format: canary.format,
            revision: 1,
        };
        let wrapped = Self::wrapped_from_row(&canary_row)?;
        let replacement = self
            .provider
            .rewrap(&DekContext::canary(), &wrapped)
            .await
            .map_err(envelope_error)?;
        if replacement.key_version < wrapped.key_version {
            return Err(store_error("provider-version-regressed"));
        }
        let canary_rewrapped = replacement.key_version > wrapped.key_version;
        if canary_rewrapped {
            let (wrapped_dek, wrapped_nonce) = Self::wrapped_fields(&replacement)?;
            sqlx::query(
                "UPDATE tenant_secret_kek_canary SET provider = $1, key_name = $2, \
                        key_version = $3, wrapped_dek = $4, wrapped_nonce = $5, format = $6, \
                        updated_at = now(), verified_at = NULL WHERE singleton = true",
            )
            .bind(replacement.provider.as_str())
            .bind(&replacement.key_name)
            .bind(i64::from(replacement.key_version))
            .bind(wrapped_dek)
            .bind(wrapped_nonce)
            .bind(replacement.format)
            .execute(&mut *tx)
            .await
            .map_err(|_| store_error("canary-rewrap-update-failed"))?;
        }
        tx.commit()
            .await
            .map_err(|_| store_error("transaction-commit-failed"))?;
        self.verify_canary().await?;
        Ok(RewrapSummary {
            scanned: dek_ids.len(),
            rewrapped: rewrapped_count,
            canary_rewrapped,
        })
    }

    #[cfg(test)]
    async fn cached_dek_count(&self) -> usize {
        self.cache.lock().await.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

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
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn encrypted_store_fences_mutations_reencrypts_renames_and_deletes_final_dek()
    -> anyhow::Result<()> {
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

        let keyring = tempfile::tempdir()?;
        fs::write(
            keyring.path().join("v1"),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let provider = Arc::new(load_keyring_provider(keyring.path(), "v1")?);
        let store = PostgresSecretStore::new(pool.clone(), provider);

        sqlx::query(
            "UPDATE tenant_secret_control \
             SET state = 'postgres', generation = generation + 1, \
                 source_revision = 'encrypted-store-test', transition_started_at = now(), \
                 verified_at = now(), updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;
        sqlx::query("DELETE FROM tenant_secret_kek_canary")
            .execute(&pool)
            .await?;
        assert!(store.initialize_canary().await?);
        assert!(!store.initialize_canary().await?);
        store.verify_canary().await?;
        store.verify_active_authority().await?;

        let canary = "tenant-secret-value-must-never-render";
        store
            .set_secret_at_path(&project_path, "OLD_KEY", canary)
            .await?;
        store
            .set_secret_at_path(&org_path, "ORG_KEY", "org-private-value")
            .await?;
        let before: Vec<u8> = sqlx::query_scalar(
            "SELECT ciphertext FROM tenant_secrets WHERE path = $1 AND key = 'OLD_KEY'",
        )
        .bind(&project_path)
        .fetch_one(&pool)
        .await?;
        let deks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tenant_secret_deks WHERE scope = 'org' AND scope_id = $1",
        )
        .bind(&org_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(deks, 1, "project and organization paths must share one DEK");

        sqlx::query(
            "UPDATE tenant_secret_control SET state = 'postgres-readonly', updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;
        let readiness = store.verify_active_authority().await.unwrap_err();
        assert!(
            readiness
                .to_string()
                .contains("failure_class=write-authority-unavailable")
        );
        let listed = store.get_secrets_raw_at_path(&project_path).await?;
        assert!(listed.len() == 1 && listed[0].value == canary);
        let fenced = store
            .set_secret_at_path(&project_path, "FENCED_KEY", canary)
            .await
            .unwrap_err();
        let rendered = fenced.to_string();
        assert!(rendered.contains("failure_class=write-authority-unavailable"));
        assert!(!rendered.contains(canary));
        sqlx::query(
            "UPDATE tenant_secret_control SET state = 'postgres', updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;

        store
            .rename_secret_at_path(&project_path, "OLD_KEY", "NEW_KEY")
            .await?;
        let after: Vec<u8> = sqlx::query_scalar(
            "SELECT ciphertext FROM tenant_secrets WHERE path = $1 AND key = 'NEW_KEY'",
        )
        .bind(&project_path)
        .fetch_one(&pool)
        .await?;
        assert!(
            before != after,
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
        sqlx::query(
            "UPDATE tenant_secret_control \
             SET state = 'local', source_revision = NULL, transition_started_at = NULL, \
                 verified_at = NULL, updated_at = now() WHERE singleton = true",
        )
        .execute(&pool)
        .await?;
        isolation.rollback().await?;
        pool.close().await;
        Ok(())
    }
}
