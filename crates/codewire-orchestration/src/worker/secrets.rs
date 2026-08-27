//! Tenant secret stores used by the API and environment setup worker.
//!
//! The encrypted PostgreSQL store is the target deployed authority. The
//! plaintext local store remains the pre-cutover authority, the bounded source
//! for the one-way import, and the isolated-test implementation. Organization
//! teardown deletes only names and paths, never logs values, and re-enumerates
//! before it can call a namespace absent.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};

/// Mirrors `worker.StoredSecret`. `created_at`/`updated_at` are surfaced by
/// the secrets-list endpoint (RFC3339 strings; empty when the backend omits
/// them); the env-setup flow only reads `key`/`value`.
#[derive(Clone, Default, Deserialize)]
pub struct StoredSecret {
    #[serde(rename = "secretKey")]
    pub key: String,
    #[serde(rename = "secretValue")]
    pub value: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
}

impl fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSecret")
            .field("key", &"[redacted]")
            .field("value", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

pub enum SecretStore {
    Local(LocalSecretStore),
    Postgres(super::postgres_secrets::PostgresSecretStore),
}

impl SecretStore {
    pub async fn verify_readiness(&self) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => {
                store.verify_canary().await?;
                store.verify_active_authority().await
            }
            Self::Local(_) => Ok(()),
        }
    }

    /// Select the encrypted PostgreSQL store only after the fenced activation.
    /// The reusable deployment base remains local until that transition is
    /// complete and the environment-specific deployment selects PostgreSQL.
    pub fn from_env(pool: PgPool) -> anyhow::Result<Self> {
        let configured = match std::env::var("TENANT_SECRET_STORE") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("tenant-secret-store failure_class=invalid-store-configuration")
            }
        };
        match configured.as_deref() {
            Some("postgres") => {
                tracing::info!("using encrypted postgres tenant secret store");
                Ok(Self::Postgres(
                    super::postgres_secrets::PostgresSecretStore::from_env(pool)?,
                ))
            }
            Some("local") => Ok(Self::Local(LocalSecretStore { pool })),
            Some(_) => {
                anyhow::bail!("tenant-secret-store failure_class=unknown-store-configuration")
            }
            None => {
                tracing::info!("using local postgres-backed secret store");
                Ok(Self::Local(LocalSecretStore { pool }))
            }
        }
    }

    /// Mirrors `GetSecretsRawAtPath`.
    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        match self {
            SecretStore::Local(l) => l.get_secrets_raw_at_path(secret_path).await,
            SecretStore::Postgres(p) => p.get_secrets_raw_at_path(secret_path).await,
        }
    }

    /// Mirrors `GetAllSecretsAtPath`.
    pub async fn get_all_secrets_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<BTreeMap<String, String>> {
        let secrets = self.get_secrets_raw_at_path(secret_path).await?;
        Ok(secrets.into_iter().map(|s| (s.key, s.value)).collect())
    }

    /// Mirrors `CreateFolderAtPath` (idempotent — "already exists" is OK).
    pub async fn create_folder_at_path(
        &self,
        _parent_path: &str,
        _name: &str,
    ) -> anyhow::Result<()> {
        match self {
            // Folders are implicit from the path in the local store (mirrors
            // `LocalSecretStore.CreateFolderAtPath`, which is a no-op).
            SecretStore::Local(_) => Ok(()),
            SecretStore::Postgres(_) => Ok(()),
        }
    }

    /// Mirrors `SetSecretAtPath` (create, else update on conflict).
    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        match self {
            SecretStore::Local(l) => l.set_secret_at_path(secret_path, key, value).await,
            SecretStore::Postgres(p) => p.set_secret_at_path(secret_path, key, value).await,
        }
    }

    /// Mirrors `DeleteSecretAtPath` (404 = already gone, treated as OK).
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        match self {
            SecretStore::Local(l) => l.delete_secret_at_path(secret_path, key).await,
            SecretStore::Postgres(p) => p.delete_secret_at_path(secret_path, key).await,
        }
    }

    /// Mirrors `RenameSecretAtPath`. Errors carry "not found" / "already
    /// exists" so handlers can map them to 404 / 409.
    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        match self {
            SecretStore::Local(l) => l.rename_secret_at_path(secret_path, old_key, new_key).await,
            SecretStore::Postgres(p) => {
                p.rename_secret_at_path(secret_path, old_key, new_key).await
            }
        }
    }

    /// Enumerate immediate child-folder names without reading their values.
    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        match self {
            SecretStore::Local(l) => l.list_folders_at_path(parent_path).await,
            SecretStore::Postgres(p) => p.list_folders_at_path(parent_path).await,
        }
    }

    /// Idempotently remove every secret at one exact path and then the
    /// provider folder. A second enumeration is the success boundary.
    pub async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
        if let Self::Local(store) = self {
            return store.delete_path(secret_path).await;
        }
        let (parent_path, folder_name) = split_folder_path(secret_path)?;
        let mut secrets = self.get_secrets_raw_at_path(secret_path).await?;
        secrets.sort_by(|left, right| left.key.cmp(&right.key));
        for secret in secrets {
            self.delete_secret_at_path(secret_path, &secret.key).await?;
        }

        let remaining = self.get_secrets_raw_at_path(secret_path).await?;
        if !remaining.is_empty() {
            anyhow::bail!(
                "tenant secret path remains non-empty after deletion ({} entries)",
                remaining.len()
            );
        }

        if self
            .list_folders_at_path(&parent_path)
            .await?
            .iter()
            .any(|name| name == &folder_name)
        {
            anyhow::bail!("tenant secret folder remains after deletion");
        }
        Ok(())
    }
}

/// Mirrors `worker.LocalSecretStore` (reads only).
pub struct LocalSecretStore {
    pub pool: PgPool,
}

impl LocalSecretStore {
    async fn lock_write_authority(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
        let state: String = sqlx::query_scalar(
            "SELECT state FROM tenant_secret_control WHERE singleton = true FOR SHARE",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| anyhow::anyhow!("tenant-secret-store failure_class=authority-lock-failed"))?;
        if state != "local" {
            anyhow::bail!("tenant-secret-store failure_class=write-authority-unavailable");
        }
        Ok(())
    }

    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        type Row = (
            String,
            String,
            Option<chrono::NaiveDateTime>,
            Option<chrono::NaiveDateTime>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT key, value, created_at, updated_at FROM local_secrets WHERE path = $1",
        )
        .bind(secret_path)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("query local_secrets: {e}"))?;
        // Mirrors Go's `time.RFC3339` (seconds precision, UTC `Z`).
        let fmt = |t: chrono::NaiveDateTime| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Ok(rows
            .into_iter()
            .map(|(key, value, created, updated)| StoredSecret {
                key,
                value,
                created_at: created.map(fmt).unwrap_or_default(),
                updated_at: updated.map(fmt).unwrap_or_default(),
            })
            .collect())
    }

    /// Mirrors `LocalSecretStore.RenameSecretAtPath` (transactional: copy the
    /// value under the new key, then drop the old).
    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_write_authority(&mut tx).await?;
        let exists_old: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM local_secrets WHERE path = $1 AND key = $2)",
        )
        .bind(secret_path)
        .bind(old_key)
        .fetch_one(&mut *tx)
        .await?;
        if !exists_old {
            anyhow::bail!("secret not found");
        }
        let exists_new: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM local_secrets WHERE path = $1 AND key = $2)",
        )
        .bind(secret_path)
        .bind(new_key)
        .fetch_one(&mut *tx)
        .await?;
        if exists_new {
            anyhow::bail!("secret already exists");
        }
        sqlx::query(
            "INSERT INTO local_secrets (path, key, value, created_at, updated_at) \
             SELECT path, $3, value, created_at, NOW() FROM local_secrets WHERE path = $1 AND key = $2",
        )
        .bind(secret_path)
        .bind(old_key)
        .bind(new_key)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM local_secrets WHERE path = $1 AND key = $2")
            .bind(secret_path)
            .bind(old_key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Mirrors `LocalSecretStore.SetSecretAtPath`: upsert into `local_secrets`.
    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_write_authority(&mut tx).await?;
        sqlx::query(
            r#"INSERT INTO local_secrets (path, key, value, updated_at)
               VALUES ($1, $2, $3, NOW())
               ON CONFLICT (path, key) DO UPDATE SET value = $3, updated_at = NOW()"#,
        )
        .bind(secret_path)
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await
        .map_err(|e| anyhow::anyhow!("upsert local_secrets: {e}"))?;
        tx.commit().await?;
        Ok(())
    }

    /// Mirrors `LocalSecretStore.DeleteSecretAtPath`.
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_write_authority(&mut tx).await?;
        sqlx::query("DELETE FROM local_secrets WHERE path = $1 AND key = $2")
            .bind(secret_path)
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("delete local_secrets: {e}"))?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
        let _ = split_folder_path(secret_path)?;
        let mut tx = self.pool.begin().await?;
        Self::lock_write_authority(&mut tx).await?;
        sqlx::query("DELETE FROM local_secrets WHERE path = $1")
            .bind(secret_path)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("delete local secret path: {e}"))?;
        let remains: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM local_secrets \
             WHERE path = $1 OR left(path, char_length($1) + 1) = $1 || '/')",
        )
        .bind(secret_path)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| anyhow::anyhow!("verify local secret path deletion: {e}"))?;
        if remains {
            anyhow::bail!("tenant secret folder remains after deletion");
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        sqlx::query_scalar(
            r#"SELECT DISTINCT split_part(
                       substring(path FROM char_length($1) + 2), '/', 1
                   )
               FROM local_secrets
               WHERE left(path, char_length($1) + 1) = $1 || '/'
                 AND substring(path FROM char_length($1) + 2) <> ''
               ORDER BY 1"#,
        )
        .bind(parent_path)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("enumerate local secret folders: {e}"))
    }
}

fn split_folder_path(secret_path: &str) -> anyhow::Result<(String, String)> {
    let normalized = secret_path.trim_end_matches('/');
    if !normalized.starts_with('/') || normalized.is_empty() || normalized == "/" {
        anyhow::bail!("tenant secret path must name a non-root folder");
    }
    let Some((parent, name)) = normalized.rsplit_once('/') else {
        anyhow::bail!("tenant secret path must name a folder");
    };
    if name.is_empty() || name == "." || name == ".." {
        anyhow::bail!("tenant secret path must name a folder");
    }
    Ok((
        if parent.is_empty() { "/" } else { parent }.into(),
        name.into(),
    ))
}

/// The product-facing secret-key contract. Keeping this deliberately narrower
/// than a general URL segment keeps the storage path sink unambiguous and
/// matches the dashboard's environment-variable-style key input.
pub fn is_valid_secret_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Mirrors `mergeSecrets`: existing keys win, optional skip set,
/// returns the number injected.
pub fn merge_secrets(
    dst: &mut BTreeMap<String, String>,
    secrets: Vec<StoredSecret>,
    skip_keys: &[&str],
) -> usize {
    let mut injected = 0;
    for s in secrets {
        if skip_keys.contains(&s.key.as_str()) {
            continue;
        }
        if dst.contains_key(&s.key) {
            continue;
        }
        dst.insert(s.key, s.value);
        injected += 1;
    }
    injected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_secrets_mirrors_go() {
        let mut dst = BTreeMap::new();
        dst.insert("EXPLICIT".to_string(), "keep".to_string());
        let n = merge_secrets(
            &mut dst,
            vec![
                StoredSecret {
                    key: "EXPLICIT".into(),
                    value: "lose".into(),
                    ..Default::default()
                },
                StoredSecret {
                    key: "NEW".into(),
                    value: "v".into(),
                    ..Default::default()
                },
                StoredSecret {
                    key: "SSH_PRIVATE_KEY".into(),
                    value: "x".into(),
                    ..Default::default()
                },
            ],
            &["SSH_PRIVATE_KEY"],
        );
        assert_eq!(n, 1);
        assert_eq!(dst.get("EXPLICIT").map(String::as_str), Some("keep"));
        assert_eq!(dst.get("NEW").map(String::as_str), Some("v"));
        assert!(!dst.contains_key("SSH_PRIVATE_KEY"));
    }

    #[test]
    fn stored_secret_parses_api_field_names() {
        let s: StoredSecret =
            serde_json::from_str(r#"{"secretKey":"K","secretValue":"V","createdAt":"x"}"#).unwrap();
        assert_eq!(s.key, "K");
        assert_eq!(s.value, "V");
    }

    #[tokio::test]
    async fn db_local_mutations_require_local_authority() -> anyhow::Result<()> {
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => {
                eprintln!("DATABASE_URL unset — skipping local tenant-secret fence flow");
                return Ok(());
            }
        };
        let pool = PgPool::connect(&database_url).await?;
        let path = format!("/users/fence_{}", uuid::Uuid::new_v4().simple());
        let store = LocalSecretStore { pool: pool.clone() };

        sqlx::query(
            "UPDATE tenant_secret_control SET state = 'local', source_revision = NULL, \
             transition_started_at = NULL, verified_at = NULL, updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await?;

        let outcome = async {
            store.set_secret_at_path(&path, "EXISTING", "value").await?;
            sqlx::query(
                "UPDATE tenant_secret_control SET state = 'importing', \
                 source_revision = 'local-fence-test', transition_started_at = now(), \
                 verified_at = NULL, updated_at = now() WHERE singleton = true",
            )
            .execute(&pool)
            .await?;

            for result in [
                store.set_secret_at_path(&path, "NEW", "value").await,
                store
                    .rename_secret_at_path(&path, "EXISTING", "RENAMED")
                    .await,
                store.delete_secret_at_path(&path, "EXISTING").await,
                store.delete_path(&path).await,
            ] {
                let error = result.err().ok_or_else(|| {
                    anyhow::anyhow!("inactive local authority accepted a mutation")
                })?;
                anyhow::ensure!(
                    error
                        .to_string()
                        .contains("failure_class=write-authority-unavailable"),
                    "local authority failure was not classified"
                );
            }
            let retained = store.get_secrets_raw_at_path(&path).await?;
            anyhow::ensure!(
                retained.len() == 1 && retained[0].key == "EXISTING",
                "fenced local mutation changed stored values"
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        let restore = sqlx::query(
            "UPDATE tenant_secret_control SET state = 'local', source_revision = NULL, \
             transition_started_at = NULL, verified_at = NULL, updated_at = now() \
             WHERE singleton = true",
        )
        .execute(&pool)
        .await;
        if restore.is_ok() {
            let _ = store.delete_path(&path).await;
        }
        pool.close().await;
        outcome?;
        restore?;
        Ok(())
    }
}
