//! Encrypted tenant-secret storage used by the API and environment worker.
//!
//! PostgreSQL stores only encrypted envelopes. OpenBao Transit is the sole
//! production KEK authority; there is no runtime selector or plaintext
//! fallback. Organization teardown deletes only names and paths, never values,
//! and re-enumerates before it can call a namespace absent.

use std::fmt;

use serde::Deserialize;
use sqlx::PgPool;

use codewire_workload_secrets::validate_workload_secret_metadata_key;

/// Reserved credential material is excluded from stored-secret APIs.
pub const SSH_PRIVATE_KEY_SECRET_KEY: &str = "SSH_PRIVATE_KEY";

/// Stored secret material used only within the protected storage boundary.
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

/// Key-only platform metadata. Listing secrets must not unwrap a DEK or
/// materialize plaintext merely to discard it at the public boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredSecretMetadata {
    pub key: String,
    pub created_at: String,
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

pub struct SecretStore(super::postgres_secrets::PostgresSecretStore);

impl SecretStore {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        pool: PgPool,
        provider: std::sync::Arc<dyn super::secret_envelope::KekProvider>,
    ) -> Self {
        Self(super::postgres_secrets::PostgresSecretStore::new(
            pool, provider,
        ))
    }

    #[cfg(feature = "kind-e2e")]
    pub fn for_kind_e2e(pool: PgPool) -> Self {
        Self(super::postgres_secrets::PostgresSecretStore::new(
            pool,
            std::sync::Arc::new(super::secret_envelope::TestKekProvider),
        ))
    }

    pub async fn verify_readiness(&self) -> anyhow::Result<()> {
        self.0.initialize_canary().await?;
        self.0.verify_canary().await
    }

    #[cfg(feature = "kind-e2e")]
    pub fn from_env(pool: PgPool) -> anyhow::Result<Self> {
        Self::from_env_with_kube(pool, None)
    }

    pub fn from_env_with_kube(pool: PgPool, kube: Option<kube::Client>) -> anyhow::Result<Self> {
        #[cfg(feature = "kind-e2e")]
        if std::env::var("CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER").as_deref() == Ok("true") {
            tracing::warn!("using the Kind-only tenant-secret KEK test provider");
            return Ok(Self(super::postgres_secrets::PostgresSecretStore::new(
                pool,
                std::sync::Arc::new(super::secret_envelope::TestKekProvider),
            )));
        }
        tracing::info!("using OpenBao-wrapped encrypted PostgreSQL tenant-secret store");
        let kube = kube.ok_or_else(|| {
            anyhow::anyhow!("OpenBao tenant-secret storage requires a Kubernetes client")
        })?;
        Ok(Self(
            super::postgres_secrets::PostgresSecretStore::from_env(pool, kube)?,
        ))
    }

    /// Mirrors `GetSecretsRawAtPath`.
    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        self.0.get_secrets_raw_at_path(secret_path).await
    }

    /// Lists keys and timestamps without unwrapping the scope DEK or reading
    /// encrypted values.
    pub async fn get_secret_metadata_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        self.0.get_secret_metadata_at_path(secret_path).await
    }

    /// Lists at most `maximum_rows` keys and timestamps without unwrapping a
    /// DEK. Preview callers request one extra row to detect an oversized
    /// source without materializing the full scope.
    pub async fn get_secret_metadata_at_path_bounded(
        &self,
        secret_path: &str,
        maximum_rows: usize,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        self.0
            .get_secret_metadata_at_path_bounded(secret_path, maximum_rows)
            .await
    }

    /// Mirrors `CreateFolderAtPath` (idempotent — "already exists" is OK).
    pub async fn create_folder_at_path(
        &self,
        _parent_path: &str,
        _name: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Mirrors `SetSecretAtPath` (create, else update on conflict).
    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.0.set_secret_at_path(secret_path, key, value).await
    }

    /// Mirrors `DeleteSecretAtPath` (404 = already gone, treated as OK).
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        self.0.delete_secret_at_path(secret_path, key).await
    }

    /// Mirrors `RenameSecretAtPath`. Errors carry "not found" / "already
    /// exists" so handlers can map them to 404 / 409.
    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        self.0
            .rename_secret_at_path(secret_path, old_key, new_key)
            .await
    }

    /// Enumerate immediate child-folder names without reading their values.
    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        self.0.list_folders_at_path(parent_path).await
    }

    /// Idempotently remove every secret at one exact path. Folders are derived
    /// from persisted paths, so a second enumeration is the success boundary.
    pub async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
        let (parent_path, folder_name) = split_folder_path(secret_path)?;
        self.0.delete_path(secret_path).await?;

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
    validate_workload_secret_metadata_key(key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_secret_parses_api_field_names() {
        let s: StoredSecret =
            serde_json::from_str(r#"{"secretKey":"K","secretValue":"V","createdAt":"x"}"#).unwrap();
        assert_eq!(s.key, "K");
        assert_eq!(s.value, "V");
    }

    #[test]
    fn folder_paths_fail_closed() {
        assert_eq!(
            split_folder_path("/projects/org/project").unwrap(),
            ("/projects/org".into(), "project".into())
        );
        for path in ["", "/", "relative", "/projects/.."] {
            assert!(split_folder_path(path).is_err(), "accepted {path:?}");
        }
    }
}
