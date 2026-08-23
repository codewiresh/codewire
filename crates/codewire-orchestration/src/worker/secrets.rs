//! Tenant secret stores used by the API and environment setup worker.
//!
//! Both Infisical and the postgres-backed local store expose the same
//! idempotent path-deletion contract. Organization teardown deletes only
//! names and paths, never logs values, and re-enumerates before it can call a
//! provider namespace absent.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Mirrors `worker.InfisicalSecret`. `created_at`/`updated_at` are surfaced by
/// the secrets-list endpoint (RFC3339 strings; empty when the backend omits
/// them); the env-setup flow only reads `key`/`value`.
#[derive(Clone, Default, Deserialize)]
pub struct InfisicalSecret {
    #[serde(rename = "secretKey")]
    pub key: String,
    #[serde(rename = "secretValue")]
    pub value: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
}

impl fmt::Debug for InfisicalSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InfisicalSecret")
            .field("key", &"[redacted]")
            .field("value", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

pub enum SecretStore {
    Infisical(InfisicalClient),
    Local(LocalSecretStore),
    Postgres(super::postgres_secrets::PostgresSecretStore),
}

impl SecretStore {
    pub async fn verify_readiness(&self) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => store.verify_canary().await,
            Self::Infisical(_) | Self::Local(_) => Ok(()),
        }
    }

    /// Mirrors the retired Go composition-root selection: Infisical when
    /// `INFISICAL_TENANT_ENABLED=true`, else the postgres-backed store.
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
            Some("infisical") => Ok(Self::Infisical(InfisicalClient::from_env(pool))),
            Some("local") => Ok(Self::Local(LocalSecretStore { pool })),
            Some(_) => {
                anyhow::bail!("tenant-secret-store failure_class=unknown-store-configuration")
            }
            None if std::env::var("INFISICAL_TENANT_ENABLED").as_deref() == Ok("true") => {
                Ok(Self::Infisical(InfisicalClient::from_env(pool)))
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
    ) -> anyhow::Result<Vec<InfisicalSecret>> {
        match self {
            SecretStore::Infisical(c) => c.get_secrets_raw_at_path(secret_path).await,
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
    pub async fn create_folder_at_path(&self, parent_path: &str, name: &str) -> anyhow::Result<()> {
        match self {
            SecretStore::Infisical(c) => c.create_folder_at_path(parent_path, name).await,
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
            SecretStore::Infisical(c) => c.set_secret_at_path(secret_path, key, value).await,
            SecretStore::Local(l) => l.set_secret_at_path(secret_path, key, value).await,
            SecretStore::Postgres(p) => p.set_secret_at_path(secret_path, key, value).await,
        }
    }

    /// Mirrors `DeleteSecretAtPath` (404 = already gone, treated as OK).
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        match self {
            SecretStore::Infisical(c) => c.delete_secret_at_path(secret_path, key).await,
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
            SecretStore::Infisical(c) => {
                c.rename_secret_at_path(secret_path, old_key, new_key).await
            }
            SecretStore::Local(l) => l.rename_secret_at_path(secret_path, old_key, new_key).await,
            SecretStore::Postgres(p) => {
                p.rename_secret_at_path(secret_path, old_key, new_key).await
            }
        }
    }

    /// Enumerate immediate child-folder names without reading their values.
    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        match self {
            SecretStore::Infisical(c) => c.list_folders_at_path(parent_path).await,
            SecretStore::Local(l) => l.list_folders_at_path(parent_path).await,
            SecretStore::Postgres(p) => p.list_folders_at_path(parent_path).await,
        }
    }

    /// Idempotently remove every secret at one exact path and then the
    /// provider folder. A second enumeration is the success boundary.
    pub async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
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

        if let SecretStore::Infisical(client) = self {
            client
                .delete_folder_at_path(&parent_path, &folder_name)
                .await?;
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
    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<InfisicalSecret>> {
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
            .map(|(key, value, created, updated)| InfisicalSecret {
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
        sqlx::query(
            r#"INSERT INTO local_secrets (path, key, value, updated_at)
               VALUES ($1, $2, $3, NOW())
               ON CONFLICT (path, key) DO UPDATE SET value = $3, updated_at = NOW()"#,
        )
        .bind(secret_path)
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("upsert local_secrets: {e}"))?;
        Ok(())
    }

    /// Mirrors `LocalSecretStore.DeleteSecretAtPath`.
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM local_secrets WHERE path = $1 AND key = $2")
            .bind(secret_path)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| anyhow::anyhow!("delete local_secrets: {e}"))?;
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

/// Mirrors `worker.InfisicalClient` (reads + auth only).
pub struct InfisicalClient {
    host_api: String,
    project_id: String,
    client_id: String,
    client_secret: String,
    /// When non-empty, K8s Auth is used instead of Universal Auth.
    k8s_identity_id: String,
    http: reqwest::Client,
    token: Mutex<Option<(String, Instant)>>,
    control_pool: Option<PgPool>,
    operator_read: bool,
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expiresIn", default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct SecretsResponse {
    #[serde(default)]
    secrets: Vec<InfisicalSecret>,
}

#[derive(Deserialize)]
struct Folder {
    name: String,
}

#[derive(Deserialize)]
struct FoldersResponse {
    #[serde(default)]
    folders: Vec<Folder>,
}

impl InfisicalClient {
    pub fn from_env(pool: PgPool) -> Self {
        Self::from_env_with_mode(pool, false)
    }

    pub fn from_env_for_import(pool: PgPool) -> Self {
        Self::from_env_with_mode(pool, true)
    }

    fn from_env_with_mode(pool: PgPool, operator_read: bool) -> Self {
        Self {
            host_api: std::env::var("INFISICAL_TENANT_HOST").unwrap_or_else(|_| {
                "http://infisical-backend.codewire-infisical.svc.cluster.local:8080".to_string()
            }),
            project_id: std::env::var("INFISICAL_TENANT_PROJECT_ID").unwrap_or_default(),
            client_id: std::env::var("INFISICAL_TENANT_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("INFISICAL_TENANT_CLIENT_SECRET").unwrap_or_default(),
            k8s_identity_id: std::env::var("INFISICAL_TENANT_K8S_AUTH_IDENTITY_ID")
                .unwrap_or_default(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            token: Mutex::new(None),
            control_pool: Some(pool),
            operator_read,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(host_api: String, project_id: String) -> Self {
        Self {
            host_api,
            project_id,
            client_id: String::new(),
            client_secret: String::new(),
            k8s_identity_id: String::new(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("test reqwest client"),
            token: Mutex::new(Some((
                "test-token".into(),
                Instant::now() + Duration::from_secs(300),
            ))),
            control_pool: None,
            operator_read: false,
        }
    }

    async fn control_state(&self) -> anyhow::Result<Option<String>> {
        let Some(pool) = &self.control_pool else {
            return Ok(None);
        };
        let state =
            sqlx::query_scalar("SELECT state FROM tenant_secret_control WHERE singleton = true")
                .fetch_one(pool)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("tenant-secret-source failure_class=authority-query-failed")
                })?;
        Ok(Some(state))
    }

    async fn require_source_read(&self) -> anyhow::Result<()> {
        let Some(state) = self.control_state().await? else {
            return Ok(());
        };
        if self.operator_read || matches!(state.as_str(), "infisical" | "importing") {
            return Ok(());
        }
        anyhow::bail!("tenant-secret-source failure_class=read-authority-unavailable")
    }

    async fn begin_source_write_fence(
        &self,
    ) -> anyhow::Result<Option<Transaction<'static, Postgres>>> {
        let Some(pool) = &self.control_pool else {
            return Ok(None);
        };
        let mut tx = pool.begin().await.map_err(|_| {
            anyhow::anyhow!("tenant-secret-source failure_class=authority-lock-failed")
        })?;
        let state: String = sqlx::query_scalar(
            "SELECT state FROM tenant_secret_control WHERE singleton = true FOR SHARE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| anyhow::anyhow!("tenant-secret-source failure_class=authority-lock-failed"))?;
        if state != "infisical" {
            anyhow::bail!("tenant-secret-source failure_class=write-authority-unavailable")
        }
        Ok(Some(tx))
    }

    async fn commit_source_write_fence(
        fence: Option<Transaction<'static, Postgres>>,
    ) -> anyhow::Result<()> {
        if let Some(tx) = fence {
            tx.commit().await.map_err(|_| {
                anyhow::anyhow!("tenant-secret-source failure_class=authority-release-failed")
            })?;
        }
        Ok(())
    }

    fn api_url(&self, suffix: &[&str]) -> anyhow::Result<url::Url> {
        let mut url = url::Url::parse(&self.host_api)
            .map_err(|error| anyhow::anyhow!("invalid Infisical host URL: {error}"))?;
        url.set_query(None);
        url.set_fragment(None);
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Infisical host URL cannot carry path segments"))?;
        segments.pop_if_empty().extend(suffix);
        drop(segments);
        Ok(url)
    }

    fn raw_secret_url(&self, key: &str) -> anyhow::Result<url::Url> {
        if !is_valid_secret_key(key) {
            anyhow::bail!("secret key must contain only ASCII letters, digits, or underscores");
        }
        self.api_url(&["api", "v3", "secrets", "raw", key])
    }

    async fn authenticate(&self) -> anyhow::Result<String> {
        let mut guard = self.token.lock().await;
        if let Some((token, expiry)) = guard.as_ref()
            && Instant::now() < *expiry
        {
            return Ok(token.clone());
        }

        let (url, body) = if !self.k8s_identity_id.is_empty() {
            let sa_token = std::fs::read_to_string(SA_TOKEN_PATH)
                .map_err(|e| anyhow::anyhow!("read SA token: {e}"))?;
            (
                format!("{}/api/v1/auth/kubernetes-auth/login", self.host_api),
                serde_json::json!({"identityId": self.k8s_identity_id, "jwt": sa_token}),
            )
        } else {
            (
                format!("{}/api/v1/auth/universal-auth/login", self.host_api),
                serde_json::json!({"clientId": self.client_id, "clientSecret": self.client_secret}),
            )
        };

        let resp = self.http.post(&url).json(&body).send().await?;
        let status = resp.status();
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical auth failed (status {status})");
        }
        let auth: AuthResponse = resp.json().await?;
        // Same 60s early-refresh margin as Go.
        let expiry = Instant::now() + Duration::from_secs(auth.expires_in.saturating_sub(60));
        *guard = Some((auth.access_token.clone(), expiry));
        Ok(auth.access_token)
    }

    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<InfisicalSecret>> {
        self.require_source_read().await?;
        self.get_secrets_raw_at_path_unfenced(secret_path).await
    }

    async fn get_secrets_raw_at_path_unfenced(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<InfisicalSecret>> {
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let mut url = self.api_url(&["api", "v3", "secrets", "raw"])?;
        url.query_pairs_mut()
            .append_pair("workspaceId", &self.project_id)
            .append_pair("environment", "prod")
            .append_pair("secretPath", secret_path);
        let resp = self
            .http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical api: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            // Folder doesn't exist yet — no secrets, not an error.
            return Ok(Vec::new());
        }
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical get secrets failed (status {status})");
        }
        let parsed: SecretsResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("decode response: {e}"))?;
        Ok(parsed.secrets)
    }

    /// Mirrors `InfisicalClient.CreateFolderAtPath`. Infisical returns 400
    /// (not 409) with "already exists" when the folder is present — both are
    /// treated as success.
    pub async fn create_folder_at_path(&self, parent_path: &str, name: &str) -> anyhow::Result<()> {
        let fence = self.begin_source_write_fence().await?;
        self.create_folder_at_path_unfenced(parent_path, name)
            .await?;
        Self::commit_source_write_fence(fence).await
    }

    async fn create_folder_at_path_unfenced(
        &self,
        parent_path: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let resp = self
            .http
            .post(format!("{}/api/v1/folders", self.host_api))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "workspaceId": self.project_id,
                "environment": "prod",
                "name": name,
                "path": parent_path,
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical api: {e}"))?;
        let status = resp.status();
        if status.as_u16() >= 400 {
            let text = resp.text().await.unwrap_or_default();
            if status.as_u16() == 409 || (status.as_u16() == 400 && text.contains("already exists"))
            {
                return Ok(());
            }
            anyhow::bail!("infisical create folder failed (status {status})");
        }
        Ok(())
    }

    /// Mirrors `InfisicalClient.SetSecretAtPath`: POST to create, and on a
    /// 400/409 conflict, PATCH to update.
    pub async fn set_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let fence = self.begin_source_write_fence().await?;
        self.set_secret_at_path_unfenced(secret_path, key, value)
            .await?;
        Self::commit_source_write_fence(fence).await
    }

    async fn set_secret_at_path_unfenced(
        &self,
        secret_path: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let url = self.raw_secret_url(key)?;
        let resp = self
            .http
            .post(url.clone())
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "workspaceId": self.project_id,
                "environment": "prod",
                "secretPath": secret_path,
                "secretKey": key,
                "secretValue": value,
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical api: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 409 || status.as_u16() == 400 {
            // Already exists — update instead.
            let resp2 = self
                .http
                .patch(url)
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "workspaceId": self.project_id,
                    "environment": "prod",
                    "secretPath": secret_path,
                    "secretValue": value,
                }))
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("infisical update api: {e}"))?;
            if resp2.status().as_u16() >= 400 {
                let update_status = resp2.status();
                anyhow::bail!("infisical update secret failed (status {update_status})");
            }
            return Ok(());
        }
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical set secret failed (status {status})");
        }
        Ok(())
    }

    /// Mirrors `InfisicalClient.DeleteSecretAtPath`: 404 (already gone) is OK.
    pub async fn delete_secret_at_path(&self, secret_path: &str, key: &str) -> anyhow::Result<()> {
        let fence = self.begin_source_write_fence().await?;
        self.delete_secret_at_path_unfenced(secret_path, key)
            .await?;
        Self::commit_source_write_fence(fence).await
    }

    async fn delete_secret_at_path_unfenced(
        &self,
        secret_path: &str,
        key: &str,
    ) -> anyhow::Result<()> {
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let resp = self
            .http
            .delete(self.raw_secret_url(key)?)
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "workspaceId": self.project_id,
                "environment": "prod",
                "secretPath": secret_path,
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical api: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(());
        }
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical delete secret failed (status {status})");
        }
        Ok(())
    }

    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        self.require_source_read().await?;
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let mut url = self.api_url(&["api", "v2", "folders"])?;
        url.query_pairs_mut()
            .append_pair("projectId", &self.project_id)
            .append_pair("environment", "prod")
            .append_pair("path", parent_path)
            .append_pair("recursive", "false");
        let resp = self
            .http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical folder enumeration: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical folder enumeration failed (status {status})");
        }
        let parsed: FoldersResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("decode folder enumeration: {e}"))?;
        Ok(parsed
            .folders
            .into_iter()
            .map(|folder| folder.name)
            .collect())
    }

    pub async fn delete_folder_at_path(&self, parent_path: &str, name: &str) -> anyhow::Result<()> {
        let fence = self.begin_source_write_fence().await?;
        self.delete_folder_at_path_unfenced(parent_path, name)
            .await?;
        Self::commit_source_write_fence(fence).await
    }

    async fn delete_folder_at_path_unfenced(
        &self,
        parent_path: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let token = self
            .authenticate()
            .await
            .map_err(|e| anyhow::anyhow!("authenticate: {e}"))?;
        let url = self.api_url(&["api", "v2", "folders", name])?;
        let resp = self
            .http
            .delete(url)
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "projectId": self.project_id,
                "environment": "prod",
                "path": parent_path,
                "forceDelete": false,
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("infisical folder deletion: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(());
        }
        if status.as_u16() >= 400 {
            anyhow::bail!("infisical folder deletion failed (status {status})");
        }
        Ok(())
    }

    /// Mirrors `InfisicalClient.RenameSecretAtPath`: read the old value (404 if
    /// absent / 409 if the new key exists), write it under the new key, then
    /// delete the old.
    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        let fence = self.begin_source_write_fence().await?;
        let secrets = self
            .get_secrets_raw_at_path_unfenced(secret_path)
            .await
            .map_err(|e| anyhow::anyhow!("get secrets: {e}"))?;
        let mut value: Option<String> = None;
        for s in &secrets {
            if s.key == new_key {
                anyhow::bail!("secret already exists");
            }
            if s.key == old_key {
                value = Some(s.value.clone());
            }
        }
        let Some(value) = value else {
            anyhow::bail!("secret not found");
        };
        self.set_secret_at_path_unfenced(secret_path, new_key, &value)
            .await?;
        self.delete_secret_at_path_unfenced(secret_path, old_key)
            .await?;
        Self::commit_source_write_fence(fence).await
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
/// than a general URL segment makes the Infisical path sink unambiguous and
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
    secrets: Vec<InfisicalSecret>,
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
                InfisicalSecret {
                    key: "EXPLICIT".into(),
                    value: "lose".into(),
                    ..Default::default()
                },
                InfisicalSecret {
                    key: "NEW".into(),
                    value: "v".into(),
                    ..Default::default()
                },
                InfisicalSecret {
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
    fn infisical_secret_parses_api_field_names() {
        let s: InfisicalSecret =
            serde_json::from_str(r#"{"secretKey":"K","secretValue":"V","createdAt":"x"}"#).unwrap();
        assert_eq!(s.key, "K");
        assert_eq!(s.value, "V");
    }

    #[test]
    fn infisical_secret_key_is_one_encoded_path_segment() {
        let client = InfisicalClient {
            host_api: "https://infisical.example/base".into(),
            project_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            k8s_identity_id: String::new(),
            http: reqwest::Client::new(),
            token: Mutex::new(None),
            control_pool: None,
            operator_read: false,
        };

        assert_eq!(
            client.raw_secret_url("DATABASE_URL").unwrap().as_str(),
            "https://infisical.example/base/api/v3/secrets/raw/DATABASE_URL"
        );
        for invalid in [
            "",
            "db/password",
            "stage?prod",
            "name#fragment",
            "..",
            "na-me",
        ] {
            assert!(
                client.raw_secret_url(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}
