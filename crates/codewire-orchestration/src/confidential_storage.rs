//! Guest-held confidential workspace key lifecycle.
//!
//! The recovery key lives only in the dedicated platform Infisical project and
//! Trustee KBS. PostgreSQL stores lifecycle metadata and a SHA-256 fingerprint,
//! never key bytes. Provider errors are deliberately reduced to a stage and
//! HTTP status before they cross this module so response bodies and credentials
//! cannot enter logs or durable error fields.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

const KEY_BYTES: usize = 32;
const KEY_NAME: &str = "LUKS_KEY_V1";
const KEY_VERSION: i32 = 1;
const INFISICAL_PARENT_PATH: &str = "/confidential-storage";
const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const KBS_RESOURCE_PREFIX: &str = "default/codewire-workspace-luks";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureFlags {
    pub enabled: bool,
    pub admin_only: bool,
}

impl FeatureFlags {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            enabled: parse_bool_env("SANDBOX_CONFIDENTIAL_STORAGE_ENABLED", false)?,
            admin_only: parse_bool_env("SANDBOX_CONFIDENTIAL_ADMIN_ONLY", true)?,
        })
    }
}

/// Authoritative product gate for confidential create and interactive
/// operations. Stop, destroy, and system reconciliation deliberately do not
/// call this helper, so disabling the feature cannot orphan resources.
pub fn require_interactive_access(
    flags: FeatureFlags,
    user: &AuthUser,
    isolation_tier: &str,
) -> AppResult<()> {
    if isolation_tier != "confidential" {
        return Ok(());
    }
    if !flags.enabled {
        return Err(AppError::Coded {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "CONFIDENTIAL_STORAGE_DISABLED",
            detail: "confidential persistent storage is disabled".into(),
        });
    }
    if flags.admin_only && user.require_global_admin().is_err() {
        return Err(AppError::Coded {
            status: StatusCode::FORBIDDEN,
            code: "CONFIDENTIAL_ADMIN_REQUIRED",
            detail: "a global administrator user credential is required".into(),
        });
    }
    Ok(())
}

fn parse_bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(value) => anyhow::bail!("{name} must be true or false, got {value:?}"),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub environment_id: String,
    pub kbs_uri: String,
    pub infisical_path: String,
    pub version: i32,
    pub sha256_fingerprint: Option<String>,
    pub state: String,
    pub last_redacted_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("confidential storage {stage} failed{status_suffix}")]
pub struct ProviderError {
    stage: &'static str,
    status: Option<u16>,
    status_suffix: String,
}

impl ProviderError {
    fn new(stage: &'static str, status: Option<reqwest::StatusCode>) -> Self {
        let status = status.map(|value| value.as_u16());
        let status_suffix = status
            .map(|value| format!(" (HTTP {value})"))
            .unwrap_or_default();
        Self {
            stage,
            status,
            status_suffix,
        }
    }

    fn redacted(&self) -> String {
        match self.status {
            Some(status) => format!("{} failed (HTTP {status})", self.stage),
            None => format!("{} failed", self.stage),
        }
    }
}

#[async_trait]
pub trait RecoveryKeyStore: Send + Sync {
    async fn get_or_create(
        &self,
        environment_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError>;
    async fn delete(&self, environment_id: &str) -> Result<(), ProviderError>;
}

#[async_trait]
pub trait KbsAdmin: Send + Sync {
    async fn set_resource(&self, environment_id: &str, key: &[u8]) -> Result<(), ProviderError>;
    async fn delete_resource(&self, environment_id: &str) -> Result<(), ProviderError>;
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn begin(&self, environment_id: &str) -> anyhow::Result<Metadata>;
    async fn set_fingerprint(&self, environment_id: &str, fingerprint: &str) -> anyhow::Result<()>;
    async fn mark_ready(&self, environment_id: &str) -> anyhow::Result<()>;
    async fn mark_error(&self, environment_id: &str, error: &str) -> anyhow::Result<()>;
    async fn mark_deleting(&self, environment_id: &str) -> anyhow::Result<()>;
    async fn mark_deleted(&self, environment_id: &str) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct ConfidentialStorageManager {
    metadata: Arc<dyn MetadataStore>,
    recovery: Arc<dyn RecoveryKeyStore>,
    kbs: Arc<dyn KbsAdmin>,
}

impl ConfidentialStorageManager {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        recovery: Arc<dyn RecoveryKeyStore>,
        kbs: Arc<dyn KbsAdmin>,
    ) -> Self {
        Self {
            metadata,
            recovery,
            kbs,
        }
    }

    /// Build the manager when creation is enabled or provider configuration is
    /// retained for cleanup. This lets operators disable new confidential
    /// workspaces first while keeping stop/destroy reconciliation available.
    /// There is no local or tenant-secret fallback: partial platform
    /// configuration is fatal.
    pub fn from_env(pool: PgPool, flags: FeatureFlags) -> anyhow::Result<Option<Self>> {
        let provider_env = [
            "CONFIDENTIAL_STORAGE_INFISICAL_HOST",
            "CONFIDENTIAL_STORAGE_INFISICAL_PROJECT_ID",
            "CONFIDENTIAL_STORAGE_INFISICAL_K8S_AUTH_IDENTITY_ID",
            "CONFIDENTIAL_STORAGE_KBS_URL",
        ];
        let any_provider_configured = provider_env.iter().any(|name| {
            std::env::var(name)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
        });
        if !flags.enabled && !any_provider_configured {
            return Ok(None);
        }
        Ok(Some(Self::new(
            Arc::new(PgMetadataStore { pool }),
            Arc::new(PlatformInfisicalClient::from_env()?),
            Arc::new(TrusteeKbsClient::from_env()?),
        )))
    }

    /// Reconcile the recovery copy and KBS resource. This runs before a
    /// SandboxClaim is created and before a stopped confidential sandbox is
    /// scaled back up. Repeated calls always recover the existing key.
    pub async fn ensure_ready(&self, environment_id: &str) -> anyhow::Result<()> {
        validate_environment_id(environment_id)?;
        let existing = self.metadata.begin(environment_id).await?;
        if existing.state == "deleting" || existing.state == "deleted" {
            anyhow::bail!("confidential storage key is being deleted");
        }

        let key = match self.recovery.get_or_create(environment_id).await {
            Ok(key) => key,
            Err(error) => {
                self.record_provider_error(environment_id, &error).await;
                return Err(error.into());
            }
        };
        if key.len() != KEY_BYTES {
            let error = ProviderError::new("Infisical key validation", None);
            self.record_provider_error(environment_id, &error).await;
            return Err(error.into());
        }

        let fingerprint = hex_sha256(&key);
        if existing
            .sha256_fingerprint
            .as_deref()
            .is_some_and(|stored| stored != fingerprint)
        {
            let error = ProviderError::new("recovery key fingerprint validation", None);
            self.record_provider_error(environment_id, &error).await;
            return Err(error.into());
        }
        self.metadata
            .set_fingerprint(environment_id, &fingerprint)
            .await?;

        if let Err(error) = self.kbs.set_resource(environment_id, &key).await {
            self.record_provider_error(environment_id, &error).await;
            return Err(error.into());
        }
        self.metadata.mark_ready(environment_id).await?;
        Ok(())
    }

    /// Delete both key copies after the caller has proved that Sandbox, PVC,
    /// PV, and Longhorn volume resources are absent. Every provider operation
    /// is idempotent, so Temporal retries resume safely.
    pub async fn delete_after_storage_absent(&self, environment_id: &str) -> anyhow::Result<()> {
        validate_environment_id(environment_id)?;
        self.metadata.mark_deleting(environment_id).await?;
        if let Err(error) = self.kbs.delete_resource(environment_id).await {
            self.record_provider_error(environment_id, &error).await;
            return Err(error.into());
        }
        if let Err(error) = self.recovery.delete(environment_id).await {
            self.record_provider_error(environment_id, &error).await;
            return Err(error.into());
        }
        self.metadata.mark_deleted(environment_id).await?;
        Ok(())
    }

    async fn record_provider_error(&self, environment_id: &str, error: &ProviderError) {
        if let Err(metadata_error) = self
            .metadata
            .mark_error(environment_id, &error.redacted())
            .await
        {
            tracing::error!(
                environment_id,
                stage = error.stage,
                error = %metadata_error,
                "failed to record redacted confidential storage error"
            );
        }
    }
}

fn validate_environment_id(environment_id: &str) -> anyhow::Result<()> {
    let parsed = Uuid::parse_str(environment_id)
        .map_err(|_| anyhow::anyhow!("confidential storage environment ID must be a UUID"))?;
    if parsed.to_string() != environment_id {
        anyhow::bail!("confidential storage environment ID must use canonical UUID form");
    }
    Ok(())
}

pub fn kbs_uri(environment_id: &str) -> String {
    format!("kbs:///{KBS_RESOURCE_PREFIX}/{environment_id}")
}

pub fn infisical_path(environment_id: &str) -> String {
    format!("{INFISICAL_PARENT_PATH}/{environment_id}")
}

fn hex_sha256(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct PgMetadataStore {
    pool: PgPool,
}

#[async_trait]
impl MetadataStore for PgMetadataStore {
    async fn begin(&self, environment_id: &str) -> anyhow::Result<Metadata> {
        let row = sqlx::query(
            r#"INSERT INTO confidential_storage_keys
                   (environment_id, kbs_uri, infisical_path, version, state, updated_at)
               VALUES ($1, $2, $3, $4, 'provisioning', NOW())
               ON CONFLICT (environment_id) DO UPDATE SET
                   state = CASE
                       WHEN confidential_storage_keys.state IN ('deleting', 'deleted')
                           THEN confidential_storage_keys.state
                       ELSE 'provisioning'
                   END,
                   last_redacted_error = CASE
                       WHEN confidential_storage_keys.state IN ('deleting', 'deleted')
                           THEN confidential_storage_keys.last_redacted_error
                       ELSE NULL
                   END,
                   updated_at = NOW()
               RETURNING environment_id, kbs_uri, infisical_path, version,
                         sha256_fingerprint, state, last_redacted_error"#,
        )
        .bind(environment_id)
        .bind(kbs_uri(environment_id))
        .bind(infisical_path(environment_id))
        .bind(KEY_VERSION)
        .fetch_one(&self.pool)
        .await?;
        Ok(Metadata {
            environment_id: row.try_get("environment_id")?,
            kbs_uri: row.try_get("kbs_uri")?,
            infisical_path: row.try_get("infisical_path")?,
            version: row.try_get("version")?,
            sha256_fingerprint: row.try_get("sha256_fingerprint")?,
            state: row.try_get("state")?,
            last_redacted_error: row.try_get("last_redacted_error")?,
        })
    }

    async fn set_fingerprint(&self, environment_id: &str, fingerprint: &str) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"UPDATE confidential_storage_keys
               SET sha256_fingerprint = COALESCE(sha256_fingerprint, $2), updated_at = NOW()
               WHERE environment_id = $1
                 AND (sha256_fingerprint IS NULL OR sha256_fingerprint = $2)
                 AND state NOT IN ('deleting', 'deleted')"#,
        )
        .bind(environment_id)
        .bind(fingerprint)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            anyhow::bail!("confidential storage fingerprint or lifecycle state changed");
        }
        Ok(())
    }

    async fn mark_ready(&self, environment_id: &str) -> anyhow::Result<()> {
        update_metadata_state(&self.pool, environment_id, "ready", None).await
    }

    async fn mark_error(&self, environment_id: &str, error: &str) -> anyhow::Result<()> {
        let redacted = truncate_redacted_error(error);
        update_metadata_state(&self.pool, environment_id, "error", Some(&redacted)).await
    }

    async fn mark_deleting(&self, environment_id: &str) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"INSERT INTO confidential_storage_keys
                   (environment_id, kbs_uri, infisical_path, version, state, deleting_at, updated_at)
               VALUES ($1, $2, $3, $4, 'deleting', NOW(), NOW())
               ON CONFLICT (environment_id) DO UPDATE SET
                   state = CASE WHEN confidential_storage_keys.state = 'deleted'
                                THEN 'deleted' ELSE 'deleting' END,
                   deleting_at = COALESCE(confidential_storage_keys.deleting_at, NOW()),
                   updated_at = NOW(), last_redacted_error = NULL"#,
        )
        .bind(environment_id)
        .bind(kbs_uri(environment_id))
        .bind(infisical_path(environment_id))
        .bind(KEY_VERSION)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            anyhow::bail!("confidential storage deletion metadata was not updated");
        }
        Ok(())
    }

    async fn mark_deleted(&self, environment_id: &str) -> anyhow::Result<()> {
        update_metadata_state(&self.pool, environment_id, "deleted", None).await
    }
}

async fn update_metadata_state(
    pool: &PgPool,
    environment_id: &str,
    state: &str,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        r#"UPDATE confidential_storage_keys
           SET state = $2, last_redacted_error = $3, updated_at = NOW(),
               ready_at = CASE WHEN $2 = 'ready' THEN NOW() ELSE ready_at END,
               deleted_at = CASE WHEN $2 = 'deleted' THEN NOW() ELSE deleted_at END
           WHERE environment_id = $1"#,
    )
    .bind(environment_id)
    .bind(state)
    .bind(error)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        anyhow::bail!("confidential storage lifecycle metadata is missing");
    }
    Ok(())
}

fn truncate_redacted_error(error: &str) -> String {
    error.chars().take(256).collect()
}

struct CachedToken {
    value: Zeroizing<String>,
    expires_at: Instant,
}

pub struct PlatformInfisicalClient {
    host: Url,
    project_id: String,
    identity_id: String,
    service_account_token_path: PathBuf,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

#[derive(Deserialize)]
struct InfisicalAuthResponse {
    #[serde(rename = "accessToken")]
    access_token: Zeroizing<String>,
    #[serde(rename = "expiresIn", default)]
    expires_in: u64,
}

#[derive(Serialize)]
struct InfisicalAuthRequest<'a> {
    #[serde(rename = "identityId")]
    identity_id: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct InfisicalFolderRequest<'a> {
    #[serde(rename = "workspaceId")]
    workspace_id: &'a str,
    environment: &'static str,
    name: &'a str,
    path: &'static str,
}

#[derive(Serialize)]
struct InfisicalCreateSecretRequest<'a> {
    #[serde(rename = "workspaceId")]
    workspace_id: &'a str,
    environment: &'static str,
    #[serde(rename = "secretPath")]
    secret_path: &'a str,
    #[serde(rename = "secretKey")]
    secret_key: &'static str,
    #[serde(rename = "secretValue")]
    secret_value: &'a str,
}

#[derive(Serialize)]
struct InfisicalDeleteSecretRequest<'a> {
    #[serde(rename = "workspaceId")]
    workspace_id: &'a str,
    environment: &'static str,
    #[serde(rename = "secretPath")]
    secret_path: &'a str,
}

#[derive(Deserialize)]
struct InfisicalSecret {
    #[serde(rename = "secretKey")]
    key: String,
    #[serde(rename = "secretValue")]
    value: Zeroizing<String>,
}

#[derive(Deserialize)]
struct InfisicalSecretsResponse {
    #[serde(default)]
    secrets: Vec<InfisicalSecret>,
}

impl PlatformInfisicalClient {
    fn from_env() -> anyhow::Result<Self> {
        let host = required_env("CONFIDENTIAL_STORAGE_INFISICAL_HOST")?;
        let host = parse_infisical_origin("CONFIDENTIAL_STORAGE_INFISICAL_HOST", &host)?;
        let https_only = host.scheme() == "https";
        Ok(Self {
            host,
            project_id: required_env("CONFIDENTIAL_STORAGE_INFISICAL_PROJECT_ID")?,
            identity_id: required_env("CONFIDENTIAL_STORAGE_INFISICAL_K8S_AUTH_IDENTITY_ID")?,
            service_account_token_path: std::env::var_os(
                "CONFIDENTIAL_STORAGE_SERVICE_ACCOUNT_TOKEN_FILE",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(SA_TOKEN_PATH)),
            http: restricted_http_client(Duration::from_secs(30), https_only, None)?,
            token: Mutex::new(None),
        })
    }

    fn url(&self, segments: &[&str]) -> Result<Url, ProviderError> {
        let mut url = self.host.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| ProviderError::new("Infisical URL construction", None))?;
        path.pop_if_empty().extend(segments);
        drop(path);
        Ok(url)
    }

    async fn authenticate(&self) -> Result<Zeroizing<String>, ProviderError> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && token.expires_at > Instant::now()
        {
            return Ok(Zeroizing::new(token.value.to_string()));
        }
        let jwt = Zeroizing::new(
            std::fs::read_to_string(&self.service_account_token_path)
                .map_err(|_| ProviderError::new("Infisical workload authentication", None))?,
        );
        let url = self.url(&["api", "v1", "auth", "kubernetes-auth", "login"])?;
        let response = self
            .http
            .post(url)
            .json(&InfisicalAuthRequest {
                identity_id: &self.identity_id,
                jwt: jwt.as_str(),
            })
            .send()
            .await
            .map_err(|_| ProviderError::new("Infisical workload authentication", None))?;
        if !response.status().is_success() {
            return Err(ProviderError::new(
                "Infisical workload authentication",
                Some(response.status()),
            ));
        }
        let response: InfisicalAuthResponse = response
            .json()
            .await
            .map_err(|_| ProviderError::new("Infisical workload authentication", None))?;
        let expires_at =
            Instant::now() + Duration::from_secs(response.expires_in.saturating_sub(60));
        let result = Zeroizing::new(response.access_token.to_string());
        *cached = Some(CachedToken {
            value: response.access_token,
            expires_at,
        });
        Ok(result)
    }

    async fn read_key(
        &self,
        environment_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ProviderError> {
        let token = self.authenticate().await?;
        let mut url = self.url(&["api", "v3", "secrets", "raw"])?;
        url.query_pairs_mut()
            .append_pair("workspaceId", &self.project_id)
            .append_pair("environment", "prod")
            .append_pair("secretPath", &infisical_path(environment_id));
        let response = self
            .http
            .get(url)
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|_| ProviderError::new("Infisical key read", None))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ProviderError::new(
                "Infisical key read",
                Some(response.status()),
            ));
        }
        let response: InfisicalSecretsResponse = response
            .json()
            .await
            .map_err(|_| ProviderError::new("Infisical key read", None))?;
        let Some(secret) = response
            .secrets
            .into_iter()
            .find(|secret| secret.key == KEY_NAME)
        else {
            return Ok(None);
        };
        let decoded = STANDARD
            .decode(secret.value.as_bytes())
            .map_err(|_| ProviderError::new("Infisical key validation", None))?;
        if decoded.len() != KEY_BYTES {
            return Err(ProviderError::new("Infisical key validation", None));
        }
        Ok(Some(Zeroizing::new(decoded)))
    }

    async fn create_folder(&self, environment_id: &str, token: &str) -> Result<(), ProviderError> {
        let url = self.url(&["api", "v1", "folders"])?;
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&InfisicalFolderRequest {
                workspace_id: &self.project_id,
                environment: "prod",
                name: environment_id,
                path: INFISICAL_PARENT_PATH,
            })
            .send()
            .await
            .map_err(|_| ProviderError::new("Infisical folder create", None))?;
        if response.status().is_success()
            || response.status() == reqwest::StatusCode::BAD_REQUEST
            || response.status() == reqwest::StatusCode::CONFLICT
        {
            return Ok(());
        }
        Err(ProviderError::new(
            "Infisical folder create",
            Some(response.status()),
        ))
    }

    async fn create_key(&self, environment_id: &str, key: &[u8]) -> Result<bool, ProviderError> {
        let token = self.authenticate().await?;
        self.create_folder(environment_id, token.as_str()).await?;
        let url = self.url(&["api", "v3", "secrets", "raw", KEY_NAME])?;
        let encoded = Zeroizing::new(STANDARD.encode(key));
        let secret_path = infisical_path(environment_id);
        let response = self
            .http
            .post(url)
            .bearer_auth(token.as_str())
            .json(&InfisicalCreateSecretRequest {
                workspace_id: &self.project_id,
                environment: "prod",
                secret_path: &secret_path,
                secret_key: KEY_NAME,
                secret_value: encoded.as_str(),
            })
            .send()
            .await
            .map_err(|_| ProviderError::new("Infisical key create", None))?;
        if response.status().is_success() {
            return Ok(true);
        }
        if response.status() == reqwest::StatusCode::BAD_REQUEST
            || response.status() == reqwest::StatusCode::CONFLICT
        {
            return Ok(false);
        }
        Err(ProviderError::new(
            "Infisical key create",
            Some(response.status()),
        ))
    }
}

#[async_trait]
impl RecoveryKeyStore for PlatformInfisicalClient {
    async fn get_or_create(
        &self,
        environment_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        validate_environment_id(environment_id)
            .map_err(|_| ProviderError::new("Infisical key path validation", None))?;
        if let Some(key) = self.read_key(environment_id).await? {
            return Ok(key);
        }

        let mut generated = Zeroizing::new(vec![0_u8; KEY_BYTES]);
        rand::rngs::OsRng.fill_bytes(&mut generated);
        if self.create_key(environment_id, &generated).await? {
            return Ok(generated);
        }
        // A concurrent retry won the create. Read its value; never overwrite.
        self.read_key(environment_id)
            .await?
            .ok_or_else(|| ProviderError::new("Infisical create conflict recovery", None))
    }

    async fn delete(&self, environment_id: &str) -> Result<(), ProviderError> {
        validate_environment_id(environment_id)
            .map_err(|_| ProviderError::new("Infisical key path validation", None))?;
        let token = self.authenticate().await?;
        let url = self.url(&["api", "v3", "secrets", "raw", KEY_NAME])?;
        let secret_path = infisical_path(environment_id);
        let response = self
            .http
            .delete(url)
            .bearer_auth(token.as_str())
            .json(&InfisicalDeleteSecretRequest {
                workspace_id: &self.project_id,
                environment: "prod",
                secret_path: &secret_path,
            })
            .send()
            .await
            .map_err(|_| ProviderError::new("Infisical key delete", None))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(ProviderError::new(
                "Infisical key delete",
                Some(response.status()),
            ))
        }
    }
}

pub struct TrusteeKbsClient {
    base_url: Url,
    admin_token_file: PathBuf,
    http: reqwest::Client,
}

impl TrusteeKbsClient {
    fn from_env() -> anyhow::Result<Self> {
        let base_url = required_env("CONFIDENTIAL_STORAGE_KBS_URL")?;
        let ca_path = PathBuf::from(required_env("CONFIDENTIAL_STORAGE_KBS_CA_PATH")?);
        let ca_pem = std::fs::read(&ca_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read public KBS CA at {}: {error}",
                ca_path.display()
            )
        })?;
        Ok(Self {
            base_url: parse_https_origin("CONFIDENTIAL_STORAGE_KBS_URL", &base_url)?,
            admin_token_file: PathBuf::from(required_env(
                "CONFIDENTIAL_STORAGE_KBS_ADMIN_TOKEN_FILE",
            )?),
            http: restricted_http_client(Duration::from_secs(30), true, Some(&ca_pem))?,
        })
    }

    #[cfg(test)]
    fn for_test(base_url: Url, admin_token_file: PathBuf) -> Self {
        Self {
            base_url,
            admin_token_file,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    fn resource_url(&self, environment_id: &str) -> Result<Url, ProviderError> {
        validate_environment_id(environment_id)
            .map_err(|_| ProviderError::new("KBS resource path validation", None))?;
        let mut url = self.base_url.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| ProviderError::new("KBS URL construction", None))?;
        path.pop_if_empty().extend([
            "kbs",
            "v0",
            "resource",
            "default",
            "codewire-workspace-luks",
            environment_id,
        ]);
        drop(path);
        Ok(url)
    }

    fn token(&self) -> Result<Zeroizing<String>, ProviderError> {
        let value = Zeroizing::new(
            std::fs::read_to_string(&self.admin_token_file)
                .map_err(|_| ProviderError::new("KBS admin authentication", None))?,
        );
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ProviderError::new("KBS admin authentication", None));
        }
        Ok(Zeroizing::new(trimmed.to_owned()))
    }
}

#[async_trait]
impl KbsAdmin for TrusteeKbsClient {
    async fn set_resource(&self, environment_id: &str, key: &[u8]) -> Result<(), ProviderError> {
        if key.len() != KEY_BYTES {
            return Err(ProviderError::new("KBS key validation", None));
        }
        let token = self.token()?;
        let response = self
            .http
            .post(self.resource_url(environment_id)?)
            .bearer_auth(token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(key.to_vec())
            .send()
            .await
            .map_err(|_| ProviderError::new("KBS resource provision", None))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ProviderError::new(
                "KBS resource provision",
                Some(response.status()),
            ))
        }
    }

    async fn delete_resource(&self, environment_id: &str) -> Result<(), ProviderError> {
        let token = self.token()?;
        let response = self
            .http
            .delete(self.resource_url(environment_id)?)
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|_| ProviderError::new("KBS resource delete", None))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(ProviderError::new(
                "KBS resource delete",
                Some(response.status()),
            ))
        }
    }
}

fn restricted_http_client(
    timeout: Duration,
    https_only: bool,
    root_certificate_pem: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);
    if let Some(root_certificate_pem) = root_certificate_pem {
        let certificate = reqwest::Certificate::from_pem(root_certificate_pem)?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().map_err(Into::into)
}

fn parse_https_origin(name: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    if url.scheme() != "https" {
        anyhow::bail!("{name} must use HTTPS");
    }
    parse_origin(name, url)
}

fn parse_infisical_origin(name: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    let internal_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host.ends_with(".svc.cluster.local"));
    if url.scheme() == "https" || internal_http {
        parse_origin(name, url)
    } else {
        anyhow::bail!("{name} must use HTTPS or an in-cluster .svc.cluster.local HTTP endpoint")
    }
}

fn parse_origin(name: &str, mut url: Url) -> anyhow::Result<Url> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("{name} must be an origin URL without credentials, query, or fragment");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("required environment variable {name} is not set"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::Request;
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    const ENVIRONMENT_ID: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";

    fn user(is_admin: bool, via_api_key: bool) -> AuthUser {
        AuthUser {
            user_id: "test-user".into(),
            org_id: Some("test-org".into()),
            is_admin,
            via_api_key,
        }
    }

    #[derive(Default)]
    struct MemoryMetadata {
        values: Mutex<BTreeMap<String, Metadata>>,
        events: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl MetadataStore for MemoryMetadata {
        async fn begin(&self, environment_id: &str) -> anyhow::Result<Metadata> {
            self.events.lock().await.push("metadata.begin");
            let mut values = self.values.lock().await;
            let value = values
                .entry(environment_id.into())
                .or_insert_with(|| Metadata {
                    environment_id: environment_id.into(),
                    kbs_uri: kbs_uri(environment_id),
                    infisical_path: infisical_path(environment_id),
                    version: 1,
                    sha256_fingerprint: None,
                    state: "provisioning".into(),
                    last_redacted_error: None,
                });
            if !matches!(value.state.as_str(), "deleting" | "deleted") {
                value.state = "provisioning".into();
                value.last_redacted_error = None;
            }
            Ok(value.clone())
        }

        async fn set_fingerprint(&self, id: &str, fingerprint: &str) -> anyhow::Result<()> {
            self.events.lock().await.push("metadata.fingerprint");
            let mut values = self.values.lock().await;
            let value = values.get_mut(id).unwrap();
            if value
                .sha256_fingerprint
                .as_deref()
                .is_some_and(|old| old != fingerprint)
            {
                anyhow::bail!("fingerprint mismatch");
            }
            value.sha256_fingerprint = Some(fingerprint.into());
            Ok(())
        }

        async fn mark_ready(&self, id: &str) -> anyhow::Result<()> {
            self.events.lock().await.push("metadata.ready");
            self.values.lock().await.get_mut(id).unwrap().state = "ready".into();
            Ok(())
        }

        async fn mark_error(&self, id: &str, error: &str) -> anyhow::Result<()> {
            self.events.lock().await.push("metadata.error");
            let mut values = self.values.lock().await;
            let value = values.get_mut(id).unwrap();
            value.state = "error".into();
            value.last_redacted_error = Some(error.into());
            Ok(())
        }

        async fn mark_deleting(&self, id: &str) -> anyhow::Result<()> {
            self.events.lock().await.push("metadata.deleting");
            let mut values = self.values.lock().await;
            values
                .entry(id.into())
                .or_insert_with(|| Metadata {
                    environment_id: id.into(),
                    kbs_uri: kbs_uri(id),
                    infisical_path: infisical_path(id),
                    version: 1,
                    sha256_fingerprint: None,
                    state: "deleting".into(),
                    last_redacted_error: None,
                })
                .state = "deleting".into();
            Ok(())
        }

        async fn mark_deleted(&self, id: &str) -> anyhow::Result<()> {
            self.events.lock().await.push("metadata.deleted");
            self.values.lock().await.get_mut(id).unwrap().state = "deleted".into();
            Ok(())
        }
    }

    struct MemoryRecovery {
        key: Mutex<Option<Zeroizing<Vec<u8>>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl RecoveryKeyStore for MemoryRecovery {
        async fn get_or_create(&self, _: &str) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            self.events.lock().await.push("infisical.get-or-create");
            let mut key = self.key.lock().await;
            Ok(Zeroizing::new(
                key.get_or_insert_with(|| Zeroizing::new(vec![0x5a; KEY_BYTES]))
                    .to_vec(),
            ))
        }

        async fn delete(&self, _: &str) -> Result<(), ProviderError> {
            self.events.lock().await.push("infisical.delete");
            *self.key.lock().await = None;
            Ok(())
        }
    }

    struct MemoryKbs {
        values: Mutex<Vec<Zeroizing<Vec<u8>>>>,
        fail: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl KbsAdmin for MemoryKbs {
        async fn set_resource(&self, _: &str, key: &[u8]) -> Result<(), ProviderError> {
            self.events.lock().await.push("kbs.set");
            if self.fail {
                return Err(ProviderError::new("KBS resource provision", None));
            }
            self.values.lock().await.push(Zeroizing::new(key.to_vec()));
            Ok(())
        }

        async fn delete_resource(&self, _: &str) -> Result<(), ProviderError> {
            self.events.lock().await.push("kbs.delete");
            self.values.lock().await.clear();
            Ok(())
        }
    }

    fn manager(
        fail_kbs: bool,
    ) -> (
        ConfidentialStorageManager,
        Arc<MemoryMetadata>,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let metadata = Arc::new(MemoryMetadata::default());
        let recovery = Arc::new(MemoryRecovery {
            key: Mutex::new(None),
            events: events.clone(),
        });
        let kbs = Arc::new(MemoryKbs {
            values: Mutex::new(Vec::new()),
            fail: fail_kbs,
            events: events.clone(),
        });
        (
            ConfidentialStorageManager::new(metadata.clone(), recovery, kbs),
            metadata,
            events,
        )
    }

    #[tokio::test]
    async fn create_retries_reuse_one_key_and_reconcile_kbs() {
        let (manager, metadata, events) = manager(false);
        manager.ensure_ready(ENVIRONMENT_ID).await.unwrap();
        let first = metadata.values.lock().await[ENVIRONMENT_ID]
            .sha256_fingerprint
            .clone();
        manager.ensure_ready(ENVIRONMENT_ID).await.unwrap();
        let second = metadata.values.lock().await[ENVIRONMENT_ID]
            .sha256_fingerprint
            .clone();
        assert_eq!(first, second);
        assert_eq!(metadata.values.lock().await[ENVIRONMENT_ID].state, "ready");
        assert_eq!(
            events.lock().await.as_slice(),
            [
                "infisical.get-or-create",
                "kbs.set",
                "infisical.get-or-create",
                "kbs.set",
            ]
        );
    }

    #[tokio::test]
    async fn kbs_failure_is_redacted_and_never_marks_ready() {
        let (manager, metadata, _) = manager(true);
        let error = manager.ensure_ready(ENVIRONMENT_ID).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "confidential storage KBS resource provision failed"
        );
        let value = &metadata.values.lock().await[ENVIRONMENT_ID];
        assert_eq!(value.state, "error");
        assert_eq!(
            value.last_redacted_error.as_deref(),
            Some("KBS resource provision failed")
        );
    }

    #[tokio::test]
    async fn deletion_order_keeps_recovery_until_kbs_is_gone() {
        let (manager, metadata, events) = manager(false);
        manager.ensure_ready(ENVIRONMENT_ID).await.unwrap();
        events.lock().await.clear();
        manager
            .delete_after_storage_absent(ENVIRONMENT_ID)
            .await
            .unwrap();
        assert_eq!(
            events.lock().await.as_slice(),
            ["kbs.delete", "infisical.delete"]
        );
        assert_eq!(
            metadata.values.lock().await[ENVIRONMENT_ID].state,
            "deleted"
        );
    }

    #[test]
    fn identifiers_and_provider_urls_fail_closed() {
        assert!(validate_environment_id(ENVIRONMENT_ID).is_ok());
        assert!(validate_environment_id("not-a-uuid").is_err());
        assert!(parse_https_origin("KBS", "https://kbs.example.test").is_ok());
        assert!(parse_https_origin("KBS", "http://kbs.example.test").is_err());
        assert!(
            parse_infisical_origin(
                "Infisical",
                "http://infisical-backend.codewire-infisical.svc.cluster.local:8080"
            )
            .is_ok()
        );
        assert!(parse_infisical_origin("Infisical", "http://infisical.example.test").is_err());
        assert!(parse_infisical_origin("Infisical", "https://infisical.example.test/api").is_err());
        assert_eq!(
            kbs_uri(ENVIRONMENT_ID),
            "kbs:///default/codewire-workspace-luks/be31063a-8ec8-46d5-aa17-75cda1729370"
        );
    }

    #[test]
    fn admin_only_gate_rejects_non_admins_and_api_keys() {
        let flags = FeatureFlags {
            enabled: true,
            admin_only: true,
        };
        assert!(require_interactive_access(flags, &user(true, false), "confidential").is_ok());
        assert!(require_interactive_access(flags, &user(false, false), "confidential").is_err());
        assert!(require_interactive_access(flags, &user(true, true), "confidential").is_err());
        assert!(require_interactive_access(flags, &user(false, true), "standard").is_ok());
        assert!(
            require_interactive_access(
                FeatureFlags {
                    enabled: false,
                    admin_only: true,
                },
                &user(true, false),
                "confidential",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn kbs_client_uses_authenticated_exact_resource_endpoint_without_logging_body() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let captured = requests.clone();
        let app = Router::new().fallback(move |request: Request| {
            let captured = captured.clone();
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let authorization = request
                    .headers()
                    .get(reqwest::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = to_bytes(request.into_body(), KEY_BYTES + 1)
                    .await
                    .unwrap()
                    .to_vec();
                captured
                    .lock()
                    .unwrap()
                    .push((method, path, authorization, body));
                StatusCode::OK
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), "admin-token\n").unwrap();
        let client = TrusteeKbsClient::for_test(
            Url::parse(&format!("http://{address}")).unwrap(),
            token_file.path().to_path_buf(),
        );
        let key = Zeroizing::new(vec![0x5a; KEY_BYTES]);

        client.set_resource(ENVIRONMENT_ID, &key).await.unwrap();
        client.delete_resource(ENVIRONMENT_ID).await.unwrap();
        server.abort();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for (_, path, authorization, _) in requests.iter() {
            assert_eq!(
                path,
                "/kbs/v0/resource/default/codewire-workspace-luks/be31063a-8ec8-46d5-aa17-75cda1729370"
            );
            assert_eq!(authorization, "Bearer admin-token");
        }
        assert_eq!(requests[0].0, reqwest::Method::POST);
        assert_eq!(requests[0].3, *key);
        assert_eq!(requests[1].0, reqwest::Method::DELETE);
        assert!(requests[1].3.is_empty());
    }
}
