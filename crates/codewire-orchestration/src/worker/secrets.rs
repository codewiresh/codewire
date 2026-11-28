//! Encrypted tenant-secret storage used by the API and environment worker.
//!
//! PostgreSQL stores only encrypted envelopes. OpenBao Transit is the default
//! KEK authority; self-hosted deployments without OpenBao may explicitly opt
//! into `CODEWIRE_SECRET_KEK_PROVIDER=local-keyring` with
//! `CODEWIRE_SECRET_KEK_DIR`. There is never a fallback when OpenBao is
//! missing, and no plaintext fallback. Organization teardown deletes only
//! names and paths, never values, and re-enumerates before it can call a
//! namespace absent.

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;
use sqlx::PgPool;

use codewire_access::ReservedHosts;
#[cfg(test)]
use codewire_protected_store::secret_envelope::KekProvider;
#[cfg(feature = "kind-e2e")]
use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_workload_secrets::validate_workload_secret_key;

pub const SECRET_KEK_PROVIDER_ENV: &str = "CODEWIRE_SECRET_KEK_PROVIDER";
pub const SECRET_KEK_DIR_ENV: &str = "CODEWIRE_SECRET_KEK_DIR";
pub const SECRET_KEK_ACTIVE_ID_ENV: &str = "CODEWIRE_SECRET_KEK_ACTIVE_ID";
const DEFAULT_LOCAL_KEK_ACTIVE_ID: &str = "v1";

pub use super::postgres_secrets::{BindingWrite, BoundSecretRename, SecretWriteError};

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
    /// Absent for a plain secret (#4003).
    pub binding: Option<codewire_access::StoredBinding>,
    pub binding_generation: u64,
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

/// The setting that names more of the deployment's own hosts, which no secret
/// may be bound to: exact names and `*.suffix` entries, comma-separated
/// (docs/CONFIGURATION.md, "Host-bound secrets").
pub const BOUND_HOST_RESERVED_NAMES_ENV: &str = "CODEWIRE_BOUND_HOST_RESERVED_NAMES";

/// The switch for host-bound secrets: `true` or `false`, off when unset.
/// While off, a write that binds a secret is refused, so no secret is ever
/// bound before the projection and the swap that honour a binding ship
/// (docs/CONFIGURATION.md, "Host-bound secrets").
pub const HOST_BOUND_SECRETS_ENABLED_ENV: &str = "CODEWIRE_HOST_BOUND_SECRETS_ENABLED";

pub struct SecretStore {
    store: super::postgres_secrets::PostgresSecretStore,
    /// The deployment's own names, which no binding may name. Built once at
    /// startup, so the API and the worker check the same list.
    reserved: ReservedHosts,
    /// [`HOST_BOUND_SECRETS_ENABLED_ENV`].
    bound_secrets: bool,
}

impl SecretStore {
    #[cfg(test)]
    pub(crate) fn new_for_test(pool: PgPool, provider: std::sync::Arc<dyn KekProvider>) -> Self {
        Self {
            store: super::postgres_secrets::PostgresSecretStore::new(pool, provider),
            reserved: ReservedHosts::default(),
            bound_secrets: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_bound_secrets_for_test(self, bound_secrets: bool) -> Self {
        Self {
            bound_secrets,
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) fn with_reserved_for_test(self, reserved: ReservedHosts) -> Self {
        Self { reserved, ..self }
    }

    #[cfg(feature = "kind-e2e")]
    pub fn for_kind_e2e(pool: PgPool) -> Self {
        Self {
            store: super::postgres_secrets::PostgresSecretStore::new(
                pool,
                std::sync::Arc::new(TestKekProvider),
            ),
            reserved: ReservedHosts::default(),
            bound_secrets: false,
        }
    }

    pub async fn verify_readiness(&self) -> anyhow::Result<()> {
        // Initialization already verifies an existing canary; only one it
        // just created still needs its first verification.
        if self.store.initialize_canary().await? {
            self.store.verify_canary().await?;
        }
        Ok(())
    }

    #[cfg(feature = "kind-e2e")]
    pub fn from_env(pool: PgPool) -> anyhow::Result<Self> {
        Self::from_env_with_kube(pool, None)
    }

    pub fn from_env_with_kube(pool: PgPool, kube: Option<kube::Client>) -> anyhow::Result<Self> {
        let configured = std::env::var(BOUND_HOST_RESERVED_NAMES_ENV).ok();
        let bound_secrets = host_bound_secrets_enabled(
            std::env::var(HOST_BOUND_SECRETS_ENABLED_ENV)
                .ok()
                .as_deref(),
            configured.as_deref(),
        )?;
        let reserved = deployment_reserved_hosts(
            std::env::var("FRONTEND_URL").ok().as_deref(),
            std::env::var("PREVIEW_BASE_DOMAIN").ok().as_deref(),
            configured.as_deref(),
        )?;
        #[cfg(feature = "kind-e2e")]
        if std::env::var("CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER").as_deref() == Ok("true") {
            tracing::warn!("using the Kind-only tenant-secret KEK test provider");
            return Ok(Self {
                store: super::postgres_secrets::PostgresSecretStore::new(
                    pool,
                    std::sync::Arc::new(TestKekProvider),
                ),
                reserved,
                bound_secrets,
            });
        }
        let mode = SecretKekProviderMode::from_lookup(|name| std::env::var(name).ok())?;
        let store = match mode {
            SecretKekProviderMode::OpenBaoTransit => {
                tracing::info!("using OpenBao-wrapped encrypted PostgreSQL tenant-secret store");
                let kube = kube.ok_or_else(|| {
                    anyhow::anyhow!(
                        "OpenBao tenant-secret storage requires a Kubernetes client \
                         (set {SECRET_KEK_PROVIDER_ENV}=local-keyring and {SECRET_KEK_DIR_ENV} \
                         for self-hosted Compose deployments; see docs/CONFIGURATION.md)"
                    )
                })?;
                super::postgres_secrets::PostgresSecretStore::from_env(pool, kube)?
            }
            SecretKekProviderMode::LocalKeyring { dir, active_id } => {
                tracing::info!(
                    active_id = %active_id,
                    "using local-keyring-wrapped encrypted PostgreSQL tenant-secret store"
                );
                super::postgres_secrets::PostgresSecretStore::from_local_keyring(
                    pool, &dir, &active_id,
                )?
            }
        };
        Ok(Self {
            store,
            reserved,
            bound_secrets,
        })
    }

    /// Mirrors `GetSecretsRawAtPath`.
    pub async fn get_secrets_raw_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecret>> {
        self.store.get_secrets_raw_at_path(secret_path).await
    }

    /// Lists keys and timestamps without unwrapping the scope DEK or reading
    /// encrypted values.
    pub async fn get_secret_metadata_at_path(
        &self,
        secret_path: &str,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        self.store.get_secret_metadata_at_path(secret_path).await
    }

    /// Lists at most `maximum_rows` keys and timestamps without unwrapping a
    /// DEK. Preview callers request one extra row to detect an oversized
    /// source without materializing the full scope.
    pub async fn get_secret_metadata_at_path_bounded(
        &self,
        secret_path: &str,
        maximum_rows: usize,
    ) -> anyhow::Result<Vec<StoredSecretMetadata>> {
        self.store
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
        self.store.set_secret_at_path(secret_path, key, value).await
    }

    /// Set `key` with `value` and apply `binding` (#4003), refusing a host
    /// the deployment serves itself. No value is accepted only for a change
    /// to a bound secret that needs none.
    pub async fn write_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
        value: Option<&str>,
        binding: BindingWrite,
    ) -> Result<(), SecretWriteError> {
        if !self.bound_secrets && matches!(binding, BindingWrite::Bind(_)) {
            return Err(SecretWriteError::Unavailable);
        }
        self.store
            .write_secret_at_path(secret_path, key, value, binding, &self.reserved)
            .await
    }

    /// Mirrors `DeleteSecretAtPath`: whether the secret was there to delete.
    pub async fn delete_secret_at_path(
        &self,
        secret_path: &str,
        key: &str,
    ) -> anyhow::Result<bool> {
        self.store.delete_secret_at_path(secret_path, key).await
    }

    /// Mirrors `RenameSecretAtPath`. Errors carry "not found" / "already
    /// exists" so handlers can map them to 404 / 409, and a bound secret is
    /// refused with [`BoundSecretRename`].
    pub async fn rename_secret_at_path(
        &self,
        secret_path: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        self.store
            .rename_secret_at_path(secret_path, old_key, new_key)
            .await
    }

    /// Enumerate immediate child-folder names without reading their values.
    pub async fn list_folders_at_path(&self, parent_path: &str) -> anyhow::Result<Vec<String>> {
        self.store.list_folders_at_path(parent_path).await
    }

    /// Idempotently remove every secret at one exact path. Folders are derived
    /// from persisted paths, so a second enumeration is the success boundary.
    pub async fn delete_path(&self, secret_path: &str) -> anyhow::Result<()> {
        let (parent_path, folder_name) = split_folder_path(secret_path)?;
        self.store.delete_path(secret_path).await?;

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

/// Whether host-bound secrets are on: only `true` or `false`, off when unset.
/// On, the deployment must name its own hosts beyond the front end and
/// previews, or the identity issuer, the registries, OpenBao and the forge
/// would be bindable, so startup is refused without that setting.
fn host_bound_secrets_enabled(
    switch: Option<&str>,
    reserved_names: Option<&str>,
) -> anyhow::Result<bool> {
    let enabled = match switch.map(str::trim) {
        None | Some("") | Some("false") => false,
        Some("true") => true,
        Some(_) => anyhow::bail!("{HOST_BOUND_SECRETS_ENABLED_ENV} must be true or false"),
    };
    if enabled && reserved_names.is_none_or(|names| names.trim().is_empty()) {
        anyhow::bail!(
            "{HOST_BOUND_SECRETS_ENABLED_ENV} is true but {BOUND_HOST_RESERVED_NAMES_ENV} is unset; \
             name the deployment's own hosts first (docs/CONFIGURATION.md, \"Host-bound secrets\")"
        );
    }
    Ok(enabled)
}

/// The names no secret may be bound to beyond the provider hosts: the host of
/// `FRONTEND_URL`, every name under `PREVIEW_BASE_DOMAIN`, and each entry of
/// [`BOUND_HOST_RESERVED_NAMES_ENV`]. A derived value that names no DNS host,
/// such as a loopback address or an unset preview domain, adds nothing, as for
/// sandbox identity audiences: an address is never a bound host anyway. An
/// entry of the setting that isn't a name or `*.suffix` refuses startup.
fn deployment_reserved_hosts(
    frontend_url: Option<&str>,
    preview_base_domain: Option<&str>,
    configured: Option<&str>,
) -> anyhow::Result<ReservedHosts> {
    let frontend_host = frontend_url
        .and_then(|value| url::Url::parse(value).ok())
        .and_then(|url| match url.host() {
            Some(url::Host::Domain(host)) => Some(host.to_owned()),
            _ => None,
        });
    let preview_suffix = preview_base_domain
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("*.{domain}"));
    let derived = frontend_host
        .into_iter()
        .chain(preview_suffix)
        .filter(|name| ReservedHosts::new([name.as_str()]).is_ok());
    let configured: Vec<&str> = match configured.map(str::trim) {
        None | Some("") => Vec::new(),
        Some(value) => value.split(',').map(str::trim).collect(),
    };
    let names: Vec<String> = derived
        .chain(configured.into_iter().map(str::to_owned))
        .collect();
    ReservedHosts::new(names.iter().map(String::as_str)).map_err(|error| {
        anyhow::anyhow!(
            "{BOUND_HOST_RESERVED_NAMES_ENV}: {error}; each entry is a host name or *.suffix \
             (docs/CONFIGURATION.md, \"Host-bound secrets\")"
        )
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum SecretKekProviderMode {
    OpenBaoTransit,
    LocalKeyring { dir: PathBuf, active_id: String },
}

impl SecretKekProviderMode {
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let provider = lookup(SECRET_KEK_PROVIDER_ENV);
        let dir = lookup(SECRET_KEK_DIR_ENV);
        let active_id = lookup(SECRET_KEK_ACTIVE_ID_ENV);

        let selected = match provider.as_deref().map(str::trim) {
            None | Some("") | Some("openbao-transit") => None,
            Some("local-keyring") => Some("local-keyring"),
            Some(other) => {
                anyhow::bail!(
                    "{SECRET_KEK_PROVIDER_ENV}={other:?} is not supported; \
                     use `openbao-transit` or `local-keyring` (see docs/CONFIGURATION.md)"
                );
            }
        };

        if selected.is_none() {
            if dir.as_deref().is_some_and(|v| !v.trim().is_empty())
                || active_id.as_deref().is_some_and(|v| !v.trim().is_empty())
            {
                anyhow::bail!(
                    "{SECRET_KEK_DIR_ENV} and {SECRET_KEK_ACTIVE_ID_ENV} require \
                     {SECRET_KEK_PROVIDER_ENV}=local-keyring; local-keyring is never a fallback"
                );
            }
            return Ok(Self::OpenBaoTransit);
        }

        let dir = dir
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{SECRET_KEK_DIR_ENV} is required when {SECRET_KEK_PROVIDER_ENV}=local-keyring"
                )
            })?;
        let active_id = match active_id {
            None => DEFAULT_LOCAL_KEK_ACTIVE_ID.to_owned(),
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "{SECRET_KEK_ACTIVE_ID_ENV} must be a canonical vN identifier (such as v1) when set"
                    );
                }
                trimmed.to_owned()
            }
        };
        Ok(Self::LocalKeyring {
            dir: PathBuf::from(dir),
            active_id,
        })
    }
}

/// The product-facing secret-key contract. Keeping this deliberately narrower
/// than a general URL segment keeps the storage path sink unambiguous and
/// matches the dashboard's environment-variable-style key input.
pub fn is_valid_secret_key(key: &str) -> bool {
    validate_workload_secret_key(key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_bound_secrets_are_off_unless_switched_on_with_reserved_names() {
        assert!(!host_bound_secrets_enabled(None, None).unwrap());
        assert!(!host_bound_secrets_enabled(Some("false"), None).unwrap());
        assert!(host_bound_secrets_enabled(Some("true"), Some("openbao.example.dev")).unwrap());
        for switch in ["yes", "1", "TRUE"] {
            assert!(host_bound_secrets_enabled(Some(switch), Some("a.example.dev")).is_err());
        }
        for names in [None, Some(""), Some("  ")] {
            let error = host_bound_secrets_enabled(Some("true"), names).unwrap_err();
            assert!(error.to_string().contains(BOUND_HOST_RESERVED_NAMES_ENV));
        }
    }

    fn lookup_from(
        vars: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn stored_secret_parses_api_field_names() {
        let s: StoredSecret =
            serde_json::from_str(r#"{"secretKey":"K","secretValue":"V","createdAt":"x"}"#).unwrap();
        assert_eq!(s.key, "K");
        assert_eq!(s.value, "V");
    }

    fn refusal(reserved: &ReservedHosts, host: &str) -> Option<codewire_access::BindingError> {
        codewire_access::BoundHost::parse(host, reserved).err()
    }

    #[test]
    fn the_deployment_reserves_its_front_end_previews_and_configured_names() {
        let reserved = deployment_reserved_hosts(
            Some("https://App.Example.dev"),
            Some("preview.example.dev"),
            Some(" openbao.sandbox.example.dev , *.registry.example.dev "),
        )
        .unwrap();
        for host in [
            "app.example.dev",
            "preview.example.dev",
            "web.preview.example.dev",
            "openbao.sandbox.example.dev",
            "registry.example.dev",
            "harbor.registry.example.dev",
        ] {
            assert_eq!(
                refusal(&reserved, host),
                Some(codewire_access::BindingError::DeploymentHost(host.into())),
                "{host}"
            );
        }
        for host in ["api.example.dev", "xpreview.example.dev"] {
            assert_eq!(refusal(&reserved, host), None, "{host}");
        }
    }

    #[test]
    fn derived_names_that_are_not_hosts_reserve_nothing() {
        for (frontend, preview) in [
            (None, None),
            (Some("http://127.0.0.1:5173"), Some("")),
            (Some("http://[::1]:8080"), Some("  ")),
            (Some("not a url"), Some("preview.example.dev:8443")),
        ] {
            assert_eq!(
                deployment_reserved_hosts(frontend, preview, None).unwrap(),
                ReservedHosts::default(),
                "{frontend:?} {preview:?}"
            );
        }
        assert_eq!(
            deployment_reserved_hosts(None, None, Some(" ")).unwrap(),
            ReservedHosts::default()
        );
    }

    #[test]
    fn a_configured_entry_that_is_no_name_refuses_startup() {
        for configured in [
            "openbao.example.dev,",
            "*.",
            "https://openbao.example.dev",
            "openbao.example.dev:443",
            "**.example.dev",
            "api.example.dev.",
        ] {
            let error = deployment_reserved_hosts(None, None, Some(configured)).unwrap_err();
            assert!(
                error.to_string().contains(BOUND_HOST_RESERVED_NAMES_ENV),
                "{configured}: {error}"
            );
        }
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

    #[test]
    fn secret_kek_provider_selection_is_explicit_and_never_falls_back() {
        assert_eq!(
            SecretKekProviderMode::from_lookup(lookup_from(&[])).unwrap(),
            SecretKekProviderMode::OpenBaoTransit
        );
        assert_eq!(
            SecretKekProviderMode::from_lookup(lookup_from(&[(
                SECRET_KEK_PROVIDER_ENV,
                "openbao-transit"
            )]))
            .unwrap(),
            SecretKekProviderMode::OpenBaoTransit
        );
        // Local keyring directory without explicit provider must never fall back.
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[(
                SECRET_KEK_DIR_ENV,
                "/etc/codewire/kek"
            )]))
            .is_err()
        );
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[
                (SECRET_KEK_PROVIDER_ENV, "openbao-transit"),
                (SECRET_KEK_DIR_ENV, "/etc/codewire/kek"),
            ]))
            .is_err()
        );
        // Unknown provider fails closed.
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[(
                SECRET_KEK_PROVIDER_ENV,
                "plaintext"
            )]))
            .is_err()
        );
        // Explicit local-keyring requires a non-empty directory.
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[(
                SECRET_KEK_PROVIDER_ENV,
                "local-keyring"
            )]))
            .is_err()
        );
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[
                (SECRET_KEK_PROVIDER_ENV, "local-keyring"),
                (SECRET_KEK_DIR_ENV, "   "),
            ]))
            .is_err()
        );
        assert!(
            SecretKekProviderMode::from_lookup(lookup_from(&[
                (SECRET_KEK_PROVIDER_ENV, "local-keyring"),
                (SECRET_KEK_DIR_ENV, "/run/secrets/kek"),
                (SECRET_KEK_ACTIVE_ID_ENV, " "),
            ]))
            .is_err()
        );
        // Explicit local-keyring defaults active_id to v1 and accepts explicit vN.
        assert_eq!(
            SecretKekProviderMode::from_lookup(lookup_from(&[
                (SECRET_KEK_PROVIDER_ENV, "local-keyring"),
                (SECRET_KEK_DIR_ENV, "/run/secrets/kek"),
            ]))
            .unwrap(),
            SecretKekProviderMode::LocalKeyring {
                dir: PathBuf::from("/run/secrets/kek"),
                active_id: "v1".into(),
            }
        );
        assert_eq!(
            SecretKekProviderMode::from_lookup(lookup_from(&[
                (SECRET_KEK_PROVIDER_ENV, "local-keyring"),
                (SECRET_KEK_DIR_ENV, "/run/secrets/kek"),
                (SECRET_KEK_ACTIVE_ID_ENV, "v2"),
            ]))
            .unwrap(),
            SecretKekProviderMode::LocalKeyring {
                dir: PathBuf::from("/run/secrets/kek"),
                active_id: "v2".into(),
            }
        );
    }
}
