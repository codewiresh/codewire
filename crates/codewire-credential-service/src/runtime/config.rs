//! Explicit isolated-service inputs, never shared service defaults.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use codewire_credential_broker::GitHubAppAuthorizationConfig;
use codewire_credential_broker::platform::keepalive::{
    OAuthKeepAliveConfig, OAuthKeepAliveConfigError,
};
use codewire_protected_store::secret_envelope::OpenBaoTransitConfig;
use codewire_tls::ServerTlsFiles;
use url::Url;
use zeroize::Zeroizing;

use super::RuntimeError;

// SQLx 0.8 consults libpq environment defaults even for a complete URI. Reject
// these inputs before constructing its options; never allow pgpass/client-key
// discovery, a host override, or ambient SQL options in this isolated process.
const LIBPQ_ENVIRONMENT: &[&str] = &[
    "PGPORT",
    "PGHOSTADDR",
    "PGHOST",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGAPPNAME",
    "PGOPTIONS",
    "PGSERVICE",
    "PGSERVICEFILE",
];

// Existing OpenBao and Kubernetes primitives stay unchanged. This isolated
// Linux process has no ambient proxy route for its Pod identity or envelope.
const PROXY_ENVIRONMENT: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Configuration has no Debug/serialization implementation: the explicit
/// restricted PostgreSQL URI is secret and is never a diagnostic source.
pub struct CredentialServiceConfig {
    pub(super) database_url: Zeroizing<String>,
    pub(super) public_listen: SocketAddr,
    pub(super) public_origin: http::HeaderValue,
    pub(super) private_listen: SocketAddr,
    pub(super) private_tls: ServerTlsFiles,
    pub(super) codex_executable: PathBuf,
    pub(super) github_executable: PathBuf,
    pub(super) github_app_authorization: Option<GitHubAppAuthorizationConfig>,
    pub(super) runtime_directory: PathBuf,
    pub(super) keks: KekAuthorityConfig,
    /// `None` when explicitly disabled.
    pub(super) oauth_keepalive: Option<OAuthKeepAliveConfig>,
}

/// Where the credential-service's key-encryption keys come from.
pub(super) enum KekAuthorityConfig {
    /// OpenBao Transit: the only authority in promotable builds.
    OpenBao {
        credential: Box<OpenBaoTransitConfig>,
        application: Box<OpenBaoTransitConfig>,
    },
    /// The in-memory test provider, compiled only into the non-promotable Kind
    /// image (as orchestration's tenant-secret test provider is). It does not
    /// really encrypt; it lets the production service run in a local cluster
    /// that has no OpenBao.
    #[cfg(feature = "kind-e2e")]
    KindTest,
}

impl CredentialServiceConfig {
    /// Read only explicit service inputs and check the presence of forbidden
    /// libpq overrides. No shared DATABASE_URL, DB_*, SESSION_SECRET, provider
    /// credential, kubeconfig, or user-home file is read.
    pub fn from_env() -> Result<Self, RuntimeError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, RuntimeError> {
        if LIBPQ_ENVIRONMENT.iter().any(|name| lookup(name).is_some()) {
            return Err(RuntimeError::Configuration("libpq environment overrides"));
        }
        if PROXY_ENVIRONMENT.iter().any(|name| lookup(name).is_some()) {
            return Err(RuntimeError::Configuration("ambient proxy overrides"));
        }
        let required = |name: &'static str| {
            lookup(name)
                .and_then(|value| value.into_string().ok())
                .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
                .ok_or(RuntimeError::Configuration(name))
        };
        let path = |name| {
            let value = PathBuf::from(required(name)?);
            if !value.is_absolute() {
                return Err(RuntimeError::Configuration(name));
            }
            Ok(value)
        };
        let database_url = Zeroizing::new(required("CREDENTIAL_DATABASE_URL")?);
        validate_database_url(&database_url)?;
        let public_listen = required("CREDENTIAL_HTTP_LISTEN_ADDR")?
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeError::Configuration("CREDENTIAL_HTTP_LISTEN_ADDR"))?;
        let private_listen = required("CREDENTIAL_BROKER_TLS_LISTEN_ADDR")?
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeError::Configuration("CREDENTIAL_BROKER_TLS_LISTEN_ADDR"))?;
        if public_listen.port() != 8086 || private_listen.port() != 9443 {
            return Err(RuntimeError::Configuration("credential listener ports"));
        }
        let public_origin = parse_public_origin(&required("CREDENTIAL_PUBLIC_ORIGIN")?)?;
        let github_app_authorization = github_app_authorization_config(&lookup, &public_origin)?;
        let private_tls = ServerTlsFiles::new(
            path("CREDENTIAL_BROKER_TLS_CERT_FILE")?,
            path("CREDENTIAL_BROKER_TLS_KEY_FILE")?,
        )
        .map_err(|_| RuntimeError::Configuration("credential broker TLS files"))?;
        let keks = match lookup("CODEWIRE_KIND_CREDENTIAL_TEST_KEK") {
            None => {
                let openbao_address: Url = required("CREDENTIAL_BAO_ADDR")?
                    .parse()
                    .map_err(|_| RuntimeError::Configuration("CREDENTIAL_BAO_ADDR"))?;
                let openbao_auth_mount = required("CREDENTIAL_BAO_AUTH_MOUNT")?;
                let openbao_expected_cluster_id = required("CREDENTIAL_BAO_EXPECTED_CLUSTER_ID")?;
                let credential_transit_mount = required("CREDENTIAL_BAO_TRANSIT_MOUNT")?;
                let application_transit_mount =
                    required("CREDENTIAL_APPLICATION_BAO_TRANSIT_MOUNT")?;
                if credential_transit_mount == application_transit_mount {
                    return Err(RuntimeError::Configuration(
                        "distinct credential and application OpenBao authorities",
                    ));
                }
                let credential_openbao = OpenBaoTransitConfig::new(
                    openbao_address.clone(),
                    openbao_auth_mount.clone(),
                    required("CREDENTIAL_BAO_ROLE")?,
                    credential_transit_mount,
                    // The existing derived tenant-dek primitive, in its dedicated
                    // credential Transit mount: not a new envelope or generic secret.
                    "tenant-dek".to_owned(),
                    openbao_expected_cluster_id.clone(),
                )
                .map_err(|_| RuntimeError::Configuration("credential OpenBao authority"))?;
                let application_openbao = OpenBaoTransitConfig::new(
                    openbao_address,
                    openbao_auth_mount,
                    required("CREDENTIAL_APPLICATION_BAO_ROLE")?,
                    application_transit_mount,
                    // Application projections use the existing tenant-secret envelope
                    // key in the independently authorized tenant Transit mount.
                    "tenant-dek".to_owned(),
                    openbao_expected_cluster_id,
                )
                .map_err(|_| RuntimeError::Configuration("application OpenBao authority"))?;
                KekAuthorityConfig::OpenBao {
                    credential: Box::new(credential_openbao),
                    application: Box::new(application_openbao),
                }
            }
            #[cfg(feature = "kind-e2e")]
            Some(value) if value == "true" => KekAuthorityConfig::KindTest,
            // Outside the Kind image the flag is never honoured, and any value
            // is a startup error rather than a silent OpenBao fallback.
            Some(_) => {
                return Err(RuntimeError::Configuration(
                    "CODEWIRE_KIND_CREDENTIAL_TEST_KEK",
                ));
            }
        };
        Ok(Self {
            database_url,
            public_listen,
            public_origin,
            private_listen,
            private_tls,
            codex_executable: path("CREDENTIAL_CODEX_EXECUTABLE")?,
            github_executable: path("CREDENTIAL_GITHUB_EXECUTABLE")?,
            github_app_authorization,
            runtime_directory: path("CREDENTIAL_RUNTIME_DIR")?,
            keks,
            oauth_keepalive: oauth_keepalive_config(&lookup)?,
        })
    }
}

const KEEPALIVE_ENABLED: &str = "CREDENTIAL_OAUTH_KEEPALIVE_ENABLED";
const KEEPALIVE_INTERVAL: &str = "CREDENTIAL_OAUTH_KEEPALIVE_INTERVAL_SECONDS";
const KEEPALIVE_CODEX_AGE: &str = "CREDENTIAL_OAUTH_KEEPALIVE_CODEX_AGE_SECONDS";
const KEEPALIVE_GITHUB_AGE: &str = "CREDENTIAL_OAUTH_KEEPALIVE_GITHUB_AGE_SECONDS";

/// Optional OAuth keep-alive inputs. It is enabled with the broker defaults
/// unless `CREDENTIAL_OAUTH_KEEPALIVE_ENABLED=false`. A present value must be
/// exact and in range, even when disabled: a typo stops startup instead of
/// silently running with defaults.
pub(super) fn oauth_keepalive_config(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<OAuthKeepAliveConfig>, RuntimeError> {
    let enabled = match lookup(KEEPALIVE_ENABLED).map(OsString::into_string) {
        None => true,
        Some(Ok(value)) if value == "true" => true,
        Some(Ok(value)) if value == "false" => false,
        Some(_) => return Err(RuntimeError::Configuration(KEEPALIVE_ENABLED)),
    };
    let seconds = |name: &'static str, default: Duration| match lookup(name) {
        None => Ok(default),
        Some(value) => value
            .into_string()
            .ok()
            .filter(|value| {
                !value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit())
            })
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .ok_or(RuntimeError::Configuration(name)),
    };
    let defaults = OAuthKeepAliveConfig::default();
    let config = OAuthKeepAliveConfig {
        interval: seconds(KEEPALIVE_INTERVAL, defaults.interval)?,
        codex_age: seconds(KEEPALIVE_CODEX_AGE, defaults.codex_age)?,
        github_age: seconds(KEEPALIVE_GITHUB_AGE, defaults.github_age)?,
    }
    .validate()
    .map_err(|error| {
        RuntimeError::Configuration(match error {
            OAuthKeepAliveConfigError::Interval => KEEPALIVE_INTERVAL,
            OAuthKeepAliveConfigError::CodexAge => KEEPALIVE_CODEX_AGE,
            OAuthKeepAliveConfigError::GitHubAge => KEEPALIVE_GITHUB_AGE,
        })
    })?;
    Ok(enabled.then_some(config))
}

fn github_app_authorization_config(
    lookup: &impl Fn(&str) -> Option<OsString>,
    public_origin: &http::HeaderValue,
) -> Result<Option<GitHubAppAuthorizationConfig>, RuntimeError> {
    let value = |name: &'static str| {
        lookup(name)
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
    };
    let (client_id, client_secret, app_slug) = (
        value("CREDENTIAL_GITHUB_APP_CLIENT_ID"),
        value("CREDENTIAL_GITHUB_APP_CLIENT_SECRET"),
        value("CREDENTIAL_GITHUB_APP_SLUG"),
    );
    let invalid = RuntimeError::Configuration("GitHub App authorization configuration");
    match (client_id, client_secret, app_slug) {
        (None, None, None) => Ok(None),
        (Some(client_id), Some(client_secret), Some(app_slug)) => {
            let callback = format!(
                "{}/api/v1/github/oauth/callback",
                public_origin.to_str().map_err(|_| invalid)?
            );
            GitHubAppAuthorizationConfig::new(
                client_id,
                Zeroizing::new(client_secret),
                app_slug,
                callback,
            )
            .map(Some)
            .map_err(|_| invalid)
        }
        _ => Err(invalid),
    }
}

fn parse_public_origin(input: &str) -> Result<http::HeaderValue, RuntimeError> {
    let invalid = RuntimeError::Configuration("CREDENTIAL_PUBLIC_ORIGIN");
    let url = Url::parse(input.trim_end_matches('/')).map_err(|_| invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid);
    }
    http::HeaderValue::from_str(url.as_str().trim_end_matches('/')).map_err(|_| invalid)
}

fn validate_database_url(input: &str) -> Result<(), RuntimeError> {
    let invalid = RuntimeError::Configuration("CREDENTIAL_DATABASE_URL");
    let url = Url::parse(input).map_err(|_| invalid)?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url
            .host_str()
            .is_none_or(|host| host.is_empty() || host.contains('%'))
        || url.port().is_none_or(|port| port == 0)
        || url.username().is_empty()
        || url.password().is_none_or(str::is_empty)
        || url
            .path()
            .strip_prefix('/')
            .is_none_or(|db| db.is_empty() || db.contains('/'))
        || url.fragment().is_some()
    {
        return Err(invalid);
    }
    let mut ssl_mode = None;
    let mut roots = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sslmode"
                if ssl_mode.is_none() && matches!(value.as_ref(), "require" | "verify-full") =>
            {
                ssl_mode = Some(value);
            }
            "sslrootcert" if roots.is_none() && PathBuf::from(value.as_ref()).is_absolute() => {
                roots = Some(value);
            }
            // No second host/user/password, socket, SQL option, client key,
            // unknown query logging, or silently ignored spelling.
            _ => return Err(invalid),
        }
    }
    if ssl_mode.is_none() || (ssl_mode.as_deref() == Some("verify-full") && roots.is_none()) {
        return Err(invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn inputs() -> BTreeMap<&'static str, OsString> {
        [
            (
                "CREDENTIAL_DATABASE_URL",
                "postgres://broker:synthetic-password@postgres.test:5432/codewire?sslmode=require",
            ),
            ("CREDENTIAL_HTTP_LISTEN_ADDR", "0.0.0.0:8086"),
            ("CREDENTIAL_PUBLIC_ORIGIN", "https://codewire.example"),
            ("CREDENTIAL_BROKER_TLS_LISTEN_ADDR", "0.0.0.0:9443"),
            ("CREDENTIAL_BROKER_TLS_CERT_FILE", "/mounted/broker/tls.crt"),
            ("CREDENTIAL_BROKER_TLS_KEY_FILE", "/mounted/broker/tls.key"),
            ("CREDENTIAL_CODEX_EXECUTABLE", "/usr/local/bin/codex"),
            ("CREDENTIAL_GITHUB_EXECUTABLE", "/usr/local/bin/gh"),
            ("CREDENTIAL_RUNTIME_DIR", "/run/codewire-credentials"),
            (
                "CREDENTIAL_BAO_ADDR",
                "http://bao.openbao.svc.cluster.local",
            ),
            ("CREDENTIAL_BAO_AUTH_MOUNT", "kubernetes"),
            ("CREDENTIAL_BAO_ROLE", "credential-service"),
            ("CREDENTIAL_BAO_TRANSIT_MOUNT", "credentials"),
            (
                "CREDENTIAL_APPLICATION_BAO_ROLE",
                "credential-service-application",
            ),
            (
                "CREDENTIAL_APPLICATION_BAO_TRANSIT_MOUNT",
                "codewire-tenant-test",
            ),
            ("CREDENTIAL_BAO_EXPECTED_CLUSTER_ID", "synthetic-cluster"),
        ]
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
    }

    #[test]
    fn explicit_complete_inputs_and_no_shared_credentials() {
        let mut values = inputs();
        values.insert("DATABASE_URL", "must-not-be-read".into());
        values.insert("SESSION_SECRET", "must-not-be-read".into());
        let config = CredentialServiceConfig::from_lookup(|name| {
            assert!(!matches!(
                name,
                "DATABASE_URL" | "SESSION_SECRET" | "HOME" | "KUBECONFIG"
            ));
            values.get(name).cloned()
        })
        .unwrap();
        assert_eq!(config.public_listen.port(), 8086);
        assert_eq!(
            config.public_origin.to_str().unwrap(),
            "https://codewire.example"
        );
        assert_eq!(config.private_listen.port(), 9443);
        for name in inputs().keys() {
            let mut partial = inputs();
            partial.remove(name);
            assert!(
                CredentialServiceConfig::from_lookup(|name| partial.get(name).cloned()).is_err()
            );
        }
    }

    #[cfg(not(feature = "kind-e2e"))]
    #[test]
    fn kind_test_kek_flag_is_rejected_outside_the_kind_build() {
        for value in ["true", "false", ""] {
            let mut values = inputs();
            values.insert("CODEWIRE_KIND_CREDENTIAL_TEST_KEK", value.into());
            assert!(
                CredentialServiceConfig::from_lookup(|name| values.get(name).cloned()).is_err()
            );
        }
    }

    #[cfg(feature = "kind-e2e")]
    #[test]
    fn kind_test_kek_replaces_only_the_openbao_inputs() {
        let mut values = inputs();
        values.retain(|name, _| !name.contains("_BAO_"));
        values.insert("CODEWIRE_KIND_CREDENTIAL_TEST_KEK", "true".into());
        let config =
            CredentialServiceConfig::from_lookup(|name| values.get(name).cloned()).unwrap();
        assert!(matches!(config.keks, KekAuthorityConfig::KindTest));
        for name in values.keys() {
            let mut partial = values.clone();
            partial.remove(name);
            if *name != "CODEWIRE_KIND_CREDENTIAL_TEST_KEK" {
                assert!(
                    CredentialServiceConfig::from_lookup(|name| partial.get(name).cloned())
                        .is_err(),
                    "{name}"
                );
            }
        }
        values.insert("CODEWIRE_KIND_CREDENTIAL_TEST_KEK", "yes".into());
        assert!(CredentialServiceConfig::from_lookup(|name| values.get(name).cloned()).is_err());
    }

    #[test]
    fn public_origin_is_exact_and_path_free() {
        assert_eq!(
            parse_public_origin("https://codewire.example/")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://codewire.example"
        );
        for value in [
            "http://user@example.test",
            "https://example.test/path",
            "https://example.test/?query=1",
            "file:///tmp/codewire",
        ] {
            assert!(parse_public_origin(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn credential_and_application_transit_mounts_must_be_distinct() {
        let mut values = inputs();
        let credential_mount = values["CREDENTIAL_BAO_TRANSIT_MOUNT"].clone();
        values.insert("CREDENTIAL_APPLICATION_BAO_TRANSIT_MOUNT", credential_mount);
        assert_eq!(
            CredentialServiceConfig::from_lookup(|name| values.get(name).cloned())
                .err()
                .unwrap(),
            RuntimeError::Configuration("distinct credential and application OpenBao authorities")
        );
    }

    #[test]
    fn github_app_authorization_is_optional_but_must_be_complete_and_exact() {
        let values = inputs();
        let public = parse_public_origin("https://codewire.example").unwrap();
        assert!(
            github_app_authorization_config(&|name| values.get(name).cloned(), &public)
                .unwrap()
                .is_none()
        );
        let mut complete = inputs();
        complete.insert("CREDENTIAL_GITHUB_APP_CLIENT_ID", "Iv1.synthetic".into());
        complete.insert(
            "CREDENTIAL_GITHUB_APP_CLIENT_SECRET",
            "synthetic-client-secret".into(),
        );
        complete.insert("CREDENTIAL_GITHUB_APP_SLUG", "codewire".into());
        assert!(
            github_app_authorization_config(&|name| complete.get(name).cloned(), &public)
                .unwrap()
                .is_some()
        );
        for name in [
            "CREDENTIAL_GITHUB_APP_CLIENT_ID",
            "CREDENTIAL_GITHUB_APP_CLIENT_SECRET",
            "CREDENTIAL_GITHUB_APP_SLUG",
        ] {
            let mut partial = complete.clone();
            partial.remove(name);
            assert!(matches!(
                github_app_authorization_config(&|key| partial.get(key).cloned(), &public),
                Err(RuntimeError::Configuration(
                    "GitHub App authorization configuration"
                ))
            ));
        }
    }

    #[test]
    fn oauth_keepalive_is_on_by_default_and_overrides_are_exact() {
        let config =
            CredentialServiceConfig::from_lookup(|name| inputs().get(name).cloned()).unwrap();
        assert_eq!(
            config.oauth_keepalive,
            Some(OAuthKeepAliveConfig::default())
        );

        let lookup = |pairs: &[(&'static str, &str)]| {
            let mut values = inputs();
            for (name, value) in pairs {
                values.insert(name, (*value).into());
            }
            move |name: &str| values.get(name).cloned()
        };
        assert_eq!(
            oauth_keepalive_config(&lookup(&[(KEEPALIVE_ENABLED, "false")])).unwrap(),
            None
        );
        assert_eq!(
            oauth_keepalive_config(&lookup(&[
                (KEEPALIVE_ENABLED, "true"),
                (KEEPALIVE_INTERVAL, "15"),
                (KEEPALIVE_CODEX_AGE, "60"),
                (KEEPALIVE_GITHUB_AGE, "120"),
            ]))
            .unwrap(),
            Some(OAuthKeepAliveConfig {
                interval: Duration::from_secs(15),
                codex_age: Duration::from_secs(60),
                github_age: Duration::from_secs(120),
            })
        );
        for (name, value) in [
            (KEEPALIVE_ENABLED, "yes"),
            (KEEPALIVE_ENABLED, ""),
            (KEEPALIVE_INTERVAL, ""),
            (KEEPALIVE_INTERVAL, "-1"),
            (KEEPALIVE_INTERVAL, "1e3"),
            (KEEPALIVE_INTERVAL, " 60"),
            (KEEPALIVE_INTERVAL, "5"),
            (KEEPALIVE_INTERVAL, "86401"),
            (KEEPALIVE_CODEX_AGE, "59"),
            // Never later than Codex CLI's own 8-day refresh habit.
            (KEEPALIVE_CODEX_AGE, "691201"),
            (KEEPALIVE_GITHUB_AGE, "7776001"),
            (KEEPALIVE_GITHUB_AGE, "99999999999"),
        ] {
            assert_eq!(
                CredentialServiceConfig::from_lookup(lookup(&[(name, value)]))
                    .err()
                    .unwrap(),
                RuntimeError::Configuration(name),
                "{name}={value:?}"
            );
        }
        // A bad value is rejected even when the keep-alive is disabled.
        assert!(
            oauth_keepalive_config(&lookup(&[
                (KEEPALIVE_ENABLED, "false"),
                (KEEPALIVE_CODEX_AGE, "0"),
            ]))
            .is_err()
        );
    }

    #[test]
    fn libpq_overrides_are_closed_before_uri_parsing() {
        for name in LIBPQ_ENVIRONMENT {
            let mut values = inputs();
            values.insert(name, "private-canary".into());
            let error = CredentialServiceConfig::from_lookup(|key| values.get(key).cloned())
                .err()
                .unwrap();
            assert_eq!(
                error,
                RuntimeError::Configuration("libpq environment overrides")
            );
            assert!(!format!("{error:?} {error}").contains("private-canary"));
        }
    }

    #[test]
    fn ambient_proxy_routes_are_rejected_before_dependency_construction() {
        for name in PROXY_ENVIRONMENT {
            for value in ["", "http://private-proxy-canary.example:8080"] {
                let mut values = inputs();
                values.insert(name, value.into());
                let error = CredentialServiceConfig::from_lookup(|key| values.get(key).cloned())
                    .err()
                    .unwrap();
                assert_eq!(
                    error,
                    RuntimeError::Configuration("ambient proxy overrides")
                );
                assert!(!format!("{error:?} {error}").contains("private-proxy-canary"));
            }
        }
    }

    #[test]
    fn database_input_is_complete_encrypted_and_has_no_override_paths() {
        let base = "postgres://broker:synthetic-password@postgres.test:5432/codewire";
        for suffix in [
            "",
            "?sslmode=prefer",
            "?sslmode=disable",
            "?sslmode=verify-full",
            "?sslmode=require&host=elsewhere",
            "?sslmode=require&sslkey=/private/key",
            "?sslmode=require&options=private-canary",
            "?sslmode=require&sslmode=require",
        ] {
            let error = validate_database_url(&format!("{base}{suffix}")).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("synthetic-password"));
        }
        for input in [
            "postgres://broker@postgres.test:5432/codewire?sslmode=require",
            "postgres://broker:password@postgres.test/codewire?sslmode=require",
            "postgres://broker:password@postgres.test:5432/?sslmode=require",
        ] {
            assert!(validate_database_url(input).is_err());
        }
        assert!(
            validate_database_url(&format!(
                "{base}?sslmode=verify-full&sslrootcert=/mounted/db/ca.crt"
            ))
            .is_ok()
        );
    }

    #[test]
    fn fixed_ports_and_absolute_administrator_paths() {
        for (name, value) in [
            ("CREDENTIAL_HTTP_LISTEN_ADDR", "0.0.0.0:9443"),
            ("CREDENTIAL_BROKER_TLS_LISTEN_ADDR", "0.0.0.0:8086"),
            ("CREDENTIAL_RUNTIME_DIR", "relative"),
            ("CREDENTIAL_CODEX_EXECUTABLE", "codex"),
            ("CREDENTIAL_GITHUB_EXECUTABLE", "gh"),
        ] {
            let mut values = inputs();
            values.insert(name, value.into());
            assert!(CredentialServiceConfig::from_lookup(|key| values.get(key).cloned()).is_err());
        }
    }
}
