//! Explicit isolated-service inputs, never shared service defaults.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    pub(super) private_listen: SocketAddr,
    pub(super) private_tls: ServerTlsFiles,
    pub(super) codex_executable: PathBuf,
    pub(super) runtime_directory: PathBuf,
    pub(super) openbao: OpenBaoTransitConfig,
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
        let private_tls = ServerTlsFiles::new(
            path("CREDENTIAL_BROKER_TLS_CERT_FILE")?,
            path("CREDENTIAL_BROKER_TLS_KEY_FILE")?,
        )
        .map_err(|_| RuntimeError::Configuration("credential broker TLS files"))?;
        let openbao = OpenBaoTransitConfig::new(
            required("CREDENTIAL_BAO_ADDR")?
                .parse()
                .map_err(|_| RuntimeError::Configuration("CREDENTIAL_BAO_ADDR"))?,
            required("CREDENTIAL_BAO_AUTH_MOUNT")?,
            required("CREDENTIAL_BAO_ROLE")?,
            required("CREDENTIAL_BAO_TRANSIT_MOUNT")?,
            // The existing derived tenant-dek primitive, in its dedicated
            // credential Transit mount: not a new envelope or generic secret.
            "tenant-dek".to_owned(),
            required("CREDENTIAL_BAO_EXPECTED_CLUSTER_ID")?,
        )
        .map_err(|_| RuntimeError::Configuration("credential OpenBao authority"))?;
        Ok(Self {
            database_url,
            public_listen,
            private_listen,
            private_tls,
            codex_executable: path("CREDENTIAL_CODEX_EXECUTABLE")?,
            runtime_directory: path("CREDENTIAL_RUNTIME_DIR")?,
            openbao,
        })
    }
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
            ("CREDENTIAL_BROKER_TLS_LISTEN_ADDR", "0.0.0.0:9443"),
            ("CREDENTIAL_BROKER_TLS_CERT_FILE", "/mounted/broker/tls.crt"),
            ("CREDENTIAL_BROKER_TLS_KEY_FILE", "/mounted/broker/tls.key"),
            ("CREDENTIAL_CODEX_EXECUTABLE", "/usr/local/bin/codex"),
            ("CREDENTIAL_RUNTIME_DIR", "/run/codewire-credentials"),
            (
                "CREDENTIAL_BAO_ADDR",
                "http://bao.openbao.svc.cluster.local",
            ),
            ("CREDENTIAL_BAO_AUTH_MOUNT", "kubernetes"),
            ("CREDENTIAL_BAO_ROLE", "credential-service"),
            ("CREDENTIAL_BAO_TRANSIT_MOUNT", "credentials"),
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
        assert_eq!(config.private_listen.port(), 9443);
        for name in inputs().keys() {
            let mut partial = inputs();
            partial.remove(name);
            assert!(
                CredentialServiceConfig::from_lookup(|name| partial.get(name).cloned()).is_err()
            );
        }
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
        ] {
            let mut values = inputs();
            values.insert(name, value.into());
            assert!(CredentialServiceConfig::from_lookup(|key| values.get(key).cloned()).is_err());
        }
    }
}
