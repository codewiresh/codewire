use std::fmt;
use std::net::SocketAddr;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
pub const MESH_URL_ENV: &str = "CODEWIRE_MESH_URL";
pub const LISTEN_ADDR_ENV: &str = "CODEWIRE_MESH_LISTEN_ADDR";
pub const DERP_URL_ENV: &str = "CODEWIRE_MESH_DERP_URL";
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";
pub const MESH_AUTHORIZATION_URL_ENV: &str = "CODEWIRE_MESH_AUTHORIZATION_URL";
pub const MESH_AUTHORIZATION_HMAC_SECRET_ENV: &str = "CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET";
pub const LOCAL_ORGANIZATION_ID_ENV: &str = "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID";
pub const LOCAL_API_KEY_HASH_ENV: &str = "CODEWIRE_MESH_LOCAL_API_KEY_HASH";
pub const LOCAL_ENVIRONMENT_ID_ENV: &str = "CODEWIRE_MESH_LOCAL_ENVIRONMENT_ID";
pub const LOCAL_ENVIRONMENT_TOKEN_HASH_ENV: &str = "CODEWIRE_MESH_LOCAL_ENVIRONMENT_TOKEN_HASH";

/// Configuration for the one cluster-local Mesh-to-primary authorization hop.
///
/// The HMAC secret is the existing shared service credential. It is never a
/// product credential and its debug representation is deliberately redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshAuthorizationConfig {
    pub url: String,
    hmac_secret: String,
}

impl MeshAuthorizationConfig {
    pub(crate) fn hmac_secret(&self) -> &str {
        &self.hmac_secret
    }
}

impl fmt::Debug for MeshAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshAuthorizationConfig")
            .field("url", &self.url)
            .field("hmac_secret", &"[redacted]")
            .finish()
    }
}

/// Hash-only standalone Mesh authorization record supplied by the local
/// launcher. The local credential values themselves remain in the hardened
/// local CLI configuration; the Mesh process receives only verification data.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMeshAuthorizationConfig {
    pub organization_id: String,
    pub api_key_hash: String,
    pub environment_id: String,
    pub environment_token_hash: String,
}

impl fmt::Debug for LocalMeshAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMeshAuthorizationConfig")
            .field("organization_id", &self.organization_id)
            .field("api_key_hash", &"[redacted]")
            .field("environment_id", &self.environment_id)
            .field("environment_token_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub base_url: String,
    pub derp_url: Option<String>,
    pub database_url: Option<String>,
    /// Present for the hosted deployment. It is mandatory whenever Mesh owns
    /// a PostgreSQL database, so a hosted request can never fall back to
    /// legacy Mesh-local credentials.
    pub mesh_authorization: Option<MeshAuthorizationConfig>,
    /// Present for the explicit standalone-local identity. Hosted and local
    /// authorization configurations are mutually exclusive.
    pub local_authorization: Option<LocalMeshAuthorizationConfig>,
}

impl Config {
    pub fn from_env_and_args() -> Result<Self, ConfigError> {
        Self::from_sources(std::env::args().skip(1), |key| std::env::var(key).ok())
    }

    pub fn from_sources<I, S, F>(args: I, getenv: F) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: Fn(&str) -> Option<String>,
    {
        let args = Args::parse(args)?;
        let base_url = first_non_empty([args.base_url, getenv(MESH_URL_ENV)])
            .ok_or(ConfigError::MissingBaseUrl)?;
        validate_base_url(&base_url)?;

        let bind_addr = match first_non_empty([args.listen, getenv(LISTEN_ADDR_ENV)]) {
            Some(raw) => parse_listen_addr("listen", &raw)?,
            None => match trim(getenv("PORT")) {
                Some(port) => parse_port(&port)?,
                None => parse_listen_addr("listen", DEFAULT_LISTEN_ADDR)?,
            },
        };

        let derp_url = first_non_empty([args.derp_url, getenv(DERP_URL_ENV)]);
        if let Some(url) = derp_url.as_deref() {
            validate_base_url(url)?;
        }
        let database_url = first_non_empty([args.database_url, getenv(DATABASE_URL_ENV), None]);
        let mesh_authorization = mesh_authorization_config(
            getenv(MESH_AUTHORIZATION_URL_ENV),
            getenv(MESH_AUTHORIZATION_HMAC_SECRET_ENV),
        )?;
        let local_authorization = local_authorization_config(
            getenv(LOCAL_ORGANIZATION_ID_ENV),
            getenv(LOCAL_API_KEY_HASH_ENV),
            getenv(LOCAL_ENVIRONMENT_ID_ENV),
            getenv(LOCAL_ENVIRONMENT_TOKEN_HASH_ENV),
        )?;
        if database_url.is_some() && mesh_authorization.is_none() {
            return Err(ConfigError::HostedMeshAuthorizationRequired);
        }
        if mesh_authorization.is_some() && local_authorization.is_some() {
            return Err(ConfigError::AmbiguousMeshAuthorization);
        }

        Ok(Self {
            bind_addr,
            base_url,
            derp_url,
            database_url,
            mesh_authorization,
            local_authorization,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("required --base-url or {MESH_URL_ENV} is not set")]
    MissingBaseUrl,
    #[error("unknown flag {0}")]
    UnknownFlag(String),
    #[error("missing value for {0}")]
    MissingFlagValue(&'static str),
    #[error("invalid base URL {value:?}: {message}")]
    InvalidBaseUrl { value: String, message: String },
    #[error("invalid listen address {value:?}: {message}")]
    InvalidListenAddr { value: String, message: String },
    #[error("invalid PORT {value:?}: {message}")]
    InvalidPort { value: String, message: String },
    #[error(
        "{MESH_AUTHORIZATION_URL_ENV} and {MESH_AUTHORIZATION_HMAC_SECRET_ENV} must be set together"
    )]
    IncompleteMeshAuthorization,
    #[error(
        "{LOCAL_ORGANIZATION_ID_ENV}, {LOCAL_API_KEY_HASH_ENV}, {LOCAL_ENVIRONMENT_ID_ENV}, and {LOCAL_ENVIRONMENT_TOKEN_HASH_ENV} must be set together"
    )]
    IncompleteLocalMeshAuthorization,
    #[error(
        "hosted Mesh requires {MESH_AUTHORIZATION_URL_ENV} and {MESH_AUTHORIZATION_HMAC_SECRET_ENV}"
    )]
    HostedMeshAuthorizationRequired,
    #[error("hosted and standalone Mesh authorization configuration are mutually exclusive")]
    AmbiguousMeshAuthorization,
}

#[derive(Default)]
struct Args {
    base_url: Option<String>,
    listen: Option<String>,
    derp_url: Option<String>,
    database_url: Option<String>,
}

impl Args {
    fn parse<I, S>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Self::default();
        let mut iter = args.into_iter().map(|arg| arg.as_ref().to_string());
        while let Some(arg) = iter.next() {
            match flag_value(&arg, "--base-url", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.base_url = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--listen", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.listen = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--derp-url", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.derp_url = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--database-url", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.database_url = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            return Err(ConfigError::UnknownFlag(arg));
        }
        Ok(parsed)
    }
}

enum FlagValue {
    Matched(String),
    NotMatched,
}

fn flag_value<I>(arg: &str, name: &'static str, iter: &mut I) -> Result<FlagValue, ConfigError>
where
    I: Iterator<Item = String>,
{
    if arg == name {
        return iter
            .next()
            .map(FlagValue::Matched)
            .ok_or(ConfigError::MissingFlagValue(name));
    }
    if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
        return Ok(FlagValue::Matched(value.to_string()));
    }
    Ok(FlagValue::NotMatched)
}

fn first_non_empty<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values.into_iter().find_map(trim)
}

fn trim(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn mesh_authorization_config(
    url: Option<String>,
    hmac_secret: Option<String>,
) -> Result<Option<MeshAuthorizationConfig>, ConfigError> {
    match (trim(url), trim(hmac_secret)) {
        (None, None) => Ok(None),
        (Some(url), Some(hmac_secret)) => {
            validate_base_url(&url)?;
            Ok(Some(MeshAuthorizationConfig { url, hmac_secret }))
        }
        _ => Err(ConfigError::IncompleteMeshAuthorization),
    }
}

fn local_authorization_config(
    organization_id: Option<String>,
    api_key_hash: Option<String>,
    environment_id: Option<String>,
    environment_token_hash: Option<String>,
) -> Result<Option<LocalMeshAuthorizationConfig>, ConfigError> {
    match (
        trim(organization_id),
        trim(api_key_hash),
        trim(environment_id),
        trim(environment_token_hash),
    ) {
        (None, None, None, None) => Ok(None),
        (
            Some(organization_id),
            Some(api_key_hash),
            Some(environment_id),
            Some(environment_token_hash),
        ) => Ok(Some(LocalMeshAuthorizationConfig {
            organization_id,
            api_key_hash,
            environment_id,
            environment_token_hash,
        })),
        _ => Err(ConfigError::IncompleteLocalMeshAuthorization),
    }
}

fn validate_base_url(value: &str) -> Result<(), ConfigError> {
    url::Url::parse(value)
        .map(|_| ())
        .map_err(|source| ConfigError::InvalidBaseUrl {
            value: value.to_string(),
            message: source.to_string(),
        })
}

fn parse_listen_addr(name: &str, value: &str) -> Result<SocketAddr, ConfigError> {
    let normalized = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_string()
    };
    normalized
        .parse::<SocketAddr>()
        .map_err(|source| ConfigError::InvalidListenAddr {
            value: format!("{name}={value}"),
            message: source.to_string(),
        })
}

fn parse_port(value: &str) -> Result<SocketAddr, ConfigError> {
    let port = value
        .parse::<u16>()
        .map_err(|source| ConfigError::InvalidPort {
            value: value.to_string(),
            message: source.to_string(),
        })?;
    Ok(([0, 0, 0, 0], port).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        move |key| vars.get(key).cloned()
    }

    #[test]
    fn reads_mesh_url() {
        let cfg = Config::from_sources(
            Vec::<String>::new(),
            env(&[(MESH_URL_ENV, "https://mesh.codewire.sh")]),
        )
        .unwrap();
        assert_eq!(cfg.base_url, "https://mesh.codewire.sh");
    }

    #[test]
    fn retained_cli_flags_win_over_mesh_env() {
        let cfg = Config::from_sources(
            [
                "--base-url=https://flag.example",
                "--listen",
                ":18080",
                "--derp-url",
                "https://derp.flag",
                "--database-url",
                "postgres://flag/db",
            ],
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (LISTEN_ADDR_ENV, "127.0.0.1:1"),
                (DERP_URL_ENV, "https://derp.env"),
                (DATABASE_URL_ENV, "postgres://env/db"),
                (
                    MESH_AUTHORIZATION_URL_ENV,
                    "http://orchestration.internal:8085",
                ),
                (MESH_AUTHORIZATION_HMAC_SECRET_ENV, "test-hmac"),
            ]),
        )
        .unwrap();

        assert_eq!(cfg.base_url, "https://flag.example");
        assert_eq!(cfg.bind_addr, "0.0.0.0:18080".parse().unwrap());
        assert_eq!(cfg.derp_url.as_deref(), Some("https://derp.flag"));
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://flag/db"));
        assert_eq!(
            cfg.mesh_authorization
                .as_ref()
                .map(|config| config.url.as_str()),
            Some("http://orchestration.internal:8085")
        );
    }

    #[test]
    fn reads_mesh_derp_url_env() {
        let cfg = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (DERP_URL_ENV, "https://derp.codewire.sh"),
            ]),
        )
        .unwrap();

        assert_eq!(cfg.derp_url.as_deref(), Some("https://derp.codewire.sh"));
    }

    #[test]
    fn rejects_invalid_derp_url() {
        let err = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (DERP_URL_ENV, "not a url"),
            ]),
        )
        .unwrap_err();

        assert_eq!(
            err,
            ConfigError::InvalidBaseUrl {
                value: "not a url".to_string(),
                message: "relative URL without a base".to_string(),
            }
        );
    }

    #[test]
    fn port_env_derives_go_style_bind_addr() {
        let cfg = Config::from_sources(
            Vec::<String>::new(),
            env(&[(MESH_URL_ENV, "https://mesh.codewire.sh"), ("PORT", "9090")]),
        )
        .unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:9090".parse().unwrap());
    }
}
