use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use codewire_tls::ConnectOriginTransport;

use url::Host;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
pub const MESH_URL_ENV: &str = "CODEWIRE_MESH_URL";
pub const LISTEN_ADDR_ENV: &str = "CODEWIRE_MESH_LISTEN_ADDR";
pub const DERP_URL_ENV: &str = "CODEWIRE_MESH_DERP_URL";
/// The internal listener DERP asks whether a node key belongs to a
/// registered Mesh node (#2844). Unset serves no lookup.
pub const DERP_VERIFY_ADDR_ENV: &str = "CODEWIRE_MESH_DERP_VERIFY_ADDR";
pub const STUN_SERVERS_ENV: &str = "CODEWIRE_MESH_STUN_SERVERS";
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";
pub const MESH_AUTHORIZATION_URL_ENV: &str = "CODEWIRE_MESH_AUTHORIZATION_URL";
pub const MESH_AUTHORIZATION_HMAC_SECRET_ENV: &str = "CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET";
/// Public roots verifying the https authorization URL; required with it.
pub const MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV: &str =
    "CODEWIRE_MESH_AUTHORIZATION_TLS_ROOTS_FILE";
pub const LOCAL_ORGANIZATION_ID_ENV: &str = "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID";
pub const LOCAL_API_KEY_HASH_ENV: &str = "CODEWIRE_MESH_LOCAL_API_KEY_HASH";

const DEFAULT_STUN_PORT: u16 = 3478;
const MAX_STUN_SERVERS: usize = 8;
const MAX_STUN_HOST_BYTES: usize = 253;

/// Configuration for the one cluster-local Mesh-to-primary authorization hop.
///
/// The HMAC secret is the existing shared service credential. It is never a
/// product credential and its debug representation is deliberately redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshAuthorizationConfig {
    pub url: String,
    hmac_secret: String,
    tls_roots_file: PathBuf,
}

impl MeshAuthorizationConfig {
    #[cfg(test)]
    pub(crate) fn for_test(url: &str, hmac_secret: &str, tls_roots_file: &std::path::Path) -> Self {
        Self {
            url: url.to_owned(),
            hmac_secret: hmac_secret.to_owned(),
            tls_roots_file: tls_roots_file.to_path_buf(),
        }
    }

    pub(crate) fn hmac_secret(&self) -> &str {
        &self.hmac_secret
    }

    pub(crate) fn tls_roots_file(&self) -> &std::path::Path {
        &self.tls_roots_file
    }
}

impl fmt::Debug for MeshAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshAuthorizationConfig")
            .field("url", &self.url)
            .field("hmac_secret", &"[redacted]")
            .field("tls_roots_file", &self.tls_roots_file)
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
}

impl fmt::Debug for LocalMeshAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMeshAuthorizationConfig")
            .field("organization_id", &self.organization_id)
            .field("api_key_hash", &"[redacted]")
            .finish()
    }
}

/// One STUN-only node advertised beside the configured DERP relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub base_url: String,
    pub derp_url: Option<String>,
    pub stun_servers: Vec<StunServerConfig>,
    /// The DERP client admission lookup listener (#2844); no ingress routes
    /// to it.
    pub derp_verify_addr: Option<SocketAddr>,
    pub database_url: Option<String>,
    /// Present for the hosted deployment. It is mandatory whenever Mesh owns
    /// a PostgreSQL database, so a hosted request can never fall back to
    /// legacy Mesh-local credentials.
    pub mesh_authorization: Option<MeshAuthorizationConfig>,
    /// Present for the explicit standalone-local identity. Hosted and local
    /// authorization configurations are mutually exclusive.
    pub local_authorization: Option<LocalMeshAuthorizationConfig>,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("base_url", &self.base_url)
            .field("derp_url", &self.derp_url)
            .field("stun_servers", &self.stun_servers)
            .field("derp_verify_addr", &self.derp_verify_addr)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[redacted]"),
            )
            .field("mesh_authorization", &self.mesh_authorization)
            .field("local_authorization", &self.local_authorization)
            .finish()
    }
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
        let stun_servers = stun_server_config(args.stun_servers, getenv(STUN_SERVERS_ENV))?;
        let derp_verify_addr = trim(getenv(DERP_VERIFY_ADDR_ENV))
            .map(|raw| parse_listen_addr("DERP verify", &raw))
            .transpose()?;
        let database_url = trim(getenv(DATABASE_URL_ENV));
        let mesh_authorization = mesh_authorization_config(
            getenv(MESH_AUTHORIZATION_URL_ENV),
            getenv(MESH_AUTHORIZATION_HMAC_SECRET_ENV),
            getenv(MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV),
        )?;
        let local_authorization = local_authorization_config(
            getenv(LOCAL_ORGANIZATION_ID_ENV),
            getenv(LOCAL_API_KEY_HASH_ENV),
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
            stun_servers,
            derp_verify_addr,
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
    #[error("invalid STUN server {0:?}")]
    InvalidStunServer(String),
    #[error("at most {MAX_STUN_SERVERS} STUN servers may be configured")]
    TooManyStunServers,
    #[error(
        "{MESH_AUTHORIZATION_URL_ENV} and {MESH_AUTHORIZATION_HMAC_SECRET_ENV} must be set together"
    )]
    IncompleteMeshAuthorization,
    #[error(
        "{MESH_AUTHORIZATION_URL_ENV} must be an exact https origin, set together with {MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV}"
    )]
    InvalidMeshAuthorizationTls,
    #[error("{LOCAL_ORGANIZATION_ID_ENV} and {LOCAL_API_KEY_HASH_ENV} must be set together")]
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
    stun_servers: Vec<String>,
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
            match flag_value(&arg, "--stun-server", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.stun_servers.push(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            let flag = arg.split_once('=').map_or(arg.as_str(), |(name, _)| name);
            return Err(ConfigError::UnknownFlag(flag.to_owned()));
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
    tls_roots_file: Option<String>,
) -> Result<Option<MeshAuthorizationConfig>, ConfigError> {
    let tls_roots_file = trim(tls_roots_file).map(PathBuf::from);
    match (trim(url), trim(hmac_secret)) {
        (None, None) if tls_roots_file.is_some() => Err(ConfigError::InvalidMeshAuthorizationTls),
        (None, None) => Ok(None),
        (Some(url), Some(hmac_secret)) => {
            validate_base_url(&url)?;
            // Orchestration's internal listener is TLS-only.
            let tls_roots_file = tls_roots_file.ok_or(ConfigError::InvalidMeshAuthorizationTls)?;
            ConnectOriginTransport::for_origin(&url, &tls_roots_file)
                .map_err(|_| ConfigError::InvalidMeshAuthorizationTls)?;
            Ok(Some(MeshAuthorizationConfig {
                url,
                hmac_secret,
                tls_roots_file,
            }))
        }
        _ => Err(ConfigError::IncompleteMeshAuthorization),
    }
}

fn local_authorization_config(
    organization_id: Option<String>,
    api_key_hash: Option<String>,
) -> Result<Option<LocalMeshAuthorizationConfig>, ConfigError> {
    match (trim(organization_id), trim(api_key_hash)) {
        (None, None) => Ok(None),
        (Some(organization_id), Some(api_key_hash)) => Ok(Some(LocalMeshAuthorizationConfig {
            organization_id,
            api_key_hash,
        })),
        _ => Err(ConfigError::IncompleteLocalMeshAuthorization),
    }
}

fn stun_server_config(
    args: Vec<String>,
    environment: Option<String>,
) -> Result<Vec<StunServerConfig>, ConfigError> {
    let values = if args.is_empty() {
        trim(environment)
            .map(|value| value.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    } else {
        args
    };
    let mut servers = Vec::new();
    for value in values {
        let server = parse_stun_server(&value)?;
        if servers.iter().any(|existing: &StunServerConfig| {
            existing.host == server.host && existing.port == server.port
        }) {
            continue;
        }
        if servers.len() >= MAX_STUN_SERVERS {
            return Err(ConfigError::TooManyStunServers);
        }
        servers.push(server);
    }
    Ok(servers)
}

fn parse_stun_server(value: &str) -> Result<StunServerConfig, ConfigError> {
    let original = value.trim();
    let value = original
        .strip_prefix("stun://")
        .or_else(|| original.strip_prefix("stun:"))
        .unwrap_or(original)
        .trim();
    if value.is_empty() {
        return Err(ConfigError::InvalidStunServer(original.to_owned()));
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| ConfigError::InvalidStunServer(original.to_owned()))?;
        let port = match suffix.strip_prefix(':') {
            Some(port) => parse_stun_port(port, original)?,
            None if suffix.is_empty() => DEFAULT_STUN_PORT,
            _ => return Err(ConfigError::InvalidStunServer(original.to_owned())),
        };
        (host, port)
    } else if value.matches(':').count() > 1 {
        (value, DEFAULT_STUN_PORT)
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) => (host, parse_stun_port(port, original)?),
            None => (value, DEFAULT_STUN_PORT),
        }
    };
    Ok(StunServerConfig {
        host: canonical_stun_host(host, original)?,
        port,
    })
}

fn parse_stun_port(value: &str, original: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::InvalidStunServer(original.to_owned()))
}

fn canonical_stun_host(value: &str, original: &str) -> Result<String, ConfigError> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() || !value.is_ascii() || value.len() > MAX_STUN_HOST_BYTES {
        return Err(ConfigError::InvalidStunServer(original.to_owned()));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    match Host::parse(value).map_err(|_| ConfigError::InvalidStunServer(original.to_owned()))? {
        Host::Ipv4(_) | Host::Ipv6(_) => unreachable!("IP literals were parsed above"),
        Host::Domain(domain)
            if domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }) =>
        {
            Ok(domain.to_ascii_lowercase())
        }
        Host::Domain(_) => Err(ConfigError::InvalidStunServer(original.to_owned())),
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
    fn standalone_authorization_requires_exactly_the_org_and_api_key_hash() {
        let cfg = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (LOCAL_ORGANIZATION_ID_ENV, "local-org"),
                (LOCAL_API_KEY_HASH_ENV, "api-key-hash"),
            ]),
        )
        .unwrap();
        let local = cfg.local_authorization.unwrap();
        assert_eq!(local.organization_id, "local-org");
        assert_eq!(local.api_key_hash, "api-key-hash");
        assert!(!format!("{local:?}").contains("api-key-hash"));

        for incomplete in [
            &[(LOCAL_ORGANIZATION_ID_ENV, "local-org")][..],
            &[(LOCAL_API_KEY_HASH_ENV, "api-key-hash")][..],
        ] {
            assert_eq!(
                Config::from_sources(Vec::<String>::new(), move |key| {
                    (key == MESH_URL_ENV)
                        .then(|| "https://mesh.codewire.sh".to_owned())
                        .or_else(|| {
                            incomplete
                                .iter()
                                .find(|(name, _)| *name == key)
                                .map(|(_, value)| (*value).to_owned())
                        })
                },)
                .unwrap_err(),
                ConfigError::IncompleteLocalMeshAuthorization
            );
        }
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
                "--stun-server=stun://STUN.FLAG.:19302",
            ],
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (LISTEN_ADDR_ENV, "127.0.0.1:1"),
                (DERP_URL_ENV, "https://derp.env"),
                (STUN_SERVERS_ENV, "stun.env:3478"),
                (DATABASE_URL_ENV, "postgres://env/db"),
                (
                    MESH_AUTHORIZATION_URL_ENV,
                    "https://orchestration.internal:8088",
                ),
                (
                    MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV,
                    "/run/codewire-mesh-authorization-roots/ca.crt",
                ),
                (MESH_AUTHORIZATION_HMAC_SECRET_ENV, "test-hmac"),
            ]),
        )
        .unwrap();

        assert_eq!(cfg.base_url, "https://flag.example");
        assert_eq!(cfg.bind_addr, "0.0.0.0:18080".parse().unwrap());
        assert_eq!(cfg.derp_url.as_deref(), Some("https://derp.flag"));
        assert_eq!(
            cfg.stun_servers,
            vec![StunServerConfig {
                host: "stun.flag".to_owned(),
                port: 19_302,
            }]
        );
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://env/db"));
        assert_eq!(
            cfg.mesh_authorization
                .as_ref()
                .map(|config| config.url.as_str()),
            Some("https://orchestration.internal:8088")
        );
    }

    #[test]
    fn authorization_url_is_an_https_origin_set_with_its_roots() {
        let https = "https://codewire-orchestration.dev.svc.cluster.local:8088";
        let roots = "/run/codewire-mesh-authorization-roots/ca.crt";
        let hosted = |vars: &[(&str, &str)]| {
            let mut all = vec![
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (MESH_AUTHORIZATION_HMAC_SECRET_ENV, "test-hmac"),
            ];
            all.extend_from_slice(vars);
            Config::from_sources(Vec::<String>::new(), env(&all))
        };
        let cfg = hosted(&[
            (MESH_AUTHORIZATION_URL_ENV, https),
            (MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV, roots),
        ])
        .unwrap();
        let authorization = cfg.mesh_authorization.unwrap();
        assert_eq!(authorization.url, https);
        assert_eq!(authorization.tls_roots_file(), std::path::Path::new(roots));
        for invalid in [
            &[(MESH_AUTHORIZATION_URL_ENV, https)][..],
            &[(
                MESH_AUTHORIZATION_URL_ENV,
                "http://orchestration.internal:8085",
            )],
            &[
                (
                    MESH_AUTHORIZATION_URL_ENV,
                    "http://orchestration.internal:8085",
                ),
                (MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV, roots),
            ],
            &[
                (MESH_AUTHORIZATION_URL_ENV, https),
                (MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV, "ca.crt"),
            ],
        ] {
            assert_eq!(
                hosted(invalid).unwrap_err(),
                ConfigError::InvalidMeshAuthorizationTls,
                "{invalid:?}"
            );
        }
        assert_eq!(
            Config::from_sources(
                Vec::<String>::new(),
                env(&[
                    (MESH_URL_ENV, "https://mesh.codewire.sh"),
                    (MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV, roots),
                ]),
            )
            .unwrap_err(),
            ConfigError::InvalidMeshAuthorizationTls
        );
    }

    #[test]
    fn rejects_database_url_flag_without_exposing_its_value() {
        const MARKER: &str = "postgres://synthetic-user:synthetic-secret@database.invalid/db";

        for args in [
            vec![format!("--database-url={MARKER}")],
            vec!["--database-url".to_owned(), MARKER.to_owned()],
        ] {
            let error =
                Config::from_sources(args, env(&[(MESH_URL_ENV, "https://mesh.codewire.sh")]))
                    .unwrap_err();
            assert_eq!(error, ConfigError::UnknownFlag("--database-url".to_owned()));
            assert!(!error.to_string().contains(MARKER));
        }
    }

    #[test]
    fn config_debug_redacts_database_url() {
        const MARKER: &str = "postgres://synthetic-user:synthetic-secret@database.invalid/db";
        let config = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (DATABASE_URL_ENV, MARKER),
                (
                    MESH_AUTHORIZATION_URL_ENV,
                    "https://orchestration.internal:8088",
                ),
                (
                    MESH_AUTHORIZATION_TLS_ROOTS_FILE_ENV,
                    "/run/codewire-mesh-authorization-roots/ca.crt",
                ),
                (MESH_AUTHORIZATION_HMAC_SECRET_ENV, "synthetic-hmac"),
            ]),
        )
        .unwrap();

        let debug = format!("{config:?}");
        assert!(debug.contains("database_url: Some(\"[redacted]\")"));
        assert!(!debug.contains(MARKER));
        assert!(!debug.contains("synthetic-hmac"));
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
    fn reads_bounded_canonical_stun_servers() {
        let cfg = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (
                    STUN_SERVERS_ENV,
                    "stun://STUN.EXAMPLE.COM.:19302, [2001:db8::1]:3478, stun.example.com:19302",
                ),
            ]),
        )
        .unwrap();
        assert_eq!(
            cfg.stun_servers,
            vec![
                StunServerConfig {
                    host: "stun.example.com".to_owned(),
                    port: 19_302,
                },
                StunServerConfig {
                    host: "2001:db8::1".to_owned(),
                    port: 3_478,
                },
            ]
        );

        for invalid in ["https://stun.example.com/path", "stün.example.com", ":0"] {
            assert!(matches!(
                Config::from_sources(
                    Vec::<String>::new(),
                    env(&[
                        (MESH_URL_ENV, "https://mesh.codewire.sh"),
                        (STUN_SERVERS_ENV, invalid)
                    ])
                ),
                Err(ConfigError::InvalidStunServer(_))
            ));
        }
    }

    #[test]
    fn rejects_more_than_the_stun_server_bound() {
        let value = (0..=MAX_STUN_SERVERS)
            .map(|index| format!("stun-{index}.example.com"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            Config::from_sources(Vec::<String>::new(), move |key| match key {
                MESH_URL_ENV => Some("https://mesh.codewire.sh".to_owned()),
                STUN_SERVERS_ENV => Some(value.clone()),
                _ => None,
            })
            .unwrap_err(),
            ConfigError::TooManyStunServers
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
