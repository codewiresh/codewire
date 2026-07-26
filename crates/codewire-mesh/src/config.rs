use std::net::SocketAddr;
use std::str::FromStr;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
pub const DEFAULT_SSH_LISTEN_ADDR: &str = "0.0.0.0:2222";
pub const DEFAULT_SSH_HOST_KEY_PATH: &str = "/var/lib/codewire-mesh/ssh_host_ed25519";
pub const MESH_URL_ENV: &str = "CODEWIRE_MESH_URL";
pub const LISTEN_ADDR_ENV: &str = "CODEWIRE_MESH_LISTEN_ADDR";
pub const SSH_LISTEN_ADDR_ENV: &str = "CODEWIRE_MESH_SSH_LISTEN_ADDR";
pub const SSH_HOST_KEY_PATH_ENV: &str = "CODEWIRE_MESH_SSH_HOST_KEY_PATH";
pub const AUTH_MODE_ENV: &str = "CODEWIRE_MESH_AUTH_MODE";
pub const AUTH_TOKEN_ENV: &str = "CODEWIRE_MESH_AUTH_TOKEN";
pub const DERP_URL_ENV: &str = "CODEWIRE_MESH_DERP_URL";
pub const OIDC_ISSUER_ENV: &str = "CODEWIRE_MESH_OIDC_ISSUER";
pub const OIDC_CLIENT_ID_ENV: &str = "CODEWIRE_MESH_OIDC_CLIENT_ID";
pub const OIDC_CLIENT_SECRET_ENV: &str = "CODEWIRE_MESH_OIDC_CLIENT_SECRET";
pub const OIDC_ALLOWED_GROUPS_ENV: &str = "CODEWIRE_MESH_OIDC_ALLOWED_GROUPS";
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    None,
    Token,
    Oidc,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Token => "token",
            Self::Oidc => "oidc",
        }
    }
}

impl FromStr for AuthMode {
    type Err = ConfigError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "token" => Ok(Self::Token),
            "oidc" => Ok(Self::Oidc),
            other => Err(ConfigError::InvalidAuthMode(other.to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub ssh_bind_addr: SocketAddr,
    pub ssh_host_key_path: String,
    pub base_url: String,
    pub auth_mode: AuthMode,
    pub auth_token: Option<String>,
    pub derp_url: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_allowed_groups: Vec<String>,
    pub database_url: Option<String>,
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

        let ssh_bind_addr = match first_non_empty([args.ssh_listen, getenv(SSH_LISTEN_ADDR_ENV)]) {
            Some(raw) => parse_listen_addr("ssh-listen", &raw)?,
            None => parse_listen_addr("ssh-listen", DEFAULT_SSH_LISTEN_ADDR)?,
        };

        let auth_mode = first_non_empty([args.auth_mode, getenv(AUTH_MODE_ENV)])
            .as_deref()
            .map(AuthMode::from_str)
            .transpose()?
            .unwrap_or(AuthMode::None);
        let derp_url = first_non_empty([args.derp_url, getenv(DERP_URL_ENV)]);
        if let Some(url) = derp_url.as_deref() {
            validate_base_url(url)?;
        }
        let oidc_allowed_groups =
            first_non_empty([args.oidc_allowed_groups, getenv(OIDC_ALLOWED_GROUPS_ENV)])
                .map(|raw| parse_csv_list(&raw))
                .unwrap_or_default();

        Ok(Self {
            bind_addr,
            ssh_bind_addr,
            ssh_host_key_path: first_non_empty([
                args.ssh_host_key_path,
                getenv(SSH_HOST_KEY_PATH_ENV),
            ])
            .unwrap_or_else(|| DEFAULT_SSH_HOST_KEY_PATH.to_string()),
            base_url,
            auth_mode,
            auth_token: first_non_empty([args.auth_token, getenv(AUTH_TOKEN_ENV)]),
            derp_url,
            oidc_issuer: first_non_empty([args.oidc_issuer, getenv(OIDC_ISSUER_ENV)]),
            oidc_client_id: first_non_empty([args.oidc_client_id, getenv(OIDC_CLIENT_ID_ENV)]),
            oidc_client_secret: first_non_empty([
                args.oidc_client_secret,
                getenv(OIDC_CLIENT_SECRET_ENV),
            ]),
            oidc_allowed_groups,
            database_url: first_non_empty([args.database_url, getenv(DATABASE_URL_ENV), None]),
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
    #[error("invalid auth mode {0:?}; expected none, token, or oidc")]
    InvalidAuthMode(String),
}

#[derive(Default)]
struct Args {
    base_url: Option<String>,
    listen: Option<String>,
    ssh_listen: Option<String>,
    ssh_host_key_path: Option<String>,
    auth_mode: Option<String>,
    auth_token: Option<String>,
    derp_url: Option<String>,
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_allowed_groups: Option<String>,
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
            match flag_value(&arg, "--ssh-listen", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.ssh_listen = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--ssh-host-key-path", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.ssh_host_key_path = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--auth-mode", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.auth_mode = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--auth-token", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.auth_token = Some(value);
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
            match flag_value(&arg, "--oidc-issuer", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.oidc_issuer = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--oidc-client-id", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.oidc_client_id = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--oidc-client-secret", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.oidc_client_secret = Some(value);
                    continue;
                }
                FlagValue::NotMatched => {}
            }
            match flag_value(&arg, "--oidc-allowed-groups", &mut iter)? {
                FlagValue::Matched(value) => {
                    parsed.oidc_allowed_groups = Some(value);
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

fn parse_csv_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
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
    fn cli_flags_win_over_mesh_env() {
        let cfg = Config::from_sources(
            [
                "--base-url=https://flag.example",
                "--listen",
                ":18080",
                "--ssh-listen",
                ":12222",
                "--ssh-host-key-path",
                "/tmp/flag-key",
                "--auth-mode",
                "oidc",
                "--auth-token",
                "flag-token",
                "--derp-url",
                "https://derp.flag",
                "--oidc-issuer",
                "https://issuer.flag",
                "--oidc-client-id",
                "client-flag",
                "--oidc-client-secret",
                "secret-flag",
                "--oidc-allowed-groups",
                "devs, operators ",
                "--database-url",
                "postgres://flag/db",
            ],
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (LISTEN_ADDR_ENV, "127.0.0.1:1"),
                (SSH_LISTEN_ADDR_ENV, "127.0.0.1:2"),
                (SSH_HOST_KEY_PATH_ENV, "/tmp/env-key"),
                (AUTH_MODE_ENV, "token"),
                (AUTH_TOKEN_ENV, "env-token"),
                (DERP_URL_ENV, "https://derp.env"),
                (OIDC_ISSUER_ENV, "https://issuer.env"),
                (OIDC_CLIENT_ID_ENV, "client-env"),
                (OIDC_CLIENT_SECRET_ENV, "secret-env"),
                (OIDC_ALLOWED_GROUPS_ENV, "envs"),
                (DATABASE_URL_ENV, "postgres://env/db"),
            ]),
        )
        .unwrap();

        assert_eq!(cfg.base_url, "https://flag.example");
        assert_eq!(cfg.bind_addr, "0.0.0.0:18080".parse().unwrap());
        assert_eq!(cfg.ssh_bind_addr, "0.0.0.0:12222".parse().unwrap());
        assert_eq!(cfg.ssh_host_key_path, "/tmp/flag-key");
        assert_eq!(cfg.auth_mode, AuthMode::Oidc);
        assert_eq!(cfg.auth_token.as_deref(), Some("flag-token"));
        assert_eq!(cfg.derp_url.as_deref(), Some("https://derp.flag"));
        assert_eq!(cfg.oidc_issuer.as_deref(), Some("https://issuer.flag"));
        assert_eq!(cfg.oidc_client_id.as_deref(), Some("client-flag"));
        assert_eq!(cfg.oidc_client_secret.as_deref(), Some("secret-flag"));
        assert_eq!(cfg.oidc_allowed_groups, ["devs", "operators"]);
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://flag/db"));
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

    #[test]
    fn rejects_invalid_auth_mode() {
        let err = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (AUTH_MODE_ENV, "saml"),
            ]),
        )
        .unwrap_err();
        assert_eq!(err, ConfigError::InvalidAuthMode("saml".to_string()));
    }

    #[test]
    fn rejects_legacy_github_auth_mode() {
        let err = Config::from_sources(
            Vec::<String>::new(),
            env(&[
                (MESH_URL_ENV, "https://mesh.codewire.sh"),
                (AUTH_MODE_ENV, "github"),
            ]),
        )
        .unwrap_err();
        assert_eq!(err, ConfigError::InvalidAuthMode("github".to_string()));
    }
}
