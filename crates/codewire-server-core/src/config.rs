//! Service configuration loaded from environment variables.
//!
//! Variables mirror the Go side's `internal/config` so the same `.env`
//! works for either implementation:
//!
//! | env var | required | default |
//! |---|---|---|
//! | `DATABASE_URL` | no | derived from `DB_*` if unset |
//! | `DB_PASSWORD` | required when `DATABASE_URL` is unset | — |
//! | `NATS_URL` | no | unset → service runs without NATS |
//! | `NATS_TOKEN` | no | unset → unauthenticated NATS |
//! | `NATS_KV_REPLICAS` | no | `1`; 1, 3 or 5 replicas of every KV bucket |
//! | `SESSION_SECRET` | yes | — |
//! | `<SERVICE>_PORT` (e.g. `BILLING_PORT`) | no | derived per service |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | no | unset → no trace export (read only by services that call `obs::init_with_traces`) |
//! | `RUST_LOG` | no | `info` |
//!
//! Each binary calls [`ServiceConfig::from_env`] once at startup; missing
//! required variables produce a typed [`ConfigError`] rather than a panic
//! deep in initialization.

use std::env;
use std::net::SocketAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is not set")]
    Missing(&'static str),
    #[error("environment variable {var}={value:?} could not be parsed: {source}")]
    Parse {
        var: &'static str,
        value: String,
        #[source]
        source: anyhow::Error,
    },
}

/// Configuration shared by every Codewire backend service.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Logical service name (e.g. `"billing"`). Used in tracing fields and
    /// to derive the default port env var.
    pub name: String,
    /// Address the HTTP server binds to. Defaults to `0.0.0.0:<port>` where
    /// `<port>` comes from `<NAME>_PORT` (e.g. `BILLING_PORT`).
    pub bind_addr: SocketAddr,
    /// Postgres connection string.
    pub database_url: String,
    /// NATS connection URL; `None` if NATS isn't configured.
    pub nats_url: Option<String>,
    /// NATS bearer token; `None` means unauthenticated NATS.
    pub nats_token: Option<String>,
    /// Replicas of every JetStream KV bucket the service keeps (#3542).
    pub nats_kv_replicas: usize,
    /// Shared platform-internal secret: HMAC sidecar/gateway tokens and
    /// the idp's 2FA secret encryption. Never used for user bearer-token
    /// validation, which is a direct database lookup (see
    /// `auth::authenticate`).
    pub session_secret: String,
    /// OTLP endpoint, e.g. `http://otel-collector:4317`. `None` disables
    /// the OpenTelemetry exporter; only [`crate::obs::init_with_traces`]
    /// reads it.
    pub otlp_endpoint: Option<String>,
}

impl ServiceConfig {
    /// Read the configuration for a service named `service`.
    ///
    /// The port env var is `<SERVICE>_PORT` upper-cased (e.g. `BILLING_PORT`),
    /// with a default of `8080`.
    pub fn from_env(service: &str) -> Result<Self, ConfigError> {
        Self::from_lookup(service, &process_env)
    }

    /// [`Self::from_env`] over any source of variables, so tests supply their
    /// own instead of changing the process environment.
    fn from_lookup(service: &str, lookup: Lookup<'_>) -> Result<Self, ConfigError> {
        let database_url = database_url_from_lookup(lookup)?;
        let session_secret = require(lookup, "SESSION_SECRET")?;
        let nats_url = optional(lookup, "NATS_URL");
        let nats_token = optional(lookup, "NATS_TOKEN");
        let nats_kv_replicas = optional(lookup, "NATS_KV_REPLICAS")
            .map(|value| {
                crate::nats::parse_kv_replicas(&value).map_err(|source| ConfigError::Parse {
                    var: "NATS_KV_REPLICAS",
                    value,
                    source,
                })
            })
            .transpose()?
            .unwrap_or(crate::nats::DEFAULT_KV_REPLICAS);
        let otlp_endpoint = optional(lookup, "OTEL_EXPORTER_OTLP_ENDPOINT");

        let port_var: &'static str = match service {
            "billing" => "BILLING_PORT",
            "orchestration" => "ORCHESTRATION_PORT",
            "events" => "EVENTS_PORT",
            "coordinator" => "COORDINATOR_PORT",
            "idp" => "IDP_PORT",
            "api" => "PORT",
            _ => "PORT",
        };
        let port: u16 = optional(lookup, port_var)
            .as_deref()
            .map(parse_port)
            .transpose()
            .map_err(|source| ConfigError::Parse {
                var: port_var,
                value: lookup(port_var).unwrap_or_default(),
                source,
            })?
            .unwrap_or(8080);
        let bind_addr: SocketAddr = ([0, 0, 0, 0], port).into();

        Ok(ServiceConfig {
            name: service.to_string(),
            bind_addr,
            database_url,
            nats_url,
            nats_token,
            nats_kv_replicas,
            session_secret,
            otlp_endpoint,
        })
    }
}

/// Resolve the Postgres connection string from the shared service environment.
///
/// A non-empty `DATABASE_URL` takes precedence. Missing and empty values use
/// the same Go-compatible `DB_*` derivation as [`ServiceConfig::from_env`].
pub fn database_url_from_env() -> Result<String, ConfigError> {
    database_url_from_lookup(&process_env)
}

fn database_url_from_lookup(lookup: Lookup<'_>) -> Result<String, ConfigError> {
    if let Some(database_url) = optional(lookup, "DATABASE_URL") {
        return Ok(database_url);
    }

    let env = optional(lookup, "ENVIRONMENT").unwrap_or_else(|| "dev".to_string());
    let env_prefix = match env.as_str() {
        "local" | "development" => "dev",
        "production" => "prod",
        _ => env.as_str(),
    };

    let db_cluster = optional(lookup, "DB_CLUSTER").unwrap_or_else(|| "codewire-db".to_string());
    let db_host =
        optional(lookup, "DB_HOST").unwrap_or_else(|| format!("{db_cluster}-rw.{env_prefix}"));
    let db_port = optional(lookup, "DB_PORT").unwrap_or_else(|| "5432".to_string());
    let db_user = optional(lookup, "DB_USER").unwrap_or_else(|| "codewire".to_string());
    let db_password = optional(lookup, "DB_PASSWORD")
        .ok_or(ConfigError::Missing("DATABASE_URL or DB_PASSWORD"))?;
    let db_name = optional(lookup, "DB_NAME").unwrap_or_else(|| "codewire".to_string());
    let db_sslmode = optional(lookup, "DB_SSLMODE").unwrap_or_else(|| "require".to_string());

    database_url_from_parts(
        &db_host,
        &db_port,
        &db_user,
        &db_password,
        &db_name,
        &db_sslmode,
    )
}

/// Construct a Postgres connection string from separately supplied fields.
///
/// This keeps password escaping and typed port validation in one shared
/// implementation for callers that intentionally forbid `DATABASE_URL` and
/// require explicit structured inputs.
pub fn database_url_from_parts(
    db_host: &str,
    db_port: &str,
    db_user: &str,
    db_password: &str,
    db_name: &str,
    db_sslmode: &str,
) -> Result<String, ConfigError> {
    let db_port = db_port
        .parse::<u16>()
        .map_err(|source| ConfigError::Parse {
            var: "DB_PORT",
            value: db_port.to_string(),
            source: anyhow::Error::new(source),
        })?;

    let mut url = url::Url::parse("postgres://localhost").expect("static database URL parses");
    url.set_username(db_user).map_err(|_| ConfigError::Parse {
        var: "DB_USER",
        value: db_user.to_string(),
        source: anyhow::anyhow!("invalid database username"),
    })?;
    url.set_password(Some(db_password))
        .map_err(|_| ConfigError::Parse {
            var: "DB_PASSWORD",
            value: "<redacted>".to_string(),
            source: anyhow::anyhow!("invalid database password"),
        })?;
    url.set_host(Some(db_host))
        .map_err(|source| ConfigError::Parse {
            var: "DB_HOST",
            value: db_host.to_string(),
            source: anyhow::Error::new(source),
        })?;
    url.set_port(Some(db_port))
        .map_err(|_| ConfigError::Parse {
            var: "DB_PORT",
            value: db_port.to_string(),
            source: anyhow::anyhow!("invalid database port"),
        })?;
    url.set_path(db_name);
    url.query_pairs_mut().append_pair("sslmode", db_sslmode);

    Ok(url.to_string())
}

/// One variable's value, or `None` when it is unset.
type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment. A value that is not Unicode reads as unset.
fn process_env(var: &str) -> Option<String> {
    env::var(var).ok()
}

fn require(lookup: Lookup<'_>, var: &'static str) -> Result<String, ConfigError> {
    optional(lookup, var).ok_or(ConfigError::Missing(var))
}

fn optional(lookup: Lookup<'_>, var: &str) -> Option<String> {
    lookup(var).filter(|v| !v.is_empty())
}

fn parse_port(s: &str) -> anyhow::Result<u16> {
    s.parse::<u16>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over exactly `vars`; every other variable is unset.
    fn vars(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            vars.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn rejects_missing_database_url() {
        assert!(matches!(
            ServiceConfig::from_lookup("billing", &vars(&[("SESSION_SECRET", "x")])),
            Err(ConfigError::Missing("DATABASE_URL or DB_PASSWORD"))
        ));
    }

    #[test]
    fn empty_database_url_derives_from_go_compatible_db_env() {
        let cfg = ServiceConfig::from_lookup(
            "coordinator",
            &vars(&[
                ("DATABASE_URL", ""),
                ("ENVIRONMENT", "development"),
                ("DB_PASSWORD", "p@ss word"),
                ("SESSION_SECRET", "y"),
            ]),
        )
        .unwrap();
        assert_eq!(
            cfg.database_url,
            "postgres://codewire:p%40ss%20word@codewire-db-rw.dev:5432/codewire?sslmode=require"
        );
    }

    #[test]
    fn derives_port_var_per_service() {
        let cfg = ServiceConfig::from_lookup(
            "orchestration",
            &vars(&[
                ("DATABASE_URL", "postgres://x"),
                ("SESSION_SECRET", "y"),
                ("ORCHESTRATION_PORT", "9001"),
                ("NATS_URL", "nats://localhost:4222"),
                ("NATS_TOKEN", "token"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.bind_addr.port(), 9001);
        assert_eq!(cfg.nats_url.as_deref(), Some("nats://localhost:4222"));
        assert_eq!(cfg.nats_token.as_deref(), Some("token"));
        assert_eq!(cfg.nats_kv_replicas, 1, "unset is one replica");
    }

    #[test]
    fn kv_replicas_come_from_the_environment_and_are_checked() {
        let with = |replicas: &str| {
            ServiceConfig::from_lookup("coordinator", &|var: &str| match var {
                "DATABASE_URL" => Some("postgres://x".into()),
                "SESSION_SECRET" => Some("y".into()),
                "NATS_KV_REPLICAS" => Some(replicas.into()),
                _ => None,
            })
        };
        assert_eq!(with("3").unwrap().nats_kv_replicas, 3);
        assert_eq!(with("").unwrap().nats_kv_replicas, 1, "empty is unset");
        let error = with("2").unwrap_err();
        assert!(
            matches!(
                error,
                ConfigError::Parse {
                    var: "NATS_KV_REPLICAS",
                    ..
                }
            ),
            "{error}"
        );
    }
}
