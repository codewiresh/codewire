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
//! | `SESSION_SECRET` | yes | — |
//! | `<SERVICE>_PORT` (e.g. `BILLING_PORT`) | no | derived per service |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | no | unset → stdout only |
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
    /// Shared platform-internal secret: HMAC sidecar/gateway tokens and
    /// the idp's 2FA secret encryption. Never used for user bearer-token
    /// validation, which is a direct database lookup (see
    /// `auth::authenticate`).
    pub session_secret: String,
    /// OTLP endpoint, e.g. `http://otel-collector:4317`. `None` disables
    /// the OpenTelemetry exporter.
    pub otlp_endpoint: Option<String>,
}

impl ServiceConfig {
    /// Read the configuration for a service named `service`.
    ///
    /// The port env var is `<SERVICE>_PORT` upper-cased (e.g. `BILLING_PORT`),
    /// with a default of `8080`.
    pub fn from_env(service: &str) -> Result<Self, ConfigError> {
        let database_url = database_url_from_env()?;
        let session_secret = require("SESSION_SECRET")?;
        let nats_url = optional("NATS_URL");
        let nats_token = optional("NATS_TOKEN");
        let otlp_endpoint = optional("OTEL_EXPORTER_OTLP_ENDPOINT");

        let port_var: &'static str = match service {
            "billing" => "BILLING_PORT",
            "orchestration" => "ORCHESTRATION_PORT",
            "events" => "EVENTS_PORT",
            "coordinator" => "COORDINATOR_PORT",
            "idp" => "IDP_PORT",
            "api" => "PORT",
            _ => "PORT",
        };
        let port: u16 = optional(port_var)
            .as_deref()
            .map(parse_port)
            .transpose()
            .map_err(|source| ConfigError::Parse {
                var: port_var,
                value: env::var(port_var).unwrap_or_default(),
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
    if let Some(database_url) = optional("DATABASE_URL") {
        return Ok(database_url);
    }

    let env = optional("ENVIRONMENT").unwrap_or_else(|| "dev".to_string());
    let env_prefix = match env.as_str() {
        "local" | "development" => "dev",
        "production" => "prod",
        _ => env.as_str(),
    };

    let db_cluster = optional("DB_CLUSTER").unwrap_or_else(|| "codewire-db".to_string());
    let db_host = optional("DB_HOST").unwrap_or_else(|| format!("{db_cluster}-rw.{env_prefix}"));
    let db_port = optional("DB_PORT").unwrap_or_else(|| "5432".to_string());
    let db_user = optional("DB_USER").unwrap_or_else(|| "codewire".to_string());
    let db_password =
        optional("DB_PASSWORD").ok_or(ConfigError::Missing("DATABASE_URL or DB_PASSWORD"))?;
    let db_name = optional("DB_NAME").unwrap_or_else(|| "codewire".to_string());
    let db_sslmode = optional("DB_SSLMODE").unwrap_or_else(|| "require".to_string());
    let db_port = db_port
        .parse::<u16>()
        .map_err(|source| ConfigError::Parse {
            var: "DB_PORT",
            value: db_port,
            source: anyhow::Error::new(source),
        })?;

    let mut url = url::Url::parse("postgres://localhost").expect("static database URL parses");
    url.set_username(&db_user).map_err(|_| ConfigError::Parse {
        var: "DB_USER",
        value: db_user.clone(),
        source: anyhow::anyhow!("invalid database username"),
    })?;
    url.set_password(Some(&db_password))
        .map_err(|_| ConfigError::Parse {
            var: "DB_PASSWORD",
            value: "<redacted>".to_string(),
            source: anyhow::anyhow!("invalid database password"),
        })?;
    url.set_host(Some(&db_host))
        .map_err(|source| ConfigError::Parse {
            var: "DB_HOST",
            value: db_host.clone(),
            source: anyhow::Error::new(source),
        })?;
    url.set_port(Some(db_port))
        .map_err(|_| ConfigError::Parse {
            var: "DB_PORT",
            value: db_port.to_string(),
            source: anyhow::anyhow!("invalid database port"),
        })?;
    url.set_path(&db_name);
    url.query_pairs_mut().append_pair("sslmode", &db_sslmode);

    Ok(url.to_string())
}

fn require(var: &'static str) -> Result<String, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(var)),
    }
}

fn optional(var: &str) -> Option<String> {
    env::var(var).ok().filter(|v| !v.is_empty())
}

fn parse_port(s: &str) -> anyhow::Result<u16> {
    s.parse::<u16>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global; serialize the tests in this module so
    // parallel runs don't fight each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear(vars: &[&str]) {
        for v in vars {
            unsafe { env::remove_var(v) };
        }
    }

    #[test]
    fn rejects_missing_database_url() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear(&[
            "DATABASE_URL",
            "DB_PASSWORD",
            "SESSION_SECRET",
            "BILLING_PORT",
            "ORCHESTRATION_PORT",
            "NATS_URL",
            "NATS_TOKEN",
        ]);
        unsafe { env::set_var("SESSION_SECRET", "x") };

        assert!(matches!(
            ServiceConfig::from_env("billing"),
            Err(ConfigError::Missing("DATABASE_URL or DB_PASSWORD"))
        ));

        clear(&["SESSION_SECRET"]);
    }

    #[test]
    fn empty_database_url_derives_from_go_compatible_db_env() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear(&[
            "DATABASE_URL",
            "ENVIRONMENT",
            "DB_CLUSTER",
            "DB_HOST",
            "DB_PORT",
            "DB_USER",
            "DB_PASSWORD",
            "DB_NAME",
            "DB_SSLMODE",
            "SESSION_SECRET",
            "NATS_URL",
            "NATS_TOKEN",
        ]);
        unsafe {
            env::set_var("DATABASE_URL", "");
            env::set_var("ENVIRONMENT", "development");
            env::set_var("DB_PASSWORD", "p@ss word");
            env::set_var("SESSION_SECRET", "y");
        }

        let cfg = ServiceConfig::from_env("coordinator").unwrap();
        assert_eq!(
            cfg.database_url,
            "postgres://codewire:p%40ss%20word@codewire-db-rw.dev:5432/codewire?sslmode=require"
        );

        clear(&[
            "DATABASE_URL",
            "ENVIRONMENT",
            "DB_PASSWORD",
            "SESSION_SECRET",
        ]);
    }

    #[test]
    fn derives_port_var_per_service() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear(&[
            "DATABASE_URL",
            "DB_PASSWORD",
            "SESSION_SECRET",
            "BILLING_PORT",
            "ORCHESTRATION_PORT",
            "NATS_URL",
            "NATS_TOKEN",
        ]);
        unsafe {
            env::set_var("DATABASE_URL", "postgres://x");
            env::set_var("SESSION_SECRET", "y");
            env::set_var("ORCHESTRATION_PORT", "9001");
            env::set_var("NATS_URL", "nats://localhost:4222");
            env::set_var("NATS_TOKEN", "token");
        }

        let cfg = ServiceConfig::from_env("orchestration").unwrap();
        assert_eq!(cfg.bind_addr.port(), 9001);
        assert_eq!(cfg.nats_url.as_deref(), Some("nats://localhost:4222"));
        assert_eq!(cfg.nats_token.as_deref(), Some("token"));

        clear(&[
            "DATABASE_URL",
            "DB_PASSWORD",
            "SESSION_SECRET",
            "ORCHESTRATION_PORT",
            "NATS_URL",
            "NATS_TOKEN",
        ]);
    }
}
