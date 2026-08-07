use std::{env, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context as _, bail};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    MultiThread,
    CurrentThread,
}

impl RuntimeMode {
    pub fn from_env() -> anyhow::Result<Self> {
        let value = env::var("CODEWIRE_DASHBOARD_RUNTIME_MODE")
            .map(Some)
            .or_else(|error| match error {
                env::VarError::NotPresent => Ok(None),
                env::VarError::NotUnicode(_) => Err(error),
            })
            .context("read CODEWIRE_DASHBOARD_RUNTIME_MODE")?;
        Self::parse(value.as_deref())
    }

    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            None | Some("multi-thread") => Ok(Self::MultiThread),
            Some("current-thread") => Ok(Self::CurrentThread),
            Some(value) => bail!(
                "CODEWIRE_DASHBOARD_RUNTIME_MODE must be `multi-thread` or `current-thread`, got {value:?}"
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub runtime_mode: RuntimeMode,
    pub(crate) public_origin: String,
    pub(crate) api_origin: http::Uri,
    pub(crate) identity_origin_string: String,
    pub(crate) browser_api_origin: String,
    pub(crate) billing_origin: http::Uri,
    pub(crate) docs_root: PathBuf,
    pub(crate) confidential_storage_enabled: bool,
    pub(crate) confidential_admin_only: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let runtime_mode = RuntimeMode::from_env()?;
        let listen_addr = env::var("CODEWIRE_DASHBOARD_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:5173".to_owned())
            .parse()
            .context("CODEWIRE_DASHBOARD_LISTEN_ADDR must be a socket address")?;
        let (_, public_origin) = parse_origin(
            "CODEWIRE_PUBLIC_ORIGIN",
            env::var("CODEWIRE_PUBLIC_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:5173".to_owned()),
        )?;
        let (api_origin, api_origin_string) = parse_origin(
            "CODEWIRE_API_ORIGIN",
            env::var("CODEWIRE_API_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned()),
        )?;
        let (_, identity_origin_string) = parse_origin(
            "CODEWIRE_IDENTITY_ORIGIN",
            env::var("CODEWIRE_IDENTITY_ORIGIN").unwrap_or_else(|_| api_origin_string.clone()),
        )?;
        let (billing_origin, _) = parse_origin(
            "CODEWIRE_BILLING_ORIGIN",
            env::var("CODEWIRE_BILLING_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:8081".to_owned()),
        )?;
        let (_, browser_api_origin) = parse_origin(
            "CODEWIRE_BROWSER_API_ORIGIN",
            env::var("CODEWIRE_BROWSER_API_ORIGIN").unwrap_or_else(|_| public_origin.clone()),
        )?;
        let docs_root = env::var_os("CODEWIRE_DOCS_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("apps/docs/zola/public"));
        let confidential_storage_enabled =
            parse_bool_env("SANDBOX_CONFIDENTIAL_STORAGE_ENABLED", false)?;
        let confidential_admin_only = parse_bool_env("SANDBOX_CONFIDENTIAL_ADMIN_ONLY", true)?;

        Ok(Self {
            listen_addr,
            runtime_mode,
            public_origin,
            api_origin,
            identity_origin_string,
            browser_api_origin,
            billing_origin,
            docs_root,
            confidential_storage_enabled,
            confidential_admin_only,
        })
    }
}

fn parse_bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match env::var(name) {
        Err(env::VarError::NotPresent) => parse_bool_value(name, None, default),
        Ok(value) => parse_bool_value(name, Some(&value), default),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

fn parse_bool_value(name: &str, value: Option<&str>, default: bool) -> anyhow::Result<bool> {
    match value {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(value) => bail!("{name} must be true or false, got {value:?}"),
    }
}

fn parse_origin(label: &str, raw: String) -> anyhow::Result<(http::Uri, String)> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = Url::parse(trimmed)
        .with_context(|| format!("{label} must be an absolute HTTP(S) origin"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("{label} must be an absolute HTTP(S) origin without a path, query, or fragment");
    }
    let normalized = url.as_str().trim_end_matches('/').to_owned();
    Ok((
        http::Uri::from_str(&normalized).context("origin is not a valid HTTP URI")?,
        normalized,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_modes_are_explicit_and_fail_closed() {
        assert_eq!(RuntimeMode::parse(None).unwrap(), RuntimeMode::MultiThread);
        assert_eq!(
            RuntimeMode::parse(Some("multi-thread")).unwrap(),
            RuntimeMode::MultiThread
        );
        assert_eq!(
            RuntimeMode::parse(Some("current-thread")).unwrap(),
            RuntimeMode::CurrentThread
        );
        assert!(RuntimeMode::parse(Some("one-thread")).is_err());
    }

    #[test]
    fn origins_require_clean_http_origins() {
        assert!(parse_origin("origin", "https://example.test".into()).is_ok());
        assert!(parse_origin("origin", "https://example.test/path".into()).is_err());
        assert!(parse_origin("origin", "https://example.test/?q=1".into()).is_err());
        assert!(parse_origin("origin", "https://user:pass@example.test".into()).is_err());
        assert!(parse_origin("origin", "file:///tmp/dashboard".into()).is_err());
    }

    #[test]
    fn confidential_flags_are_strict() {
        assert!(!parse_bool_value("flag", None, false).unwrap());
        assert!(parse_bool_value("flag", Some("true"), false).unwrap());
        assert!(!parse_bool_value("flag", Some("false"), true).unwrap());
        assert!(parse_bool_value("flag", Some("yes"), false).is_err());
    }
}
