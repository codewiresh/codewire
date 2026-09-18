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
    pub(crate) credential_origin: http::Uri,
    pub(crate) identity_origin_string: String,
    pub(crate) browser_api_origin: String,
    pub(crate) billing_origin: http::Uri,
    pub(crate) docs_root: PathBuf,
    pub(crate) confidential_storage_enabled: bool,
    pub(crate) confidential_admin_only: bool,
    pub(crate) turnstile_site_key: String,
    /// Public GitHub App identifiers. The client secret is held solely by
    /// credential-service, never the dashboard or browser.
    pub(crate) github_app_slug: String,
    pub(crate) github_app_client_id: String,
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
        let (credential_origin, _) = parse_origin(
            "CODEWIRE_CREDENTIAL_ORIGIN",
            env::var("CODEWIRE_CREDENTIAL_ORIGIN")
                .context("read required CODEWIRE_CREDENTIAL_ORIGIN")?,
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
        let turnstile_site_key = env::var("TURNSTILE_SITE_KEY")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let github_app_slug = match env::var("GITHUB_APP_SLUG") {
            Ok(value) => parse_github_app_slug(value)?,
            Err(env::VarError::NotPresent) => String::new(),
            Err(env::VarError::NotUnicode(_)) => bail!("GITHUB_APP_SLUG must be valid UTF-8"),
        };
        let github_app_client_id = match env::var("GITHUB_APP_CLIENT_ID") {
            Ok(value) => parse_github_app_client_id(value)?,
            Err(env::VarError::NotPresent) => String::new(),
            Err(env::VarError::NotUnicode(_)) => bail!("GITHUB_APP_CLIENT_ID must be valid UTF-8"),
        };

        Ok(Self {
            listen_addr,
            runtime_mode,
            public_origin,
            api_origin,
            credential_origin,
            identity_origin_string,
            browser_api_origin,
            billing_origin,
            docs_root,
            confidential_storage_enabled,
            confidential_admin_only,
            turnstile_site_key,
            github_app_slug,
            github_app_client_id,
        })
    }
}

fn parse_github_app_client_id(value: String) -> anyhow::Result<String> {
    let value = value.trim().to_owned();
    if value.len() > 100
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        bail!("GITHUB_APP_CLIENT_ID must be a GitHub App client ID")
    }
    Ok(value)
}

fn parse_github_app_slug(value: String) -> anyhow::Result<String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Ok(value);
    }
    if value.len() > 100
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("GITHUB_APP_SLUG must be an exact GitHub App slug")
    }
    Ok(value)
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

    #[test]
    fn github_app_slug_is_optional_but_never_a_path_or_host_fragment() {
        assert_eq!(parse_github_app_slug(String::new()).unwrap(), "");
        assert_eq!(
            parse_github_app_slug("codewire-app".into()).unwrap(),
            "codewire-app"
        );
        for value in ["Codewire", "codewire/app", "codewire?next=bad", "-codewire"] {
            assert!(
                parse_github_app_slug(value.into()).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn github_app_client_id_is_optional_and_is_not_a_url_or_secret() {
        assert_eq!(parse_github_app_client_id(String::new()).unwrap(), "");
        for value in ["Iv1.kindsynthetic", "Iv23lif1Example"] {
            assert_eq!(parse_github_app_client_id(value.into()).unwrap(), value);
        }
        for value in ["https://github.com", "id&redirect_uri=bad", "a b", "a\nb"] {
            assert!(parse_github_app_client_id(value.into()).is_err());
        }
        assert!(parse_github_app_client_id("a".repeat(101)).is_err());
    }
}
