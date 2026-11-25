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
    pub(crate) turnstile_site_key: String,
    /// Public GitHub App identifiers. The client secret is held solely by
    /// credential-service, never the dashboard or browser.
    pub(crate) github_app_slug: String,
    pub(crate) github_app_client_id: String,
    /// Where the header's Support button writes to, from
    /// `CODEWIRE_SUPPORT_EMAIL`; unset hides the button, since a self-hosted
    /// deployment without its own support address has nowhere to send it.
    pub(crate) support_email: Option<String>,
    /// The Liminal site the public Updates page reads, from `LIMINAL_ORIGIN`
    /// and `LIMINAL_API_KEY`; both unset turns the page and its sidebar link
    /// off, so a self-hosted deployment points at no one else's CMS.
    pub(crate) updates_site: Option<crate::updates_connect::LiminalSite>,
    /// The public pages' analytics tag, from `CODEWIRE_ANALYTICS_ORIGIN` and
    /// `CODEWIRE_ANALYTICS_WEBSITE_ID`; both unset leaves every page untagged.
    pub(crate) analytics: Option<crate::analytics::Analytics>,
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
        let support_email = match env::var("CODEWIRE_SUPPORT_EMAIL") {
            Ok(value) => parse_support_email(&value)?,
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                bail!("CODEWIRE_SUPPORT_EMAIL must be valid UTF-8")
            }
        };
        let updates_site = parse_updates_site(
            optional_env("LIMINAL_ORIGIN")?,
            optional_env("LIMINAL_API_KEY")?,
            optional_env("LIMINAL_MEDIA_ORIGIN")?,
        )?;
        let analytics = crate::analytics::parse(
            optional_env("CODEWIRE_ANALYTICS_ORIGIN")?,
            optional_env("CODEWIRE_ANALYTICS_WEBSITE_ID")?,
            &public_origin,
        )?;

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
            turnstile_site_key,
            github_app_slug,
            github_app_client_id,
            support_email,
            updates_site,
            analytics,
        })
    }
}

/// An email address, or `None` for an empty value.
fn parse_support_email(value: &str) -> anyhow::Result<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let valid = value.len() <= 254
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
        && value.matches('@').count() == 1
        && value.chars().all(|c| c.is_ascii_graphic());
    if !valid {
        bail!("CODEWIRE_SUPPORT_EMAIL must be one email address, such as support@example.com");
    }
    Ok(Some(value.to_owned()))
}

/// An environment variable's value, `None` when it is unset or blank.
fn optional_env(name: &str) -> anyhow::Result<Option<String>> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

/// Both values or neither: one without the other is a half-configured
/// deployment, which refuses to start rather than hide the page silently. The
/// media origin is optional, and only with a site.
fn parse_updates_site(
    origin: Option<String>,
    api_key: Option<String>,
    media_origin: Option<String>,
) -> anyhow::Result<Option<crate::updates_connect::LiminalSite>> {
    let (origin, api_key) = match (origin, api_key) {
        (None, None) if media_origin.is_none() => return Ok(None),
        (None, None) => bail!("LIMINAL_MEDIA_ORIGIN needs LIMINAL_ORIGIN and LIMINAL_API_KEY"),
        (Some(origin), Some(api_key)) => (origin, api_key),
        _ => bail!("LIMINAL_ORIGIN and LIMINAL_API_KEY are set together or not at all"),
    };
    let media_origin = media_origin
        .map(|media_origin| parse_liminal_origin("LIMINAL_MEDIA_ORIGIN", media_origin))
        .transpose()?;
    let origin = parse_liminal_origin("LIMINAL_ORIGIN", origin)?;
    let api_key = api_key.trim().to_owned();
    if api_key.len() > 512 || !api_key.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("LIMINAL_API_KEY must be one Liminal API key");
    }
    Ok(Some(crate::updates_connect::LiminalSite::new(
        origin,
        api_key,
        media_origin,
    )))
}

/// An HTTPS origin: the dashboard sends the site's key to it, so plain HTTP
/// is refused except on loopback, where it never leaves the machine.
fn parse_liminal_origin(label: &str, raw: String) -> anyhow::Result<String> {
    let (_, origin) = parse_origin(label, raw)?;
    let url = Url::parse(&origin).context("a parsed origin is a URL")?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if url.scheme() != "https" && !loopback {
        bail!("{label} must be an https:// origin");
    }
    Ok(origin)
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

pub(crate) fn parse_origin(label: &str, raw: String) -> anyhow::Result<(http::Uri, String)> {
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
    fn the_updates_site_needs_both_its_origin_and_its_key() {
        assert!(parse_updates_site(None, None, None).unwrap().is_none());
        let site = parse_updates_site(
            Some("https://cms.example.com/".to_owned()),
            Some(" lim_sk_test ".to_owned()),
            Some("https://media.example.com/".to_owned()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(site.posts_url(), "https://cms.example.com/api/v1/posts");
        assert_eq!(site.media_origin(), Some("https://media.example.com"));
        assert!(!format!("{site:?}").contains("lim_sk_test"));
        let owned = |value: Option<&str>| value.map(str::to_owned);
        for (origin, api_key, media_origin) in [
            (Some("https://cms.example.com"), None, None),
            (None, Some("lim_sk_test"), None),
            (None, None, Some("https://media.example.com")),
            (
                Some("https://cms.example.com/blog"),
                Some("lim_sk_test"),
                None,
            ),
            (Some("https://cms.example.com"), Some("lim sk"), None),
            (
                Some("https://cms.example.com"),
                Some("lim_sk_test"),
                Some("https://media.example.com/images"),
            ),
            (Some("http://cms.example.com"), Some("lim_sk_test"), None),
            (
                Some("https://cms.example.com"),
                Some("lim_sk_test"),
                Some("http://media.example.com"),
            ),
        ] {
            assert!(
                parse_updates_site(owned(origin), owned(api_key), owned(media_origin)).is_err(),
                "{origin:?} {api_key:?} {media_origin:?}"
            );
        }
    }

    #[test]
    fn plain_http_is_admitted_only_on_loopback() {
        for origin in [
            "http://127.0.0.1:18471",
            "http://localhost:3000",
            "http://[::1]:3000",
        ] {
            assert!(
                parse_updates_site(
                    Some(origin.to_owned()),
                    Some("lim_sk_test".to_owned()),
                    None
                )
                .unwrap()
                .is_some(),
                "{origin}"
            );
        }
        for origin in [
            "http://cms.example.com",
            "http://10.0.0.1",
            "http://localhost.example.com",
        ] {
            assert!(
                parse_updates_site(
                    Some(origin.to_owned()),
                    Some("lim_sk_test".to_owned()),
                    None
                )
                .is_err(),
                "{origin}"
            );
        }
    }

    #[test]
    fn the_support_email_is_one_address_or_nothing() {
        assert_eq!(
            parse_support_email(" support@codewire.sh ")
                .unwrap()
                .as_deref(),
            Some("support@codewire.sh")
        );
        assert_eq!(parse_support_email("").unwrap(), None);
        for invalid in [
            "support",
            "@codewire.sh",
            "a@b",
            "a@b@c.sh",
            "a b@c.sh",
            "a@c.sh,b@c.sh\n",
        ] {
            assert!(parse_support_email(invalid).is_err(), "{invalid}");
        }
    }

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
