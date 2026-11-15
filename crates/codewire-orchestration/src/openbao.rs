//! Shared checks for the hand-written OpenBao clients in this crate: the
//! origin, mount, role and cluster-id shapes they accept, and the HTTP client
//! they all use, which never follows a redirect.

use std::time::Duration;

use url::Url;

pub(crate) fn valid_openbao_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn valid_openbao_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

pub(crate) fn valid_openbao_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn restricted_http_client(
    timeout: Duration,
    https_only: bool,
    root_certificate_pem: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);
    if let Some(root_certificate_pem) = root_certificate_pem {
        let certificate = reqwest::Certificate::from_pem(root_certificate_pem)?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().map_err(Into::into)
}

pub(crate) fn parse_https_origin(name: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    if url.scheme() != "https" {
        anyhow::bail!("{name} must use HTTPS");
    }
    parse_origin(name, url)
}

pub(crate) fn parse_openbao_origin(name: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    let internal_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host == "127.0.0.1" || host.ends_with(".svc.cluster.local"));
    if url.scheme() == "https" || internal_http {
        parse_origin(name, url)
    } else {
        anyhow::bail!("{name} must use HTTPS or an in-cluster .svc.cluster.local HTTP endpoint")
    }
}

fn parse_origin(name: &str, mut url: Url) -> anyhow::Result<Url> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("{name} must be an origin URL without credentials, query, or fragment");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub(crate) fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("required environment variable {name} is not set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_urls_fail_closed() {
        assert!(parse_https_origin("KBS", "https://kbs.example.test").is_ok());
        assert!(parse_https_origin("KBS", "http://kbs.example.test").is_err());
        assert!(parse_openbao_origin("OpenBao", "http://openbao.svc.cluster.local").is_ok());
        assert!(parse_openbao_origin("OpenBao", "http://openbao.example.test").is_err());
        assert!(parse_openbao_origin("OpenBao", "https://openbao.example.test/api").is_err());
    }
}
