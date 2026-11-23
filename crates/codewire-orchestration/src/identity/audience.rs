//! Audiences (docs/dev/SANDBOX-IDENTITY.md, "Audiences"): a verifier an
//! organization registered, named by an absolute `https` URI.
//!
//! [`CanonicalAudience::parse`] is the one canonical form. Registration stores
//! it, and a mint canonicalises its `resource` with the same function and
//! must match a registration exactly. [`AudienceDenylist`] holds what
//! registration refuses on top of the form.

use std::fmt;

use url::Host;

/// The longest audience accepted, in bytes, so a registration and a mint's
/// `resource` stay a bounded size.
pub const MAX_AUDIENCE_BYTES: usize = 2048;
/// The port an `https` audience names when it names none.
const DEFAULT_PORT: u16 = 443;

/// Why an audience was refused, worded as the rule it breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudienceError {
    #[error("an audience is an absolute https URI, such as https://verifier.example")]
    NotAbsolute,
    #[error("an audience uses https")]
    NotHttps,
    #[error("an audience is at most {MAX_AUDIENCE_BYTES} bytes")]
    TooLong,
    #[error("an audience has no user name or password")]
    Userinfo,
    #[error("an audience has no query")]
    Query,
    #[error("an audience has no fragment")]
    Fragment,
    #[error("an audience's host is not a valid host name")]
    InvalidHost,
    #[error("an audience's port is a number from 1 to 65535")]
    InvalidPort,
    #[error("an audience's path holds only characters a URI allows, and well-formed %XX escapes")]
    InvalidPath,
    #[error("an audience can't be an IP address")]
    IpAddress,
    #[error(
        "an audience can't be localhost, or a name that only a local or private network serves"
    )]
    PrivateHost,
    #[error("an audience can't be the in-cluster Kubernetes API")]
    InClusterKubernetes,
    #[error("an audience can't be {0} or a host under it: this deployment serves it")]
    DeploymentDomain(String),
}

/// An audience's host, as the canonical form spells it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AudienceHost {
    /// Lowercase IDNA A-labels.
    Domain(String),
    Ip(std::net::IpAddr),
}

/// An audience in its canonical form: `https`, the host lowercased as IDNA
/// A-labels, no default `:443`, and the path exactly as written, trailing
/// slash included. It holds no user name, password, query or fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalAudience {
    canonical: String,
    host: AudienceHost,
}

impl CanonicalAudience {
    /// The canonical form of `input`, or the form rule it breaks. Nothing is
    /// trimmed or decoded but the host.
    pub fn parse(input: &str) -> Result<Self, AudienceError> {
        if input.len() > MAX_AUDIENCE_BYTES {
            return Err(AudienceError::TooLong);
        }
        let (scheme, rest) = input.split_once(':').ok_or(AudienceError::NotAbsolute)?;
        if !valid_scheme(scheme) {
            return Err(AudienceError::NotAbsolute);
        }
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(AudienceError::NotHttps);
        }
        let rest = rest.strip_prefix("//").ok_or(AudienceError::NotAbsolute)?;
        // In a URI, `#` always starts the fragment and `?` the query.
        if rest.contains('#') {
            return Err(AudienceError::Fragment);
        }
        if rest.contains('?') {
            return Err(AudienceError::Query);
        }
        let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
        if authority.contains('@') {
            return Err(AudienceError::Userinfo);
        }
        let (host, port) = split_port(authority)?;
        let host = parse_host(host)?;
        if !valid_path(path) {
            return Err(AudienceError::InvalidPath);
        }
        let mut canonical = String::from("https://");
        match &host {
            AudienceHost::Domain(domain) => canonical.push_str(domain),
            AudienceHost::Ip(std::net::IpAddr::V4(ip)) => canonical.push_str(&ip.to_string()),
            AudienceHost::Ip(std::net::IpAddr::V6(ip)) => canonical.push_str(&format!("[{ip}]")),
        }
        if let Some(port) = port.filter(|port| *port != DEFAULT_PORT) {
            canonical.push_str(&format!(":{port}"));
        }
        canonical.push_str(path);
        Ok(Self { canonical, host })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub fn host(&self) -> &AudienceHost {
        &self.host
    }
}

impl fmt::Display for CanonicalAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// RFC 3986 `scheme`: a letter, then letters, digits, `+`, `-` or `.`.
fn valid_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// The host and the port an authority names, if it names one.
fn split_port(authority: &str) -> Result<(&str, Option<u16>), AudienceError> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(AudienceError::InvalidHost)?;
        let (host, after) = authority.split_at(end + 1);
        match after {
            "" => (host, None),
            after => (
                host,
                Some(after.strip_prefix(':').ok_or(AudienceError::InvalidHost)?),
            ),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = port
        .map(|port| {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(AudienceError::InvalidPort);
            }
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(AudienceError::InvalidPort)
        })
        .transpose()?;
    Ok((host, port))
}

/// The WHATWG host parser, so a name a browser or HTTP client reads as an
/// IPv4 address (`0x7f.1`, `2130706433`) is one here too. A domain with an
/// empty label, a trailing dot included, is refused: it would spell one host
/// two ways.
fn parse_host(host: &str) -> Result<AudienceHost, AudienceError> {
    if host.is_empty() {
        return Err(AudienceError::InvalidHost);
    }
    match Host::parse(host).map_err(|_| AudienceError::InvalidHost)? {
        Host::Domain(domain) => {
            if domain.split('.').any(str::is_empty) {
                return Err(AudienceError::InvalidHost);
            }
            Ok(AudienceHost::Domain(domain))
        }
        Host::Ipv4(ip) => Ok(AudienceHost::Ip(ip.into())),
        Host::Ipv6(ip) => Ok(AudienceHost::Ip(ip.into())),
    }
}

/// RFC 3986 `path-abempty`: empty, or `/`-led segments of unreserved
/// characters, sub-delims, `:`, `@` and `%XX` escapes.
fn valid_path(path: &str) -> bool {
    if !path.is_empty() && !path.starts_with('/') {
        return false;
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let escape = bytes.get(index + 1..index + 3);
            if !escape.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte)) {
            return false;
        }
        index += 1;
    }
    true
}

/// Names that only a local or private network answers: `localhost` (RFC
/// 6761), mDNS's `local` (RFC 6762), which holds every in-cluster
/// `cluster.local` name, the residential `home.arpa` (RFC 8375) and the
/// private-use `internal`.
const PRIVATE_DOMAINS: [&str; 4] = ["localhost", "local", "home.arpa", "internal"];

/// What registration refuses on top of the form: IP addresses, local and
/// private-network names, the in-cluster Kubernetes API, and every domain
/// the deployment serves, with every host under it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudienceDenylist {
    deployment_domains: Vec<String>,
}

impl AudienceDenylist {
    /// The deployment serves its API and dashboard on `FRONTEND_URL`'s host,
    /// its previews under `PREVIEW_BASE_DOMAIN`, and its issuers on
    /// `CODEWIRE_IDENTITY_ISSUER_BASE`'s host. A value that names no DNS
    /// host, such as an unset preview domain or a loopback address, adds
    /// nothing: an IP address is refused anyway.
    pub fn for_deployment(
        frontend_url: &str,
        preview_base_domain: &str,
        issuer_base: Option<&str>,
    ) -> Self {
        let url_host = |value: &str| {
            url::Url::parse(value)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        };
        Self::new(
            [
                url_host(frontend_url),
                Some(preview_base_domain.to_owned()),
                issuer_base.and_then(url_host),
            ]
            .into_iter()
            .flatten(),
        )
    }

    /// A denylist of these domains, each spelled as a canonical host is.
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let mut deployment_domains: Vec<String> = domains
            .into_iter()
            .filter_map(|domain| match parse_host(domain.trim()) {
                Ok(AudienceHost::Domain(domain)) => Some(domain),
                Ok(AudienceHost::Ip(_)) | Err(_) => None,
            })
            .collect();
        deployment_domains.sort();
        deployment_domains.dedup();
        Self { deployment_domains }
    }

    pub fn deployment_domains(&self) -> &[String] {
        &self.deployment_domains
    }

    /// Whether registration admits `audience`, or the rule it breaks.
    pub fn check(&self, audience: &CanonicalAudience) -> Result<(), AudienceError> {
        let domain = match audience.host() {
            AudienceHost::Ip(_) => return Err(AudienceError::IpAddress),
            AudienceHost::Domain(domain) => domain.as_str(),
        };
        if let Some(served) = self
            .deployment_domains
            .iter()
            .find(|served| at_or_under(domain, served))
        {
            return Err(AudienceError::DeploymentDomain(served.clone()));
        }
        if in_cluster_kubernetes(domain) {
            return Err(AudienceError::InClusterKubernetes);
        }
        // A name of one label is resolved through a search list, so it
        // names whatever host the resolving network has under that name.
        if !domain.contains('.')
            || PRIVATE_DOMAINS
                .iter()
                .any(|private| at_or_under(domain, private))
        {
            return Err(AudienceError::PrivateHost);
        }
        Ok(())
    }
}

fn at_or_under(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// `kubernetes`, `kubernetes.default`, and `kubernetes.default.svc` with
/// every name that extends it, such as `kubernetes.default.svc.cluster.local`,
/// or lies under it.
fn in_cluster_kubernetes(host: &str) -> bool {
    const SERVICE: &str = "kubernetes.default.svc";
    host == "kubernetes"
        || host == "kubernetes.default"
        || at_or_under(host, SERVICE)
        || host
            .strip_prefix(SERVICE)
            .is_some_and(|rest| rest.starts_with('.'))
}

#[cfg(test)]
mod tests;
