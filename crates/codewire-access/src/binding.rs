//! A value bound to the hosts it may be sent to, and how it is presented
//! there: a host-bound application secret (#4003), and later the `bound`
//! credential kind (#5043), which shares these rules. The rules are
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound application secrets".
//! Everything here is parsed once, at the edge, into types that cannot hold
//! a binding the front door would refuse.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ANTIGRAVITY_HOSTS, CLAUDE_TOKEN_HOST, FRONT_DOOR_HOSTS, GEMINI_API_HOST, GITHUB_HOSTS,
};

/// The most hosts one binding names.
pub const MAX_BOUND_HOSTS: usize = 16;
/// The most bound-secret hosts one environment's selection binds, so that with
/// the provider hosts it stays under what `cw-egress` carries.
pub const MAX_BOUND_HOSTS_PER_ENVIRONMENT: usize = 16;
/// The most header names one binding sends its value in.
pub const MAX_BOUND_HEADERS: usize = 2;
/// The longest placeholder prefix.
pub const MAX_PLACEHOLDER_PREFIX_LENGTH: usize = 16;
/// The longest bound value.
pub const MAX_BOUND_VALUE_BYTES: usize = 8 * 1024;
/// The user name a `basic` binding sends when none is given.
pub const DEFAULT_BASIC_USERNAME: &str = "x-access-token";
/// The header a `header` binding sends its value in when none is given.
pub const DEFAULT_BOUND_HEADER: &str = "Authorization";
/// The scheme a `header` binding puts before its value when none is given.
pub const DEFAULT_BOUND_SCHEME: &str = "Bearer";

const MAX_HOST_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;
const MAX_TOKEN_LENGTH: usize = 64;
const PLACEHOLDER_MARKER: &str = "cwp1_";
const MAX_PRESET_LENGTH: usize = 32;

/// Suffixes no public name ends in.
const INTERNAL_SUFFIXES: [&str; 6] = [
    "localhost",
    "local",
    "internal",
    "arpa",
    "cluster.local",
    "svc",
];

/// Headers the proxy controls, or that servers log or echo, compared in
/// lowercase. Names starting `x-forwarded-`, `proxy-` or `codewire-` are
/// refused as well.
const REFUSED_HEADERS: [&str; 22] = [
    "host",
    "cookie",
    "set-cookie",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "via",
    "max-forwards",
    "early-data",
    "forwarded",
    "origin",
    "referer",
    "user-agent",
    "x-request-id",
    "traceparent",
];
const REFUSED_HEADER_PREFIXES: [&str; 3] = ["x-forwarded-", "proxy-", "codewire-"];
const TRACESTATE: &str = "tracestate";

/// Why a binding, or a value for one, is refused. Each message is the one a
/// person reads, naming what they gave.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("{0} can't be bound: name each host exactly")]
    Wildcard(String),
    #[error("{0} can't be bound: an IP address")]
    IpAddress(String),
    #[error("{0} can't be bound: only port 443")]
    Port(String),
    #[error("{0} can't be bound: not a public name")]
    NotPublic(String),
    #[error("{0} can't be bound: not a host name")]
    InvalidHost(String),
    #[error("{0} is a provider host Codewire connects for you")]
    ProviderHost(String),
    #[error("{0} can't be bound: Codewire serves it itself")]
    DeploymentHost(String),
    #[error("a binding names at least one host")]
    NoHosts,
    #[error("a secret can be sent to at most {MAX_BOUND_HOSTS} hosts")]
    TooManyHosts,
    #[error("{0} is named twice")]
    DuplicateHost(String),
    #[error("{0} can't carry a bound secret: the proxy sets it, or servers log or echo it")]
    RefusedHeader(String),
    #[error("{0} isn't a header name")]
    InvalidHeader(String),
    #[error("a binding sends its value in at most {MAX_BOUND_HEADERS} headers")]
    TooManyHeaders,
    #[error("the header {0} is named twice")]
    DuplicateHeader(String),
    #[error("the scheme must be one word of letters, digits and !#$%&'*+-.^_`|~")]
    InvalidScheme,
    #[error("the user name can use letters, digits and -._~, up to {MAX_TOKEN_LENGTH}")]
    InvalidUsername,
    #[error(
        "the prefix can use letters, digits, _ and -, up to {MAX_PLACEHOLDER_PREFIX_LENGTH}, and not {PLACEHOLDER_MARKER}"
    )]
    InvalidPrefix,
    #[error("a bound secret's value must be printable ASCII, at most 8 KiB")]
    InvalidValue,
    #[error("a Basic user name can't contain ':'")]
    BasicUserColon,
    #[error("the deployment's own name {0} isn't a host name")]
    InvalidDeploymentName(String),
    #[error("a preset's name is lowercase letters, digits and -, up to {MAX_PRESET_LENGTH}")]
    InvalidPreset,
}

impl BindingError {
    /// The stable code a refusal carries on the wire.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProviderHost(_) => "bound_host_provider",
            Self::DeploymentHost(_) => "bound_host_reserved",
            _ => "secret_binding_invalid",
        }
    }
}

/// The names no binding may name: every host a built-in credential names, and
/// the deployment's own service names, which come from its configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReservedHosts {
    deployment: BTreeSet<String>,
    /// Each of these and every name under it, such as a preview domain.
    deployment_suffixes: BTreeSet<String>,
}

impl ReservedHosts {
    /// The reserved set for a deployment whose own services answer at
    /// `deployment_names`: the Sandbox gateway's names, the identity issuer,
    /// the registries, the forge and the rest of its configuration. An entry
    /// `*.example.com` reserves `example.com` and every name under it.
    pub fn new<'a>(
        deployment_names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, BindingError> {
        let mut reserved = Self::default();
        for entry in deployment_names {
            let invalid = || BindingError::InvalidDeploymentName(entry.to_owned());
            match entry.strip_prefix("*.") {
                Some(suffix) => {
                    let suffix = canonical_name(suffix).ok_or_else(invalid)?;
                    reserved.deployment_suffixes.insert(suffix);
                }
                None => {
                    let name = canonical_name(entry).ok_or_else(invalid)?;
                    reserved.deployment.insert(name);
                }
            }
        }
        Ok(reserved)
    }

    fn check(&self, host: &str) -> Result<(), BindingError> {
        if is_provider_host(host) {
            return Err(BindingError::ProviderHost(host.to_owned()));
        }
        let under_suffix = self.deployment_suffixes.iter().any(|suffix| {
            host == suffix
                || host
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|label| label.ends_with('.'))
        });
        if self.deployment.contains(host) || under_suffix {
            return Err(BindingError::DeploymentHost(host.to_owned()));
        }
        Ok(())
    }
}

/// Whether a built-in credential names `host`: the front door's provider
/// table, Claude's token host, GitHub's hosts, Gemini's API host,
/// Antigravity's hosts and every name under `chatgpt.com`.
pub fn is_provider_host(host: &str) -> bool {
    FRONT_DOOR_HOSTS.iter().any(|entry| entry.host == host)
        || host == CLAUDE_TOKEN_HOST
        || GITHUB_HOSTS.contains(&host)
        || host == GEMINI_API_HOST
        || ANTIGRAVITY_HOSTS.contains(&host)
        || host.ends_with(".chatgpt.com")
}

/// One exact public DNS name a value may be sent to on port 443, in
/// canonical lowercase form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundHost(String);

impl BoundHost {
    /// Parse what a person typed: an exact name, optionally `:443`. Case is
    /// folded; a trailing dot, a wildcard, an address, another port, a
    /// single label or an internal suffix is refused, never normalised.
    pub fn parse(input: &str, reserved: &ReservedHosts) -> Result<Self, BindingError> {
        let refuse = |error: fn(String) -> BindingError| Err(error(input.to_owned()));
        if input.contains('*') {
            return refuse(BindingError::Wildcard);
        }
        let name = match input.rsplit_once(':') {
            Some((name, "443")) if !name.contains(':') => name,
            Some((name, port))
                if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                return refuse(BindingError::Port);
            }
            Some(_) if input.matches(':').count() > 1 => return refuse(BindingError::IpAddress),
            Some(_) => return refuse(BindingError::InvalidHost),
            None => input,
        };
        if name.starts_with('[') || name.parse::<std::net::Ipv4Addr>().is_ok() {
            return refuse(BindingError::IpAddress);
        }
        let Some(host) = canonical_name(name) else {
            return refuse(BindingError::InvalidHost);
        };
        if !host.contains('.')
            || INTERNAL_SUFFIXES
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        {
            return refuse(BindingError::NotPublic);
        }
        if host
            .rsplit('.')
            .next()
            // No top-level domain starts with a digit, and a URL parser reads
            // `1.2.3.0x4` as an IPv4 address.
            .is_some_and(|tld| tld.starts_with(|c: char| c.is_ascii_digit()))
        {
            return refuse(BindingError::IpAddress);
        }
        reserved.check(&host)?;
        Ok(Self(host))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// `name` in canonical lowercase form, if it is an LDH host name: labels of
/// letters, digits and inner hyphens, none empty, no trailing dot. Anything
/// else, including an IDN in Unicode, is `None`.
fn canonical_name(name: &str) -> Option<String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_HOST_LENGTH
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LENGTH
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    valid.then(|| name.to_ascii_lowercase())
}

/// A header a bound value is sent in: an RFC 9110 token that is not one the
/// proxy controls or that servers log or echo. It keeps the case it was
/// given, for display, and compares without case.
#[derive(Clone, Debug)]
pub struct BoundHeader(String);

impl BoundHeader {
    pub fn parse(input: &str) -> Result<Self, BindingError> {
        if !is_token(input) {
            return Err(BindingError::InvalidHeader(input.to_owned()));
        }
        let lower = input.to_ascii_lowercase();
        if REFUSED_HEADERS.contains(&lower.as_str())
            || lower == TRACESTATE
            || REFUSED_HEADER_PREFIXES
                .iter()
                .any(|prefix| lower.starts_with(prefix))
        {
            return Err(BindingError::RefusedHeader(input.to_owned()));
        }
        Ok(Self(input.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, name: &str) -> bool {
        self.0.eq_ignore_ascii_case(name)
    }
}

impl PartialEq for BoundHeader {
    fn eq(&self, other: &Self) -> bool {
        self.matches(&other.0)
    }
}

impl Eq for BoundHeader {}

/// The word before the value in a `header` binding, or none for a header
/// that holds the value alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scheme {
    None,
    Word(String),
}

impl Scheme {
    /// `none` (in any case) means no scheme; anything else must be one token.
    pub fn parse(input: &str) -> Result<Self, BindingError> {
        if input.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        if !is_token(input) || input.len() > MAX_TOKEN_LENGTH {
            return Err(BindingError::InvalidScheme);
        }
        Ok(Self::Word(input.to_owned()))
    }
}

/// How the value is presented on a bound host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presentation {
    /// `<scheme> <value>` in one or two headers.
    Header {
        headers: Vec<BoundHeader>,
        scheme: Scheme,
    },
    /// HTTP Basic, the value as the password and `username` as the user.
    Basic { username: String },
    /// HTTP Basic, the value as the user name and an empty password.
    BasicUser,
}

impl Presentation {
    /// `Authorization: Bearer <value>`.
    pub fn default_header() -> Self {
        Self::Header {
            headers: vec![BoundHeader(DEFAULT_BOUND_HEADER.to_owned())],
            scheme: Scheme::Word(DEFAULT_BOUND_SCHEME.to_owned()),
        }
    }

    /// A `header` presentation: 1 or 2 distinct headers and a scheme.
    pub fn header(headers: Vec<BoundHeader>, scheme: Scheme) -> Result<Self, BindingError> {
        if headers.is_empty() {
            return Ok(Self::Header {
                headers: vec![BoundHeader(DEFAULT_BOUND_HEADER.to_owned())],
                scheme,
            });
        }
        if headers.len() > MAX_BOUND_HEADERS {
            return Err(BindingError::TooManyHeaders);
        }
        if let [first, second] = headers.as_slice()
            && first == second
        {
            return Err(BindingError::DuplicateHeader(second.0.clone()));
        }
        Ok(Self::Header { headers, scheme })
    }

    /// A `basic` presentation; `None` takes [`DEFAULT_BASIC_USERNAME`].
    pub fn basic(username: Option<&str>) -> Result<Self, BindingError> {
        let username = username.unwrap_or(DEFAULT_BASIC_USERNAME);
        let valid = !username.is_empty()
            && username.len() <= MAX_TOKEN_LENGTH
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if !valid {
            return Err(BindingError::InvalidUsername);
        }
        Ok(Self::Basic {
            username: username.to_owned(),
        })
    }
}

/// Text put before the placeholder for a client that checks a key's shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderPrefix(String);

impl PlaceholderPrefix {
    pub fn parse(input: &str) -> Result<Self, BindingError> {
        let valid = !input.is_empty()
            && input.len() <= MAX_PLACEHOLDER_PREFIX_LENGTH
            && !input.contains(PLACEHOLDER_MARKER)
            && input
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
        if !valid {
            return Err(BindingError::InvalidPrefix);
        }
        Ok(Self(input.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The hosts a value may be sent to and how it is presented there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBinding {
    hosts: BTreeSet<BoundHost>,
    presentation: Presentation,
    prefix: Option<PlaceholderPrefix>,
}

impl HostBinding {
    /// One to [`MAX_BOUND_HOSTS`] distinct hosts.
    pub fn new(
        hosts: Vec<BoundHost>,
        presentation: Presentation,
        prefix: Option<PlaceholderPrefix>,
    ) -> Result<Self, BindingError> {
        if hosts.is_empty() {
            return Err(BindingError::NoHosts);
        }
        if hosts.len() > MAX_BOUND_HOSTS {
            return Err(BindingError::TooManyHosts);
        }
        let mut set = BTreeSet::new();
        for host in hosts {
            if let Some(duplicate) = set.replace(host) {
                return Err(BindingError::DuplicateHost(duplicate.0));
            }
        }
        Ok(Self {
            hosts: set,
            presentation,
            prefix,
        })
    }

    pub fn hosts(&self) -> impl ExactSizeIterator<Item = &BoundHost> {
        self.hosts.iter()
    }

    pub fn names(&self, host: &str) -> bool {
        self.hosts.iter().any(|bound| bound.0 == host)
    }

    pub fn presentation(&self) -> &Presentation {
        &self.presentation
    }

    pub fn prefix(&self) -> Option<&PlaceholderPrefix> {
        self.prefix.as_ref()
    }

    /// Check a value for this binding before it is stored.
    pub fn validate_value(&self, value: &[u8]) -> Result<(), BindingError> {
        if value.is_empty()
            || value.len() > MAX_BOUND_VALUE_BYTES
            || !value.iter().all(|b| (0x20..=0x7e).contains(b))
        {
            return Err(BindingError::InvalidValue);
        }
        if self.presentation == Presentation::BasicUser && value.contains(&b':') {
            return Err(BindingError::BasicUserColon);
        }
        Ok(())
    }
}

/// The form a binding is stored and carried in: what a person chose, before
/// validation. [`StoredBinding::parse`] turns it into a [`HostBinding`], so a
/// stored binding is checked again every time it is read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBinding {
    pub hosts: Vec<String>,
    pub presentation: StoredPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The preset that filled it, shown to people; never validated or used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredPresentation {
    Header {
        headers: Vec<String>,
        /// `None` is no scheme: the header holds the value alone.
        scheme: Option<String>,
    },
    Basic {
        username: String,
    },
    BasicUser,
}

impl StoredBinding {
    pub fn parse(&self, reserved: &ReservedHosts) -> Result<HostBinding, BindingError> {
        let hosts = self
            .hosts
            .iter()
            .map(|host| BoundHost::parse(host, reserved))
            .collect::<Result<_, _>>()?;
        let presentation = match &self.presentation {
            StoredPresentation::Header { headers, scheme } => Presentation::header(
                headers
                    .iter()
                    .map(|header| BoundHeader::parse(header))
                    .collect::<Result<_, _>>()?,
                match scheme {
                    None => Scheme::None,
                    Some(word) => Scheme::parse(word)?,
                },
            )?,
            StoredPresentation::Basic { username } => Presentation::basic(Some(username))?,
            StoredPresentation::BasicUser => Presentation::BasicUser,
        };
        let prefix = self
            .prefix
            .as_deref()
            .map(PlaceholderPrefix::parse)
            .transpose()?;
        if let Some(preset) = &self.preset {
            let valid = !preset.is_empty()
                && preset.len() <= MAX_PRESET_LENGTH
                && preset
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !valid {
                return Err(BindingError::InvalidPreset);
            }
        }
        HostBinding::new(hosts, presentation, prefix)
    }
}

impl From<&HostBinding> for StoredBinding {
    fn from(binding: &HostBinding) -> Self {
        let presentation = match &binding.presentation {
            Presentation::Header { headers, scheme } => StoredPresentation::Header {
                headers: headers.iter().map(|header| header.0.clone()).collect(),
                scheme: match scheme {
                    Scheme::None => None,
                    Scheme::Word(word) => Some(word.clone()),
                },
            },
            Presentation::Basic { username } => StoredPresentation::Basic {
                username: username.clone(),
            },
            Presentation::BasicUser => StoredPresentation::BasicUser,
        };
        Self {
            hosts: binding.hosts.iter().map(|host| host.0.clone()).collect(),
            presentation,
            prefix: binding.prefix.as_ref().map(|prefix| prefix.0.clone()),
            preset: None,
        }
    }
}

/// Whether changing a secret's binding from `before` to `after` needs its
/// value entered again (`None` is plain): adding a host, the first one
/// included, replacing one, changing the presentation, and making it plain.
/// Removing some of its hosts and changing the prefix don't.
pub fn change_needs_value(before: Option<&HostBinding>, after: Option<&HostBinding>) -> bool {
    match (before, after) {
        (None, None) => false,
        (None, Some(_)) | (Some(_), None) => true,
        (Some(before), Some(after)) => {
            before.presentation != after.presentation || !after.hosts.is_subset(&before.hosts)
        }
    }
}

/// Whether the change moves the binding's generation, which changes its
/// placeholder: anything but its hosts or its value.
pub fn change_moves_generation(before: Option<&HostBinding>, after: Option<&HostBinding>) -> bool {
    match (before, after) {
        (None, None) => false,
        (None, Some(_)) | (Some(_), None) => true,
        (Some(before), Some(after)) => {
            before.presentation != after.presentation || before.prefix != after.prefix
        }
    }
}

/// RFC 9110 `token`: one or more tchar.
fn is_token(input: &str) -> bool {
    !input.is_empty()
        && input.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests;
