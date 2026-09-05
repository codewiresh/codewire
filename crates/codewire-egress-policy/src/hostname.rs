use std::fmt;
use std::net::IpAddr;

use crate::{NameClass, PolicyError};

pub(crate) const MAX_HOSTNAME_BYTES: usize = 253;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NamePattern {
    Any,
    Exact(String),
    Suffix(String),
}

impl NamePattern {
    pub(crate) fn parse(value: &str, rule_id: &str) -> Result<Self, PolicyError> {
        if value == "*" {
            return Ok(Self::Any);
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            let suffix = canonical_hostname(suffix).map_err(|detail| PolicyError::InvalidRule {
                rule_id: rule_id.to_string(),
                field: "destinations",
                detail,
            })?;
            return Ok(Self::Suffix(suffix));
        }
        canonical_hostname(value)
            .map(Self::Exact)
            .map_err(|detail| PolicyError::InvalidRule {
                rule_id: rule_id.to_string(),
                field: "destinations",
                detail,
            })
    }

    pub(crate) fn matches(&self, hostname: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => hostname == expected,
            Self::Suffix(suffix) => {
                hostname.len() > suffix.len()
                    && hostname.ends_with(suffix)
                    && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => formatter.write_str("*"),
            Self::Exact(value) => formatter.write_str(value),
            Self::Suffix(value) => write!(formatter, "*.{value}"),
        }
    }
}

pub(crate) fn canonical_hostname(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_HOSTNAME_BYTES || value.trim() != value {
        return Err("hostname must be a bounded canonical value".to_string());
    }
    if !value.is_ascii() {
        return Err("hostname must use ASCII or normalized punycode".to_string());
    }
    let without_dot = value.strip_suffix('.').unwrap_or(value);
    if without_dot.is_empty() || without_dot.ends_with('.') {
        return Err("hostname has an invalid trailing dot".to_string());
    }
    let canonical = without_dot.to_ascii_lowercase();
    if canonical.parse::<IpAddr>().is_ok() {
        return Err("hostname must not be an IP literal".to_string());
    }
    for label in canonical.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("hostname contains an invalid DNS label".to_string());
        }
    }
    Ok(canonical)
}

pub(crate) fn protected_name(hostname: &str) -> Option<NameClass> {
    if hostname == "metadata.google.internal" || hostname == "instance-data" {
        return Some(NameClass::Metadata);
    }
    const PROTECTED_SUFFIXES: [(&str, NameClass); 7] = [
        ("localhost", NameClass::Localhost),
        ("local", NameClass::Local),
        ("internal", NameClass::Internal),
        ("home.arpa", NameClass::Home),
        ("invalid", NameClass::Reserved),
        ("test", NameClass::Reserved),
        ("example", NameClass::Reserved),
    ];
    for (suffix, class) in PROTECTED_SUFFIXES {
        if hostname == suffix
            || (hostname.len() > suffix.len()
                && hostname.ends_with(suffix)
                && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.')
        {
            return Some(class);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_canonical_and_ip_literals_are_not_names() {
        assert_eq!(
            canonical_hostname("API.Example.COM.").unwrap(),
            "api.example.com"
        );
        for invalid in [
            "",
            ".",
            "two..dots",
            "-bad.example",
            "bad-.example",
            "bad_name.example",
            "127.0.0.1",
            "::1",
            " café.example",
        ] {
            assert!(canonical_hostname(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn wildcards_match_subdomains_but_not_the_apex_or_adjacent_suffixes() {
        let pattern = NamePattern::parse("*.example.com", "rule").unwrap();
        assert!(pattern.matches("api.example.com"));
        assert!(pattern.matches("deep.api.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("notexample.com"));
    }

    #[test]
    fn protected_suffixes_require_label_boundaries() {
        assert_eq!(protected_name("localhost"), Some(NameClass::Localhost));
        assert_eq!(protected_name("api.localhost"), Some(NameClass::Localhost));
        assert_eq!(
            protected_name("service.internal"),
            Some(NameClass::Internal)
        );
        assert_eq!(
            protected_name("metadata.google.internal"),
            Some(NameClass::Metadata)
        );
        assert_eq!(protected_name("notinternal"), None);
        assert_eq!(protected_name("example.com"), None);
    }
}
