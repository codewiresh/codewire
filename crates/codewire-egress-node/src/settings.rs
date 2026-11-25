//! cw-egress's node settings (#4000), read once at start. A value that is
//! missing or does not parse stops cw-egress before it serves anything.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use codewire_egress_policy::host_addresses::{
    AddressPrefix, HostAddressError, HostAddressSet, PrefixError,
};

use crate::drain::{DRAIN_SECONDS, DrainSettingError, drain_deadline};

/// The origin cw-egress calls. Its host is only the name TLS verifies: the
/// Pod has no cluster DNS, so it never resolves (cw-network's review, #4000).
pub const ORCHESTRATION_URL: &str = "CODEWIRE_EGRESS_ORCHESTRATION_URL";
/// The IP address and port cw-egress dials for that origin. The connection
/// always takes the origin's port, so the two must agree.
pub const ORCHESTRATION_ADDR: &str = "CODEWIRE_EGRESS_ORCHESTRATION_ADDR";
pub const ORCHESTRATION_ROOTS: &str = "CODEWIRE_EGRESS_ORCHESTRATION_ROOTS";
pub const NODE_TOKEN_PATH: &str = "CODEWIRE_EGRESS_NODE_TOKEN_PATH";
/// The cluster's own public addresses and prefixes, comma-separated, which
/// every broker refuses as an ordinary "not allowed" (#4000). Rendered by the
/// deployment; empty refuses none beyond the fixed ranges. A prefix is at most
/// a /24 or a /48, with no bits past its length.
pub const REFUSED_ADDRESSES: &str = "CODEWIRE_EGRESS_REFUSED_ADDRESSES";

#[derive(Debug)]
pub struct NodeSettings {
    pub orchestration_url: String,
    pub orchestration_address: SocketAddr,
    pub orchestration_roots: PathBuf,
    pub node_token_path: PathBuf,
    pub drain: Duration,
    pub refused: HostAddressSet,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettingsError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error(transparent)]
    Drain(#[from] DrainSettingError),
    #[error("{ORCHESTRATION_ADDR} is not an IP address and port")]
    OrchestrationAddress,
    #[error("{ORCHESTRATION_URL} is not an https URL")]
    OrchestrationUrl,
    #[error("{ORCHESTRATION_ADDR} names port {addr}, but {ORCHESTRATION_URL} port {url}")]
    OrchestrationPorts { addr: u16, url: u16 },
    #[error("{REFUSED_ADDRESSES}: {entry:?} {reason}")]
    RefusedAddress { entry: String, reason: PrefixError },
    #[error("{REFUSED_ADDRESSES}: {0}")]
    TooManyRefused(HostAddressError),
}

impl NodeSettings {
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    fn from_values(value: impl Fn(&str) -> Option<String>) -> Result<Self, SettingsError> {
        let required = |name: &'static str| {
            value(name)
                .filter(|value| !value.trim().is_empty())
                .ok_or(SettingsError::Missing(name))
        };
        let refused = value(REFUSED_ADDRESSES)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<AddressPrefix>()
                    .map_err(|reason| SettingsError::RefusedAddress {
                        entry: entry.to_owned(),
                        reason,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let orchestration_url = required(ORCHESTRATION_URL)?;
        let orchestration_address: SocketAddr = required(ORCHESTRATION_ADDR)?
            .trim()
            .parse()
            .map_err(|_| SettingsError::OrchestrationAddress)?;
        let url_port = origin_port(&orchestration_url)?;
        if orchestration_address.port() != url_port {
            return Err(SettingsError::OrchestrationPorts {
                addr: orchestration_address.port(),
                url: url_port,
            });
        }
        Ok(Self {
            orchestration_url,
            orchestration_address,
            orchestration_roots: PathBuf::from(required(ORCHESTRATION_ROOTS)?),
            node_token_path: PathBuf::from(required(NODE_TOKEN_PATH)?),
            drain: drain_deadline(value(DRAIN_SECONDS).as_deref())?,
            refused: HostAddressSet::with_prefixes([], refused)
                .map_err(SettingsError::TooManyRefused)?,
        })
    }
}

/// The port a connection to `url` uses: its own, or https's.
fn origin_port(url: &str) -> Result<u16, SettingsError> {
    let uri = url
        .parse::<http::Uri>()
        .map_err(|_| SettingsError::OrchestrationUrl)?;
    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) || uri.host().is_none() {
        return Err(SettingsError::OrchestrationUrl);
    }
    Ok(uri.port_u16().unwrap_or(443))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Result<NodeSettings, SettingsError> {
        let values: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        NodeSettings::from_values(|name| values.get(name).cloned())
    }

    const BASE: [(&str, &str); 5] = [
        (ORCHESTRATION_URL, "https://orchestration.example:8088"),
        (ORCHESTRATION_ADDR, "10.96.0.20:8088"),
        (ORCHESTRATION_ROOTS, "/run/roots/ca.crt"),
        (NODE_TOKEN_PATH, "/run/token"),
        (DRAIN_SECONDS, "1800"),
    ];

    #[test]
    fn every_required_setting_must_be_present() {
        let ok = settings(&BASE).unwrap();
        assert_eq!(ok.drain, Duration::from_secs(1800));
        assert_eq!(ok.orchestration_roots, PathBuf::from("/run/roots/ca.crt"));
        assert_eq!(
            ok.orchestration_address,
            SocketAddr::from(([10, 96, 0, 20], 8088))
        );
        for missing in [
            ORCHESTRATION_URL,
            ORCHESTRATION_ADDR,
            ORCHESTRATION_ROOTS,
            NODE_TOKEN_PATH,
        ] {
            let without: Vec<_> = BASE
                .iter()
                .copied()
                .filter(|(name, _)| *name != missing)
                .collect();
            assert_eq!(
                settings(&without).unwrap_err(),
                SettingsError::Missing(missing)
            );
        }
        let no_drain: Vec<_> = BASE
            .iter()
            .copied()
            .filter(|(name, _)| *name != DRAIN_SECONDS)
            .collect();
        assert!(matches!(settings(&no_drain), Err(SettingsError::Drain(_))));
    }

    fn with(name: &'static str, value: &'static str) -> Vec<(&'static str, &'static str)> {
        let mut pairs = BASE.to_vec();
        pairs.retain(|(other, _)| *other != name);
        pairs.push((name, value));
        pairs
    }

    #[test]
    fn the_orchestration_address_is_an_ip_and_the_urls_port() {
        for named in ["codewire-orchestration.codewire.svc:8088", "10.96.0.20"] {
            assert_eq!(
                settings(&with(ORCHESTRATION_ADDR, named)).unwrap_err(),
                SettingsError::OrchestrationAddress,
                "{named}"
            );
        }
        assert_eq!(
            settings(&with(ORCHESTRATION_ADDR, "10.96.0.20:8089")).unwrap_err(),
            SettingsError::OrchestrationPorts {
                addr: 8089,
                url: 8088
            }
        );
        // An origin without a port is reached on https's.
        let mut default_port = with(ORCHESTRATION_URL, "https://orchestration.example");
        default_port.retain(|(name, _)| *name != ORCHESTRATION_ADDR);
        default_port.push((ORCHESTRATION_ADDR, "[fd00::20]:443"));
        assert!(settings(&default_port).is_ok());
        assert_eq!(
            settings(&with(
                ORCHESTRATION_URL,
                "http://orchestration.example:8088"
            ))
            .unwrap_err(),
            SettingsError::OrchestrationUrl
        );
    }

    #[test]
    fn refused_addresses_parse_and_a_bad_one_stops_start() {
        let mut with = BASE.to_vec();
        with.push((REFUSED_ADDRESSES, " 203.0.113.9, 2001:db8::1 ,"));
        let parsed = settings(&with).unwrap();
        assert!(
            parsed
                .refused
                .classify("203.0.113.9".parse().unwrap())
                .is_some()
        );
        assert!(
            parsed
                .refused
                .classify("2001:db8::1".parse().unwrap())
                .is_some()
        );
        assert!(
            parsed
                .refused
                .classify("198.51.100.1".parse().unwrap())
                .is_none()
        );
        let mut bad = BASE.to_vec();
        bad.push((REFUSED_ADDRESSES, "203.0.113.9, api.example.com"));
        assert_eq!(
            settings(&bad).unwrap_err(),
            SettingsError::RefusedAddress {
                entry: "api.example.com".into(),
                reason: PrefixError::Malformed
            }
        );
    }

    #[test]
    fn refused_prefixes_parse_and_each_broken_rule_is_named() {
        let mut with = BASE.to_vec();
        with.push((REFUSED_ADDRESSES, "203.0.113.9,2001:db8:5:7::/64"));
        let parsed = settings(&with).unwrap();
        assert!(
            parsed
                .refused
                .classify("2001:db8:5:7::abcd".parse().unwrap())
                .is_some()
        );
        assert!(
            parsed
                .refused
                .classify("2001:db8:5:8::".parse().unwrap())
                .is_none()
        );

        for (value, error) in [
            (
                "203.0.113.9/24",
                "CODEWIRE_EGRESS_REFUSED_ADDRESSES: \"203.0.113.9/24\" has bits set past its /24",
            ),
            (
                "198.51.100.0/23",
                "CODEWIRE_EGRESS_REFUSED_ADDRESSES: \"198.51.100.0/23\" is wider than /24, the widest allowed",
            ),
            (
                "2001:db8::/32",
                "CODEWIRE_EGRESS_REFUSED_ADDRESSES: \"2001:db8::/32\" is wider than /48, the widest allowed",
            ),
        ] {
            let mut bad = BASE.to_vec();
            bad.push((REFUSED_ADDRESSES, value));
            assert_eq!(settings(&bad).unwrap_err().to_string(), error);
        }

        let at_cap: Vec<String> = (0..64).map(|n| format!("198.51.100.{n}")).collect();
        let over_cap: Vec<String> = (0..65).map(|n| format!("198.51.100.{n}")).collect();
        let (at_cap, over_cap) = (at_cap.join(","), over_cap.join(","));
        let mut at = BASE.to_vec();
        at.push((REFUSED_ADDRESSES, at_cap.as_str()));
        assert!(settings(&at).is_ok());
        let mut over = BASE.to_vec();
        over.push((REFUSED_ADDRESSES, over_cap.as_str()));
        assert_eq!(
            settings(&over).unwrap_err().to_string(),
            "CODEWIRE_EGRESS_REFUSED_ADDRESSES: 65 network public entries, over the cap of 64"
        );
    }
}
