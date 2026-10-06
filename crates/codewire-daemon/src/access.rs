//! The bound daemon's tailnet and SSH access grant (#2460).
//!
//! `BindWorkspace` and `RefreshAccess` return a `WorkspaceAccess` for the
//! binding's environment: a short-lived peer token for the public
//! coordinator, its expiry and operation generation, the coordinator origin
//! and the environment's public UDP endpoints. The daemon accepts a grant only
//! after validating every field, and never logs the peer token.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

/// Longest peer token the daemon accepts; a compact signed token is far
/// shorter.
const MAX_PEER_TOKEN_BYTES: usize = 4 * 1024;
/// A grant that names more endpoints than this is refused.
const MAX_ENDPOINTS: usize = 16;

/// The raw `WorkspaceAccess` fields, before validation.
pub struct AccessFields<'a> {
    pub peer_token: &'a str,
    pub peer_token_expires_at: i64,
    pub operation_generation: i64,
    pub coordinator_url: &'a str,
    pub direct_udp_endpoints: &'a [String],
    pub peer_relay_endpoints: &'a [String],
}

/// A peer token the daemon holds. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerToken(Zeroizing<String>);

impl PeerToken {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PeerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerToken([redacted])")
    }
}

/// A validated access grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceAccessGrant {
    peer_token: PeerToken,
    expires_at: SystemTime,
    operation_generation: u64,
    coordinator_url: String,
    direct_udp_endpoints: Vec<String>,
    peer_relay_endpoints: Vec<String>,
}

/// An access grant the daemon refused. Value-blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("workspace access grant is invalid")]
pub struct InvalidAccessGrant;

impl WorkspaceAccessGrant {
    /// Validate one grant against the clock `now`. The token must be
    /// unexpired, the generation positive, the coordinator an `https` origin
    /// and every endpoint a plain `host:port`.
    pub fn validate(
        fields: &AccessFields<'_>,
        now: SystemTime,
    ) -> Result<Self, InvalidAccessGrant> {
        let invalid = InvalidAccessGrant;
        let token = fields.peer_token;
        if token.is_empty()
            || token.len() > MAX_PEER_TOKEN_BYTES
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid);
        }
        let expires_at = u64::try_from(fields.peer_token_expires_at)
            .ok()
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
            .filter(|expires_at| *expires_at > now)
            .ok_or(invalid)?;
        let operation_generation = u64::try_from(fields.operation_generation)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or(invalid)?;
        if !valid_https_origin(fields.coordinator_url) {
            return Err(invalid);
        }
        let endpoints = |values: &[String]| -> Result<Vec<String>, InvalidAccessGrant> {
            if values.len() > MAX_ENDPOINTS || !values.iter().all(|value| valid_host_port(value)) {
                return Err(invalid);
            }
            Ok(values.to_vec())
        };
        Ok(Self {
            peer_token: PeerToken(Zeroizing::new(token.to_owned())),
            expires_at,
            operation_generation,
            coordinator_url: fields.coordinator_url.trim_end_matches('/').to_owned(),
            direct_udp_endpoints: endpoints(fields.direct_udp_endpoints)?,
            peer_relay_endpoints: endpoints(fields.peer_relay_endpoints)?,
        })
    }

    pub fn peer_token(&self) -> &PeerToken {
        &self.peer_token
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    pub fn operation_generation(&self) -> u64 {
        self.operation_generation
    }

    pub fn coordinator_url(&self) -> &str {
        &self.coordinator_url
    }

    pub fn direct_udp_endpoints(&self) -> &[String] {
        &self.direct_udp_endpoints
    }

    pub fn peer_relay_endpoints(&self) -> &[String] {
        &self.peer_relay_endpoints
    }

    /// When to fetch the next grant: half the remaining lifetime from `now`,
    /// so a refresh that fails once still has time to retry before expiry.
    pub fn refresh_at(&self, now: SystemTime) -> SystemTime {
        let remaining = self.expires_at.duration_since(now).unwrap_or_default();
        now + remaining / 2
    }
}

/// `https://host[:port]` with an optional trailing slash: no credentials,
/// path, query or fragment.
fn valid_https_origin(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    valid_host_port_or_host(authority)
}

fn valid_host_port(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    valid_host(host) && port.parse::<u16>().is_ok_and(|port| port > 0)
}

fn valid_host_port_or_host(value: &str) -> bool {
    match value.rsplit_once(':') {
        Some(_) => valid_host_port(value),
        None => valid_host(value),
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && !host.starts_with(['.', '-'])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "synthetic.peer.token";

    fn fields<'a>(
        coordinator: &'a str,
        direct: &'a [String],
        relay: &'a [String],
        expires_at: i64,
    ) -> AccessFields<'a> {
        AccessFields {
            peer_token: TOKEN,
            peer_token_expires_at: expires_at,
            operation_generation: 4,
            coordinator_url: coordinator,
            direct_udp_endpoints: direct,
            peer_relay_endpoints: relay,
        }
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    #[test]
    fn a_valid_grant_is_accepted_and_refreshes_at_half_life() {
        let direct = vec!["203.0.113.7:41641".to_owned()];
        let relay = vec!["relay.codewire.sh:41641".to_owned()];
        let grant = WorkspaceAccessGrant::validate(
            &fields("https://codewire.sh/", &direct, &relay, 1_000_600),
            now(),
        )
        .unwrap();
        assert_eq!(grant.peer_token().expose_secret(), TOKEN);
        assert_eq!(grant.coordinator_url(), "https://codewire.sh");
        assert_eq!(grant.operation_generation(), 4);
        assert_eq!(grant.refresh_at(now()), now() + Duration::from_secs(300));
        assert!(!format!("{grant:?}").contains(TOKEN));
    }

    #[test]
    fn invalid_grants_are_refused() {
        let ok: Vec<String> = Vec::new();
        for (coordinator, expires) in [
            ("http://codewire.sh", 1_000_600),
            ("https://user@codewire.sh", 1_000_600),
            ("https://codewire.sh/path", 1_000_600),
            ("", 1_000_600),
            ("https://codewire.sh", 1_000_000),
            ("https://codewire.sh", 999_000),
            ("https://codewire.sh", -1),
        ] {
            assert_eq!(
                WorkspaceAccessGrant::validate(&fields(coordinator, &ok, &ok, expires), now()),
                Err(InvalidAccessGrant),
                "{coordinator} {expires}"
            );
        }
        for endpoint in [
            "",
            "host",
            "host:0",
            "host:99999",
            "Host:1",
            "host:1/path",
            ":1",
        ] {
            let bad = vec![endpoint.to_owned()];
            assert_eq!(
                WorkspaceAccessGrant::validate(
                    &fields("https://codewire.sh", &bad, &ok, 1_000_600),
                    now()
                ),
                Err(InvalidAccessGrant),
                "{endpoint}"
            );
        }
        let mut generation_zero = fields("https://codewire.sh", &ok, &ok, 1_000_600);
        generation_zero.operation_generation = 0;
        assert!(WorkspaceAccessGrant::validate(&generation_zero, now()).is_err());
        let mut blank_token = fields("https://codewire.sh", &ok, &ok, 1_000_600);
        blank_token.peer_token = "";
        assert!(WorkspaceAccessGrant::validate(&blank_token, now()).is_err());
    }
}
