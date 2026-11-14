//! HTTPS hostnames for a local environment's labelled ports (#4316).
//!
//! A `ports:` entry with a `label` is served at
//! `https://<label>-<environment>.cw.localhost` by one router in the per-user
//! supervisor, on `127.0.0.1`. The router reads the server name from the TLS
//! ClientHello, refuses any name that is not a running environment's labelled
//! port, and completes the handshake with a leaf from the user's local CA
//! ([`ca::LocalCa`]). It then sends each request to the same port on the
//! workload's loopback through the daemon's `ForwardTcp`
//! ([`crate::guest_loopback`]), so a server bound only to `127.0.0.1` answers.
//! The TLS, HTTP/1.1, HTTP/2 and WebSocket handling is the egress front
//! door's.
//!
//! Browsers resolve every `*.localhost` name to loopback without DNS, and
//! keep cookies per host, so two environments' copies of one app keep their
//! own sessions.

pub(crate) mod ca;
pub(crate) mod choice;
mod proxy;
mod router;

use std::future::Future;

use codewire_workspace_access::daemon::DaemonSessionClient;
use uuid::Uuid;

pub(crate) use router::{BindError, Router};

/// The name every local HTTPS hostname ends with.
pub const SUFFIX: &str = "cw.localhost";
/// The port the router listens on unless the user chose another.
pub const DEFAULT_PORT: u16 = 443;
/// The port offered when another program holds [`DEFAULT_PORT`].
pub const ALTERNATIVE_PORT: u16 = 8443;

/// The hostname a labelled port gets, `<label>-<environment>.cw.localhost`,
/// lowercase. `None` when that first part is not one DNS label of at most 63
/// letters, digits and inner hyphens.
pub fn hostname(label: &str, environment: &str) -> Option<String> {
    let first = format!("{label}-{environment}").to_ascii_lowercase();
    dns_label(&first).then(|| format!("{first}.{SUFFIX}"))
}

/// The URL a hostname is served at on `port`.
pub fn url(hostname: &str, port: u16) -> String {
    if port == DEFAULT_PORT {
        format!("https://{hostname}")
    } else {
        format!("https://{hostname}:{port}")
    }
}

/// Whether `host`, lowercase, is one DNS label under [`SUFFIX`]: the only
/// names the local CA signs.
pub(crate) fn under_suffix(host: &str) -> bool {
    host.strip_suffix(SUFFIX)
        .and_then(|rest| rest.strip_suffix('.'))
        .is_some_and(dns_label)
}

fn dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// The running environment and guest port a hostname names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) environment_id: Uuid,
    pub(crate) environment: String,
    pub(crate) guest_port: u16,
}

/// What the router asks the supervisor.
pub(crate) trait Routes: Send + Sync + 'static {
    /// The labelled port of a running environment that `host` names, if any.
    /// `host` is lowercase.
    fn route(&self, host: &str) -> Option<Route>;

    /// A client for the route's environment daemon, or `None` once the
    /// environment no longer runs.
    fn daemon(&self, route: &Route) -> impl Future<Output = Option<DaemonSessionClient>> + Send;
}

#[cfg(test)]
mod tests;
