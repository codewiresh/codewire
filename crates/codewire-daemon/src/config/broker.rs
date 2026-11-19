//! A hosted egress Pod's platform addresses (#4000;
//! `designs/hosted-egress.md`, "The daemon's platform path").
//!
//! Broker mode is exactly a rendered [`EGRESS_STREAM_ADDR_ENV`]. Its daemon
//! resolves no names: every platform peer is an `IPv4:port` from the Pod's
//! configuration, the peer's URL keeping the TLS name, and a missing or
//! malformed one stops the start and names its variable.

use std::ffi::OsString;
use std::net::SocketAddrV4;

use codewire_daemon_proto::{
    API_ADDR_ENV, COORDINATOR_ADDR_ENV, DERP_ADDR_ENV, EGRESS_STREAM_ADDR_ENV, MESH_ADDR_ENV,
    WORKSPACE_BINDING_ADDR_ENV,
};

use super::ConfigError;

/// Where a broker-mode daemon reaches each platform peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerPlatform {
    stream: SocketAddrV4,
    binding: SocketAddrV4,
    coordinator: SocketAddrV4,
    mesh: Option<SocketAddrV4>,
    derp: DerpAddress,
}

/// The deployment's own DERP relay: the hostname the DERP map gives it and
/// the address the daemon dials for that hostname, under that name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpAddress {
    host: String,
    address: SocketAddrV4,
}

impl BrokerPlatform {
    /// [`Self::from_lookup`] over the process environment.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_lookup(&|name| std::env::var_os(name))
    }

    /// None when no stream address is rendered: the Pod is not in broker
    /// mode, and its daemon dials as before.
    pub fn from_lookup(
        lookup: &impl Fn(&str) -> Option<OsString>,
    ) -> Result<Option<Self>, ConfigError> {
        if lookup(EGRESS_STREAM_ADDR_ENV).is_none() {
            return Ok(None);
        }
        let required = |name| address(lookup, name)?.ok_or(ConfigError::BrokerAddress(name));
        let api = address(lookup, API_ADDR_ENV)?;
        // The coordinator's own address, else the API's, else the start
        // stops: never a lookup of the coordinator URL's host.
        let coordinator = match address(lookup, COORDINATOR_ADDR_ENV)?.or(api) {
            Some(coordinator) => coordinator,
            None => return Err(ConfigError::BrokerAddress(API_ADDR_ENV)),
        };
        Ok(Some(Self {
            stream: required(EGRESS_STREAM_ADDR_ENV)?,
            binding: required(WORKSPACE_BINDING_ADDR_ENV)?,
            coordinator,
            mesh: address(lookup, MESH_ADDR_ENV)?,
            derp: DerpAddress::from_lookup(lookup)?,
        }))
    }

    /// cw-egress's stream address on the Pod's node.
    pub fn stream(&self) -> SocketAddrV4 {
        self.stream
    }

    /// The workspace binding's address.
    pub fn binding(&self) -> SocketAddrV4 {
        self.binding
    }

    /// The tailnet coordinator's address.
    pub fn coordinator(&self) -> SocketAddrV4 {
        self.coordinator
    }

    /// Mesh's address; None when the deployment renders no Mesh, and a Mesh
    /// URL in the access grant is then refused rather than looked up.
    pub fn mesh(&self) -> Option<SocketAddrV4> {
        self.mesh
    }

    /// The deployment's own DERP relay.
    pub fn derp(&self) -> &DerpAddress {
        &self.derp
    }
}

impl DerpAddress {
    fn from_lookup(lookup: &impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let value = lookup(DERP_ADDR_ENV).ok_or(ConfigError::BrokerDerpAddress)?;
        let (host, address) = value
            .to_str()
            .and_then(|value| value.split_once('='))
            .filter(|(host, _)| dns_name(host))
            .ok_or(ConfigError::BrokerDerpAddress)?;
        Ok(Self {
            host: host.to_owned(),
            address: socket_address(address).ok_or(ConfigError::BrokerDerpAddress)?,
        })
    }

    /// The DERP map hostname this address stands for.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The address dialled for [`Self::host`].
    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }
}

/// `name`'s address: None when unset; refused when set to anything but
/// `IPv4:port` with a nonzero port.
fn address(
    lookup: &impl Fn(&str) -> Option<OsString>,
    name: &'static str,
) -> Result<Option<SocketAddrV4>, ConfigError> {
    match lookup(name) {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .and_then(socket_address)
            .map(Some)
            .ok_or(ConfigError::BrokerAddress(name)),
    }
}

fn socket_address(value: &str) -> Option<SocketAddrV4> {
    value
        .parse::<SocketAddrV4>()
        .ok()
        .filter(|address| address.port() != 0)
}

/// A lowercase multi-label DNS name with no trailing dot, as a DERP map
/// names its nodes.
fn dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests;
