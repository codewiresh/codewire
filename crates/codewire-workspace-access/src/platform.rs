//! A hosted egress daemon's platform path (#4000; `designs/hosted-egress.md`,
//! "The daemon's platform path"): the coordinator, Mesh and the deployment's
//! own DERP relay at configured addresses, every connection opened by one
//! dial that binds it to the Pod's interface. The daemon looks no name up.

use std::net::SocketAddr;

use codewire_tailnet::platform_dial::TcpDial;

/// Where a broker-mode daemon's tailnet and Mesh connections go.
#[derive(Clone)]
pub struct DaemonPlatform {
    /// The tailnet coordinator, whose URL from the access grant keeps the TLS
    /// name. With no DERP map, DERP on the coordinator's origin is here too.
    pub coordinator: SocketAddr,
    /// Mesh; None when the deployment renders none, and a Mesh URL in a
    /// grant is then refused rather than looked up.
    pub mesh: Option<SocketAddr>,
    /// The DERP map hostname of the deployment's relay. No other node is
    /// dialled.
    pub derp_host: String,
    pub derp: SocketAddr,
    /// Roots the relay's certificate may chain to beside the WebPKI roots.
    pub derp_extra_roots: codewire_tailnet::platform_dial::PlatformRoots,
    pub dial: TcpDial,
    /// Where the tailnet reports a platform input it refuses, for GetHealth.
    pub refusal: codewire_daemon::platform_refusal::PlatformRefusal,
}

/// A platform input a broker-mode daemon refuses rather than look up. Each
/// has a fixed class for logs and for GetHealth.
#[derive(Debug, thiserror::Error)]
pub enum BrokerRefusal {
    #[error("direct UDP endpoint {0:?} is not an address and port")]
    EndpointNotLiteral(String),
    #[error("the DERP map has no node {0}, the only relay a broker-mode daemon dials")]
    NoDeploymentRelay(String),
    #[error("the DERP map's node {0} would be dialled without verifying its certificate")]
    UnverifiedRelay(String),
}

impl BrokerRefusal {
    pub fn class(&self) -> &'static str {
        match self {
            Self::EndpointNotLiteral(_) => "broker_endpoint_not_literal",
            Self::NoDeploymentRelay(_) => "broker_no_deployment_relay",
            Self::UnverifiedRelay(_) => "broker_relay_unverified",
        }
    }
}

impl std::fmt::Debug for DaemonPlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DaemonPlatform")
            .field("coordinator", &self.coordinator)
            .field("mesh", &self.mesh)
            .field("derp_host", &self.derp_host)
            .field("derp", &self.derp)
            .field("derp_extra_roots", &self.derp_extra_roots.len())
            .finish_non_exhaustive()
    }
}
