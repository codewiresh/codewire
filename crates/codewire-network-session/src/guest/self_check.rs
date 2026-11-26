//! The hosted guest's egress self-check (#4000 P6, infra#1806's failure
//! mode). At every start, before the daemon reports ready, the guest makes a
//! TCP connection and a DNS query that bypass its TUN device on purpose, each
//! bound to the Pod's own interface. Both must fail: if either is answered,
//! the sandbox's lockdown is not enforcing, so the sandbox must not start.
//! A refusal, an unreachable network and a timeout all count as the probe
//! failing, which is the good outcome. A probe that cannot even be set up
//! counts as having reached the network, so an unknown state fails closed.
//!
//! What it proves: that the platform's lockdown is applied to this Pod, at
//! this start. It catches the platform lapsing, not a hostile guest, which
//! could report a pass it never earned. So a pass admits nothing: the host
//! acts on the result in one direction only, and a failure, or no result,
//! fails the sandbox closed.
//!
//! The caller is the daemon's hosted egress loop: after
//! [`super::authenticate_guest`] it calls [`self_check`], sends the result
//! with [`crate::NetworkSession::encode_self_check`] as the guest's first
//! frame, and on a failure never signals readiness. The session's
//! [`SelfCheck`] is the only result type and the only encoding.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::{TcpSocket, UdpSocket};

use crate::{SelfCheck, SelfCheckFailure};

/// The address the direct dial targets: a public anycast resolver, on 443.
/// It answers TCP from anywhere, so a direct dial that is not blocked
/// reliably connects, and it belongs to no Codewire service, so allowing it
/// for some other reason can never make the probe pass by accident.
pub const DIRECT_DIAL_TARGET: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443);

/// The interface a hosted sandbox Pod sends on outside its TUN device.
pub const DEFAULT_POD_INTERFACE: &str = "eth0";

/// How long each probe waits for an answer. A probe that reaches it counts
/// as blocked, which is the wanted result: a lockdown that drops the probe
/// answers nothing. The two probes run together, so both are over within
/// about one timeout, and the host's bound on the result must cover it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The name the DNS probe asks for. Any answer, even a refusal, means the
/// query reached the resolver.
const DNS_PROBE_NAME: &str = "kubernetes.default.svc.cluster.local";

/// Whether a probe reached the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// It was answered, or could not be set up: the lockdown is not proven.
    Reached,
    /// It was refused, found no route, or timed out.
    Blocked,
}

/// The two probes, so tests can stand in for the network.
pub trait SelfCheckProbes {
    fn direct_dial(&self) -> impl Future<Output = ProbeOutcome> + Send;
    fn dns_query(&self) -> impl Future<Output = ProbeOutcome> + Send;
}

/// Run both probes together. A reached direct dial is reported ahead of DNS.
pub async fn self_check(probes: &impl SelfCheckProbes) -> SelfCheck {
    let (dial, dns) = tokio::join!(probes.direct_dial(), probes.dns_query());
    match (dial, dns) {
        (ProbeOutcome::Reached, _) => SelfCheck::Failed(SelfCheckFailure::DirectDial),
        (_, ProbeOutcome::Reached) => SelfCheck::Failed(SelfCheckFailure::Dns),
        (ProbeOutcome::Blocked, ProbeOutcome::Blocked) => SelfCheck::Passed,
    }
}

/// The real probes, bound to one network interface with `SO_BINDTODEVICE`.
#[derive(Clone, Debug)]
pub struct InterfaceProbes {
    pub interface: String,
    pub dial_target: SocketAddr,
    /// The cluster resolver: the cluster DNS Service's address.
    pub resolver: SocketAddr,
    pub timeout: Duration,
}

impl InterfaceProbes {
    /// Probes on [`DEFAULT_POD_INTERFACE`] against [`DIRECT_DIAL_TARGET`].
    pub fn for_pod(resolver: Ipv4Addr) -> Self {
        Self {
            interface: DEFAULT_POD_INTERFACE.to_owned(),
            dial_target: SocketAddr::V4(DIRECT_DIAL_TARGET),
            resolver: SocketAddr::V4(SocketAddrV4::new(resolver, 53)),
            timeout: PROBE_TIMEOUT,
        }
    }

    async fn dial(&self) -> Result<(), ProbeError> {
        let socket = match self.dial_target {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(|_| ProbeError::Setup)?;
        socket
            .bind_device(Some(self.interface.as_bytes()))
            .map_err(|_| ProbeError::Setup)?;
        socket
            .connect(self.dial_target)
            .await
            .map(drop)
            .map_err(ProbeError::Network)
    }

    async fn query(&self) -> Result<(), ProbeError> {
        let local: SocketAddr = match self.resolver {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = std::net::UdpSocket::bind(local).map_err(|_| ProbeError::Setup)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| ProbeError::Setup)?;
        let socket = UdpSocket::from_std(socket).map_err(|_| ProbeError::Setup)?;
        socket
            .bind_device(Some(self.interface.as_bytes()))
            .map_err(|_| ProbeError::Setup)?;
        // Connect the UDP socket to the resolver so it is never an unconnected
        // listening socket and only accepts datagrams from that peer.
        socket
            .connect(self.resolver)
            .await
            .map_err(ProbeError::Network)?;
        let query = dns_query(DNS_PROBE_ID, DNS_PROBE_NAME);
        socket.send(&query).await.map_err(ProbeError::Network)?;
        let mut answer = [0_u8; 512];
        loop {
            let len = socket
                .recv(&mut answer)
                .await
                .map_err(ProbeError::Network)?;
            if answers_query(&answer[..len], DNS_PROBE_ID) {
                return Ok(());
            }
        }
    }
}

/// Where a probe stopped short of an answer.
#[derive(Debug)]
enum ProbeError {
    /// The socket could not be made or bound to the interface.
    Setup,
    /// The network refused or could not carry it.
    Network(io::Error),
}

/// A probe's outcome from whether it could be set up and whether it was
/// answered in time.
fn outcome(probe: Result<Result<(), ProbeError>, tokio::time::error::Elapsed>) -> ProbeOutcome {
    match probe {
        Ok(Ok(())) => ProbeOutcome::Reached,
        Err(_elapsed) => ProbeOutcome::Blocked,
        Ok(Err(ProbeError::Network(error))) if is_blocked(&error) => ProbeOutcome::Blocked,
        // A socket that cannot be made or bound to the interface, or a
        // network error that is not a refusal, proves nothing: fail closed.
        Ok(Err(ProbeError::Setup | ProbeError::Network(_))) => ProbeOutcome::Reached,
    }
}

/// The errors a blocked path produces: refused, reset, or no route.
fn is_blocked(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::TimedOut
    )
}

impl SelfCheckProbes for InterfaceProbes {
    async fn direct_dial(&self) -> ProbeOutcome {
        outcome(tokio::time::timeout(self.timeout, self.dial()).await)
    }

    async fn dns_query(&self) -> ProbeOutcome {
        outcome(tokio::time::timeout(self.timeout, self.query()).await)
    }
}

const DNS_PROBE_ID: u16 = 0xc0de;

/// One recursive A query for `name`.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = Vec::with_capacity(17 + name.len() + 2);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

/// Whether `packet` is a DNS response to query `id`, whatever its answer.
fn answers_query(packet: &[u8], id: u16) -> bool {
    packet.len() >= 12 && packet[..2] == id.to_be_bytes() && packet[2] & 0x80 != 0
}

#[cfg(test)]
mod tests;
