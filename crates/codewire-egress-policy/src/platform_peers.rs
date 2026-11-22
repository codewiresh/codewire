//! A standard Pod's platform peers (#5602, cw-security's condition 3).
//!
//! The hosted daemon in a standard Pod's guest dials the platform from the
//! Pod's address: the binding, the gateway, DERP and `cw-egress`, all inside
//! the cluster. The runtime's host end is a deputy in the Pod's own network
//! namespace, so it may reach only literal address and port pairs fixed at
//! boot from pinned settings: never a name, loopback, link-local, an
//! unspecified, multicast or broadcast address. Those pairs are allowed over
//! TCP before any address class is refused; nothing else changes.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::{
    BuiltinPolicy, CompiledPolicy, DecisionAction, DecisionReason, EgressProtocol, EgressRequest,
    PolicyDecision, PolicyDocument, PolicyError,
};

/// At most the four peers a Kata broker Pod's policy names, with room.
const MAX_PLATFORM_PEERS: usize = 8;
/// The rule id a platform peer's allow carries in decisions and logs.
pub const PLATFORM_PEER_RULE_ID: &str = "codewire-platform-peer";

impl CompiledPolicy {
    /// The `locked` policy plus a standard Pod's platform peers: no workload
    /// egress, and exactly these pairs for its daemon.
    pub fn locked_with_platform_peers(peers: &[SocketAddrV4]) -> Result<Self, PolicyError> {
        let mut document = BuiltinPolicy::Locked.compile().canonical_document().clone();
        document.platform_peers = peers.iter().map(SocketAddrV4::to_string).collect();
        Self::compile_document(document)
    }

    /// A broker's own bootstrap: the document its runner wrote, which may
    /// name platform peers. No workload's policy reaches this.
    pub fn compile_bootstrap(document: PolicyDocument) -> Result<Self, PolicyError> {
        Self::compile_document(document)
    }

    pub fn platform_peers(&self) -> &[SocketAddrV4] {
        &self.platform_peers
    }

    pub(crate) fn platform_peer_decision(&self, request: &EgressRequest) -> Option<PolicyDecision> {
        let std::net::IpAddr::V4(address) = request.address? else {
            return None;
        };
        (request.protocol == EgressProtocol::Tcp
            && self
                .platform_peers
                .contains(&SocketAddrV4::new(address, request.port)))
        .then(|| PolicyDecision {
            action: DecisionAction::Allow,
            reason: DecisionReason::RuleAllow,
            rule_id: Some(PLATFORM_PEER_RULE_ID.to_owned()),
            policy_digest: self.digest,
        })
    }
}

/// Parses, checks and sorts the document's peers in place, so a policy's
/// digest names exactly one order.
pub(crate) fn canonicalize(peers: &mut Vec<String>) -> Result<Vec<SocketAddrV4>, PolicyError> {
    if peers.len() > MAX_PLATFORM_PEERS {
        return Err(PolicyError::InvalidPlatformPeer(format!(
            "{} peers; at most {MAX_PLATFORM_PEERS}",
            peers.len()
        )));
    }
    let mut parsed = peers
        .iter()
        .map(|peer| parse(peer))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort();
    parsed.dedup();
    *peers = parsed.iter().map(SocketAddrV4::to_string).collect();
    Ok(parsed)
}

/// One literal pair of another host: the text must be exactly how the pair
/// prints, so no name, port alias or other spelling passes.
pub fn parse(peer: &str) -> Result<SocketAddrV4, PolicyError> {
    let invalid = || PolicyError::InvalidPlatformPeer(peer.to_owned());
    let address: SocketAddrV4 = peer.parse().map_err(|_| invalid())?;
    let ip: Ipv4Addr = *address.ip();
    if address.to_string() != peer
        || address.port() == 0
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return Err(invalid());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RouteClass;

    fn tcp(address: &str, port: u16) -> EgressRequest {
        EgressRequest::tcp(address.parse().unwrap(), port, None, RouteClass::General).unwrap()
    }

    #[test]
    fn only_the_exact_pairs_are_allowed_and_everything_else_stays_locked() {
        let policy = CompiledPolicy::locked_with_platform_peers(&[
            "10.96.0.20:443".parse().unwrap(),
            "10.96.0.30:8443".parse().unwrap(),
        ])
        .unwrap();
        for (address, port) in [("10.96.0.20", 443), ("10.96.0.30", 8443)] {
            let decision = policy.evaluate(&tcp(address, port));
            assert!(decision.is_allowed(), "{address}:{port}");
            assert_eq!(decision.rule_id.as_deref(), Some(PLATFORM_PEER_RULE_ID));
        }
        // Another port, another address, or the open internet stay refused.
        for (address, port) in [("10.96.0.20", 80), ("10.96.0.21", 443), ("1.1.1.1", 443)] {
            assert!(
                !policy.evaluate(&tcp(address, port)).is_allowed(),
                "{address}:{port}"
            );
        }
        assert_eq!(policy.platform_peers().len(), 2);
        assert_ne!(policy.digest(), CompiledPolicy::locked().digest());
    }

    #[test]
    fn no_workload_policy_can_name_a_platform_peer() {
        let mut document = CompiledPolicy::locked().canonical_document().clone();
        document.platform_peers = vec!["10.96.0.20:443".to_owned()];
        assert!(matches!(
            CompiledPolicy::compile(document.clone()),
            Err(PolicyError::PlatformPeersRefused)
        ));
        assert!(CompiledPolicy::compile_bootstrap(document).is_ok());
        let yaml = b"version: 1\ndefault: deny\nplatform_peers: ['10.96.0.20:443']\n";
        assert!(PolicyDocument::parse_yaml(yaml).is_err());
    }

    #[test]
    fn a_peer_is_a_literal_pair_of_another_host() {
        for refused in [
            "127.0.0.1:443",
            "169.254.169.254:80",
            "0.0.0.0:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "10.96.0.20:0",
            "10.96.0.20",
            "binding.codewire.svc:443",
            "010.96.0.20:443",
            "[::1]:443",
        ] {
            assert!(parse(refused).is_err(), "{refused}");
        }
        assert_eq!(parse("10.96.0.20:443").unwrap().port(), 443);
    }

    #[test]
    fn the_peers_print_in_one_order_so_the_digest_is_stable() {
        let forward = CompiledPolicy::locked_with_platform_peers(&[
            "10.0.0.2:1".parse().unwrap(),
            "10.0.0.1:1".parse().unwrap(),
        ])
        .unwrap();
        let backward = CompiledPolicy::locked_with_platform_peers(&[
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:1".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(forward.digest(), backward.digest());
    }
}
