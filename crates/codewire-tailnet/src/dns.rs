//! Absolute lookups for the endpoint names a Sandbox daemon dials (#2701).
//!
//! A Kubernetes Pod resolves with `ndots:5`, so a name with fewer dots, such
//! as `codewire-orchestration-workspace-binding.dev.svc.cluster.local` or
//! `dev.codewire.sh`, is first tried with each search domain appended. A
//! static musl `cw` abandons the whole lookup when any of those candidates
//! answers SERVFAIL, as a workstation's Tailscale search domain inherited by a
//! Kind node does; glibc moves on. The endpoints the platform hands a daemon
//! are always fully qualified, so the daemon looks them up as absolute names
//! and no search domain is ever tried.
//!
//! Only the lookup uses the trailing dot. TLS verification, SNI and the HTTP
//! authority keep the name as configured.

use std::borrow::Cow;
use std::net::IpAddr;

/// `host` as an absolute DNS name for a resolver query: a multi-label name
/// gains a trailing dot. IP literals (bracketed or not), single-label names
/// such as `localhost`, which only the hosts file or the search list can
/// answer, and names that are already absolute are returned unchanged.
pub fn absolute_dns_name(host: &str) -> Cow<'_, str> {
    if host.ends_with('.')
        || host.starts_with('[')
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
    {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("{host}."))
    }
}

/// `host:port` with its host made absolute as [`absolute_dns_name`] does.
/// Socket addresses and anything without a port are returned unchanged.
pub fn absolute_host_port(endpoint: &str) -> Cow<'_, str> {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Cow::Borrowed(endpoint);
    };
    match absolute_dns_name(host) {
        Cow::Borrowed(_) => Cow::Borrowed(endpoint),
        Cow::Owned(host) => Cow::Owned(format!("{host}:{port}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_label_names_become_absolute() {
        for (host, want) in [
            (
                "codewire-orchestration-workspace-binding.codewire-e2e.svc.cluster.local",
                "codewire-orchestration-workspace-binding.codewire-e2e.svc.cluster.local.",
            ),
            ("dev.codewire.sh", "dev.codewire.sh."),
            ("codewire.sh", "codewire.sh."),
        ] {
            assert_eq!(absolute_dns_name(host), want);
        }
    }

    #[test]
    fn literals_single_labels_and_absolute_names_are_unchanged() {
        for host in [
            "",
            "localhost",
            "codewire-derp",
            "dev.codewire.sh.",
            "192.0.2.10",
            "2001:db8::1",
            "::ffff:192.0.2.10",
            "[2001:db8::1]",
            "[::ffff:192.0.2.10]",
        ] {
            assert!(
                matches!(absolute_dns_name(host), Cow::Borrowed(same) if same == host),
                "{host}"
            );
        }
    }

    #[test]
    fn host_ports_keep_their_port_and_literals() {
        assert_eq!(
            absolute_host_port("codewire-udp-relay.dev.svc.cluster.local:41641"),
            "codewire-udp-relay.dev.svc.cluster.local.:41641"
        );
        assert_eq!(
            absolute_host_port("stun.codewire-dev.sh:3478"),
            "stun.codewire-dev.sh.:3478"
        );
        for endpoint in [
            "192.0.2.36:32000",
            "[2001:db8::1]:41641",
            "[::ffff:192.0.2.10]:41641",
            "localhost:7777",
            "dev.codewire.sh.:443",
            "dev.codewire.sh",
            "2001:db8::1",
        ] {
            assert!(
                matches!(absolute_host_port(endpoint), Cow::Borrowed(same) if same == endpoint),
                "{endpoint}"
            );
        }
    }
}
