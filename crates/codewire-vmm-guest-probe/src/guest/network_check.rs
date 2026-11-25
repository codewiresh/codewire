//! The isolated workspace's network check: the guest reaches nothing
//! except through the trusted TUN, and gets no answer it should not.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

use super::{
    NETWORK_GATEWAY_ADDRESS, NETWORK_INTERFACE, NETWORK_MARKER, read_guest_identity,
    verify_isolated_tun,
};

pub fn run_network_check() -> Result<()> {
    let _ = read_guest_identity()?;
    verify_isolated_tun(
        NETWORK_INTERFACE,
        NETWORK_GATEWAY_ADDRESS
            .parse()
            .context("parse the guest network gateway")?,
        Path::new("/proc/net/dev"),
        Path::new("/proc/net/route"),
        Path::new("/proc/net/ipv6_route"),
    )?;
    for destination in [
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53),
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 19), 443),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
        SocketAddrV4::new(Ipv4Addr::new(169, 254, 169, 254), 80),
    ] {
        ensure!(
            TcpStream::connect_timeout(&SocketAddr::V4(destination), Duration::from_millis(100),)
                .is_err(),
            "isolated workspace unexpectedly completed a TCP connection"
        );
    }
    require_no_udp_response()?;
    require_raw_icmp_denied()?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NETWORK_MARKER}")?;
    stdout.flush()?;
    Ok(())
}

/// The guest resolver, the only UDP destination that answers anything.
const GUEST_RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53);

/// An A query for `canary.invalid`, a reserved name the locked policy refuses
/// by construction.
const UDP_CANARY_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06canary\x07invalid\x00\x00\x01\x00\x01";

/// A query sent to the guest resolver may come back as the network worker's
/// refusal of it (#5748), and only when the worker is attached. Silence
/// proves nothing escapes as well as the refusal does; any other reply, a
/// second one, or any reply to another destination fails. Each destination
/// has its own socket, so a late reply cannot count against the wrong one.
fn require_no_udp_response() -> Result<()> {
    let mut response = [0_u8; 512];
    for destination in [
        GUEST_RESOLVER,
        SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
    ] {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            .context("bind isolated workspace UDP canary")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .context("bound isolated workspace UDP canary")?;
        let _ = socket.send_to(UDP_CANARY_QUERY, destination);
        let mut refused = false;
        // After an accepted refusal, read once more to catch a second reply.
        for _ in 0..2 {
            let Ok((length, source)) = socket.recv_from(&mut response) else {
                break;
            };
            ensure!(
                !refused && is_resolver_refusal(destination, source, &response[..length]),
                "isolated workspace unexpectedly received a UDP response"
            );
            refused = true;
        }
    }
    Ok(())
}

/// The network worker's refusal of [`UDP_CANARY_QUERY`]: the guest
/// resolver answering its own socket with the query's ID and question,
/// flags `0x8183` (response, recursion desired and available, NXDOMAIN),
/// one question and no record.
fn is_resolver_refusal(destination: SocketAddrV4, source: SocketAddr, reply: &[u8]) -> bool {
    destination == GUEST_RESOLVER
        && source == SocketAddr::V4(GUEST_RESOLVER)
        && reply.len() == UDP_CANARY_QUERY.len()
        && reply[..2] == UDP_CANARY_QUERY[..2]
        && reply[2..4] == [0x81, 0x83]
        && reply[4..] == UDP_CANARY_QUERY[4..]
}

fn require_raw_icmp_denied() -> Result<()> {
    let descriptor = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if descriptor != -1 {
        unsafe {
            libc::close(descriptor);
        }
        bail!("isolated workspace unexpectedly created a raw ICMP socket");
    }
    ensure!(
        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "isolated workspace raw ICMP denial is not capability-enforced"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal the network worker sent the guest in #5748's diagnostic run.
    const OBSERVED_REFUSAL: &[u8] =
        b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x06canary\x07invalid\x00\x00\x01\x00\x01";

    #[test]
    fn only_the_resolvers_exact_refusal_of_the_canary_is_accepted() {
        let resolver = SocketAddr::V4(GUEST_RESOLVER);
        let public = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);
        assert!(is_resolver_refusal(
            GUEST_RESOLVER,
            resolver,
            OBSERVED_REFUSAL
        ));
        for (destination, source) in [
            (public, resolver),
            (public, SocketAddr::V4(public)),
            (GUEST_RESOLVER, SocketAddr::V4(public)),
            (
                GUEST_RESOLVER,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 5353)),
            ),
        ] {
            assert!(
                !is_resolver_refusal(destination, source, OBSERVED_REFUSAL),
                "{destination} {source}"
            );
        }
        let changed = |index: usize, value: u8| {
            let mut reply = OBSERVED_REFUSAL.to_vec();
            reply[index] = value;
            reply
        };
        for reply in [
            changed(1, 0x35),
            changed(2, 0x85),
            changed(3, 0x80),
            changed(3, 0x82),
            changed(7, 0x01),
            changed(11, 0x01),
            changed(13, b'x'),
            [OBSERVED_REFUSAL, b"\x00"].concat(),
            OBSERVED_REFUSAL[..OBSERVED_REFUSAL.len() - 1].to_vec(),
            UDP_CANARY_QUERY.to_vec(),
        ] {
            assert!(
                !is_resolver_refusal(GUEST_RESOLVER, resolver, &reply),
                "{reply:02x?}"
            );
        }
    }
}
