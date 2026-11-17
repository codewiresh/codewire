use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::*;

struct Fake {
    dial: ProbeOutcome,
    dns: ProbeOutcome,
}

impl SelfCheckProbes for Fake {
    async fn direct_dial(&self) -> ProbeOutcome {
        self.dial
    }

    async fn dns_query(&self) -> ProbeOutcome {
        self.dns
    }
}

#[tokio::test]
async fn only_two_blocked_probes_pass() {
    use ProbeOutcome::{Blocked, Reached};
    for (dial, dns, expected) in [
        (Blocked, Blocked, SelfCheck::Passed),
        (
            Reached,
            Blocked,
            SelfCheck::Failed(SelfCheckFailure::DirectDial),
        ),
        (Blocked, Reached, SelfCheck::Failed(SelfCheckFailure::Dns)),
        (
            Reached,
            Reached,
            SelfCheck::Failed(SelfCheckFailure::DirectDial),
        ),
    ] {
        assert_eq!(
            self_check(&Fake { dial, dns }).await,
            expected,
            "{dial:?} {dns:?}"
        );
    }
}

#[test]
fn the_pods_probes_wait_the_exported_timeout() {
    let probes = InterfaceProbes::for_pod(Ipv4Addr::new(10, 96, 0, 10));
    assert_eq!(probes.timeout, PROBE_TIMEOUT);
    // Through the path a caller uses to bound the whole check.
    assert_eq!(crate::guest::PROBE_TIMEOUT, PROBE_TIMEOUT);
}

/// Long enough that a probe the fake answers at once never times out on a
/// loaded machine.
const ANSWERED: Duration = Duration::from_secs(30);
/// For the one probe that is meant to time out.
const UNANSWERED: Duration = Duration::from_millis(300);

fn loopback(dial_target: SocketAddr, resolver: SocketAddr, timeout: Duration) -> InterfaceProbes {
    InterfaceProbes {
        interface: "lo".to_owned(),
        dial_target,
        resolver,
        timeout,
    }
}

/// A local port with nothing listening on it.
fn closed_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn a_dial_that_connects_is_reached_and_a_refused_one_is_blocked() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let open = listener.local_addr().unwrap();
    let unused = closed_port();
    assert_eq!(
        loopback(open, unused, ANSWERED).direct_dial().await,
        ProbeOutcome::Reached
    );
    // A closed loopback port refuses at once; nothing waits for the timeout.
    assert_eq!(
        loopback(closed_port(), unused, ANSWERED)
            .direct_dial()
            .await,
        ProbeOutcome::Blocked
    );
}

#[tokio::test]
async fn a_dial_on_an_interface_that_does_not_exist_fails_closed() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut probes = loopback(closed_port(), closed_port(), ANSWERED);
    probes.dial_target = listener.local_addr().unwrap();
    probes.interface = "cw-no-such-if".to_owned();
    assert_eq!(probes.direct_dial().await, ProbeOutcome::Reached);
    assert_eq!(probes.dns_query().await, ProbeOutcome::Reached);
}

#[tokio::test]
async fn an_answered_dns_query_is_reached_and_a_silent_resolver_is_blocked() {
    let resolver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let resolver_address = resolver.local_addr().unwrap();
    let answering = tokio::spawn(async move {
        let mut query = [0_u8; 512];
        let (len, from) = resolver.recv_from(&mut query).await.unwrap();
        let mut answer = query[..len].to_vec();
        answer[2] |= 0x80; // the response bit; the answer itself is irrelevant
        resolver.send_to(&answer, from).await.unwrap();
    });
    let probes = loopback(closed_port(), resolver_address, ANSWERED);
    assert_eq!(probes.dns_query().await, ProbeOutcome::Reached);
    answering.await.unwrap();

    let silent = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let probes = loopback(closed_port(), silent.local_addr().unwrap(), UNANSWERED);
    assert_eq!(probes.dns_query().await, ProbeOutcome::Blocked);
}

#[test]
fn the_query_is_one_recursive_a_question() {
    let query = dns_query(0x1234, "a.bc");
    assert_eq!(&query[..4], &[0x12, 0x34, 0x01, 0x00]);
    assert_eq!(&query[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&query[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
    assert!(answers_query(
        &[0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0],
        0x1234
    ));
    assert!(!answers_query(
        &[0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        0x1234
    ));
    assert!(!answers_query(
        &[0x12, 0x35, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0],
        0x1234
    ));
}

/// The result has one encoding, the session's: what the probes return is
/// what the host's reader decodes from the guest's control frame.
#[tokio::test]
async fn the_probes_result_crosses_as_the_sessions_control_frame() {
    use crate::{NetworkFrame, NetworkKey, NetworkRole, NetworkSession, PacketBound};

    let key = NetworkKey::from_derived_bytes([0xa5; crate::NETWORK_KEY_LEN]).unwrap();
    let nonce = [9_u8; 32];
    let bound = PacketBound::new(2_048).unwrap();
    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound).unwrap();
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host, bound).unwrap();
    let result = self_check(&Fake {
        dial: ProbeOutcome::Blocked,
        dns: ProbeOutcome::Reached,
    })
    .await;
    let frame = guest.encode_self_check(result).unwrap();
    assert_eq!(
        host.decode_frame(&frame).unwrap(),
        NetworkFrame::SelfCheck(SelfCheck::Failed(SelfCheckFailure::Dns))
    );
}
