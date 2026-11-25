//! A hosted session's two additions (#4000): the egress trust in the host's
//! first frame, and the guest's self-check, which must be its first frame.

use codewire_network_session::{EgressTrust, NetworkFrame, SelfCheck, SelfCheckFailure};

use super::*;

const POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
const CA_DER: &[u8] = b"fixture certificate bytes";

fn pod() -> Uuid {
    Uuid::parse_str(POD).unwrap()
}

/// The guest's end of a hosted session, and the host's controls.
struct Hosted {
    guest: DuplexStream,
    codec: NetworkSession,
    first: NetworkFrame,
    checked: oneshot::Receiver<SelfCheck>,
    drain: oneshot::Sender<()>,
    session: tokio::task::JoinHandle<Result<(), NetworkSessionError>>,
}

async fn hosted_guest(trust: EgressTrust) -> Hosted {
    hosted_guest_with(trust, Arc::new(DenyBroker)).await
}

/// Runs a hosted session over `host`, and on the guest end completes the
/// handshake and reads the host's first frame.
async fn hosted_guest_with<B: EgressBroker>(trust: EgressTrust, broker: Arc<B>) -> Hosted {
    let key = NetworkKey::derive(TOKEN, pod(), 1).unwrap();
    let host_key = NetworkKey::derive(TOKEN, pod(), 1).unwrap();
    let (host, mut guest) = duplex(256 * 1024);
    let (self_check, checked) = oneshot::channel();
    let (drain, drain_request) = oneshot::channel();
    let session = tokio::spawn(run_hosted_network_session(
        host,
        host_key,
        pod(),
        broker,
        HostedChecks {
            trust,
            self_check,
            drain: drain_request,
        },
        || Ok(()),
    ));
    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    guest.read_exact(&mut hello).await.unwrap();
    // The hello names the Pod with generation 1, at the hosted bound.
    let hello = NetworkHostHello::decode(&hello, &key, pod(), 1).unwrap();
    assert_eq!(hello.packet_bound, SessionLimits::HOSTED.packet_bound());
    guest
        .write_all(
            &NetworkGuestAck::new(hello.nonce, hello.packet_bound)
                .unwrap()
                .encode(&key),
        )
        .await
        .unwrap();
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    guest.read_exact(&mut ready).await.unwrap();
    NetworkHostReady::decode(&ready, &key, &hello.nonce).unwrap();
    let mut session_codec =
        NetworkSession::new(&key, &hello.nonce, NetworkRole::Guest, hello.packet_bound).unwrap();
    let frame = read_frame(&mut guest, hello.packet_bound).await.unwrap();
    let first = session_codec.decode_frame(&frame).unwrap();
    Hosted {
        guest,
        codec: session_codec,
        first,
        checked,
        drain,
        session,
    }
}

/// A hosted guest that has passed its self-check.
async fn passed_guest<B: EgressBroker>(broker: Arc<B>) -> Hosted {
    let mut hosted = hosted_guest_with(EgressTrust::None, broker).await;
    let passed = hosted.codec.encode_self_check(SelfCheck::Passed).unwrap();
    hosted.guest.write_all(&passed).await.unwrap();
    hosted
}

#[tokio::test]
async fn the_hosts_first_frame_carries_the_trust_it_was_given() {
    let hosted = hosted_guest(EgressTrust::Ca(CA_DER.to_vec())).await;
    assert_eq!(
        hosted.first,
        NetworkFrame::EgressTrust(EgressTrust::Ca(CA_DER.to_vec()))
    );
    hosted.session.abort();
}

#[tokio::test]
async fn after_a_passed_self_check_the_guests_packets_are_answered() {
    let Hosted {
        mut guest,
        mut codec,
        first,
        checked,
        session,
        ..
    } = hosted_guest(EgressTrust::None).await;
    assert_eq!(first, NetworkFrame::EgressTrust(EgressTrust::None));
    guest
        .write_all(&codec.encode_self_check(SelfCheck::Passed).unwrap())
        .await
        .unwrap();
    assert_eq!(checked.await.unwrap(), SelfCheck::Passed);
    // A lookup is answered (refused, by the denying broker): the session
    // forwards the guest's packets once the check has passed.
    write_guest_packet(
        &mut guest,
        &mut codec,
        &dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME),
    )
    .await
    .unwrap();
    let reply = tokio::time::timeout(HANG_GUARD, read_guest_packet(&mut guest, &mut codec))
        .await
        .unwrap()
        .unwrap();
    assert!(!reply.is_empty());
    session.abort();
}

#[tokio::test]
async fn a_packet_before_the_self_check_ends_the_session_unanswered() {
    let Hosted {
        mut guest,
        mut codec,
        checked,
        session,
        ..
    } = hosted_guest(EgressTrust::None).await;
    write_guest_packet(
        &mut guest,
        &mut codec,
        &dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME),
    )
    .await
    .unwrap();
    let ended = tokio::time::timeout(HANG_GUARD, session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended, Err(NetworkSessionError::Protocol));
    // No result was ever reported, and no reply came back.
    assert!(checked.await.is_err());
    let mut byte = [0_u8; 1];
    assert_eq!(guest.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn a_failed_self_check_ends_the_session_with_its_reason() {
    for failure in [
        SelfCheckFailure::DirectDial,
        SelfCheckFailure::Dns,
        SelfCheckFailure::Routing,
    ] {
        let Hosted {
            mut guest,
            mut codec,
            checked,
            session,
            ..
        } = hosted_guest(EgressTrust::None).await;
        guest
            .write_all(&codec.encode_self_check(SelfCheck::Failed(failure)).unwrap())
            .await
            .unwrap();
        assert_eq!(checked.await.unwrap(), SelfCheck::Failed(failure));
        let ended = tokio::time::timeout(HANG_GUARD, session)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended, Err(NetworkSessionError::SelfCheckFailed(failure)));
    }
}

#[tokio::test]
async fn a_drained_session_with_no_open_flow_ends_at_once() {
    let hosted = passed_guest(Arc::new(DenyBroker)).await;
    assert_eq!(hosted.checked.await.unwrap(), SelfCheck::Passed);
    hosted.drain.send(()).unwrap();
    let ended = tokio::time::timeout(HANG_GUARD, hosted.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended, Ok(()));
}

#[tokio::test]
async fn a_drained_session_waits_for_a_lookup_in_flight_and_still_answers_it() {
    let broker = SlowLookupBroker::new();
    let Hosted {
        mut guest,
        mut codec,
        checked,
        drain,
        mut session,
        ..
    } = passed_guest(Arc::clone(&broker)).await;
    assert_eq!(checked.await.unwrap(), SelfCheck::Passed);
    write_guest_packet(
        &mut guest,
        &mut codec,
        &dns_query_packet(WORKER_IP, 53, SLOW_DNS_NAME),
    )
    .await
    .unwrap();
    broker.wait_for_slow(1).await;
    drain.send(()).unwrap();
    // The lookup is in flight, so the session is not idle and keeps running.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut session)
            .await
            .is_err()
    );
    broker.release.add_permits(1);
    // Its answer reaches the guest, and then the session ends.
    let reply = tokio::time::timeout(HANG_GUARD, read_guest_packet(&mut guest, &mut codec))
        .await
        .unwrap()
        .unwrap();
    assert!(!reply.is_empty());
    let ended = tokio::time::timeout(HANG_GUARD, session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended, Ok(()));
}

/// Admits every TCP flow and keeps the far end of each upstream it dials, so
/// a bridged connection stays open, and quiet, until the test drops it.
#[derive(Default)]
struct HeldBroker {
    far: std::sync::Mutex<Vec<DuplexStream>>,
}

#[async_trait]
impl EgressBroker for HeldBroker {
    async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
        Ok(())
    }

    async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
        let (upstream, far) = duplex(1024);
        self.far.lock().unwrap().push(far);
        Ok(Box::pin(upstream))
    }

    async fn resolve_dns(&self, _question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
        Err(denied())
    }
}

/// #6483: a drain must not end a session that holds an open connection,
/// even one that carries nothing; it waits for the connection, or the
/// supervisor's deadline.
#[tokio::test]
async fn a_drained_session_keeps_an_open_quiet_connection() {
    let broker = Arc::new(HeldBroker::default());
    let Hosted {
        mut guest,
        mut codec,
        checked,
        drain,
        mut session,
        ..
    } = passed_guest(Arc::clone(&broker)).await;
    assert_eq!(checked.await.unwrap(), SelfCheck::Passed);
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 80), 443);
    write_guest_packet(
        &mut guest,
        &mut codec,
        &tcp_packet(40_000, server, 1, 0, 0x02),
    )
    .await
    .unwrap();
    let syn_ack = tokio::time::timeout(HANG_GUARD, read_guest_packet(&mut guest, &mut codec))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_flags(&syn_ack), 0x12, "expected the stack's SYN-ACK");
    let server_seq = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
    write_guest_packet(
        &mut guest,
        &mut codec,
        &tcp_packet(40_000, server, 2, server_seq.wrapping_add(1), 0x10),
    )
    .await
    .unwrap();
    // The upstream's bytes reach the guest, so the connection is bridged.
    let mut far = tokio::time::timeout(HANG_GUARD, async {
        loop {
            if let Some(far) = broker.far.lock().unwrap().pop() {
                return far;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    far.write_all(b"hello").await.unwrap();
    let data = tokio::time::timeout(HANG_GUARD, async {
        loop {
            let packet = read_guest_packet(&mut guest, &mut codec).await.unwrap();
            if packet[9] == 6 && packet.len() > 40 {
                return packet;
            }
        }
    })
    .await
    .unwrap();
    assert!(data.ends_with(b"hello"));

    drain.send(()).unwrap();
    // Longer than the drain's recheck: the open connection keeps it running.
    assert!(
        tokio::time::timeout(Duration::from_secs(3), &mut session)
            .await
            .is_err(),
        "a drained session ended while a connection was open"
    );
    session.abort();
}

#[tokio::test]
async fn without_a_drain_an_idle_session_keeps_running() {
    let hosted = passed_guest(Arc::new(DenyBroker)).await;
    assert_eq!(hosted.checked.await.unwrap(), SelfCheck::Passed);
    let mut session = hosted.session;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut session)
            .await
            .is_err()
    );
    drop(hosted.drain);
    // A drain whose sender is gone asks for nothing.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut session)
            .await
            .is_err()
    );
    session.abort();
}
