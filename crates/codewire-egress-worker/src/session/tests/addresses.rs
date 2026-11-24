//! A session's /30 is the host side's to choose (#5602): a broker-mode
//! standard guest's session takes [`SessionAddresses::HOSTED_BROKER`], and
//! accepts and answers on that pair alone; every other session keeps
//! [`SessionAddresses::STANDARD`].

use super::*;

/// The guest's end of a ready session on `addresses`, served by `broker`.
async fn ready_session_at<B: EgressBroker>(
    broker: Arc<B>,
    addresses: SessionAddresses,
) -> (DuplexStream, NetworkSession) {
    let (vm_id, generation) = identity();
    let (host_endpoint, mut guest_endpoint) = duplex(128 * 1024);
    let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    tokio::spawn(run_network_session_with_ingress(
        host_endpoint,
        host_key,
        (vm_id, generation),
        (SessionLimits::LOCAL, addresses),
        broker,
        None,
        || Ok(()),
    ));
    let guest_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let session = authenticate_guest_endpoint(&mut guest_endpoint, &guest_key, vm_id, generation)
        .await
        .unwrap();
    (guest_endpoint, session)
}

fn query(source: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
    udp_packet(source, server, 53_000, 53, &dns_query(TEST_DNS_NAME, &[]))
}

fn answering() -> Arc<RecordingBroker> {
    RecordingBroker::new(|| {
        Ok(BrokerDnsAnswer {
            answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
            ttl_seconds: 30,
        })
    })
}

/// Sends each of `ignored`, then `answered`, and returns the first reply.
/// The session handles packets in order, so a reply to any ignored packet
/// would come first.
async fn first_reply(addresses: SessionAddresses, ignored: &[Vec<u8>], answered: &[u8]) -> Vec<u8> {
    let broker = answering();
    let (mut guest, mut session) = ready_session_at(Arc::clone(&broker), addresses).await;
    for packet in ignored {
        write_guest_packet(&mut guest, &mut session, packet)
            .await
            .unwrap();
    }
    let reply = exchange(&mut guest, &mut session, answered).await;
    assert_eq!(
        broker.questions.lock().unwrap().len(),
        1,
        "only the answered query reached the broker"
    );
    reply
}

#[test]
fn the_two_pairs_are_neighbouring_slash_30s_never_the_same() {
    assert_eq!(
        SessionAddresses::STANDARD,
        SessionAddresses {
            worker: Ipv4Addr::new(192, 0, 2, 1),
            guest: Ipv4Addr::new(192, 0, 2, 2),
        }
    );
    let broker = SessionAddresses::HOSTED_BROKER;
    assert_eq!(
        (broker.worker, broker.guest),
        (Ipv4Addr::new(192, 0, 2, 5), Ipv4Addr::new(192, 0, 2, 6))
    );
    assert_ne!(u32::from(broker.guest) >> 2, u32::from(GUEST_IP) >> 2);
}

/// On the broker pair, the session answers its guest at the worker's
/// address, and neither a packet from today's guest address nor a lookup at
/// today's resolver gets an answer or reaches the broker.
#[tokio::test]
async fn a_broker_mode_session_answers_only_its_own_pair() {
    let broker = SessionAddresses::HOSTED_BROKER;
    let answered = query(broker.guest, broker.worker);
    let reply = first_reply(
        broker,
        &[
            query(GUEST_IP, broker.worker),
            query(GUEST_IP, WORKER_IP),
            query(broker.guest, WORKER_IP),
        ],
        &answered,
    )
    .await;
    assert_eq!(&reply[12..16], &broker.worker.octets());
    assert_eq!(&reply[16..20], &broker.guest.octets());
    assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
}

/// Every other session, `cw-egress`'s hosted one's among them
/// (`run_hosted_network_session` names [`SessionAddresses::STANDARD`]),
/// keeps today's pair: the broker pair gets no answer there.
#[tokio::test]
async fn a_standard_session_keeps_todays_pair() {
    let broker = SessionAddresses::HOSTED_BROKER;
    let reply = first_reply(
        SessionAddresses::STANDARD,
        &[
            query(broker.guest, broker.worker),
            query(broker.guest, WORKER_IP),
        ],
        &query(GUEST_IP, WORKER_IP),
    )
    .await;
    assert_eq!(&reply[12..16], &WORKER_IP.octets());
    assert_eq!(&reply[16..20], &GUEST_IP.octets());
}
