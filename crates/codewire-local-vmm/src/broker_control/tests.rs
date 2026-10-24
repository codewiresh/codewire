use std::net::{IpAddr, Ipv4Addr};

use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy};

use super::*;

fn policy(target: &str) -> CompiledPolicy {
    TypedPolicy::new([AllowRule::new(AllowTarget::parse(target).unwrap(), [443]).unwrap()])
        .unwrap()
        .compile()
}

fn addresses() -> HostAddressSet {
    HostAddressSet::new([IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))], []).unwrap()
}

#[tokio::test]
async fn frames_round_trip_and_a_wrong_digest_or_unknown_frame_is_refused() {
    let work = policy("github.com");
    let frame = encode_policy_frame(&work).unwrap();
    match read_control_frame(&mut frame.as_slice()).await.unwrap() {
        ControlFrame::ReplacePolicy(read) => assert_eq!(read.digest(), work.digest()),
        other => panic!("not a replacement: {other:?}"),
    }
    let host = encode_frame(&addresses());
    assert!(matches!(
        read_control_frame(&mut host.as_slice()).await.unwrap(),
        ControlFrame::HostAddresses(set) if set == addresses()
    ));
    let ack = encode_policy_ack(work.digest());
    assert_eq!(
        read_policy_ack(&mut ack.as_slice()).await.unwrap(),
        work.digest()
    );

    let mut wrong_digest = frame.clone();
    wrong_digest[5] ^= 1;
    assert!(
        read_control_frame(&mut wrong_digest.as_slice())
            .await
            .is_err()
    );
    let mut unknown = frame.clone();
    unknown[..4].copy_from_slice(b"CWXX");
    assert!(read_control_frame(&mut unknown.as_slice()).await.is_err());
    let mut version = frame.clone();
    version[4] = 2;
    assert!(read_control_frame(&mut version.as_slice()).await.is_err());
    let truncated = &frame[..frame.len() - 1];
    assert!(read_control_frame(&mut &truncated[..]).await.is_err());
    let mut oversized = frame[..5 + 32].to_vec();
    oversized.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(read_control_frame(&mut oversized.as_slice()).await.is_err());
}

#[tokio::test]
async fn the_runner_waits_for_each_acknowledgement_and_carries_host_addresses() {
    let (runner, mut broker) = tokio::io::duplex(1 << 20);
    let (address_updates, address_receiver) = mpsc::channel(4);
    let (replace, replacements) = mpsc::channel(4);
    let served = tokio::spawn(serve_runner_control(
        runner,
        address_receiver,
        replacements,
        POLICY_ACK_TIMEOUT,
    ));

    address_updates.send(addresses()).await.unwrap();
    assert!(matches!(
        read_control_frame(&mut broker).await.unwrap(),
        ControlFrame::HostAddresses(_)
    ));
    let work = policy("github.com");
    let (reply, acknowledged) = oneshot::channel();
    replace
        .send(PolicyReplacementRequest {
            policy: work.clone(),
            reply,
        })
        .await
        .unwrap();
    let ControlFrame::ReplacePolicy(read) = read_control_frame(&mut broker).await.unwrap() else {
        panic!("not a replacement");
    };
    broker
        .write_all(&encode_policy_ack(read.digest()))
        .await
        .unwrap();
    assert_eq!(acknowledged.await.unwrap(), work.digest());

    // An acknowledgement of another policy ends the channel, and its
    // caller hears nothing.
    let (reply, unanswered) = oneshot::channel();
    replace
        .send(PolicyReplacementRequest {
            policy: policy("pypi.org"),
            reply,
        })
        .await
        .unwrap();
    read_control_frame(&mut broker).await.unwrap();
    broker
        .write_all(&encode_policy_ack(work.digest()))
        .await
        .unwrap();
    assert!(served.await.unwrap().is_err());
    assert!(unanswered.await.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_late_acknowledgement_ends_the_channel() {
    let (runner, mut broker) = tokio::io::duplex(1 << 20);
    let (_address_updates, address_receiver) = mpsc::channel(1);
    let (replace, replacements) = mpsc::channel(1);
    let served = tokio::spawn(serve_runner_control(
        runner,
        address_receiver,
        replacements,
        POLICY_ACK_TIMEOUT,
    ));
    let (reply, unanswered) = oneshot::channel();
    replace
        .send(PolicyReplacementRequest {
            policy: policy("github.com"),
            reply,
        })
        .await
        .unwrap();
    read_control_frame(&mut broker).await.unwrap();
    assert_eq!(
        served.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(unanswered.await.is_err());
}

#[tokio::test]
async fn the_channel_closes_when_the_host_address_monitor_stops() {
    let (runner, mut broker) = tokio::io::duplex(64);
    let (address_updates, address_receiver) = mpsc::channel(1);
    let (_replace, replacements) = mpsc::channel(1);
    let served = tokio::spawn(serve_runner_control(
        runner,
        address_receiver,
        replacements,
        POLICY_ACK_TIMEOUT,
    ));
    drop(address_updates);
    served.await.unwrap().unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(broker.read(&mut byte).await.unwrap(), 0);
}
