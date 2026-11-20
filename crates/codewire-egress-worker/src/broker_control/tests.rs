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
async fn interception_frames_round_trip_and_bad_ones_are_refused() {
    use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet, InterceptSuffix};
    let set = InterceptSet::with_suffixes(
        [
            InterceptBinding::new("api.anthropic.com", 443).unwrap(),
            InterceptBinding::new("github.com", 443).unwrap(),
        ],
        [InterceptSuffix::new("chatgpt.com", 443).unwrap()],
    )
    .unwrap();
    let frame = encode_intercept_frame(&set).unwrap();
    assert!(matches!(
        read_control_frame(&mut frame.as_slice()).await.unwrap(),
        ControlFrame::ReplaceIntercepts(read) if read == set
    ));
    let exact = InterceptSet::new([InterceptBinding::new("github.com", 443).unwrap()]).unwrap();
    let exact_frame = encode_intercept_frame(&exact).unwrap();
    assert!(matches!(
        read_control_frame(&mut exact_frame.as_slice()).await.unwrap(),
        ControlFrame::ReplaceIntercepts(read) if read == exact && read.suffixes().is_empty()
    ));
    let empty = encode_intercept_frame(&InterceptSet::default()).unwrap();
    assert!(matches!(
        read_control_frame(&mut empty.as_slice()).await.unwrap(),
        ControlFrame::ReplaceIntercepts(read) if read.is_empty()
    ));

    // Version 1 had no suffixes; the runner and broker are one build.
    for other in [1, 3] {
        let mut version = frame.clone();
        version[4] = other;
        assert!(read_control_frame(&mut version.as_slice()).await.is_err());
    }
    let mut too_many = frame[..5].to_vec();
    too_many.push(33);
    assert!(read_control_frame(&mut too_many.as_slice()).await.is_err());
    let mut too_many_suffixes = exact_frame[..exact_frame.len() - 1].to_vec();
    too_many_suffixes.push(9);
    assert!(
        read_control_frame(&mut too_many_suffixes.as_slice())
            .await
            .is_err()
    );
    let truncated = &frame[..frame.len() - 1];
    assert!(read_control_frame(&mut &truncated[..]).await.is_err());
    // A name the binding would canonicalize differently was not sent by us.
    let mut upper = frame.clone();
    upper[7] = b'A';
    assert!(read_control_frame(&mut upper.as_slice()).await.is_err());
    let mut upper_suffix = frame.clone();
    let at = upper_suffix.len() - 2 - "chatgpt.com".len();
    upper_suffix[at] = b'C';
    assert!(
        read_control_frame(&mut upper_suffix.as_slice())
            .await
            .is_err()
    );
    // A repeated binding is refused, not silently collapsed.
    let binding = &exact_frame[6..exact_frame.len() - 1];
    let mut repeated = exact_frame[..5].to_vec();
    repeated.push(2);
    repeated.extend_from_slice(binding);
    repeated.extend_from_slice(binding);
    repeated.push(0);
    assert!(read_control_frame(&mut repeated.as_slice()).await.is_err());
    // A protected name cannot be bound, nor a one-label suffix.
    let mut protected = frame[..5].to_vec();
    protected.push(1);
    protected.push(9);
    protected.extend_from_slice(b"localhost");
    protected.extend_from_slice(&443_u16.to_be_bytes());
    protected.push(0);
    assert!(read_control_frame(&mut protected.as_slice()).await.is_err());
    let mut top_level = frame[..5].to_vec();
    top_level.push(0);
    top_level.push(1);
    top_level.push(3);
    top_level.extend_from_slice(b"com");
    top_level.extend_from_slice(&443_u16.to_be_bytes());
    assert!(read_control_frame(&mut top_level.as_slice()).await.is_err());
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
