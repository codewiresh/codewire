use std::net::Ipv4Addr;
use std::os::fd::AsFd as _;

use codewire_egress_policy::handoff::{
    HANDOFF_VERSION, HandoffReceiver, HandoffSender, stream_pair,
};

use super::*;

fn header() -> InterceptedStreamHeader {
    InterceptedStreamHeader {
        version: HANDOFF_VERSION,
        hostname: "api.openai.com".to_owned(),
        port: 443,
        destination_ip: Ipv4Addr::new(192, 0, 2, 7),
        stream_id: 9,
        environment_id: "0b0c3a52-5d4e-4f4d-9a36-1b2c3d4e5f60".to_owned(),
        aliases: Vec::new(),
    }
}

/// The front door's receiving end and the broker's sender.
fn socket() -> (HandoffSocket, HandoffSender) {
    let (front_door, broker) = stream_pair().unwrap();
    (
        HandoffSocket::new(front_door).unwrap(),
        HandoffSender::new(broker).unwrap(),
    )
}

/// A message that arrives only after the receive started waiting: the
/// receive waits for readability rather than failing on an empty socket.
#[tokio::test]
async fn a_stream_sent_while_waiting_arrives_with_its_header() {
    let (mut socket, mut broker) = socket();
    let (guest, handed) = stream_pair().unwrap();
    let receive = tokio::spawn(async move { socket.receive().await });
    tokio::task::yield_now().await;
    broker
        .send_intercepted_stream(&header(), handed.as_fd())
        .unwrap();
    drop(handed);
    let Received::Stream(received, stream) = receive.await.unwrap().unwrap() else {
        panic!("expected a stream");
    };
    assert_eq!(received, header());
    rustix::io::write(&stream, b"x").unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(rustix::io::read(&guest, &mut byte).unwrap(), 1);
}

/// The broker is trusted, so a frame it should never send ends the hand-off
/// socket: one whose descriptor is not a connected stream, or one carrying
/// two descriptors. What such a frame carried is closed.
#[tokio::test]
async fn a_frame_the_broker_should_never_send_ends_the_socket() {
    let (mut socket, mut broker) = socket();
    let (_peer, datagram) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    broker
        .send_intercepted_stream(&header(), datagram.as_fd())
        .unwrap();
    let error = socket.receive().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let (mut socket, mut broker) = self::socket();
    let (first_guest, first) = stream_pair().unwrap();
    let (second_guest, second) = stream_pair().unwrap();
    broker
        .send_frame(
            &header().encode().unwrap(),
            &[first.as_fd(), second.as_fd()],
        )
        .unwrap();
    drop((first, second));
    let error = socket.receive().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let mut byte = [0_u8; 1];
    assert_eq!(rustix::io::read(&first_guest, &mut byte).unwrap(), 0);
    assert_eq!(rustix::io::read(&second_guest, &mut byte).unwrap(), 0);
}

#[tokio::test]
async fn the_broker_closing_its_end_is_seen() {
    let (mut socket, broker) = socket();
    drop(broker);
    assert!(matches!(socket.receive().await.unwrap(), Received::Closed));
}

/// The front door checks its end itself: a datagram socket or an
/// unconnected stream is refused before anything is read.
#[test]
fn a_hand_off_end_that_is_not_a_connected_unix_stream_is_refused() {
    let (_peer, datagram) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let unconnected = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    for end in [datagram, unconnected] {
        assert!(HandoffSocket::new(end).is_err());
    }
}

/// The broker's side of acknowledgements: a receiver on a duplicate of its
/// end, with a deadline so a missing frame fails the test.
fn acknowledgements(broker: &HandoffSender) -> HandoffReceiver {
    let duplicate = rustix::io::fcntl_dupfd_cloexec(broker, 0).unwrap();
    rustix::net::sockopt::set_socket_timeout(
        &duplicate,
        rustix::net::sockopt::Timeout::Recv,
        Some(std::time::Duration::from_secs(5)),
    )
    .unwrap();
    HandoffReceiver::new(duplicate).unwrap()
}

/// An acknowledgement is one frame back: the stream id, eight bytes little
/// endian, and no descriptors.
#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_is_the_stream_id_back_to_the_broker() {
    let (mut socket, mut broker) = socket();
    let mut acknowledged = acknowledgements(&broker);
    let (_guest, handed) = stream_pair().unwrap();
    broker
        .send_intercepted_stream(&header(), handed.as_fd())
        .unwrap();
    let Received::Stream(received, _) = socket.receive().await.unwrap() else {
        panic!("expected a stream");
    };
    socket.acknowledge(received.stream_id).await.unwrap();
    let (body, descriptors) =
        tokio::task::block_in_place(|| acknowledged.recv_frame(8, 0)).unwrap();
    assert_eq!(body, header().stream_id.to_le_bytes());
    assert!(descriptors.is_empty());
}
