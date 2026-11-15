use std::io::{IoSlice, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use super::*;

const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";

fn header() -> InterceptedStreamHeader {
    InterceptedStreamHeader {
        version: HANDOFF_VERSION,
        hostname: "api.anthropic.com".into(),
        port: 443,
        destination_ip: Ipv4Addr::new(160, 79, 104, 10),
        stream_id: 7,
        environment_id: ENVIRONMENT.into(),
    }
}

fn pair(non_blocking: bool) -> (OwnedFd, OwnedFd) {
    let (one, two) = stream_pair().unwrap();
    for end in [&one, &two] {
        rustix::io::ioctl_fionbio(end, non_blocking).unwrap();
    }
    (one, two)
}

fn ends() -> (HandoffSender, HandoffReceiver) {
    let (sender, receiver) = pair(false);
    (
        HandoffSender::new(sender).unwrap(),
        HandoffReceiver::new(receiver).unwrap(),
    )
}

/// Writes raw bytes, optionally with descriptors, as one `sendmsg`.
fn send_raw(socket: BorrowedFd<'_>, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) {
    let vectors = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() {
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(descriptors)));
    }
    assert_eq!(
        sendmsg(socket, &vectors, &mut ancillary, SendFlags::empty()).unwrap(),
        bytes.len()
    );
}

fn prefix(bytes: &[u8]) -> [u8; 2] {
    u16::try_from(bytes.len()).unwrap().to_le_bytes()
}

/// The peer of a closed descriptor reads end of file.
fn assert_closed(peer: &StdUnixStream) {
    let mut buffer = [0_u8; 1];
    assert_eq!((&*peer).read(&mut buffer).unwrap(), 0);
}

#[test]
fn header_round_trips_with_the_documented_layout() {
    let bytes = header().encode().unwrap();
    assert_eq!(&bytes[0..2], &[1, 0]);
    assert_eq!(&bytes[2..4], &(17_u16).to_le_bytes());
    assert_eq!(&bytes[4..6], &443_u16.to_le_bytes());
    assert_eq!(&bytes[6..10], &[160, 79, 104, 10]);
    assert_eq!(&bytes[10..18], &7_u64.to_le_bytes());
    assert_eq!(&bytes[18..20], &(36_u16).to_le_bytes());
    assert_eq!(&bytes[20..37], b"api.anthropic.com");
    assert_eq!(InterceptedStreamHeader::decode(&bytes).unwrap(), header());
}

#[test]
fn malformed_headers_are_refused() {
    let good = header().encode().unwrap();
    let mut version = good.clone();
    version[0] = 2;
    assert_eq!(
        InterceptedStreamHeader::decode(&version),
        Err(HandoffError::Version)
    );
    assert_eq!(
        InterceptedStreamHeader::decode(&good[..19]),
        Err(HandoffError::Malformed)
    );
    assert_eq!(
        InterceptedStreamHeader::decode(&good[..good.len() - 1]),
        Err(HandoffError::Malformed)
    );
    let mut trailing = good.clone();
    trailing.push(b'x');
    assert_eq!(
        InterceptedStreamHeader::decode(&trailing),
        Err(HandoffError::Malformed)
    );
    let mut zero_port = good.clone();
    zero_port[4..6].copy_from_slice(&[0, 0]);
    assert_eq!(
        InterceptedStreamHeader::decode(&zero_port),
        Err(HandoffError::Malformed)
    );
    let mut upper = good.clone();
    upper[20] = b'A';
    assert_eq!(
        InterceptedStreamHeader::decode(&upper),
        Err(HandoffError::Malformed)
    );
    let mut upper_id = good.clone();
    let id_at = upper_id.len() - 36;
    upper_id[id_at] = b'F';
    assert_eq!(
        InterceptedStreamHeader::decode(&upper_id),
        Err(HandoffError::Malformed)
    );
    let mut long = good;
    long[2..4].copy_from_slice(&254_u16.to_le_bytes());
    assert_eq!(
        InterceptedStreamHeader::decode(&long),
        Err(HandoffError::Malformed)
    );
    for bad in [
        InterceptedStreamHeader {
            hostname: String::new(),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "e".repeat(129),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "0F8C2F6E-2C1E-4A8E-9C55-3B1F0F7D9A11".into(),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "{0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11}".into(),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "0f8c2f6e-2c1e-4a8e-9c55".into(),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9z11".into(),
            ..header()
        },
        InterceptedStreamHeader {
            environment_id: "0f8c2f6e2c1e-4a8e-9c55-3b1f0f7d9a11-".into(),
            ..header()
        },
        InterceptedStreamHeader {
            port: 0,
            ..header()
        },
    ] {
        assert_eq!(bad.encode(), Err(HandoffError::Malformed));
    }
}

#[test]
fn only_a_canonical_uuid_is_an_environment_id() {
    assert!(valid_environment_id(ENVIRONMENT));
    for bad in [
        "0F8C2F6E-2C1E-4A8E-9C55-3B1F0F7D9A11",
        "{0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11}",
        "0f8c2f6e-2c1e-4a8e-9c55",
        "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9z11",
        "0f8c2f6e2c1e-4a8e-9c55-3b1f0f7d9a11-",
        "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a1\n",
    ] {
        assert!(!valid_environment_id(bad), "{bad}");
    }
}

#[test]
fn a_descriptor_and_its_header_arrive_together_and_carry_bytes() {
    let (mut sender, mut receiver) = ends();
    let (mut ours, theirs) = StdUnixStream::pair().unwrap();
    sender
        .send_intercepted_stream(&header(), theirs.as_fd())
        .unwrap();
    drop(theirs);
    let (received, descriptor) = receiver.recv_intercepted_stream().unwrap();
    assert_eq!(received, header());
    let mut passed = StdUnixStream::from(descriptor);
    ours.write_all(b"hello").unwrap();
    let mut got = [0_u8; 5];
    passed.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hello");
}

#[test]
fn a_received_descriptor_is_close_on_exec() {
    let (mut sender, mut receiver) = ends();
    let (passed, _keep) = StdUnixStream::pair().unwrap();
    sender
        .send_intercepted_stream(&header(), passed.as_fd())
        .unwrap();
    let (_, descriptor) = receiver.recv_intercepted_stream().unwrap();
    assert!(
        rustix::io::fcntl_getfd(&descriptor)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
}

#[test]
fn frames_round_trip_with_and_without_descriptors() {
    let (mut sender, mut receiver) = ends();
    let (passed, _keep) = StdUnixStream::pair().unwrap();
    sender.send_frame(b"first", &[passed.as_fd()]).unwrap();
    sender.send_frame(b"", &[]).unwrap();
    sender.send_frame(b"third", &[]).unwrap();
    let (body, fds) = receiver.recv_frame(16, 1).unwrap();
    assert_eq!((body.as_slice(), fds.len()), (&b"first"[..], 1));
    let (body, fds) = receiver.recv_frame(16, 1).unwrap();
    assert_eq!((body.len(), fds.len()), (0, 0));
    let (body, fds) = receiver.recv_frame(16, 1).unwrap();
    assert_eq!((body.as_slice(), fds.len()), (&b"third"[..], 0));
}

#[test]
fn a_frame_written_in_pieces_resumes_after_would_block() {
    let (writer, reader) = pair(true);
    let mut receiver = HandoffReceiver::new(reader).unwrap();
    let (passed, _keep) = StdUnixStream::pair().unwrap();
    let bytes = header().encode().unwrap();
    let length = prefix(&bytes);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::WouldBlock
    );
    send_raw(writer.as_fd(), &length[..1], &[passed.as_fd()]);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::WouldBlock
    );
    send_raw(writer.as_fd(), &length[1..], &[]);
    send_raw(writer.as_fd(), &bytes[..7], &[]);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::WouldBlock
    );
    send_raw(writer.as_fd(), &bytes[7..], &[]);
    let (received, _descriptor) = receiver.recv_intercepted_stream().unwrap();
    assert_eq!(received, header());
}

#[test]
fn joined_frames_keep_their_own_descriptors() {
    let (writer, reader) = pair(false);
    let mut receiver = HandoffReceiver::new(reader).unwrap();
    let (one, mut keep_one) = StdUnixStream::pair().unwrap();
    let (two, mut keep_two) = StdUnixStream::pair().unwrap();
    let first = header().encode().unwrap();
    let second = InterceptedStreamHeader {
        stream_id: 8,
        ..header()
    }
    .encode()
    .unwrap();
    let mut frame = prefix(&first).to_vec();
    frame.extend_from_slice(&first);
    send_raw(writer.as_fd(), &frame, &[one.as_fd()]);
    let mut frame = prefix(&second).to_vec();
    frame.extend_from_slice(&second);
    send_raw(writer.as_fd(), &frame, &[two.as_fd()]);
    drop((one, two));
    let (header_one, descriptor_one) = receiver.recv_intercepted_stream().unwrap();
    let (header_two, descriptor_two) = receiver.recv_intercepted_stream().unwrap();
    assert_eq!((header_one.stream_id, header_two.stream_id), (7, 8));
    // Each header's descriptor is the one sent with it: a byte written to
    // each peer comes out of the matching descriptor.
    let mut received_one = StdUnixStream::from(descriptor_one);
    let mut received_two = StdUnixStream::from(descriptor_two);
    keep_one.write_all(b"1").unwrap();
    keep_two.write_all(b"2").unwrap();
    let mut byte = [0_u8; 1];
    received_one.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"1");
    received_two.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"2");
}

#[test]
fn a_frame_without_exactly_one_descriptor_is_refused_and_closed() {
    let (mut sender, mut receiver) = ends();
    sender.send_frame(&header().encode().unwrap(), &[]).unwrap();
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );

    let (one, keep_one) = StdUnixStream::pair().unwrap();
    let (two, keep_two) = StdUnixStream::pair().unwrap();
    sender
        .send_frame(&header().encode().unwrap(), &[one.as_fd(), two.as_fd()])
        .unwrap();
    drop((one, two));
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );
    assert_closed(&keep_one);
    assert_closed(&keep_two);
}

#[test]
fn a_descriptor_after_the_first_byte_is_refused_and_closed() {
    let (writer, reader) = pair(false);
    let mut receiver = HandoffReceiver::new(reader).unwrap();
    let (passed, keep) = StdUnixStream::pair().unwrap();
    let bytes = header().encode().unwrap();
    send_raw(writer.as_fd(), &prefix(&bytes), &[]);
    send_raw(writer.as_fd(), &bytes, &[passed.as_fd()]);
    drop(passed);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );
    assert_closed(&keep);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn an_over_long_frame_is_refused_and_its_descriptor_closed() {
    let (mut sender, mut receiver) = ends();
    let (passed, keep) = StdUnixStream::pair().unwrap();
    sender
        .send_frame(&vec![b'a'; HANDOFF_MAX_LEN + 1], &[passed.as_fd()])
        .unwrap();
    drop(passed);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Malformed
    );
    assert_closed(&keep);
}

#[test]
fn a_malformed_header_closes_its_descriptor_and_poisons_the_receiver() {
    let (mut sender, mut receiver) = ends();
    let (passed, keep) = StdUnixStream::pair().unwrap();
    let mut bytes = header().encode().unwrap();
    bytes[0] = 9;
    sender.send_frame(&bytes, &[passed.as_fd()]).unwrap();
    drop(passed);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Version
    );
    assert_closed(&keep);
    let (good, _keep_good) = StdUnixStream::pair().unwrap();
    sender
        .send_intercepted_stream(&header(), good.as_fd())
        .unwrap();
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn a_descriptor_that_is_not_a_unix_stream_is_refused() {
    let (mut sender, mut receiver) = ends();
    let (datagram, _keep) = std::os::unix::net::UnixDatagram::pair().unwrap();
    sender
        .send_frame(&header().encode().unwrap(), &[datagram.as_fd()])
        .unwrap();
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );
}

#[test]
fn end_of_file_inside_a_frame_is_an_error_and_between_frames_is_closed() {
    let (writer, reader) = pair(false);
    let mut receiver = HandoffReceiver::new(reader).unwrap();
    let bytes = header().encode().unwrap();
    send_raw(writer.as_fd(), &prefix(&bytes), &[]);
    send_raw(writer.as_fd(), &bytes[..5], &[]);
    drop(writer);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Io
    );

    let (sender, mut receiver) = ends();
    drop(sender);
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Closed
    );
}

#[test]
fn sending_to_a_closed_peer_is_closed_and_poisons_the_sender() {
    let (mut sender, receiver) = ends();
    drop(receiver);
    let (passed, _keep) = StdUnixStream::pair().unwrap();
    assert_eq!(
        sender
            .send_intercepted_stream(&header(), passed.as_fd())
            .unwrap_err(),
        HandoffError::Closed
    );
    assert_eq!(
        sender
            .send_intercepted_stream(&header(), passed.as_fd())
            .unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn a_full_peer_never_poisons_and_never_gets_a_silent_partial_frame() {
    let (sender, reader) = pair(true);
    let mut sender = HandoffSender::new(sender).unwrap();
    // Fill the buffer with small frames until one does not fit.
    let mut blocked = None;
    for _ in 0..1_000_000 {
        if let Err(error) = sender.send_frame(b"x", &[]) {
            blocked = Some(error);
            break;
        }
    }
    let blocked = blocked.expect("the buffer fills");
    assert_eq!(blocked, HandoffError::WouldBlock);
    // Still usable: Linux may refuse even an empty frame, macOS (which counts
    // the buffer in bytes) may take its prefix. Neither is a poison.
    assert_ne!(
        sender.send_frame(b"", &[]).err(),
        Some(HandoffError::Poisoned)
    );
    // A frame that does not fit sends nothing, or a part of it that poisons.
    let refused = sender.send_frame(&[b'y'; 512], &[]).unwrap_err();
    match refused {
        HandoffError::WouldBlock => {
            let mut receiver = HandoffReceiver::new(reader).unwrap();
            loop {
                match receiver.recv_frame(1, 0) {
                    Ok((body, _)) => assert!(body.len() <= 1),
                    Err(HandoffError::WouldBlock) => break,
                    Err(error) => panic!("a partial frame reached the peer: {error}"),
                }
            }
        }
        HandoffError::Io => assert_eq!(
            sender.send_frame(b"", &[]).unwrap_err(),
            HandoffError::Poisoned
        ),
        other => panic!("unexpected {other}"),
    }
}

#[test]
fn only_a_unix_stream_makes_an_end_and_a_closed_peer_shows_at_the_first_send() {
    let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(HandoffSender::new(OwnedFd::from(datagram)).is_err());
    let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(HandoffReceiver::new(OwnedFd::from(datagram)).is_err());
    let (sender, receiver) = pair(false);
    drop(receiver);
    let mut sender = HandoffSender::new(sender).unwrap();
    assert_eq!(
        sender.send_frame(b"", &[]).unwrap_err(),
        HandoffError::Closed
    );
    assert_eq!(
        sender.send_frame(b"", &[]).unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn a_short_write_poisons_the_sender_and_ends_the_stream() {
    let (sender, reader) = pair(true);
    // Shrinking the buffer makes the frame go out in part on Linux; where the
    // option is refused, the default buffer is still smaller than the frame.
    let _ = rustix::net::sockopt::set_socket_send_buffer_size(&sender, 4096);
    let mut sender = HandoffSender::new(sender).unwrap();
    let body = vec![0_u8; FRAME_MAX_LEN];
    assert_eq!(sender.send_frame(&body, &[]).unwrap_err(), HandoffError::Io);
    assert_eq!(
        sender.send_frame(b"", &[]).unwrap_err(),
        HandoffError::Poisoned
    );
    // The sender is still alive, so end of file after what got through
    // proves it shut its writing side down. Without the shutdown the read
    // times out instead of hanging.
    let reader = StdUnixStream::from(reader);
    reader.set_nonblocking(false).unwrap();
    reader
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut drained = Vec::new();
    (&reader).read_to_end(&mut drained).unwrap();
    assert!(drained.len() < body.len() + 2);
}

// Every hand-off frame is small enough that ENOBUFS on it sent nothing.
const _: () = assert!(HANDOFF_MAX_LEN + 2 < ENOBUFS_WHOLE_FRAME_LEN);
