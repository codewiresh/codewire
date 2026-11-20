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
        aliases: Vec::new(),
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
    assert_eq!(&bytes[0..2], &[2, 0]);
    assert_eq!(&bytes[2..4], &(17_u16).to_le_bytes());
    assert_eq!(&bytes[4..6], &443_u16.to_le_bytes());
    assert_eq!(&bytes[6..10], &[160, 79, 104, 10]);
    assert_eq!(&bytes[10..18], &7_u64.to_le_bytes());
    assert_eq!(&bytes[18..20], &(36_u16).to_le_bytes());
    assert_eq!(&bytes[20..37], b"api.anthropic.com");
    assert_eq!(&bytes[37..73], ENVIRONMENT.as_bytes());
    assert_eq!(&bytes[73..], &[0], "no aliases");
    assert_eq!(InterceptedStreamHeader::decode(&bytes).unwrap(), header());

    // The other bound names at the address follow, each length-prefixed.
    let shared = InterceptedStreamHeader {
        hostname: "chatgpt.com".into(),
        aliases: vec!["routed.chatgpt.com".into(), "a.chatgpt.com".into()],
        ..header()
    };
    let bytes = shared.encode().unwrap();
    let names_at = 20 + "chatgpt.com".len() + 36;
    assert_eq!(bytes[names_at], 2);
    assert_eq!(bytes[names_at + 1], 18);
    assert_eq!(&bytes[names_at + 2..names_at + 20], b"routed.chatgpt.com");
    assert_eq!(InterceptedStreamHeader::decode(&bytes).unwrap(), shared);
    let most = InterceptedStreamHeader {
        aliases: (0..HANDOFF_MAX_ALIASES)
            .map(|index| format!("{index}.{}", "a".repeat(251)))
            .collect(),
        hostname: "b".repeat(253),
        ..header()
    };
    let bytes = most.encode().unwrap();
    assert_eq!(bytes.len(), HANDOFF_MAX_LEN);
    assert_eq!(InterceptedStreamHeader::decode(&bytes).unwrap(), most);
}

#[test]
fn malformed_aliases_are_refused() {
    let good = InterceptedStreamHeader {
        aliases: vec!["routed.chatgpt.com".into()],
        ..header()
    }
    .encode()
    .unwrap();
    let names_at = 20 + 17 + 36;
    let mut too_many = good[..names_at].to_vec();
    too_many.push(u8::try_from(HANDOFF_MAX_ALIASES + 1).unwrap());
    let mut empty_name = good[..names_at].to_vec();
    empty_name.extend_from_slice(&[1, 0]);
    let mut upper = good.clone();
    upper[names_at + 2] = b'R';
    let mut short = good.clone();
    short[names_at + 1] = 19;
    let mut trailing = good.clone();
    trailing.push(b'x');
    for bad in [too_many, empty_name, upper, short, trailing] {
        assert_eq!(
            InterceptedStreamHeader::decode(&bad),
            Err(HandoffError::Malformed)
        );
    }
    for bad in [
        InterceptedStreamHeader {
            aliases: vec!["Upper.Example.com".into()],
            ..header()
        },
        InterceptedStreamHeader {
            aliases: vec![String::new()],
            ..header()
        },
        InterceptedStreamHeader {
            aliases: vec!["a.example.com".into(); HANDOFF_MAX_ALIASES + 1],
            ..header()
        },
    ] {
        assert_eq!(bad.encode(), Err(HandoffError::Malformed));
    }
}

#[test]
fn malformed_headers_are_refused() {
    let good = header().encode().unwrap();
    let mut version = good.clone();
    version[0] = 1;
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
    // The environment id ends right before the alias count.
    let id_at = upper_id.len() - 37;
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
    let (header_one, descriptor_one) = receiver.recv_intercepted_stream().unwrap();
    let (header_two, descriptor_two) = receiver.recv_intercepted_stream().unwrap();
    // Dropped only once received: macOS can dispose of a socket whose last
    // reference is in flight while other tests pass descriptors (#3999).
    drop((one, two));
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
fn a_frame_without_a_descriptor_poisons_the_receiver() {
    let (mut sender, mut receiver) = ends();
    sender.send_frame(&header().encode().unwrap(), &[]).unwrap();
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn a_frame_with_two_descriptors_is_refused_and_closed() {
    let (mut sender, mut receiver) = ends();
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
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Poisoned
    );
    // The poisoned receiver shut its socket down: the broker's next send is
    // refused rather than queued.
    let (good, _keep_good) = StdUnixStream::pair().unwrap();
    assert_eq!(
        sender
            .send_intercepted_stream(&header(), good.as_fd())
            .unwrap_err(),
        HandoffError::Closed
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
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut drained = Vec::new();
    (&reader).read_to_end(&mut drained).unwrap();
    assert!(drained.len() < body.len() + 2);
}

// Every hand-off frame is small enough that ENOBUFS on it sent nothing.
const _: () = assert!(HANDOFF_MAX_LEN + 2 < ENOBUFS_WHOLE_FRAME_LEN);

fn tag_ends() -> (HandoffSender, HandoffReceiver) {
    let (sender, receiver) = pair(true);
    (
        HandoffSender::new(sender).unwrap(),
        HandoffReceiver::new(receiver).unwrap(),
    )
}

/// A hang guard, not a product bound: the waits under test are 200 ms.
const TAG_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// #3999: on a blocking socket too, the wait ends at its timeout. Measured
/// on macOS 27.2.1, a blocking receive here once waited for an hour; the
/// wait runs on its own thread, so a regression fails instead of hanging.
#[test]
fn a_missing_role_tag_times_out_on_a_blocking_socket_too() {
    let (broker, front_door) = pair(false);
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut receiver = HandoffReceiver::new(front_door).unwrap();
        let started = std::time::Instant::now();
        let result = receiver.expect_role_tag(std::time::Duration::from_millis(200));
        let _ = done.send((result, started.elapsed()));
    });
    let (result, elapsed) = finished
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the role-tag wait blocked past its timeout");
    assert_eq!(result, Err(HandoffError::RoleTag));
    assert!(elapsed < TAG_WAIT, "{elapsed:?}");
    drop(broker);
}

#[test]
fn the_role_tag_is_accepted_then_streams_follow() {
    let (mut sender, mut receiver) = tag_ends();
    sender.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
    receiver.expect_role_tag(TAG_WAIT).unwrap();
    let (stream, _keep) = StdUnixStream::pair().unwrap();
    sender
        .send_intercepted_stream(&header(), stream.as_fd())
        .unwrap();
    assert_eq!(receiver.recv_intercepted_stream().unwrap().0, header());
}

#[test]
fn a_missing_role_tag_times_out_and_poisons() {
    let (_sender, mut receiver) = tag_ends();
    let started = std::time::Instant::now();
    assert_eq!(
        receiver
            .expect_role_tag(std::time::Duration::from_millis(200))
            .unwrap_err(),
        HandoffError::RoleTag
    );
    assert!(started.elapsed() < TAG_WAIT);
    assert_eq!(
        receiver.recv_frame(FRAME_MAX_LEN, 0).unwrap_err(),
        HandoffError::Poisoned
    );
}

#[test]
fn a_wrong_role_tag_poisons() {
    let (mut sender, mut receiver) = tag_ends();
    sender.send_frame(b"C", &[]).unwrap();
    assert_eq!(
        receiver.expect_role_tag(TAG_WAIT).unwrap_err(),
        HandoffError::RoleTag
    );
}

#[test]
fn a_role_tag_with_a_descriptor_poisons_and_closes_it() {
    let (mut sender, mut receiver) = tag_ends();
    let (stream, keep) = StdUnixStream::pair().unwrap();
    sender
        .send_frame(HANDOFF_ROLE_TAG, &[stream.as_fd()])
        .unwrap();
    assert_eq!(
        receiver.expect_role_tag(TAG_WAIT).unwrap_err(),
        HandoffError::RoleTag
    );
    // Dropped only now: received, so neither kernel disposes of it in flight.
    drop(stream);
    assert_closed(&keep);
}

#[test]
fn a_stream_frame_first_is_not_a_role_tag() {
    let (mut sender, mut receiver) = tag_ends();
    let (stream, _keep) = StdUnixStream::pair().unwrap();
    sender
        .send_intercepted_stream(&header(), stream.as_fd())
        .unwrap();
    assert_eq!(
        receiver.expect_role_tag(TAG_WAIT).unwrap_err(),
        HandoffError::RoleTag
    );
}

#[test]
fn a_repeated_role_tag_is_a_protocol_error() {
    let (mut sender, mut receiver) = tag_ends();
    sender.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
    sender.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
    receiver.expect_role_tag(TAG_WAIT).unwrap();
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Descriptors
    );
    assert_eq!(
        receiver.recv_intercepted_stream().unwrap_err(),
        HandoffError::Poisoned
    );
}

/// A poisoned receiver shuts its socket down, so the broker's next send is
/// refused at once instead of queueing for nobody. The send is non-blocking,
/// so a regression fails here rather than hanging.
#[test]
fn a_poisoned_receiver_makes_the_next_send_fail_at_once() {
    let (mut sender, mut receiver) = tag_ends();
    sender.send_frame(b"C", &[]).unwrap();
    assert!(receiver.expect_role_tag(TAG_WAIT).is_err());
    let (stream, _keep) = StdUnixStream::pair().unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        sender
            .send_intercepted_stream(&header(), stream.as_fd())
            .unwrap_err(),
        HandoffError::Closed
    );
    assert!(started.elapsed() < TAG_WAIT);
}

/// What a test passes in flight: one end of a Unix socket pair, or an
/// accepted loopback TCP connection, the shape of a Mesh ingress connection.
#[derive(Clone, Copy)]
enum Passed {
    Unix,
    Tcp,
}

/// Passes a socket whose peer has written `MESH` `attempts` times, receives
/// each 20 ms later, and counts those whose bytes arrived, while other threads
/// keep discarding sockets still queued in closed carriers. The sender closes
/// its own copy right after sending unless `sender_keeps` holds it until the
/// receiver has taken it.
fn in_flight_sockets_keeping_their_bytes(
    kind: Passed,
    attempts: usize,
    sender_keeps: bool,
) -> usize {
    use std::io::Write as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    let stop = Arc::new(AtomicBool::new(false));
    let churn: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Churn only: an iteration that cannot get its sockets
                    // (a descriptor limit while the suite runs) is skipped.
                    let (Ok((carrier, carrier_end)), Ok((queued, queued_peer))) =
                        (stream_pair(), stream_pair())
                    else {
                        std::thread::yield_now();
                        continue;
                    };
                    if let Ok(mut sender) = HandoffSender::new(carrier) {
                        let _ = sender.send_frame(b"c", &[queued.as_fd()]);
                    }
                    drop((queued, queued_peer, carrier_end));
                }
            })
        })
        .collect();
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (control, control_end) = stream_pair().unwrap();
    let mut sender = HandoffSender::new(control).unwrap();
    let mut receiver = HandoffReceiver::new(control_end).unwrap();
    let mut kept_bytes = 0;
    for _ in 0..attempts {
        // The peer, which must outlive the read, and the socket passed.
        let (peer, passed): (Box<dyn std::any::Any>, OwnedFd) = match kind {
            Passed::Unix => {
                let (peer, passed) = stream_pair().unwrap();
                assert_eq!(rustix::io::write(&peer, b"MESH").unwrap(), 4);
                (Box::new(peer), passed)
            }
            Passed::Tcp => {
                let mut client =
                    std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                client.write_all(b"MESH").unwrap();
                let (accepted, _) = listener.accept().unwrap();
                (Box::new(client), OwnedFd::from(accepted))
            }
        };
        sender.send_frame(b"p", &[passed.as_fd()]).unwrap();
        let held = sender_keeps.then_some(passed);
        std::thread::sleep(Duration::from_millis(20));
        let (_, descriptors) = receiver.recv_frame(1, 1).unwrap();
        drop(held);
        let mut bytes = [0_u8; 4];
        if read_passed(&descriptors[0], &mut bytes) && bytes == *b"MESH" {
            kept_bytes += 1;
        }
        drop(peer);
    }
    stop.store(true, Ordering::Relaxed);
    for thread in churn {
        thread.join().unwrap();
    }
    kept_bytes
}

/// Fills `bytes` from a received socket of either kind, waiting at most
/// 500 ms for each read; false at end of file, on an error, or on a wait that
/// runs out.
fn read_passed(socket: &OwnedFd, bytes: &mut [u8]) -> bool {
    let mut read = 0;
    while read < bytes.len() {
        let mut fds = [rustix::event::PollFd::new(
            socket,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 500_000_000,
        };
        if !matches!(rustix::event::poll(&mut fds, Some(&timeout)), Ok(ready) if ready > 0) {
            return false;
        }
        match rustix::io::read(socket, &mut bytes[read..]) {
            Ok(0) | Err(_) => return false,
            Ok(more) => read += more,
        }
    }
    true
}

/// macOS discards a socket in flight in `SCM_RIGHTS` once its sender has
/// closed its last copy, if the kernel collects in-flight sockets before the
/// receiver takes it: the receiver gets a socket with no data that reads as end
/// of file (#4916). Measured on macOS 27.2.1 with this churn: 200 of 200 Unix
/// sockets and 200 of 200 accepted TCP connections lost, and 14 of 200 Unix
/// sockets with no churn at all. Linux keeps them.
#[cfg(target_os = "macos")]
#[test]
fn macos_loses_an_in_flight_socket_whose_sender_closed_it() {
    for kind in [Passed::Unix, Passed::Tcp] {
        let kept = in_flight_sockets_keeping_their_bytes(kind, 20, false);
        assert!(
            kept < 20,
            "macOS kept every in-flight socket ({kept} of 20): the kernel no longer discards them, \
             so re-measure before relaxing the rule that a sender keeps each passed descriptor \
             until the receiver has it"
        );
    }
}

/// Linux keeps an in-flight socket whose sender closed its copy: the same
/// churn loses nothing there (#4916).
#[cfg(target_os = "linux")]
#[test]
fn linux_keeps_an_in_flight_socket_whose_sender_closed_it() {
    for kind in [Passed::Unix, Passed::Tcp] {
        assert_eq!(in_flight_sockets_keeping_their_bytes(kind, 20, false), 20);
    }
}

/// A sender that keeps its copy until the receiver has taken the socket loses
/// nothing under the same churn: what a descriptor's sender must do on macOS.
#[test]
fn a_sender_that_keeps_its_copy_until_received_loses_nothing() {
    for kind in [Passed::Unix, Passed::Tcp] {
        assert_eq!(in_flight_sockets_keeping_their_bytes(kind, 20, true), 20);
    }
}
