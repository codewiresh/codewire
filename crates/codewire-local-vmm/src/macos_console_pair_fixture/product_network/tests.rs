use std::ffi::CString;
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use codewire_egress_policy::{CompiledPolicy, DecisionReason, EgressRequest, RouteClass};

use super::endpoint;
use super::topology::fixtures;
use super::{
    ENDPOINT_CANCEL_MESSAGE, ENDPOINT_COMPLETED_MESSAGE, ENDPOINT_READY_MESSAGE, PUBLIC_ADDRESS,
    PUBLIC_PORT, payload,
};
use crate::macos_console_pair_fixture::{descriptor as fd, process};

#[cfg(feature = "macos-workload-network-fixture")]
#[test]
fn actual_workload_client_and_service_endpoint_share_exact_transcript() {
    use codewire_vmm_guest_probe::macos_workload_network_fixture as client;
    use sha2::{Digest as _, Sha256};

    assert_eq!(super::destination(), SocketAddr::V4(client::DESTINATION));
    assert_eq!(payload(false), client::request_payload());
    assert_eq!(payload(true), client::response_payload());
    assert_eq!(<[u8; 32]>::from(Sha256::digest(payload(false))), client::REQUEST_SHA256);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(payload(true))), client::RESPONSE_SHA256);
}

#[test]
fn topology_requests_and_inventory_are_strict() {
    let initial = fixtures::initial_inventory();
    assert_eq!(fixtures::validate_initial(&initial).unwrap(), 1);
    let configured = fixtures::configured_inventory();
    fixtures::validate_configured(&configured, 1).unwrap();
    assert!(fixtures::initial_rejects_preconfigured_link());
    assert!(fixtures::configured_rejects_extra_link());
    assert!(fixtures::configured_rejects_extra_address());
    assert!(fixtures::configured_rejects_default_route());
    assert!(fixtures::configured_rejects_wrong_route());
    assert!(fixtures::configured_rejects_ipv6());

    let link = fixtures::encode_link(7, 1).unwrap();
    assert!(fixtures::encoded_link_is_exact(&link, 7, 1));
    let address = fixtures::encode_address(8, 1).unwrap();
    assert!(fixtures::encoded_address_is_exact(&address, 8, 1));
    assert_eq!(fixtures::roundtrip_link_message(9).unwrap().name, "lo");
    assert!(fixtures::encode_link(1, 0).is_err());
    assert!(fixtures::encode_address(1, 0).is_err());
}

#[test]
fn netlink_decoder_rejects_truncation_sequence_and_sender_substitution() {
    let valid = fixtures::encode_link(17, 1).unwrap();
    for length in 0..valid.len() {
        assert!(fixtures::rejects_datagram(&valid[..length], 17));
    }
    assert!(fixtures::rejects_datagram(&valid, 18));
    let mut sender = valid.clone();
    sender[12..16].copy_from_slice(&1_u32.to_ne_bytes());
    assert!(fixtures::rejects_datagram(&sender, 17));
    let mut kernel_sender = sender;
    kernel_sender[12..16].copy_from_slice(&0_u32.to_ne_bytes());
    assert!(!fixtures::rejects_datagram(&kernel_sender, 17));
    let mut oversized = valid;
    oversized[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert!(fixtures::rejects_datagram(&oversized, 17));

    let request = fixtures::encode_link(19, 1).unwrap();
    let success = fixtures::ack_payload(&request, 0).unwrap();
    assert_eq!(fixtures::parse_ack(&success, &request).unwrap(), 0);
    let denied = fixtures::ack_payload(&request, -libc::EPERM).unwrap();
    assert_eq!(
        fixtures::parse_ack(&denied, &request).unwrap(),
        -libc::EPERM
    );
    for invalid_error in [1, -4096, i32::MIN] {
        let malformed = fixtures::ack_payload(&request, invalid_error).unwrap();
        assert!(fixtures::parse_ack(&malformed, &request).is_err());
    }
    for offset in [4, 4 + 4, 4 + 8, 4 + 12] {
        let mut substituted = success.clone();
        substituted[offset] ^= 1;
        assert!(fixtures::parse_ack(&substituted, &request).is_err());
    }
    assert!(fixtures::parse_ack(&success[..success.len() - 1], &request).is_err());
}

#[test]
fn actual_kernel_netlink_inventory_dump_is_bounded_and_parseable() {
    fixtures::validate_kernel_inventory_dump().unwrap();
}

#[test]
fn endpoint_control_check_is_zero_wait_and_retains_partial_cancel() {
    endpoint::verify_zero_wait_and_retained_partial_cancel().unwrap();
}

#[test]
fn baseline_policy_accepts_only_the_fixed_public_class_shape() {
    let policy = CompiledPolicy::developer_baseline();
    let admitted = EgressRequest::tcp(
        PUBLIC_ADDRESS.into(),
        PUBLIC_PORT,
        None,
        RouteClass::General,
    )
    .unwrap();
    assert!(policy.evaluate(&admitted).is_allowed());
    for denied in [
        EgressRequest::tcp(
            Ipv4Addr::LOCALHOST.into(),
            PUBLIC_PORT,
            None,
            RouteClass::General,
        )
        .unwrap(),
        EgressRequest::tcp(
            Ipv4Addr::new(198, 51, 100, 7).into(),
            PUBLIC_PORT,
            None,
            RouteClass::General,
        )
        .unwrap(),
        EgressRequest::tcp(PUBLIC_ADDRESS.into(), 4242, None, RouteClass::General).unwrap(),
        EgressRequest::tcp(
            PUBLIC_ADDRESS.into(),
            PUBLIC_PORT,
            Some("fixture.test"),
            RouteClass::General,
        )
        .unwrap(),
    ] {
        assert!(!policy.evaluate(&denied).is_allowed());
    }
    assert_eq!(
        policy
            .evaluate(
                &EgressRequest::tcp(
                    PUBLIC_ADDRESS.into(),
                    PUBLIC_PORT,
                    Some("fixture.test"),
                    RouteClass::General,
                )
                .unwrap(),
            )
            .reason,
        DecisionReason::ProtectedName(codewire_egress_policy::NameClass::Reserved)
    );
}

#[test]
#[ignore = "fixed confined child invoked only by owned parent tests"]
fn confined_product_endpoint_child() {
    let run = || -> io::Result<()> {
        let executable = CString::new(std::env::current_exe()?.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        endpoint::run_inherited_endpoint_for_test(&executable)
    };
    std::process::exit(if run().is_ok() { 0 } else { 71 });
}

#[test]
fn confined_endpoint_completes_one_exact_tcp_exchange() {
    let (mut child, mut control, address) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let request = payload(false);
    for chunk in request.chunks(127) {
        stream.write_all(chunk).unwrap();
    }
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = [0_u8; 4096];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response, payload(true));
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).unwrap(), 0);
    read_exact_bounded(&mut control, ENDPOINT_COMPLETED_MESSAGE);
    assert_child(&mut child, true);
}

#[test]
fn confined_endpoint_rejects_wrong_payload_without_completion() {
    let (mut child, mut control, address) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    let mut stream = TcpStream::connect(address).unwrap();
    let mut request = payload(false);
    request[2048] ^= 1;
    stream.write_all(&request).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert_child(&mut child, false);
    assert_stream_closed_without(&mut control, ENDPOINT_COMPLETED_MESSAGE);
}

#[test]
fn confined_endpoint_rejects_trailing_data_without_completion() {
    let (mut child, mut control, address) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(&payload(false)).unwrap();
    stream.write_all(b"unexpected").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert_child(&mut child, false);
    assert_stream_closed_without(&mut control, ENDPOINT_COMPLETED_MESSAGE);
}

#[test]
fn confined_endpoint_rejects_a_different_loopback_peer() {
    let (mut child, mut control, address) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    let stream = connect_from(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0), address);
    assert_child(&mut child, false);
    assert_stream_closed_without(&mut control, ENDPOINT_COMPLETED_MESSAGE);
    drop(stream);
}

#[test]
fn confined_endpoint_rejects_queued_cancel_before_response() {
    let (mut child, mut control, address) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(&payload(false)).unwrap();
    control.write_all(ENDPOINT_CANCEL_MESSAGE).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert_child(&mut child, false);
    assert_stream_closed_without(&mut control, ENDPOINT_COMPLETED_MESSAGE);
}

#[test]
fn confined_endpoint_cancel_is_failure_and_never_completion() {
    let (mut child, mut control, _) = spawn_endpoint();
    read_exact_bounded(&mut control, ENDPOINT_READY_MESSAGE);
    control.write_all(ENDPOINT_CANCEL_MESSAGE).unwrap();
    assert_child(&mut child, false);
    assert_stream_closed_without(&mut control, ENDPOINT_COMPLETED_MESSAGE);
}

#[test]
fn listener_validation_rejects_wrong_type_blocking_and_nonlistener() {
    let (unix, _) = UnixStream::pair().unwrap();
    assert!(
        super::topology::validate_listener(unix.as_raw_fd(), "127.0.0.1:1".parse().unwrap())
            .is_err()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert!(super::topology::validate_listener(listener.as_raw_fd(), address).is_err());
    listener.set_nonblocking(true).unwrap();
    set_cloexec(listener.as_raw_fd());
    super::topology::validate_listener(listener.as_raw_fd(), address).unwrap();
    let stream = TcpStream::connect(address).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let (accepted, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "listener accept exceeded deadline"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    drop(stream);
    assert!(super::topology::validate_listener(accepted.as_raw_fd(), address).is_err());
}

fn connect_from(source: SocketAddrV4, destination: SocketAddr) -> TcpStream {
    let SocketAddr::V4(destination) = destination else {
        panic!("test endpoint must be IPv4");
    };
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    assert!(raw >= 0, "socket failed: {}", io::Error::last_os_error());
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let source = socket_address(source);
    assert_eq!(
        unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const source).cast(),
                std::mem::size_of_val(&source) as libc::socklen_t,
            )
        },
        0,
        "bind failed: {}",
        io::Error::last_os_error()
    );
    let destination = socket_address(destination);
    assert_eq!(
        unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&raw const destination).cast(),
                std::mem::size_of_val(&destination) as libc::socklen_t,
            )
        },
        0,
        "connect failed: {}",
        io::Error::last_os_error()
    );
    TcpStream::from(socket)
}

fn socket_address(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn spawn_endpoint() -> (process::OwnedChild, UnixStream, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    set_cloexec(listener.as_raw_fd());
    let address = listener.local_addr().unwrap();
    let (control, child_control) = UnixStream::pair().unwrap();
    for stream in [&control, &child_control] {
        stream.set_nonblocking(true).unwrap();
    }
    let arguments = [
        "--exact",
        "macos_console_pair_fixture::product_network::tests::confined_product_endpoint_child",
        "--ignored",
        "--nocapture",
    ]
    .map(String::from);
    let child = process::spawn(
        &std::env::current_exe().unwrap(),
        &arguments,
        &[(listener.as_raw_fd(), 3), (child_control.as_raw_fd(), 4)],
    )
    .unwrap();
    drop(listener);
    drop(child_control);
    (child, control, address)
}

fn read_exact_bounded(stream: &mut UnixStream, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut received = vec![0_u8; expected.len()];
    let mut position = 0;
    while position < received.len() {
        match stream.read(&mut received[position..]) {
            Ok(0) => panic!("endpoint status closed before marker"),
            Ok(count) => position += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                fd::poll(
                    &mut [fd::pollfd(stream.as_raw_fd(), libc::POLLIN)],
                    deadline,
                )
                .unwrap();
            }
            Err(error) => panic!("endpoint status read failed: {error}"),
        }
    }
    assert_eq!(received, expected);
}

fn assert_stream_closed_without(stream: &mut UnixStream, forbidden: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = Vec::new();
    loop {
        let mut bytes = [0_u8; 64];
        match stream.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => received.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                fd::poll(
                    &mut [fd::pollfd(stream.as_raw_fd(), libc::POLLIN)],
                    deadline,
                )
                .unwrap();
            }
            Err(error) => panic!("endpoint status read failed: {error}"),
        }
    }
    assert!(
        !received
            .windows(forbidden.len())
            .any(|bytes| bytes == forbidden)
    );
}

fn assert_child(child: &mut process::OwnedChild, success: bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.poll().unwrap() {
            assert_eq!(
                status.success(),
                success,
                "unexpected endpoint exit: {status}"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "endpoint child exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn set_cloexec(descriptor: i32) {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
        0
    );
}
