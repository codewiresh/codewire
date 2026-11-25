#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]
//! The real `cw __native-front-door` process, confined, driven as the runner
//! drives it (#3999).

use std::io;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codewire_credential_bridge::{BridgeIdentity, FrontDoorHostSession};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_egress_policy::handoff::{
    HANDOFF_VERSION, HandoffReceiver, HandoffSender, InterceptedStreamHeader, stream_pair,
};
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
use codewire_local_vmm::broker_control::encode_intercept_frame;
use codewire_local_vmm::front_door::{
    DroppedSocket, FRONT_DOOR_CONTROL_FD, FRONT_DOOR_CREDENTIAL_TAG,
    FRONT_DOOR_CREDENTIALS_MESSAGE, FRONT_DOOR_READY_MESSAGE, FRONT_DOOR_SOCKETS_MESSAGE,
    HANDOFF_ROLE_TAG, front_door_dropped_message, front_door_serving_message,
};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::AsyncWriteExt as _;
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

const GENERATION: u64 = 2;
const BOUND: &str = "api.openai.com";
/// Generous, so a loaded CI host fails only a missing frame.
const WAIT: Duration = Duration::from_secs(30);

struct FrontDoorChild(Option<Child>);

impl FrontDoorChild {
    fn pid(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn exited(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            assert!(Instant::now() < deadline, "front door did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for FrontDoorChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn pair(kind: SocketType) -> (OwnedFd, OwnedFd) {
    let (one, two) = socketpair(AddressFamily::UNIX, kind, CLOEXEC, None).unwrap();
    close_on_exec(&one);
    close_on_exec(&two);
    (one, two)
}

/// An unconnected Unix stream socket.
fn unconnected_unix_stream() -> OwnedFd {
    let socket =
        rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, CLOEXEC, None).unwrap();
    close_on_exec(&socket);
    socket
}

#[cfg(target_os = "linux")]
const CLOEXEC: SocketFlags = SocketFlags::CLOEXEC;
// macOS has no SOCK_CLOEXEC: the ends are marked right after they are made,
// and each child sweeps what it inherited before exec.
#[cfg(target_os = "macos")]
const CLOEXEC: SocketFlags = SocketFlags::empty();

fn close_on_exec(socket: &OwnedFd) {
    rustix::io::fcntl_setfd(socket, rustix::io::FdFlags::CLOEXEC).unwrap();
}

/// A socket of the wrong kind for a control socket. macOS has no Unix
/// `SOCK_SEQPACKET`.
#[cfg(target_os = "linux")]
const WRONG_KIND: SocketType = SocketType::SEQPACKET;
#[cfg(target_os = "macos")]
const WRONG_KIND: SocketType = SocketType::DGRAM;

/// The process, with the runner's end of its control socket.
fn spawn(environment_id: Uuid) -> (OwnedFd, FrontDoorChild) {
    let (runner, child_end) = stream_pair().unwrap();
    let child = spawn_with(&environment_id.to_string(), child_end);
    (runner, child)
}

/// The process, given `control` as its control descriptor and `environment_id`
/// as its argument.
fn spawn_with(environment_id: &str, control: OwnedFd) -> FrontDoorChild {
    let source = control.as_raw_fd();
    // Swept on macOS, keeping nothing by number: the hook below dup2s the
    // control socket to its fixed descriptor, and the source stays
    // close-on-exec, so the child holds stdio and that alone.
    let mut command = codewire_local_vmm::swept_command(env!("CARGO_BIN_EXE_cw"), &[]);
    command
        .arg("__native-front-door")
        .arg("--environment-id")
        .arg(environment_id)
        .arg("--generation")
        .arg(GENERATION.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls, placing the control socket at
    // its fixed descriptor without close-on-exec, after the sweep has closed
    // on exec whatever another test's socket left open in the fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, FRONT_DOOR_CONTROL_FD) == -1
                || libc::fcntl(FRONT_DOOR_CONTROL_FD, libc::F_SETFD, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(control);
    FrontDoorChild(Some(child))
}

/// One frame to the process, as the runner's control channel sends it.
fn send_message(socket: &OwnedFd, bytes: &[u8], descriptors: &[std::os::fd::BorrowedFd<'_>]) {
    let duplicate = rustix::io::fcntl_dupfd_cloexec(socket, 0).unwrap();
    HandoffSender::new(duplicate)
        .unwrap()
        .send_frame(bytes, descriptors)
        .unwrap();
}

/// One frame from the process, waiting at most [`WAIT`].
fn receive_message(socket: &OwnedFd) -> Vec<u8> {
    rustix::net::sockopt::set_socket_timeout(
        socket,
        rustix::net::sockopt::Timeout::Recv,
        Some(WAIT),
    )
    .unwrap();
    let duplicate = rustix::io::fcntl_dupfd_cloexec(socket, 0).unwrap();
    let (body, _) = HandoffReceiver::new(duplicate)
        .unwrap()
        .recv_frame(8192, 0)
        .unwrap();
    body
}

fn bindings(hosts: &[&str]) -> Vec<u8> {
    encode_intercept_frame(
        &InterceptSet::new(
            hosts
                .iter()
                .map(|host| InterceptBinding::new(host, 443).unwrap()),
        )
        .unwrap(),
    )
    .unwrap()
}

/// The process's `/proc` status line for `field`.
/// One whole HTTP/1.1 response from `stream`: its head, then its body to the
/// terminating chunk or its content length. A single read may stop after the
/// head, and the rest of the body would then be read as the next response.
async fn read_response(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 512];
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
                let body = &response[end + 4..];
                let complete = if head.contains("transfer-encoding: chunked") {
                    body.ends_with(b"0\r\n\r\n")
                } else {
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                    body.len() >= length
                };
                if complete {
                    return;
                }
            }
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "the response ended early: {response:?}");
            response.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .expect("a whole response");
    response
}

#[cfg(target_os = "linux")]
fn status_field(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .unwrap()
        .trim()
        .to_owned()
}

/// Whether `pid` runs under a Seatbelt profile: `sandbox_check` with no
/// operation reports exactly that.
#[cfg(target_os = "macos")]
fn sandboxed(pid: u32) -> bool {
    unsafe extern "C" {
        fn sandbox_check(
            pid: libc::pid_t,
            operation: *const std::ffi::c_char,
            filter: std::ffi::c_int,
            ...
        ) -> std::ffi::c_int;
    }
    let pid = libc::pid_t::try_from(pid).unwrap();
    // SAFETY: with no operation and no filter, the call reads no further
    // arguments.
    unsafe { sandbox_check(pid, std::ptr::null(), 0) == 1 }
}

/// Driven as the runner drives it, the confined process reports a CA, then
/// terminates TLS for a handed-over stream with it and hands the decrypted
/// request to the credential broker naming its bound host. Closing the
/// hand-off socket stops it.
#[tokio::test]
async fn the_front_door_process_reports_its_ca_and_serves_a_handed_over_stream() {
    let environment_id = Uuid::new_v4();
    let (runner, mut child) = spawn(environment_id);
    send_message(&runner, &bindings(&[BOUND]), &[]);
    let ready = receive_message(&runner);
    let ca = ready
        .strip_prefix(FRONT_DOOR_READY_MESSAGE)
        .expect("a ready message")
        .to_vec();

    // Confined before it had a CA: no new privileges, a syscall filter.
    #[cfg(target_os = "linux")]
    {
        assert_eq!(status_field(child.pid(), "NoNewPrivs"), "1");
        assert_eq!(status_field(child.pid(), "Seccomp"), "2");
    }
    // Confined before it had a CA: under a Seatbelt profile.
    #[cfg(target_os = "macos")]
    assert!(sandboxed(child.pid()));

    let (handoff, handoff_door_end) = stream_pair().unwrap();
    let acknowledgements = rustix::io::fcntl_dupfd_cloexec(&handoff, 0).unwrap();
    let mut handoff = HandoffSender::new(handoff).unwrap();
    // Each peer's role tag comes first, as the brokers send them.
    handoff.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
    let (credentials, credentials_door_end) = std::os::unix::net::UnixStream::pair().unwrap();
    (&credentials)
        .write_all(&[FRONT_DOOR_CREDENTIAL_TAG])
        .unwrap();
    send_message(
        &runner,
        FRONT_DOOR_SOCKETS_MESSAGE,
        &[handoff_door_end.as_fd(), credentials_door_end.as_fd()],
    );
    // Each door end sent stays open until the test ends: on macOS, a socket
    // in flight whose sender has closed its last copy can lose its buffered
    // data and read end of file under load before the receiver takes it
    // (#4916).
    // It has checked both role tags, and says so before it serves.
    assert_eq!(receive_message(&runner), front_door_serving_message(1));
    credentials.set_nonblocking(true).unwrap();
    let credentials = tokio::net::UnixStream::from_std(credentials).unwrap();
    let identity = BridgeIdentity {
        environment_id,
        environment_generation: GENERATION,
    };
    let mut host = tokio::time::timeout(
        WAIT,
        FrontDoorHostSession::open(
            credentials,
            identity,
            &codewire_credential_bridge::front_door_capabilities(true),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let ready = tokio::time::timeout(WAIT, host.receive()).await.unwrap();
    assert!(matches!(
        ready.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));

    let (guest, handed) = std::os::unix::net::UnixStream::pair().unwrap();
    let header = InterceptedStreamHeader {
        version: HANDOFF_VERSION,
        hostname: BOUND.to_owned(),
        port: 443,
        destination_ip: Ipv4Addr::new(192, 0, 2, 1),
        stream_id: 1,
        environment_id: environment_id.to_string(),
        aliases: Vec::new(),
    };
    handoff
        .send_intercepted_stream(&header, handed.as_fd())
        .unwrap();
    // As the broker does, hold the stream until the front door acknowledges
    // it: macOS can dispose of a socket whose last reference is in flight.
    rustix::net::sockopt::set_socket_timeout(
        &acknowledgements,
        rustix::net::sockopt::Timeout::Recv,
        Some(WAIT),
    )
    .unwrap();
    let (acknowledged, descriptors) = HandoffReceiver::new(acknowledgements)
        .unwrap()
        .recv_frame(8, 0)
        .unwrap();
    assert_eq!(acknowledged, header.stream_id.to_le_bytes());
    assert!(descriptors.is_empty());
    drop(handed);
    guest.set_nonblocking(true).unwrap();
    let guest = tokio::net::UnixStream::from_std(guest).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca)).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut tls = tokio::time::timeout(
        WAIT,
        TlsConnector::from(Arc::new(config)).connect(ServerName::try_from(BOUND).unwrap(), guest),
    )
    .await
    .unwrap()
    .expect("the guest trusts the reported CA");
    tls.write_all(
        b"POST /v1/responses HTTP/1.1\r\nhost: api.openai.com\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
    )
    .await
    .unwrap();

    let request = tokio::time::timeout(WAIT, host.receive()).await.unwrap();
    let Some(GuestPayload::Request(seen)) = request.unwrap().unwrap().payload else {
        panic!("expected the request at the credential broker");
    };
    assert_eq!(seen.intercepted_host, BOUND);
    assert_eq!(seen.path, "/responses");
    let sender = host.sender();
    for payload in [
        HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
            request_id: seen.request_id.clone(),
            status_code: 200,
            // The bridge frames the body itself; a host never sends a length.
            headers: Vec::new(),
        }),
        HostPayload::ResponseBody(v1::CredentialBridgeResponseBody {
            request_id: seen.request_id.clone(),
            data: b"ok".to_vec(),
        }),
        HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: seen.request_id.clone(),
        }),
    ] {
        sender
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }
    let response = read_response(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

    // A path the route doesn't serve is refused at the front door, which
    // reports it on its control channel by the route's bound host, its port
    // and the code alone: nothing of the request reaches the runner (#5058).
    tls.write_all(
        b"GET /v2/secret-path?secret-query=1 HTTP/1.1\r\nhost: api.openai.com\r\nx-secret-header: secret-value\r\nauthorization: Bearer secret-token\r\n\r\n",
    )
    .await
    .unwrap();
    let response = read_response(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    let word = receive_message(&runner);
    assert!(!word.windows(6).any(|window| window == b"secret"));
    let report = codewire_local_vmm::front_door::refusals::decode_report(&word).unwrap();
    let [row] = report.rows.as_slice() else {
        panic!("one row: {report:?}");
    };
    assert_eq!(
        (row.host.as_str(), row.port, row.code.as_str(), row.count),
        (BOUND, 443, "path_not_served", 1)
    );

    // A successor whose role tag never comes stalls nothing: a request on
    // the first session is answered well inside the tag's deadline.
    let (_silent, silent_door_end) = std::os::unix::net::UnixStream::pair().unwrap();
    send_message(
        &runner,
        FRONT_DOOR_CREDENTIALS_MESSAGE,
        &[silent_door_end.as_fd()],
    );
    let started = Instant::now();
    tls.write_all(
        b"POST /v1/responses HTTP/1.1\r\nhost: api.openai.com\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
    )
    .await
    .unwrap();
    let request = tokio::time::timeout(WAIT, host.receive()).await.unwrap();
    let Some(GuestPayload::Request(seen)) = request.unwrap().unwrap().payload else {
        panic!("expected the request at the first broker");
    };
    let sender = host.sender();
    for payload in [
        HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
            request_id: seen.request_id.clone(),
            status_code: 200,
            headers: Vec::new(),
        }),
        HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: seen.request_id.clone(),
        }),
    ] {
        sender
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }
    let response = read_response(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );

    // The broker's renewal: its successor pairs with its own session, which
    // takes the next request, and the first's end stops nothing.
    let (renewed, renewed_door_end) = std::os::unix::net::UnixStream::pair().unwrap();
    (&renewed).write_all(&[FRONT_DOOR_CREDENTIAL_TAG]).unwrap();
    send_message(
        &runner,
        FRONT_DOOR_CREDENTIALS_MESSAGE,
        &[renewed_door_end.as_fd()],
    );
    renewed.set_nonblocking(true).unwrap();
    let renewed = tokio::net::UnixStream::from_std(renewed).unwrap();
    let mut successor = tokio::time::timeout(
        WAIT,
        FrontDoorHostSession::open(
            renewed,
            identity,
            &codewire_credential_bridge::front_door_capabilities(true),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let ready = tokio::time::timeout(WAIT, successor.receive())
        .await
        .unwrap();
    assert!(matches!(
        ready.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    // Its word for the silent one, whose tag never came, and then for the
    // successor it took, the generation's third pairing frame.
    assert_eq!(
        receive_message(&runner),
        front_door_dropped_message(2, DroppedSocket::RoleTag)
    );
    assert_eq!(receive_message(&runner), front_door_serving_message(3));
    drop(host);
    tls.write_all(
        b"POST /v1/responses HTTP/1.1\r\nhost: api.openai.com\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
    )
    .await
    .unwrap();
    let request = tokio::time::timeout(WAIT, successor.receive())
        .await
        .unwrap();
    let Some(GuestPayload::Request(seen)) = request.unwrap().unwrap().payload else {
        panic!("expected the request at the successor broker");
    };
    let sender = successor.sender();
    for payload in [
        HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
            request_id: seen.request_id.clone(),
            status_code: 200,
            headers: Vec::new(),
        }),
        HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: seen.request_id.clone(),
        }),
    ] {
        sender
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }
    let response = read_response(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

    drop(handoff);
    assert!(
        !child.exited().success(),
        "a stopped front door exits non-zero"
    );
}

/// Bindings that are missing or not an interception frame stop the process
/// before it confines itself or makes a CA, with a failure line.
#[test]
fn a_front_door_without_valid_bindings_reports_the_stage_and_exits() {
    for bindings in [b"not a frame".to_vec(), bindings(&[])] {
        let (runner, mut child) = spawn(Uuid::new_v4());
        send_message(&runner, &bindings, &[]);
        assert_eq!(receive_message(&runner), b"CWFD1 failed bindings\n");
        assert!(!child.exited().success());
    }
}

/// The sockets frame must carry exactly two connected Unix streams, the
/// hand-off end and the credential session; anything else stops the process.
#[test]
fn a_front_door_given_the_wrong_sockets_reports_the_stage_and_exits() {
    let (_handoff, handoff_door_end) = stream_pair().unwrap();
    let (_peer, datagram) = pair(SocketType::DGRAM);
    let one: Vec<std::os::fd::BorrowedFd<'_>> = vec![handoff_door_end.as_fd()];
    let wrong_kind = vec![handoff_door_end.as_fd(), datagram.as_fd()];
    for descriptors in [one, wrong_kind] {
        let (runner, mut child) = spawn(Uuid::new_v4());
        send_message(&runner, &bindings(&[BOUND]), &[]);
        assert!(receive_message(&runner).starts_with(FRONT_DOOR_READY_MESSAGE));
        send_message(&runner, FRONT_DOOR_SOCKETS_MESSAGE, &descriptors);
        assert_eq!(receive_message(&runner), b"CWFD1 failed sockets\n");
        assert!(!child.exited().success());
    }
}

/// The control socket must be a connected Unix stream; the process refuses
/// to start on anything else.
#[test]
fn a_front_door_refuses_a_control_socket_of_the_wrong_kind() {
    let (_peer, wrong_kind) = pair(WRONG_KIND);
    for control in [wrong_kind, unconnected_unix_stream()] {
        let mut child = spawn_with(&Uuid::new_v4().to_string(), control);
        assert!(!child.exited().success());
    }
}

/// The environment id must be canonical: lowercase, hyphenated, not nil,
/// exactly as the hand-off header carries it.
#[test]
fn a_front_door_refuses_an_environment_id_that_is_not_canonical() {
    let id = Uuid::new_v4();
    for presented in [
        id.to_string().to_uppercase(),
        id.simple().to_string(),
        format!("{{{id}}}"),
        Uuid::nil().to_string(),
    ] {
        let (runner, child_end) = stream_pair().unwrap();
        let mut child = spawn_with(&presented, child_end);
        assert_eq!(
            receive_message(&runner),
            b"CWFD1 failed identity\n",
            "{presented}"
        );
        assert!(!child.exited().success());
    }
}

/// A credential socket that is not connected is refused like a wrong one.
#[test]
fn a_front_door_refuses_an_unconnected_credential_socket() {
    let (runner, mut child) = spawn(Uuid::new_v4());
    send_message(&runner, &bindings(&[BOUND]), &[]);
    assert!(receive_message(&runner).starts_with(FRONT_DOOR_READY_MESSAGE));
    let (_handoff, handoff_door_end) = stream_pair().unwrap();
    let unconnected = unconnected_unix_stream();
    send_message(
        &runner,
        FRONT_DOOR_SOCKETS_MESSAGE,
        &[handoff_door_end.as_fd(), unconnected.as_fd()],
    );
    assert_eq!(receive_message(&runner), b"CWFD1 failed sockets\n");
    assert!(!child.exited().success());
}

/// The two sockets' peers tag them before anything is served, so a swapped
/// pair, or a socket whose peer never tagged it, is refused at once.
#[test]
fn a_front_door_refuses_swapped_or_untagged_sockets() {
    // (hand-off tagged, credential tagged, passed swapped)
    for (tag_handoff, tag_credentials, swapped) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
    ] {
        let (runner, mut child) = spawn(Uuid::new_v4());
        send_message(&runner, &bindings(&[BOUND]), &[]);
        assert!(receive_message(&runner).starts_with(FRONT_DOOR_READY_MESSAGE));
        let (handoff, handoff_door_end) = stream_pair().unwrap();
        let mut handoff = HandoffSender::new(handoff).unwrap();
        if tag_handoff {
            handoff.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
        }
        let (credentials, credentials_door_end) = std::os::unix::net::UnixStream::pair().unwrap();
        if tag_credentials {
            (&credentials)
                .write_all(&[FRONT_DOOR_CREDENTIAL_TAG])
                .unwrap();
        }
        let credentials_door_end = OwnedFd::from(credentials_door_end);
        let passed = if swapped {
            [credentials_door_end.as_fd(), handoff_door_end.as_fd()]
        } else {
            [handoff_door_end.as_fd(), credentials_door_end.as_fd()]
        };
        send_message(&runner, FRONT_DOOR_SOCKETS_MESSAGE, &passed);
        assert_eq!(
            receive_message(&runner),
            b"CWFD1 failed sockets\n",
            "{tag_handoff} {tag_credentials} {swapped}"
        );
        assert!(!child.exited().success());
    }
}

/// SIGTERM ends a serving front door at once: it has no handler, and nothing
/// it inherits blocks or ignores the signal (#5216).
#[test]
fn sigterm_ends_a_serving_front_door_at_once() {
    let (runner, mut child) = spawn(Uuid::new_v4());
    send_message(&runner, &bindings(&[BOUND]), &[]);
    assert!(receive_message(&runner).starts_with(FRONT_DOOR_READY_MESSAGE));
    let (handoff, handoff_door_end) = stream_pair().unwrap();
    let mut handoff = HandoffSender::new(handoff).unwrap();
    handoff.send_frame(HANDOFF_ROLE_TAG, &[]).unwrap();
    let (credentials, credentials_door_end) = std::os::unix::net::UnixStream::pair().unwrap();
    (&credentials)
        .write_all(&[FRONT_DOOR_CREDENTIAL_TAG])
        .unwrap();
    send_message(
        &runner,
        FRONT_DOOR_SOCKETS_MESSAGE,
        &[handoff_door_end.as_fd(), credentials_door_end.as_fd()],
    );
    assert_eq!(receive_message(&runner), front_door_serving_message(1));

    #[cfg(target_os = "linux")]
    {
        let term = 1u64 << (libc::SIGTERM - 1);
        for field in ["SigBlk", "SigIgn"] {
            let mask = u64::from_str_radix(&status_field(child.pid(), field), 16).unwrap();
            assert_eq!(mask & term, 0, "{field} holds SIGTERM");
        }
    }
    let pid = libc::pid_t::try_from(child.pid()).unwrap();
    // SAFETY: a signal to the child this test started and has not reaped.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    // `exited` is the hang guard: it fails after `WAIT`.
    let status = child.exited();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGTERM)
    );
}
