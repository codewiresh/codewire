//! The local runtime's Seatbelt profiles: the egress broker's, the Mesh
//! transport's, the Mesh enrollment issuer's and the TLS front door's. The Seatbelt core, the
//! deny-all profile and the single-thread check are `codewire-confinement`'s.

use std::ffi::{CStr, CString};
use std::io;

// The Seatbelt core and the thread check live in codewire-confinement (#4000).
pub(crate) use codewire_confinement::darwin::require_single_thread;
pub use codewire_confinement::darwin::{apply_profile, deny_all};

/// The Mesh transport's profile. After confinement it dials TCP to its DERP
/// relay (reconnecting as needed) and runs direct UDP: one bound socket that
/// sends STUN probes and WireGuard/disco datagrams to any peer address and
/// port and receives unconnected replies. Each Mesh stream it hands to the
/// runner is an unnamed socketpair, which Seatbelt does not mediate. Files,
/// processes, signals, Mach services, named Unix sockets and TCP listeners
/// are refused, as Landlock and the INET/socketpair syscall filter refuse
/// them on Linux.
const MESH_TRANSPORT_PROFILE: &CStr = c"(version 1)(deny default)\
(allow network-outbound (remote tcp \"*:*\"))\
(allow network-outbound (remote udp \"*:*\"))\
(allow network-bind (local udp \"*:*\"))\
(allow network-inbound (local udp \"*:*\"))";

/// Irreversibly confine the Mesh transport to TCP dials and direct UDP.
pub(crate) fn confine_mesh_transport() -> io::Result<()> {
    apply_profile(MESH_TRANSPORT_PROFILE)
}

/// Irreversibly confine the one-shot Mesh enrollment issuer to TCP dials to
/// its Mesh origin's port. It has already pinned the origin's addresses, so
/// it needs no DNS; the only request it makes after confinement is the one
/// enrollment.
pub(crate) fn confine_mesh_enrollment(origin_port: u16) -> io::Result<()> {
    if origin_port == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let profile = CString::new(format!(
        "(version 1)(deny default)(allow network-outbound (remote tcp \"*:{origin_port}\"))"
    ))
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    apply_profile(&profile)
}

/// Irreversibly confine the TLS front door (#3999) to the descriptors it
/// holds and the ones it receives over them: it opens nothing, dials
/// nothing and starts nothing, so it takes the deny-all profile.
pub(crate) fn confine_front_door() -> io::Result<()> {
    deny_all()
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    use super::*;

    // The broker's profile is `codewire-egress-worker`'s; its tests run here,
    // beside the close-on-exec sweep and UDP probe their children need.
    use codewire_egress_worker::darwin::confine_egress_broker;

    /// #3999: the broker profile admits the front-door hand-off as the broker
    /// makes it after confinement. A new socketpair's end goes to the front
    /// door with its length-prefixed header over the held hand-off socket and
    /// carries bytes both ways, and the front door's acknowledgement wakes a
    /// reader on the broker's runtime. Named Unix sockets, TCP listeners and
    /// files stay refused.
    /// The broker profile admits exactly what the broker does after
    /// confinement: dial TCP, hand the connected stream on over a held Unix
    /// socket, and run hickory's DNS exchange (UDP bind, send to port 53,
    /// unconnected receive). Everything else stays refused. If Seatbelt stops
    /// accepting the profile, or narrows or widens it, this test fails.
    #[test]
    fn egress_broker_profile_admits_only_tcp_dials_and_dns() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_EGRESS_BROKER";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (held, mut peer) = UnixStream::pair().unwrap();
            confine_egress_broker().unwrap();

            let dialed = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            // The hand-off's sendmsg with one descriptor; which marker byte
            // rides with it does not matter to the profile.
            crate::network_worker::send_worker_descriptor(
                held.as_raw_fd(),
                dialed.as_raw_fd(),
                crate::network_worker::WORKER_NETWORK_DESCRIPTOR_MARKER,
            )
            .unwrap();
            let mut marker = [0_u8; 1];
            peer.read_exact(&mut marker).unwrap();

            let dns = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
            announce_udp_port(&dns);
            dns.send_to(b"query", "127.0.0.1:53").unwrap();
            let refused = dns.send_to(b"query", "127.0.0.1:9").unwrap_err();
            assert_eq!(refused.raw_os_error(), Some(libc::EPERM));
            dns.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reply = [0_u8; 5];
            let (length, _) = dns.recv_from(&mut reply).unwrap();
            assert_eq!(&reply[..length], b"reply");

            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(std::fs::File::create("/private/tmp/codewire-broker-probe").is_err());
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            return;
        }
        assert!(
            run_child_receiving_udp(
                "darwin::sandbox::tests::egress_broker_profile_admits_only_tcp_dials_and_dns",
                CHILD_MARKER,
            )
            .success()
        );
    }

    /// #3999: the broker profile admits the front-door hand-off as the broker
    /// makes it after confinement. A new socketpair's end goes to the front
    /// door with its length-prefixed header over the held hand-off socket and
    /// carries bytes both ways, and the front door's acknowledgement wakes a
    /// reader on the broker's runtime. Named Unix sockets, TCP listeners and
    /// files stay refused.
    #[test]
    fn egress_broker_profile_admits_the_front_door_hand_off() {
        use std::os::fd::AsFd as _;

        use codewire_egress_broker::handoff::HANDOFF_ACK_LEN;
        use codewire_egress_policy::handoff::{
            HANDOFF_VERSION, HandoffReceiver, HandoffSender, InterceptedStreamHeader, stream_pair,
        };

        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_EGRESS_HANDOFF";
        if std::env::var_os(CHILD_MARKER).is_some() {
            // Made before confinement, as the broker makes them at startup.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            let (broker_end, front_door_end) = stream_pair().unwrap();
            let readable = UnixStream::from(broker_end.try_clone().unwrap());
            readable.set_nonblocking(true).unwrap();
            let readable = runtime
                .block_on(async { tokio::net::UnixStream::from_std(readable) })
                .unwrap();
            let mut sender = HandoffSender::new(broker_end.try_clone().unwrap()).unwrap();
            let mut acknowledgements = HandoffReceiver::new(broker_end).unwrap();
            let mut front_door = HandoffReceiver::new(front_door_end.try_clone().unwrap()).unwrap();
            let mut acknowledging = HandoffSender::new(front_door_end).unwrap();
            confine_egress_broker().unwrap();

            let (worker, handed) = stream_pair().unwrap();
            let header = InterceptedStreamHeader {
                version: HANDOFF_VERSION,
                hostname: "allowed.example.com".into(),
                port: 443,
                destination_ip: std::net::Ipv4Addr::new(192, 0, 2, 7),
                stream_id: 1,
                environment_id: "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11".into(),
                aliases: Vec::new(),
            };
            sender
                .send_intercepted_stream(&header, handed.as_fd())
                .unwrap();
            let (received_header, received) = front_door.recv_intercepted_stream().unwrap();
            drop(handed);
            assert_eq!(received_header, header);
            let (mut worker, mut received) = (UnixStream::from(worker), UnixStream::from(received));
            let mut byte = [0_u8; 1];
            worker.write_all(b"w").unwrap();
            received.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"w");
            received.write_all(b"f").unwrap();
            worker.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"f");

            acknowledging
                .send_frame(&header.stream_id.to_le_bytes(), &[])
                .unwrap();
            runtime.block_on(readable.readable()).unwrap();
            let (body, descriptors) = acknowledgements.recv_frame(HANDOFF_ACK_LEN, 0).unwrap();
            assert_eq!(body, header.stream_id.to_le_bytes());
            assert!(descriptors.is_empty());

            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            return;
        }
        let status = crate::test_child(&mut std::process::Command::new(
            std::env::current_exe().unwrap(),
        ))
        .arg("--exact")
        .arg("darwin::sandbox::tests::egress_broker_profile_admits_the_front_door_hand_off")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
        assert!(status.success());
    }

    /// The Mesh transport profile admits TCP dials and direct UDP to any
    /// address and port, and unnamed socketpairs for Mesh streams, and
    /// refuses everything else.
    #[test]
    fn mesh_transport_profile_admits_only_tcp_dials_and_direct_udp() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_MESH_TRANSPORT";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            confine_mesh_transport().unwrap();

            std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut stream, mut peer) = UnixStream::pair().unwrap();
            stream.write_all(b"m").unwrap();
            let mut byte = [0_u8; 1];
            peer.read_exact(&mut byte).unwrap();

            let udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
            announce_udp_port(&udp);
            udp.send_to(b"stun", "127.0.0.1:3478").unwrap();
            udp.send_to(b"wireguard", "127.0.0.1:41641").unwrap();
            udp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reply = [0_u8; 5];
            let (length, _) = udp.recv_from(&mut reply).unwrap();
            assert_eq!(&reply[..length], b"reply");

            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            return;
        }
        assert!(
            run_child_receiving_udp(
                "darwin::sandbox::tests::mesh_transport_profile_admits_only_tcp_dials_and_direct_udp",
                CHILD_MARKER,
            )
            .success()
        );
    }

    /// The enrollment issuer may dial only its Mesh origin's port.
    #[test]
    fn mesh_enrollment_profile_admits_only_its_origin_port() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_MESH_ENROLLMENT";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            assert!(confine_mesh_enrollment(0).is_err());
            confine_mesh_enrollment(origin.local_addr().unwrap().port()).unwrap();

            std::net::TcpStream::connect(origin.local_addr().unwrap()).unwrap();
            let refused = std::net::TcpStream::connect(other.local_addr().unwrap()).unwrap_err();
            assert_eq!(refused.raw_os_error(), Some(libc::EPERM));
            assert!(
                std::net::UdpSocket::bind("0.0.0.0:0")
                    .and_then(|socket| socket.send_to(b"query", "127.0.0.1:53"))
                    .is_err()
            );
            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("darwin::sandbox::tests::mesh_enrollment_profile_admits_only_its_origin_port")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Run one confined test child and keep sending a "reply" datagram to the
    /// UDP port named in its marker until it exits; only inbound UDP lets
    /// the child see it.
    const UDP_PORT_LINE: &str = "codewire-test-udp-port=";

    /// The confined child binds its UDP socket to port 0 (a port picked
    /// beforehand could be taken in between) and reports the port on its
    /// stdout, a descriptor it already holds.
    fn announce_udp_port(socket: &std::net::UdpSocket) {
        println!("{UDP_PORT_LINE}{}", socket.local_addr().unwrap().port());
    }

    /// Runs one test as a confined child and sends `reply` to the UDP port
    /// it reports until it exits.
    fn run_child_receiving_udp(test: &str, marker: &str) -> std::process::ExitStatus {
        use std::io::BufRead as _;

        let mut child = crate::test_child(&mut std::process::Command::new(
            std::env::current_exe().unwrap(),
        ))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(marker, "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (port_sender, port_receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                match line.strip_prefix(UDP_PORT_LINE) {
                    Some(port) => {
                        let _ = port_sender.send(port.parse::<u16>().unwrap());
                    }
                    None => println!("{line}"),
                }
            }
        });
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut port = None;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("the confined probe {test} did not finish");
            }
            port = port.or_else(|| port_receiver.try_recv().ok());
            if let Some(port) = port {
                let _ = sender.send_to(b"reply", ("127.0.0.1", port));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// `bootstrap_look_up`'s status for `service`: 0 when it resolves.
    fn bootstrap_look_up_status(service: &std::ffi::CStr) -> i32 {
        unsafe extern "C" {
            static bootstrap_port: u32;
            fn bootstrap_look_up(
                bootstrap: u32,
                service: *const std::ffi::c_char,
                port: *mut u32,
            ) -> i32;
        }
        let mut port = 0_u32;
        // SAFETY: a NUL-terminated name and an out-pointer to a local; a
        // right it returns is this test child's and ends with it.
        unsafe { bootstrap_look_up(bootstrap_port, service.as_ptr(), &mut port) }
    }

    /// #3999: what the front door does after confinement still works: it
    /// makes its CA, takes a stream passed over a socket it holds, and
    /// carries bytes on it. Every file, named or network endpoint, listener,
    /// process, signal to another process and Mach service lookup is refused.
    #[test]
    fn front_door_profile_keeps_received_streams_and_refuses_new_authority() {
        use std::os::fd::AsFd as _;

        use codewire_egress_policy::handoff::{HandoffReceiver, HandoffSender, stream_pair};
        use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};

        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_FRONT_DOOR";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let (broker_end, front_door_end) = stream_pair().unwrap();
            let mut sender = HandoffSender::new(broker_end).unwrap();
            let mut receiver = HandoffReceiver::new(front_door_end).unwrap();
            // Before confinement the parent takes a signal check and a Mach
            // service resolves, so their refusals below are the profile's.
            // SAFETY: getppid has no preconditions; signal 0 sends nothing.
            assert_eq!(unsafe { libc::kill(libc::getppid(), 0) }, 0);
            assert_eq!(
                bootstrap_look_up_status(c"com.apple.system.notification_center"),
                0
            );
            confine_front_door().unwrap();
            // SAFETY: as above.
            assert_eq!(unsafe { libc::kill(libc::getppid(), 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            assert_ne!(
                bootstrap_look_up_status(c"com.apple.system.notification_center"),
                0
            );

            let intercepts =
                InterceptSet::new([InterceptBinding::new("api.openai.com", 443).unwrap()]).unwrap();
            let door = codewire_egress_front_door_bridge::EnvironmentFrontDoor::start(
                uuid::Uuid::new_v4(),
                2,
                intercepts,
            )
            .unwrap();
            assert!(!door.ca_certificate_der().is_empty());

            let (worker, passed) = stream_pair().unwrap();
            sender.send_frame(b"s", &[passed.as_fd()]).unwrap();
            let (_, mut descriptors) = receiver.recv_frame(1, 1).unwrap();
            drop(passed);
            let (mut worker, mut received) = (
                UnixStream::from(worker),
                UnixStream::from(descriptors.pop().unwrap()),
            );
            let mut byte = [0_u8; 1];
            worker.write_all(b"w").unwrap();
            received.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"w");
            received.write_all(b"f").unwrap();
            worker.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"f");

            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(std::fs::File::create("/private/tmp/codewire-front-door-probe").is_err());
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            assert!(
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .and_then(|socket| socket.send_to(b"x", "127.0.0.1:9"))
                    .is_err()
            );
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            return;
        }
        let status = crate::test_child(&mut std::process::Command::new(
            std::env::current_exe().unwrap(),
        ))
        .arg("--exact")
        .arg("darwin::sandbox::tests::front_door_profile_keeps_received_streams_and_refuses_new_authority")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
        assert!(status.success());
    }
}
