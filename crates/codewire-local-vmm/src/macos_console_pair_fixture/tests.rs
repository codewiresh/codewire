use super::binding::{BINDING_LEN, Binding, Control, Role, Status};
use super::{descriptor as fd, packet, process};
use codewire_vmm_guest_probe::NetworkKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn document(role: &str) -> serde_json::Value {
    serde_json::json!({"schemaVersion": 1, "role": role,
        "vmID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "generation": 7,
        "runNonce": "11".repeat(32), "networkKey": "22".repeat(32), "statusKey": "33".repeat(32)})
}
fn sealed(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.resize(BINDING_LEN, 0);
    bytes
}
fn binding(role: Role) -> Binding {
    Binding::decode(
        &sealed(&document(if role == Role::Guest {
            "guest"
        } else {
            "service"
        })),
        role,
    )
    .unwrap()
}

#[test]
fn sealed_binding_is_exact_role_identity_and_zero_padded() {
    let good = sealed(&document("guest"));
    assert!(Binding::decode(&good, Role::Guest).is_ok());
    assert!(Binding::decode(&good, Role::Service).is_err());
    assert!(Binding::decode(&good[..4095], Role::Guest).is_err());
    let mut bad = good.clone();
    bad[4095] = 1;
    assert!(Binding::decode(&bad, Role::Guest).is_err());
    for (field, value) in [
        ("schemaVersion", serde_json::json!(2)),
        ("generation", serde_json::json!(0)),
        ("vmID", serde_json::json!(Uuid::nil().to_string())),
        (
            "vmID",
            serde_json::json!("DDDDDDDD-DDDD-4DDD-8DDD-DDDDDDDDDDDD"),
        ),
        ("runNonce", serde_json::json!("00".repeat(32))),
        ("networkKey", serde_json::json!("33".repeat(32))),
        ("statusKey", serde_json::json!("AA".repeat(32))),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut value_doc = document("guest");
        value_doc[field] = value;
        assert!(
            Binding::decode(&sealed(&value_doc), Role::Guest).is_err(),
            "{field}"
        );
    }
    let mut duplicate = serde_json::to_string(&document("guest")).unwrap();
    duplicate.insert_str(1, "\"generation\":7,");
    let mut bytes = duplicate.into_bytes();
    bytes.resize(BINDING_LEN, 0);
    assert!(Binding::decode(&bytes, Role::Guest).is_err());
}

#[test]
fn controls_bind_every_field_direction_sequence_and_tag() {
    let guest = binding(Role::Guest);
    let service = binding(Role::Service);
    for code in [
        Control::Start,
        Control::Cancel,
        Control::ClosePacket,
        Control::ObserveEof,
        Control::PowerOff,
    ] {
        let frame = guest.test_control(code, 1);
        assert_eq!(guest.control(&frame, 1).unwrap(), code);
        assert!(guest.control(&frame, 2).is_err());
        assert!(guest.control(&frame, 0).is_err());
        assert!(service.control(&frame, 1).is_err());
        for index in [0, 8, 9, 10, 15, 16, 32, 40, 72, 80, 95, 96, 127] {
            let mut modified = frame;
            modified[index] ^= 128;
            assert!(guest.control(&modified, 1).is_err(), "byte {index}");
        }
    }
    assert!(
        guest
            .control(&guest.status(Status::PortsReady, 1), 1)
            .is_err()
    );
}

#[test]
fn child_wait_status_offsets_are_service_only_and_authenticated() {
    let service = binding(Role::Service);
    let frame = service.reaped(4, 9472, 0).unwrap();
    assert_eq!(&frame[..8], b"CWCPST1\0");
    assert_eq!(&frame[8..10], &[2, 10]);
    assert_eq!(&frame[80..84], &9472_i32.to_le_bytes());
    assert_eq!(&frame[84..96], &[0; 12]);
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x33; 32]).unwrap();
    mac.update(b"codewire-console-pair-status-v1\0");
    mac.update(&frame[..96]);
    mac.verify_slice(&frame[96..]).unwrap();
    assert!(binding(Role::Guest).reaped(1, 0, 0).is_err());
    assert_eq!(&service.status(Status::EofArmed, 1)[80..96], &[0; 16]);
}

#[test]
fn device_number_parser_is_strict() {
    assert_eq!(fd::dev_number(b"1:3\n").unwrap(), libc::makedev(1, 3));
    for bad in [
        b"1:3".as_slice(),
        b"1:3\nextra",
        b"-1:3\n",
        b"1:+3\n",
        b"1:3:4\n",
        b":3\n",
        b"4294967296:3\n",
    ] {
        assert!(fd::dev_number(bad).is_err());
    }
}
fn fake_port(class: &Path, name: &str, role: &str) {
    fs::create_dir(class.join(name)).unwrap();
    fs::write(class.join(name).join("name"), format!("{role}\n")).unwrap();
    fs::write(class.join(name).join("dev"), "1:3\n").unwrap();
}
#[test]
fn port_discovery_rejects_duplicates_regular_nodes_symlinks_and_missing_names() {
    let temp = tempfile::tempdir().unwrap();
    let class = temp.path().join("class");
    let dev = temp.path().join("dev");
    fs::create_dir(&class).unwrap();
    fs::create_dir(&dev).unwrap();
    assert_eq!(
        fd::discover_port_at(&class, &dev, fd::PACKET_PORT)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    fake_port(&class, "vport9p7", fd::PACKET_PORT);
    fs::write(dev.join("vport9p7"), []).unwrap();
    assert!(fd::discover_port_at(&class, &dev, fd::PACKET_PORT).is_err());
    fs::remove_file(dev.join("vport9p7")).unwrap();
    std::os::unix::fs::symlink("/dev/null", dev.join("vport9p7")).unwrap();
    assert!(fd::discover_port_at(&class, &dev, fd::PACKET_PORT).is_err());
    fake_port(&class, "vport9p8", fd::PACKET_PORT);
    assert_eq!(
        fd::discover_port_at(&class, &dev, fd::PACKET_PORT)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[test]
fn descriptors_reject_aliases_wrong_classes_listeners_and_blocking() {
    let (a, b) = UnixStream::pair().unwrap();
    fd::unix_stream(a.as_raw_fd()).unwrap();
    fd::distinct(&[a.as_raw_fd(), b.as_raw_fd()]).unwrap();
    assert!(fd::require_rw_nonblocking(a.as_raw_fd()).is_err());
    fd::nonblocking(a.as_raw_fd()).unwrap();
    fd::require_rw_nonblocking(a.as_raw_fd()).unwrap();
    assert!(fd::distinct(&[a.as_raw_fd(), a.as_raw_fd()]).is_err());
    assert!(fd::distinct(&[a.as_raw_fd(), a.try_clone().unwrap().as_raw_fd()]).is_err());
    let null = fs::File::open("/dev/null").unwrap();
    assert!(fd::unix_stream(null.as_raw_fd()).is_err());
    let temp = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(temp.path().join("listener")).unwrap();
    assert!(fd::unix_stream(listener.as_raw_fd()).is_err());
}

#[tokio::test]
async fn actual_worker_authenticates_dns_and_binary_tcp_with_injected_broker() {
    let identity = Uuid::from_u128(0xdddddddddddd4ddd8ddddddddddddddd);
    let key = || NetworkKey::from_derived_bytes([0x22; 32]).unwrap();
    let (host, mut guest) = tokio::io::duplex(64 * 1024);
    let (ready, ready_rx) = tokio::sync::oneshot::channel();
    let host = tokio::spawn(crate::network_worker::run_host_session(
        host,
        key(),
        identity,
        7,
        Arc::new(packet::FixtureBroker::new(false)),
        move || ready.send(()).map_err(|_| super::invalid()),
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        let session = packet::authenticate(&mut guest, key(), identity, 7)
            .await
            .unwrap();
        ready_rx.await.unwrap();
        packet::traffic(&mut guest, session).await.unwrap();
    })
    .await
    .expect("fixed real packet transcript exceeded deadline");
    drop(guest);
    let exit = tokio::time::timeout(Duration::from_secs(2), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(exit.exit_code(), 37);
}
#[tokio::test]
async fn actual_host_hello_rejects_wrong_generation_before_ack() {
    let identity = Uuid::from_u128(0xdddddddddddd4ddd8ddddddddddddddd);
    let key = || NetworkKey::from_derived_bytes([0x22; 32]).unwrap();
    let (host, mut guest) = tokio::io::duplex(4096);
    let host = tokio::spawn(crate::network_worker::run_host_session(
        host,
        key(),
        identity,
        7,
        Arc::new(packet::FixtureBroker::new(false)),
        || panic!("wrong generation reached READY"),
    ));
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            packet::authenticate(&mut guest, key(), identity, 8)
        )
        .await
        .unwrap()
        .is_err()
    );
    drop(guest);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), host)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

fn bounded_byte(source: i32) -> u8 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut byte = [0];
        match fd::read_some(source, &mut byte) {
            Ok(1) => return byte[0],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                fd::poll(&mut [fd::pollfd(source, libc::POLLIN)], deadline).unwrap()
            }
            other => panic!("missing fixed adapter status: {other:?}"),
        }
    }
}
fn pty() -> (OwnedFd, OwnedFd) {
    let mut master = -1;
    let mut slave = -1;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    unsafe {
        libc::cfmakeraw(&mut term);
    }
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                &term,
                std::ptr::null(),
            )
        },
        0
    );
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    for number in [master.as_raw_fd(), slave.as_raw_fd()] {
        fd::nonblocking(number).unwrap();
    }
    (master, slave)
}
#[test]
#[ignore = "fixed child invoked only by owned parent test"]
fn confined_adapter_child() {
    // Test-only subprocess; no relaxation of production PID1/FD admission.
    let run = || -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let executable = std::ffi::CString::new(std::env::current_exe()?.as_os_str().as_bytes())
            .map_err(|_| super::invalid())?;
        crate::linux::confinement::lock_process_privileges()?;
        crate::linux::confinement::install_deny_all_filesystem_domain()?;
        process::install_adapter_filter()?;
        process::denial_canaries(&executable)?;
        process::prepared_adapter(Instant::now() + Duration::from_secs(8))
    };
    std::process::exit(if run().is_ok() { 0 } else { 71 });
}

#[test]
#[ignore = "fixed child invoked only by owned parent test"]
fn landlock_exec_canary_child() {
    let run = || -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let executable = std::env::current_exe()?;
        if !executable.is_file() || executable.metadata()?.permissions().mode() & 0o111 == 0 {
            return Err(super::invalid());
        }
        let executable = std::ffi::CString::new(executable.as_os_str().as_bytes())
            .map_err(|_| super::invalid())?;
        crate::linux::confinement::lock_process_privileges()?;
        crate::linux::confinement::install_deny_all_filesystem_domain()?;
        // This is the real worker's filesystem layer, without the adapter's
        // extra syscall-deny layer masking pathname resolution with EPERM.
        if process::exec_denial_canary(c"/__console_pair_absent_exec_canary")
            .unwrap_err()
            .raw_os_error()
            != Some(libc::ENOENT)
        {
            return Err(super::invalid());
        }
        process::exec_denial_canary(&executable)
    };
    std::process::exit(if run().is_ok() { 0 } else { 71 });
}

#[test]
fn landlock_exec_probe_requires_present_admitted_executable() {
    let args = [
        "--exact",
        "macos_console_pair_fixture::tests::landlock_exec_canary_child",
        "--ignored",
        "--nocapture",
    ]
    .map(String::from);
    let mut child = process::spawn(&std::env::current_exe().unwrap(), &args, &[]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.poll().unwrap() {
            assert!(
                status.success(),
                "existing executable was not recognized as denied: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "owned canary child exceeded its bound"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn confined_adapter_prepared_go_binary_backpressure_and_cancel() {
    let (master, slave) = pty();
    let (mut peer, adapter) = UnixStream::pair().unwrap();
    let (control, child_control) = UnixStream::pair().unwrap();
    for number in [
        peer.as_raw_fd(),
        adapter.as_raw_fd(),
        control.as_raw_fd(),
        child_control.as_raw_fd(),
    ] {
        fd::nonblocking(number).unwrap();
    }
    let args = [
        "--exact",
        "macos_console_pair_fixture::tests::confined_adapter_child",
        "--ignored",
        "--nocapture",
    ]
    .map(String::from);
    let mut child = process::spawn(
        &std::env::current_exe().unwrap(),
        &args,
        &[
            (slave.as_raw_fd(), 3),
            (adapter.as_raw_fd(), 4),
            (child_control.as_raw_fd(), 5),
        ],
    )
    .unwrap();
    drop(slave);
    drop(adapter);
    drop(child_control);
    let deadline = Instant::now() + Duration::from_secs(5);
    fd::write_all(master.as_raw_fd(), b"preloaded\0bytes", deadline).unwrap();
    assert_eq!(bounded_byte(control.as_raw_fd()), process::ADAPTER_PREPARED);
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut events = [fd::pollfd(peer.as_raw_fd(), libc::POLLIN)];
    fd::poll(&mut events, Instant::now() + Duration::from_millis(40)).unwrap();
    assert_eq!(events[0].revents, 0);
    fd::write_all(control.as_raw_fd(), &[process::ADAPTER_GO], deadline).unwrap();
    let mut got = Vec::new();
    for _ in 0..15 {
        got.push(bounded_byte(peer.as_raw_fd()));
    }
    assert_eq!(got, b"preloaded\0bytes");
    // Exceed the fixed buffer with the output peer unread. Control must remain responsive.
    let buffer = [0x5a; 32768];
    for _ in 0..32 {
        match peer.write(&buffer) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            other => panic!("{other:?}"),
        }
    }
    fd::write_all(control.as_raw_fd(), &[process::ADAPTER_STOP], deadline).unwrap();
    assert_eq!(
        bounded_byte(control.as_raw_fd()),
        process::ADAPTER_CANCELLED
    );
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.poll().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn bridge_records_only_actual_read_zero_and_rejects_second_go() {
    for (close_character, second_go, expected) in [
        (true, false, Some(process::ADAPTER_CHAR_EOF)),
        (false, false, Some(process::ADAPTER_UNIX_EOF)),
        (false, true, None),
    ] {
        let (character, remote_char) = UnixStream::pair().unwrap();
        let (unix, remote_unix) = UnixStream::pair().unwrap();
        let (control, remote_control) = UnixStream::pair().unwrap();
        for number in [character.as_raw_fd(), unix.as_raw_fd(), control.as_raw_fd()] {
            fd::nonblocking(number).unwrap();
        }
        if second_go {
            fd::write_all(
                remote_control.as_raw_fd(),
                &[process::ADAPTER_GO],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        } else if close_character {
            drop(remote_char);
        } else {
            drop(remote_unix);
        }
        let result = process::bridge(
            character.as_raw_fd(),
            unix.as_raw_fd(),
            control.as_raw_fd(),
            Instant::now() + Duration::from_secs(1),
        );
        match expected {
            Some(code) => assert_eq!(result.unwrap(), code),
            None => assert!(result.is_err()),
        }
    }
}
#[test]
fn owned_child_repeated_reap_never_signals_another_process() {
    let mut first = process::spawn(Path::new("/usr/bin/true"), &[], &[]).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if first.poll().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut second = process::spawn(Path::new("/usr/bin/sleep"), &["2".into()], &[]).unwrap();
    assert!(first.terminate(until).unwrap().success());
    assert!(first.terminate(until).unwrap().success());
    assert!(second.poll().unwrap().is_none());
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        second
            .terminate(Instant::now() + Duration::from_secs(2))
            .unwrap()
            .signal(),
        Some(libc::SIGKILL)
    );
}

#[tokio::test]
async fn injected_broker_rejects_wrong_tcp_source_and_destination_before_connect() {
    use crate::network_worker::{EgressBroker, TcpFlow};
    let broker = packet::FixtureBroker::new(false);
    let good = TcpFlow {
        source: "192.0.2.2:40000".parse().unwrap(),
        destination: "198.51.100.7:4242".parse().unwrap(),
    };
    broker.authorize_tcp(good).await.unwrap();
    for flow in [
        TcpFlow {
            source: "192.0.2.3:40000".parse().unwrap(),
            ..good
        },
        TcpFlow {
            destination: "198.51.100.7:4243".parse().unwrap(),
            ..good
        },
        TcpFlow {
            destination: "203.0.113.1:4242".parse().unwrap(),
            ..good
        },
    ] {
        assert_eq!(
            broker.authorize_tcp(flow).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(broker.connect_tcp(flow).await.is_err());
    }
}

#[test]
fn bridge_preserves_large_binary_both_directions_with_partial_io() {
    let (character, mut source) = UnixStream::pair().unwrap();
    let (unix, mut sink) = UnixStream::pair().unwrap();
    let (control, remote_control) = UnixStream::pair().unwrap();
    for number in [character.as_raw_fd(), unix.as_raw_fd(), control.as_raw_fd()] {
        fd::nonblocking(number).unwrap();
    }
    for peer in [&source, &sink] {
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let bytes: Vec<u8> = (0..131072).map(|i| i as u8).collect();
    std::thread::scope(|scope| {
        let bridge = scope.spawn(|| {
            process::bridge(
                character.as_raw_fd(),
                unix.as_raw_fd(),
                control.as_raw_fd(),
                Instant::now() + Duration::from_secs(3),
            )
        });
        let echo = scope.spawn(|| {
            let mut read = vec![0; bytes.len()];
            sink.read_exact(&mut read).unwrap();
            assert_eq!(read, bytes);
            sink.write_all(&read).unwrap();
            // Keep the peer open until cancellation is sent, not an implicit EOF.
            sink
        });
        source.write_all(&bytes).unwrap();
        let mut read = vec![0; bytes.len()];
        source.read_exact(&mut read).unwrap();
        assert_eq!(read, bytes);
        let _sink = echo.join().unwrap();
        fd::write_all(
            remote_control.as_raw_fd(),
            &[process::ADAPTER_STOP],
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(bridge.join().unwrap().unwrap(), process::ADAPTER_CANCELLED);
    });
}
