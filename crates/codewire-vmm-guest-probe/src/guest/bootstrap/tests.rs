use super::*;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn explicit_bootstrap_prelude_required_disabled_and_malformed_are_closed() {
    for required in [false, true] {
        let (mut parent, child) = UnixStream::pair().unwrap();
        BootstrapParent::new(required, std::process::id())
            .prelude(&mut parent, deadline())
            .unwrap();
        let child = BootstrapChild::receive_from(child, deadline()).unwrap();
        assert_eq!(child.required, required);
        if !required {
            assert!(
                child
                    .channel(BootstrapPhase::Install, deadline())
                    .unwrap()
                    .is_none()
            );
        }
    }
    for bytes in [*b"CWBOOT\x00\x01", *b"CWBOOT\x01\x02", [0; 8]] {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.write_all(&bytes).unwrap();
        assert!(BootstrapChild::receive_from(child, deadline()).is_err());
    }
    let (parent, child) = UnixStream::pair().unwrap();
    drop(parent);
    assert!(BootstrapChild::receive_from(child, deadline()).is_err());
}

#[test]
fn descriptor_transfer_is_exact_cloexec_and_uses_a_distinct_private_channel() {
    let (mut parent, child) = UnixStream::pair().unwrap();
    BootstrapParent::new(true, std::process::id())
        .prelude(&mut parent, deadline())
        .unwrap();
    let child = BootstrapChild::receive_from(child, deadline()).unwrap();
    let consumer = thread::spawn(move || {
        child
            .channel(BootstrapPhase::Install, deadline())
            .unwrap()
            .unwrap()
    });
    let mut request = [0; 2];
    parent.read_exact(&mut request).unwrap();
    assert_eq!(request, [REQUEST, BootstrapPhase::Install as u8]);
    let (channel, mut producer) = UnixStream::pair().unwrap();
    send_descriptor(&parent, &channel, BootstrapPhase::Install as u8, deadline()).unwrap();
    drop(channel);
    let mut received = consumer.join().unwrap();
    assert!(
        rustix::io::fcntl_getfd(&received)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    producer.write_all(b"synthetic ciphertext framing").unwrap();
    let mut bytes = [0; 28];
    received.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"synthetic ciphertext framing");
}

#[test]
fn descriptor_transfer_rejects_missing_extra_wrong_phase_and_non_socket() {
    for count in [0, 2, 4] {
        let (parent, child) = UnixStream::pair().unwrap();
        let (channel, _producer) = UnixStream::pair().unwrap();
        let descriptors = vec![channel.as_fd(); count];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if count != 0 {
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        }
        rustix::net::sendmsg(
            &parent,
            &[IoSlice::new(&[1])],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(receive_descriptor(&child, 1, deadline()).is_err());
    }
    let (parent, child) = UnixStream::pair().unwrap();
    let (channel, _) = UnixStream::pair().unwrap();
    send_descriptor(&parent, &channel, 2, deadline()).unwrap();
    assert!(receive_descriptor(&child, 1, deadline()).is_err());

    let (parent, child) = UnixStream::pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    let descriptors = [file.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    rustix::net::sendmsg(
        &parent,
        &[IoSlice::new(&[1])],
        &mut ancillary,
        SendFlags::empty(),
    )
    .unwrap();
    assert!(receive_descriptor(&child, 1, deadline()).is_err());
}

#[test]
fn phase_parser_does_not_consume_install_ack_or_accept_disabled_duplicate_unknown() {
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    parent.set_nonblocking(true).unwrap();
    let mut bootstrap = BootstrapParent::new(false, std::process::id());
    child.write_all(b"CWINSTALLED").unwrap();
    assert!(!bootstrap.advance(&mut parent, deadline()).unwrap());
    let mut retained = [0; 11];
    parent.read_exact(&mut retained).unwrap();
    assert_eq!(&retained, b"CWINSTALLED");
    child.write_all(&[REQUEST, 1]).unwrap();
    assert!(bootstrap.advance(&mut parent, deadline()).is_err());
    parent.read_exact(&mut [0; 2]).unwrap();
    bootstrap.required = true;
    bootstrap.used = 1;
    child.write_all(&[REQUEST, 1]).unwrap();
    assert!(bootstrap.advance(&mut parent, deadline()).is_err());
    parent.read_exact(&mut [0; 2]).unwrap();
    child.write_all(&[REQUEST, 9]).unwrap();
    assert!(bootstrap.advance(&mut parent, deadline()).is_err());
}

#[test]
fn required_descriptor_receive_is_bounded_and_does_not_disable_projection() {
    let (mut parent, child) = UnixStream::pair().unwrap();
    BootstrapParent::new(true, std::process::id())
        .prelude(&mut parent, deadline())
        .unwrap();
    let child = BootstrapChild::receive_from(child, deadline()).unwrap();
    assert!(
        child
            .channel(BootstrapPhase::Image, Instant::now())
            .is_err()
    );
    drop(parent);
    assert!(child.channel(BootstrapPhase::Image, deadline()).is_err());
}

#[test]
fn exec_status_requires_pending_then_close_and_failure_kills_exact_child_group() {
    use codewire_workload_secrets::launcher::{LAUNCH_EXEC_FAILED, LAUNCH_EXEC_PENDING};
    for bytes in [
        &[][..],
        &[LAUNCH_EXEC_FAILED][..],
        &[LAUNCH_EXEC_PENDING, LAUNCH_EXEC_FAILED][..],
        &[99][..],
    ] {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let (status, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(bytes).unwrap();
        drop(writer);
        assert!(wait_exec_status(&mut child, status, deadline()).is_err());
        assert!(child.try_wait().unwrap().is_some());
    }
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let (status, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&[LAUNCH_EXEC_PENDING]).unwrap();
    drop(writer);
    assert!(wait_exec_status(&mut child, status, deadline()).is_ok());
    stop_workspace_install(&mut child).unwrap();
}

#[test]
fn exec_status_wait_has_a_deadline_and_reaps_the_helper() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let (status, _writer) = UnixStream::pair().unwrap();
    assert!(wait_exec_status(&mut child, status, Instant::now()).is_err());
    assert!(child.try_wait().unwrap().is_some());
}

#[test]
fn admitted_exec_status_does_not_claim_background_application_health() {
    let mut child = Command::new("/bin/false").process_group(0).spawn().unwrap();
    assert!(!child.wait().unwrap().success());
    let (status, mut writer) = UnixStream::pair().unwrap();
    writer
        .write_all(&[codewire_workload_secrets::launcher::LAUNCH_EXEC_PENDING])
        .unwrap();
    drop(writer);
    assert!(wait_exec_status(&mut child, status, deadline()).is_ok());
}
