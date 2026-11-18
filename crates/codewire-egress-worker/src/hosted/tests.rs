use std::io::Write as _;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

const POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";

fn pod() -> Uuid {
    Uuid::parse_str(POD).unwrap()
}

fn bootstrap(trust: EgressTrust) -> HostedWorkerBootstrap {
    HostedWorkerBootstrap {
        pod_uid: pod(),
        network_key: NetworkKey::derive(
            "hosted-worker-test-token-0123456789abcdef",
            pod(),
            HOSTED_GENERATION,
        )
        .unwrap(),
        broker_key: [0x5a; BROKER_IPC_KEY_LEN],
        policy_digest: PolicyDigest::from_bytes([0x11; 32]),
        trust,
    }
}

/// The supervisor's bytes, read back the way the worker reads them.
fn read_back(bytes: &[u8], expected_pod: Uuid) -> Result<Prepared, NetworkWorkerError> {
    let (mut writer, mut reader) = StdUnixStream::pair().unwrap();
    writer.write_all(bytes).unwrap();
    drop(writer);
    read_bootstrap(&mut reader, expected_pod)
}

#[test]
fn the_bootstrap_carries_the_key_digest_broker_key_and_trust() {
    let der = b"fixture certificate bytes".to_vec();
    let sent = bootstrap(EgressTrust::Ca(der.clone()));
    let bytes = encode_hosted_worker_bootstrap(&sent).unwrap();
    assert_eq!(bytes.len(), HOSTED_BOOTSTRAP_FIXED_LEN + der.len());
    let prepared = read_back(&bytes, pod()).unwrap();
    assert_eq!(prepared.trust, EgressTrust::Ca(der));
    prepared
        .network_key
        .with_bytes(|got| sent.network_key.with_bytes(|want| assert_eq!(got, want)));
    assert_eq!(
        prepared.broker_binding,
        BrokerIpcBinding::new(pod(), HOSTED_GENERATION, sent.policy_digest).unwrap()
    );

    let none = encode_hosted_worker_bootstrap(&bootstrap(EgressTrust::None)).unwrap();
    assert_eq!(none.len(), HOSTED_BOOTSTRAP_FIXED_LEN);
    assert_eq!(read_back(&none, pod()).unwrap().trust, EgressTrust::None);
}

#[test]
fn a_bootstrap_for_another_pod_or_out_of_shape_is_refused() {
    let bytes = encode_hosted_worker_bootstrap(&bootstrap(EgressTrust::None)).unwrap();
    let other = Uuid::parse_str("0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e02").unwrap();
    assert!(matches!(
        read_back(&bytes, other),
        Err(NetworkWorkerError::InvalidBootstrap)
    ));
    let mut wrong_magic = bytes.to_vec();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        read_back(&wrong_magic, pod()),
        Err(NetworkWorkerError::InvalidBootstrap)
    ));
    // A trust length past the bound is refused before its bytes are read.
    let mut long_trust = bytes.to_vec();
    long_trust[TRUST_LEN].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        read_back(&long_trust, pod()),
        Err(NetworkWorkerError::InvalidBootstrap)
    ));
    // A trust shorter than its length is a cut-off bootstrap.
    let mut short_trust = bytes.to_vec();
    short_trust[TRUST_LEN].copy_from_slice(&8_u16.to_le_bytes());
    assert!(matches!(
        read_back(&short_trust, pod()),
        Err(NetworkWorkerError::BootstrapIo)
    ));
}

#[test]
fn the_supervisor_cannot_encode_a_bootstrap_the_worker_would_refuse() {
    let mut nil = bootstrap(EgressTrust::None);
    nil.pod_uid = Uuid::nil();
    assert!(encode_hosted_worker_bootstrap(&nil).is_err());
    let mut no_digest = bootstrap(EgressTrust::None);
    no_digest.policy_digest = PolicyDigest::from_bytes([0; 32]);
    assert!(encode_hosted_worker_bootstrap(&no_digest).is_err());
    let mut no_broker_key = bootstrap(EgressTrust::None);
    no_broker_key.broker_key = [0; BROKER_IPC_KEY_LEN];
    assert!(encode_hosted_worker_bootstrap(&no_broker_key).is_err());
    assert!(encode_hosted_worker_bootstrap(&bootstrap(EgressTrust::Ca(Vec::new()))).is_err());
    let too_long = vec![1_u8; MAX_EGRESS_TRUST_BYTES + 1];
    assert!(encode_hosted_worker_bootstrap(&bootstrap(EgressTrust::Ca(too_long))).is_err());
}

#[test]
fn the_guest_stream_must_be_a_connected_tcp_socket() {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(validate_tcp_stream(accepted.as_fd()).is_ok());
    assert!(validate_tcp_stream(client.as_fd()).is_ok());
    // A listener has no peer, and a Unix stream is not the guest's stream.
    assert!(validate_tcp_stream(listener.as_fd()).is_err());
    let (unix, _peer) = StdUnixStream::pair().unwrap();
    assert!(validate_tcp_stream(unix.as_fd()).is_err());
}

#[test]
fn the_accepted_stream_crosses_once_and_arrives_as_tcp() {
    let (sender, receiver) = StdUnixStream::pair().unwrap();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    send_worker_stream_descriptor(sender.as_raw_fd(), accepted.as_fd()).unwrap();
    let received = receive_worker_stream_descriptor(receiver.as_raw_fd()).unwrap();
    assert!(validate_tcp_stream(received.as_fd()).is_ok());
    // A Unix stream is refused before it is sent.
    let (unix, _peer) = StdUnixStream::pair().unwrap();
    assert!(send_worker_stream_descriptor(sender.as_raw_fd(), unix.as_fd()).is_err());
}

#[tokio::test]
async fn the_control_task_writes_each_status_in_order_and_turns_a_drain_request_into_the_drain() {
    let (worker_end, mut supervisor) = tokio::net::UnixStream::pair().unwrap();
    let (statuses, queue) = mpsc::channel(STATUS_QUEUE);
    let (drain_request, drain) = oneshot::channel();
    let control = tokio::spawn(run_control(worker_end, queue, drain_request));
    statuses.send(WORKER_READY_MESSAGE).await.unwrap();
    statuses
        .send(WORKER_SELF_CHECK_PASSED_MESSAGE)
        .await
        .unwrap();
    let mut written =
        vec![0_u8; WORKER_READY_MESSAGE.len() + WORKER_SELF_CHECK_PASSED_MESSAGE.len()];
    supervisor.read_exact(&mut written).await.unwrap();
    assert_eq!(
        written,
        [WORKER_READY_MESSAGE, WORKER_SELF_CHECK_PASSED_MESSAGE].concat()
    );
    supervisor.write_all(WORKER_DRAIN_REQUEST).await.unwrap();
    drain.await.unwrap();
    statuses.send(WORKER_IDLE_MESSAGE).await.unwrap();
    drop(statuses);
    let mut idle = vec![0_u8; WORKER_IDLE_MESSAGE.len()];
    supervisor.read_exact(&mut idle).await.unwrap();
    assert_eq!(idle, WORKER_IDLE_MESSAGE);
    assert!(control.await.unwrap().is_ok());
}

#[tokio::test]
async fn any_other_request_from_the_supervisor_ends_the_control_task() {
    let (worker_end, mut supervisor) = tokio::net::UnixStream::pair().unwrap();
    let (_statuses, queue) = mpsc::channel(STATUS_QUEUE);
    let (drain_request, drain) = oneshot::channel();
    let control = tokio::spawn(run_control(worker_end, queue, drain_request));
    supervisor.write_all(b"CWNETW1 drai?\n").await.unwrap();
    assert!(matches!(
        control.await.unwrap(),
        Err(NetworkWorkerError::Protocol)
    ));
    assert!(drain.await.is_err());
}

/// The control task runs inside the worker's own seccomp list, which denies
/// `sendto` and `recvfrom`: it must still write its statuses and read the
/// drain request. A child process installs the list, as the worker does.
#[cfg(target_os = "linux")]
#[test]
fn the_control_task_works_under_the_workers_seccomp() {
    const CHILD_MARKER: &str = "CODEWIRE_TEST_HOSTED_CONTROL_SECCOMP";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let (worker_end, supervisor) = StdUnixStream::pair().unwrap();
        worker_end.set_nonblocking(true).unwrap();
        // The supervisor's end stays blocking, on a thread started before the
        // seccomp list, which denies creating one: it writes the request once
        // the ready line arrives.
        let supervisor_side = std::thread::spawn(move || {
            let mut supervisor = supervisor;
            let mut ready = vec![0_u8; WORKER_READY_MESSAGE.len()];
            supervisor.read_exact(&mut ready).unwrap();
            assert_eq!(ready, WORKER_READY_MESSAGE);
            supervisor.write_all(WORKER_DRAIN_REQUEST).unwrap();
            let mut idle = vec![0_u8; WORKER_IDLE_MESSAGE.len()];
            supervisor.read_exact(&mut idle).unwrap();
            assert_eq!(idle, WORKER_IDLE_MESSAGE);
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        assert_eq!(
            // SAFETY: the call takes integer arguments and no pointer, so it cannot
            // touch this process's memory.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        crate::worker::install_network_worker_seccomp_for_test().unwrap();
        let control = {
            let _runtime = runtime.enter();
            tokio::net::UnixStream::from_std(worker_end).unwrap()
        };
        runtime.block_on(async {
            let (statuses, queue) = mpsc::channel(STATUS_QUEUE);
            let (drain_request, drain) = oneshot::channel();
            let control = tokio::spawn(run_control(control, queue, drain_request));
            statuses.send(WORKER_READY_MESSAGE).await.unwrap();
            drain.await.unwrap();
            statuses.send(WORKER_IDLE_MESSAGE).await.unwrap();
            drop(statuses);
            assert!(control.await.unwrap().is_ok());
        });
        supervisor_side.join().unwrap();
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("hosted::tests::the_control_task_works_under_the_workers_seccomp")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
    assert!(status.success());
}
