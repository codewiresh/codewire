use super::*;
use codewire_daemon::client::v1;
use codewire_vmm_guest_probe::{
    GuestBootStage, LayerEncoding, PROGRESS_REQUEST_LEN, ProgressFrame, ProgressRequest, SEED_LEN,
    SetupArchitecture, SetupBinding, SetupBlob, SetupHeader, SetupLayerBlob, Sha256Value,
    oci_root_generation,
};
use std::io::Seek;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

fn seed() -> Seed {
    Seed::new_with_setup(
        Uuid::from_u128(1),
        1,
        7777,
        "synthetic-only-workload-network-test-capability",
        SetupBinding::new(
            128 * 1024,
            Sha256Value::calculate(b"root"),
            Sha256Value::calculate(b"header"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn options_for(values: &[(&str, String)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).into(), value.clone()))
        .collect()
}

fn setup(directory: &std::path::Path) -> File {
    let project = Sha256Value::calculate(b"{}");
    let manifest = Sha256Value::calculate(b"synthetic manifest");
    let header = SetupHeader::layout(
        oci_root_generation(project, manifest, SetupArchitecture::Arm64),
        manifest,
        SetupArchitecture::Arm64,
        SetupBlob {
            size: 2,
            sha256: project,
        },
        SetupBlob {
            size: 2,
            sha256: project,
        },
        vec![SetupLayerBlob {
            blob: SetupBlob {
                size: 1,
                sha256: project,
            },
            diff_id: project,
            encoding: LayerEncoding::Tar,
        }],
    )
    .unwrap();
    let path = directory.join("setup");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&header.encode().unwrap()).unwrap();
    file.set_len(header.total_bytes).unwrap();
    drop(file);
    File::open(path).unwrap()
}

fn output(path: &std::path::Path) -> File {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

#[test]
fn seed_outputs_exact_private_seed_and_its_actual_derived_network_key() {
    let temporary = tempfile::tempdir().unwrap();
    let seed_path = temporary.path().join("seed");
    let key_path = temporary.path().join("key");
    let options = options_for(&[
        (
            "--setup-fd",
            setup(temporary.path()).into_raw_fd().to_string(),
        ),
        ("--output-fd", output(&seed_path).into_raw_fd().to_string()),
        (
            "--network-key-fd",
            output(&key_path).into_raw_fd().to_string(),
        ),
        ("--vm-id", seed().vm_id().to_string()),
        ("--generation", "1".into()),
    ]);
    make_seed(options).unwrap();
    assert_eq!(seed_path.metadata().unwrap().len(), SEED_LEN as u64);
    assert_eq!(key_path.metadata().unwrap().len(), 32);
    assert_eq!(key_path.metadata().unwrap().mode() & 0o7777, 0o600);
    let seed = common::fixture_seed(File::open(seed_path).unwrap()).unwrap();
    let key = Zeroizing::new(std::fs::read(key_path).unwrap());
    let derived = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation()).unwrap();
    // Never include generated capability bytes in assertion diagnostics.
    assert!(derived.with_bytes(|bytes| bytes.as_slice() == key.as_slice()));
}

#[test]
fn seed_rejects_same_inode_outputs_before_writing_any_artifact() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("output");
    let seed_output = output(&path);
    let key_output = seed_output.try_clone().unwrap();
    let options = options_for(&[
        (
            "--setup-fd",
            setup(temporary.path()).into_raw_fd().to_string(),
        ),
        ("--output-fd", seed_output.into_raw_fd().to_string()),
        ("--network-key-fd", key_output.into_raw_fd().to_string()),
        ("--vm-id", seed().vm_id().to_string()),
        ("--generation", "1".into()),
    ]);
    assert!(make_seed(options).is_err());
    assert_eq!(path.metadata().unwrap().len(), 0);
}

#[test]
fn descriptors_and_options_reject_alias_numbers_noncanonical_names_and_extra_authority() {
    for values in [
        vec!["verify", "--seed-fd"],
        vec!["verify", "--seed-fd", "3", "--seed-fd", "4"],
    ] {
        assert!(options(values.into_iter().map(str::to_owned)).is_err());
    }
    for number in ["0", "1", "2", "03", "+3", "-3", "2147483648"] {
        assert!(
            descriptors(
                &options_for(&[("--seed-fd", number.into())]),
                &["--seed-fd"]
            )
            .is_err()
        );
    }
    let keys = ["--progress-fd", "--daemon-fd", "--control-fd", "--seed-fd"];
    let mut values = options_for(&[
        (keys[0], "3".into()),
        (keys[1], "4".into()),
        (keys[2], "5".into()),
        (keys[3], "6".into()),
    ]);
    assert!(common::exact_keys(&values, &keys).is_ok());
    values.insert("--network-fd".into(), "7".into());
    assert!(common::exact_keys(&values, &keys).is_err());
    values.remove("--network-fd");
    values.insert("--daemon-fd".into(), "3".into());
    assert!(descriptors(&values, &keys).is_err());
}

#[test]
fn private_artifacts_reject_permissions_offsets_and_wrong_access() {
    let temporary = tempfile::tempdir().unwrap();
    for (index, mode) in [0o644, 0o700, 0o1600].into_iter().enumerate() {
        let path = temporary.path().join(index.to_string());
        let file = output(&path);
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert!(strict_file(file.into_raw_fd(), true).is_err());
    }
    let path = temporary.path().join("offset");
    let mut file = output(&path);
    file.seek(io::SeekFrom::Start(1)).unwrap();
    assert!(strict_file(file.into_raw_fd(), true).is_err());
    assert!(strict_file(File::open(&path).unwrap().into_raw_fd(), true).is_err());
}

#[test]
fn all_control_markers_are_one_use_ordered_and_batch_atomic() {
    for byte in [b'E', b'Q', b'F', b'N', b'K', b'X', 0, 255] {
        assert!(Facts::default().input(byte).is_err());
    }
    for prefix in [b"P".as_slice(), b"D", b"S", b"SE"] {
        let mut facts = Facts::default();
        facts.batch(prefix).unwrap();
        assert!(facts.input(*prefix.last().unwrap()).is_err());
    }
    let mut facts = Facts::default();
    assert!(facts.batch(b"PDSS").is_err());
    assert!(!facts.progress_started && !facts.daemon_started && !facts.service_ready);
    for p in [false, true] {
        for d in [false, true] {
            for s in [false, true] {
                let facts = Facts {
                    progress_ready: p,
                    daemon_ready: d,
                    service_ready: s,
                    ..Facts::default()
                };
                assert_eq!(facts.pending(), (p && d && s).then_some(b'R'));
            }
        }
    }
}

#[test]
fn endpoint_session_and_shutdown_facts_cannot_substitute_for_each_other() {
    let mut facts = Facts {
        ready_sent: true,
        ..Facts::default()
    };
    facts.session_stopped = true;
    assert_eq!(facts.pending(), None);
    facts.endpoint_completed = true;
    assert_eq!(facts.pending(), Some(b'W'));
    assert!(facts.input(b'Q').is_err());
    facts.workload_sent = true;
    assert!(facts.batch(b"QF").is_err());
    assert!(!facts.poweroff_requested);
    facts.input(b'Q').unwrap();
    assert!(facts.input(b'Q').is_err());
    assert!(facts.input(b'F').is_err());
    facts.poweroff_accepted = true;
    assert_eq!(facts.pending(), Some(b'A'));
    facts.acceptance_sent = true;
    facts.input(b'F').unwrap();
    assert_eq!(facts.pending(), None);
    facts.poweroff_ended = true;
    assert_eq!(facts.pending(), Some(b'C'));
    assert!(facts.input(b'F').is_err());
}

fn message(payload: v1::exec_message::Payload) -> v1::ExecMessage {
    v1::ExecMessage {
        payload: Some(payload),
    }
}

#[test]
fn poweroff_requires_exact_identity_stdout_before_expected_transport_teardown() {
    use v1::exec_message::Payload;
    let expected = format!(
        "CWPOWEROFF1 accepted vm_id={} generation=1\n",
        seed().vm_id()
    )
    .into_bytes();
    for split in 1..expected.len() {
        let mut proof = workload::PoweroffProof::new(&seed());
        proof
            .observe(message(Payload::Stdout(expected[..split].to_vec())))
            .unwrap();
        assert!(!proof.accepted());
        assert!(proof.closed(None).is_err());
        proof
            .observe(message(Payload::Stdout(expected[split..].to_vec())))
            .unwrap();
        assert!(proof.accepted());
        assert!(proof.closed(None).is_ok());
        assert!(proof.closed(Some(tonic::Code::Unavailable)).is_ok());
        assert!(proof.closed(Some(tonic::Code::Cancelled)).is_ok());
        for code in [
            tonic::Code::Internal,
            tonic::Code::Unknown,
            tonic::Code::Unauthenticated,
            tonic::Code::DeadlineExceeded,
        ] {
            assert!(proof.closed(Some(code)).is_err());
        }
        assert!(
            proof
                .observe(message(Payload::Stdout(b"trailing".to_vec())))
                .is_err()
        );
        assert!(
            proof
                .observe(message(Payload::Stderr(b"failure".to_vec())))
                .is_err()
        );
        assert!(
            proof
                .observe(message(Payload::Exit(v1::ExitStatus { code: 1 })))
                .is_err()
        );
        proof
            .observe(message(Payload::Exit(v1::ExitStatus { code: 0 })))
            .unwrap();
        assert!(
            proof
                .observe(message(Payload::Exit(v1::ExitStatus { code: 0 })))
                .is_err()
        );
    }
    for bytes in [
        b"CWPOWEROFF1 accepted\n".to_vec(),
        expected
            .iter()
            .map(|b| if *b == b'1' { b'2' } else { *b })
            .collect(),
        vec![0; 1024],
        vec![],
    ] {
        let mut proof = workload::PoweroffProof::new(&seed());
        assert!(proof.observe(message(Payload::Stdout(bytes))).is_err());
        assert!(proof.closed(Some(tonic::Code::Unavailable)).is_err());
    }
}

#[test]
fn fixed_workload_command_and_endpoint_transcript_are_golden_bound() {
    use codewire_vmm_guest_probe::macos_workload_network_fixture as client;
    let request = workload::request("/workspace");
    assert_eq!(
        request.command,
        [
            "/bin/sh",
            "-c",
            "/run/codewire-runtime/init macos-workload-network-client && printf 'workload-network-ready\\n' && exec /bin/sleep 300"
        ]
    );
    assert_eq!(request.working_dir, "/workspace");
    assert!(request.env.is_empty() && !request.pty && request.term.is_empty());
    assert_eq!((request.width, request.height), (0, 0));
    assert_eq!(client::DESTINATION.to_string(), "93.184.216.34:443");
    assert_eq!(client::PAYLOAD_LEN, 4096);
    assert_eq!(
        Sha256Value::from_bytes(client::REQUEST_SHA256).to_string(),
        "c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193"
    );
    assert_eq!(
        Sha256Value::from_bytes(client::RESPONSE_SHA256).to_string(),
        "8f04c27407f8082faf5e54b853caf7889a5fccca357e8f653799ab5a10d0d114"
    );
    assert_eq!(
        Sha256Value::calculate(&client::request_payload()).as_bytes(),
        client::REQUEST_SHA256
    );
    assert_eq!(
        Sha256Value::calculate(&client::response_payload()).as_bytes(),
        client::RESPONSE_SHA256
    );
}

async fn progress_peer(mut peer: UnixStream) {
    let mut bytes = [0; PROGRESS_REQUEST_LEN];
    peer.read_exact(&mut bytes).await.unwrap();
    let request = ProgressRequest::decode(&bytes).unwrap();
    let frame = ProgressFrame {
        vm_id: seed().vm_id(),
        generation: 1,
        sequence: 16,
        stage: GuestBootStage::DaemonStarted,
    };
    peer.write_all(
        &frame
            .encode(&request.challenge, seed().auth_token())
            .unwrap(),
    )
    .await
    .unwrap();
    peer.shutdown().await.unwrap();
}

struct Daemon {
    stream: Option<UnixStream>,
    incoming: Option<tokio::sync::mpsc::Sender<std::result::Result<UnixStream, io::Error>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    _root: tempfile::TempDir,
}

impl Daemon {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let (incoming, receiver) = tokio::sync::mpsc::channel(1);
        incoming.send(Ok::<_, io::Error>(server)).await.unwrap();
        let (shutdown, stop) = oneshot::channel();
        let config = codewire_daemon::Config {
            listen_addr: "unused-injected-transport".into(),
            workspace_root: root.path().to_path_buf(),
            home_root: root.path().to_path_buf(),
            auth_token: codewire_daemon::DaemonAuthToken::new(seed().auth_token()).unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
        };
        let task = tokio::spawn(async move {
            codewire_daemon::server::serve_grpc_with_incoming_and_runtime_state(
                config,
                codewire_daemon::service::DaemonRuntimeState::ready(),
                tokio_stream::wrappers::ReceiverStream::new(receiver),
                async {
                    let _ = stop.await;
                },
            )
            .await
            .map_err(|_| invalid().into())
        });
        Self {
            stream: Some(client),
            incoming: Some(incoming),
            stop: Some(shutdown),
            task: Some(task),
            _root: root,
        }
    }
    async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        drop(self.incoming.take());
        tokio::time::timeout(Duration::from_secs(3), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn marker(parent: &mut UnixStream) -> u8 {
    tokio::time::timeout(Duration::from_secs(3), parent.read_u8())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn real_transport_shutdown_is_forwarded_while_exact_receive_endpoint_is_retained() {
    for retain in [false, true] {
        let (mut consumer, mut native) = UnixStream::pair().unwrap();
        let endpoint = retain.then(|| retain_daemon_receive_endpoint(&consumer).unwrap());
        if let Some(endpoint) = &endpoint {
            let original = unsafe { libc::fcntl(consumer.as_raw_fd(), libc::F_GETFD) };
            let retained = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_GETFD) };
            assert!(original >= 0 && retained & libc::FD_CLOEXEC != 0);
            let left = unsafe { libc::fcntl(consumer.as_raw_fd(), libc::F_GETFL) };
            let right = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(left, right);
        }
        // This is Tokio's real shutdown, the same operation used by h2. A dup
        // does not suppress SHUT_WR or fabricate a successful async shutdown.
        consumer.shutdown().await.unwrap();
        drop(consumer);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), native.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let tail = b"synthetic-final-daemon-bytes";
        let forwarded = native.write_all(tail).await;
        if let Some(endpoint) = endpoint {
            forwarded.unwrap();
            native.shutdown().await.unwrap();
            // Test-only observation after the sole consumer was dropped. The
            // actual verifier never reads this retained descriptor.
            let received = std::os::unix::net::UnixStream::from(endpoint);
            received.set_nonblocking(true).unwrap();
            let mut received = UnixStream::from_std(received).unwrap();
            let mut bytes = vec![0; tail.len()];
            received.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, tail);
            assert_eq!(received.read(&mut [0]).await.unwrap(), 0);
        } else {
            // Without exact endpoint lifetime, normal consumer drop makes
            // the native drain fail even though SHUT_WR was legitimate.
            assert!(forwarded.is_err());
        }
    }
}

#[tokio::test]
async fn retained_receive_endpoint_is_released_on_scope_failure() {
    let (consumer, mut native) = UnixStream::pair().unwrap();
    let endpoint = retain_daemon_receive_endpoint(&consumer).unwrap();
    drop(consumer);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), native.read_u8())
            .await
            .is_err()
    );
    drop(endpoint);
    assert_eq!(native.read(&mut [0]).await.unwrap(), 0);
    assert!(
        native
            .write_all(b"synthetic-after-owned-close")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn control_failure_cancels_a_blocked_ready_rpc_without_starting_workload() {
    for input in [b"PD".as_slice(), b"PDS", b"PDSS"] {
        let (progress, _peer_progress) = UnixStream::pair().unwrap();
        let (daemon, _peer_daemon) = UnixStream::pair().unwrap();
        let (control, mut parent) = UnixStream::pair().unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let observed = started.clone();
        let verifier = tokio::spawn(verify_with_operations(
            Arc::new(seed()),
            progress,
            daemon,
            control,
            move |_| async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _| async { Err(invalid().into()) },
        ));
        parent.write_all(input).await.unwrap();
        parent.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), verifier)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(started.load(Ordering::SeqCst), 0);
        assert_eq!(parent.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn control_remains_live_during_workload_and_poweroff_tasks() {
    for during_poweroff in [false, true] {
        let mut daemon = Daemon::new().await;
        let (progress, peer_progress) = UnixStream::pair().unwrap();
        let (control, mut parent) = UnixStream::pair().unwrap();
        let (power_started, power_wait) = oneshot::channel();
        let progress_task = tokio::spawn(progress_peer(peer_progress));
        let verifier = tokio::spawn(verify_with_operations(
            Arc::new(seed()),
            progress,
            daemon.stream.take().unwrap(),
            control,
            move |_| async move {
                if during_poweroff {
                    Ok(())
                } else {
                    std::future::pending().await
                }
            },
            move |_, _, accepted| async move {
                let _ = power_started.send(());
                // Retain the acceptance sender while deliberately blocked;
                // dropping it models a failed task, not a pending RPC.
                let result = std::future::pending::<Result<()>>().await;
                drop(accepted);
                result
            },
        ));
        parent.write_all(b"PDSE").await.unwrap();
        assert_eq!(marker(&mut parent).await, b'R');
        if during_poweroff {
            assert_eq!(marker(&mut parent).await, b'W');
            parent.write_all(b"Q").await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), power_wait)
                .await
                .unwrap()
                .unwrap();
        }
        parent.write_all(b"X").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), verifier)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(parent.read(&mut [0]).await.unwrap(), 0);
        progress_task.await.unwrap();
        daemon.close().await;
    }
}

#[tokio::test]
async fn full_control_join_requires_endpoint_and_keeps_poweroff_until_parent_finish() {
    let mut daemon = Daemon::new().await;
    let (progress, peer_progress) = UnixStream::pair().unwrap();
    let (control, mut parent) = UnixStream::pair().unwrap();
    let progress_task = tokio::spawn(progress_peer(peer_progress));
    let (stopped, stopped_wait) = oneshot::channel();
    let (close_poweroff, close_wait) = oneshot::channel();
    let verifier = tokio::spawn(verify_with_operations(
        Arc::new(seed()),
        progress,
        daemon.stream.take().unwrap(),
        control,
        move |_| async move {
            let _ = stopped.send(());
            Ok(())
        },
        move |_, _, accepted| async move {
            accepted.send(()).map_err(|_| invalid())?;
            close_wait.await?;
            Ok(())
        },
    ));
    parent.write_all(b"PDS").await.unwrap();
    assert_eq!(marker(&mut parent).await, b'R');
    tokio::time::timeout(Duration::from_secs(1), stopped_wait)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), parent.read_u8())
            .await
            .is_err()
    );
    parent.write_all(b"E").await.unwrap();
    assert_eq!(marker(&mut parent).await, b'W');
    parent.write_all(b"Q").await.unwrap();
    assert_eq!(marker(&mut parent).await, b'A');
    parent.write_all(b"F").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), parent.read_u8())
            .await
            .is_err()
    );
    close_poweroff.send(()).unwrap();
    assert_eq!(marker(&mut parent).await, b'C');
    tokio::time::timeout(Duration::from_secs(1), verifier)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(parent.read(&mut [0]).await.unwrap(), 0);
    progress_task.await.unwrap();
    daemon.close().await;
}
