use super::*;
use codewire_daemon::client::v1;
use codewire_vmm_guest_probe::{PROGRESS_REQUEST_LEN, Sha256Value};
use std::os::unix::fs::OpenOptionsExt;

fn seed() -> Seed {
    Seed::new_with_setup(
        Uuid::from_u128(1),
        1,
        7777,
        "synthetic-only-capability-for-vz-fixture-tests",
        SetupBinding::new(
            128 * 1024,
            Sha256Value::calculate(b"root"),
            Sha256Value::calculate(b"header"),
        )
        .unwrap(),
    )
    .unwrap()
}

async fn serve_progress(
    mut peer: UnixStream,
    seed: Seed,
    stages: Vec<(u64, GuestBootStage)>,
    wrong_key: bool,
) {
    let mut bytes = [0; PROGRESS_REQUEST_LEN];
    peer.read_exact(&mut bytes).await.unwrap();
    let request = ProgressRequest::decode(&bytes).unwrap();
    let token = if wrong_key {
        "wrong-synthetic-capability-for-vz-fixture-tests"
    } else {
        seed.auth_token()
    };
    for (sequence, stage) in stages {
        let frame = ProgressFrame {
            vm_id: seed.vm_id(),
            generation: seed.generation(),
            sequence,
            stage,
        };
        if peer
            .write_all(&frame.encode(&request.challenge, token).unwrap())
            .await
            .is_err()
        {
            break;
        }
    }
    peer.shutdown().await.unwrap();
}

#[tokio::test]
async fn only_authenticated_monotonic_daemon_started_and_eof_is_progress_ready() {
    for (stages, wrong_key, accepted) in [
        (
            vec![
                (4, GuestBootStage::RootMounted),
                (16, GuestBootStage::DaemonStarted),
            ],
            false,
            true,
        ),
        (vec![(16, GuestBootStage::DaemonStarted)], false, true),
        (vec![(4, GuestBootStage::RootMounted)], false, false),
        (vec![(17, GuestBootStage::SetupFailed)], false, false),
        (vec![(18, GuestBootStage::WorkspaceFailed)], false, false),
        (
            vec![
                (4, GuestBootStage::RootMounted),
                (4, GuestBootStage::DaemonStarted),
            ],
            false,
            false,
        ),
        (
            vec![
                (4, GuestBootStage::RootMounted),
                (5, GuestBootStage::DisksAdmitted),
            ],
            false,
            false,
        ),
        (vec![(16, GuestBootStage::DaemonStarted)], true, false),
        (
            vec![
                (16, GuestBootStage::DaemonStarted),
                (17, GuestBootStage::DaemonStarted),
            ],
            false,
            false,
        ),
    ] {
        let (client, peer) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_progress(peer, seed(), stages, wrong_key));
        let result = tokio::time::timeout(Duration::from_secs(2), prove_progress(client, &seed()))
            .await
            .unwrap();
        assert_eq!(result.is_ok(), accepted);
        task.await.unwrap();
    }
}

#[test]
fn fixture_seed_rejects_unimplemented_authority_bindings() {
    let temporary = tempfile::tempdir().unwrap();
    for (index, seed, accepted) in [
        (0, seed(), true),
        (1, seed().with_docker_data_disk(), false),
        (
            2,
            seed().with_environment_projection_sha256(Sha256Value::calculate(b"projection")),
            false,
        ),
        (
            3,
            Seed::new(
                Uuid::from_u128(1),
                1,
                7777,
                "synthetic-only-capability-for-vz-fixture-tests",
            )
            .unwrap(),
            false,
        ),
        (
            4,
            Seed::new_with_bindings(
                seed().vm_id(),
                1,
                7777,
                seed().auth_token(),
                seed().setup(),
                Some(Sha256Value::calculate(b"shares")),
            )
            .unwrap(),
            false,
        ),
        (
            5,
            Seed::new_with_all_bindings(
                seed().vm_id(),
                1,
                7777,
                seed().auth_token(),
                seed().setup(),
                None,
                Some(Sha256Value::calculate(b"skills")),
            )
            .unwrap(),
            false,
        ),
        (
            6,
            Seed::new_with_setup(
                seed().vm_id(),
                1,
                7778,
                seed().auth_token(),
                seed().setup().unwrap(),
            )
            .unwrap(),
            false,
        ),
        (
            7,
            seed().with_managed_credential_clients(
                codewire_access::ManagedCredentialClients::decode("v1:openai").unwrap(),
            ),
            false,
        ),
    ] {
        let path = temporary.path().join(index.to_string());
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&seed.encode()).unwrap();
        drop(file);
        assert_eq!(fixture_seed(File::open(path).unwrap()).is_ok(), accepted);
    }
}

#[test]
fn options_are_closed_and_descriptor_numbers_cannot_name_standard_io() {
    let mut options = BTreeMap::from([("--seed-fd".to_owned(), "3".to_owned())]);
    assert!(exact_keys(&options, &["--seed-fd"]).is_ok());
    assert_eq!(descriptor(&options, "--seed-fd").unwrap(), 3);
    options.insert("--seed-fd".to_owned(), "2".to_owned());
    assert!(descriptor(&options, "--seed-fd").is_err());
    options.insert("--address".to_owned(), "unused".to_owned());
    assert!(exact_keys(&options, &["--seed-fd"]).is_err());
}

#[test]
fn regular_descriptors_must_start_at_the_exact_artifact_origin() {
    use std::os::fd::IntoRawFd;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("output");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.seek(io::SeekFrom::Start(17)).unwrap();
    assert!(private_file(file.try_clone().unwrap().into_raw_fd(), true).is_err());
    assert_eq!(file.metadata().unwrap().len(), 0);
    file.rewind().unwrap();
    assert!(private_file(file.into_raw_fd(), true).is_ok());
    let mut file = File::open(path).unwrap();
    file.seek(io::SeekFrom::Start(1)).unwrap();
    assert!(private_file(file.try_clone().unwrap().into_raw_fd(), false).is_err());
    file.rewind().unwrap();
    assert!(private_file(file.into_raw_fd(), false).is_ok());
}

#[test]
fn no_partial_transport_progress_or_daemon_proof_can_emit_readiness() {
    for network in [false, true] {
        for progress in [false, true] {
            for daemon in [false, true] {
                assert_eq!(
                    complete_readiness(network, progress, daemon),
                    network && progress && daemon
                );
            }
        }
    }
}

#[tokio::test]
async fn daemon_proof_requires_authenticated_ready_rpc_on_injected_unix_stream() {
    use codewire_daemon::service::DaemonRuntimeState;
    for (is_ready, valid_token) in [(true, true), (false, true), (true, false)] {
        let temporary = tempfile::tempdir().unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let (incoming, receiver) = tokio::sync::mpsc::channel(1);
        incoming.send(Ok::<_, io::Error>(server)).await.unwrap();
        let (shutdown, stop) = oneshot::channel();
        let config = codewire_daemon::Config {
            listen_addr: "unused-injected-transport".to_owned(),
            workspace_root: temporary.path().to_path_buf(),
            home_root: temporary.path().to_path_buf(),
            auth_token: codewire_daemon::DaemonAuthToken::new(if valid_token {
                seed().auth_token().to_owned()
            } else {
                "wrong-synthetic-daemon-capability".to_owned()
            })
            .unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
        };
        let state = if is_ready {
            DaemonRuntimeState::ready()
        } else {
            DaemonRuntimeState::new(Default::default(), "synthetic not ready", vec![])
        };
        let task = tokio::spawn(
            codewire_daemon::server::serve_grpc_with_incoming_and_runtime_state(
                config,
                state,
                tokio_stream::wrappers::ReceiverStream::new(receiver),
                async {
                    let _ = stop.await;
                },
            ),
        );
        let result = tokio::time::timeout(Duration::from_secs(3), prove_daemon(client, &seed()))
            .await
            .unwrap();
        assert_eq!(result.is_ok(), is_ready && valid_token);
        drop(result);
        let _ = shutdown.send(());
        drop(incoming);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn authenticate_network(peer: &mut UnixStream) {
    use codewire_vmm_guest_probe::{
        NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
        NetworkHostReady,
    };
    let seed = seed();
    let key = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation()).unwrap();
    let mut bytes = [0; NETWORK_HOST_HELLO_LEN];
    peer.read_exact(&mut bytes).await.unwrap();
    let hello = NetworkHostHello::decode(&bytes, &key, seed.vm_id(), seed.generation()).unwrap();
    peer.write_all(&NetworkGuestAck::new(hello.nonce).unwrap().encode(&key))
        .await
        .unwrap();
    let mut ready = [0; NETWORK_HOST_READY_LEN];
    peer.read_exact(&mut ready).await.unwrap();
    NetworkHostReady::decode(&ready, &key, &hello.nonce).unwrap();
}

#[tokio::test]
async fn verifier_rejects_early_kill_and_network_closure_before_composite_readiness() {
    for early_kill in [false, true] {
        let (network, mut guest_network) = UnixStream::pair().unwrap();
        let (progress, _guest_progress) = UnixStream::pair().unwrap();
        let (daemon, _guest_daemon) = UnixStream::pair().unwrap();
        let (control, mut parent) = UnixStream::pair().unwrap();
        let task = tokio::spawn(verify_session(
            Arc::new(seed()),
            network,
            progress,
            daemon,
            control,
        ));
        parent.write_all(b"N").await.unwrap();
        authenticate_network(&mut guest_network).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), parent.read_u8())
                .await
                .is_err()
        );
        if early_kill {
            parent.write_all(b"K").await.unwrap();
        } else {
            drop(guest_network);
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(parent.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn verifier_rejects_k_or_network_eof_after_readiness_but_before_workload() {
    use codewire_daemon::service::DaemonRuntimeState;

    for early_kill in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let (network, mut guest_network) = UnixStream::pair().unwrap();
        let (progress, guest_progress) = UnixStream::pair().unwrap();
        let (daemon, guest_daemon) = UnixStream::pair().unwrap();
        let (control, mut parent) = UnixStream::pair().unwrap();
        let (incoming, receiver) = tokio::sync::mpsc::channel(1);
        incoming
            .send(Ok::<_, io::Error>(guest_daemon))
            .await
            .unwrap();
        let (shutdown, stop) = oneshot::channel();
        let config = codewire_daemon::Config {
            listen_addr: "unused-injected-transport".to_owned(),
            workspace_root: temporary.path().to_path_buf(),
            home_root: temporary.path().to_path_buf(),
            auth_token: codewire_daemon::DaemonAuthToken::new(seed().auth_token().to_owned())
                .unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
        };
        let server = tokio::spawn(
            codewire_daemon::server::serve_grpc_with_incoming_and_runtime_state(
                config,
                DaemonRuntimeState::ready(),
                tokio_stream::wrappers::ReceiverStream::new(receiver),
                async {
                    let _ = stop.await;
                },
            ),
        );
        let verifier = tokio::spawn(verify_session_with_workload(
            Arc::new(seed()),
            network,
            progress,
            daemon,
            control,
            |_| async { std::future::pending::<Result<()>>().await },
        ));
        parent.write_all(b"N").await.unwrap();
        authenticate_network(&mut guest_network).await;
        parent.write_all(b"P").await.unwrap();
        serve_progress(
            guest_progress,
            seed(),
            vec![(16, GuestBootStage::DaemonStarted)],
            false,
        )
        .await;
        parent.write_all(b"D").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), parent.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'R'
        );
        if early_kill {
            parent.write_all(b"K").await.unwrap();
        } else {
            drop(guest_network);
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(3), verifier)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            parent.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let _ = shutdown.send(());
        drop(incoming);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn failed_workload_emits_no_workload_marker() {
    use codewire_daemon::service::DaemonRuntimeState;

    let temporary = tempfile::tempdir().unwrap();
    let (network, mut guest_network) = UnixStream::pair().unwrap();
    let (progress, guest_progress) = UnixStream::pair().unwrap();
    let (daemon, guest_daemon) = UnixStream::pair().unwrap();
    let (control, mut parent) = UnixStream::pair().unwrap();
    let (incoming, receiver) = tokio::sync::mpsc::channel(1);
    incoming
        .send(Ok::<_, io::Error>(guest_daemon))
        .await
        .unwrap();
    let (shutdown, stop) = oneshot::channel();
    let config = codewire_daemon::Config {
        listen_addr: "unused-injected-transport".to_owned(),
        workspace_root: temporary.path().to_path_buf(),
        home_root: temporary.path().to_path_buf(),
        auth_token: codewire_daemon::DaemonAuthToken::new(seed().auth_token().to_owned()).unwrap(),
        process_execution: codewire_daemon::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
    };
    let server = tokio::spawn(
        codewire_daemon::server::serve_grpc_with_incoming_and_runtime_state(
            config,
            DaemonRuntimeState::ready(),
            tokio_stream::wrappers::ReceiverStream::new(receiver),
            async {
                let _ = stop.await;
            },
        ),
    );
    let verifier = tokio::spawn(verify_session_with_workload(
        Arc::new(seed()),
        network,
        progress,
        daemon,
        control,
        |_| async { Err(invalid().into()) },
    ));
    parent.write_all(b"N").await.unwrap();
    authenticate_network(&mut guest_network).await;
    parent.write_all(b"P").await.unwrap();
    serve_progress(
        guest_progress,
        seed(),
        vec![(16, GuestBootStage::DaemonStarted)],
        false,
    )
    .await;
    parent.write_all(b"D").await.unwrap();
    assert_eq!(parent.read_u8().await.unwrap(), b'R');
    assert!(
        tokio::time::timeout(Duration::from_secs(3), verifier)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        parent.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    drop(guest_network);
    let _ = shutdown.send(());
    drop(incoming);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn verifier_readiness_and_workload_precede_arming_and_only_armed_eof_completes() {
    use codewire_daemon::service::DaemonRuntimeState;
    // Mode0: EOF before K rejects, mode1: armed EOF succeeds, mode2: armed
    // malformed network protocol rejects (it is not an ownership-close event).
    for mode in 0..3 {
        let temporary = tempfile::tempdir().unwrap();
        let (network, mut guest_network) = UnixStream::pair().unwrap();
        let (progress, guest_progress) = UnixStream::pair().unwrap();
        let (daemon, guest_daemon) = UnixStream::pair().unwrap();
        let (control, mut parent) = UnixStream::pair().unwrap();
        let (incoming, receiver) = tokio::sync::mpsc::channel(1);
        incoming
            .send(Ok::<_, io::Error>(guest_daemon))
            .await
            .unwrap();
        let (shutdown, stop) = oneshot::channel();
        let config = codewire_daemon::Config {
            listen_addr: "unused-injected-transport".to_owned(),
            workspace_root: temporary.path().to_path_buf(),
            home_root: temporary.path().to_path_buf(),
            auth_token: codewire_daemon::DaemonAuthToken::new(seed().auth_token().to_owned())
                .unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
        };
        let server = tokio::spawn(
            codewire_daemon::server::serve_grpc_with_incoming_and_runtime_state(
                config,
                DaemonRuntimeState::ready(),
                tokio_stream::wrappers::ReceiverStream::new(receiver),
                async {
                    let _ = stop.await;
                },
            ),
        );
        let working_dir = temporary.path().to_string_lossy().into_owned();
        let verifier = tokio::spawn(verify_session_with_workload(
            Arc::new(seed()),
            network,
            progress,
            daemon,
            control,
            move |client| async move { workload::prove_in_test(&client, &working_dir).await },
        ));
        parent.write_all(b"N").await.unwrap();
        authenticate_network(&mut guest_network).await;
        parent.write_all(b"P").await.unwrap();
        serve_progress(
            guest_progress,
            seed(),
            vec![(16, GuestBootStage::DaemonStarted)],
            false,
        )
        .await;
        // Both authenticated network and terminal progress are insufficient.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), parent.read_u8())
                .await
                .is_err()
        );
        parent.write_all(b"D").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), parent.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'R'
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(8), parent.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'W'
        );
        if mode != 0 {
            parent.write_all(b"K").await.unwrap();
            assert_eq!(parent.read_u8().await.unwrap(), b'A');
        }
        if mode == 2 {
            guest_network
                .write_all(&[0; codewire_vmm_guest_probe::NETWORK_FRAME_HEADER_LEN])
                .await
                .unwrap();
        } else {
            drop(guest_network);
        }
        let result = tokio::time::timeout(Duration::from_secs(3), verifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.is_ok(), mode == 1);
        if mode == 1 {
            assert_eq!(parent.read_u8().await.unwrap(), b'C');
        }
        assert_eq!(parent.read(&mut [0]).await.unwrap(), 0);
        let _ = shutdown.send(());
        drop(incoming);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn exec_message(payload: v1::exec_message::Payload) -> v1::ExecMessage {
    v1::ExecMessage {
        payload: Some(payload),
    }
}

#[test]
fn transient_workload_rejects_malformed_duplicate_oversize_and_trailing_frames() {
    use v1::exec_message::Payload;

    let valid = vec![
        exec_message(Payload::Stdout(b"out".to_vec())),
        exec_message(Payload::Stderr(b"err".to_vec())),
        exec_message(Payload::Stdout(vec![0xff])),
        exec_message(Payload::Stderr(vec![0xfe])),
        exec_message(Payload::Exit(v1::ExitStatus { code: 23 })),
    ];
    assert!(workload::transient_messages(valid.clone()).is_ok());

    for invalid_messages in [
        vec![v1::ExecMessage::default()],
        vec![
            exec_message(Payload::Stdout(b"out\xff".to_vec())),
            exec_message(Payload::Stderr(b"err\xfe".to_vec())),
            exec_message(Payload::Exit(v1::ExitStatus { code: 23 })),
            exec_message(Payload::Exit(v1::ExitStatus { code: 23 })),
        ],
        vec![exec_message(Payload::Stdout(vec![b'x'; 257]))],
        vec![
            exec_message(Payload::Stdout(b"out\xff".to_vec())),
            exec_message(Payload::Stderr(b"err\xfe".to_vec())),
            exec_message(Payload::Exit(v1::ExitStatus { code: 23 })),
            exec_message(Payload::Stdout(b"trailing".to_vec())),
        ],
    ] {
        assert!(workload::transient_messages(invalid_messages).is_err());
    }
}

fn output_chunk(
    offset: u64,
    stream: v1::SessionOutputStream,
    data: &[u8],
) -> v1::SessionOutputChunk {
    v1::SessionOutputChunk {
        offset,
        next_offset: offset + data.len() as u64,
        stream: stream as i32,
        data: data.to_vec(),
    }
}

#[test]
fn durable_output_rejects_malformed_oversize_and_trailing_frames() {
    let valid = v1::ReadSessionOutputResponse {
        chunks: vec![
            output_chunk(0, v1::SessionOutputStream::Stdout, b"session-"),
            output_chunk(8, v1::SessionOutputStream::Stdout, b"ready\n"),
        ],
        next_offset: 14,
        eof: true,
        ..Default::default()
    };
    assert_eq!(
        workload::output_response(valid).unwrap(),
        (b"session-ready\n".to_vec(), true)
    );

    for invalid in [
        v1::ReadSessionOutputResponse {
            chunks: vec![output_chunk(
                1,
                v1::SessionOutputStream::Stdout,
                b"session-ready\n",
            )],
            next_offset: 15,
            eof: true,
            ..Default::default()
        },
        v1::ReadSessionOutputResponse {
            chunks: vec![output_chunk(
                0,
                v1::SessionOutputStream::Stderr,
                b"session-ready\n",
            )],
            next_offset: 14,
            eof: true,
            ..Default::default()
        },
        v1::ReadSessionOutputResponse {
            chunks: vec![output_chunk(
                0,
                v1::SessionOutputStream::Stdout,
                &vec![b'x'; 257],
            )],
            next_offset: 257,
            eof: true,
            ..Default::default()
        },
        v1::ReadSessionOutputResponse {
            chunks: vec![output_chunk(
                0,
                v1::SessionOutputStream::Stdout,
                b"session-ready\ntrailing",
            )],
            next_offset: 22,
            eof: true,
            ..Default::default()
        },
    ] {
        assert!(workload::output_response(invalid).is_err());
    }
}

fn running_record(output_end_offset: u64) -> v1::SessionRecord {
    v1::SessionRecord {
        name: String::new(),
        parent_session_id: None,
        cleanup_unknown: false,
        launch_generation: 1,
        session_id: "session-00000000-0000-4000-8000-000000000001".to_owned(),
        state: v1::SessionLifecycleState::Running as i32,
        command: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf 'session-ready\\n'; exec /bin/sleep 300".to_owned(),
        ],
        working_dir: "/synthetic-workspace".to_owned(),
        pty: false,
        created_at: Some(Default::default()),
        started_at: Some(Default::default()),
        finished_at: None,
        exit_code: None,
        output_start_offset: 0,
        output_end_offset,
        status_message: "session running".to_owned(),
    }
}

#[test]
fn complete_output_with_stale_metadata_repolls_before_acceptance() {
    let stale = running_record(0);
    assert!(
        !workload::running_output_for_test(
            &stale,
            "/synthetic-workspace",
            b"session-ready\n",
            true,
        )
        .unwrap()
    );
    let current = running_record(14);
    assert!(
        workload::running_output_for_test(
            &current,
            "/synthetic-workspace",
            b"session-ready\n",
            true,
        )
        .unwrap()
    );
}

#[test]
fn only_canonical_matching_launch_response_establishes_session_ownership() {
    let valid = running_record(0);
    assert!(workload::owned_launch_for_test(&valid, "/synthetic-workspace").unwrap());
    for invalid in [
        {
            let mut record = valid.clone();
            record.session_id = "foreign-session".to_owned();
            record
        },
        {
            let mut record = valid.clone();
            record.command.push("substituted".to_owned());
            record
        },
        {
            let mut record = valid;
            record.working_dir = "/substituted".to_owned();
            record
        },
    ] {
        assert!(!workload::owned_launch_for_test(&invalid, "/synthetic-workspace").unwrap());
    }
}
