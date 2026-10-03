use super::*;
use crate::{CredentialBridgeConfig, DaemonAuthToken, LaunchProjectionConfig};
use codewire_workload_secrets::launcher::LAUNCH_CONTEXT_BYTES;
use tokio::net::UnixStream;

// Bootstrap always has an empty command-override section after its context.
const BOOTSTRAP_HEADER_BYTES: usize = LAUNCH_CONTEXT_BYTES + 4;

fn config(directory: &Path) -> Config {
    Config {
        listen_addr: "unused:0".into(),
        workspace_root: "/workspace".into(),
        home_root: "/home/codewire".into(),
        auth_token: DaemonAuthToken::new("synthetic-bootstrap-daemon-token").unwrap(),
        process_execution: ProcessExecution::Runc(RuncExecution {
            helper_path: "/init".into(),
            process_directory: directory.into(),
            container_id: "codewire-workspace".into(),
            process_wrapper: vec!["/run/codewire-runtime/init".into(), "workspace-exec".into()],
            default_shell: "/bin/sh".into(),
            base_environment: vec![],
            uid: 1000,
            gid: 1000,
            additional_gids: vec![],
        }),
        credential_bridge: Some(CredentialBridgeConfig {
            transport: crate::CredentialBridgeTransport::Local,
            environment_id: Uuid::new_v4(),
            environment_generation: 2,
            ingress_socket: directory.join("provider.sock"),
            ingress_uid: rustix::process::geteuid().as_raw(),
            ingress_gid: rustix::process::getegid().as_raw(),
        }),
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: Some(LaunchProjectionConfig {
            selection_sha256: [3; 32],
            native: None,
        }),
    }
}

fn prepare() -> (tempfile::TempDir, StartupProjectionIngress) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = config(directory.path());
    let bridge = CredentialBridge::new(config.credential_bridge.clone());
    let ingress = StartupProjectionIngress::prepare(&config, bridge)
        .unwrap()
        .unwrap();
    (directory, ingress)
}

async fn closed(channel: &mut UnixStream) {
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), channel.read(&mut [0]))
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset)
    );
}

#[tokio::test]
async fn bootstrap_authenticates_exact_pid_and_uid_before_context() {
    for wrong_pid in [true, false] {
        let (_directory, ingress) = prepare();
        let path = ingress.path.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let uid = rustix::process::geteuid().as_raw();
        let task = tokio::spawn(ingress.serve_for_peer(
            async {
                let _ = stopped.await;
            },
            std::process::id() + u32::from(wrong_pid),
            uid + u32::from(!wrong_pid),
        ));
        let mut channel = UnixStream::connect(&path).await.unwrap();
        closed(&mut channel).await;
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(!path.exists());
    }
}

#[tokio::test]
async fn bootstrap_three_phases_get_fresh_bound_context_and_finish_drains_pending_channels() {
    let (_directory, ingress) = prepare();
    let path = ingress.path.clone();
    let expected_identity = ingress.environment_id;
    let task = tokio::spawn(ingress.serve_for_peer(
        std::future::pending(),
        std::process::id(),
        rustix::process::geteuid().as_raw(),
    ));
    let mut channels = Vec::new();
    for phase in [
        BootstrapPhase::Install,
        BootstrapPhase::Image,
        BootstrapPhase::Startup,
    ] {
        let mut channel = UnixStream::connect(&path).await.unwrap();
        channel.write_all(&[phase as u8]).await.unwrap();
        let mut context = [0; BOOTSTRAP_HEADER_BYTES];
        channel.read_exact(&mut context).await.unwrap();
        assert_eq!(&context[LAUNCH_CONTEXT_BYTES..], &[0; 4]);
        assert_eq!(&context[8..24], &expected_identity);
        assert_eq!(&context[24..32], &2_u64.to_be_bytes());
        assert_eq!(&context[32..64], &[3; 32]);
        let deadline = u64::from_be_bytes(context[64..72].try_into().unwrap());
        assert!(deadline > now_unix_ms().unwrap());
        assert!(deadline <= now_unix_ms().unwrap() + MAX_PROJECTION_LIFETIME_MS);
        channels.push(channel);
    }
    let mut finish = UnixStream::connect(&path).await.unwrap();
    finish.write_all(&[BOOTSTRAP_FINISH]).await.unwrap();
    let mut acknowledged = [0];
    finish.read_exact(&mut acknowledged).await.unwrap();
    assert_eq!(acknowledged, [BOOTSTRAP_FINISH]);
    task.await.unwrap().unwrap();
    for mut channel in channels {
        closed(&mut channel).await;
    }
    assert!(!path.exists());
}

#[tokio::test]
async fn bootstrap_unknown_duplicate_phase_and_disconnect_fail_closed() {
    for second in [0, 1, 255] {
        let (_directory, ingress) = prepare();
        let path = ingress.path.clone();
        let task = tokio::spawn(ingress.serve_for_peer(
            std::future::pending(),
            std::process::id(),
            rustix::process::geteuid().as_raw(),
        ));
        let mut first = UnixStream::connect(&path).await.unwrap();
        first.write_all(&[1]).await.unwrap();
        first
            .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
            .await
            .unwrap();
        let mut channel = UnixStream::connect(&path).await.unwrap();
        channel.write_all(&[second]).await.unwrap();
        assert!(task.await.unwrap().is_err());
        closed(&mut first).await;
        closed(&mut channel).await;
        assert!(!path.exists());
    }
    let (_directory, ingress) = prepare();
    let path = ingress.path.clone();
    let task = tokio::spawn(ingress.serve_for_peer(
        std::future::pending(),
        std::process::id(),
        rustix::process::geteuid().as_raw(),
    ));
    let mut channel = UnixStream::connect(&path).await.unwrap();
    channel.write_all(&[1]).await.unwrap();
    channel
        .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
        .await
        .unwrap();
    drop(channel);
    assert!(task.await.unwrap().is_err());
    assert!(!path.exists());
}

#[tokio::test]
async fn bootstrap_shutdown_drains_and_exact_cleanup_preserves_replacement() {
    let (_directory, ingress) = prepare();
    let path = ingress.path.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(ingress.serve_for_peer(
        async {
            let _ = stopped.await;
        },
        std::process::id(),
        rustix::process::geteuid().as_raw(),
    ));
    let mut channel = UnixStream::connect(&path).await.unwrap();
    channel.write_all(&[1]).await.unwrap();
    channel
        .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
        .await
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"synthetic replacement").unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    closed(&mut channel).await;
    assert_eq!(fs::read(&path).unwrap(), b"synthetic replacement");
}

#[tokio::test]
async fn bootstrap_waits_for_initial_host_without_executing_and_shutdown_closes_recipient() {
    let (_directory, ingress) = prepare();
    let path = ingress.path.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(ingress.serve_for_peer(
        async {
            let _ = stopped.await;
        },
        std::process::id(),
        rustix::process::geteuid().as_raw(),
    ));
    let mut channel = UnixStream::connect(&path).await.unwrap();
    channel.write_all(&[1]).await.unwrap();
    channel
        .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
        .await
        .unwrap();
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    channel.write_all(&recipient.public_key()).await.unwrap();
    // The received context and submitted recipient synchronize the phase.
    // Before initial host activation there is neither a result nor an early
    // bridge-unavailable EOF; owner cancellation still closes it promptly.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), channel.read(&mut [0]))
            .await
            .is_err()
    );
    assert!(!task.is_finished());
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    closed(&mut channel).await;
    assert!(!path.exists());
}

#[tokio::test]
async fn startup_host_wait_cannot_extend_the_original_launch_deadline() {
    let (_directory, ingress) = prepare();
    let mut context = ingress.context().unwrap();
    context.deadline_unix_ms = now_unix_ms().unwrap() + 250;
    let (server, mut child) = UnixStream::pair().unwrap();
    let bridge = ingress.bridge.clone();
    let task = tokio::spawn(async move {
        super::super::projection::relay_accepted_launch(
            server,
            context,
            &bridge,
            true,
            &Default::default(),
        )
        .await
    });
    child
        .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
        .await
        .unwrap();
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    child.write_all(&recipient.public_key()).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    closed(&mut child).await;
}

#[tokio::test]
async fn bootstrap_only_runc_with_explicit_selection_binds_and_never_removes_existing_socket() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = config(directory.path());
    let bridge = CredentialBridge::new(config.credential_bridge.clone());
    config.process_execution = ProcessExecution::Native;
    assert!(
        StartupProjectionIngress::prepare(&config, bridge.clone())
            .unwrap()
            .is_none()
    );
    config = self::config(directory.path());
    config.launch_projection = None;
    assert!(
        StartupProjectionIngress::prepare(&config, bridge.clone())
            .unwrap()
            .is_none()
    );
    config = self::config(directory.path());
    config.credential_bridge = None;
    assert!(StartupProjectionIngress::prepare(&config, bridge.clone()).is_err());
    config = self::config(directory.path());
    let first = StartupProjectionIngress::prepare(&config, bridge.clone())
        .unwrap()
        .unwrap();
    assert!(StartupProjectionIngress::prepare(&config, bridge).is_err());
    assert_eq!(
        fs::symlink_metadata(&first.path).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn synthetic_bootstrap_peer_child() {
    let Some(path) = std::env::var_os("CW_SYNTHETIC_BOOTSTRAP_SOCKET") else {
        return;
    };
    use std::io::{Read, Write};
    let mut channel = std::os::unix::net::UnixStream::connect(path).unwrap();
    channel.write_all(&[1]).unwrap();
    channel
        .read_exact(&mut [0; BOOTSTRAP_HEADER_BYTES])
        .unwrap();
    println!("CW_SYNTHETIC_BOOTSTRAP_CONNECTED");
    std::io::stdout().flush().unwrap();
    let _ = channel.read(&mut [0]);
}

#[tokio::test]
async fn bootstrap_exact_peer_death_closes_phase_and_reaps_synthetic_peer() {
    use tokio::io::AsyncBufReadExt;
    let (_directory, ingress) = prepare();
    let path = ingress.path.clone();
    let mut peer = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "execution::bootstrap::tests::synthetic_bootstrap_peer_child",
            "--nocapture",
        ])
        .env_clear()
        .env("CW_SYNTHETIC_BOOTSTRAP_SOCKET", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = peer.id().unwrap();
    let task = tokio::spawn(ingress.serve_for_peer(
        std::future::pending(),
        pid,
        rustix::process::geteuid().as_raw(),
    ));
    let mut lines = tokio::io::BufReader::new(peer.stdout.take().unwrap()).lines();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("peer reached bootstrap channel");
            if line.ends_with("CW_SYNTHETIC_BOOTSTRAP_CONNECTED") {
                break;
            }
        }
    })
    .await
    .unwrap();
    peer.kill().await.unwrap();
    peer.wait().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!path.exists());
}
