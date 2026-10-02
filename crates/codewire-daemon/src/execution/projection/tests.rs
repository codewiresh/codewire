use super::*;
use crate::{CredentialBridgeConfig, DaemonAuthToken, LaunchProjectionConfig};

fn config(directory: &Path) -> Config {
    Config {
        listen_addr: "unused:0".into(),
        workspace_root: "/workspace".into(),
        home_root: "/home/codewire".into(),
        auth_token: DaemonAuthToken::new("synthetic-daemon-test-token").unwrap(),
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
            ingress_uid: unsafe { libc::geteuid() },
            ingress_gid: unsafe { libc::getegid() },
        }),
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: Some(LaunchProjectionConfig {
            selection_sha256: [3; 32],
            native: None,
        }),
    }
}

fn prepare(config: &Config) -> io::Result<PreparedProcess> {
    let bridge = CredentialBridge::new(config.credential_bridge.clone());
    PreparedProcess::prepare_configured(
        (config, &bridge),
        &["/usr/bin/env".into()],
        "/workspace",
        &crate::env::ProcessEnvironment {
            entries: vec!["PUBLIC=value".into()],
            override_names: std::collections::BTreeSet::from(["PUBLIC".into()]),
        },
        false,
        0,
        0,
    )
}

#[tokio::test]
async fn runc_projection_has_only_metadata_in_spec_and_exact_socket_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut prepared = prepare(&config(directory.path())).unwrap();
    let spec = prepared.pending_process_spec.as_ref().unwrap().clone();
    let socket = prepared.launch.as_ref().unwrap().path.clone();
    assert_eq!(socket, spec.with_extension("sock"));
    assert_eq!(fs::symlink_metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&spec).unwrap()).unwrap();
    assert_eq!(document["env"], serde_json::json!(["PUBLIC=value"]));
    assert_eq!(
        document["args"],
        serde_json::json!([
            "/run/codewire-runtime/init",
            "workspace-exec",
            "--projection-fd=3",
            "/usr/bin/env"
        ])
    );
    assert_eq!(prepared.arguments.len(), 3);
    assert!(prepared.environment.is_empty());
    assert_eq!(
        prepared.launch.as_ref().unwrap().override_names,
        std::collections::BTreeSet::from(["PUBLIC".into()]),
    );
    prepared.spawned();
    drop(prepared);
    assert!(!spec.exists());
    assert!(!socket.exists());
}

#[tokio::test]
async fn accepted_rendezvous_sends_names_without_command_values_before_projection_request() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut prepared = prepare(&config(directory.path())).unwrap();
    let launch = prepared.launch.take().unwrap();
    let mut channel = tokio::net::UnixStream::connect(&launch.path).await.unwrap();
    let task = tokio::spawn(launch.deliver(std::process::id()));
    let mut context = [0; codewire_workload_secrets::launcher::LAUNCH_CONTEXT_BYTES];
    channel.read_exact(&mut context).await.unwrap();
    let mut length = [0; 4];
    channel.read_exact(&mut length).await.unwrap();
    assert_eq!(u32::from_be_bytes(length), 7);
    let mut names = [0; 7];
    channel.read_exact(&mut names).await.unwrap();
    assert_eq!(&names, b"PUBLIC\0");
    // No recipient has been sent; cancellation closes this exact launch.
    drop(channel);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn only_hosted_launches_wait_for_first_host_and_keep_the_original_deadline() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut configuration = config(directory.path());
    let local = prepare(&configuration).unwrap();
    assert!(!local.launch.as_ref().unwrap().wait_for_initial_host);
    drop(local);
    configuration.credential_bridge.as_mut().unwrap().transport =
        crate::CredentialBridgeTransport::Hosted;
    let mut prepared = prepare(&configuration).unwrap();
    let mut launch = prepared.launch.take().unwrap();
    assert!(launch.wait_for_initial_host);
    launch.context.deadline_unix_ms = now_unix_ms().unwrap() + 150;
    let path = launch.path.clone();
    let mut channel = tokio::net::UnixStream::connect(&path).await.unwrap();
    let mut task = tokio::spawn(launch.deliver(std::process::id()));
    let mut header = [0; codewire_workload_secrets::launcher::LAUNCH_CONTEXT_BYTES + 4 + 7];
    channel.read_exact(&mut header).await.unwrap();
    channel.write_all(&[7; 32]).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut task)
            .await
            .is_err()
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!path.exists());
}

#[tokio::test]
async fn rendezvous_rejects_wrong_process_before_context_or_authority_request() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut prepared = prepare(&config(directory.path())).unwrap();
    let socket = prepared.launch.as_ref().unwrap().path.clone();
    let mut channel = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let result = prepared
        .project_spawned(Some(std::process::id().checked_add(1).unwrap()))
        .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    let mut byte = [0];
    assert_eq!(channel.read(&mut byte).await.unwrap(), 0);
    assert!(!socket.exists());
}

#[tokio::test]
async fn cancellation_drops_socket_and_does_not_remove_replacement_object() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut prepared = prepare(&config(directory.path())).unwrap();
    let socket = prepared.launch.as_ref().unwrap().path.clone();
    let launch = prepared.launch.take().unwrap();
    let task = tokio::spawn(launch.deliver(std::process::id()));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!socket.exists());

    let prepared = prepare(&config(directory.path())).unwrap();
    let socket = prepared.launch.as_ref().unwrap().path.clone();
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"synthetic-unrelated-object").unwrap();
    drop(prepared);
    assert_eq!(fs::read(&socket).unwrap(), b"synthetic-unrelated-object");
}

#[tokio::test]
async fn selected_projection_never_falls_back_when_identity_or_native_helper_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut configuration = config(directory.path());
    configuration.credential_bridge = None;
    assert!(prepare(&configuration).is_err());
    configuration = config(directory.path());
    configuration.process_execution = ProcessExecution::Native;
    assert!(prepare(&configuration).is_err());
    configuration = config(directory.path());
    configuration
        .launch_projection
        .as_mut()
        .unwrap()
        .selection_sha256 = [0; 32];
    assert!(prepare(&configuration).is_err());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}
