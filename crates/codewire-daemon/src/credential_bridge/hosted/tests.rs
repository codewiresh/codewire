use super::*;
use crate::credential_bridge::{CredentialBridge, CredentialBridgeConnection};
use crate::{CredentialBridgeConfig, CredentialBridgeTransport};
use codewire_gateway_proto::{CREDENTIAL_BRIDGE_PROTOCOL_VERSION, codewire::bridge::v1};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

fn fixture() -> (tempfile::TempDir, CredentialBridge, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("token");
    std::fs::write(&path, "workspace.synthetic.one").unwrap();
    let bridge = CredentialBridge::new(Some(CredentialBridgeConfig {
        transport: CredentialBridgeTransport::Hosted,
        environment_id: uuid::Uuid::new_v4(),
        environment_generation: 7,
        ingress_socket: temp.path().join("ingress.sock"),
        ingress_uid: 1000,
        ingress_gid: 1000,
    }));
    (temp, bridge, path)
}

async fn prepared(
    bridge: &CredentialBridge,
    path: &Path,
) -> (
    mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    CredentialBridgeConnection,
) {
    let (sender, receiver) = mpsc::channel(2);
    let connection = bridge
        .connect_with_token_file(ReceiverStream::new(receiver), path)
        .await
        .unwrap();
    (sender, connection)
}

fn open(bridge: &CredentialBridge) -> v1::CredentialBridgeHostMessage {
    let config = bridge.config.as_ref().unwrap();
    v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::Open(
            v1::CredentialBridgeOpen {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: config.environment_id.to_string(),
                environment_generation: config.environment_generation,
                capabilities: Vec::new(),
            },
        )),
    }
}

fn context(bridge: &CredentialBridge) -> codewire_workload_secrets::ProjectionContext {
    let config = bridge.config.as_ref().unwrap();
    codewire_workload_secrets::ProjectionContext {
        environment_id: *config.environment_id.as_bytes(),
        operation_generation: config.environment_generation,
        selection_sha256: [1; 32],
        deadline_unix_ms: codewire_workload_secrets::launcher::now_unix_ms().unwrap() + 5_000,
    }
}

#[tokio::test]
async fn token_reader_allows_projected_rotation_but_not_invalid_or_oversized_values() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("version-one");
    let path = temp.path().join("token");
    std::fs::write(&target, "synthetic.one").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let token = read_workspace_authorization(&path).await.unwrap();
    assert!(token.0.is_sensitive());
    assert_eq!(token.0.to_bytes().unwrap(), b"Bearer synthetic.one"[..]);
    assert!(!format!("{token:?}").contains("synthetic.one"));
    std::fs::write(&target, "synthetic.two").unwrap();
    assert_eq!(
        read_workspace_authorization(&path)
            .await
            .unwrap()
            .into_metadata()
            .to_bytes()
            .unwrap(),
        b"Bearer synthetic.two"[..]
    );
    for invalid in [
        Vec::new(),
        b"canary\n".to_vec(),
        b"Bearer canary".to_vec(),
        vec![b'a'; MAX_TOKEN_BYTES + 1],
    ] {
        std::fs::write(&target, invalid).unwrap();
        let error = read_workspace_authorization(&path).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(!error.message().contains("canary"));
    }
}

#[tokio::test]
async fn fifo_and_directory_are_rejected_without_blocking() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fifo");
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_workspace_authorization(&path)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(read_workspace_authorization(temp.path()).await.is_err());
}

#[tokio::test]
async fn hosted_ready_and_sensitive_metadata_precede_open_but_not_activation() {
    let (_temp, bridge, path) = fixture();
    let (sender, mut connection) = prepared(&bridge, &path).await;
    assert_eq!(
        connection
            .workspace_authorization
            .as_ref()
            .unwrap()
            .0
            .to_bytes()
            .unwrap(),
        b"Bearer workspace.synthetic.one"[..]
    );
    assert!(matches!(
        connection.output.next().await.unwrap().unwrap().payload,
        Some(v1::credential_bridge_guest_message::Payload::Ready(_))
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            bridge.wait_for_initial_host(&context(&bridge))
        )
        .await
        .is_err()
    );
    sender.send(Ok(open(&bridge))).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        bridge.wait_for_initial_host(&context(&bridge)),
    )
    .await
    .unwrap()
    .unwrap();
    bridge.shutdown().await;
    assert!(connection.output.next().await.is_none());
    assert!(
        bridge
            .wait_for_initial_host(&context(&bridge))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepared_replacement_and_invalid_open_do_not_replace_active_epoch() {
    let (_temp, bridge, path) = fixture();
    let (first_sender, mut first) = prepared(&bridge, &path).await;
    first.output.next().await.unwrap().unwrap();
    first_sender.send(Ok(open(&bridge))).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        bridge.wait_for_initial_host(&context(&bridge)),
    )
    .await
    .unwrap()
    .unwrap();
    let (second_sender, mut second) = prepared(&bridge, &path).await;
    second.output.next().await.unwrap().unwrap();
    let mut invalid = open(&bridge);
    if let Some(v1::credential_bridge_host_message::Payload::Open(value)) = invalid.payload.as_mut()
    {
        value.environment_generation += 1;
    }
    second_sender.send(Ok(invalid)).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), second.output.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), first.output.next())
            .await
            .is_err()
    );
    bridge.shutdown().await;
}

#[tokio::test]
async fn pending_admission_budget_and_shutdown_include_deferred_open_tasks() {
    let (_temp, bridge, path) = fixture();
    // Three permits: an active, a draining and a prepared epoch.
    let (_first_sender, mut first) = prepared(&bridge, &path).await;
    let (_second_sender, mut second) = prepared(&bridge, &path).await;
    let (_third_sender, mut third) = prepared(&bridge, &path).await;
    let (_sender, receiver) = mpsc::channel(1);
    assert_eq!(
        bridge
            .connect_with_token_file(ReceiverStream::new(receiver), &path)
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::ResourceExhausted
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), bridge.shutdown())
        .await
        .unwrap();
    assert!(first.output.next().await.is_none());
    assert!(second.output.next().await.is_none());
    assert!(third.output.next().await.is_none());
    let (_sender, receiver) = mpsc::channel(1);
    assert_eq!(
        bridge
            .connect_with_token_file(ReceiverStream::new(receiver), &path)
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(bridge.owner.tasks.is_empty());
}

#[tokio::test]
async fn dropped_unopened_stream_releases_admission_without_activating() {
    let (_temp, bridge, path) = fixture();
    let (sender, mut connection) = prepared(&bridge, &path).await;
    connection.output.next().await.unwrap().unwrap();
    drop(sender);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), connection.output.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            bridge.wait_for_initial_host(&context(&bridge))
        )
        .await
        .is_err()
    );
    bridge.shutdown().await;
}

#[tokio::test]
async fn the_hosts_listed_capabilities_reach_the_epoch_and_malformed_lists_refuse_it() {
    let with_capabilities = |bridge: &CredentialBridge, capabilities: Vec<String>| {
        let mut message = open(bridge);
        if let Some(v1::credential_bridge_host_message::Payload::Open(value)) =
            message.payload.as_mut()
        {
            value.capabilities = capabilities;
        }
        message
    };
    // A current gateway copies the broker's "codex-login"; an older one
    // lists nothing, and the daemon then never sends the operation.
    for (capabilities, supported) in [
        (vec![], false),
        (vec!["future-op".to_owned()], false),
        (vec!["codex-login".to_owned()], true),
    ] {
        let (_temp, bridge, path) = fixture();
        let (sender, mut connection) = prepared(&bridge, &path).await;
        connection.output.next().await.unwrap().unwrap();
        sender
            .send(Ok(with_capabilities(&bridge, capabilities)))
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.wait_for_initial_host(&context(&bridge)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            bridge.shared().unwrap().supports_codex_login().await,
            supported
        );
        bridge.shutdown().await;
    }
    for capabilities in [
        vec!["Codex-Login".to_owned()],
        vec![
            "codex-login".to_owned();
            codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES + 1
        ],
    ] {
        let (_temp, bridge, path) = fixture();
        let (sender, mut connection) = prepared(&bridge, &path).await;
        connection.output.next().await.unwrap().unwrap();
        sender
            .send(Ok(with_capabilities(&bridge, capabilities)))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), connection.output.next())
                .await
                .unwrap()
                .is_none()
        );
        assert!(!bridge.shared().unwrap().supports_codex_login().await);
        bridge.shutdown().await;
    }
}
