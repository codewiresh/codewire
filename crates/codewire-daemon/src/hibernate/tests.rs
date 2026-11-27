use std::sync::Mutex;

use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonService as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_stream::StreamExt;

use super::*;
use crate::{CredentialBridgeConfig, CredentialBridgeTransport};

const OLD_TOKEN: &str = "synthetic-old-pod-daemon-credential";
const NEW_TOKEN: &str = "synthetic-new-pod-daemon-credential";

#[derive(Clone, Copy)]
enum AskOutcome {
    Ok,
    No,
    Fails,
}

struct FakeHibernatePlatform {
    calls: Mutex<Vec<&'static str>>,
    ask: AskOutcome,
    release_rebind: Notify,
    rebound: Mutex<Option<Result<ReboundIdentity, String>>>,
    rebind_serving: Notify,
}

impl FakeHibernatePlatform {
    fn new(ask: AskOutcome, rebound: Result<ReboundIdentity, String>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::default(),
            ask,
            release_rebind: Notify::new(),
            rebound: Mutex::new(Some(rebound)),
            rebind_serving: Notify::new(),
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }

    fn trigger_restore(&self) {
        self.release_rebind.notify_one();
    }
}

impl HibernatePlatform for FakeHibernatePlatform {
    fn hold_for_hibernate(&self) {
        self.note("hold");
    }

    fn release_on_refusal(&self) {
        self.note("release");
    }

    fn ask_hibernate(&self) -> Pending<'_, io::Result<bool>> {
        self.note("ask");
        let ask = self.ask;
        Box::pin(async move {
            match ask {
                AskOutcome::Ok => Ok(true),
                AskOutcome::No => Ok(false),
                AskOutcome::Fails => Err(io::Error::other("runtime socket closed")),
            }
        })
    }

    fn wait_for_restore_and_rebind(&self) -> Pending<'_, Result<ReboundIdentity, String>> {
        self.note("wait-restore");
        Box::pin(async move {
            self.release_rebind.notified().await;
            self.note("rebind-done");
            self.rebound
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err("no scripted rebound identity".into()))
        })
    }

    fn on_rebind_serving(&self) -> Pending<'_, ()> {
        self.note("serving");
        self.rebind_serving.notify_one();
        Box::pin(async {})
    }
}

fn own_cgroups(path: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        format!("2:cpuset,cpu,memory,devices,freezer,pids:{path}\n"),
    )
    .unwrap();
    file
}

fn auth_request<T>(payload: T, token: Option<&str>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(payload);
    if let Some(token) = token {
        request.metadata_mut().insert(
            codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER,
            token.parse().unwrap(),
        );
    }
    request
}

fn service(
    root: &Path,
    bridge: Option<CredentialBridgeConfig>,
) -> crate::service::DaemonServiceImpl {
    crate::service::DaemonServiceImpl::new(crate::Config {
        listen_addr: "unused:0".into(),
        workspace_root: root.to_path_buf(),
        home_root: root.to_path_buf(),
        mount_roots: Vec::new(),
        auth_token: DaemonAuthToken::new(OLD_TOKEN).unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: bridge,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
        session_working_dir: None,
        sandbox_server_url: None,
        interception: None,
    })
}

fn rebound_identity(env_id: Uuid, generation: u64) -> ReboundIdentity {
    ReboundIdentity {
        daemon_credential: DaemonAuthToken::new(NEW_TOKEN).unwrap(),
        environment_id: env_id,
        operation_generation: generation,
    }
}

/// cw-security (#5484, #6647): port 7777 refuses every RPC (both old and new
/// credentials) between hibernate acceptance/restore and new bind completion,
/// and refuses the old Pod's daemon credential once the new bind succeeds.
#[tokio::test]
async fn port_7777_refuses_during_rebind_and_refuses_old_credential_after_rebind() {
    let temp = tempfile::tempdir().unwrap();
    let env_id = Uuid::new_v4();
    let cgroups = own_cgroups("/workload/workspace");
    let platform = FakeHibernatePlatform::new(AskOutcome::Ok, Ok(rebound_identity(env_id, 2)));
    let daemon = service(temp.path(), None).with_hibernate_for_test(
        Hibernate::new(platform.clone())
            .with_own_cgroups(cgroups.path())
            .with_answer_lead(Duration::from_millis(5)),
    );

    // Before hibernate: old credential works.
    daemon
        .get_health(auth_request(v1::GetHealthRequest {}, Some(OLD_TOKEN)))
        .await
        .unwrap();

    // Hibernate is accepted.
    let response = daemon
        .hibernate(auth_request(v1::HibernateRequest {}, Some(OLD_TOKEN)))
        .await
        .unwrap()
        .into_inner();
    assert!(response.accepted);

    // Immediately after acceptance and throughout restore-before-bind, 7777
    // refuses every credential with Unavailable.
    for token in [Some(OLD_TOKEN), Some(NEW_TOKEN), None] {
        let error = daemon
            .get_health(auth_request(v1::GetHealthRequest {}, token))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable, "token = {token:?}");
    }

    // Complete restore + BindWorkspace for the new Pod.
    platform.trigger_restore();
    tokio::time::timeout(Duration::from_secs(2), platform.rebind_serving.notified())
        .await
        .expect("rebind did not complete");

    // After re-bind: old Pod's daemon credential is permanently refused.
    let old_error = daemon
        .get_health(auth_request(v1::GetHealthRequest {}, Some(OLD_TOKEN)))
        .await
        .unwrap_err();
    assert_eq!(old_error.code(), tonic::Code::Unauthenticated);

    // New Pod's daemon credential works.
    daemon
        .get_health(auth_request(v1::GetHealthRequest {}, Some(NEW_TOKEN)))
        .await
        .unwrap();
    assert_eq!(
        platform.calls(),
        ["hold", "ask", "wait-restore", "rebind-done", "serving"]
    );
}

/// cw-security (#5484, #6647): a running daemon never re-binds. Calling
/// `complete_hosted_rebind` while an active credential is installed fails with
/// `FailedPrecondition` and leaves the running daemon's credential untouched.
#[test]
fn running_daemon_never_rebinds() {
    let auth = DaemonAuth::new(DaemonAuthToken::new(OLD_TOKEN).unwrap());
    let error = auth
        .complete_hosted_rebind(DaemonAuthToken::new(NEW_TOKEN).unwrap())
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);

    auth.authorize(Some(OLD_TOKEN)).unwrap();
    assert_eq!(
        auth.authorize(Some(NEW_TOKEN)).unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

/// Pre-hibernate connections are aborted after `answer_lead`, so no stream
/// opened under the old Pod's credential can survive hibernate/restore.
#[tokio::test]
async fn pre_hibernate_connections_end_before_restore() {
    let env_id = Uuid::new_v4();
    let cgroups = own_cgroups("/workload/workspace");
    let platform = FakeHibernatePlatform::new(AskOutcome::Ok, Ok(rebound_identity(env_id, 2)));
    let auth = DaemonAuth::new(DaemonAuthToken::new(OLD_TOKEN).unwrap());
    let bridge = CredentialBridge::new(None);
    let hibernate = Hibernate::new(platform.clone())
        .with_own_cgroups(cgroups.path())
        .with_answer_lead(Duration::from_millis(10));

    let (old, mut old_peer) = tokio::io::duplex(64);
    let mut old = auth.bind_connection(old);
    old_peer.write_all(b"a").await.unwrap();
    let mut byte = [0_u8; 1];
    old.read_exact(&mut byte).await.unwrap();

    assert!(hibernate.begin(&auth, &bridge).await.unwrap());
    let pending = tokio::spawn(async move {
        let mut byte = [0_u8; 1];
        old.read_exact(&mut byte).await
    });
    let result = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .expect("old connection did not close")
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
}

/// cw-security (#5484, #6647): an open credential bridge epoch ends when
/// hibernate starts, and after restore + re-bind an epoch presenting the old
/// Pod's generation is refused while the new Pod's generation is admitted.
#[tokio::test]
async fn old_credential_bridge_epoch_is_ended_and_old_generation_refused_after_rebind() {
    let temp = tempfile::tempdir().unwrap();
    let env_id = Uuid::new_v4();
    let bridge = CredentialBridge::new(Some(CredentialBridgeConfig {
        environment_id: env_id,
        environment_generation: 1,
        ingress_socket: temp.path().join("bridge.sock"),
        ingress_uid: 0,
        ingress_gid: 0,
        transport: CredentialBridgeTransport::Local,
    }));
    let auth = DaemonAuth::new(DaemonAuthToken::new(OLD_TOKEN).unwrap());
    let cgroups = own_cgroups("/workload/workspace");
    let platform = FakeHibernatePlatform::new(AskOutcome::Ok, Ok(rebound_identity(env_id, 2)));
    let hibernate = Hibernate::new(platform.clone())
        .with_own_cgroups(cgroups.path())
        .with_answer_lead(Duration::from_millis(5));

    // Open an epoch for generation 1 before hibernate.
    let (old_tx, old_rx) = tokio::sync::mpsc::channel(4);
    old_tx
        .send(Ok(bridge_v1::CredentialBridgeHostMessage {
            payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                bridge_v1::CredentialBridgeOpen {
                    protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: env_id.to_string(),
                    environment_generation: 1,
                    capabilities: Vec::new(),
                    placeholders: Vec::new(),
                },
            )),
        }))
        .await
        .unwrap();
    let mut old_output = bridge
        .connect_stream_for_test(tokio_stream::wrappers::ReceiverStream::new(old_rx))
        .await
        .unwrap()
        .output;
    let ready = old_output.next().await.unwrap().unwrap();
    assert!(matches!(
        ready.payload,
        Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(
            _
        ))
    ));

    // Start hibernate: the open epoch ends and new epochs are refused while held.
    assert!(hibernate.begin(&auth, &bridge).await.unwrap());
    assert!(bridge.owner_for_test().epoch_token().is_none());
    let closed = tokio::time::timeout(Duration::from_secs(2), old_output.next())
        .await
        .expect("old bridge epoch did not close on hibernate");
    assert!(closed.is_none());

    // Complete restore + re-bind to generation 2.
    platform.trigger_restore();
    tokio::time::timeout(Duration::from_secs(2), platform.rebind_serving.notified())
        .await
        .expect("rebind did not complete");

    // Presenting the old generation (1) after re-bind is refused.
    let (stale_tx, stale_rx) = tokio::sync::mpsc::channel(4);
    stale_tx
        .send(Ok(bridge_v1::CredentialBridgeHostMessage {
            payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                bridge_v1::CredentialBridgeOpen {
                    protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: env_id.to_string(),
                    environment_generation: 1,
                    capabilities: Vec::new(),
                    placeholders: Vec::new(),
                },
            )),
        }))
        .await
        .unwrap();
    let stale_err = bridge
        .connect_stream_for_test(tokio_stream::wrappers::ReceiverStream::new(stale_rx))
        .await
        .err()
        .expect("old generation epoch must be refused");
    assert_eq!(stale_err.code(), tonic::Code::FailedPrecondition);

    // Presenting the new generation (2) succeeds.
    let (fresh_tx, fresh_rx) = tokio::sync::mpsc::channel(4);
    fresh_tx
        .send(Ok(bridge_v1::CredentialBridgeHostMessage {
            payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                bridge_v1::CredentialBridgeOpen {
                    protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: env_id.to_string(),
                    environment_generation: 2,
                    capabilities: Vec::new(),
                    placeholders: Vec::new(),
                },
            )),
        }))
        .await
        .unwrap();
    let mut fresh_output = bridge
        .connect_stream_for_test(tokio_stream::wrappers::ReceiverStream::new(fresh_rx))
        .await
        .unwrap()
        .output;
    let ready = fresh_output.next().await.unwrap().unwrap();
    assert!(matches!(
        ready.payload,
        Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(
            _
        ))
    ));
}

#[tokio::test]
async fn failed_rebind_leaves_daemon_closed_and_does_not_signal_serving() {
    let temp = tempfile::tempdir().unwrap();
    let cgroups = own_cgroups("/workload/workspace");
    let platform = FakeHibernatePlatform::new(AskOutcome::Ok, Err("bind refused".into()));
    let daemon = service(temp.path(), None).with_hibernate_for_test(
        Hibernate::new(platform.clone())
            .with_own_cgroups(cgroups.path())
            .with_answer_lead(Duration::from_millis(5)),
    );

    assert!(
        daemon
            .hibernate(auth_request(v1::HibernateRequest {}, Some(OLD_TOKEN)))
            .await
            .unwrap()
            .into_inner()
            .accepted
    );
    platform.trigger_restore();
    // Give run_rebind time to observe the error and exit.
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        platform.calls(),
        ["hold", "ask", "wait-restore", "rebind-done"]
    );
    for token in [Some(OLD_TOKEN), Some(NEW_TOKEN)] {
        let error = daemon
            .get_health(auth_request(v1::GetHealthRequest {}, token))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
    }
}

#[tokio::test]
async fn refused_or_failed_ask_releases_and_keeps_serving() {
    let env_id = Uuid::new_v4();
    let cgroups = own_cgroups("/workload/workspace");

    // Runtime says `no`: returns accepted = false, releases hold, old token still works.
    let no_platform = FakeHibernatePlatform::new(AskOutcome::No, Ok(rebound_identity(env_id, 2)));
    let auth = DaemonAuth::new(DaemonAuthToken::new(OLD_TOKEN).unwrap());
    let bridge = CredentialBridge::new(None);
    let hibernate = Hibernate::new(no_platform.clone()).with_own_cgroups(cgroups.path());
    assert!(!hibernate.begin(&auth, &bridge).await.unwrap());
    assert_eq!(no_platform.calls(), ["hold", "ask", "release"]);
    assert!(bridge.owner_for_test().epoch_token().is_some());
    auth.authorize(Some(OLD_TOKEN)).unwrap();

    // Runtime transport fails: returns Unavailable, releases hold, old token still works.
    let fail_platform =
        FakeHibernatePlatform::new(AskOutcome::Fails, Ok(rebound_identity(env_id, 2)));
    let hibernate = Hibernate::new(fail_platform.clone()).with_own_cgroups(cgroups.path());
    let error = hibernate.begin(&auth, &bridge).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert_eq!(fail_platform.calls(), ["hold", "ask", "release"]);
    assert!(bridge.owner_for_test().epoch_token().is_some());
    auth.authorize(Some(OLD_TOKEN)).unwrap();
}

#[tokio::test]
async fn refuses_outside_frozen_workload_concurrent_and_unimplemented() {
    let temp = tempfile::tempdir().unwrap();
    let env_id = Uuid::new_v4();

    // Without a hibernate platform: Unimplemented.
    let unimplemented = service(temp.path(), None)
        .hibernate(auth_request(v1::HibernateRequest {}, Some(OLD_TOKEN)))
        .await
        .unwrap_err();
    assert_eq!(unimplemented.code(), tonic::Code::Unimplemented);

    // Outside /workload: FailedPrecondition and holds nothing.
    let outside = own_cgroups("/kubepods/burstable/pod");
    let platform = FakeHibernatePlatform::new(AskOutcome::Ok, Ok(rebound_identity(env_id, 2)));
    let auth = DaemonAuth::new(DaemonAuthToken::new(OLD_TOKEN).unwrap());
    let bridge = CredentialBridge::new(None);
    let error = Hibernate::new(platform.clone())
        .with_own_cgroups(outside.path())
        .begin(&auth, &bridge)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(platform.calls().is_empty());
    assert!(bridge.owner_for_test().epoch_token().is_some());

    // Concurrent hibernate: second call returns accepted = false.
    let inside = own_cgroups("/workload/workspace");
    let hibernate = Hibernate::new(platform.clone())
        .with_own_cgroups(inside.path())
        .with_answer_lead(Duration::from_millis(5));
    assert!(hibernate.begin(&auth, &bridge).await.unwrap());
    assert!(!hibernate.begin(&auth, &bridge).await.unwrap());
}
