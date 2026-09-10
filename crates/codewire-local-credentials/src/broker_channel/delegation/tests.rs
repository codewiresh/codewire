use uuid::Uuid;

use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};

use codewire_project::PlatformProjectionSelection;
use futures::{future, stream};
use tokio::sync::{Notify, oneshot, watch};

use super::super::{BrokerLeaseAuditLog, BrokerLeaseChannelControl};
use crate::tests::TestProtectedStore;
use crate::{LocalCredentialAuthority, PlatformCredentialBinding, PlatformCredentialConnector};

fn environment() -> EnvironmentId {
    EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap()
}

fn ready(environment: &EnvironmentId, generation: u64) -> bridge::CredentialBridgeReady {
    bridge::CredentialBridgeReady {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: environment.to_string(),
        environment_generation: generation,
    }
}

#[test]
fn guest_ready_must_match_the_inherited_channel_generation_exactly() {
    let environment = environment();
    let admitted = ready(&environment, 7);
    assert!(ready_matches(&environment, 7, &admitted));

    let mut wrong = admitted.clone();
    wrong.environment_generation = 8;
    assert!(!ready_matches(&environment, 7, &wrong));
    wrong = admitted.clone();
    wrong.environment_id = Uuid::new_v4().to_string();
    assert!(!ready_matches(&environment, 7, &wrong));
    wrong = admitted;
    wrong.protocol_version = wrong.protocol_version.saturating_add(1);
    assert!(!ready_matches(&environment, 7, &wrong));
}

#[test]
fn private_admission_must_echo_the_exact_actual_ready() {
    let environment = environment();
    let expected = ready(&environment, 11);
    let admitted = v1::BrokerDelegationResponse {
        output: Some(v1::broker_delegation_response::Output::Admitted(
            expected.clone(),
        )),
    };
    assert_eq!(validate_admission(admitted, &expected), Ok(()));

    let mut wrong = expected.clone();
    wrong.environment_generation += 1;
    let admitted = v1::BrokerDelegationResponse {
        output: Some(v1::broker_delegation_response::Output::Admitted(wrong)),
    };
    assert_eq!(
        validate_admission(admitted, &expected),
        Err(BrokerLeaseChannelError::InvalidResponse)
    );
    assert_eq!(
        validate_admission(v1::BrokerDelegationResponse::default(), &expected),
        Err(BrokerLeaseChannelError::InvalidResponse)
    );
}

#[test]
fn ready_cannot_reappear_in_the_transparent_operation_stream() {
    let environment = environment();
    let duplicate = bridge::CredentialBridgeGuestMessage {
        payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
            ready(&environment, 1),
        )),
    };
    assert!(!valid_remaining_frame(&duplicate));
    assert!(!valid_remaining_frame(
        &bridge::CredentialBridgeGuestMessage::default()
    ));

    let cancel = bridge::CredentialBridgeGuestMessage {
        payload: Some(bridge::credential_bridge_guest_message::Payload::Cancel(
            bridge::CredentialBridgeCancel {
                request_id: Uuid::new_v4().to_string(),
            },
        )),
    };
    assert!(valid_remaining_frame(&cancel));
}

enum ConnectorMode {
    Admit(VecDeque<Result<bridge::CredentialBridgeHostMessage, Status>>),
    Pending,
}

struct SyntheticConnector {
    mode: StdMutex<Option<ConnectorMode>>,
    started: Arc<Notify>,
}

impl PlatformCredentialConnector for SyntheticConnector {
    fn connect(
        &self,
        _binding: PlatformCredentialBinding,
        _ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        _deadline: Instant,
    ) -> futures::future::BoxFuture<'static, Result<PlatformCredentialOutput, Status>> {
        self.started.notify_waiters();
        match self.mode.lock().unwrap().take().unwrap() {
            ConnectorMode::Admit(frames) => Box::pin(async move {
                Ok(Box::pin(HoldingOutput {
                    input,
                    frames,
                    input_error_emitted: false,
                }) as PlatformCredentialOutput)
            }),
            ConnectorMode::Pending => Box::pin(async move {
                let _input = input;
                future::pending().await
            }),
        }
    }
}

struct HoldingOutput {
    input: PlatformCredentialInput,
    frames: VecDeque<Result<bridge::CredentialBridgeHostMessage, Status>>,
    input_error_emitted: bool,
}

impl Stream for HoldingOutput {
    type Item = Result<bridge::CredentialBridgeHostMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(frame) = self.frames.pop_front() {
            return Poll::Ready(Some(frame));
        }
        if self.input_error_emitted {
            return Poll::Pending;
        }
        match self.input.as_mut().poll_next(context) {
            Poll::Ready(Some(Err(status))) => {
                self.input_error_emitted = true;
                Poll::Ready(Some(Err(status)))
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    client: LocalCredentialDelegationClient,
    manager_ready: oneshot::Receiver<()>,
    shutdown: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), BrokerLeaseChannelError>>,
    connector_started: Arc<Notify>,
}

async fn fixture(mode: ConnectorMode) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let store = TestProtectedStore::new(
        codewire_protected_store::ProtectedStorePersistence::ProcessLifetime,
    );
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            store,
            codewire_access::ProviderCatalog::from_definitions(std::iter::empty::<
                codewire_access::ProviderDefinition,
            >())
            .unwrap(),
        )
        .unwrap(),
    );
    let environment = environment();
    let generation = 7;
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let (manager_ready_tx, manager_ready) = oneshot::channel();
    let (shutdown, stopped) = watch::channel(false);
    let connector_started = Arc::new(Notify::new());
    let connector = Arc::new(SyntheticConnector {
        mode: StdMutex::new(Some(mode)),
        started: Arc::clone(&connector_started),
    });
    let binding = PlatformCredentialBinding {
        config_directory: temp.path().join("platform"),
        server_url: "https://codewire.example".into(),
        selection: PlatformProjectionSelection {
            creator: "owner".into(),
            organization: "organization".into(),
            organization_selected: false,
            project_id: Some(Uuid::new_v4().to_string()),
            user_selected: false,
            profile: None,
            ordinary_keys: Default::default(),
            reserved_keys: Default::default(),
        },
        selection_sha256: [7; 32],
    };
    let lifetime = BrokerChannelRefreshLifetime::new(authority);
    let server = tokio::spawn(super::super::serve_broker_lease_channel_with_ready(
        lifetime,
        server_stream,
        environment.clone(),
        generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        None,
        BrokerLeaseChannelControl {
            local_profile: None,
            ready: Some(manager_ready_tx),
            shutdown: Some(stopped),
            platform: Some((binding, connector)),
            platform_delegated: true,
        },
    ));
    let client = LocalCredentialDelegationClient::connect(client_stream, environment, generation)
        .await
        .unwrap();
    Fixture {
        _temp: temp,
        client,
        manager_ready,
        shutdown,
        server,
        connector_started,
    }
}

#[tokio::test]
async fn inherited_relay_requires_exact_admission_before_ready_and_is_once_only() {
    let response = bridge::CredentialBridgeHostMessage {
        payload: Some(
            bridge::credential_bridge_host_message::Payload::ResponseEnd(
                bridge::CredentialBridgeResponseEnd {
                    request_id: Uuid::new_v4().to_string(),
                },
            ),
        ),
    };
    let mut fixture = fixture(ConnectorMode::Admit(VecDeque::from([Ok(response.clone())]))).await;
    assert_eq!(
        fixture.client.report_ready().await,
        Err(BrokerLeaseChannelError::Denied)
    );
    let local = fixture
        .client
        .inner
        .project_environment(v1::BrokerEnvironmentProjectionRequest::default())
        .await
        .unwrap_err();
    assert_eq!(local.code(), tonic::Code::FailedPrecondition);

    let expected = ready(
        &fixture.client.environment_id,
        fixture.client.environment_generation,
    );
    let mut output = fixture
        .client
        .delegate_credentials(expected.clone(), stream::pending())
        .await
        .unwrap();
    fixture.client.report_ready().await.unwrap();
    fixture.manager_ready.await.unwrap();
    assert_eq!(output.next().await.unwrap().unwrap(), response);
    assert!(matches!(
        fixture
            .client
            .delegate_credentials(expected, stream::pending())
            .await,
        Err(BrokerLeaseChannelError::Denied)
    ));

    fixture.shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn duplicate_ready_terminates_the_admitted_relay() {
    let mut fixture = fixture(ConnectorMode::Admit(VecDeque::new())).await;
    let expected = ready(
        &fixture.client.environment_id,
        fixture.client.environment_generation,
    );
    let duplicate = bridge::CredentialBridgeGuestMessage {
        payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
            expected.clone(),
        )),
    };
    let mut output = fixture
        .client
        .delegate_credentials(expected, stream::once(async move { duplicate }))
        .await
        .unwrap();
    assert_eq!(
        output.next().await,
        Some(Err(BrokerLeaseChannelError::Unavailable))
    );
    fixture.shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_cancels_pending_connector_and_idle_output() {
    let pending = fixture(ConnectorMode::Pending).await;
    let expected = ready(
        &pending.client.environment_id,
        pending.client.environment_generation,
    );
    let started_notify = Arc::clone(&pending.connector_started);
    let mut started = Box::pin(started_notify.notified());
    started.as_mut().enable();
    let Fixture {
        _temp,
        mut client,
        manager_ready: _,
        shutdown,
        server,
        connector_started: _,
    } = pending;
    let delegation = tokio::spawn(async move {
        client
            .delegate_credentials(expected, stream::pending())
            .await
    });
    started.await;
    shutdown.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), delegation)
            .await
            .is_ok()
    );
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let mut idle = fixture(ConnectorMode::Admit(VecDeque::new())).await;
    let expected = ready(
        &idle.client.environment_id,
        idle.client.environment_generation,
    );
    let mut output = idle
        .client
        .delegate_credentials(expected, stream::pending())
        .await
        .unwrap();
    idle.shutdown.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), output.next())
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::timeout(Duration::from_secs(2), idle.server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
