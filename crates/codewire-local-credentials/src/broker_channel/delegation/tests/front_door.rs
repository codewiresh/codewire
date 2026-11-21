//! The boot's front-door session over a platform-delegated channel (#4909):
//! it joins only this channel's admitted delegation, one at a time, carries
//! only front-door frames, and the epoch's handle never reaches the relay.

use std::sync::atomic::AtomicUsize;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::*;

/// A marker standing in for the platform's epoch handle. The joiner holds
/// it, as the CLI's does; nothing the relay receives may carry it.
const HANDLE: [u8; 32] = [0xc3; 32];
const CAPABILITIES: [&str; 2] = [
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
];

/// The platform's side of a join: it records the Ready it was given and
/// answers every frame with a request end.
#[derive(Default)]
struct SyntheticJoiner {
    joins: AtomicUsize,
    readies: StdMutex<Vec<bridge::CredentialBridgeReady>>,
    handle: StdMutex<Vec<u8>>,
}

impl crate::PlatformFrontDoorJoiner for SyntheticJoiner {
    fn join(
        &self,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        _deadline: Instant,
    ) -> futures::future::BoxFuture<'static, Result<(Vec<String>, PlatformCredentialOutput), Status>>
    {
        self.joins.fetch_add(1, Ordering::SeqCst);
        self.readies.lock().unwrap().push(ready);
        *self.handle.lock().unwrap() = HANDLE.to_vec();
        Box::pin(async move {
            // Every frame is answered, so one that should never reach the
            // platform shows up as an answer.
            let output = input.map(|frame| {
                let request_id = match frame?.payload {
                    Some(bridge::credential_bridge_guest_message::Payload::Request(request)) => {
                        request.request_id
                    }
                    _ => "answered".into(),
                };
                Ok(bridge::CredentialBridgeHostMessage {
                    payload: Some(
                        bridge::credential_bridge_host_message::Payload::ResponseEnd(
                            bridge::CredentialBridgeResponseEnd { request_id },
                        ),
                    ),
                })
            });
            Ok((
                CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                Box::pin(output) as PlatformCredentialOutput,
            ))
        })
    }
}

fn guest(
    payload: bridge::credential_bridge_guest_message::Payload,
) -> bridge::CredentialBridgeGuestMessage {
    bridge::CredentialBridgeGuestMessage {
        payload: Some(payload),
    }
}

fn request(request_id: &str) -> bridge::CredentialBridgeGuestMessage {
    guest(bridge::credential_bridge_guest_message::Payload::Request(
        bridge::CredentialBridgeRequest {
            request_id: request_id.into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            ..Default::default()
        },
    ))
}

impl Fixture {
    /// Admit the channel's delegation, as the relay does first.
    async fn admit(&mut self) -> impl Sized + use<> {
        let expected = ready(
            &self.client.environment_id,
            self.client.environment_generation,
        );
        let output = self
            .client
            .delegate_credentials(expected, stream::pending())
            .await
            .unwrap();
        self.client.report_ready().await.unwrap();
        output
    }

    /// Open a front-door session whose first frame is `first`; returns its
    /// input sender and the answer.
    async fn front_door(
        &mut self,
        first: bridge::CredentialBridgeGuestMessage,
    ) -> (
        mpsc::Sender<bridge::CredentialBridgeGuestMessage>,
        Result<tonic::Response<tonic::Streaming<bridge::CredentialBridgeHostMessage>>, Status>,
    ) {
        let (input, receiver) = mpsc::channel(4);
        input.send(first).await.unwrap();
        let answer = self
            .client
            .inner
            .delegate_front_door(ReceiverStream::new(receiver))
            .await;
        (input, answer)
    }

    fn own_ready(&self) -> bridge::CredentialBridgeGuestMessage {
        guest(bridge::credential_bridge_guest_message::Payload::Ready(
            ready(
                &self.client.environment_id,
                self.client.environment_generation,
            ),
        ))
    }
}

#[tokio::test]
async fn a_front_door_session_waits_for_its_delegations_admission() {
    let joiner = Arc::new(SyntheticJoiner::default());
    let mut fixture = fixture(ConnectorMode::AdmitJoinable(joiner.clone())).await;
    let own = fixture.own_ready();
    let (_input, answer) = fixture.front_door(own).await;
    assert_eq!(answer.unwrap_err().code(), tonic::Code::FailedPrecondition);
    assert_eq!(joiner.joins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_delegation_the_platform_joins_no_front_door_to_refuses_one() {
    let mut fixture = fixture(ConnectorMode::Admit(VecDeque::new())).await;
    let _delegation = fixture.admit().await;
    let own = fixture.own_ready();
    let (_input, answer) = fixture.front_door(own).await;
    assert_eq!(answer.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn a_front_door_session_joins_its_own_delegation_and_lists_its_capabilities() {
    let joiner = Arc::new(SyntheticJoiner::default());
    let mut fixture = fixture(ConnectorMode::AdmitJoinable(joiner.clone())).await;
    let _delegation = fixture.admit().await;
    let own = fixture.own_ready();
    let (input, answer) = fixture.front_door(own).await;
    let mut answer = answer.unwrap();
    let capabilities: Vec<_> = answer
        .metadata()
        .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(capabilities, CAPABILITIES);
    // The platform got this channel's own Ready, never a frame's choice.
    assert_eq!(
        joiner.readies.lock().unwrap().as_slice(),
        [ready(
            &fixture.client.environment_id,
            fixture.client.environment_generation
        )]
    );
    input.send(request("front-door-request")).await.unwrap();
    let frame = answer.get_mut().message().await.unwrap().unwrap();
    assert!(matches!(
        frame.payload,
        Some(bridge::credential_bridge_host_message::Payload::ResponseEnd(end))
            if end.request_id == "front-door-request"
    ));
}

#[tokio::test]
async fn a_delegation_serves_one_front_door_session_at_a_time() {
    let joiner = Arc::new(SyntheticJoiner::default());
    let mut fixture = fixture(ConnectorMode::AdmitJoinable(joiner.clone())).await;
    let _delegation = fixture.admit().await;
    let own = fixture.own_ready();
    let (first_input, first) = fixture.front_door(own.clone()).await;
    let first = first.unwrap();
    let (_second_input, second) = fixture.front_door(own.clone()).await;
    assert_eq!(second.unwrap_err().code(), tonic::Code::AlreadyExists);
    drop((first_input, first));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (_input, answer) = fixture.front_door(own.clone()).await;
            match answer {
                Ok(_) => break,
                Err(status) if status.code() == tonic::Code::AlreadyExists => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(status) => panic!("unexpected {status:?}"),
            }
        }
    })
    .await
    .expect("the next session joins once the first has ended");
}

#[tokio::test]
async fn a_session_must_open_with_its_own_ready_and_carries_no_login_or_projection() {
    let joiner = Arc::new(SyntheticJoiner::default());
    let mut fixture = fixture(ConnectorMode::AdmitJoinable(joiner.clone())).await;
    let _delegation = fixture.admit().await;
    let other = guest(bridge::credential_bridge_guest_message::Payload::Ready(
        ready(
            &fixture.client.environment_id,
            fixture.client.environment_generation + 1,
        ),
    ));
    let (_input, answer) = fixture.front_door(other).await;
    assert_eq!(answer.unwrap_err().code(), tonic::Code::PermissionDenied);
    let (_input, answer) = fixture.front_door(request("before-ready")).await;
    assert_eq!(answer.unwrap_err().code(), tonic::Code::PermissionDenied);

    for refused in [
        login_request("login"),
        claude_login_request("claude-login"),
        guest(
            bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionRequest::default(),
            ),
        ),
        fixture.own_ready(),
    ] {
        let own = fixture.own_ready();
        let (input, answer) = fixture.front_door(own).await;
        let mut answer = answer.unwrap();
        input.send(refused).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(2), answer.get_mut().message())
            .await
            .unwrap();
        assert!(
            !matches!(ended, Ok(Some(_))),
            "a refused frame was answered: {ended:?}"
        );
    }
}

/// The handle lives in the joiner, inside the authority: no answer the
/// relay reads carries it, frames or metadata (#4909, cw-security).
#[tokio::test]
async fn the_relay_never_receives_the_epochs_handle() {
    let joiner = Arc::new(SyntheticJoiner::default());
    let mut fixture = fixture(ConnectorMode::AdmitJoinable(joiner.clone())).await;
    let _delegation = fixture.admit().await;
    let own = fixture.own_ready();
    let (input, answer) = fixture.front_door(own).await;
    let mut answer = answer.unwrap();
    assert_eq!(joiner.handle.lock().unwrap().as_slice(), HANDLE);
    let mut seen = Vec::new();
    for (name, value) in answer.metadata().clone().into_headers().iter() {
        seen.extend(name.as_str().as_bytes());
        seen.extend(value.as_bytes());
    }
    input.send(request("handle-check")).await.unwrap();
    seen.extend(
        answer
            .get_mut()
            .message()
            .await
            .unwrap()
            .unwrap()
            .encode_to_vec(),
    );
    assert!(
        !seen.windows(HANDLE.len()).any(|window| window == HANDLE),
        "the handle reached the relay"
    );
}
