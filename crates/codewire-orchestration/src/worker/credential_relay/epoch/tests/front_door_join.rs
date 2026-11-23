//! Upstreams joined to an admitted epoch (#4001): the broker stream is opened
//! with the epoch's own credentials, handle and binding Ready, none of which
//! reach the daemon; messages cross unchanged; the newest admitted epoch
//! takes new joins; and the broker's refusals are passed by code alone. A
//! signing ask (N3b) is made with the same credentials and handle, and its
//! refusals are passed by code alone too.
use super::budgets::admitted;
use super::*;
use crate::front_door::{BindingKey, EpochRequest, Join, Joined, Sign};
use codewire_daemon_proto::broker::v1::{InterceptionLeaf, SignInterceptionLeavesResponse};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
};

const HANDLE: [u8; 32] = [7; 32];
const SUCCESSOR_HANDLE: [u8; 32] = [8; 32];

type EpochTask = tokio::task::JoinHandle<Result<(), DrainFailure>>;

fn key(fixture: &Fixture) -> BindingKey {
    BindingKey {
        environment_id: fixture.config.environment_id,
        pod_uid: SYNTHETIC_POD_UID.into(),
        generation: 7,
    }
}

fn front_doors(fixture: &Fixture) -> &crate::front_door::FrontDoorEpochs {
    fixture.config.front_doors.as_deref().unwrap()
}

fn front_door_capabilities() -> Vec<&'static str> {
    vec![
        CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
        CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    ]
}

fn guest_cancel() -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
            v1::CredentialBridgeCancel {
                request_id: Uuid::new_v4().to_string(),
            },
        )),
    }
}

fn credit() -> v1::CredentialBridgeHostMessage {
    v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::StreamCredit(
            v1::CredentialBridgeStreamCredit {
                request_id: Uuid::new_v4().to_string(),
                credit_bytes: 1024,
            },
        )),
    }
}

/// An admitted epoch whose broker issued `handle`.
async fn admitted_with(
    fixture: &mut Fixture,
    handle: [u8; 32],
) -> (CancellationToken, EpochTask, DaemonCall, BrokerCall) {
    *fixture.broker_handle.lock().unwrap() = Some(handle.to_vec());
    let (cancel, task) = fixture.epoch();
    let (daemon, broker) = admitted(fixture).await;
    (cancel, task, daemon, broker)
}

/// End `epochs` and then the fixture. The caller drops every stream it held
/// first: the synthetic servers drain theirs before they stop.
async fn finish(fixture: Fixture, epochs: Vec<(CancellationToken, EpochTask)>) {
    for (cancel, task) in epochs {
        cancel.cancel();
        bounded(task).await.unwrap().unwrap();
    }
    fixture.stop().await;
}

/// The binding's current epoch, once one has registered.
async fn current(fixture: &Fixture) -> mpsc::Sender<EpochRequest> {
    let key = key(fixture);
    bounded(async {
        loop {
            if let Some((_, epoch)) = front_doors(fixture).current(&key) {
                return epoch;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

/// Ask `epoch` for an upstream, as a session does.
fn ask(epoch: mpsc::Sender<EpochRequest>) -> tokio::task::JoinHandle<Result<Joined, Status>> {
    tokio::spawn(async move {
        let (reply, answer) = oneshot::channel();
        epoch
            .send(EpochRequest::Join(Join { reply }))
            .await
            .map_err(|_| Status::unavailable("no epoch"))?;
        answer.await.map_err(|_| Status::unavailable("no epoch"))?
    })
}

/// The broker's next `FrontDoorBridge`, answered.
async fn broker_answers(
    fixture: &mut Fixture,
    answer: Result<Vec<&'static str>, Status>,
) -> FrontDoorCall {
    let mut call = bounded(fixture.front_door_calls.recv()).await.unwrap();
    let reply = std::mem::replace(&mut call.answer, oneshot::channel().0);
    reply.send(answer).unwrap();
    call
}

/// An upstream joined to the current epoch.
async fn join_upstream(fixture: &mut Fixture) -> (Joined, FrontDoorCall) {
    let asked = ask(current(fixture).await);
    let call = broker_answers(fixture, Ok(front_door_capabilities())).await;
    (bounded(asked).await.unwrap().unwrap(), call)
}

/// Whether the broker's side of an upstream ended within `wait`.
async fn ended(call: &mut FrontDoorCall, wait: Duration) -> bool {
    matches!(
        tokio::time::timeout(wait, call.input.message()).await,
        Ok(Ok(None) | Err(_))
    )
}

#[tokio::test]
async fn an_upstream_opens_with_the_epochs_credentials_handle_and_binding_ready() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (joined, call) = join_upstream(&mut fixture).await;
    assert_eq!(call.relay, "Bearer synthetic.relay.one");
    assert_eq!(call.workspace, WORKSPACE_TOKEN.as_bytes());
    assert_eq!(call.handle.as_deref(), Some(&HANDLE[..]));
    assert_eq!(
        call.ready,
        v1::CredentialBridgeReady {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: fixture.config.environment_id.to_string(),
            environment_generation: 7,
        },
        "the binding's Ready, read before the broker answered"
    );
    assert_eq!(joined.capabilities, front_door_capabilities());
    drop((daemon, broker, call, joined));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn messages_cross_an_upstream_unchanged_both_ways() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (mut joined, mut call) = join_upstream(&mut fixture).await;
    let guest = guest_cancel();
    joined.guest.send(guest.encode_to_vec()).await.unwrap();
    assert_eq!(bounded(call.input.message()).await.unwrap().unwrap(), guest);
    let host = credit();
    call.output.send(Ok(host.clone())).await.unwrap();
    assert_eq!(
        bounded(joined.host.next()).await.unwrap().unwrap(),
        host.encode_to_vec()
    );
    drop((daemon, broker, joined, call));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn the_epoch_handle_never_reaches_the_daemon() {
    let mut fixture = Fixture::new().await;
    *fixture.broker_handle.lock().unwrap() = Some(HANDLE.to_vec());
    let (cancel, task) = fixture.epoch();
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let mut broker = bounded(fixture.broker_calls.recv()).await.unwrap();
    std::mem::replace(&mut broker.accept, oneshot::channel().0)
        .send(Ok(()))
        .unwrap();
    let open = bounded(daemon.input.message()).await.unwrap().unwrap();
    assert!(matches!(
        open.payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    // Registered, so the handle was read and kept.
    current(&fixture).await;
    let contains = |bytes: &[u8]| bytes.windows(HANDLE.len()).any(|window| window == HANDLE);
    assert!(!contains(&open.encode_to_vec()), "not in the daemon's Open");
    assert!(
        daemon
            .metadata
            .get_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
            .is_none()
    );
    for entry in daemon.metadata.iter() {
        let value = match entry {
            tonic::metadata::KeyAndValueRef::Ascii(_, value) => value.as_bytes().to_vec(),
            tonic::metadata::KeyAndValueRef::Binary(_, value) => value.to_bytes().unwrap().to_vec(),
        };
        assert!(!contains(&value), "not in the daemon's metadata");
    }
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_join_after_the_successor_is_admitted_reaches_the_successor() {
    let mut fixture = Fixture::new().await;
    let (first_cancel, first, first_daemon, first_broker) =
        admitted_with(&mut fixture, HANDLE).await;
    current(&fixture).await;
    let first_id = front_doors(&fixture).current(&key(&fixture)).unwrap().0;
    // The successor is admitted while the first epoch still drains.
    let (second_cancel, second, second_daemon, second_broker) =
        admitted_with(&mut fixture, SUCCESSOR_HANDLE).await;
    let key = key(&fixture);
    bounded(async {
        while front_doors(&fixture).current(&key).unwrap().0 == first_id {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    for _ in 0..3 {
        let (joined, call) = join_upstream(&mut fixture).await;
        assert_eq!(call.handle.as_deref(), Some(&SUCCESSOR_HANDLE[..]));
        drop((joined, call));
    }
    // The successor ending leaves no joinable epoch: the draining one never
    // takes a join again.
    second_cancel.cancel();
    bounded(second).await.unwrap().unwrap();
    assert!(!first.is_finished());
    assert!(front_doors(&fixture).current(&key).is_none());
    drop((first_daemon, first_broker, second_daemon, second_broker));
    finish(fixture, vec![(first_cancel, first)]).await;
}

#[tokio::test]
async fn an_upstream_ends_with_its_epoch() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (mut joined, mut call) = join_upstream(&mut fixture).await;
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    assert!(front_doors(&fixture).current(&key(&fixture)).is_none());
    assert!(ended(&mut call, Duration::from_secs(5)).await);
    while let Some(message) = bounded(joined.host.next()).await {
        assert!(message.is_ok(), "{message:?}");
    }
    drop((daemon, broker, joined, call));
    fixture.stop().await;
}

#[tokio::test]
async fn a_broker_that_issues_no_handle_takes_no_join() {
    let mut fixture = Fixture::new().await;
    let (cancel, task) = fixture.epoch();
    let (daemon, broker) = admitted(&mut fixture).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    assert!(front_doors(&fixture).current(&key(&fixture)).is_none());
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_dropped_upstream_ends_its_broker_stream_and_the_epoch_serves_on() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (joined, mut call) = join_upstream(&mut fixture).await;
    drop(joined);
    assert!(ended(&mut call, Duration::from_secs(5)).await);
    assert!(!task.is_finished(), "loopback keeps serving");
    let next = join_upstream(&mut fixture).await;
    drop((daemon, broker, call, next));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_brokers_refusal_reaches_the_session_by_its_code_alone() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    for (answer, code) in [
        (
            Err(Status::already_exists("broker detail")),
            tonic::Code::AlreadyExists,
        ),
        (
            Err(Status::permission_denied("broker detail")),
            tonic::Code::PermissionDenied,
        ),
        (
            Err(Status::internal("broker detail")),
            tonic::Code::Unavailable,
        ),
        // A stream that does not serve front-door sessions is not joined.
        (Ok(Vec::new()), tonic::Code::Unavailable),
    ] {
        let asked = ask(current(&fixture).await);
        broker_answers(&mut fixture, answer).await;
        let Err(status) = bounded(asked).await.unwrap() else {
            panic!("refused");
        };
        assert_eq!(status.code(), code);
        assert!(!status.message().contains("broker detail"));
    }
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_broker_that_fails_mid_stream_ends_the_upstream_cleanly() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (mut joined, call) = join_upstream(&mut fixture).await;
    drop(call);
    while let Some(message) = bounded(joined.host.next()).await {
        assert!(message.is_ok(), "{message:?}");
    }
    bounded(async {
        while !joined.guest.is_closed() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(!task.is_finished());
    drop((daemon, broker, joined));
    finish(fixture, vec![(cancel, task)]).await;
}

/// Ask `epoch` to sign `key`, as `SignInterceptionLeaves` does.
fn ask_to_sign(
    epoch: mpsc::Sender<EpochRequest>,
    key: &[u8],
) -> tokio::task::JoinHandle<Result<SignInterceptionLeavesResponse, Status>> {
    let leaf_public_key = key.to_vec();
    tokio::spawn(async move {
        let (reply, answer) = oneshot::channel();
        epoch
            .send(EpochRequest::Sign(Sign {
                leaf_public_key,
                reply,
            }))
            .await
            .map_err(|_| Status::unavailable("no epoch"))?;
        answer.await.map_err(|_| Status::unavailable("no epoch"))?
    })
}

#[tokio::test]
async fn leaves_are_signed_with_the_epochs_credentials_and_handle() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let asked = ask_to_sign(current(&fixture).await, b"front-door-key");
    let call = bounded(fixture.sign_calls.recv()).await.unwrap();
    assert_eq!(call.relay, "Bearer synthetic.relay.one");
    assert_eq!(call.workspace, WORKSPACE_TOKEN.as_bytes());
    assert_eq!(call.handle.as_deref(), Some(&HANDLE[..]));
    assert_eq!(call.leaf_public_key, b"front-door-key");
    let leaves = SignInterceptionLeavesResponse {
        leaves: vec![InterceptionLeaf {
            certificate_der: vec![1, 2, 3],
            hosts: vec!["api.anthropic.com".into()],
        }],
        renew_at_unix: 1_900_000_000,
    };
    call.answer.send(Ok(leaves.clone())).unwrap();
    assert_eq!(bounded(asked).await.unwrap().unwrap(), leaves);
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_signing_refusal_reaches_the_caller_by_code_alone() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    for (answer, code) in [
        (
            Status::permission_denied("broker detail"),
            tonic::Code::PermissionDenied,
        ),
        (
            Status::invalid_argument("broker detail"),
            tonic::Code::InvalidArgument,
        ),
        (
            Status::unavailable("broker detail"),
            tonic::Code::Unavailable,
        ),
        (Status::internal("broker detail"), tonic::Code::Unavailable),
    ] {
        let asked = ask_to_sign(current(&fixture).await, b"front-door-key");
        let call = bounded(fixture.sign_calls.recv()).await.unwrap();
        call.answer.send(Err(answer)).unwrap();
        let Err(status) = bounded(asked).await.unwrap() else {
            panic!("refused");
        };
        assert_eq!(status.code(), code);
        assert!(!status.message().contains("broker detail"));
    }
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}
