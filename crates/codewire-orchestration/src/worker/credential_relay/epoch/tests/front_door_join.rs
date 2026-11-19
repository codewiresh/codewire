//! Front-door sessions joining an admitted epoch (#4001): the broker stream
//! is opened with the epoch's own credentials and handle, which never reach
//! the daemon; frames cross unchanged; the newest admitted epoch takes new
//! sessions; and a bad frame or a stalled cw-egress ends only its session.
use super::budgets::admitted;
use super::*;
use crate::front_door::{self as registry, BindingKey, Join, Joined};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
};

const HANDLE: [u8; 32] = [7; 32];
const SUCCESSOR_HANDLE: [u8; 32] = [8; 32];
const STALL: Limits = Limits {
    stall: Duration::from_millis(300),
    ..Limits::DEFAULT
};

fn key(fixture: &Fixture) -> BindingKey {
    BindingKey {
        environment_id: fixture.config.environment_id,
        pod_uid: SYNTHETIC_POD_UID.into(),
        generation: 7,
    }
}

fn front_door_capabilities() -> Vec<&'static str> {
    vec![
        CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
        CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    ]
}

fn framed(message: &impl prost::Message) -> Vec<u8> {
    registry::framed(&message.encode_to_vec()).unwrap()
}

/// The Ready of the fixture's binding, as the relay writes it and the front
/// door must send it.
fn binding_ready(fixture: &Fixture) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
            v1::CredentialBridgeReady {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: fixture.config.environment_id.to_string(),
                environment_generation: 7,
            },
        )),
    }
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

type EpochTask = tokio::task::JoinHandle<Result<(), DrainFailure>>;

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
async fn current(fixture: &Fixture) -> mpsc::Sender<Join> {
    let key = key(fixture);
    bounded(async {
        loop {
            if let Some(epoch) = fixture.config.front_doors.as_ref().unwrap().current(&key) {
                return epoch;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

/// A session asking `epoch` to join, as `EgressService` asks.
struct Session {
    guest: mpsc::Sender<Result<Vec<u8>, Status>>,
    joined: tokio::task::JoinHandle<Result<Joined, Status>>,
}

fn ask(epoch: mpsc::Sender<Join>) -> Session {
    let (guest, frames) = mpsc::channel(4);
    let (reply, answer) = oneshot::channel();
    let joined = tokio::spawn(async move {
        let frames = Box::pin(ReceiverStream::new(frames));
        epoch
            .send(Join { frames, reply })
            .await
            .map_err(|_| Status::unavailable("no epoch"))?;
        answer.await.map_err(|_| Status::unavailable("no epoch"))?
    });
    Session { guest, joined }
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

/// A joined session, past the Open the relay writes for it.
async fn join_session(
    fixture: &mut Fixture,
) -> (mpsc::Sender<Result<Vec<u8>, Status>>, Joined, FrontDoorCall) {
    let session = ask(current(fixture).await);
    let call = broker_answers(fixture, Ok(front_door_capabilities())).await;
    let mut joined = bounded(session.joined).await.unwrap().unwrap();
    let open = bounded(joined.frames.next()).await.unwrap().unwrap();
    let open =
        v1::CredentialBridgeHostMessage::decode(registry::frame_message(&open).unwrap()).unwrap();
    assert!(matches!(
        open.payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    (session.guest, joined, call)
}

/// Whether the broker's side of a joined stream ended within `wait`.
async fn ended(call: &mut FrontDoorCall, wait: Duration) -> bool {
    matches!(
        tokio::time::timeout(wait, call.input.message()).await,
        Ok(Ok(None) | Err(_))
    )
}

#[tokio::test]
async fn a_session_reaches_the_broker_with_the_epochs_credentials_and_handle() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let session = ask(current(&fixture).await);
    let call = broker_answers(&mut fixture, Ok(front_door_capabilities())).await;
    assert_eq!(call.relay, "Bearer synthetic.relay.one");
    assert_eq!(call.workspace, WORKSPACE_TOKEN.as_bytes());
    assert_eq!(call.handle.as_deref(), Some(&HANDLE[..]));
    let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) =
        binding_ready(&fixture).payload
    else {
        unreachable!()
    };
    assert_eq!(call.ready, ready, "the binding's Ready, before any answer");

    // The Open lists exactly the stream's capabilities, for this binding.
    let mut joined = bounded(session.joined).await.unwrap().unwrap();
    let open = bounded(joined.frames.next()).await.unwrap().unwrap();
    let Some(v1::credential_bridge_host_message::Payload::Open(open)) =
        v1::CredentialBridgeHostMessage::decode(registry::frame_message(&open).unwrap())
            .unwrap()
            .payload
    else {
        panic!("the Open comes first");
    };
    assert_eq!(open.protocol_version, CREDENTIAL_BRIDGE_PROTOCOL_VERSION);
    assert_eq!(
        open.environment_id,
        fixture.config.environment_id.to_string()
    );
    assert_eq!(open.environment_generation, 7);
    assert_eq!(open.capabilities, front_door_capabilities());
    drop((daemon, broker, call, joined));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn frames_cross_a_joined_session_unchanged_both_ways() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (guest, mut joined, mut call) = join_session(&mut fixture).await;
    // The front door's Ready is checked and consumed, never forwarded.
    guest
        .send(Ok(framed(&binding_ready(&fixture))))
        .await
        .unwrap();
    let cancel_frame = guest_cancel();
    guest.send(Ok(framed(&cancel_frame))).await.unwrap();
    assert_eq!(
        bounded(call.input.message()).await.unwrap().unwrap(),
        cancel_frame
    );
    let host = credit();
    call.output.send(Ok(host.clone())).await.unwrap();
    assert_eq!(
        bounded(joined.frames.next()).await.unwrap().unwrap(),
        framed(&host)
    );
    drop((daemon, broker, guest, joined, call));
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
async fn a_session_opened_after_the_successor_is_admitted_joins_the_successor() {
    let mut fixture = Fixture::new().await;
    let (first_cancel, first, first_daemon, first_broker) =
        admitted_with(&mut fixture, HANDLE).await;
    current(&fixture).await;
    // The successor is admitted while the first epoch still drains.
    let (second_cancel, second, second_daemon, second_broker) =
        admitted_with(&mut fixture, SUCCESSOR_HANDLE).await;
    let key = key(&fixture);
    bounded(async {
        loop {
            let session = ask(fixture
                .config
                .front_doors
                .as_ref()
                .unwrap()
                .current(&key)
                .unwrap());
            let call = broker_answers(&mut fixture, Ok(front_door_capabilities())).await;
            drop(session);
            if call.handle.as_deref() == Some(&SUCCESSOR_HANDLE[..]) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    // Once it is current, every session goes to it, never to the first.
    for _ in 0..3 {
        let session = ask(current(&fixture).await);
        let call = broker_answers(&mut fixture, Ok(front_door_capabilities())).await;
        assert_eq!(call.handle.as_deref(), Some(&SUCCESSOR_HANDLE[..]));
        drop((session, call));
    }
    // The successor ending leaves no joinable epoch: the draining one never
    // takes a session again.
    second_cancel.cancel();
    bounded(second).await.unwrap().unwrap();
    assert!(!first.is_finished());
    assert!(
        fixture
            .config
            .front_doors
            .as_ref()
            .unwrap()
            .current(&key)
            .is_none()
    );
    drop((first_daemon, first_broker, second_daemon, second_broker));
    finish(fixture, vec![(first_cancel, first)]).await;
}

#[tokio::test]
async fn an_ended_epoch_takes_no_session() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (guest, mut joined, mut call) = join_session(&mut fixture).await;
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    assert!(
        fixture
            .config
            .front_doors
            .as_ref()
            .unwrap()
            .current(&key(&fixture))
            .is_none()
    );
    // Its joined session ended with it.
    assert!(ended(&mut call, Duration::from_secs(5)).await);
    while let Some(frame) = bounded(joined.frames.next()).await {
        assert!(frame.is_ok(), "{frame:?}");
    }
    drop((daemon, broker, guest, joined, call));
    fixture.stop().await;
}

#[tokio::test]
async fn a_broker_that_issues_no_handle_takes_no_session() {
    let mut fixture = Fixture::new().await;
    let (cancel, task) = fixture.epoch();
    let (daemon, broker) = admitted(&mut fixture).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    assert!(
        fixture
            .config
            .front_doors
            .as_ref()
            .unwrap()
            .current(&key(&fixture))
            .is_none()
    );
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_bad_frame_ends_only_its_session() {
    let max =
        u32::try_from(codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES).unwrap();
    let whole = framed(&credit());
    let mut over = (max + 1).to_be_bytes().to_vec();
    over.resize(4 + usize::try_from(max + 1).unwrap(), 0);
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    for (case, frame) in [
        ("a zero length", vec![0, 0, 0, 0]),
        ("the maximum plus one", over),
        ("half of a frame", whole[..whole.len() / 2].to_vec()),
    ] {
        let (guest, mut joined, mut call) = join_session(&mut fixture).await;
        guest.send(Ok(frame)).await.unwrap();
        let error = bounded(joined.frames.next()).await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{case}");
        assert!(bounded(joined.frames.next()).await.is_none(), "{case}");
        assert!(ended(&mut call, Duration::from_secs(5)).await, "{case}");
        // The epoch keeps serving loopback, and the next session joins.
        assert!(!task.is_finished(), "{case}");
        drop((guest, joined, call));
    }
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_cw_egress_that_takes_no_frame_ends_only_its_session() {
    let mut fixture = Fixture::with_limits(STALL).await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (guest, joined, mut call) = join_session(&mut fixture).await;
    guest
        .send(Ok(framed(&binding_ready(&fixture))))
        .await
        .unwrap();
    // Idle, and the broker sending nothing (a socket out of credit): no
    // stall, however long.
    assert!(!ended(&mut call, STALL.stall * 3).await);
    // cw-egress reads nothing more while the broker sends.
    for _ in 0..3 {
        if call.output.send(Ok(credit())).await.is_err() {
            break;
        }
    }
    assert!(ended(&mut call, STALL.stall * 10).await);
    assert!(!task.is_finished(), "loopback keeps serving");
    drop((guest, joined, call));
    // And the next session joins at once.
    let next = join_session(&mut fixture).await;
    drop((daemon, broker, next));
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
        let session = ask(current(&fixture).await);
        broker_answers(&mut fixture, answer).await;
        let Err(status) = bounded(session.joined).await.unwrap() else {
            panic!("refused");
        };
        assert_eq!(status.code(), code);
        assert!(!status.message().contains("broker detail"));
    }
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_broker_that_fails_mid_session_ends_it_cleanly() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (guest, mut joined, call) = join_session(&mut fixture).await;
    // The broker's stream fails under the session.
    drop(call);
    while let Some(frame) = bounded(joined.frames.next()).await {
        assert!(frame.is_ok(), "{frame:?}");
    }
    // The guest side is closed too, and loopback keeps serving.
    bounded(async {
        while !guest.is_closed() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(!task.is_finished());
    drop((daemon, broker, joined));
    finish(fixture, vec![(cancel, task)]).await;
}

/// A front door that opens with anything but its binding's Ready, byte for
/// byte, is ended before any frame reaches the broker.
#[tokio::test]
async fn a_front_door_must_open_with_its_bindings_ready() {
    let mut fixture = Fixture::new().await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let mut other_generation = binding_ready(&fixture);
    if let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) =
        &mut other_generation.payload
    {
        ready.environment_generation = 8;
    }
    for (case, first) in [
        ("another generation", framed(&other_generation)),
        ("a frame before Ready", framed(&guest_cancel())),
    ] {
        let (guest, mut joined, mut call) = join_session(&mut fixture).await;
        guest.send(Ok(first)).await.unwrap();
        let error = bounded(joined.frames.next()).await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{case}");
        assert!(ended(&mut call, Duration::from_secs(5)).await, "{case}");
        drop((guest, joined, call));
    }
    assert!(!task.is_finished());
    drop((daemon, broker));
    finish(fixture, vec![(cancel, task)]).await;
}

#[tokio::test]
async fn a_front_door_that_never_sends_ready_is_ended() {
    let mut fixture = Fixture::with_limits(STALL).await;
    let (cancel, task, daemon, broker) = admitted_with(&mut fixture, HANDLE).await;
    let (guest, mut joined, mut call) = join_session(&mut fixture).await;
    let error = bounded(joined.frames.next()).await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(ended(&mut call, Duration::from_secs(5)).await);
    drop((daemon, broker, guest, joined, call));
    finish(fixture, vec![(cancel, task)]).await;
}
