//! A session launched with `end_after_detached_seconds` ends once no client
//! has been attached for that long (#3827), against a real session engine and
//! PTY processes. Clients attach through `run_attach_session`, the one place
//! every attachment passes, and once through the daemon's gRPC stream.

use std::time::{Duration, Instant};

use codewire_daemon_proto::daemon::v1;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, sleep_until, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::run_attach_session;
use super::tests::{attach_engine, authenticated_client, spawn_daemon};
use crate::durable_session::SessionEngine;

fn shell(end_after_detached_seconds: u32) -> v1::LaunchSessionRequest {
    v1::LaunchSessionRequest {
        command: vec!["sh".into(), "-c".into(), "exec sleep 60".into()],
        pty: true,
        term: "xterm-256color".into(),
        width: 80,
        height: 24,
        end_after_detached_seconds,
        ..Default::default()
    }
}

/// One client attachment, served as the daemon serves every one.
struct Client {
    input: mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
    _output: mpsc::Receiver<Result<v1::SessionAttachMessage, Status>>,
    owner: JoinHandle<()>,
}

impl Client {
    async fn attach(engine: &SessionEngine, session_id: &str) -> Self {
        let (input, incoming) = mpsc::channel(8);
        let (tx, mut output) = mpsc::channel(32);
        let owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session_id.into(),
                output_offset: 0,
                ..Default::default()
            },
            tx,
        ));
        // The attachment counts itself before it sends anything, so its
        // first message proves it is counted.
        timeout(Duration::from_secs(5), output.recv())
            .await
            .expect("the attachment answers")
            .expect("the attachment is open")
            .expect("the attachment is admitted");
        Self {
            input,
            _output: output,
            owner,
        }
    }

    /// The client says it is detaching.
    async fn detach(self, session_id: &str) {
        self.input
            .send(Ok(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Detach(
                    v1::DetachSessionRequest {
                        session_id: session_id.into(),
                    },
                )),
            }))
            .await
            .unwrap();
        timeout(Duration::from_secs(5), self.owner)
            .await
            .expect("detach ends the attachment")
            .unwrap();
    }

    /// The client's connection is lost without a word.
    async fn disconnect(self) {
        drop(self.input);
        timeout(Duration::from_secs(5), self.owner)
            .await
            .expect("a lost client ends its attachment")
            .unwrap();
    }
}

async fn state(engine: &SessionEngine, session_id: &str) -> v1::SessionLifecycleState {
    v1::SessionLifecycleState::try_from(engine.get(session_id).await.unwrap().state).unwrap()
}

async fn wait_ended(engine: &SessionEngine, session_id: &str) -> v1::SessionRecord {
    timeout(Duration::from_secs(15), async {
        loop {
            let record = engine.get(session_id).await.unwrap();
            if !super::is_attached_session_live(record.state) {
                return record;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the session ended")
}

/// A shell whose client never attached does not run forever; one launched
/// without the setting is untouched, attached to or not.
#[tokio::test]
async fn a_session_nobody_attaches_to_ends_after_its_grace_and_says_why() {
    let (_temp, engine) = attach_engine();
    let launched = Instant::now();
    let ending = engine.launch(shell(1)).await.unwrap();
    assert_eq!(ending.end_after_detached_seconds, 1);
    let durable = engine.launch(shell(0)).await.unwrap();
    Client::attach(&engine, &durable.session_id)
        .await
        .detach(&durable.session_id)
        .await;

    let ended = wait_ended(&engine, &ending.session_id).await;
    assert!(launched.elapsed() >= Duration::from_secs(1));
    assert_eq!(ended.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(ended.status_message, "ended: no client for 1 second");
    assert_eq!(ended.end_after_detached_seconds, 1);

    assert_eq!(
        state(&engine, &durable.session_id).await,
        v1::SessionLifecycleState::Running
    );
    assert_eq!(engine.unattended_timer(&durable.session_id), None);
    engine.stop(&durable.session_id).await.unwrap();
}

/// An attached client holds the session past its grace. The timer starts at
/// the last detach, a reattachment cancels it, and the next last detach, here
/// a lost connection, gets a whole new grace.
#[tokio::test]
async fn an_attachment_holds_the_session_and_each_last_detach_starts_a_whole_grace() {
    const GRACE: Duration = Duration::from_secs(2);
    let (_temp, engine) = attach_engine();
    let session = engine.launch(shell(2)).await.unwrap();
    let id = session.session_id.as_str();

    let first = Client::attach(&engine, id).await;
    sleep(GRACE + Duration::from_secs(1)).await;
    assert_eq!(state(&engine, id).await, v1::SessionLifecycleState::Running);

    first.detach(id).await;
    let detached = tokio::time::Instant::now();
    sleep(GRACE / 2).await;
    let second = Client::attach(&engine, id).await;
    sleep_until(detached + GRACE + Duration::from_secs(1)).await;
    assert_eq!(state(&engine, id).await, v1::SessionLifecycleState::Running);

    second.disconnect().await;
    let lost = Instant::now();
    let ended = wait_ended(&engine, id).await;
    assert!(lost.elapsed() >= GRACE, "{:?}", lost.elapsed());
    assert_eq!(ended.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(ended.status_message, "ended: no client for 2 seconds");
}

/// The timer has run out but its expiry waits for the session's operation
/// lock, as it does behind a stop or restart in progress, while a client
/// attaches. The expiry then finds a client and leaves the session running.
/// With nobody attached, the timer the last detach armed ends it, and the
/// stale one never does.
#[tokio::test]
async fn expiry_racing_a_reattachment_never_ends_the_attached_session() {
    let (_temp, engine) = attach_engine();
    let session = engine.launch(shell(3600)).await.unwrap();
    let id = session.session_id.clone();
    let armed = engine.unattended_timer(&id).expect("launch arms the timer");

    let (held_tx, held) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let holder = tokio::spawn({
        let (engine, id) = (engine.clone(), id.clone());
        async move {
            engine
                .hold_test_operation_lock(&id, held_tx, release_rx)
                .await
        }
    });
    held.await.unwrap();
    let mut expiry = Box::pin(engine.expire_unattended(&id, armed));
    assert!(
        timeout(Duration::from_millis(50), &mut expiry)
            .await
            .is_err(),
        "the expiry waits for the operation lock"
    );
    let client = Client::attach(&engine, &id).await;
    assert_eq!(engine.unattended_timer(&id), None, "attaching cancels it");
    release.send(()).unwrap();
    timeout(Duration::from_secs(5), expiry)
        .await
        .expect("the expiry settles");
    holder.await.unwrap();
    assert_eq!(
        state(&engine, &id).await,
        v1::SessionLifecycleState::Running
    );
    assert!(!client.owner.is_finished(), "the client is still attached");

    client.detach(&id).await;
    let rearmed = engine
        .unattended_timer(&id)
        .expect("the last detach arms a new timer");
    assert_ne!(rearmed, armed);
    engine.expire_unattended(&id, armed).await;
    assert_eq!(
        state(&engine, &id).await,
        v1::SessionLifecycleState::Running
    );
    engine.expire_unattended(&id, rearmed).await;
    let ended = engine.get(&id).await.unwrap();
    assert_eq!(ended.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(ended.status_message, "ended: no client for 1 hour");
}

/// A restart arms a new timer that retires the old one; an expiry after an
/// explicit stop finds nothing live and leaves the stop's own status; once
/// the daemon is shutting down no expiry acts.
#[tokio::test]
async fn restart_stop_and_shutdown_leave_no_stale_expiry_to_end_a_session() {
    let (_temp, engine) = attach_engine();
    let session = engine.launch(shell(3600)).await.unwrap();
    let id = session.session_id.as_str();
    let at_launch = engine.unattended_timer(id).unwrap();

    let restarted = engine.restart(id).await.unwrap();
    assert_eq!(restarted.state, v1::SessionLifecycleState::Running as i32);
    assert_eq!(restarted.end_after_detached_seconds, 3600);
    let at_restart = engine.unattended_timer(id).expect("restart arms a timer");
    assert_ne!(at_restart, at_launch);
    engine.expire_unattended(id, at_launch).await;
    assert_eq!(state(&engine, id).await, v1::SessionLifecycleState::Running);

    let stopped = engine.stop(id).await.unwrap();
    assert_eq!(stopped.status_message, "session stopped");
    engine.expire_unattended(id, at_restart).await;
    let after = engine.get(id).await.unwrap();
    assert_eq!(after.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(after.status_message, "session stopped");

    let other = engine.launch(shell(3600)).await.unwrap();
    let armed = engine.unattended_timer(&other.session_id).unwrap();
    engine.cancel_launches();
    engine.expire_unattended(&other.session_id, armed).await;
    assert_eq!(
        state(&engine, &other.session_id).await,
        v1::SessionLifecycleState::Running
    );
}

/// Over the daemon's own API: the launch setting is kept on the record, the
/// capability is advertised, a value past the bound is refused, and an
/// attach stream counts as a client until it closes.
#[tokio::test]
async fn the_daemon_api_keeps_the_setting_and_its_attach_stream_counts_as_a_client() {
    let (_temp, addr, shutdown) = spawn_daemon().await;
    let mut client = authenticated_client(addr).await;
    let capabilities = client
        .get_capabilities(v1::GetCapabilitiesRequest {
            protocol_version: codewire_daemon_proto::DAEMON_PROTOCOL_VERSION,
            required_capabilities: vec![
                codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_END_AFTER_DETACHED.into(),
            ],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(capabilities.state, v1::DaemonState::Ready as i32);

    let refused = client
        .launch_session(shell(
            codewire_daemon_proto::SESSION_END_AFTER_DETACHED_MAX_SECONDS + 1,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);

    let session = client
        .launch_session(shell(1))
        .await
        .unwrap()
        .into_inner()
        .session
        .unwrap();
    assert_eq!(session.end_after_detached_seconds, 1);
    let (input, incoming) = mpsc::channel(4);
    input
        .send(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Attach(
                v1::AttachSessionRequest {
                    session_id: session.session_id.clone(),
                    output_offset: 0,
                    ..Default::default()
                },
            )),
        })
        .await
        .unwrap();
    let mut attached = client
        .attach_session(ReceiverStream::new(incoming))
        .await
        .unwrap()
        .into_inner();
    timeout(Duration::from_secs(5), attached.message())
        .await
        .expect("the attachment answers")
        .unwrap()
        .expect("the attachment is open");
    sleep(Duration::from_secs(2)).await;
    let get = |client: &mut super::tests::TestClient| {
        let request = v1::GetSessionRequest {
            session_id: session.session_id.clone(),
        };
        let mut client = client.clone();
        async move {
            client
                .get_session(request)
                .await
                .unwrap()
                .into_inner()
                .session
                .unwrap()
        }
    };
    assert_eq!(
        get(&mut client).await.state,
        v1::SessionLifecycleState::Running as i32,
        "an open attach stream holds the session past its grace"
    );

    drop((input, attached));
    let closed = Instant::now();
    let ended = timeout(Duration::from_secs(15), async {
        loop {
            let record = get(&mut client).await;
            if !super::is_attached_session_live(record.state) {
                return record;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the session ended after its stream closed");
    assert!(closed.elapsed() >= Duration::from_secs(1));
    assert_eq!(ended.status_message, "ended: no client for 1 second");
    let _ = shutdown.send(());
}
