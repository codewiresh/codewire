//! A joined front-door session ends after 120 seconds with no request, open
//! socket or pending handshake, and nothing received; nothing else ever ends
//! for idleness (#4963). And a request is refused alike on either entry of
//! one broker.

use std::time::Duration;

use super::*;

const IDLE: Duration = Duration::from_secs(120);

/// A runner serving a loopback session and the front-door sessions that
/// join it, with the hosted idle bound.
struct Joined {
    environment_id: Uuid,
    joins: mpsc::Sender<AdmittedCredentialBridge<FrontDoorTransport>>,
    runner: tokio::task::JoinHandle<Result<(), BrokerBridgeError>>,
    _loopback_input: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    _loopback_output: mpsc::Receiver<Payload>,
}

impl Joined {
    async fn start(recorded: &Recorded) -> Self {
        let environment_id = Uuid::new_v4();
        let (loopback, loopback_input, loopback_output) = loopback_session(environment_id).await;
        let (joins, joining) = mpsc::channel(1);
        // A front door is served only beside placeholder logins (#4001).
        let broker = recorded.broker().paired_with_front_door();
        let runner = tokio::spawn(async move {
            run_admitted_credential_bridge_with_front_doors(broker, loopback, joining, Some(IDLE))
                .await
        });
        Self {
            environment_id,
            joins,
            runner,
            _loopback_input: loopback_input,
            _loopback_output: loopback_output,
        }
    }

    async fn join(
        &self,
    ) -> (
        CredentialBridge,
        tokio::task::JoinHandle<Result<(), FrontDoorSessionError>>,
    ) {
        let (guest, task, session) = front_door_pair(self.environment_id).await;
        self.joins.send(session).await.unwrap();
        (guest, task)
    }
}

fn recorded() -> Recorded {
    Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    }
}

async fn served(guest: &CredentialBridge) -> StatusCode {
    guest
        .respond_intercepted("api.anthropic.com", intercepted_anthropic_request())
        .await
        .status()
}

#[tokio::test(start_paused = true)]
async fn an_idle_joined_front_door_ends_and_the_next_one_joins() {
    let recorded = recorded();
    let joined = Joined::start(&recorded).await;
    let (guest, task) = joined.join().await;
    assert_eq!(served(&guest).await, StatusCode::OK);

    tokio::time::sleep(IDLE - Duration::from_secs(1)).await;
    assert!(!task.is_finished(), "not before the bound");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("it ended")
            .unwrap(),
        Ok(()),
        "it ended as its front door closing would"
    );
    assert!(!joined.runner.is_finished(), "loopback keeps serving");

    let (next, _next_task) = joined.join().await;
    assert_eq!(served(&next).await, StatusCode::OK, "the next one joins");
}

#[tokio::test(start_paused = true)]
async fn a_request_in_flight_keeps_a_joined_front_door_open() {
    let hold = Arc::new(tokio::sync::Notify::new());
    let recorded = Recorded {
        hold: Some(Arc::clone(&hold)),
        ..recorded()
    };
    let joined = Joined::start(&recorded).await;
    let (guest, task) = joined.join().await;
    let request = tokio::spawn(async move {
        let status = served(&guest).await;
        (guest, status)
    });

    // Past the idle bound, within the request's own bounds.
    tokio::time::sleep(IDLE + Duration::from_secs(60)).await;
    assert!(!task.is_finished(), "a request in flight is not idle");
    hold.notify_one();
    let (_guest, status) = request.await.unwrap();
    assert_eq!(status, StatusCode::OK);

    // Idle from its completion.
    tokio::time::sleep(IDLE + Duration::from_secs(1)).await;
    assert!(task.is_finished());
}

#[tokio::test(start_paused = true)]
async fn an_open_socket_keeps_a_joined_front_door_open() {
    use tokio::io::AsyncWriteExt as _;

    let recorded = Recorded {
        codex_sign_in: true,
        ..recorded()
    };
    let joined = Joined::start(&recorded).await;
    let (guest, task) = joined.join().await;
    let request = http::Request::get("/v1/backend-api/codex/responses")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "test-nonce")
        .header("sec-websocket-version", "13")
        .header("authorization", format!("Bearer {OURS}"))
        .body(())
        .unwrap();
    let codewire_credential_bridge::UpgradeAnswer::Switched { mut socket, .. } =
        guest.upgrade_intercepted("chatgpt.com", request).await
    else {
        panic!("the front door's handshake switches");
    };
    let provider = recorded.sockets.lock().unwrap().pop().unwrap();

    // A socket is in flight however long it is quiet.
    tokio::time::sleep(IDLE + Duration::from_secs(60)).await;
    assert!(!task.is_finished(), "an open socket is not idle");

    // Once it ends, the session idles out from then.
    socket.shutdown().await.unwrap();
    drop(socket);
    drop(provider);
    tokio::time::sleep(IDLE + Duration::from_secs(1)).await;
    assert!(task.is_finished(), "idle once the socket has ended");
}

#[tokio::test(start_paused = true)]
async fn traffic_before_the_bound_pushes_the_end_back() {
    let recorded = recorded();
    let joined = Joined::start(&recorded).await;
    let (guest, task) = joined.join().await;
    for _ in 0..3 {
        tokio::time::sleep(IDLE - Duration::from_secs(20)).await;
        assert_eq!(served(&guest).await, StatusCode::OK);
        assert!(!task.is_finished());
    }
    tokio::time::sleep(IDLE + Duration::from_secs(1)).await;
    assert!(task.is_finished());
}

#[tokio::test(start_paused = true)]
async fn loopback_and_a_local_front_door_never_end_for_idleness() {
    // A local front door cannot open another session.
    let recorded = recorded();
    let mut local = TwoSessions::start(&recorded).await;
    // Loopback beside a joined front door.
    let joined = Joined::start(&recorded).await;
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(
        !local.guest_task.is_finished(),
        "the local front door serves"
    );
    assert!(!local.runner.is_finished());
    assert!(!joined.runner.is_finished(), "loopback serves");
    assert_eq!(served(&local.guest).await, StatusCode::OK);
    assert!(local.loopback_request().await.iter().any(|frame| matches!(
        frame,
        Payload::ResponseStart(start) if start.status_code == 200
    )));
}

#[tokio::test]
async fn a_request_refused_on_loopback_is_refused_alike_on_a_front_door() {
    let recorded = Recorded {
        denied: Some("anthropic"),
        ..recorded()
    };
    let mut sessions = TwoSessions::start(&recorded).await;
    sessions
        .loopback_input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                cases()[2].request(""),
            )),
        })
        .await
        .unwrap();
    // Loopback: the broker's own refusal frame, denied.
    let loopback = loop {
        match sessions.loopback_output.recv().await.unwrap() {
            Payload::ResponseFailure(failure) => break Some(failure.reason),
            Payload::ResponseStart(_) | Payload::ResponseEnd(_) => break None,
            _ => {}
        }
    };
    assert_eq!(
        loopback,
        Some(v1::CredentialBridgeFailureReason::Denied as i32),
        "refused on loopback"
    );
    // The front door: the same decision, which its guest answers as 403.
    let response = sessions
        .guest
        .respond_intercepted("api.anthropic.com", intercepted_anthropic_request())
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "refused alike");
    assert_eq!(recorded.leases(), 2, "both asked the one decision");
    assert!(
        recorded.outbound().is_empty(),
        "nothing reached the provider"
    );
}
