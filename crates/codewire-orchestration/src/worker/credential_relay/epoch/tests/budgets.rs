//! The relay's byte and progress bounds over the generated RPCs: a broker
//! that stops reading back-pressures the daemon and ends the epoch, a frame
//! larger than a budget is never queued, and the relay starts a fresh epoch
//! after either.
use super::*;

const FRAME_BYTES: usize = 64 * 1024;
const LIMITS: Limits = Limits {
    stream: 4 * FRAME_BYTES + 1024,
    environment: 6 * FRAME_BYTES + 2048,
    stall: Duration::from_millis(500),
};

fn projection(bytes: usize) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(
            v1::credential_bridge_guest_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionRequest {
                    request_id: Uuid::new_v4().to_string(),
                    recipient_public_key: vec![7; bytes],
                    selection_sha256: vec![9; 32],
                    deadline_unix_ms: 123456,
                    local_inventories: Vec::new(),
                },
            ),
        ),
    }
}

/// Admit one epoch and return its daemon and broker ends after the Open.
pub(super) async fn admitted(fixture: &mut Fixture) -> (DaemonCall, BrokerCall) {
    let daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let mut broker = bounded(fixture.broker_calls.recv()).await.unwrap();
    let accept = std::mem::replace(&mut broker.accept, oneshot::channel().0);
    accept.send(Ok(())).unwrap();
    let mut daemon = daemon;
    assert!(matches!(
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    (daemon, broker)
}

#[tokio::test]
async fn a_broker_that_stops_reading_back_pressures_the_daemon_and_ends_the_epoch() {
    let mut fixture = Fixture::with_limits(LIMITS).await;
    let budget = fixture.config.budget.clone();
    let (_cancel, task) = fixture.epoch();
    // The broker admits the epoch and then never reads another frame.
    let (daemon, broker) = admitted(&mut fixture).await;
    let mut sent = 0_usize;
    let mut most_held = 0_usize;
    loop {
        match tokio::time::timeout(
            Duration::from_secs(2),
            daemon.output.send(Ok(projection(FRAME_BYTES))),
        )
        .await
        {
            Ok(Ok(())) => sent += 1,
            // The epoch ended and closed the daemon's stream, or the daemon
            // is back-pressured: either way it can send no more.
            Ok(Err(_)) | Err(_) => break,
        }
        most_held = most_held.max(LIMITS.environment - budget.available());
        assert!(sent < 1024, "the daemon was never back-pressured");
    }
    // The relay never held more than one stream's budget, whatever the
    // transport buffered around it.
    assert!(most_held <= LIMITS.stream, "held {most_held} bytes");
    assert!(sent > 0);
    // The stalled frame ended the epoch by itself, and its bytes came back.
    bounded(task).await.unwrap().unwrap();
    assert_eq!(budget.available(), LIMITS.environment);
    drop((daemon, broker));
    fixture.stop().await;
}

#[tokio::test]
async fn an_oversized_frame_is_never_queued_and_ends_the_epoch() {
    let mut fixture = Fixture::with_limits(LIMITS).await;
    let budget = fixture.config.budget.clone();
    let (_cancel, task) = fixture.epoch();
    let (daemon, mut broker) = admitted(&mut fixture).await;
    let small = projection(16);
    daemon.output.send(Ok(small.clone())).await.unwrap();
    assert_eq!(
        bounded(broker.input.message()).await.unwrap().unwrap(),
        small
    );
    daemon
        .output
        .send(Ok(projection(LIMITS.stream + 1)))
        .await
        .unwrap();
    bounded(task).await.unwrap().unwrap();
    // The broker saw the stream end, never the oversized frame.
    assert!(!matches!(
        bounded(broker.input.message()).await,
        Ok(Some(_))
    ));
    assert_eq!(budget.available(), LIMITS.environment);
    drop((daemon, broker));
    fixture.stop().await;
}

#[tokio::test]
async fn a_daemon_that_stops_reading_ends_the_epoch() {
    let mut fixture = Fixture::with_limits(LIMITS).await;
    let (_cancel, task) = fixture.epoch();
    // The daemon never reads its responses again.
    let (daemon, broker) = admitted(&mut fixture).await;
    let response = |index: usize| v1::CredentialBridgeHostMessage {
        payload: Some(
            v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionResponse {
                    request_id: format!("synthetic-{index}"),
                    result: Some(
                        v1::environment_projection_response::Result::SealedProjection(vec![
                            3;
                            FRAME_BYTES
                        ]),
                    ),
                },
            ),
        ),
    };
    for index in 0..1024 {
        match tokio::time::timeout(
            Duration::from_secs(2),
            broker.output.send(Ok(response(index))),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    // The relay waited for the daemon only the stall bound, then ended, and
    // severed the connection the daemon left undrained: what it never read
    // ends in an error rather than a clean end of its stream.
    bounded(task).await.unwrap().unwrap();
    let mut daemon = daemon;
    let mut unread = 0;
    let ended = loop {
        match bounded(daemon.input.message()).await {
            Ok(Some(_)) => unread += 1,
            ended => break ended,
        }
    };
    assert!(ended.is_err(), "the undrained daemon stream ended cleanly");
    assert!(unread < 1024);
    drop((daemon, broker));
    fixture.stop().await;
}

#[tokio::test]
async fn a_bounded_epoch_is_followed_by_a_fresh_one() {
    let mut fixture = Fixture::with_limits(LIMITS).await;
    let shutdown = CancellationToken::new();
    let relay = {
        let config = fixture.config.clone();
        let shutdown = shutdown.clone();
        let (_, admission) = watch::channel(true);
        tokio::spawn(async move { run(&config, admission, shutdown.cancelled()).await })
    };
    let (first_daemon, first_broker) = admitted(&mut fixture).await;
    first_daemon
        .output
        .send(Ok(projection(LIMITS.stream + 1)))
        .await
        .unwrap();
    // After the usual delay the relay prepares and admits a fresh epoch, with
    // freshly read tokens.
    let (second_daemon, second_broker) = admitted(&mut fixture).await;
    assert_eq!(second_broker.relay, "Bearer synthetic.relay.one");
    shutdown.cancel();
    bounded(relay).await.unwrap().unwrap();
    drop((first_daemon, first_broker, second_daemon, second_broker));
    fixture.stop().await;
}
