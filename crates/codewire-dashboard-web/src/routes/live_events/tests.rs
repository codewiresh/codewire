use codewire_proto::codewire::console::v1::{
    CreditChanged, LiveHeartbeat, ResizeChanged, SandboxChanged,
};

use super::*;

fn response(event: Event) -> WatchResponse {
    WatchResponse {
        event: Some(event),
        ..Default::default()
    }
}

fn resync() -> WatchResponse {
    response(Event::Resync(Box::default()))
}

fn sandbox(org: &str, environment: &str) -> WatchResponse {
    response(Event::Sandbox(Box::new(SandboxChanged {
        org_id: org.into(),
        environment_id: environment.into(),
        ..Default::default()
    })))
}

fn text(frame: Option<Bytes>) -> String {
    String::from_utf8(frame.expect("a frame").to_vec()).unwrap()
}

#[test]
fn each_event_is_one_frame_of_ids_named_by_its_kind() {
    assert_eq!(text(frame(&resync())), "event: resync\ndata: {}\n\n");
    assert_eq!(
        text(frame(&sandbox("org_a", "env_1"))),
        "event: sandbox\ndata: {\"environment\":\"env_1\",\"organization\":\"org_a\"}\n\n"
    );
    assert_eq!(
        text(frame(&response(Event::Resize(Box::new(ResizeChanged {
            org_id: "org_a".into(),
            environment_id: "env_1".into(),
            ..Default::default()
        }))))),
        "event: resize\ndata: {\"environment\":\"env_1\",\"organization\":\"org_a\"}\n\n"
    );
    assert_eq!(
        text(frame(&response(Event::Credit(Box::new(CreditChanged {
            org_id: "org_a".into(),
            ..Default::default()
        }))))),
        "event: credit\ndata: {\"organization\":\"org_a\"}\n\n"
    );
    // A heartbeat is a comment, which EventSource never dispatches.
    assert_eq!(
        text(frame(&response(Event::Heartbeat(
            Box::<LiveHeartbeat>::default()
        )))),
        ": heartbeat\n\n"
    );
    // A kind this page doesn't know yet is skipped, not an error.
    assert!(frame(&WatchResponse::default()).is_none());
}

/// Relays `script` after `first` and returns every frame sent.
async fn relayed(
    first: WatchResponse,
    script: Vec<Result<WatchResponse, ConnectError>>,
) -> Vec<String> {
    let (events, receiver) = mpsc::channel(16);
    for event in script {
        events.send(event).await.unwrap();
    }
    drop(events);
    let (frames, mut out) = mpsc::channel(16);
    relay(first, receiver, frames).await;
    let mut sent = Vec::new();
    while let Some(frame) = out.recv().await {
        sent.push(String::from_utf8(frame.to_vec()).unwrap());
    }
    sent
}

#[tokio::test]
async fn the_relay_sends_events_in_order_and_ends_with_the_watch() {
    let sent = relayed(
        resync(),
        vec![
            Ok(sandbox("org_a", "env_1")),
            Ok(WatchResponse::default()),
            Ok(sandbox("org_a", "env_2")),
        ],
    )
    .await;
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(sent[0].starts_with("event: resync"));
    assert!(sent[1].contains("env_1"));
    assert!(sent[2].contains("env_2"));
}

#[tokio::test]
async fn over_the_accounts_watch_limit_the_page_is_told_busy() {
    let sent = relayed(
        resync(),
        vec![Err(ConnectError::new(
            ErrorCode::ResourceExhausted,
            "too many live watches",
        ))],
    )
    .await;
    assert_eq!(sent, ["event: resync\ndata: {}\n\n", BUSY_FRAME]);
    // Any other failure just ends the stream; EventSource reconnects.
    let sent = relayed(resync(), vec![Err(ConnectError::unavailable("synthetic"))]).await;
    assert_eq!(sent, ["event: resync\ndata: {}\n\n"]);
}

#[tokio::test]
async fn the_relay_stops_when_the_browser_leaves() {
    let (events, receiver) = mpsc::channel(16);
    let (frames, out) = mpsc::channel(16);
    drop(out);
    // The watch never ends by itself; the relay still returns.
    tokio::time::timeout(Duration::from_secs(5), relay(resync(), receiver, frames))
        .await
        .expect("the relay ends when its reader is gone");
    drop(events);
}

#[test]
fn a_refused_watch_is_a_status_eventsource_does_not_retry() {
    assert_eq!(
        refusal(&ConnectError::new(ErrorCode::Unauthenticated, "")),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refusal(&ConnectError::new(ErrorCode::PermissionDenied, "")),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        refusal(&ConnectError::unavailable("")),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
