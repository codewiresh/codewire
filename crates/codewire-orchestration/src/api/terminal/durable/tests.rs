use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::HeaderValue;
use serde_json::{Value, json};
use tokio_stream::wrappers::ReceiverStream;

use super::*;

const SESSION: &str = "session-12345678-1234-1234-1234-123456789abc";
const ORIGIN: &str = "https://codewire-dev.sh";

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        header::COOKIE,
        format!("{SESSION_COOKIE_NAME}=synthetic-session")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(PROTOCOL),
    );
    headers
}

fn query() -> String {
    format!("account_id=synthetic-account&session_id={SESSION}&output_offset=0")
}

fn chunk(offset: u64, bytes: &[u8]) -> v1::SessionOutputChunk {
    v1::SessionOutputChunk {
        offset,
        next_offset: offset + bytes.len() as u64,
        // The real durable PTY writer emits Pty, not Stdout. Keep every
        // browser relay fixture on that wire contract.
        stream: v1::SessionOutputStream::Pty.into(),
        data: bytes.to_vec(),
    }
}

fn output(offset: u64, bytes: &[u8]) -> v1::SessionAttachMessage {
    v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Output(chunk(
            offset, bytes,
        ))),
    }
}

fn status(state: v1::SessionLifecycleState, offset: u64) -> v1::SessionAttachMessage {
    v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Status(
            v1::SessionStatus {
                session_id: SESSION.into(),
                state: state.into(),
                exit_code: (state == v1::SessionLifecycleState::Exited).then_some(0),
                output_end_offset: offset,
                output_start_offset: 0,
                message: "private daemon diagnostic must not reach browser".into(),
            },
        )),
    }
}

#[test]
fn shared_browser_contract_matches_server_limits_and_examples() {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/codewire-design/reference/contracts/durable-terminal-v1.json"
    )))
    .unwrap();
    assert_eq!(fixture["protocol"], PROTOCOL);
    assert_eq!(
        fixture["limits"],
        json!({
            "frameBytes": FRAME_BYTES, "inputBytes": INPUT_BYTES, "outputChunkBytes": CHUNK_BYTES,
            "unacknowledgedOutputBytes": WINDOW_BYTES, "unacknowledgedOutputFrames": WINDOW_FRAMES,
            "pendingInputFrames": INPUT_QUEUE_FRAMES, "pendingInputBytes": INPUT_QUEUE_BYTES,
        })
    );
    for example in fixture["client"].as_array().unwrap() {
        let frame: ClientFrame = serde_json::from_value(example.clone()).unwrap();
        if let ClientFrame::Ack { offset } = frame {
            assert!(cursor(&offset).is_some());
        }
    }
    for invalid in fixture["invalidOffsets"].as_array().unwrap() {
        assert_eq!(cursor(invalid.as_str().unwrap()), None);
    }
    assert_eq!(cursor("18446744073709551615"), Some(u64::MAX));
    let mut window = Window::new(0);
    assert_eq!(
        serde_json::to_value(window.output(chunk(0, b"hello\n")).unwrap()).unwrap(),
        fixture["server"][0]
    );
    assert_eq!(
        serde_json::to_value(ServerFrame::Status {
            state: "running",
            exit_code: None
        })
        .unwrap(),
        fixture["server"][1]
    );
    assert_eq!(
        serde_json::to_value(ServerFrame::Status {
            state: "exited",
            exit_code: Some(0)
        })
        .unwrap(),
        fixture["server"][2]
    );
    assert_eq!(
        serde_json::to_value(
            window
                .history_gap(v1::SessionOutputGap {
                    requested_offset: 6,
                    retained_start_offset: 4096
                })
                .unwrap()
        )
        .unwrap(),
        fixture["server"][3]
    );
    for state in fixture["states"].as_array().unwrap() {
        assert!(
            (1..=7)
                .filter_map(lifecycle)
                .any(|value| value == state.as_str().unwrap())
        );
    }
    assert_eq!(lifecycle(0), None);
    assert_eq!(lifecycle(999), None);
}

#[test]
fn durable_intent_cannot_downgrade_into_legacy_launch() {
    let headers = headers();
    let selected = coordinates(&headers, Some(&query())).unwrap().unwrap();
    assert_eq!(selected.session_id, SESSION);
    assert_eq!(selected.output_offset, 0);
    assert_eq!(selected.account_id, "synthetic-account");
    for invalid in [
        String::new(),
        format!("session_id={SESSION}"),
        "output_offset=0".into(),
        format!("{}&ticket=synthetic", query()),
        format!("{}&output_offset=1", query()),
        format!("{}&session_id={SESSION}", query()),
        format!("{}&account_id=other-account", query()),
        format!("account_id=&session_id={SESSION}&output_offset=0"),
        format!("account_id=bad%3Aaccount&session_id={SESSION}&output_offset=0"),
        format!("{}&unexpected=1", query()),
        format!("session_id={SESSION}&output_offset=01"),
        format!("session_id={}&output_offset=0", SESSION.to_uppercase()),
        "session_id=12345678123412341234123456789abc&output_offset=0".into(),
        format!("{}&{}", query(), "x".repeat(256)),
    ] {
        assert!(coordinates(&headers, Some(&invalid)).is_err(), "{invalid}");
    }
    for protocol in [
        None,
        Some("terminal"),
        Some("codewire.durable-terminal.v2"),
        Some("terminal, codewire.durable-terminal.v1"),
        Some("codewire.durable-terminal.v1, codewire.durable-terminal.v1"),
    ] {
        let mut changed = headers.clone();
        changed.remove(header::SEC_WEBSOCKET_PROTOCOL);
        if let Some(protocol) = protocol {
            changed.insert(header::SEC_WEBSOCKET_PROTOCOL, protocol.parse().unwrap());
        }
        assert!(coordinates(&changed, Some(&query())).is_err());
    }
    let mut duplicate = headers.clone();
    duplicate.append(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(PROTOCOL),
    );
    assert!(coordinates(&duplicate, Some(&query())).is_err());
    let mut legacy = HeaderMap::new();
    legacy.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("terminal"),
    );
    assert!(
        coordinates(&legacy, Some("ticket=existing-legacy-ticket"))
            .unwrap()
            .is_none()
    );
    assert!(coordinates(&legacy, None).unwrap().is_none());
    legacy.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("codewire.durable-terminal.v2"),
    );
    assert!(coordinates(&legacy, None).is_err());
}

#[test]
fn changed_authenticated_account_cannot_attach_a_saved_shell() {
    assert!(require_account("account-a", "account-a").is_ok());
    assert_eq!(
        require_account("account-a", "account-b"),
        Err(StatusCode::FORBIDDEN)
    );
    assert!(!valid_account_id(""));
    assert!(!valid_account_id(&"a".repeat(129)));
    assert!(!valid_account_id("account:other"));
    assert!(valid_account_id("account-0123_ABC"));
}

#[test]
fn browser_auth_requires_exact_single_origin_and_canonical_cookie_only() {
    let original = headers();
    assert_eq!(browser_cookie(&original, ORIGIN), Ok("synthetic-session"));
    for origin in [
        None,
        Some("null"),
        Some("http://codewire-dev.sh"),
        Some("https://codewire-dev.sh:444"),
        Some("https://codewire-dev.sh/"),
        Some("https://other.invalid"),
        Some("https://codewire-dev.sh https://other.invalid"),
    ] {
        let mut changed = original.clone();
        changed.remove(header::ORIGIN);
        changed.insert(
            header::REFERER,
            HeaderValue::from_static("https://codewire-dev.sh/"),
        );
        if let Some(origin) = origin {
            changed.insert(header::ORIGIN, origin.parse().unwrap());
        }
        assert!(browser_cookie(&changed, ORIGIN).is_err());
    }
    for configuration in [
        "*",
        "null",
        "https://codewire-dev.sh/",
        "https://codewire-dev.sh/path",
        "https://user@codewire-dev.sh",
        "https://codewire-dev.sh?query",
        "https://codewire-dev.sh#fragment",
    ] {
        assert!(browser_cookie(&original, configuration).is_err());
    }
    for name in [header::ORIGIN, header::COOKIE] {
        let mut changed = original.clone();
        changed.append(name.clone(), original[&name].clone());
        assert!(browser_cookie(&changed, ORIGIN).is_err());
    }
    let mut bearer = original.clone();
    bearer.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer synthetic"),
    );
    assert!(browser_cookie(&bearer, ORIGIN).is_err());
    for cookie in [
        "other=value".to_owned(),
        format!("{SESSION_COOKIE_NAME}="),
        format!("{SESSION_COOKIE_NAME}=a; {SESSION_COOKIE_NAME}=b"),
        format!("{SESSION_COOKIE_NAME} =a; {SESSION_COOKIE_NAME}=b"),
        format!("{SESSION_COOKIE_NAME}=a; {SESSION_COOKIE_NAME}"),
        format!("{SESSION_COOKIE_NAME}=a, {SESSION_COOKIE_NAME}=b"),
        format!("{SESSION_COOKIE_NAME}=\"quoted\""),
        format!("{SESSION_COOKIE_NAME}=a b"),
        format!("{SESSION_COOKIE_NAME}=a "),
        format!("{SESSION_COOKIE_NAME}={}", "a".repeat(4097)),
    ] {
        let mut changed = original.clone();
        changed.insert(header::COOKIE, cookie.parse().unwrap());
        assert!(browser_cookie(&changed, ORIGIN).is_err());
    }
    let mut local = original;
    local.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://127.0.0.1:8090"),
    );
    assert!(browser_cookie(&local, "http://127.0.0.1:8090").is_ok());
}

#[test]
fn output_window_is_byte_and_frame_bounded_and_acks_are_cumulative_boundaries() {
    let mut window = Window::new(0);
    for i in 0..8 {
        window
            .output(chunk(i * CHUNK_BYTES as u64, &vec![0; CHUNK_BYTES]))
            .unwrap();
    }
    assert!(!window.has_capacity());
    assert_eq!(window.output(chunk(WINDOW_BYTES, b"x")), Err(End::Invalid));
    assert_eq!(window.acknowledge("1"), Err(End::Invalid));
    assert_eq!(window.acknowledge("262145"), Err(End::Invalid));
    window.acknowledge("65536").unwrap();
    assert!(window.has_capacity());
    window.acknowledge("65536").unwrap();
    assert_eq!(window.acknowledge("32768"), Err(End::Invalid));
    assert_eq!(window.ends.len(), 6);
    let mut tiny = Window::new(0);
    for i in 0..WINDOW_FRAMES as u64 {
        tiny.output(chunk(i, b"x")).unwrap();
    }
    assert!(!tiny.has_capacity());
    tiny.acknowledge("64").unwrap();
    assert!(tiny.has_capacity());
    let mut irregular = Window::new(0);
    irregular.output(chunk(0, b"x")).unwrap();
    for i in 0..7 {
        irregular
            .output(chunk(1 + i * CHUNK_BYTES as u64, &vec![0; CHUNK_BYTES]))
            .unwrap();
    }
    assert!(!irregular.has_capacity());
    irregular.acknowledge("1").unwrap();
    irregular
        .output(chunk(1 + 7 * CHUNK_BYTES as u64, &vec![0; CHUNK_BYTES]))
        .unwrap();
    assert_eq!(irregular.issued - irregular.acknowledged, WINDOW_BYTES);
    let mut maximum = Window::new(u64::MAX - 1);
    maximum.output(chunk(u64::MAX - 1, b"x")).unwrap();
    maximum.acknowledge(&u64::MAX.to_string()).unwrap();
    assert_eq!(
        maximum.output(v1::SessionOutputChunk {
            offset: u64::MAX,
            next_offset: 0,
            data: vec![0],
            stream: 1
        }),
        Err(End::Invalid)
    );
}

#[test]
fn pty_replay_preserves_nonzero_byte_cursor_and_ack_boundary() {
    let bytes = b"\x1b[31m\xf0\x9f\x8c\x88\x1b[0m\r\n";
    let offset = 173;
    let next = offset + bytes.len() as u64;
    let mut window = Window::new(offset);
    assert_eq!(
        window.output(chunk(offset, bytes)),
        Ok(ServerFrame::Output {
            offset: offset.to_string(),
            next_offset: next.to_string(),
            data: STANDARD.encode(bytes),
        })
    );
    assert_eq!(
        window.acknowledge(&(next - 1).to_string()),
        Err(End::Invalid)
    );
    assert_eq!(window.acknowledge(&next.to_string()), Ok(()));
    assert_eq!(window.acknowledged, next);
    assert!(window.ends.is_empty());
}

#[test]
fn rejects_invalid_chunk_continuity_and_client_shapes() {
    // Admission requires a PTY record; pipe/unspecified/unknown streams are
    // not the output of that authorized interactive session.
    for stream in [
        v1::SessionOutputStream::Unspecified as i32,
        v1::SessionOutputStream::Stdout as i32,
        v1::SessionOutputStream::Stderr as i32,
        999,
    ] {
        assert_eq!(
            Window::new(0).output(v1::SessionOutputChunk {
                stream,
                ..chunk(0, b"x")
            }),
            Err(End::Invalid)
        );
    }
    for invalid in [
        chunk(1, b"x"),
        chunk(0, b""),
        chunk(0, &vec![0; CHUNK_BYTES + 1]),
        v1::SessionOutputChunk {
            next_offset: 3,
            ..chunk(0, b"x")
        },
        v1::SessionOutputChunk {
            stream: 0,
            ..chunk(0, b"x")
        },
    ] {
        assert_eq!(Window::new(0).output(invalid), Err(End::Invalid));
    }
    for invalid in [
        json!({"type":"stop"}),
        json!({"type":"input","data":"x","token":"not accepted"}),
        json!({"type":"ack","offset":1}),
        json!({"type":"resize","columns":65536,"rows":24}),
        json!({"type":"resize","columns":-1,"rows":24}),
        json!({"type":"input","data":[1]}),
    ] {
        assert!(serde_json::from_value::<ClientFrame>(invalid).is_err());
    }
    assert!(
        serde_json::from_str::<ClientFrame>(r#"{"type":"input","data":"a","data":"b"}"#).is_err()
    );
}

struct TestSink {
    sent: mpsc::UnboundedSender<Message>,
    block_flush: bool,
}
impl Sink<Message> for TestSink {
    type Error = Infallible;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.sent.send(item).unwrap();
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.block_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct Harness {
    browser: mpsc::Sender<Result<Message, ()>>,
    daemon_output: mpsc::Sender<Result<v1::SessionAttachMessage, tonic::Status>>,
    daemon_input: mpsc::Receiver<v1::SessionAttachMessage>,
    rendered: mpsc::UnboundedReceiver<Message>,
    task: tokio::task::JoinHandle<End>,
}

fn harness(block_flush: bool, io_timeout: Duration) -> Harness {
    let (browser, browser_rx) = mpsc::channel(128);
    let (daemon_output, output_rx) = mpsc::channel(128);
    let (input_tx, daemon_input) = mpsc::channel(1);
    let (sent, rendered) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        relay(
            &mut TestSink { sent, block_flush },
            &mut ReceiverStream::new(browser_rx),
            input_tx,
            ReceiverStream::new(output_rx),
            Coordinates {
                account_id: "synthetic-account".into(),
                session_id: SESSION.into(),
                output_offset: 0,
            },
            io_timeout,
        )
        .await
    });
    Harness {
        browser,
        daemon_output,
        daemon_input,
        rendered,
        task,
    }
}

async fn send(browser: &mpsc::Sender<Result<Message, ()>>, value: Value) {
    browser
        .send(Ok(Message::Text(value.to_string().into())))
        .await
        .unwrap();
}

async fn rendered(harness: &mut Harness) -> Value {
    let message = timeout(Duration::from_secs(1), harness.rendered.recv())
        .await
        .unwrap()
        .unwrap();
    let Message::Text(text) = message else {
        panic!("expected text frame")
    };
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn full_output_window_still_services_input_resize_and_render_acks() {
    let mut h = harness(false, Duration::from_secs(1));
    for offset in 0..=WINDOW_FRAMES as u64 {
        h.daemon_output
            .send(Ok(output(offset, b"x")))
            .await
            .unwrap();
    }
    for offset in 0..WINDOW_FRAMES {
        assert_eq!(rendered(&mut h).await["offset"], offset.to_string());
    }
    assert!(h.rendered.try_recv().is_err());
    send(&h.browser, json!({"type":"input","data":"\u{3}"})).await;
    let input = timeout(Duration::from_secs(1), h.daemon_input.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(input.payload, Some(v1::session_attach_message::Payload::Input(v1::SessionInput { data })) if data == [3])
    );
    send(&h.browser, json!({"type":"resize","columns":120,"rows":40})).await;
    let resize = timeout(Duration::from_secs(1), h.daemon_input.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        resize.payload,
        Some(v1::session_attach_message::Payload::Resize(
            v1::ResizeRequest {
                width: 120,
                height: 40
            }
        ))
    ));
    send(&h.browser, json!({"type":"ack","offset":"64"})).await;
    assert_eq!(rendered(&mut h).await["offset"], "64");
    h.browser.send(Ok(Message::Close(None))).await.unwrap();
    assert_eq!(h.task.await.unwrap(), End::PeerClosed);
    assert_eq!(h.daemon_input.recv().await, None);
    assert!(h.daemon_output.is_closed());
}

#[tokio::test]
async fn stalled_browser_write_does_not_duplicate_output_or_starve_control_c() {
    let mut h = harness(true, Duration::from_millis(100));
    h.daemon_output.send(Ok(output(0, b"x"))).await.unwrap();
    assert_eq!(rendered(&mut h).await["offset"], "0");
    for _ in 0..10 {
        send(&h.browser, json!({"type":"ack","offset":"0"})).await;
    }
    send(&h.browser, json!({"type":"input","data":"\u{3}"})).await;
    assert!(
        timeout(Duration::from_secs(1), h.daemon_input.recv())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        timeout(Duration::from_secs(1), h.task)
            .await
            .unwrap()
            .unwrap(),
        End::Transport
    );
    assert!(h.rendered.try_recv().is_err());
    assert!(h.daemon_output.is_closed());
}

#[tokio::test]
async fn blocked_daemon_input_has_a_fixed_deadline_and_detaches() {
    let mut h = harness(false, Duration::from_millis(30));
    send(&h.browser, json!({"type":"input","data":"a"})).await;
    send(&h.browser, json!({"type":"input","data":"b"})).await;
    for _ in 0..20 {
        send(&h.browser, json!({"type":"ack","offset":"0"})).await;
    }
    assert_eq!(
        timeout(Duration::from_secs(1), h.task)
            .await
            .unwrap()
            .unwrap(),
        End::Transport
    );
    assert!(h.daemon_output.is_closed());
    let first = h.daemon_input.recv().await.unwrap();
    assert!(
        matches!(first.payload, Some(v1::session_attach_message::Payload::Input(v1::SessionInput { data })) if data == b"a")
    );
    assert_eq!(h.daemon_input.recv().await, None);
}

#[tokio::test]
async fn queued_input_is_bounded_by_bytes_and_frame_count() {
    for data in ["x".to_owned(), "x".repeat(INPUT_BYTES)] {
        let mut h = harness(false, Duration::from_secs(1));
        // No daemon consumer: one message may enter its bounded channel, but
        // the browser-side queue must reject either kind of subsequent flood.
        for _ in 0..80 {
            h.browser
                .try_send(Ok(Message::Text(
                    json!({"type":"input", "data":data}).to_string().into(),
                )))
                .unwrap();
        }
        assert_eq!(
            timeout(Duration::from_secs(1), h.task)
                .await
                .unwrap()
                .unwrap(),
            End::Invalid
        );
        assert!(h.daemon_output.is_closed());
        assert!(h.daemon_input.len() <= 1);
        while let Some(message) = h.daemon_input.recv().await {
            assert!(matches!(
                message.payload,
                Some(v1::session_attach_message::Payload::Input(_))
            ));
        }
    }
}

#[tokio::test]
async fn terminal_status_flushes_after_output_without_private_diagnostics() {
    let mut h = harness(false, Duration::from_secs(1));
    h.daemon_output
        .send(Ok(status(v1::SessionLifecycleState::Running, 6)))
        .await
        .unwrap();
    h.daemon_output
        .send(Ok(output(0, b"hello\n")))
        .await
        .unwrap();
    h.daemon_output
        .send(Ok(status(v1::SessionLifecycleState::Exited, 6)))
        .await
        .unwrap();
    assert_eq!(
        rendered(&mut h).await,
        json!({"type":"status","state":"running"})
    );
    assert_eq!(
        rendered(&mut h).await,
        json!({"type":"output","offset":"0","nextOffset":"6","data":"aGVsbG8K"})
    );
    assert_eq!(
        rendered(&mut h).await,
        json!({"type":"status","state":"exited","exitCode":0})
    );
    drop(h.daemon_output);
    assert_eq!(h.task.await.unwrap(), End::Complete);
    assert_eq!(h.daemon_input.recv().await, None);
}

#[tokio::test]
async fn malformed_input_or_upstream_eof_detaches_without_stop() {
    for frame in [
        Message::Binary(vec![0, 1].into()),
        Message::Text("{".into()),
        Message::Text(json!({"type":"input","data":""}).to_string().into()),
        Message::Text(
            json!({"type":"input","data":"x".repeat(INPUT_BYTES+1)})
                .to_string()
                .into(),
        ),
        Message::Text(
            json!({"type":"resize","columns":0,"rows":24})
                .to_string()
                .into(),
        ),
        Message::Text(json!({"type":"ack","offset":"1"}).to_string().into()),
    ] {
        let mut h = harness(false, Duration::from_secs(1));
        h.browser.send(Ok(frame)).await.unwrap();
        assert_eq!(h.task.await.unwrap(), End::Invalid);
        assert_eq!(h.daemon_input.recv().await, None);
        assert!(h.daemon_output.is_closed());
    }
    let mut h = harness(false, Duration::from_secs(1));
    drop(h.daemon_output);
    assert_eq!(h.task.await.unwrap(), End::Transport);
    assert_eq!(h.daemon_input.recv().await, None);
}

#[tokio::test]
async fn upstream_status_must_match_session_and_replayed_output() {
    for mut message in [
        status(v1::SessionLifecycleState::Running, 0),
        status(v1::SessionLifecycleState::Exited, 1),
        status(v1::SessionLifecycleState::Unspecified, 0),
    ] {
        if let Some(v1::session_attach_message::Payload::Status(status)) = &mut message.payload
            && status.state == i32::from(v1::SessionLifecycleState::Running)
        {
            status.session_id = "another-session".into();
        }
        let h = harness(false, Duration::from_secs(1));
        h.daemon_output.send(Ok(message)).await.unwrap();
        assert_eq!(h.task.await.unwrap(), End::Invalid);
    }
}

#[test]
fn declared_orchestration_origins_match_dashboard_without_overriding_kind() {
    // The two local process defaults must use the same origin spelling, too;
    // hostname aliases are not equivalent under browser Origin checks.
    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    let dashboard_config = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../codewire-dashboard-web/src/config.rs"
    ));
    assert!(main.contains(".unwrap_or_else(|_| \"http://127.0.0.1:5173\".into())"));
    assert!(dashboard_config.contains(".unwrap_or_else(|_| \"http://127.0.0.1:5173\".to_owned())"));
    fn yaml(text: &str) -> serde_yaml::Value {
        serde_yaml::from_str(text).unwrap()
    }
    fn env(document: &serde_yaml::Value, name: &str) -> String {
        document["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|entry| entry["name"].as_str() == Some(name))
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .into()
    }
    for (origin, patch, dashboard, kustomization) in [
        (
            ORIGIN,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/overlays/dev/orchestration-origin-patch.yaml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/overlays/dev/dashboard-deployment.yaml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/overlays/dev/kustomization.yaml"
            )),
        ),
        (
            "https://codewire.sh",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/overlays/production/orchestration-origin-patch.yaml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/dashboard/deployment.yaml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deployments/k8s/overlays/production/kustomization.yaml"
            )),
        ),
    ] {
        assert_eq!(env(&yaml(patch), "FRONTEND_URL"), origin);
        assert_eq!(env(&yaml(dashboard), "CODEWIRE_PUBLIC_ORIGIN"), origin);
        assert!(
            yaml(kustomization)["patches"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(
                    |entry| entry["path"].as_str() == Some("orchestration-origin-patch.yaml")
                        && entry["target"]["name"].as_str() == Some("codewire-orchestration")
                )
        );
    }
    let base = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/deployment.yaml"
    ));
    assert!(!base.contains("FRONTEND_URL"));
    let local = yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/overlays/local-kind/configmap-patch.yaml"
    )));
    assert_eq!(
        local["data"]["FRONTEND_URL"].as_str(),
        Some("http://127.0.0.1:8080")
    );
    let managed = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/e2e/kind/support.yaml"
    ));
    assert!(managed.contains("FRONTEND_URL: http://127.0.0.1:8090"));
}

#[test]
fn retention_gaps_do_not_count_skipped_bytes_or_forgive_outstanding_output() {
    let mut window = Window::new(0);
    window.output(chunk(0, b"old")).unwrap();
    window
        .history_gap(v1::SessionOutputGap {
            requested_offset: 3,
            retained_start_offset: 1_000_000,
        })
        .unwrap();
    assert_eq!(window.pending_bytes, 3);
    assert_eq!(window.acknowledged, 0);
    assert_eq!(window.ends.len(), 2);
    window.output(chunk(1_000_000, b"new")).unwrap();
    assert_eq!(window.pending_bytes, 6);
    assert_eq!(window.acknowledge("999999"), Err(End::Invalid));
    window.acknowledge("3").unwrap();
    assert_eq!(window.pending_bytes, 3);
    window.acknowledge("1000000").unwrap();
    assert_eq!(window.pending_bytes, 3);
    window.acknowledge("1000003").unwrap();
    assert_eq!(window.pending_bytes, 0);
    assert!(window.ends.is_empty());
    for gap in [
        v1::SessionOutputGap {
            requested_offset: 3,
            retained_start_offset: 4,
        },
        v1::SessionOutputGap {
            requested_offset: 1_000_003,
            retained_start_offset: 1_000_003,
        },
        v1::SessionOutputGap {
            requested_offset: 1_000_003,
            retained_start_offset: 1_000_002,
        },
    ] {
        assert_eq!(window.history_gap(gap), Err(End::Invalid));
    }
    let mut sparse = Window::new(0);
    for offset in 0..WINDOW_FRAMES as u64 {
        sparse
            .history_gap(v1::SessionOutputGap {
                requested_offset: offset,
                retained_start_offset: offset + 1,
            })
            .unwrap();
    }
    assert_eq!(sparse.pending_bytes, 0);
    assert!(!sparse.has_capacity());
    sparse.acknowledge(&WINDOW_FRAMES.to_string()).unwrap();
    assert!(sparse.has_capacity());
}

#[tokio::test]
async fn gap_relay_orders_old_output_notice_new_output_and_terminal_status() {
    let mut h = harness(false, Duration::from_secs(1));
    h.daemon_output.send(Ok(output(0, b"old"))).await.unwrap();
    h.daemon_output
        .send(Ok(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::HistoryGap(
                v1::SessionOutputGap {
                    requested_offset: 3,
                    retained_start_offset: 1_000_000,
                },
            )),
        }))
        .await
        .unwrap();
    h.daemon_output
        .send(Ok(output(1_000_000, b"new")))
        .await
        .unwrap();
    h.daemon_output
        .send(Ok(status(v1::SessionLifecycleState::Exited, 1_000_003)))
        .await
        .unwrap();
    assert_eq!(rendered(&mut h).await["offset"], "0");
    assert_eq!(
        rendered(&mut h).await,
        json!({"type":"historyGap","requestedOffset":"3","retainedStartOffset":"1000000"})
    );
    assert_eq!(rendered(&mut h).await["offset"], "1000000");
    assert_eq!(
        rendered(&mut h).await,
        json!({"type":"status","state":"exited","exitCode":0})
    );
    drop(h.daemon_output);
    assert_eq!(h.task.await.unwrap(), End::Complete);
    assert_eq!(h.daemon_input.recv().await, None);
}
