use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::HeaderValue;
use futures::channel::mpsc;
use tokio::io::duplex;

use super::*;

/// A bound on every wait in these tests, far above what each needs.
const TEST_WAIT: Duration = Duration::from_secs(10);
/// The stall bound the relay gets here, so a stall shows quickly.
const TEST_STALL: Duration = Duration::from_millis(200);

fn headers(protocols: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for protocol in protocols {
        headers.append(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(protocol).unwrap(),
        );
    }
    headers
}

#[test]
fn only_the_one_subprotocol_and_one_account_are_accepted() {
    assert_eq!(
        requested_account(&headers(&[PROTOCOL]), Some("account_id=user-1")).as_deref(),
        Ok("user-1")
    );
    for (protocols, query) in [
        (vec![], Some("account_id=user-1")),
        (vec![PROTOCOL, PROTOCOL], Some("account_id=user-1")),
        (
            vec!["codewire.desktop-stream.v2"],
            Some("account_id=user-1"),
        ),
        (
            vec!["codewire.desktop-stream.v1, terminal"],
            Some("account_id=user-1"),
        ),
        (vec![PROTOCOL], None),
        (vec![PROTOCOL], Some("")),
        (vec![PROTOCOL], Some("account_id=user-1&account_id=user-2")),
        (vec![PROTOCOL], Some("account_id=user-1&session_id=x")),
        (vec![PROTOCOL], Some("account_id=user%2F1")),
        (vec![PROTOCOL], Some("account_id=")),
    ] {
        assert!(
            requested_account(&headers(&protocols), query).is_err(),
            "{protocols:?} {query:?}"
        );
    }
    let long = format!("account_id={}", "a".repeat(250));
    assert!(requested_account(&headers(&[PROTOCOL]), Some(&long)).is_err());
}

#[test]
fn the_desktop_is_reached_on_the_workloads_loopback_port_5901() {
    assert_eq!(desktop_address().to_string(), "127.0.0.1:5901");
}

#[test]
fn an_environment_takes_four_viewers_and_a_leaving_one_frees_its_place() {
    let viewers: Vec<Viewer> = (0..VIEWERS_PER_ENVIRONMENT)
        .map(|_| Viewer::admit("env-viewer-limit").expect("a viewer under the limit"))
        .collect();
    assert!(Viewer::admit("env-viewer-limit").is_none());
    // Another environment's viewers are counted apart.
    let other = Viewer::admit("env-viewer-limit-other");
    assert!(other.is_some());
    drop(viewers.into_iter().next());
    assert!(Viewer::admit("env-viewer-limit").is_some());
}

#[test]
fn each_end_closes_with_its_code_and_a_reason() {
    let close = |end| match close_for(end) {
        Message::Close(Some(frame)) => (frame.code, frame.reason.to_string()),
        other => panic!("{other:?}"),
    };
    assert_eq!(close(End::ViewerLeft).0, 1000);
    assert_eq!(close(End::Restarting).0, 1012);
    assert_eq!(
        close(End::Revoked(Revocation::ApiKey)),
        (1008, "access revoked".to_owned())
    );
    assert_eq!(
        close(End::Revoked(Revocation::Membership)),
        (1008, "membership ended".to_owned())
    );
    assert_eq!(
        close(End::Revoked(Revocation::Organization)),
        (1008, "organization is being deleted".to_owned())
    );
    for end in [
        End::Invalid,
        End::Stalled,
        End::DesktopEnded,
        End::NotRunning,
        End::DaemonTooOld,
        End::DaemonUnreachable,
        End::TooManyViewers,
    ] {
        let (code, reason) = close(end);
        assert_eq!(code, 1008, "{end:?}");
        // A close frame's reason fits in 123 bytes.
        assert!(!reason.is_empty() && reason.len() <= 123, "{end:?}");
    }
    assert!(close(End::TooManyViewers).1.contains('4'));
}

#[test]
fn a_forward_the_daemon_refuses_says_why() {
    let status =
        |code, message: &str| SessionClientError::Status(tonic::Status::new(code, message));
    assert_eq!(
        refused(&status(Code::Unavailable, "nothing accepted")),
        End::NotRunning
    );
    assert_eq!(refused(&status(Code::Unimplemented, "")), End::DaemonTooOld);
    assert_eq!(
        refused(&status(Code::PermissionDenied, "")),
        End::DaemonUnreachable
    );
}

/// The browser's side of a relay: what the relay sends arrives on `sent`;
/// what the test pushes on `receive` is what the browser sends.
struct Browser {
    sent: mpsc::Receiver<Message>,
    receive: mpsc::Sender<Result<Message, Infallible>>,
}

fn browser(
    capacity: usize,
) -> (
    Browser,
    mpsc::Sender<Message>,
    mpsc::Receiver<Result<Message, Infallible>>,
) {
    let (output, sent) = mpsc::channel(capacity);
    let (receive, input) = mpsc::channel(capacity);
    (Browser { sent, receive }, output, input)
}

#[tokio::test(start_paused = true)]
async fn a_still_desktop_is_pinged_every_30_seconds() {
    let (mut browser, mut output, mut input) = browser(8);
    let (desktop, _server) = duplex(1024);
    let _relay =
        tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });
    let started = tokio::time::Instant::now();
    for n in 1..=2 {
        let message = timeout(
            crate::api::socket_keepalive::PING_EVERY + TEST_WAIT,
            browser.sent.next(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(message, Message::Ping(_)), "{message:?}");
        assert_eq!(
            started.elapsed(),
            n * crate::api::socket_keepalive::PING_EVERY
        );
    }
}

#[tokio::test]
async fn desktop_bytes_cross_unchanged_both_ways_and_the_viewer_leaving_ends_with_1000() {
    let (mut browser, mut output, mut input) = browser(8);
    let (desktop, mut server) = duplex(1024 * 1024);
    let relay =
        tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });

    server.write_all(b"RFB 003.008\n").await.unwrap();
    let greeting = timeout(TEST_WAIT, browser.sent.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, Message::Binary(b"RFB 003.008\n".to_vec().into()));

    browser
        .receive
        .try_send(Ok(Message::Binary(b"RFB 003.008\n".to_vec().into())))
        .unwrap();
    let mut echoed = [0; 12];
    timeout(TEST_WAIT, server.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"RFB 003.008\n");

    browser.receive.try_send(Ok(Message::Close(None))).unwrap();
    assert_eq!(
        timeout(TEST_WAIT, relay).await.unwrap().unwrap(),
        End::ViewerLeft
    );
}

#[tokio::test]
async fn a_large_screen_update_reaches_the_browser_in_chunks_of_at_most_32_kib() {
    let (mut browser, mut output, mut input) = browser(64);
    let (desktop, mut server) = duplex(1024 * 1024);
    let _keep = browser.receive.clone();
    let relay =
        tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });
    let update: Vec<u8> = (0..200 * 1024).map(|index| (index % 251) as u8).collect();
    server.write_all(&update).await.unwrap();
    let mut received = Vec::new();
    while received.len() < update.len() {
        match timeout(TEST_WAIT, browser.sent.next())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Binary(bytes) => {
                assert!(!bytes.is_empty() && bytes.len() <= CHUNK_BYTES);
                received.extend_from_slice(&bytes);
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(received, update);
    relay.abort();
}

#[tokio::test]
async fn the_desktop_ending_ends_the_stream() {
    let (browser, mut output, mut input) = browser(8);
    let (desktop, server) = duplex(1024);
    let relay =
        tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });
    drop(server);
    assert_eq!(
        timeout(TEST_WAIT, relay).await.unwrap().unwrap(),
        End::DesktopEnded
    );
    drop(browser);
}

#[tokio::test]
async fn a_text_frame_or_a_message_over_64_kib_ends_the_stream() {
    for message in [
        Message::Text("RFB".into()),
        Message::Binary(vec![0; FRAME_BYTES + 1].into()),
    ] {
        let (mut browser, mut output, mut input) = browser(8);
        let (desktop, _server) = duplex(1024 * 1024);
        let relay =
            tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });
        browser.receive.try_send(Ok(message)).unwrap();
        assert_eq!(
            timeout(TEST_WAIT, relay).await.unwrap().unwrap(),
            End::Invalid
        );
    }
}

/// A browser that never takes another message.
struct Stuck;

impl Sink<Message> for Stuck {
    type Error = Infallible;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }
    fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Infallible> {
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn a_browser_that_stops_taking_bytes_ends_the_stream_at_the_stall_bound() {
    let (browser, _output, mut input) = browser(8);
    let (desktop, mut server) = duplex(1024);
    let relay =
        tokio::spawn(async move { relay(&mut Stuck, &mut input, desktop, TEST_STALL).await });
    server.write_all(b"framebuffer").await.unwrap();
    assert_eq!(
        timeout(TEST_WAIT, relay).await.unwrap().unwrap(),
        End::Stalled
    );
    drop(browser);
}

#[tokio::test]
async fn a_desktop_that_stops_taking_bytes_ends_the_stream_at_the_stall_bound() {
    let (mut browser, mut output, mut input) = browser(8);
    // Nobody reads the desktop's side, and it holds 16 bytes.
    let (desktop, _server) = duplex(16);
    let relay =
        tokio::spawn(async move { relay(&mut output, &mut input, desktop, TEST_STALL).await });
    browser
        .receive
        .try_send(Ok(Message::Binary(vec![1; 1024].into())))
        .unwrap();
    assert_eq!(
        timeout(TEST_WAIT, relay).await.unwrap().unwrap(),
        End::Stalled
    );
}
