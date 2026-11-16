use codewire_credential_bridge::upgraded_stream::StreamCredits;
use v1::credential_bridge_guest_message::Payload;

use super::*;

struct Discard;

impl StreamSink for Discard {
    async fn send(&self, _frame: StreamFrame) -> Result<(), ()> {
        Ok(())
    }
}

fn control() -> StreamControl {
    let (_local, io) = tokio::io::duplex(1024);
    pump(
        io,
        Discard,
        StreamCredits {
            send: 0,
            granted: CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
        },
    )
    .0
}

fn data(request_id: &str, bytes: usize) -> Payload {
    Payload::StreamData(v1::CredentialBridgeStreamData {
        request_id: request_id.to_owned(),
        data: vec![1; bytes],
    })
}

#[tokio::test]
async fn a_session_holds_at_most_its_socket_limit() {
    let sockets = Sockets::default();
    for index in 0..MAX_OPEN_SOCKETS {
        assert!(sockets.admit(&index.to_string(), control()));
    }
    assert!(!sockets.admit("one-more", control()));
    sockets.remove("0");
    assert!(sockets.admit("one-more", control()));
}

#[tokio::test]
async fn frames_reach_their_socket_and_stray_or_bad_ones_are_told_apart() {
    let sockets = Sockets::default();
    assert!(sockets.admit("open", control()));
    assert_eq!(sockets.apply(data("open", 10)), Ok(true));
    // Not open here: the runner decides whether it just ended.
    assert_eq!(sockets.apply(data("never", 10)), Ok(false));
    // Past the window the guest was granted.
    assert_eq!(
        sockets.apply(data("open", CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES as usize)),
        Err(())
    );
    let bad_close = Payload::StreamClose(v1::CredentialBridgeStreamClose {
        request_id: "open".to_owned(),
        kind: 0,
    });
    assert_eq!(sockets.apply(bad_close), Err(()));
    let zero_credit = Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
        request_id: "open".to_owned(),
        credit_bytes: 0,
    });
    assert_eq!(sockets.apply(zero_credit), Err(()));
}
