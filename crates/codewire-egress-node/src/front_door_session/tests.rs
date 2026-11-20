use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_egress_front_door_bridge::control::ControlChannel;

use super::*;
use crate::front_door::protocol::{
    CREDENTIALS, MAX_CONTROL_MESSAGE, SESSION_SERVING, SessionRefusal, session_dropped_message,
};

const WAIT: Duration = Duration::from_secs(10);

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("bounded test step")
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}

/// Orchestration's side of an attached session.
struct Far {
    from_front_door: mpsc::Receiver<Vec<u8>>,
    to_front_door: mpsc::Sender<Result<Vec<u8>, SessionEnd>>,
}

fn attached() -> (Attached, Far) {
    let (to_orchestration, from_front_door) = mpsc::channel(1);
    let (to_front_door, from_orchestration) = mpsc::channel(1);
    (
        Attached {
            to_orchestration,
            from_orchestration,
        },
        Far {
            from_front_door,
            to_front_door,
        },
    )
}

fn socket_pair() -> (UnixStream, UnixStream) {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    ours.set_nonblocking(true).unwrap();
    theirs.set_nonblocking(true).unwrap();
    (
        UnixStream::from_std(ours).unwrap(),
        UnixStream::from_std(theirs).unwrap(),
    )
}

#[test]
fn every_wait_is_in_the_upper_half_of_its_interval_and_the_backoff_resets_only_when_healthy() {
    let short = Some(Duration::from_secs(5));
    let healthy = Some(HEALTHY_FOR);
    for _ in 0..50 {
        let mut backoff = Backoff::default();
        let mut interval = BACKOFF_FLOOR;
        for _ in 0..8 {
            let wait = backoff.after(SessionEnd::Unavailable, short);
            assert!(
                wait >= interval / 2 && wait < interval,
                "{wait:?} in {interval:?}"
            );
            interval = (interval * 2).min(BACKOFF_CAP);
        }
        // A clean end soon after attaching is no better than a failure.
        let wait = backoff.after(SessionEnd::Clean, short);
        assert!(wait >= BACKOFF_CAP / 2, "{wait:?}");
        // A healthy session's clean end, as at the token's expiry, reopens
        // at once and resets the backoff.
        assert!(backoff.after(SessionEnd::Clean, healthy) < REOPEN_WITHIN);
        let wait = backoff.after(SessionEnd::Unavailable, None);
        assert!(wait < BACKOFF_FLOOR, "{wait:?}");

        let wait = backoff.after(SessionEnd::Refused, None);
        assert!(wait >= REFUSED_WAIT / 2 && wait < REFUSED_WAIT, "{wait:?}");
        let wait = backoff.after(SessionEnd::Unimplemented, None);
        assert!(
            wait >= UNIMPLEMENTED_WAIT / 2 && wait < UNIMPLEMENTED_WAIT,
            "{wait:?}"
        );
    }
}

/// Toward the front door, frames go unchanged; toward orchestration, its
/// bytes are cut into whole frames, one message each.
#[tokio::test]
async fn a_relay_carries_frames_unchanged_and_cuts_the_front_doors_bytes_into_frames() {
    let (session, mut far) = attached();
    let (ours, mut front_door) = socket_pair();
    let relaying = tokio::spawn(relay(session, ours));

    far.to_front_door.send(Ok(frame(b"open"))).await.unwrap();
    let mut read = vec![0_u8; 8];
    bounded(front_door.read_exact(&mut read)).await.unwrap();
    assert_eq!(read, frame(b"open"));

    // Two frames in one write, the second split across writes.
    let mut bytes = frame(b"ready");
    let second = frame(b"request");
    bytes.extend_from_slice(&second[..3]);
    front_door.write_all(&bytes).await.unwrap();
    assert_eq!(
        bounded(far.from_front_door.recv()).await,
        Some(frame(b"ready"))
    );
    front_door.write_all(&second[3..]).await.unwrap();
    assert_eq!(bounded(far.from_front_door.recv()).await, Some(second));

    // Orchestration ending it cleanly ends the relay and closes the socket.
    drop(far.to_front_door);
    assert_eq!(bounded(relaying).await.unwrap(), SessionEnd::Clean);
    let mut byte = [0_u8; 1];
    assert_eq!(bounded(front_door.read(&mut byte)).await.unwrap(), 0);
}

#[tokio::test]
async fn a_frame_of_no_length_or_over_the_bridges_maximum_ends_the_relay() {
    let too_long = u32::try_from(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1).unwrap();
    for length in [0, too_long] {
        let (session, mut far) = attached();
        let (ours, mut front_door) = socket_pair();
        let relaying = tokio::spawn(relay(session, ours));
        front_door.write_all(&length.to_be_bytes()).await.unwrap();
        assert_eq!(
            bounded(relaying).await.unwrap(),
            SessionEnd::Unavailable,
            "{length}"
        );
        assert_eq!(far.from_front_door.recv().await, None, "nothing was sent");
    }
}

#[tokio::test]
async fn a_relay_ends_with_whichever_side_ends_first() {
    let (session, far) = attached();
    let (ours, front_door) = socket_pair();
    let relaying = tokio::spawn(relay(session, ours));
    far.to_front_door
        .send(Err(SessionEnd::Refused))
        .await
        .unwrap();
    assert_eq!(bounded(relaying).await.unwrap(), SessionEnd::Refused);
    drop(front_door);

    let (session, mut far) = attached();
    let (ours, front_door) = socket_pair();
    let relaying = tokio::spawn(relay(session, ours));
    drop(front_door);
    assert_eq!(bounded(relaying).await.unwrap(), SessionEnd::Unavailable);
    assert_eq!(far.from_front_door.recv().await, None);
}

/// An opener whose sessions the test drives: each open hands back the far
/// side of a new session, or fails as `refuse` says.
#[derive(Debug)]
struct Opener {
    opens: AtomicUsize,
    sessions: std::sync::Mutex<mpsc::UnboundedSender<Far>>,
}

impl SessionOpener for Opener {
    fn open<'a>(
        &'a self,
        _pod_uid: &'a str,
        _pod_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Attached, SessionEnd>> + Send + 'a>> {
        Box::pin(async move {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let (session, far) = attached();
            self.sessions.lock().unwrap().send(far).unwrap();
            Ok(session)
        })
    }
}

/// The front door's side of the sessions socket: takes one hand-off, checks
/// the tag the supervisor wrote, and answers `answer`.
async fn take_session(front_door: &mut ControlChannel, answer: &[u8]) -> UnixStream {
    let (message, descriptors) = bounded(front_door.receive(MAX_CONTROL_MESSAGE, 1))
        .await
        .unwrap();
    assert_eq!(message, CREDENTIALS);
    let [socket] = <[std::os::fd::OwnedFd; 1]>::try_from(descriptors).unwrap();
    let socket = std::os::unix::net::UnixStream::from(socket);
    socket.set_nonblocking(true).unwrap();
    let mut socket = UnixStream::from_std(socket).unwrap();
    let mut tag = [0_u8; 1];
    bounded(socket.read_exact(&mut tag)).await.unwrap();
    assert_eq!(
        tag[0], FRONT_DOOR_SESSION_ROLE_TAG,
        "the supervisor wrote it"
    );
    front_door.send(answer, &[]).await.unwrap();
    socket
}

/// Each session is handed over tagged and relayed; when it ends, the next is
/// opened after its wait. A front door that won't take one ends the task.
#[tokio::test(start_paused = true)]
async fn the_task_hands_each_session_over_reopens_it_and_ends_when_the_front_door_refuses() {
    let (supervisor, front_door) = stream_pair().unwrap();
    let mut front_door = ControlChannel::new(front_door).unwrap();
    let (opened, mut far) = mpsc::unbounded_channel();
    let opener = Arc::new(Opener {
        opens: AtomicUsize::new(0),
        sessions: std::sync::Mutex::new(opened),
    });
    let task = tokio::spawn({
        let opener = Arc::clone(&opener);
        async move {
            let mut sessions = ControlChannel::new(supervisor).unwrap();
            run(&*opener, "pod-uid", "pod-name", &mut sessions).await
        }
    });

    let mut socket = take_session(&mut front_door, SESSION_SERVING).await;
    let session = bounded(far.recv()).await.unwrap();
    session
        .to_front_door
        .send(Ok(frame(b"open")))
        .await
        .unwrap();
    let mut read = vec![0_u8; 8];
    bounded(socket.read_exact(&mut read)).await.unwrap();
    assert_eq!(read, frame(b"open"));

    // Orchestration ends it: the socket closes, and a new one is opened.
    drop(session);
    let mut byte = [0_u8; 1];
    assert_eq!(bounded(socket.read(&mut byte)).await.unwrap(), 0);
    let _second = take_session(&mut front_door, SESSION_SERVING).await;
    assert_eq!(opener.opens.load(Ordering::SeqCst), 2);
    drop(bounded(far.recv()).await.unwrap());

    // One relay runs at a time, so a busy front door is a fault.
    let _third = take_session(
        &mut front_door,
        &session_dropped_message(SessionRefusal::Busy),
    )
    .await;
    assert_eq!(
        bounded(task).await.unwrap(),
        SessionTaskError::Hand(HandError::Dropped(SessionRefusal::Busy))
    );
}
