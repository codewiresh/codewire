use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::DuplexStream;

use super::*;

const WINDOW: u32 = CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;
/// A hang guard, not a product bound.
const GUARD: Duration = Duration::from_secs(30);

/// One side's session: frames go straight to the other pump's control, as
/// the session would carry them, and are counted.
#[derive(Clone)]
struct Link {
    peer: Arc<Mutex<Option<StreamControl>>>,
    data_bytes: Arc<AtomicUsize>,
    resets: Arc<AtomicUsize>,
    broken: bool,
}

impl Link {
    fn new() -> Self {
        Self {
            peer: Arc::default(),
            data_bytes: Arc::default(),
            resets: Arc::default(),
            broken: false,
        }
    }

    fn connect(&self, peer: &StreamControl) {
        *self.peer.lock().unwrap() = Some(peer.clone());
    }
}

impl StreamSink for Link {
    async fn send(&self, frame: StreamFrame) -> Result<(), ()> {
        if self.broken {
            return Err(());
        }
        let peer = self.peer.lock().unwrap().clone().ok_or(())?;
        match frame {
            StreamFrame::Data(data) => {
                self.data_bytes.fetch_add(data.len(), Ordering::SeqCst);
                peer.deliver(data).map_err(|_| ())
            }
            StreamFrame::Credit(bytes) => peer.credit(bytes).map_err(|_| ()),
            StreamFrame::Close(kind) => {
                if kind == StreamClose::Reset {
                    self.resets.fetch_add(1, Ordering::SeqCst);
                }
                peer.close(kind).map_err(|_| ())
            }
        }
    }
}

/// Two pumps joined as a front door and a broker would be: each starts with
/// a window granted each way. Returns the two local ends, the links, and the
/// running pumps.
struct Pair {
    near: DuplexStream,
    far: DuplexStream,
    near_link: Link,
    far_link: Link,
    near_control: StreamControl,
    near_end: tokio::task::JoinHandle<StreamEnd>,
    far_end: tokio::task::JoinHandle<StreamEnd>,
}

fn pair() -> Pair {
    let credits = StreamCredits {
        send: WINDOW,
        granted: WINDOW,
    };
    let (near, near_io) = tokio::io::duplex(8 * 1024);
    let (far, far_io) = tokio::io::duplex(8 * 1024);
    let (near_link, far_link) = (Link::new(), Link::new());
    let (near_control, near_run) = pump(near_io, near_link.clone(), credits);
    let (far_control, far_run) = pump(far_io, far_link.clone(), credits);
    near_link.connect(&far_control);
    far_link.connect(&near_control);
    Pair {
        near,
        far,
        near_link,
        far_link,
        near_control,
        near_end: tokio::spawn(near_run),
        far_end: tokio::spawn(far_run),
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31) ^ seed)
        .collect()
}

#[tokio::test]
async fn bytes_cross_both_ways_beyond_the_window_and_both_closes_end_it() {
    let Pair {
        near,
        far,
        near_end,
        far_end,
        ..
    } = pair();
    let up = pattern(1024 * 1024 + 17, 1);
    let down = pattern(700 * 1024 + 3, 2);
    let (mut near_read, mut near_write) = tokio::io::split(near);
    let (mut far_read, mut far_write) = tokio::io::split(far);
    let send_up = {
        let up = up.clone();
        async move {
            near_write.write_all(&up).await.unwrap();
            near_write.shutdown().await.unwrap();
        }
    };
    let send_down = {
        let down = down.clone();
        async move {
            far_write.write_all(&down).await.unwrap();
            far_write.shutdown().await.unwrap();
        }
    };
    let receive_up = async move {
        let mut got = Vec::new();
        far_read.read_to_end(&mut got).await.unwrap();
        got
    };
    let receive_down = async move {
        let mut got = Vec::new();
        near_read.read_to_end(&mut got).await.unwrap();
        got
    };
    let ((), (), got_up, got_down) = tokio::time::timeout(GUARD, async {
        tokio::join!(send_up, send_down, receive_up, receive_down)
    })
    .await
    .unwrap();
    assert_eq!(got_up, up);
    assert_eq!(got_down, down);
    assert_eq!(near_end.await.unwrap(), StreamEnd::Closed);
    assert_eq!(far_end.await.unwrap(), StreamEnd::Closed);
}

#[tokio::test(start_paused = true)]
async fn a_reader_that_stops_holds_one_window_and_nothing_more() {
    let Pair {
        near,
        far: _far,
        near_link,
        ..
    } = pair();
    let (_near_read, mut near_write) = tokio::io::split(near);
    // The far side never reads: once its window and its pipe are full, the
    // near pump sends nothing more and the writer blocks.
    let writing = tokio::spawn(async move {
        let _ = near_write.write_all(&pattern(4 * 1024 * 1024, 3)).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sent = near_link.data_bytes.load(Ordering::SeqCst);
    // The far pump writes up to its pipe's 8 KiB before blocking, and grants
    // nothing back until it has written a step.
    assert!(sent <= WINDOW as usize, "sent {sent} past the window");
    assert!(sent >= WINDOW as usize - 64 * 1024, "sent only {sent}");
    assert!(!writing.is_finished());
    writing.abort();
}

#[tokio::test]
async fn a_peer_reset_ends_both_local_ends_without_a_frame_back() {
    let Pair {
        mut near,
        mut far,
        near_link,
        far_link,
        near_control,
        near_end,
        far_end,
        ..
    } = pair();
    near_control.abort();
    near_link
        .send(StreamFrame::Close(StreamClose::Reset))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(GUARD, far_end).await.unwrap().unwrap(),
        StreamEnd::Reset
    );
    assert_eq!(near_end.await.unwrap(), StreamEnd::Reset);
    // Each local end sees its stream gone.
    let mut byte = [0_u8; 1];
    assert!(matches!(far.read(&mut byte).await, Ok(0) | Err(_)));
    assert!(matches!(near.read(&mut byte).await, Ok(0) | Err(_)));
    assert_eq!(far_link.resets.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failed_session_resets_the_stream_once() {
    let credits = StreamCredits {
        send: WINDOW,
        granted: WINDOW,
    };
    let (mut local, io) = tokio::io::duplex(1024);
    let mut link = Link::new();
    link.broken = true;
    let (_control, running) = pump(io, link, credits);
    let running = tokio::spawn(running);
    local.write_all(b"hello").await.unwrap();
    assert_eq!(
        tokio::time::timeout(GUARD, running).await.unwrap().unwrap(),
        StreamEnd::Failed
    );
}

#[tokio::test]
async fn half_close_one_way_keeps_the_other_way_open() {
    let Pair {
        near,
        far,
        near_end,
        far_end,
        ..
    } = pair();
    let (mut near_read, mut near_write) = tokio::io::split(near);
    let (mut far_read, mut far_write) = tokio::io::split(far);
    near_write.write_all(b"request").await.unwrap();
    near_write.shutdown().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(GUARD, far_read.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"request");
    // The far side still answers after the near side stopped sending.
    far_write.write_all(b"reply").await.unwrap();
    far_write.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(GUARD, near_read.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"reply");
    assert_eq!(near_end.await.unwrap(), StreamEnd::Closed);
    assert_eq!(far_end.await.unwrap(), StreamEnd::Closed);
}

#[tokio::test]
async fn peer_frames_out_of_bounds_are_protocol_errors() {
    let Pair { near_control, .. } = pair();
    assert_eq!(
        near_control.deliver(Bytes::new()),
        Err(StreamProtocolError::DataSize)
    );
    assert_eq!(
        near_control.deliver(Bytes::from(vec![
            0;
            CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES + 1
        ])),
        Err(StreamProtocolError::DataSize)
    );
    assert_eq!(near_control.credit(0), Err(StreamProtocolError::Credit));
    assert_eq!(
        near_control.credit(MAX_SEND_CREDIT),
        Err(StreamProtocolError::Credit)
    );
    near_control.close(StreamClose::HalfClose).unwrap();
    assert_eq!(
        near_control.deliver(Bytes::from_static(b"late")),
        Err(StreamProtocolError::AfterClose)
    );
    assert_eq!(
        near_control.close(StreamClose::HalfClose),
        Err(StreamProtocolError::AfterClose)
    );
    // A reset after a half-close is still taken.
    near_control.close(StreamClose::Reset).unwrap();
}

#[tokio::test]
async fn data_past_the_granted_credit_is_refused() {
    let (_local, io) = tokio::io::duplex(1024);
    let (control, _running) = pump(
        io,
        Link::new(),
        StreamCredits {
            send: 0,
            granted: 100,
        },
    );
    control.deliver(Bytes::from(vec![1; 60])).unwrap();
    assert_eq!(
        control.deliver(Bytes::from(vec![1; 41])),
        Err(StreamProtocolError::OverCredit)
    );
    control.deliver(Bytes::from(vec![1; 40])).unwrap();
}

#[tokio::test(start_paused = true)]
async fn nothing_is_sent_before_the_peer_grants_credit() {
    let (mut local, io) = tokio::io::duplex(1024);
    let link = Link::new();
    let (peer, _peer_running) = pump(
        tokio::io::duplex(1024).1,
        Link::new(),
        StreamCredits {
            send: 0,
            granted: WINDOW,
        },
    );
    link.connect(&peer);
    let (control, running) = pump(
        io,
        link.clone(),
        StreamCredits {
            send: 0,
            granted: WINDOW,
        },
    );
    let _running = tokio::spawn(running);
    local.write_all(b"early").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(link.data_bytes.load(Ordering::SeqCst), 0);
    control.credit(5).unwrap();
    tokio::time::timeout(GUARD, async {
        while link.data_bytes.load(Ordering::SeqCst) < 5 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
