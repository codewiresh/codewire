//! A heartbeat for an event stream the dashboard writes itself (#4762).
//!
//! A proxy closes a response that sends nothing for long enough: Cloudflare
//! cuts a proxied one after about 100 s. The streams relayed from orchestration
//! carry its heartbeats; a stream whose events come from the dashboard, such as
//! a credential enrollment waiting on the provider, sends this comment instead.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::Bytes;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};

/// As orchestration's streams send theirs.
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_FRAME: &str = ": heartbeat\n\n";

/// `frames` as a response body, with a heartbeat comment after every interval
/// that sent nothing. It ends when `frames` ends or the browser leaves.
pub(crate) fn with_heartbeat<S>(frames: S) -> ReceiverStream<Result<Bytes, Infallible>>
where
    S: Stream<Item = Bytes> + Send + Unpin + 'static,
{
    let (body, receiver) = tokio::sync::mpsc::channel(2);
    tokio::spawn(async move {
        let mut frames = frames;
        let mut idle = tokio::time::interval_at(
            tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
            HEARTBEAT_INTERVAL,
        );
        // A send held up past an interval is followed by one heartbeat, not a burst.
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let frame = tokio::select! {
                () = body.closed() => return,
                frame = frames.next() => match frame {
                    Some(frame) => {
                        idle.reset();
                        frame
                    }
                    None => return,
                },
                _ = idle.tick() => Bytes::from_static(HEARTBEAT_FRAME.as_bytes()),
            };
            if body.send(Ok(frame)).await.is_err() {
                return;
            }
        }
    });
    ReceiverStream::new(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUND: Duration = Duration::from_secs(60);

    async fn next(stream: &mut ReceiverStream<Result<Bytes, Infallible>>) -> Option<String> {
        let frame = tokio::time::timeout(BOUND, stream.next())
            .await
            .expect("a frame or the end within the bound")?;
        let Ok(frame) = frame;
        Some(String::from_utf8(frame.to_vec()).expect("utf-8 frame"))
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_stream_sends_a_heartbeat_each_interval_and_events_pass_through() {
        let (events, frames) = tokio::sync::mpsc::channel(4);
        let mut stream = with_heartbeat(ReceiverStream::new(frames));
        events
            .send(Bytes::from_static(b"event: one\n\n"))
            .await
            .unwrap();
        assert_eq!(next(&mut stream).await.as_deref(), Some("event: one\n\n"));
        let before = tokio::time::Instant::now();
        assert_eq!(next(&mut stream).await.as_deref(), Some(HEARTBEAT_FRAME));
        assert_eq!(before.elapsed(), HEARTBEAT_INTERVAL);
        assert_eq!(next(&mut stream).await.as_deref(), Some(HEARTBEAT_FRAME));
        assert_eq!(before.elapsed(), HEARTBEAT_INTERVAL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_event_postpones_the_next_heartbeat() {
        let (events, frames) = tokio::sync::mpsc::channel(4);
        let mut stream = with_heartbeat(ReceiverStream::new(frames));
        tokio::time::sleep(HEARTBEAT_INTERVAL - Duration::from_secs(1)).await;
        events
            .send(Bytes::from_static(b"event: two\n\n"))
            .await
            .unwrap();
        assert_eq!(next(&mut stream).await.as_deref(), Some("event: two\n\n"));
        let sent = tokio::time::Instant::now();
        assert_eq!(next(&mut stream).await.as_deref(), Some(HEARTBEAT_FRAME));
        assert_eq!(sent.elapsed(), HEARTBEAT_INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn the_stream_ends_with_its_events() {
        let (events, frames) = tokio::sync::mpsc::channel(4);
        let mut stream = with_heartbeat(ReceiverStream::new(frames));
        events
            .send(Bytes::from_static(b"event: last\n\n"))
            .await
            .unwrap();
        drop(events);
        assert_eq!(next(&mut stream).await.as_deref(), Some("event: last\n\n"));
        assert_eq!(next(&mut stream).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_browser_that_leaves_stops_the_heartbeat() {
        let (events, frames) = tokio::sync::mpsc::channel(4);
        let stream = with_heartbeat(ReceiverStream::new(frames));
        drop(stream);
        // The relay lets go of its events at once, not at its next heartbeat.
        tokio::time::timeout(Duration::from_secs(1), events.closed())
            .await
            .expect("the relay lets go of its events");
    }
}
