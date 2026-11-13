//! Ending a public response stream when its server restarts (#4426).
//!
//! A draining replica ends the streams its clients re-attach to as soon as it
//! begins, so they move to the next replica at once. Every other stream it
//! still serves ends at a deadline before the replica is killed. Either way
//! the client gets `unavailable`, an error it can retry, where the kill would
//! have left it a protocol reset.

use std::future::Future;
use std::pin::Pin;

use connectrpc::{ConnectError, ServiceStream};
use futures::{Stream, StreamExt as _};

/// The moment of a restart at which a stream ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    /// The replica begins draining: streams whose clients re-attach.
    Begins,
    /// The drain's deadline, before the replica is killed: every other
    /// stream still open.
    Deadline,
}

/// Completes once the server reaches a [`Restart`] moment.
pub type RestartSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `stream` until `signal` completes, then one `unavailable` error with
/// `message`, and the end. Without a signal, `stream` unchanged.
pub fn end_at<T: Send + 'static>(
    stream: impl Stream<Item = Result<T, ConnectError>> + Send + 'static,
    signal: Option<RestartSignal>,
    message: &'static str,
) -> ServiceStream<T> {
    let Some(signal) = signal else {
        return Box::pin(stream);
    };
    let stream = Box::pin(stream);
    Box::pin(futures::stream::unfold(
        Some((stream, signal)),
        move |state| async move {
            let (mut stream, mut signal) = state?;
            // The restart is checked first: a stream that always has its
            // next item ready, a fast download, must still end at it.
            tokio::select! {
                biased;
                () = &mut signal => Some((Err(ConnectError::unavailable(message)), None)),
                item = stream.next() => item.map(|item| (item, Some((stream, signal)))),
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;

    fn signal(rx: oneshot::Receiver<()>) -> Option<RestartSignal> {
        Some(Box::pin(async move {
            // A dropped sender is a restart too; the fixture never drops it.
            let _ = rx.await;
        }))
    }

    #[tokio::test]
    async fn a_stream_passes_through_until_the_restart_then_ends_unavailable() {
        let (items, received) = mpsc::channel::<Result<u32, ConnectError>>(4);
        let (restart, restarted) = oneshot::channel();
        let mut stream = end_at(
            ReceiverStream::new(received),
            signal(restarted),
            "restarting",
        );
        items.send(Ok(1)).await.expect("send");
        assert_eq!(stream.next().await.expect("item").expect("ok"), 1);
        restart.send(()).expect("restart");
        let error = stream
            .next()
            .await
            .expect("error")
            .expect_err("unavailable");
        assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
        assert_eq!(error.message.as_deref(), Some("restarting"));
        assert!(stream.next().await.is_none());
        assert!(
            items.is_closed(),
            "the inner stream is dropped at the restart"
        );
    }

    #[tokio::test]
    async fn a_stream_that_is_always_ready_still_ends_at_the_restart() {
        let (restart, restarted) = oneshot::channel();
        let mut stream = end_at(
            futures::stream::repeat_with(|| Ok::<_, ConnectError>(1)),
            signal(restarted),
            "restarting",
        );
        assert!(stream.next().await.expect("item").is_ok());
        restart.send(()).expect("restart");
        let error = stream
            .next()
            .await
            .expect("error")
            .expect_err("unavailable");
        assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn a_stream_that_ends_first_ends_normally() {
        let (_restart, restarted) = oneshot::channel::<()>();
        let mut stream = end_at(
            futures::stream::iter([Ok::<_, ConnectError>(7)]),
            signal(restarted),
            "restarting",
        );
        assert_eq!(stream.next().await.expect("item").expect("ok"), 7);
        assert!(stream.next().await.is_none());
    }
}
