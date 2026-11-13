//! Streamed request bodies on the host side (#4280). A request marked
//! `streamed_body` is answered like any other, but its body arrives in
//! `CredentialBridgeRequestBody` frames that feed the provider request as a
//! stream. The host grants frames as credit: one window
//! ([`CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES`]) when the request starts
//! and one more for each frame handed upstream, so a request never queues more
//! than a window here.
//!
//! The bounds are time, not size, and they live here because only this layer
//! sees both the guest's frames and the provider's bytes:
//! - no body frame for [`CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT`] fails the body;
//! - no body frame taken by the provider for the idle bound fails the request,
//!   so a provider that stops reading mid-body (its write blocked, the body
//!   stream never polled) cannot hold the request and its connection, and a
//!   guest's cancel takes effect within the bound;
//! - after the body ends, the response must start within
//!   [`CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT`];
//! - no response byte for the idle bound fails the response.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT, CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES,
    CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
    CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT,
};
use futures::stream;
use tokio::sync::{Notify, mpsc, oneshot};

use super::{BrokerRequestExecutor, CredentialBridgeResponseSink};
use crate::{BrokerHttpResponse, BrokerRequestBodyStream, BrokerRequestError};

/// The receiving end of one streamed body, held by the request's ledger
/// entry. Dropping it without [`Self::end`] fails the body.
pub(super) struct BodyFeed {
    frames: mpsc::Sender<Vec<u8>>,
    ended: Arc<AtomicBool>,
}

/// The body's frames, for the request's task. The channel holds exactly one
/// window, so a frame past the credit finds it full.
pub(super) struct BodyFrames {
    frames: mpsc::Receiver<Vec<u8>>,
    ended: Arc<AtomicBool>,
}

impl BodyFeed {
    pub(super) fn new() -> (Self, BodyFrames) {
        let (sender, receiver) =
            mpsc::channel(CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES as usize);
        let ended = Arc::new(AtomicBool::new(false));
        (
            Self {
                frames: sender,
                ended: Arc::clone(&ended),
            },
            BodyFrames {
                frames: receiver,
                ended,
            },
        )
    }

    /// Queue one frame. An empty or oversized frame, or one past the credit
    /// granted, is a protocol violation. A frame for a body whose request
    /// already stopped reading is dropped.
    pub(super) fn push(&self, data: Vec<u8>) -> Result<(), ()> {
        if data.is_empty() || data.len() > CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES {
            return Err(());
        }
        match self.frames.try_send(data) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(()),
        }
    }

    /// The body is complete: its frames end once the queued ones are read.
    pub(super) fn end(self) {
        self.ended.store(true, Ordering::Release);
    }
}

/// Run a streamed request: grant the first window, feed the body to the
/// executor, and bound the wait for the response once the body is complete.
pub(super) async fn execute<E, S>(
    broker: &E,
    sender: &S,
    request_id: &str,
    request: v1::CredentialBridgeRequest,
    frames: BodyFrames,
) -> Result<BrokerHttpResponse, BrokerRequestError>
where
    E: BrokerRequestExecutor + ?Sized,
    S: CredentialBridgeResponseSink,
{
    grant(
        sender,
        request_id,
        CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
    )
    .await
    .map_err(|()| BrokerRequestError::AuthorityUnavailable)?;
    let (complete, mut completed) = oneshot::channel();
    let progress = Arc::new(Progress::default());
    let body = body_stream(
        frames,
        sender.clone(),
        request_id.to_owned(),
        complete,
        Arc::clone(&progress),
    );
    let bound = async {
        // While the body flows, each frame the provider takes restarts the
        // idle bound, and a provider waiting on the guest is bounded by the
        // body itself. The body's own failures fail the request on their own.
        loop {
            tokio::select! {
                biased;
                completed = &mut completed => match completed {
                    Ok(()) => break,
                    Err(_) => std::future::pending::<()>().await,
                },
                () = progress.taken.notified() => {}
                () = tokio::time::sleep(CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT) => {
                    if !progress.reading.load(Ordering::Acquire) {
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT).await;
    };
    tokio::select! {
        response = broker.execute_streamed_request(request, body) => response,
        () = bound => Err(BrokerRequestError::UpstreamFailed),
    }
}

/// The idle bound on a streamed request's response body, or none for a request
/// whose body was whole.
pub(super) fn response_idle(streamed: bool) -> Option<Duration> {
    streamed.then_some(CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT)
}

async fn grant<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: &str,
    frames: u32,
) -> Result<(), ()> {
    sender
        .send(v1::credential_bridge_host_message::Payload::RequestCredit(
            v1::CredentialBridgeRequestCredit {
                request_id: request_id.to_owned(),
                frames,
            },
        ))
        .await
        .map_err(|_| ())
}

/// What the provider does with the body, for the bound on a provider that
/// stops reading it.
#[derive(Default)]
struct Progress {
    /// Told of each frame handed to the provider.
    taken: Notify,
    /// The provider is waiting for the guest's next frame.
    reading: AtomicBool,
}

struct BodyState<S> {
    frames: BodyFrames,
    sender: S,
    request_id: String,
    complete: Option<oneshot::Sender<()>>,
    progress: Arc<Progress>,
    failed: bool,
}

/// The provider request's body: each frame as it arrives, one credit granted
/// back for each. It fails, rather than ends, when the guest's frames stop for
/// the idle bound or stop without an end.
fn body_stream<S: CredentialBridgeResponseSink>(
    frames: BodyFrames,
    sender: S,
    request_id: String,
    complete: oneshot::Sender<()>,
    progress: Arc<Progress>,
) -> BrokerRequestBodyStream {
    let state = BodyState {
        frames,
        sender,
        request_id,
        complete: Some(complete),
        progress,
        failed: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        if state.failed || state.complete.is_none() {
            return None;
        }
        state.progress.reading.store(true, Ordering::Release);
        let received = tokio::time::timeout(
            CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT,
            state.frames.frames.recv(),
        )
        .await;
        state.progress.reading.store(false, Ordering::Release);
        let failure = match received {
            Ok(Some(data)) => {
                if grant(&state.sender, &state.request_id, 1).await.is_ok() {
                    state.progress.taken.notify_one();
                    return Some((Ok(Bytes::from(data)), state));
                }
                io::Error::new(io::ErrorKind::BrokenPipe, "credential bridge was lost")
            }
            Ok(None) if state.frames.ended.load(Ordering::Acquire) => {
                if let Some(complete) = state.complete.take() {
                    let _ = complete.send(());
                }
                return None;
            }
            Ok(None) => io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "credential bridge request body ended without completion",
            ),
            Err(_) => io::Error::new(
                io::ErrorKind::TimedOut,
                "credential bridge request body was idle",
            ),
        };
        state.failed = true;
        Some((Err(failure), state))
    }))
}

#[cfg(test)]
mod tests;
