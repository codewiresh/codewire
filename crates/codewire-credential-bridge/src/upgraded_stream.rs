//! An upgraded byte stream, such as a WebSocket after its `101`, carried as
//! bridge frames on a front-door session (#3999). Both ends of the session
//! use the same pump: the front door between its client and the session, the
//! broker between the session and the provider.
//!
//! The bytes are never read. Each side lets its peer send at most what it has
//! granted, [`CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES`] at first, and grants
//! more only as it writes bytes out, so a stalled reader holds one window of
//! its own stream and never the session's other requests or streams. Frames
//! from the peer are checked here; a frame past its credit, after its close,
//! or out of bounds is a protocol error for the caller to end the session on.
//!
//! The first grants travel outside the pump: the guest's in its
//! `CredentialBridgeUpgrade` (`initial_credit_bytes`), the host's as a
//! `StreamCredit` sent right after `UpgradeAccepted`. Each side starts its
//! pump with what it has granted and been granted so far.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES, CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Notify;

/// Credit is granted back in steps of this many written bytes. A peer that
/// has sent less than a step since the last grant still holds three quarters
/// of the window, so neither side waits on the other.
const GRANT_STEP: u32 = CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES / 4;
/// The most send credit a peer may grant ahead: a peer that grants without
/// bound is broken, and the counter must not wrap.
const MAX_SEND_CREDIT: u32 = 4 * CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;

/// A frame the pump sends to its peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamFrame {
    Data(Bytes),
    Credit(u32),
    Close(StreamClose),
}

/// How a direction of the stream ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamClose {
    /// The sender sends no more; it still reads what its peer sends.
    HalfClose,
    /// Both directions end at once, and unsent bytes are dropped.
    Reset,
}

/// Where the pump's frames go: the session, tagged with the stream's request.
pub trait StreamSink: Send + Sync + 'static {
    /// Send `frame`, waiting while the session's writer is busy. An error
    /// means the session is gone.
    fn send(&self, frame: StreamFrame) -> impl Future<Output = Result<(), ()>> + Send;
}

/// A peer frame this stream cannot take.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum StreamProtocolError {
    #[error("upgraded stream data is empty or larger than a chunk")]
    DataSize,
    #[error("upgraded stream data exceeds the credit granted")]
    OverCredit,
    #[error("upgraded stream frame after the peer closed")]
    AfterClose,
    #[error("upgraded stream credit is zero or beyond the bound")]
    Credit,
}

/// How the pump ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEnd {
    /// Both directions closed in order.
    Closed,
    /// The peer reset the stream, or [`StreamControl::abort`] was called; no
    /// frame was sent for it.
    Reset,
    /// The local stream or the session failed; a reset was sent if the
    /// session still took frames.
    Failed,
}

/// The credit each side holds when the pump starts, after the upgrade's own
/// frames: what the peer has granted this side, and what this side has
/// granted the peer.
#[derive(Clone, Copy, Debug)]
pub struct StreamCredits {
    pub send: u32,
    pub granted: u32,
}

/// Delivers the peer's frames to a running pump. Cloning shares the stream.
#[derive(Clone)]
pub struct StreamControl {
    shared: Arc<Shared>,
}

/// Waiters create their `Notified` before reading the state and are woken
/// with `notify_waiters`, so no wake-up is lost between the check and the
/// wait, and one direction's wake-up never goes to the other.
struct Shared {
    state: Mutex<State>,
    /// Wakes the side that writes the peer's bytes out.
    inbound: Notify,
    /// Wakes the side that sends local bytes to the peer.
    outbound: Notify,
}

struct State {
    buffer: VecDeque<Bytes>,
    /// Bytes the peer may still send.
    allowance: u32,
    /// Bytes this side may still send.
    send_credit: u32,
    peer_closed: bool,
    reset: bool,
}

impl StreamControl {
    /// The peer's data. It is held until written out; credit bounds it.
    pub fn deliver(&self, data: Bytes) -> Result<(), StreamProtocolError> {
        if data.is_empty() || data.len() > CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES {
            return Err(StreamProtocolError::DataSize);
        }
        let mut state = self.lock();
        if state.reset {
            // A frame that raced a local abort is dropped.
            return Ok(());
        }
        if state.peer_closed {
            return Err(StreamProtocolError::AfterClose);
        }
        let len = u32::try_from(data.len()).map_err(|_| StreamProtocolError::DataSize)?;
        state.allowance = state
            .allowance
            .checked_sub(len)
            .ok_or(StreamProtocolError::OverCredit)?;
        state.buffer.push_back(data);
        drop(state);
        self.shared.inbound.notify_waiters();
        Ok(())
    }

    /// The peer grants this side `bytes` more.
    pub fn credit(&self, bytes: u32) -> Result<(), StreamProtocolError> {
        let mut state = self.lock();
        if state.reset {
            return Ok(());
        }
        state.send_credit = state
            .send_credit
            .checked_add(bytes)
            .filter(|credit| bytes > 0 && *credit <= MAX_SEND_CREDIT)
            .ok_or(StreamProtocolError::Credit)?;
        drop(state);
        self.shared.outbound.notify_waiters();
        Ok(())
    }

    /// The peer closed its direction, or reset both.
    pub fn close(&self, kind: StreamClose) -> Result<(), StreamProtocolError> {
        let mut state = self.lock();
        match kind {
            StreamClose::Reset => state.reset = true,
            StreamClose::HalfClose if state.reset => {}
            StreamClose::HalfClose if state.peer_closed => {
                return Err(StreamProtocolError::AfterClose);
            }
            StreamClose::HalfClose => state.peer_closed = true,
        }
        drop(state);
        self.wake();
        Ok(())
    }

    /// End the pump without sending anything, as when the session is lost.
    pub fn abort(&self) {
        self.lock().reset = true;
        self.wake();
    }

    fn wake(&self) {
        self.shared.inbound.notify_waiters();
        self.shared.outbound.notify_waiters();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Carry `io` over the session through `sink`. Run the returned future for
/// the stream's lifetime, and route the peer's frames for it to the control;
/// dropping the future drops `io`. `credits.granted` is capped at the window.
pub fn pump<IO, S>(
    io: IO,
    sink: S,
    credits: StreamCredits,
) -> (StreamControl, impl Future<Output = StreamEnd> + Send)
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
    S: StreamSink,
{
    let control = StreamControl {
        shared: Arc::new(Shared {
            state: Mutex::new(State {
                buffer: VecDeque::new(),
                allowance: credits.granted.min(CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES),
                send_credit: credits.send.min(MAX_SEND_CREDIT),
                peer_closed: false,
                reset: false,
            }),
            inbound: Notify::new(),
            outbound: Notify::new(),
        }),
    };
    let running = run(io, sink, control.clone());
    (control, running)
}

/// Why one direction stopped early.
enum Stop {
    Reset,
    Failed,
}

async fn run<IO, S>(io: IO, sink: S, control: StreamControl) -> StreamEnd
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
    S: StreamSink,
{
    let (reader, writer) = tokio::io::split(io);
    let outbound = send_local(reader, &sink, &control);
    let inbound = write_peer(writer, &sink, &control);
    tokio::pin!(outbound, inbound);
    let (mut sent, mut written) = (false, false);
    let stop = loop {
        tokio::select! {
            result = &mut outbound, if !sent => match result {
                Ok(()) => sent = true,
                Err(stop) => break stop,
            },
            result = &mut inbound, if !written => match result {
                Ok(()) => written = true,
                Err(stop) => break stop,
            },
        }
        if sent && written {
            return StreamEnd::Closed;
        }
    };
    match stop {
        Stop::Reset => StreamEnd::Reset,
        Stop::Failed => {
            control.abort();
            let _ = sink.send(StreamFrame::Close(StreamClose::Reset)).await;
            StreamEnd::Failed
        }
    }
}

/// Local bytes to the peer, within its credit, then this side's half-close.
async fn send_local<R, S>(mut reader: R, sink: &S, control: &StreamControl) -> Result<(), Stop>
where
    R: AsyncRead + Unpin,
    S: StreamSink,
{
    let mut buffer = vec![0_u8; CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES];
    loop {
        let allowed = loop {
            let woken = control.shared.outbound.notified();
            {
                let state = control.lock();
                if state.reset {
                    return Err(Stop::Reset);
                }
                if state.send_credit > 0 {
                    break state.send_credit as usize;
                }
            }
            woken.await;
        };
        let limit = allowed.min(buffer.len());
        let read = tokio::select! {
            read = reader.read(&mut buffer[..limit]) => read.map_err(|_| Stop::Failed)?,
            () = reset(control) => return Err(Stop::Reset),
        };
        if read == 0 {
            return sink
                .send(StreamFrame::Close(StreamClose::HalfClose))
                .await
                .map_err(|_| Stop::Failed);
        }
        {
            let mut state = control.lock();
            if state.reset {
                return Err(Stop::Reset);
            }
            // `read` is at most the credit read above, which only grows.
            state.send_credit -= read as u32;
        }
        sink.send(StreamFrame::Data(Bytes::copy_from_slice(&buffer[..read])))
            .await
            .map_err(|_| Stop::Failed)?;
    }
}

/// The peer's bytes written out, granting credit back as they go, then the
/// local half-close once the peer has closed and everything is written.
async fn write_peer<W, S>(mut writer: W, sink: &S, control: &StreamControl) -> Result<(), Stop>
where
    W: AsyncWrite + Unpin,
    S: StreamSink,
{
    let mut written: u32 = 0;
    loop {
        let next = loop {
            let woken = control.shared.inbound.notified();
            {
                let mut state = control.lock();
                if state.reset {
                    return Err(Stop::Reset);
                }
                if let Some(chunk) = state.buffer.pop_front() {
                    break Some(chunk);
                }
                if state.peer_closed {
                    break None;
                }
            }
            woken.await;
        };
        let Some(chunk) = next else {
            return writer.shutdown().await.map_err(|_| Stop::Failed);
        };
        tokio::select! {
            result = writer.write_all(&chunk) => result.map_err(|_| Stop::Failed)?,
            () = reset(control) => return Err(Stop::Reset),
        }
        // A chunk is at most CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES.
        written += chunk.len() as u32;
        if written >= GRANT_STEP {
            let grant = std::mem::take(&mut written);
            {
                let mut state = control.lock();
                if state.peer_closed {
                    // A peer that sends no more needs no credit.
                    continue;
                }
                state.allowance += grant;
            }
            sink.send(StreamFrame::Credit(grant))
                .await
                .map_err(|_| Stop::Failed)?;
        }
    }
}

/// Resolves once the stream is reset, by the peer or by an abort.
async fn reset(control: &StreamControl) {
    loop {
        let inbound = control.shared.inbound.notified();
        let outbound = control.shared.outbound.notified();
        if control.lock().reset {
            return;
        }
        tokio::select! {
            () = inbound => {}
            () = outbound => {}
        }
    }
}

#[cfg(test)]
mod tests;
