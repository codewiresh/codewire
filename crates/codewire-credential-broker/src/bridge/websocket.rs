//! WebSocket sockets on a front-door session (#3999).
//!
//! A handshake is served like a request and holds one of the session's
//! in-flight slots until the provider answers. A refusal is answered as a
//! reply. A `101` becomes an open socket: the guest is sent `UpgradeAccepted`
//! and a window of credit, and the socket moves to the session's own map of
//! at most [`MAX_OPEN_SOCKETS`], leaving the in-flight slot. Its bytes run
//! through [`codewire_credential_bridge::upgraded_stream`], the one pump both
//! ends of the session use, so a socket whose reader stalls holds one window
//! and never the session's other requests or sockets.
//!
//! A socket opened with this environment's credential is leased again every
//! [`RELEASE_EVERY`]; a refused lease, an error or another credential resets
//! it. Every socket ends with the session.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_credential_bridge::upgraded_stream::{
    StreamClose, StreamControl, StreamCredits, StreamEnd, StreamFrame, StreamSink, pump,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;
use codewire_daemon_proto::codewire::bridge::v1;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{
    BrokerRequestExecutor, CredentialBridgeResponseSink, finish_with_failure,
    response_headers_to_proto, send_failure, send_response,
};
use crate::runtime::upgrade::{BrokerUpgradeOutcome, SocketGrant};
use crate::{BrokerRequestError, timing};

/// The open sockets one session carries at once, apart from its requests.
pub(super) const MAX_OPEN_SOCKETS: usize = 16;
/// How often a socket opened with this environment's credential is leased
/// again.
pub(super) const RELEASE_EVERY: Duration = Duration::from_secs(30);
/// How long that lease may take. An authority that does not answer in time
/// counts as a refusal, so a socket never outlives its grant by more.
pub(super) const RELEASE_WITHIN: Duration = Duration::from_secs(5);

/// A socket's run, handed to the session's runner, which owns it and ends it
/// with the session. It resolves to the socket's request id.
pub(super) struct SocketRun {
    request_id: String,
    run: Pin<Box<dyn Future<Output = String> + Send>>,
}

/// The session's open sockets, for routing the guest's stream frames.
#[derive(Clone, Default)]
pub(super) struct Sockets(Arc<Mutex<HashMap<String, StreamControl>>>);

impl Sockets {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, StreamControl>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn get(&self, request_id: &str) -> Option<StreamControl> {
        self.lock().get(request_id).cloned()
    }

    pub(super) fn remove(&self, request_id: &str) {
        self.lock().remove(request_id);
    }

    /// Admit a socket unless the session already carries its limit.
    fn admit(&self, request_id: &str, control: StreamControl) -> bool {
        let mut sockets = self.lock();
        if sockets.len() >= MAX_OPEN_SOCKETS {
            return false;
        }
        sockets.insert(request_id.to_owned(), control);
        true
    }

    pub(super) fn contains(&self, request_id: &str) -> bool {
        self.lock().contains_key(request_id)
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    /// Route one of the guest's stream frames. A frame for a socket that has
    /// ended is dropped by the caller; one this session never opened, or one
    /// past its bounds, is a protocol error.
    pub(super) fn apply(
        &self,
        payload: v1::credential_bridge_guest_message::Payload,
    ) -> Result<bool, ()> {
        use v1::credential_bridge_guest_message::Payload;
        let request_id = match &payload {
            Payload::StreamData(data) => &data.request_id,
            Payload::StreamCredit(credit) => &credit.request_id,
            Payload::StreamClose(close) => &close.request_id,
            _ => return Err(()),
        };
        let Some(control) = self.get(request_id) else {
            return Ok(false);
        };
        let applied = match payload {
            Payload::StreamData(data) => control.deliver(data.data.into()),
            Payload::StreamCredit(credit) => control.credit(credit.credit_bytes),
            Payload::StreamClose(close) => {
                let kind = match v1::CredentialBridgeStreamCloseKind::try_from(close.kind) {
                    Ok(v1::CredentialBridgeStreamCloseKind::HalfClose) => StreamClose::HalfClose,
                    Ok(v1::CredentialBridgeStreamCloseKind::Reset) => StreamClose::Reset,
                    _ => return Err(()),
                };
                control.close(kind)
            }
            _ => return Err(()),
        };
        applied.map(|()| true).map_err(|_| ())
    }
}

/// Sockets that ended recently, whose late frames are dropped: a peer that
/// sent before it saw the end may still have a window of frames in flight.
const ENDED_KEPT: usize = 2 * MAX_OPEN_SOCKETS;

/// A session's sockets and their runs, owned by its runner: dropping it
/// ends every socket.
pub(super) struct SocketRuns {
    sockets: Sockets,
    opened: mpsc::Sender<SocketRun>,
    opened_runs: mpsc::Receiver<SocketRun>,
    runs: JoinSet<String>,
    /// Handshakes answered by no one yet: each may still become a socket.
    handshakes: Arc<std::sync::atomic::AtomicUsize>,
    /// Each run's socket, for a run that panics and so returns no id.
    run_sockets: HashMap<tokio::task::Id, String>,
    ended: VecDeque<String>,
}

impl SocketRuns {
    pub(super) fn new() -> Self {
        let (opened, opened_runs) = mpsc::channel(MAX_OPEN_SOCKETS);
        Self {
            sockets: Sockets::default(),
            opened,
            opened_runs,
            runs: JoinSet::new(),
            handshakes: Arc::default(),
            run_sockets: HashMap::new(),
            ended: VecDeque::new(),
        }
    }

    /// Start a socket a handshake opened, or retire one that ended. Never
    /// resolves while there is neither.
    pub(super) async fn step(&mut self) {
        tokio::select! {
            Some(run) = self.opened_runs.recv() => {
                let request_id = run.request_id.clone();
                let started = self.runs.spawn(run.run);
                self.run_sockets.insert(started.id(), request_id);
            }
            Some(ended) = self.runs.join_next_with_id(), if !self.runs.is_empty() => {
                let task = match &ended {
                    Ok((task, _)) => *task,
                    Err(error) => error.id(),
                };
                if let Some(request_id) = self.run_sockets.remove(&task) {
                    self.sockets.remove(&request_id);
                    if self.ended.len() == ENDED_KEPT {
                        self.ended.pop_front();
                    }
                    self.ended.push_back(request_id);
                }
            }
        }
    }

    /// Whether `request_id` names a socket this session carries now.
    pub(super) fn contains(&self, request_id: &str) -> bool {
        self.sockets.contains(request_id)
    }

    /// Whether open sockets and the handshakes that may become sockets have
    /// reached the limit: a new handshake is then refused before any lease.
    pub(super) fn full(&self) -> bool {
        self.in_use() >= MAX_OPEN_SOCKETS
    }

    /// Open sockets plus the handshakes that may become sockets.
    pub(super) fn in_use(&self) -> usize {
        self.sockets.len() + self.handshakes.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The handshake's task, run like a request's.
    pub(super) fn handshake<E, S>(
        &self,
        broker: Arc<E>,
        sender: S,
        upgrade: v1::CredentialBridgeUpgrade,
    ) -> impl Future<Output = Result<(), ()>> + Send + 'static
    where
        E: BrokerRequestExecutor + 'static,
        S: CredentialBridgeResponseSink,
    {
        let sockets = self.sockets.clone();
        let opened = self.opened.clone();
        let pending = Handshake::start(Arc::clone(&self.handshakes));
        async move {
            let served = serve_upgrade(broker, &sender, &sockets, &opened, upgrade).await;
            drop(pending);
            served
        }
    }

    /// Route one of the guest's stream frames. One for a socket that just
    /// ended is dropped; one for a socket never opened, or past its bounds,
    /// is a protocol error.
    pub(super) fn route(
        &self,
        payload: v1::credential_bridge_guest_message::Payload,
    ) -> Result<(), ()> {
        use v1::credential_bridge_guest_message::Payload;
        let request_id = match &payload {
            Payload::StreamData(data) => data.request_id.clone(),
            Payload::StreamCredit(credit) => credit.request_id.clone(),
            Payload::StreamClose(close) => close.request_id.clone(),
            _ => return Err(()),
        };
        match self.sockets.apply(payload)? {
            true => Ok(()),
            false if self.ended.contains(&request_id) => Ok(()),
            false => Err(()),
        }
    }
}

/// One handshake counted until its task ends, however it ends.
struct Handshake(Arc<std::sync::atomic::AtomicUsize>);

impl Handshake {
    fn start(count: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(count)
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Sends one socket's frames on the session, tagged with its request.
struct HostStreamSink<S> {
    sender: S,
    request_id: String,
}

impl<S: CredentialBridgeResponseSink> StreamSink for HostStreamSink<S> {
    async fn send(&self, frame: StreamFrame) -> Result<(), ()> {
        use v1::credential_bridge_host_message::Payload;
        let request_id = self.request_id.clone();
        let payload = match frame {
            StreamFrame::Data(data) => Payload::StreamData(v1::CredentialBridgeStreamData {
                request_id,
                data: data.to_vec(),
            }),
            StreamFrame::Credit(credit_bytes) => {
                Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
                    request_id,
                    credit_bytes,
                })
            }
            StreamFrame::Close(kind) => Payload::StreamClose(v1::CredentialBridgeStreamClose {
                request_id,
                kind: match kind {
                    StreamClose::HalfClose => v1::CredentialBridgeStreamCloseKind::HalfClose,
                    StreamClose::Reset => v1::CredentialBridgeStreamCloseKind::Reset,
                }
                .into(),
            }),
        };
        self.sender.send(payload).await.map_err(|_| ())
    }
}

/// Serve one handshake. A switched socket is handed to the runner through
/// `opened`; this returns once the handshake is answered, freeing its
/// in-flight slot.
pub(super) async fn serve_upgrade<E, S>(
    broker: Arc<E>,
    sender: &S,
    sockets: &Sockets,
    opened: &mpsc::Sender<SocketRun>,
    upgrade: v1::CredentialBridgeUpgrade,
) -> Result<(), ()>
where
    E: BrokerRequestExecutor + 'static,
    S: CredentialBridgeResponseSink,
{
    let request_id = upgrade.request_id.clone();
    let send_credit = upgrade
        .initial_credit_bytes
        .min(CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES);
    let upgraded = crate::credential_uses::scoped(broker.execute_upgrade(upgrade)).await;
    let (headers, stream, grant) = match upgraded {
        Err(error) => return finish_with_failure(sender, request_id, error).await,
        Ok(BrokerUpgradeOutcome::Response(response)) => {
            return send_response(sender, &request_id, response, None).await;
        }
        Ok(BrokerUpgradeOutcome::Switched {
            headers,
            stream,
            grant,
        }) => (headers, stream, grant),
    };
    let headers = match response_headers_to_proto(&headers) {
        Ok(headers) => headers,
        Err(error) => return send_failure(sender, request_id, error).await,
    };
    let sink = HostStreamSink {
        sender: sender.clone(),
        request_id: request_id.clone(),
    };
    let (control, running) = pump(
        stream,
        sink,
        StreamCredits {
            send: send_credit,
            granted: CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
        },
    );
    // Admitted before the guest learns of the socket, so its first frame
    // finds it.
    if !sockets.admit(&request_id, control.clone()) {
        timing::capacity_rejected(
            "bridge_open_sockets",
            "websocket",
            MAX_OPEN_SOCKETS,
            MAX_OPEN_SOCKETS,
        );
        return send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable).await;
    }
    use v1::credential_bridge_host_message::Payload;
    let accepted = async {
        sender
            .send(Payload::UpgradeAccepted(
                v1::CredentialBridgeUpgradeAccepted {
                    request_id: request_id.clone(),
                    headers,
                },
            ))
            .await?;
        sender
            .send(Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
                request_id: request_id.clone(),
                credit_bytes: CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
            }))
            .await
    };
    if accepted.await.is_err() {
        sockets.remove(&request_id);
        return Err(());
    }
    tracing::debug!(request_id, swapped = grant.is_some(), "WebSocket opened");
    let reset = HostStreamSink {
        sender: sender.clone(),
        request_id: request_id.clone(),
    };
    let run = SocketRun {
        request_id: request_id.clone(),
        run: Box::pin(run_socket(broker, control, running, grant, reset)),
    };
    // A runner that has ended drops the socket with it.
    let _ = opened.send(run).await;
    Ok(())
}

/// A socket until either end closes it or its grant lapses. A lapsed grant
/// resets the socket at both ends.
async fn run_socket<E, S>(
    broker: Arc<E>,
    control: StreamControl,
    running: impl Future<Output = StreamEnd> + Send,
    grant: Option<SocketGrant>,
    reset: HostStreamSink<S>,
) -> String
where
    E: BrokerRequestExecutor + 'static,
    S: CredentialBridgeResponseSink,
{
    let request_id = reset.request_id.clone();
    let lapsed = async {
        let Some(grant) = grant else {
            return std::future::pending().await;
        };
        loop {
            tokio::time::sleep(RELEASE_EVERY).await;
            let holds = tokio::time::timeout(RELEASE_WITHIN, broker.socket_grant_holds(&grant));
            if !matches!(holds.await, Ok(true)) {
                return;
            }
        }
    };
    tokio::select! {
        end = running => {
            tracing::debug!(request_id, ?end, "WebSocket closed");
        }
        () = lapsed => {
            tracing::info!(request_id, "WebSocket reset: its credential no longer leases");
            control.abort();
            let _ = reset.send(StreamFrame::Close(StreamClose::Reset)).await;
        }
    }
    request_id
}

#[cfg(test)]
mod tests;
