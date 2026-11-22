//! cw-egress's admission (#4000): the stream listener, the guest's hello,
//! the start limit, orchestration's `Admit`, the stream key and the Pod's
//! assignment watch. Each admitted stream goes to the supervisor. A session
//! version cw-egress does not accept gets the one constant version answer;
//! every other refusal is a close with no answer.
//!
//! A start counts against the limit for its peer before anything is read, so
//! a flapping guest costs neither a token review nor an orchestration call.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_network_session::hosted::hello::{
    self, GuestHello, NONCE_LEN, PREFIX_LEN, TOKEN_LEN_LEN, VERSION_ANSWER, encode_answer,
};
use codewire_network_session::hosted::key::{StreamKeyInput, stream_key};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::admitted::AdmittedStream;
use crate::orchestration::{Admitted, Assignment, AssignmentError, CallError, Orchestration};
use crate::replacement::StartLimiter;
use crate::reporter::Reporter;

/// How long a guest has to send its hello, and cw-egress to answer it.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// The first wait before a lost assignment watch is opened again.
const WATCH_RETRY_MIN: Duration = Duration::from_secs(1);
/// The longest wait before a lost assignment watch is opened again.
const WATCH_RETRY_MAX: Duration = Duration::from_secs(30);

/// What admission asks orchestration: orchestration itself, or a test's.
pub trait Admits: Send + Sync + 'static {
    fn admit(
        &self,
        guest_token: &str,
        peer: IpAddr,
    ) -> impl Future<Output = Result<Admitted, CallError>> + Send;

    /// Follows the Pod's assignment until orchestration ends it.
    fn watch(
        &self,
        pod_uid: &str,
        pod_name: &str,
        on_change: impl FnMut(Result<Assignment, AssignmentError>) + Send,
    ) -> impl Future<Output = Result<(), CallError>> + Send;
}

impl Admits for Orchestration {
    fn admit(
        &self,
        guest_token: &str,
        peer: IpAddr,
    ) -> impl Future<Output = Result<Admitted, CallError>> + Send {
        Orchestration::admit(self, guest_token, peer)
    }

    fn watch(
        &self,
        pod_uid: &str,
        pod_name: &str,
        on_change: impl FnMut(Result<Assignment, AssignmentError>) + Send,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        Orchestration::watch(self, pod_uid, pod_name, on_change)
    }
}

/// Accepts guest streams until `stop` fires, then drops its sender, so the
/// supervisor returns once its last pair is gone.
pub async fn serve<A: Admits>(
    listener: TcpListener,
    admits: Arc<A>,
    reporter: Reporter,
    admitted: mpsc::Sender<AdmittedStream>,
    stop: CancellationToken,
) {
    let limiter = Arc::new(Mutex::new(StartLimiter::default()));
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "accepting a guest stream failed");
                        continue;
                    }
                };
                let started = limiter
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .allow(peer.ip(), std::time::Instant::now());
                if !started {
                    tracing::info!(%peer, "a guest stream was refused by the start limit");
                    continue;
                }
                tokio::spawn(admit_one(
                    stream,
                    peer,
                    Arc::clone(&admits),
                    reporter.clone(),
                    admitted.clone(),
                ));
            }
        }
    }
}

async fn admit_one<A: Admits>(
    mut stream: TcpStream,
    peer: SocketAddr,
    admits: Arc<A>,
    reporter: Reporter,
    admitted: mpsc::Sender<AdmittedStream>,
) {
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut stream)).await {
        Ok(Ok(hello)) => hello,
        Ok(Err(hello::HelloError::Version(version))) => {
            tracing::info!(%peer, version, "a guest stream speaks a session version cw-egress does not accept");
            // The guest learns why only if the answer arrives; it is closed
            // either way.
            let _ = tokio::time::timeout(HELLO_TIMEOUT, stream.write_all(&VERSION_ANSWER)).await;
            return;
        }
        _ => {
            tracing::info!(%peer, "a guest stream sent no valid hello");
            return;
        }
    };
    let admission = match admits.admit(&hello.token, peer.ip()).await {
        Ok(admission) => admission,
        Err(error) => {
            tracing::info!(%peer, %error, "orchestration did not admit a guest stream");
            return;
        }
    };
    let (assignment, pod_uid) = match (admission.assignment, Uuid::parse_str(&admission.pod_uid)) {
        (Ok(assignment), Ok(pod_uid)) => (assignment, pod_uid),
        (Err(error), _) => {
            tracing::warn!(%peer, pod = %admission.pod_uid, %error, "an admitted Pod's assignment does not parse");
            return;
        }
        (_, Err(_)) => {
            tracing::warn!(%peer, "orchestration admitted a stream without a Pod UID");
            return;
        }
    };
    let Ok(node_nonce) = nonce() else {
        tracing::warn!(%peer, "no nonce could be drawn for a guest stream");
        return;
    };
    let key = match stream_key(&StreamKeyInput {
        token: &hello.token,
        guest_nonce: &hello.nonce,
        node_nonce: &node_nonce,
        pod_uid,
    }) {
        Ok(key) => key,
        Err(_) => return,
    };
    let answer = encode_answer(&node_nonce);
    let answered = tokio::time::timeout(HELLO_TIMEOUT, stream.write_all(&answer)).await;
    if !matches!(answered, Ok(Ok(()))) {
        return;
    }
    // The watch starts from the assignment `Admit` returned.
    let (changes, assignment_changes) = watch::channel(Ok(assignment.clone()));
    tokio::spawn(follow_assignment(
        admits,
        admission.pod_uid,
        admission.pod_name.clone(),
        changes,
    ));
    let events = reporter.admit(pod_uid, admission.pod_name.clone());
    let stream_admitted = AdmittedStream {
        pod_uid,
        pod_name: admission.pod_name,
        peer,
        stream,
        key,
        assignment,
        trust: admission.trust,
        changes: assignment_changes,
        events,
    };
    // A supervisor that stopped taking streams closes the guest's.
    let _ = admitted.send(stream_admitted).await;
}

/// Reads the prefix alone before deciding on the version, so a version
/// refusal never depends on bytes after it.
async fn read_hello(stream: &mut TcpStream) -> Result<GuestHello, hello::HelloError> {
    let mut prefix = [0_u8; PREFIX_LEN];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| hello::HelloError::Magic)?;
    let version = hello::decode_prefix(&prefix)?;
    let mut token_len = [0_u8; TOKEN_LEN_LEN];
    stream
        .read_exact(&mut token_len)
        .await
        .map_err(|_| hello::HelloError::Magic)?;
    let mut body = vec![0_u8; hello::body_len(&token_len)?];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| hello::HelloError::Length {
            actual: 0,
            expected: body.len(),
        })?;
    hello::decode_body(version, &body)
}

/// Follows the Pod's assignment into `changes` until orchestration ends the
/// Pod or the supervisor drops the stream. Through an orchestration outage
/// the stream keeps its last assignment, and the watch is opened again. The
/// backoff starts over after a watch that delivered, so one outage doesn't
/// slow every later reopening.
async fn follow_assignment<A: Admits>(
    admits: Arc<A>,
    pod_uid: String,
    pod_name: String,
    changes: watch::Sender<Result<Assignment, AssignmentError>>,
) {
    let mut retry = WATCH_RETRY_MIN;
    loop {
        let mut delivered = false;
        let watched = tokio::select! {
            () = changes.closed() => return,
            watched = admits.watch(&pod_uid, &pod_name, |assignment| {
                delivered = true;
                // A receiver that is gone is noticed by `closed` above.
                let _ = changes.send(assignment);
            }) => watched,
        };
        if delivered {
            retry = WATCH_RETRY_MIN;
        }
        match watched {
            // Orchestration ended the Pod's stream: the Pod is gone, and the
            // closed channel tells the supervisor.
            Ok(()) | Err(CallError::Refused) => return,
            // A working stream reached its lifetime.
            Err(CallError::Expired) if delivered => {}
            Err(error) => {
                tracing::warn!(pod = %pod_uid, %error, "the assignment watch was lost; retrying");
                tokio::select! {
                    () = changes.closed() => return,
                    () = tokio::time::sleep(retry) => {}
                }
                retry = (retry * 2).min(WATCH_RETRY_MAX);
            }
        }
    }
}

/// A nonce from the kernel's random source, never reused across streams.
fn nonce() -> std::io::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    let mut filled = 0;
    while filled < NONCE_LEN {
        filled +=
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())?;
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests;
