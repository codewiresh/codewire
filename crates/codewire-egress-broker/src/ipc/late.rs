//! A request whose answer misses its deadline (#4948). The request is refused
//! on time, but its session is not retired: a task waits for that answer,
//! checks it as it would any answer, and only then gives the session back. A
//! broker that answers late, as one whose only thread stalled, so costs one
//! request instead of every session.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout, timeout_at};

use super::{
    BrokerIpcClient, BrokerIpcError, CheckedOut, ClientState, DnsRecordFamily, FRAME_KIND_RESPONSE,
    OP_AUTHORIZE_TCP, OP_CONNECT_TCP, OP_REFUSE_UDP, STATUS_INTERCEPTED, SessionPool,
    decode_dns_response, decode_empty_response, read_client_exact, read_client_frame,
    receive_descriptor,
};

/// Once an answer starts to arrive, the rest of its frame follows within this,
/// or the session is retired.
const BROKER_IPC_FRAME_TIMEOUT: Duration = Duration::from_secs(2);

/// What a session still has to read after its request missed the deadline.
#[derive(Clone, Copy, Debug)]
pub(super) enum LateAnswer {
    /// The response frame with this sequence.
    Frame {
        sequence: u64,
        operation: LateOperation,
    },
    /// A connect's descriptor, after its response frame was read.
    Descriptor,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum LateOperation {
    Dns(DnsRecordFamily),
    Authorize,
    Connect,
    RefuseUdp,
}

impl ClientState {
    /// The answer to request `sequence`. The deadline may end only the wait
    /// for its first byte: a one-byte read is cancelled only before it reads
    /// anything, so a request that misses the deadline leaves the whole answer
    /// for the session to wait for.
    pub(super) async fn read_answer(
        &mut self,
        sequence: u64,
        deadline: Instant,
        operation: LateOperation,
    ) -> Result<Vec<u8>, BrokerIpcError> {
        let mut first = [0_u8; 1];
        let Ok(started) = timeout_at(deadline, read_client_exact(&self.stream, &mut first)).await
        else {
            self.late = Some(LateAnswer::Frame {
                sequence,
                operation,
            });
            return Err(BrokerIpcError::Late);
        };
        started.map_err(|_| BrokerIpcError::FrameIo)?;
        timeout(
            BROKER_IPC_FRAME_TIMEOUT,
            read_client_frame(
                &mut self.stream,
                Some(first[0]),
                FRAME_KIND_RESPONSE,
                sequence,
                self.binding,
                &self.key,
            ),
        )
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?
    }

    /// A connect's descriptor by `deadline`. Nothing of it is read before
    /// then, so past it the session waits for the descriptor and closes it.
    pub(super) async fn receive_descriptor_by(
        &mut self,
        deadline: Instant,
    ) -> Result<OwnedFd, BrokerIpcError> {
        let Ok(received) = timeout_at(deadline, receive_descriptor(&self.stream)).await else {
            self.late = Some(LateAnswer::Descriptor);
            return Err(BrokerIpcError::Late);
        };
        received
    }

    /// Read the answer a request gave up on. Anything but that authenticated
    /// answer, and a connect's one descriptor, fails as any answer would.
    async fn receive_late(&mut self, late: LateAnswer) -> Result<(), BrokerIpcError> {
        let LateAnswer::Frame {
            sequence,
            operation,
        } = late
        else {
            return receive_descriptor(&self.stream).await.map(drop);
        };
        let response = read_client_frame(
            &mut self.stream,
            None,
            FRAME_KIND_RESPONSE,
            sequence,
            self.binding,
            &self.key,
        )
        .await?;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(BrokerIpcError::SequenceExhausted)?;
        let decoded = match operation {
            LateOperation::Dns(family) => decode_dns_response(&response, family).map(drop),
            LateOperation::Authorize => decode_empty_response(&response, OP_AUTHORIZE_TCP),
            LateOperation::RefuseUdp => decode_empty_response(&response, OP_REFUSE_UDP),
            LateOperation::Connect if response == [OP_CONNECT_TCP, STATUS_INTERCEPTED] => Ok(()),
            LateOperation::Connect => decode_empty_response(&response, OP_CONNECT_TCP),
        };
        match decoded {
            // A connect that was answered passes its descriptor next; closing
            // it ends that connection.
            Ok(()) if matches!(operation, LateOperation::Connect) => {
                receive_descriptor(&self.stream).await.map(drop)
            }
            Ok(()) => Ok(()),
            Err(error) if error.is_valid_remote_result() => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// A session being given back. One whose request left its answer unread goes
/// to a task that waits for that answer, and `None` comes back; any other, or
/// one dropped outside a runtime, comes back to be returned or retired.
pub(super) fn wait_for_late_answer(
    pool: &Arc<SessionPool>,
    mut state: ClientState,
    permit: OwnedSemaphorePermit,
) -> Option<(ClientState, OwnedSemaphorePermit)> {
    let Some(late) = state.late.take() else {
        return Some((state, permit));
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return Some((state, permit));
    };
    let session = CheckedOut {
        pool: Arc::clone(pool),
        state: Some(state),
        permit: Some(permit),
    };
    runtime.spawn(drain_late_answer(session, late));
    None
}

/// Wait for a late answer, then give the session back if it is in step.
async fn drain_late_answer(mut session: CheckedOut, late: LateAnswer) {
    if session.receive_late(late).await.is_ok() {
        session.failed = false;
    }
}

/// The client's late answers: how many requests were refused because the
/// broker's answer missed its deadline, and since when it has been refusing.
#[derive(Debug, Default)]
pub(super) struct LateAnswers {
    count: AtomicU64,
    refusing_since: Mutex<Option<Instant>>,
}

/// What a client reports about its late answers (#4965): how many in all,
/// and how long it has been refusing, while no request since has been
/// answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LateAnswerStatus {
    pub late_answers: u64,
    pub refusing_for: Option<Duration>,
}

impl BrokerIpcClient {
    /// Requests refused because the broker's answer missed its deadline, for
    /// the refusal log (#4948).
    pub fn late_answers(&self) -> u64 {
        self.late.count.load(Ordering::Relaxed)
    }

    /// The late answers and how long the client has been refusing, for the
    /// owner's "egress unavailable" line (#4965).
    pub fn late_answer_status(&self) -> LateAnswerStatus {
        let refusing_since = *self
            .late
            .refusing_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        LateAnswerStatus {
            late_answers: self.late_answers(),
            refusing_for: refusing_since.map(|since| since.elapsed()),
        }
    }

    /// Count a late answer, and note when refusing began. An answer in time,
    /// whatever it says, ends it; a session's own failure is neither.
    pub(super) fn count_late<T>(
        &self,
        result: Result<T, BrokerIpcError>,
    ) -> Result<T, BrokerIpcError> {
        let late = matches!(result, Err(BrokerIpcError::Late));
        if late {
            self.late.count.fetch_add(1, Ordering::Relaxed);
        }
        let answered = matches!(
            result,
            Ok(_)
                | Err(BrokerIpcError::Denied
                    | BrokerIpcError::RemoteUnavailable
                    | BrokerIpcError::RemoteMalformed)
        );
        if late || answered {
            let mut since = self
                .late
                .refusing_since
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *since = late.then(|| since.unwrap_or_else(Instant::now));
        }
        result
    }
}
