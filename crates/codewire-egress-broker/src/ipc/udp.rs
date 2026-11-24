//! A guest UDP datagram the worker dropped, recorded as refused (#3997). It
//! travels on the admission session: recording it is a local policy step
//! that never waits on anything upstream, as an admission is.
//!
//! A report is best effort and never delays a TCP admission. It takes the
//! session only when it is idle at that moment and is dropped otherwise, so
//! it never queues for it: a browser's failed QUIC attempts must not hold
//! the session while its TCP fallback needs it. A session handed back goes
//! to a waiting admission first, never to a report.

use std::net::SocketAddr;
use std::sync::{Arc, PoisonError};

use tokio::net::UnixStream;
use tokio::time::Instant;

use super::late::LateOperation;
use super::{
    BROKER_IPC_TRANSACTION_TIMEOUT, BrokerIpcBinding, BrokerIpcClient, BrokerIpcError,
    BrokerIpcKey, CheckedOut, FRAME_KIND_RESPONSE, OP_REFUSE_UDP, STATUS_OK, SessionPool,
    decode_empty_response, encode_tcp_request, write_frame,
};

impl BrokerIpcClient {
    /// Has the broker record one dropped guest datagram to `destination`.
    /// `Ok` means it was recorded, or the broker keeps no record; nothing is
    /// ever sent to `destination`. [`BrokerIpcError::SessionBusy`] means the
    /// admission session was not idle, and the report was dropped unsent.
    pub async fn refuse_udp(&self, destination: SocketAddr) -> Result<(), BrokerIpcError> {
        let request = encode_tcp_request(OP_REFUSE_UDP, destination)?;
        let mut state = self
            .admission
            .try_checkout()
            .ok_or(BrokerIpcError::SessionBusy)?;
        let deadline = Instant::now() + BROKER_IPC_TRANSACTION_TIMEOUT;
        let response = self.count_late(
            state
                .request(&request, deadline, LateOperation::RefuseUdp)
                .await,
        )?;
        match decode_empty_response(&response, OP_REFUSE_UDP) {
            Ok(()) => Ok(()),
            Err(error) if error.is_valid_remote_result() => Err(error),
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }
}

impl SessionPool {
    /// An idle session now, or `None`, without waiting. A permit released
    /// while a request waits goes to that request, so this never takes a
    /// session ahead of one.
    fn try_checkout(self: &Arc<Self>) -> Option<CheckedOut> {
        let permit = Arc::clone(&self.available).try_acquire_owned().ok()?;
        let state = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()?;
        Some(CheckedOut {
            pool: Arc::clone(self),
            state: Some(state),
            permit: Some(permit),
        })
    }
}

/// The broker's answer to a recorded datagram.
pub(super) async fn write_refused(
    stream: &mut UnixStream,
    sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
) -> Result<(), BrokerIpcError> {
    let payload = [OP_REFUSE_UDP, STATUS_OK];
    write_frame(
        stream,
        FRAME_KIND_RESPONSE,
        sequence,
        binding,
        key,
        &payload,
    )
    .await
}
