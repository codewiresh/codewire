//! A guest UDP datagram the worker dropped, recorded as refused (#3997). It
//! travels on the admission session: recording it is a local policy step
//! that never waits on anything upstream, as an admission is.

use std::net::SocketAddr;

use tokio::net::UnixStream;
use tokio::time::Instant;

use super::late::LateOperation;
use super::{
    BROKER_IPC_TRANSACTION_TIMEOUT, BrokerIpcBinding, BrokerIpcClient, BrokerIpcError,
    BrokerIpcKey, FRAME_KIND_RESPONSE, OP_REFUSE_UDP, STATUS_OK, decode_empty_response,
    encode_tcp_request, write_frame,
};

impl BrokerIpcClient {
    /// Has the broker record one dropped guest datagram to `destination`.
    /// `Ok` means it was recorded, or the broker keeps no record; nothing is
    /// ever sent to `destination`.
    pub async fn refuse_udp(&self, destination: SocketAddr) -> Result<(), BrokerIpcError> {
        let request = encode_tcp_request(OP_REFUSE_UDP, destination)?;
        let mut state = self.admission.checkout().await?;
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
