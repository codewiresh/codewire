//! Reading a local guest daemon's recent log from the host.

use tonic::Status;

use super::{SessionClient, SessionClientError, v1};

/// Room for the protobuf framing around the log bytes.
const FRAMING_BYTES: usize = 64;

impl SessionClient {
    /// The daemon's recent log lines, refusing an answer over
    /// `maximum_bytes`: the caller is outside the guest and doesn't trust it
    /// with its memory. `Status` with `Unimplemented` from a daemon that
    /// keeps no log.
    pub async fn read_daemon_log(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, SessionClientError> {
        let mut client = self
            .inner
            .clone()
            .max_decoding_message_size(maximum_bytes.saturating_add(FRAMING_BYTES));
        let data = client
            .read_daemon_log(self.authorized(v1::ReadDaemonLogRequest {}))
            .await?
            .into_inner()
            .data;
        if data.len() > maximum_bytes {
            return Err(Status::out_of_range("daemon log is over the reader's limit").into());
        }
        Ok(data)
    }
}
