//! Upload bytes batched into large daemon writes (#4460).
//!
//! Each daemon write is one round trip to the sandbox, which may be in another
//! site, so an upload buffers its public chunks and writes them a mebibyte at
//! a time. Only written bytes count: a staging file's size, and every size an
//! upload reports, is what reached the daemon. A buffered tail that is never
//! flushed is lost with the request, and a resumed upload sends it again.

use super::upload_mutation;
use crate::client::{DaemonClient, DaemonClientError, v1};

/// The most an upload buffers before it writes to the daemon. The daemon and
/// the bridge's client both accept messages of a few mebibytes.
pub(super) const UPLOAD_WRITE_BYTES: usize = 1024 * 1024;

/// The bytes of one staging file: written up to `written`, then buffered.
pub(super) struct StagedWrites {
    path: String,
    written: i64,
    buffer: Vec<u8>,
}

impl StagedWrites {
    /// A staging file that already holds `written` bytes.
    pub(super) fn new(path: String, written: i64) -> Self {
        Self {
            path,
            written,
            buffer: Vec::new(),
        }
    }

    /// The bytes on disk; buffered bytes are not counted.
    pub(super) fn written(&self) -> i64 {
        self.written
    }

    /// Appends `bytes`, writing each full batch as it fills.
    pub(super) async fn push(
        &mut self,
        daemon: &DaemonClient,
        bytes: &[u8],
    ) -> Result<(), DaemonClientError> {
        self.buffer.extend_from_slice(bytes);
        while self.buffer.len() >= UPLOAD_WRITE_BYTES {
            let rest = self.buffer.split_off(UPLOAD_WRITE_BYTES);
            let batch = std::mem::replace(&mut self.buffer, rest);
            self.write(daemon, batch).await?;
        }
        Ok(())
    }

    /// Writes whatever is buffered.
    pub(super) async fn flush(&mut self, daemon: &DaemonClient) -> Result<(), DaemonClientError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.buffer);
        self.write(daemon, batch).await
    }

    async fn write(
        &mut self,
        daemon: &DaemonClient,
        data: Vec<u8>,
    ) -> Result<(), DaemonClientError> {
        let expected = i64::try_from(data.len())
            .map_err(|_| DaemonClientError::InvalidFrame("file write length"))?;
        let written = upload_mutation(daemon.write_file(v1::WriteRequest {
            path: self.path.clone(),
            offset: self.written,
            data,
        }))
        .await?;
        if written != expected {
            return Err(DaemonClientError::InvalidFrame("file write"));
        }
        self.written = self
            .written
            .checked_add(written)
            .ok_or(DaemonClientError::InvalidFrame("file write offset"))?;
        Ok(())
    }
}
