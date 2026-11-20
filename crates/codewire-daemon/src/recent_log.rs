//! A local guest daemon's recent log lines, kept in memory for the host to
//! read with `ReadDaemonLog` (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Diagnosing delivery in a local VM"). A guest has no console and no log
//! file the host can reach, so this buffer is the only place its events go.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

/// The most bytes kept. Past it the oldest whole lines are dropped.
pub const RECENT_LOG_BYTES: usize = 32 * 1024;

/// A bounded in-memory log. Clones share one buffer.
#[derive(Clone, Default)]
pub struct RecentLog {
    bytes: Arc<Mutex<VecDeque<u8>>>,
}

impl RecentLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// A writer whose every `write` is appended whole. A log formatter that
    /// writes one event per call, as `tracing_subscriber::fmt` does, keeps
    /// events from interleaving.
    pub fn writer(&self) -> RecentLogWriter {
        RecentLogWriter(self.clone())
    }

    /// The kept lines, oldest first.
    pub fn snapshot(&self) -> Vec<u8> {
        self.lock().iter().copied().collect()
    }

    fn append(&self, written: &[u8]) {
        // One write larger than the whole buffer keeps its end, which then
        // starts inside a line.
        let oversized = written.len() > RECENT_LOG_BYTES;
        let written = &written[written.len().saturating_sub(RECENT_LOG_BYTES)..];
        let mut bytes = self.lock();
        if oversized {
            bytes.clear();
        }
        bytes.extend(written);
        let excess = bytes.len().saturating_sub(RECENT_LOG_BYTES);
        if excess == 0 && !oversized {
            return;
        }
        // Drop through the first line break that frees enough room, so the
        // buffer always starts at the beginning of a line.
        let from = excess.saturating_sub(1);
        let cut = bytes
            .iter()
            .skip(from)
            .position(|byte| *byte == b'\n')
            .map_or(excess, |offset| from + offset + 1);
        bytes.drain(..cut);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<u8>> {
        // The bytes stay valid whatever a panicking writer left behind.
        self.bytes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// See [`RecentLog::writer`].
pub struct RecentLogWriter(RecentLog);

impl io::Write for RecentLogWriter {
    fn write(&mut self, written: &[u8]) -> io::Result<usize> {
        self.0.append(written);
        Ok(written.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER;
    use codewire_daemon_proto::daemon::v1;
    use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonService as _;

    use super::*;
    use crate::service::DaemonServiceImpl;

    fn line(index: usize) -> Vec<u8> {
        format!("line {index:04}\n").into_bytes()
    }

    #[test]
    fn keeps_lines_in_order_while_under_the_bound() {
        let log = RecentLog::new();
        let mut writer = log.writer();
        writer.write_all(b"first\n").unwrap();
        writer.write_all(b"second\n").unwrap();
        assert_eq!(log.snapshot(), b"first\nsecond\n");
    }

    #[test]
    fn drops_the_oldest_whole_lines_past_the_bound() {
        let log = RecentLog::new();
        let mut writer = log.writer();
        let count = RECENT_LOG_BYTES / line(0).len() + 50;
        for index in 0..count {
            writer.write_all(&line(index)).unwrap();
        }
        let kept = log.snapshot();
        assert!(kept.len() <= RECENT_LOG_BYTES);
        // More than one line's room would mean a line was dropped needlessly.
        assert!(kept.len() > RECENT_LOG_BYTES - line(0).len());
        assert!(kept.starts_with(b"line "));
        assert!(kept.ends_with(&line(count - 1)));
        assert!(!kept.windows(10).any(|window| window == &line(0)[..]));
    }

    #[test]
    fn a_write_larger_than_the_bound_keeps_its_end() {
        let log = RecentLog::new();
        let mut oversized = vec![b'a'; RECENT_LOG_BYTES];
        oversized.extend_from_slice(b"\nthe end\n");
        log.writer().write_all(&oversized).unwrap();
        assert_eq!(log.snapshot(), b"the end\n");
    }

    #[test]
    fn clones_share_one_buffer() {
        let log = RecentLog::new();
        log.clone().writer().write_all(b"shared\n").unwrap();
        assert_eq!(log.snapshot(), b"shared\n");
    }

    const TOKEN: &str = "recent-log-test-token";

    fn read_request(token: Option<&str>) -> tonic::Request<v1::ReadDaemonLogRequest> {
        let mut request = tonic::Request::new(v1::ReadDaemonLogRequest {});
        if let Some(token) = token {
            request
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, token.parse().unwrap());
        }
        request
    }

    fn service(root: &std::path::Path) -> DaemonServiceImpl {
        DaemonServiceImpl::new(crate::Config {
            listen_addr: "unused:0".into(),
            workspace_root: root.to_path_buf(),
            home_root: root.to_path_buf(),
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new(TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
            sandbox_server_url: None,
            interception: None,
        })
    }

    #[tokio::test]
    async fn the_daemon_returns_its_log_only_to_an_authorized_caller() {
        let temp = tempfile::tempdir().unwrap();
        let log = RecentLog::new();
        log.writer().write_all(b"one line\n").unwrap();
        let service = service(temp.path()).with_recent_log(log);

        for token in [None, Some("wrong-daemon-token")] {
            let error = service
                .read_daemon_log(read_request(token))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unauthenticated);
        }
        let answer = service
            .read_daemon_log(read_request(Some(TOKEN)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answer.data, b"one line\n");
    }

    #[tokio::test]
    async fn a_daemon_that_keeps_no_log_says_unimplemented() {
        let temp = tempfile::tempdir().unwrap();
        let error = service(temp.path())
            .read_daemon_log(read_request(Some(TOKEN)))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }
}
