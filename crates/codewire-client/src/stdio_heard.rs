//! When `cw shell --stdio` last heard from the environment's SSH server
//! (#6101), so the CLI can tell a lost connection from one that ended.
//!
//! While a connection is up, the workspace SSH server sends a keepalive
//! whenever it has heard nothing for 15 s, and a connection that ends
//! cleanly ends with the server's own closing packets. So a connection that
//! ends after a long silence from the server was lost. The time is the wall
//! clock: a monotonic clock stops while a Mac sleeps, and a sleep is the
//! commonest cut.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWrite;

/// Milliseconds since the Unix epoch of the last write; 0 before any.
static LAST_HEARD_MS: AtomicU64 = AtomicU64::new(0);

/// A writer that stamps the time of every write. The stdio pipes write to
/// stdout only what the server sent.
pub(crate) struct Heard<W>(W);

/// The process's stdout, stamping each write.
pub(crate) fn stdout() -> Heard<tokio::io::Stdout> {
    Heard(tokio::io::stdout())
}

/// How long ago bytes from the server last reached stdout, or `None` when
/// none have in this process.
pub fn stdio_silent_for() -> Option<Duration> {
    match LAST_HEARD_MS.load(Ordering::Relaxed) {
        0 => None,
        last => Some(Duration::from_millis(now_ms().saturating_sub(last))),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Heard<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.0).poll_write(cx, buf);
        if matches!(written, Poll::Ready(Ok(n)) if n > 0) {
            LAST_HEARD_MS.store(now_ms(), Ordering::Relaxed);
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // The only test that writes through `Heard`, so nothing else moves the
    // stamp while it runs.
    #[tokio::test]
    async fn a_write_from_the_server_is_heard_now_and_an_empty_one_is_not() {
        let mut heard = Heard(Vec::new());
        assert_eq!(heard.write(b"").await.unwrap(), 0);
        assert_eq!(stdio_silent_for(), None);

        heard.write_all(b"SSH-2.0-server\r\n").await.unwrap();
        let silent = stdio_silent_for().expect("a write was heard");
        assert!(silent < Duration::from_secs(5), "{silent:?}");
        assert_eq!(heard.0, b"SSH-2.0-server\r\n");
    }
}
