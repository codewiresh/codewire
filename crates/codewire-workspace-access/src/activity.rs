//! Inbound traffic as idle-stop activity (#3384, `docs/dev/IDLE-STOP.md`).
//!
//! The hosted daemon sets [`set_hook`] to its own activity clock. A new SSH or
//! tailnet connection then counts as use, and so does data, either way,
//! through a forward into the workspace ([`ActivityIo`]). Only the time is
//! noted, never what passed. Without a hook (local VMs, hosts, tests) nothing
//! is noted.

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static HOOK: OnceLock<fn()> = OnceLock::new();

/// Notes activity through `hook` from now on. The first call wins.
pub fn set_hook(hook: fn()) {
    let _ = HOOK.set(hook);
}

/// Notes activity now.
pub fn note() {
    if let Some(hook) = HOOK.get() {
        hook();
    }
}

/// A stream that notes activity whenever data passes through it.
pub struct ActivityIo<T> {
    inner: T,
}

impl<T> ActivityIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            note();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            note();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    static NOTED: AtomicUsize = AtomicUsize::new(0);

    fn count() {
        NOTED.fetch_add(1, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn data_either_way_is_noted_and_silence_is_not() {
        set_hook(count);
        let (near, mut far) = tokio::io::duplex(64);
        let mut near = ActivityIo::new(near);
        let start = NOTED.load(Ordering::SeqCst);

        near.write_all(b"in").await.unwrap();
        assert!(NOTED.load(Ordering::SeqCst) > start, "a write is use");

        let after_write = NOTED.load(Ordering::SeqCst);
        far.write_all(b"out").await.unwrap();
        let mut buf = [0; 3];
        near.read_exact(&mut buf).await.unwrap();
        assert!(NOTED.load(Ordering::SeqCst) > after_write, "a read is use");

        let after_read = NOTED.load(Ordering::SeqCst);
        near.flush().await.unwrap();
        assert_eq!(
            NOTED.load(Ordering::SeqCst),
            after_read,
            "a flush moves nothing"
        );
    }
}
