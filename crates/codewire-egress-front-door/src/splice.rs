//! Copying a spliced WebSocket's bytes both ways, unread.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const BUFFER_BYTES: usize = 16 * 1024;
/// How long each side's orderly shutdown may take once the splice ends.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Bytes copied each way.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Spliced {
    pub(crate) to_upstream: u64,
    pub(crate) to_client: u64,
}

/// Copies until either side ends or fails, no bytes move either way for
/// `idle`, or `stop` is cancelled; then shuts both sides down.
pub(crate) async fn splice<C, U>(
    client: C,
    upstream: U,
    idle: Duration,
    stop: &CancellationToken,
) -> Spliced
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let activity = Activity::new();
    let mut spliced = Spliced::default();
    tokio::select! {
        () = copy(&mut client_read, &mut upstream_write, &activity, &mut spliced.to_upstream) => {}
        () = copy(&mut upstream_read, &mut client_write, &activity, &mut spliced.to_client) => {}
        () = activity.idle_for(idle) => {}
        () = stop.cancelled() => {}
    }
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, async {
        let _ = tokio::join!(client_write.shutdown(), upstream_write.shutdown());
    })
    .await;
    spliced
}

async fn copy<R, W>(reader: &mut R, writer: &mut W, activity: &Activity, copied: &mut u64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; BUFFER_BYTES];
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        activity.touch();
        if writer.write_all(&buffer[..count]).await.is_err() || writer.flush().await.is_err() {
            return;
        }
        *copied += count as u64;
    }
}

/// When bytes last moved. Both copies run in one task, but the splice runs in
/// a spawned task, so the record must be `Sync`.
struct Activity {
    start: Instant,
    last_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let millis = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    /// Resolves once nothing has moved for `idle`.
    async fn idle_for(&self, idle: Duration) {
        loop {
            let last = self.start + Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
            let deadline = last + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}
