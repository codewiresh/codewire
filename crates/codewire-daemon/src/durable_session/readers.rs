//! A session's output waits for the clients reading it (#4436). A session
//! keeps only its most recent output ([`RETAINED_OUTPUT_BYTES`]), so a
//! command that writes faster than an attached client reads would otherwise
//! push unread output out, and the client would get a history gap instead.
//!
//! - **Who counts.** Every attachment stream registers a [`Reader`] with the
//!   offset it has handed to its client, and moves it as it hands over more.
//!   Dropping the stream (detach, disconnect, end) removes it. With no reader
//!   the session records at full speed and keeps its most recent output, as
//!   scrollback.
//! - **The wait.** Before recording a chunk, capture waits while recording it
//!   would leave a reader's unread output outside what the session keeps.
//!   While capture waits it reads nothing more, so the command blocks on its
//!   full pipe or terminal, as it would writing to a slow `ssh`.
//! - **A reader that stops reading** holds the command back for at most
//!   [`READER_STALL`] after it last moved, timed per reader, so readers'
//!   stalls never add up. Then it is released for good: it never holds the
//!   command back again, and it gets a gap when it reads on. A dead client,
//!   whose connection dropped without an end, stops moving and is released
//!   the same way.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::{RETAINED_OUTPUT_BYTES, SessionEngine, SessionHandle, lock};

/// How long a reader that stopped moving holds the command back.
pub(super) const READER_STALL: Duration = Duration::from_secs(30);

/// A session's readers.
pub(super) struct Readers {
    next: u64,
    readers: HashMap<u64, ReaderState>,
    stall: Duration,
}

impl Default for Readers {
    fn default() -> Self {
        Self::with_stall(READER_STALL)
    }
}

struct ReaderState {
    /// The output offset handed to the client.
    cursor: u64,
    /// When `cursor` last moved, or the reader registered.
    moved_at: Instant,
    /// Stalled once: it never holds the command back again.
    released: bool,
}

impl Readers {
    pub(super) fn with_stall(stall: Duration) -> Self {
        Self {
            next: 0,
            readers: HashMap::new(),
            stall,
        }
    }

    /// Whether recording `length` more bytes after `end` must wait, at `now`:
    /// `None` when no reader holds it back, otherwise when the first holding
    /// reader is released if it doesn't move. A holding reader whose stall
    /// has run out is released here, for good.
    fn wait(&mut self, end: u64, length: u64, now: Instant) -> Option<Instant> {
        let stall = self.stall;
        let mut until = None::<Instant>;
        for reader in self.readers.values_mut() {
            if reader.released
                || end.saturating_add(length).saturating_sub(reader.cursor) <= RETAINED_OUTPUT_BYTES
            {
                continue;
            }
            let release = reader.moved_at + stall;
            if now >= release {
                reader.released = true;
                continue;
            }
            until = Some(until.map_or(release, |until| until.min(release)));
        }
        until
    }
}

/// One attachment's reading, counted on its session until it is dropped.
pub(crate) struct Reader {
    handle: Arc<SessionHandle>,
    id: u64,
}

impl Reader {
    /// The attachment has handed output up to `cursor` to its client.
    pub(crate) fn moved(&self, cursor: u64) {
        {
            let mut readers = lock(&self.handle.readers);
            if let Some(reader) = readers.readers.get_mut(&self.id)
                && cursor != reader.cursor
            {
                reader.cursor = cursor;
                reader.moved_at = Instant::now();
            }
        }
        self.handle.reader_moved.notify_waiters();
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        lock(&self.handle.readers).readers.remove(&self.id);
        self.handle.reader_moved.notify_waiters();
    }
}

impl Reader {
    /// Counts a reader of `handle`'s output from `cursor` until it is dropped.
    pub(super) fn on(handle: Arc<SessionHandle>, cursor: u64) -> Self {
        let id = {
            let mut readers = lock(&handle.readers);
            let id = readers.next;
            readers.next += 1;
            readers.readers.insert(
                id,
                ReaderState {
                    cursor,
                    moved_at: Instant::now(),
                    released: false,
                },
            );
            id
        };
        Self { handle, id }
    }
}

impl SessionEngine {
    /// Counts an attachment reading `session_id` from `cursor` until the
    /// result is dropped. An unknown session counts nothing.
    pub(crate) fn reader(&self, session_id: &str, cursor: u64) -> Option<Reader> {
        Some(Reader::on(self.handle(session_id).ok()?, cursor))
    }
}

/// Waits until recording `length` more bytes leaves every reader's unread
/// output inside what the session keeps, or each reader holding it back has
/// stalled.
pub(super) async fn wait_for_readers(handle: &SessionHandle, length: u64) {
    loop {
        // Asked for before the check, so a move between the two still wakes.
        let moved = handle.reader_moved.notified();
        tokio::pin!(moved);
        moved.as_mut().enable();
        let end = *handle.output_end.borrow();
        let Some(until) = lock(&handle.readers).wait(end, length, Instant::now()) else {
            return;
        };
        tokio::select! {
            () = moved => {}
            () = tokio::time::sleep_until(until) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn reader(cursor: u64, moved_at: Instant) -> ReaderState {
        ReaderState {
            cursor,
            moved_at,
            released: false,
        }
    }

    #[test]
    fn a_reader_holds_the_command_back_only_past_what_the_session_keeps() {
        let now = Instant::now();
        let mut readers = Readers::default();
        readers.readers.insert(0, reader(10 * MIB, now));
        assert_eq!(readers.wait(13 * MIB, 32 * 1024, now), None, "within 4 MiB");
        assert_eq!(
            readers.wait(14 * MIB, MIB, now),
            Some(now + READER_STALL),
            "past it"
        );
    }

    #[test]
    fn a_stalled_reader_is_released_for_good() {
        let now = Instant::now();
        let mut readers = Readers::default();
        readers.readers.insert(0, reader(0, now));
        assert!(readers.wait(8 * MIB, 1, now + READER_STALL).is_none());
        assert!(readers.readers[&0].released);
        // Moving again, and falling behind again, never holds it back again.
        readers.readers.get_mut(&0).unwrap().moved_at = now + READER_STALL;
        assert!(readers.wait(8 * MIB, 1, now + READER_STALL).is_none());
    }

    #[test]
    fn each_reader_has_its_own_stall_and_they_never_add_up() {
        let now = Instant::now();
        let mut readers = Readers::default();
        readers.readers.insert(0, reader(0, now));
        readers
            .readers
            .insert(1, reader(0, now + Duration::from_secs(10)));
        // The writer wakes at the first release; then the second still holds
        // it, but only to its own deadline, 30 s after it last moved.
        assert_eq!(readers.wait(8 * MIB, 1, now), Some(now + READER_STALL));
        let first = now + READER_STALL;
        assert_eq!(
            readers.wait(8 * MIB, 1, first),
            Some(now + Duration::from_secs(10) + READER_STALL)
        );
        assert!(readers.readers[&0].released);
        assert!(
            readers
                .wait(8 * MIB, 1, now + Duration::from_secs(40))
                .is_none()
        );
    }
}
