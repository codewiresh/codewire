//! A session's input streams (#3993): for each client that names one when it
//! attaches, how much of that client's input the session has written to its
//! terminal. A client that reconnects after a drop resends from that offset,
//! so a key typed during the drop arrives once, neither lost nor repeated.
//!
//! Several clients can type into one session, so offsets are per stream,
//! never per session. A stream this record doesn't know (its first attach,
//! one evicted from the most recent [`MAX_STREAMS`], or a daemon that has
//! restarted) takes the client's own position as written: unknown history
//! counts as delivered, so a resend can lose a key but never repeat one.

use std::collections::VecDeque;
use std::sync::Mutex;

/// The streams a session remembers; the least recently used goes first.
const MAX_STREAMS: usize = 16;

#[derive(Default)]
pub(super) struct InputStreams {
    /// Serializes offset input, so checking an offset, writing the bytes past
    /// it and advancing it are one step for each stream.
    pub(super) write: tokio::sync::Mutex<()>,
    /// Each stream's written offset, the most recently used last.
    offsets: Mutex<VecDeque<(String, u64)>>,
}

impl InputStreams {
    /// The stream's written offset, registering an unknown one at `claimed`,
    /// the client's own position. A known stream's offset is never past what
    /// the client says it sent, so the claim also bounds it.
    pub(super) fn open(&self, stream: &str, claimed: u64) -> u64 {
        let mut offsets = self.offsets.lock().unwrap_or_else(|e| e.into_inner());
        let written = match offsets.iter().position(|(name, _)| name == stream) {
            Some(index) => {
                let (_, written) = offsets.remove(index).expect("found");
                written.min(claimed)
            }
            None => claimed,
        };
        offsets.push_back((stream.to_owned(), written));
        while offsets.len() > MAX_STREAMS {
            offsets.pop_front();
        }
        written
    }

    /// The stream's written offset, if this session knows it.
    pub(super) fn written(&self, stream: &str) -> Option<u64> {
        let offsets = self.offsets.lock().unwrap_or_else(|e| e.into_inner());
        offsets
            .iter()
            .find(|(name, _)| name == stream)
            .map(|(_, written)| *written)
    }

    /// Records the stream as written up to `end`.
    pub(super) fn advance(&self, stream: &str, end: u64) {
        let mut offsets = self.offsets.lock().unwrap_or_else(|e| e.into_inner());
        match offsets.iter_mut().find(|(name, _)| name == stream) {
            Some((_, written)) => *written = end.max(*written),
            None => {
                offsets.push_back((stream.to_owned(), end));
                while offsets.len() > MAX_STREAMS {
                    offsets.pop_front();
                }
            }
        }
    }
}

/// What to write of input at `offset` when the stream is written up to
/// `written`: the bytes past it, nothing when all of it was written already,
/// or a refusal when it would leave a gap.
pub(super) fn unwritten(offset: u64, written: u64, data: &[u8]) -> Result<&[u8], InputGap> {
    if offset > written {
        return Err(InputGap { offset, written });
    }
    let skip = usize::try_from(written - offset).unwrap_or(usize::MAX);
    Ok(data.get(skip..).unwrap_or_default())
}

/// Input that starts past what the stream has written.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct InputGap {
    pub(super) offset: u64,
    pub(super) written: u64,
}

impl std::fmt::Display for InputGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "input at offset {} would skip bytes: the session has written its stream to {}",
            self.offset, self.written
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bytes_past_the_written_offset_are_written() {
        assert_eq!(unwritten(0, 0, b"abc"), Ok(&b"abc"[..]));
        assert_eq!(unwritten(10, 12, b"abcd"), Ok(&b"cd"[..]));
        assert_eq!(unwritten(10, 14, b"abcd"), Ok(&b""[..]));
        assert_eq!(unwritten(10, 20, b"abcd"), Ok(&b""[..]));
        assert_eq!(
            unwritten(15, 12, b"abcd"),
            Err(InputGap {
                offset: 15,
                written: 12
            })
        );
    }

    #[test]
    fn streams_are_kept_apart() {
        let streams = InputStreams::default();
        assert_eq!(streams.open("phone", 0), 0);
        assert_eq!(streams.open("laptop", 0), 0);
        streams.advance("phone", 7);
        assert_eq!(streams.written("phone"), Some(7));
        assert_eq!(streams.written("laptop"), Some(0));
    }

    #[test]
    fn an_unknown_stream_takes_the_client_s_position_and_a_known_one_its_own() {
        let streams = InputStreams::default();
        assert_eq!(
            streams.open("phone", 40),
            40,
            "unknown: counted as delivered"
        );
        streams.advance("phone", 45);
        assert_eq!(streams.open("phone", 52), 45, "known: what it wrote");
        assert_eq!(
            streams.open("phone", 43),
            43,
            "never past what the client sent"
        );
    }

    #[test]
    fn the_least_recently_used_stream_is_forgotten_past_the_bound() {
        let streams = InputStreams::default();
        for index in 0..MAX_STREAMS {
            streams.open(&format!("client-{index}"), 1);
        }
        streams.open("client-0", 1);
        streams.open("one-more", 1);
        assert_eq!(streams.written("client-1"), None, "the oldest went");
        assert_eq!(streams.written("client-0"), Some(1), "a reopened one stays");
        assert_eq!(streams.written("one-more"), Some(1));
    }
}
