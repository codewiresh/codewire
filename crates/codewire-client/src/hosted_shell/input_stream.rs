//! The shell's input stream (#3993): keys typed while a connection drops
//! reach the shell once, neither lost nor repeated.
//!
//! The client numbers the bytes it sends. A server that keeps offsets says,
//! in each attachment's statuses, how much of the stream the session has
//! written; on reattach the client resends from there. Until an attachment's
//! first status the client holds keys, since only that status says whether
//! the server keeps offsets: one that doesn't (an older daemon or server)
//! gets plain input, exactly as before. Held keys follow the same bounds as
//! sent ones, by when they were typed.
//!
//! A server that reports more of the stream written than the client sent has
//! lost track of it; numbering on would have it drop the next keys as
//! duplicates. The client starts a new stream instead, and sends this
//! attachment's keys plain.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::{AttachSessionInput, AttachSessionRequest, attach_session_request};

/// Unacknowledged input kept for a resend: at most this many bytes...
pub const KEPT_INPUT_BYTES: usize = 4096;
/// ...typed at most this long ago. Anything older is no longer what the
/// person meant to type now.
pub const KEPT_INPUT_AGE: Duration = Duration::from_secs(30);

/// What the client tells the person about its input after a reattach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputNotice {
    /// Keys typed during the drop were sent again.
    Resent(u64),
    /// Keys typed during the drop were older than the client keeps, or more
    /// than it keeps, and are lost.
    Lost(u64),
}

/// One client's input stream, kept across its reattachments.
pub struct InputStream {
    id: String,
    /// Bytes sent: the offset of the next one.
    sent: u64,
    /// Sent but not yet acknowledged, oldest first: (offset, sent at, bytes).
    unacknowledged: VecDeque<(u64, Instant, Vec<u8>)>,
    /// Keys typed before this attachment's first status, oldest first, with
    /// when they were typed.
    held: VecDeque<(Instant, Vec<u8>)>,
    /// Held keys dropped past the bounds, reported with the next first status.
    held_lost: u64,
    /// Whether this attachment's first status has arrived, and whether it
    /// said the server keeps offsets.
    attachment: Attachment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attachment {
    Unanswered,
    Plain,
    Offsets,
}

impl Default for InputStream {
    fn default() -> Self {
        Self::new(uuid::Uuid::new_v4().to_string())
    }
}

impl InputStream {
    pub fn new(id: String) -> Self {
        Self {
            id,
            sent: 0,
            unacknowledged: VecDeque::new(),
            held: VecDeque::new(),
            held_lost: 0,
            attachment: Attachment::Unanswered,
        }
    }

    /// The stream's id and the client's position, for the attachment's open.
    pub fn open(&self) -> (String, u64) {
        (self.id.clone(), self.sent)
    }

    /// A new attachment: its keys wait for its first status.
    pub fn attaching(&mut self) {
        self.attachment = Attachment::Unanswered;
    }

    /// Keys the person typed. Returns the request to send now, if any.
    pub fn typed(&mut self, keys: Vec<u8>, now: Instant) -> Option<AttachSessionRequest> {
        match self.attachment {
            Attachment::Unanswered => {
                self.held.push_back((now, keys));
                let mut held: usize = self.held.iter().map(|(_, keys)| keys.len()).sum();
                while held > KEPT_INPUT_BYTES {
                    let (_, oldest) = self.held.pop_front().expect("over the bound");
                    held -= oldest.len();
                    self.held_lost += oldest.len() as u64;
                }
                None
            }
            Attachment::Plain => Some(plain(keys)),
            Attachment::Offsets => Some(self.numbered(keys, now, now)),
        }
    }

    /// A status of this attachment. `written` is its input_end_offset: how
    /// much of the stream the session has written, when the server keeps
    /// offsets. The first status returns what to send now (a resend, then the
    /// held keys) and what to tell the person.
    pub fn status(
        &mut self,
        written: Option<u64>,
        now: Instant,
    ) -> (Vec<AttachSessionRequest>, Vec<InputNotice>) {
        if self.attachment != Attachment::Unanswered {
            match written {
                Some(written) if written > self.sent => self.broken(),
                Some(written) if self.attachment == Attachment::Offsets => {
                    self.acknowledge(written);
                }
                _ => {}
            }
            return (Vec::new(), Vec::new());
        }
        // Held keys typed too long ago are no longer what the person means.
        while let Some((typed_at, keys)) = self.held.front() {
            if now.duration_since(*typed_at) <= KEPT_INPUT_AGE {
                break;
            }
            self.held_lost += keys.len() as u64;
            self.held.pop_front();
        }
        let held: Vec<_> = self.held.drain(..).collect();
        let mut lost = std::mem::take(&mut self.held_lost);
        let mut requests = Vec::new();
        let mut resent = 0;
        match written {
            Some(written) if written > self.sent => self.broken(),
            None => self.attachment = Attachment::Plain,
            Some(written) => {
                self.attachment = Attachment::Offsets;
                self.forget_old(now);
                let kept_from = self
                    .unacknowledged
                    .front()
                    .map_or(self.sent, |(offset, _, _)| *offset);
                if written >= kept_from {
                    self.acknowledge(written);
                    for (offset, _, data) in &self.unacknowledged {
                        resent += data.len() as u64;
                        requests.push(offset_input(data.clone(), *offset));
                    }
                } else {
                    // The session lacks bytes the client no longer keeps.
                    // Sending the newer ones would leave a hole, so the
                    // stream restarts where the session is.
                    lost += self.sent - written;
                    self.unacknowledged.clear();
                    self.sent = written;
                }
            }
        }
        for (typed_at, keys) in held {
            requests.push(match self.attachment {
                Attachment::Offsets => self.numbered(keys, typed_at, now),
                _ => plain(keys),
            });
        }
        let mut notices = Vec::new();
        if resent > 0 {
            notices.push(InputNotice::Resent(resent));
        }
        if lost > 0 {
            notices.push(InputNotice::Lost(lost));
        }
        (requests, notices)
    }

    /// The server reported more of the stream written than the client sent:
    /// it has lost track of this stream. A new one starts at the next
    /// attachment, and this one's keys go plain.
    fn broken(&mut self) {
        tracing::debug!(stream = %self.id, sent = self.sent, "the server's input offset is past the stream; starting a new one");
        *self = Self {
            attachment: Attachment::Plain,
            ..Self::default()
        };
    }

    fn numbered(&mut self, data: Vec<u8>, typed_at: Instant, now: Instant) -> AttachSessionRequest {
        let offset = self.sent;
        self.sent += data.len() as u64;
        self.unacknowledged
            .push_back((offset, typed_at, data.clone()));
        self.forget_old(now);
        offset_input(data, offset)
    }

    fn acknowledge(&mut self, written: u64) {
        while let Some((offset, _, data)) = self.unacknowledged.front_mut() {
            let end = *offset + data.len() as u64;
            if end <= written {
                self.unacknowledged.pop_front();
            } else {
                if *offset < written {
                    data.drain(..(written - *offset) as usize);
                    *offset = written;
                }
                break;
            }
        }
    }

    /// Keeps at most [`KEPT_INPUT_BYTES`], typed within [`KEPT_INPUT_AGE`].
    fn forget_old(&mut self, now: Instant) {
        let mut kept: usize = self
            .unacknowledged
            .iter()
            .map(|(_, _, data)| data.len())
            .sum();
        while let Some((_, sent_at, data)) = self.unacknowledged.front() {
            if kept <= KEPT_INPUT_BYTES && now.duration_since(*sent_at) <= KEPT_INPUT_AGE {
                break;
            }
            kept -= data.len();
            self.unacknowledged.pop_front();
        }
    }
}

fn plain(keys: Vec<u8>) -> AttachSessionRequest {
    AttachSessionRequest {
        input: Some(attach_session_request::Input::Stdin(keys)),
        ..Default::default()
    }
}

fn offset_input(data: Vec<u8>, offset: u64) -> AttachSessionRequest {
    AttachSessionRequest {
        input: Some(attach_session_request::Input::StdinAt(Box::new(
            AttachSessionInput {
                data,
                offset,
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(request: &AttachSessionRequest) -> (Vec<u8>, Option<u64>) {
        match &request.input {
            Some(attach_session_request::Input::Stdin(data)) => (data.clone(), None),
            Some(attach_session_request::Input::StdinAt(input)) => {
                (input.data.clone(), Some(input.offset))
            }
            other => panic!("not input: {other:?}"),
        }
    }

    fn sent_all(requests: &[AttachSessionRequest]) -> Vec<(Vec<u8>, Option<u64>)> {
        requests.iter().map(sent).collect()
    }

    /// A stream whose attachment has answered with offsets, at `written`.
    fn numbering(now: Instant) -> InputStream {
        let mut stream = InputStream::new("phone".into());
        stream.attaching();
        assert_eq!(stream.status(Some(0), now), (Vec::new(), Vec::new()));
        stream
    }

    #[test]
    fn keys_wait_for_the_first_status_and_go_plain_to_a_server_without_offsets() {
        let now = Instant::now();
        let mut stream = InputStream::new("phone".into());
        stream.attaching();
        assert!(
            stream.typed(b"ls".to_vec(), now).is_none(),
            "held until the status"
        );
        let (requests, notices) = stream.status(None, now);
        assert_eq!(sent_all(&requests), [(b"ls".to_vec(), None)]);
        assert!(notices.is_empty());
        let after = stream.typed(b"\n".to_vec(), now).expect("sent at once");
        assert_eq!(sent(&after), (b"\n".to_vec(), None), "plain, as before");
        assert_eq!(
            stream.open(),
            ("phone".into(), 0),
            "plain input is never numbered"
        );
    }

    #[test]
    fn keys_lost_with_a_dropped_connection_are_resent_from_what_the_session_wrote() {
        let now = Instant::now();
        let mut stream = numbering(now);
        for keys in [b"echo ".as_slice(), b"hi", b"\n"] {
            let request = stream.typed(keys.to_vec(), now).expect("sent");
            assert!(sent(&request).1.is_some());
        }
        stream.status(Some(5), now); // a heartbeat: "echo " was written
        // The connection drops; "hi\n" may or may not have arrived.
        stream.attaching();
        assert!(
            stream.typed(b"!".to_vec(), now).is_none(),
            "held until the status"
        );
        assert_eq!(stream.open(), ("phone".into(), 8));
        let (requests, notices) = stream.status(Some(6), now); // only "h" arrived
        assert_eq!(
            sent_all(&requests),
            [
                (b"i".to_vec(), Some(6)),
                (b"\n".to_vec(), Some(7)),
                (b"!".to_vec(), Some(8))
            ]
        );
        assert_eq!(notices, [InputNotice::Resent(2)]);
    }

    #[test]
    fn nothing_is_resent_when_the_session_wrote_it_all() {
        let now = Instant::now();
        let mut stream = numbering(now);
        stream.typed(b"ls\n".to_vec(), now);
        stream.attaching();
        assert_eq!(stream.status(Some(3), now), (Vec::new(), Vec::new()));
    }

    #[test]
    fn keys_older_than_the_client_keeps_are_reported_lost_never_sent_with_a_hole() {
        let start = Instant::now();
        let mut stream = numbering(start);
        stream.typed(b"old".to_vec(), start);
        let later = start + KEPT_INPUT_AGE + Duration::from_secs(1);
        stream.typed(b"new".to_vec(), later); // "old" is no longer kept
        stream.attaching();
        let (requests, notices) = stream.status(Some(0), later);
        assert!(requests.is_empty(), "\"new\" would follow a hole");
        assert_eq!(notices, [InputNotice::Lost(6)]);
        assert_eq!(
            stream.open(),
            ("phone".into(), 0),
            "the stream restarts at the session's"
        );
        let next = stream.typed(b"x".to_vec(), later).expect("sent");
        assert_eq!(sent(&next), (b"x".to_vec(), Some(0)));
    }

    #[test]
    fn at_most_the_kept_bytes_are_kept() {
        let now = Instant::now();
        let mut stream = numbering(now);
        stream.typed(vec![b'a'; KEPT_INPUT_BYTES], now);
        stream.typed(b"b".to_vec(), now);
        stream.attaching();
        let (requests, notices) = stream.status(Some(0), now);
        assert!(requests.is_empty());
        assert_eq!(notices, [InputNotice::Lost(KEPT_INPUT_BYTES as u64 + 1)]);
    }

    #[test]
    fn held_keys_typed_too_long_ago_are_not_sent_and_are_reported() {
        let start = Instant::now();
        let mut stream = InputStream::new("phone".into());
        stream.attaching();
        stream.typed(b"stale".to_vec(), start);
        let later = start + KEPT_INPUT_AGE + Duration::from_secs(1);
        stream.typed(b"ok".to_vec(), later);
        let (requests, notices) = stream.status(Some(0), later);
        assert_eq!(sent_all(&requests), [(b"ok".to_vec(), Some(0))]);
        assert_eq!(notices, [InputNotice::Lost(5)]);
    }

    #[test]
    fn held_keys_past_the_bound_keep_the_newest() {
        let now = Instant::now();
        let mut stream = InputStream::new("phone".into());
        stream.attaching();
        stream.typed(vec![b'a'; KEPT_INPUT_BYTES], now);
        stream.typed(b"b".to_vec(), now);
        let (requests, notices) = stream.status(None, now);
        assert_eq!(sent_all(&requests), [(b"b".to_vec(), None)]);
        assert_eq!(notices, [InputNotice::Lost(KEPT_INPUT_BYTES as u64)]);
    }

    #[test]
    fn a_first_status_past_what_was_sent_starts_a_new_stream_and_sends_plain() {
        let now = Instant::now();
        let mut stream = InputStream::new("phone".into());
        stream.attaching();
        stream.typed(b"ls".to_vec(), now);
        let (requests, notices) = stream.status(Some(5), now);
        assert_eq!(
            sent_all(&requests),
            [(b"ls".to_vec(), None)],
            "never dropped as duplicates"
        );
        assert!(notices.is_empty());
        let (id, offset) = stream.open();
        assert_ne!(id, "phone");
        assert_eq!(offset, 0);
        assert_eq!(
            sent(&stream.typed(b"\n".to_vec(), now).expect("sent")),
            (b"\n".to_vec(), None)
        );
    }

    #[test]
    fn a_later_status_past_what_was_sent_starts_a_new_stream_and_sends_plain() {
        let now = Instant::now();
        let mut stream = numbering(now);
        stream.typed(b"ls".to_vec(), now);
        assert_eq!(stream.status(Some(9), now), (Vec::new(), Vec::new()));
        assert_ne!(stream.open().0, "phone");
        assert_eq!(
            sent(&stream.typed(b"\n".to_vec(), now).expect("sent")),
            (b"\n".to_vec(), None)
        );
    }
}
