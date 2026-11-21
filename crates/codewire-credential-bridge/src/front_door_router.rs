//! One front-door session across many upstreams (#4001, #4909).
//!
//! A relay holds a front door's one session for its whole life while the
//! broker streams behind it come and go with their epochs. New requests go
//! to the current upstream; a request's later frames follow it to the
//! upstream it opened on; an old upstream drains only its own requests.
//!
//! The router reads one field of each message, its `request_id` (field 1 of
//! every routed message), and the envelope's frame type. It never decodes a
//! payload, and nothing from a payload reaches its results except that id,
//! which the caller must not log. Only a malformed envelope or a second
//! Ready ends the session; every other refusal is answered for its own id or
//! dropped, and named by a [`Refusal`] for counting.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM, CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET,
};
use prost::encoding::{WireType, decode_key, decode_varint};
use tokio::time::Instant;

/// How long a finished id is remembered: frames racing its answer are
/// dropped, and it cannot be opened again.
pub const FINISHED_ID_WINDOW: Duration = Duration::from_secs(60);
/// The most finished ids remembered; past it the oldest are forgotten first.
pub const FINISHED_ID_CAP: usize = 4096;
/// The most requests one session holds open across its upstreams.
pub const LIVE_ID_CAP: usize = 256;
/// The longest request id; a longer one is a malformed envelope.
pub const MAX_ID_BYTES: usize = 128;

/// Guest envelope field numbers (`CredentialBridgeGuestMessage.payload`).
mod guest {
    pub const READY: u32 = 1;
    pub const REQUEST: u32 = 2;
    pub const CANCEL: u32 = 3;
    pub const UPGRADE: u32 = 8;
    pub const STREAM_DATA: u32 = 9;
    pub const STREAM_CREDIT: u32 = 10;
    pub const STREAM_CLOSE: u32 = 11;
    pub const REQUEST_BODY: u32 = 12;
    pub const REQUEST_END: u32 = 13;
}

/// Host envelope field numbers (`CredentialBridgeHostMessage.payload`).
mod host {
    pub const RESPONSE_START: u32 = 2;
    pub const RESPONSE_BODY: u32 = 3;
    pub const RESPONSE_END: u32 = 4;
    pub const RESPONSE_FAILURE: u32 = 5;
    pub const UPGRADE_ACCEPTED: u32 = 10;
    pub const STREAM_DATA: u32 = 11;
    pub const STREAM_CREDIT: u32 = 12;
    pub const STREAM_CLOSE: u32 = 13;
    pub const INTERCEPTION_HINT: u32 = 14;
    pub const REQUEST_CREDIT: u32 = 15;
}

/// Why a frame was not forwarded, for counting. Never carries the id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// No upstream takes new requests.
    NoUpstream,
    /// A frame for an id never opened, or forgotten.
    UnknownId,
    /// An open for an id that is live or finished within the window.
    ReusedId,
    /// A frame for an id that finished within the window: it raced the
    /// answer and is dropped unanswered.
    FinishedId,
    /// A frame needing a capability the session did not pin.
    OutsidePin,
    /// A frame type the front-door entry never serves.
    NotServed,
    /// An open past [`LIVE_ID_CAP`].
    TooManyRequests,
    /// An upstream sent a frame for an id it does not own, or a frame type
    /// a front-door session never receives; that upstream is ended.
    ForeignHostFrame,
}

/// What to do with one guest message.
#[derive(Debug, PartialEq)]
pub enum GuestRoute<U> {
    /// The session's first message: every upstream is opened with it.
    Ready,
    /// Send the message, unchanged, to this upstream.
    Forward(U),
    /// Answer the front door with this; nothing is forwarded.
    Answer(v1::CredentialBridgeHostMessage, Refusal),
    /// Drop it unanswered.
    Drop(Refusal),
    /// The router has ended this live id: answer the front door with
    /// `answer`, and send `upstream` the `cancel` (a request's Cancel, a
    /// socket's reset). Its later frames from that upstream are dropped.
    Cancel {
        answer: v1::CredentialBridgeHostMessage,
        upstream: U,
        cancel: Box<v1::CredentialBridgeGuestMessage>,
        refusal: Refusal,
    },
    /// The envelope cannot be read safely: end the session.
    End,
}

/// What to do with one host message from an upstream.
#[derive(Debug, PartialEq)]
pub enum HostRoute {
    /// Send the message, unchanged, to the front door.
    Forward,
    /// Drop it: a late frame for an id the router cancelled on this
    /// upstream, which has already been answered.
    Drop(Refusal),
    /// The upstream broke the protocol: end it, and send the front door
    /// these answers for the ids it held.
    EndUpstream(Vec<v1::CredentialBridgeHostMessage>, Refusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Http,
    Socket,
}

struct Live<U> {
    upstream: U,
    kind: Kind,
    guest_closed: bool,
    host_closed: bool,
    /// A socket's upgrade was accepted; until then it may be refused with an
    /// ordinary response.
    accepted: bool,
    /// A socket's upgrade was refused with an ordinary response; no socket
    /// frame follows.
    refused: bool,
}

/// Recently finished ids, bounded by time and by count.
#[derive(Default)]
struct Finished {
    order: VecDeque<(String, Instant)>,
    ids: HashSet<String>,
}

impl Finished {
    fn insert(&mut self, id: String, now: Instant) {
        self.expire(now);
        if self.ids.insert(id.clone()) {
            self.order.push_back((id, now));
        }
        while self.order.len() > FINISHED_ID_CAP {
            if let Some((oldest, _)) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
    }

    fn contains(&mut self, id: &str, now: Instant) -> bool {
        self.expire(now);
        self.ids.contains(id)
    }

    fn expire(&mut self, now: Instant) {
        while let Some((id, at)) = self.order.front() {
            if now.duration_since(*at) < FINISHED_ID_WINDOW {
                break;
            }
            self.ids.remove(id);
            self.order.pop_front();
        }
    }
}

/// A session's refusals, counted by reason and reported at most once a
/// minute, so a front door that floods bad frames is counted without a log
/// line each. The caller logs what [`Refusals::count`] hands back.
pub struct Refusals {
    counts: HashMap<Refusal, u64>,
    next_log: Instant,
}

impl Default for Refusals {
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
            next_log: Instant::now(),
        }
    }
}

impl Refusals {
    /// Count `refusal`. Once a minute, it hands back every count since the
    /// last report, for the caller to log.
    pub fn count(&mut self, refusal: Refusal) -> Vec<(Refusal, u64)> {
        *self.counts.entry(refusal).or_default() += 1;
        let now = Instant::now();
        if now < self.next_log {
            return Vec::new();
        }
        self.next_log = now + Duration::from_secs(60);
        self.counts.drain().collect()
    }
}

/// The routing state of one front-door session.
pub struct FrontDoorRouter<U> {
    pinned: Vec<String>,
    current: Option<U>,
    ready_seen: bool,
    live: HashMap<String, Live<U>>,
    finished: Finished,
    /// Ids the router cancelled, with the upstream still finishing them.
    cancelled: HashMap<String, U>,
}

impl<U: Copy + Eq + Hash> FrontDoorRouter<U> {
    /// A session whose capabilities are those its first upstream listed.
    pub fn new(pinned: Vec<String>) -> Self {
        Self {
            pinned,
            current: None,
            ready_seen: false,
            live: HashMap::new(),
            finished: Finished::default(),
            cancelled: HashMap::new(),
        }
    }

    /// The capabilities the session advertises, exactly.
    pub fn pinned(&self) -> &[String] {
        &self.pinned
    }

    /// Whether an upstream listing `capabilities` may take new requests: it
    /// must serve everything the session pinned.
    pub fn accepts(&self, capabilities: &[String]) -> bool {
        self.pinned
            .iter()
            .all(|pinned| capabilities.contains(pinned))
    }

    /// Where new requests open now.
    pub fn current(&self) -> Option<U> {
        self.current
    }

    /// Where new requests open from now on; `None` answers them.
    pub fn set_current(&mut self, upstream: Option<U>) {
        self.current = upstream;
    }

    /// Whether `upstream` still holds a request.
    pub fn holds(&self, upstream: U) -> bool {
        self.live.values().any(|live| live.upstream == upstream)
    }

    /// Route one guest message, already bounded in length.
    pub fn guest(&mut self, message: &[u8], now: Instant) -> GuestRoute<U> {
        let Some((field, id)) = envelope(message) else {
            return GuestRoute::End;
        };
        if field == guest::READY {
            if self.ready_seen || id.is_some() {
                return GuestRoute::End;
            }
            self.ready_seen = true;
            return GuestRoute::Ready;
        }
        if !self.ready_seen {
            return GuestRoute::End;
        }
        let Some(id) = id else {
            return GuestRoute::End;
        };
        if id.len() > MAX_ID_BYTES {
            return GuestRoute::End;
        }
        match field {
            guest::REQUEST => self.open(id, Kind::Http, None, now),
            guest::UPGRADE => self.open(
                id,
                Kind::Socket,
                Some(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET),
                now,
            ),
            guest::CANCEL => self.follow(id, Kind::Http, None, false, now),
            guest::REQUEST_BODY | guest::REQUEST_END => self.follow(
                id,
                Kind::Http,
                Some(CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM),
                false,
                now,
            ),
            guest::STREAM_DATA | guest::STREAM_CREDIT => self.follow(
                id,
                Kind::Socket,
                Some(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET),
                false,
                now,
            ),
            guest::STREAM_CLOSE => self.follow(
                id,
                Kind::Socket,
                Some(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET),
                true,
                now,
            ),
            _ => GuestRoute::Answer(answer(id, Kind::Http), Refusal::NotServed),
        }
    }

    fn open(&mut self, id: String, kind: Kind, needs: Option<&str>, now: Instant) -> GuestRoute<U> {
        if self.live.contains_key(&id) || self.finished.contains(&id, now) {
            // Never answered: the id's own request would read the answer.
            return GuestRoute::Drop(Refusal::ReusedId);
        }
        if needs.is_some_and(|needs| !self.pinned.iter().any(|pinned| pinned == needs)) {
            return GuestRoute::Answer(answer(id, kind), Refusal::OutsidePin);
        }
        let Some(upstream) = self.current else {
            return GuestRoute::Answer(answer(id, kind), Refusal::NoUpstream);
        };
        if self.live.len() >= LIVE_ID_CAP {
            return GuestRoute::Answer(answer(id, kind), Refusal::TooManyRequests);
        }
        self.live.insert(
            id,
            Live {
                upstream,
                kind,
                guest_closed: false,
                host_closed: false,
                accepted: false,
                refused: false,
            },
        );
        GuestRoute::Forward(upstream)
    }

    fn follow(
        &mut self,
        id: String,
        kind: Kind,
        needs: Option<&str>,
        closes: bool,
        now: Instant,
    ) -> GuestRoute<U> {
        let outside_pin =
            needs.is_some_and(|needs| !self.pinned.iter().any(|pinned| pinned == needs));
        if let Some(live) = self.live.get_mut(&id) {
            // A frame of the other kind is dropped, never answered: the live
            // id's own request would read the answer (#4909).
            if live.kind != kind {
                return GuestRoute::Drop(Refusal::UnknownId);
            }
            // A live id's own frame outside the pin ends its request: it is
            // answered once, finished, and cancelled on its upstream, whose
            // later frames for it are dropped (#4909, cw-security).
            if outside_pin {
                let upstream = live.upstream;
                let cancel = Box::new(cancel(id.clone(), kind));
                self.finish(id.clone(), now);
                self.cancelled
                    .retain(|cancelled, _| self.finished.ids.contains(cancelled));
                self.cancelled.insert(id.clone(), upstream);
                return GuestRoute::Cancel {
                    answer: answer(id, kind),
                    upstream,
                    cancel,
                    refusal: Refusal::OutsidePin,
                };
            }
            let upstream = live.upstream;
            if closes {
                live.guest_closed = true;
                if live.host_closed {
                    self.finish(id, now);
                }
            }
            return GuestRoute::Forward(upstream);
        }
        if self.finished.contains(&id, now) {
            return GuestRoute::Drop(Refusal::FinishedId);
        }
        if outside_pin {
            return GuestRoute::Answer(answer(id, kind), Refusal::OutsidePin);
        }
        GuestRoute::Answer(answer(id, kind), Refusal::UnknownId)
    }

    /// Route one host message from `upstream`.
    pub fn host(&mut self, upstream: U, message: &[u8], now: Instant) -> HostRoute {
        if let Some((_, Some(id))) = envelope(message)
            && self.cancelled.get(&id) == Some(&upstream)
        {
            // Remembered only while the id is still among the finished.
            if self.finished.contains(&id, now) {
                return HostRoute::Drop(Refusal::FinishedId);
            }
            self.cancelled.remove(&id);
        }
        let owned = envelope(message).and_then(|(field, id)| {
            let id = id?;
            let live = self.live.get(&id)?;
            let kind = host_kind(field)?;
            // A socket not yet accepted may be refused with an ordinary
            // response, which then finishes it; after that, no socket frame.
            let fits = match (live.kind, kind) {
                (Kind::Http, Kind::Http) => true,
                (Kind::Socket, Kind::Socket) => !live.refused,
                (Kind::Socket, Kind::Http) => !live.accepted,
                (Kind::Http, Kind::Socket) => false,
            };
            (live.upstream == upstream && fits).then_some((field, id, kind))
        });
        let Some((field, id, kind)) = owned else {
            return HostRoute::EndUpstream(
                self.upstream_ended(upstream, now),
                Refusal::ForeignHostFrame,
            );
        };
        if kind == Kind::Http
            && let Some(live) = self.live.get_mut(&id)
            && live.kind == Kind::Socket
        {
            live.refused = true;
        }
        match field {
            host::RESPONSE_END | host::RESPONSE_FAILURE => self.finish(id, now),
            host::UPGRADE_ACCEPTED => {
                if let Some(live) = self.live.get_mut(&id) {
                    live.accepted = true;
                }
            }
            host::STREAM_CLOSE => {
                if let Some(live) = self.live.get_mut(&id) {
                    live.host_closed = true;
                    if live.guest_closed {
                        self.finish(id, now);
                    }
                }
            }
            _ => {}
        }
        HostRoute::Forward
    }

    /// `upstream` has ended: answer each id it still held, which then
    /// counts as finished.
    pub fn upstream_ended(
        &mut self,
        upstream: U,
        now: Instant,
    ) -> Vec<v1::CredentialBridgeHostMessage> {
        let ids: Vec<(String, Kind)> = self
            .live
            .iter()
            .filter(|(_, live)| live.upstream == upstream)
            .map(|(id, live)| (id.clone(), live.kind))
            .collect();
        if self.current == Some(upstream) {
            self.current = None;
        }
        ids.into_iter()
            .map(|(id, kind)| {
                self.finish(id.clone(), now);
                answer(id, kind)
            })
            .collect()
    }

    fn finish(&mut self, id: String, now: Instant) {
        self.live.remove(&id);
        self.finished.insert(id, now);
    }
}

/// The kind of request a host frame type answers.
fn host_kind(field: u32) -> Option<Kind> {
    match field {
        host::RESPONSE_START
        | host::RESPONSE_BODY
        | host::RESPONSE_END
        | host::RESPONSE_FAILURE
        | host::REQUEST_CREDIT
        | host::INTERCEPTION_HINT => Some(Kind::Http),
        host::UPGRADE_ACCEPTED | host::STREAM_DATA | host::STREAM_CREDIT | host::STREAM_CLOSE => {
            Some(Kind::Socket)
        }
        _ => None,
    }
}

/// What tells an upstream the router ended `id`: a request's Cancel, a
/// socket's reset.
fn cancel(id: String, kind: Kind) -> v1::CredentialBridgeGuestMessage {
    use v1::credential_bridge_guest_message::Payload;
    let payload = match kind {
        Kind::Http => Payload::Cancel(v1::CredentialBridgeCancel { request_id: id }),
        Kind::Socket => Payload::StreamClose(v1::CredentialBridgeStreamClose {
            request_id: id,
            kind: v1::CredentialBridgeStreamCloseKind::Reset as i32,
        }),
    };
    v1::CredentialBridgeGuestMessage {
        payload: Some(payload),
    }
}

/// The bridge's own error answer for `id`.
fn answer(id: String, kind: Kind) -> v1::CredentialBridgeHostMessage {
    use v1::credential_bridge_host_message::Payload;
    let payload = match kind {
        Kind::Http => Payload::ResponseFailure(v1::CredentialBridgeResponseFailure {
            request_id: id,
            reason: v1::CredentialBridgeFailureReason::Unavailable as i32,
            ..Default::default()
        }),
        Kind::Socket => Payload::StreamClose(v1::CredentialBridgeStreamClose {
            request_id: id,
            kind: v1::CredentialBridgeStreamCloseKind::Reset as i32,
        }),
    };
    v1::CredentialBridgeHostMessage {
        payload: Some(payload),
    }
}

/// An envelope's one payload field number and, when that payload carries
/// one, its `request_id`. `None` for anything but exactly one
/// length-delimited payload field whose own fields parse.
fn envelope(message: &[u8]) -> Option<(u32, Option<String>)> {
    let mut outer = message;
    let (field, wire) = decode_key(&mut outer).ok()?;
    if wire != WireType::LengthDelimited {
        return None;
    }
    let length = usize::try_from(decode_varint(&mut outer).ok()?).ok()?;
    if outer.len() != length {
        return None;
    }
    Some((field, request_id(outer)?))
}

/// Field 1 of a payload, as a string, if present. Other fields are skipped
/// unread; `None` when the payload does not parse.
fn request_id(mut payload: &[u8]) -> Option<Option<String>> {
    let mut id = None;
    while !payload.is_empty() {
        let (field, wire) = decode_key(&mut payload).ok()?;
        match wire {
            WireType::Varint => {
                decode_varint(&mut payload).ok()?;
            }
            WireType::SixtyFourBit => payload = payload.get(8..)?,
            WireType::ThirtyTwoBit => payload = payload.get(4..)?,
            WireType::LengthDelimited => {
                let length = usize::try_from(decode_varint(&mut payload).ok()?).ok()?;
                let value = payload.get(..length)?;
                if field == 1 {
                    id = Some(String::from_utf8(value.to_vec()).ok()?);
                }
                payload = &payload[length..];
            }
            WireType::StartGroup | WireType::EndGroup => return None,
        }
    }
    Some(id.filter(|id| !id.is_empty()))
}

#[cfg(test)]
mod tests;
