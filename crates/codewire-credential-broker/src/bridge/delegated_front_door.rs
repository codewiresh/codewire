//! A platform-delegated relay's front-door session (#4909).
//!
//! The boot's front door pairs with this relay as it would with a local
//! broker, but its requests are decided by the platform broker: the relay
//! joins its admitted delegation's front-door session through the host
//! authority, which keeps the platform's epoch handle, and routes every
//! request by its id between the two (`front_door_router`).
//!
//! The session's capabilities are pinned in advance:
//! [`CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES`], what the
//! platform's front-door entry admits. A join is used only when it admits at
//! least those. The relay holds the Open until its first join is accepted, or
//! [`OPEN_HOLD`] after pairing, whichever is first: the front door gives all
//! new work to the newest session as soon as it opens, so a session that
//! opens unjoined would answer every new request unavailable. The front
//! door's first frame must then be exactly this binding's Ready.
//!
//! The platform ends a joined stream after an idle spell. The relay then has
//! no upstream until the next request, which waits while it joins again,
//! bounded by [`JOIN_TIMEOUT`] and spaced by a backoff. Each join is a new
//! upstream to the router, so nothing from an ended stream reaches the next.

use std::time::Duration;

use codewire_credential_bridge::front_door_router::{
    FrontDoorRouter, GuestRoute, HostRoute, Refusal, Refusals,
};
use codewire_credential_bridge::{
    BridgeIdentity, FrontDoorHostSender, FrontDoorHostSession, FrontDoorSessionError,
    SessionStream, binding_ready,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES;
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use prost::Message as _;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// The longest the relay holds the Open after pairing, inside the front
/// door's own 10 seconds.
pub const OPEN_HOLD: Duration = Duration::from_secs(8);
/// How long the front door has to send its Ready once the Open is written,
/// as for a hosted session.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// The bound on one join through the authority.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// The first wait before a failed join is tried again; it doubles up to
/// [`MAX_JOIN_BACKOFF`].
const FIRST_JOIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_JOIN_BACKOFF: Duration = Duration::from_secs(30);
/// How long a frame waits for room toward the platform before its upstream
/// is ended.
const GUEST_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the relay waits to write its last answers before it ends.
const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// The platform end of one join, through the authority.
pub struct DelegatedFrontDoorUpstream {
    /// What the platform admitted for this join.
    pub capabilities: Vec<String>,
    /// Guest frames toward the platform broker.
    pub guest: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    /// Host frames from the platform broker; an error or the end ends it.
    pub host: BoxStream<'static, Result<v1::CredentialBridgeHostMessage, ()>>,
}

/// Joins this relay's admitted delegation to its front-door session, once
/// per call, through the authority (which allows one live join per
/// channel). `None` when the join is refused or fails.
pub trait DelegatedFrontDoorJoiner: Send + 'static {
    fn join(&mut self) -> BoxFuture<'_, Option<DelegatedFrontDoorUpstream>>;
}

/// Why a delegated front-door session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum DelegatedFrontDoorEnd {
    /// The front door closed its side.
    FrontDoorClosed,
    /// The front door broke the protocol: a bad first frame, a second
    /// Ready, or an envelope that cannot be read.
    FrontDoorRefused,
    /// The front door sent no Ready in time.
    ReadyTimedOut,
    /// A write to the front door failed.
    Transport,
}

/// Serve one front-door session on `stream`, already paired, for `identity`.
/// `joiner` arrives once the relay's delegation is admitted; `paired_at` is
/// when the role tag was written.
pub async fn serve_delegated_front_door<S, J>(
    stream: S,
    identity: BridgeIdentity,
    joiner: oneshot::Receiver<J>,
    paired_at: Instant,
) -> DelegatedFrontDoorEnd
where
    S: SessionStream,
    J: DelegatedFrontDoorJoiner,
{
    let pinned: Vec<String> = CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES
        .iter()
        .map(|&capability| capability.to_owned())
        .collect();
    let mut upstreams = Upstreams::new(pinned.clone());
    // The first join, before the Open, bounded by the hold.
    let hold = paired_at + OPEN_HOLD;
    let mut joiner = Joiner::Waiting(joiner);
    if let Joiner::Waiting(handed) = &mut joiner
        && let Ok(Ok(arrived)) = tokio::time::timeout_at(hold, handed).await
    {
        joiner = Joiner::Ready(arrived);
    }
    if let Joiner::Ready(ready) = &mut joiner {
        let first = upstreams.join(ready);
        let _ = tokio::time::timeout_at(hold, first).await; // A missed join is retried on demand.
    }
    let mut session = match FrontDoorHostSession::open(
        stream,
        identity,
        CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES,
    )
    .await
    {
        Ok(session) => session,
        Err(FrontDoorSessionError::InvalidOpen) => {
            return DelegatedFrontDoorEnd::FrontDoorRefused;
        }
        Err(_) => return DelegatedFrontDoorEnd::Transport,
    };
    let sender = session.sender();
    // The front door's first frame must be this binding's Ready, byte for
    // byte, as a hosted session requires; it travels no further.
    let ready = binding_ready(identity.environment_id, identity.environment_generation);
    let end = match tokio::time::timeout(READY_TIMEOUT, session.receive_frame()).await {
        Err(_) => DelegatedFrontDoorEnd::ReadyTimedOut,
        Ok(Ok(Some(first))) if first[..] == ready[..] => {
            if upstreams.router.guest(&first, Instant::now()) == GuestRoute::Ready {
                route(&mut session, &sender, &mut upstreams, joiner).await
            } else {
                DelegatedFrontDoorEnd::FrontDoorRefused
            }
        }
        Ok(Ok(None)) => DelegatedFrontDoorEnd::FrontDoorClosed,
        Ok(_) => DelegatedFrontDoorEnd::FrontDoorRefused,
    };
    // Answers queued for the front door are written before the session ends.
    drop(sender);
    let _ = tokio::time::timeout(FINISH_TIMEOUT, session.finish()).await; // It ends either way.
    end
}

/// The relay's joiner: handed over once its delegation is admitted, which may
/// be after the Open's hold, so it is taken whenever it arrives.
enum Joiner<J> {
    Waiting(oneshot::Receiver<J>),
    Ready(J),
    Gone,
}

impl<J> Joiner<J> {
    /// The joiner, taking it up if it has arrived since.
    fn ready(&mut self) -> Option<&mut J> {
        if let Self::Waiting(handed) = self {
            *self = match handed.try_recv() {
                Ok(joiner) => Self::Ready(joiner),
                Err(oneshot::error::TryRecvError::Empty) => return None,
                Err(oneshot::error::TryRecvError::Closed) => Self::Gone,
            };
        }
        match self {
            Self::Ready(joiner) => Some(joiner),
            _ => None,
        }
    }
}

/// The joined platform upstream, if any, and the router that sees each join
/// as a new upstream.
struct Upstreams {
    router: FrontDoorRouter<u64>,
    current: Option<Joined>,
    next_id: u64,
    retry_at: Instant,
    backoff: Duration,
    refusals: Refusals,
}

struct Joined {
    id: u64,
    /// When it was joined: a join that ends sooner than the backoff counts
    /// as failed, so a guest's frames can't drive joins faster than that.
    since: Instant,
    guest: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    host: BoxStream<'static, Result<v1::CredentialBridgeHostMessage, ()>>,
}

impl Upstreams {
    fn new(pinned: Vec<String>) -> Self {
        Self {
            router: FrontDoorRouter::new(pinned),
            current: None,
            next_id: 0,
            retry_at: Instant::now(),
            backoff: FIRST_JOIN_BACKOFF,
            refusals: Refusals::default(),
        }
    }

    /// Join once, bounded, unless a failed join's backoff is still running.
    /// A join admitting less than the pin is never used.
    async fn join<J: DelegatedFrontDoorJoiner>(&mut self, joiner: &mut J) {
        if Instant::now() < self.retry_at {
            return;
        }
        let joined = tokio::time::timeout(JOIN_TIMEOUT, joiner.join()).await;
        let upstream = match joined {
            Ok(Some(upstream)) if self.router.accepts(&upstream.capabilities) => upstream,
            Ok(Some(upstream)) => {
                let missing: Vec<&String> = self
                    .router
                    .pinned()
                    .iter()
                    .filter(|pinned| !upstream.capabilities.contains(pinned))
                    .collect();
                tracing::warn!(
                    ?missing,
                    "the platform's front-door session admits less than the relay pins"
                );
                self.failed();
                return;
            }
            _ => {
                tracing::warn!("the platform's front-door session was not joined");
                self.failed();
                return;
            }
        };
        self.next_id += 1;
        let id = self.next_id;
        self.router.set_current(Some(id));
        self.current = Some(Joined {
            id,
            since: Instant::now(),
            guest: upstream.guest,
            host: upstream.host,
        });
    }

    /// Where a frame routed to upstream `id` goes, if it is still current.
    fn guest_for(&self, id: u64) -> Option<mpsc::Sender<v1::CredentialBridgeGuestMessage>> {
        self.current
            .as_ref()
            .filter(|joined| joined.id == id)
            .map(|joined| joined.guest.clone())
    }

    fn failed(&mut self) {
        self.retry_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_JOIN_BACKOFF);
    }

    /// The current upstream ended: the answers for the ids it still held.
    /// One that lasted the backoff resets it; one that ended sooner counts
    /// as a failed join, so every join is spaced.
    fn ended(&mut self) -> Vec<v1::CredentialBridgeHostMessage> {
        let Some(joined) = self.current.take() else {
            return Vec::new();
        };
        let now = Instant::now();
        if now.duration_since(joined.since) < self.backoff {
            self.failed();
        } else {
            self.backoff = FIRST_JOIN_BACKOFF;
        }
        self.router.upstream_ended(joined.id, now)
    }

    fn count(&mut self, refusal: Refusal) {
        for (reason, count) in self.refusals.count(refusal) {
            tracing::info!(
                event = "front_door_frames_refused",
                reason = ?reason,
                count,
                "front-door session refused frames"
            );
        }
    }
}

/// Route frames both ways until the front door ends. The platform's end
/// ends only that join; the next request joins again.
async fn route<J: DelegatedFrontDoorJoiner>(
    session: &mut FrontDoorHostSession,
    sender: &FrontDoorHostSender,
    upstreams: &mut Upstreams,
    mut joiner: Joiner<J>,
) -> DelegatedFrontDoorEnd {
    loop {
        tokio::select! {
            received = session.receive_frame() => {
                let frame = match received {
                    Ok(Some(frame)) => frame,
                    Ok(None) => return DelegatedFrontDoorEnd::FrontDoorClosed,
                    Err(_) => return DelegatedFrontDoorEnd::FrontDoorRefused,
                };
                // A request with no upstream waits while the relay joins.
                if upstreams.current.is_none()
                    && let Some(ready) = joiner.ready()
                {
                    upstreams.join(ready).await;
                }
                match upstreams.router.guest(&frame, Instant::now()) {
                    GuestRoute::Forward(id) => {
                        // The router read this envelope; anything it
                        // forwards decodes.
                        let Ok(message) = v1::CredentialBridgeGuestMessage::decode(frame) else {
                            return DelegatedFrontDoorEnd::FrontDoorRefused;
                        };
                        if !forward(upstreams.guest_for(id), message).await
                            && !answer_all(sender, upstreams.ended()).await
                        {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                    }
                    GuestRoute::Answer(answer, refusal) => {
                        upstreams.count(refusal);
                        if sender.send(answer).await.is_err() {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                    }
                    GuestRoute::Drop(refusal) => upstreams.count(refusal),
                    GuestRoute::Cancel { answer, upstream, cancel, refusal } => {
                        upstreams.count(refusal);
                        if !forward(upstreams.guest_for(upstream), *cancel).await
                            && !answer_all(sender, upstreams.ended()).await
                        {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                        if sender.send(answer).await.is_err() {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                    }
                    GuestRoute::Ready | GuestRoute::End => {
                        return DelegatedFrontDoorEnd::FrontDoorRefused;
                    }
                }
            }
            frame = next_host(&mut upstreams.current) => {
                let Some(id) = upstreams.current.as_ref().map(|joined| joined.id) else {
                    continue;
                };
                let Some(Ok(message)) = frame else {
                    if !answer_all(sender, upstreams.ended()).await {
                        return DelegatedFrontDoorEnd::Transport;
                    }
                    continue;
                };
                match upstreams.router.host(id, &message.encode_to_vec(), Instant::now()) {
                    HostRoute::Forward => {
                        if sender.send(message).await.is_err() {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                    }
                    HostRoute::Drop(refusal) => upstreams.count(refusal),
                    HostRoute::EndUpstream(answers, refusal) => {
                        upstreams.count(refusal);
                        tracing::warn!(?refusal, "the platform's front-door session broke the protocol");
                        let rest = upstreams.ended();
                        if !answer_all(sender, answers).await || !answer_all(sender, rest).await {
                            return DelegatedFrontDoorEnd::Transport;
                        }
                    }
                }
            }
        }
    }
}

/// The current upstream's next host frame; never, with none joined.
async fn next_host(
    current: &mut Option<Joined>,
) -> Option<Result<v1::CredentialBridgeHostMessage, ()>> {
    match current.as_mut() {
        Some(joined) => joined.host.next().await,
        None => std::future::pending().await,
    }
}

/// Send `message` toward `guest`, bounded; `None` is an upstream already
/// gone. `false` when it is full or closed, which ends it.
async fn forward(
    guest: Option<mpsc::Sender<v1::CredentialBridgeGuestMessage>>,
    message: v1::CredentialBridgeGuestMessage,
) -> bool {
    match guest {
        Some(guest) => guest
            .send_timeout(message, GUEST_SEND_TIMEOUT)
            .await
            .is_ok(),
        None => true,
    }
}

/// Send each answer to the front door; `false` when it can't be written.
async fn answer_all(
    sender: &FrontDoorHostSender,
    answers: Vec<v1::CredentialBridgeHostMessage>,
) -> bool {
    for answer in answers {
        if sender.send(answer).await.is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests;
