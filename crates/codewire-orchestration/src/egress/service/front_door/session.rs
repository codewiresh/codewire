//! One front-door session across the relay epochs of its binding (#4001).
//!
//! The session holds cw-egress's stream for its whole life while the
//! epochs behind it renew. Each epoch it joins is an upstream; the shared
//! router (`codewire_credential_bridge::front_door_router`) sends each new
//! request to the current upstream and every later frame of a request to
//! the upstream it opened on, so a renewal ends nothing in flight. A newer
//! epoch is joined at the session's next frame after the registry shows it,
//! and an older upstream is closed once it holds no request. A frame waits
//! for room on its upstream, which pauses the session; an upstream whose
//! broker takes nothing for the stall bound is ended, so that pause is
//! bounded too.
//!
//! The session reads each frame's length, the front door's Ready (which must
//! equal its binding's, byte for byte, and is consumed) and, through the
//! router, one field of each message: its request id. It writes the front
//! door's one Open, from the first upstream's capabilities, which the router
//! then pins.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use codewire_credential_bridge::SUCCESSOR_EPOCH_WAIT;
use codewire_credential_bridge::front_door_router::{
    FrontDoorRouter, GuestRoute, HostRoute, Refusal, Refusals,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use futures::stream::{BoxStream, SelectAll};
use prost::Message as _;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};
use tonic::Status;

use crate::front_door::{self, BindingKey, EpochRequest, FrontDoorEpochs, Join, Joined};

/// A cw-egress that takes no frame for this long, or a front door that
/// sends no Ready for this long, ends its session.
pub(crate) const STALL: Duration = Duration::from_secs(30);
/// How long joining an epoch may take; the broker's admission bounds it too.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// A session with no epoch and no upstream for this long ends, so cw-egress
/// opens it again and the Pod's binding is read again: after an unbind or a
/// new generation, this binding's epochs will not come back.
pub(crate) const NO_EPOCH: Duration = Duration::from_secs(60);
/// The upstreams a session holds at once: the current one and one draining.
/// A newer epoch waits until one of them is gone.
const MAX_UPSTREAMS: usize = 2;
/// Between attempts to join an epoch that refused: 1 s, doubling to 30 s.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

type Hosts = SelectAll<BoxStream<'static, (u64, Option<Result<Vec<u8>, Status>>)>>;

/// Join the binding's current epoch: its id and an upstream.
pub(super) async fn join(
    front_doors: &FrontDoorEpochs,
    key: &BindingKey,
) -> Result<(u64, Joined), Status> {
    let (id, epoch) = front_doors.current(key).ok_or_else(no_epoch)?;
    let (reply, joined) = oneshot::channel();
    epoch
        .send(EpochRequest::Join(Join { reply }))
        .await
        .map_err(|_| no_epoch())?;
    let joined = tokio::time::timeout(JOIN_TIMEOUT, joined)
        .await
        .map_err(|_| no_epoch())?
        .map_err(|_| no_epoch())??;
    Ok((id, joined))
}

/// The front door's Open, framed, for the binding and capabilities.
pub(super) fn open_frame(key: &BindingKey, capabilities: &[String]) -> Option<Vec<u8>> {
    let open = v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::Open(
            v1::CredentialBridgeOpen {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: key.environment_id.to_string(),
                environment_generation: key.generation,
                capabilities: capabilities.to_vec(),
                placeholders: Vec::new(),
            },
        )),
    };
    front_door::framed(&open.encode_to_vec())
}

fn no_epoch() -> Status {
    Status::unavailable("no credential relay epoch is running for this Pod")
}

pub(super) struct Session {
    pub(super) front_doors: Arc<FrontDoorEpochs>,
    pub(super) key: BindingKey,
    /// Framed frames for cw-egress, or the error that ends the session.
    pub(super) output: mpsc::Sender<Result<Vec<u8>, Status>>,
    pub(super) stop: CancellationToken,
}

/// The upstreams a session holds, by epoch id.
#[derive(Default)]
struct Upstreams {
    guests: HashMap<u64, mpsc::Sender<Vec<u8>>>,
    guards: HashMap<u64, DropGuard>,
    hosts: Hosts,
    /// Epochs that serve less than the pin, never joined again.
    lesser: HashSet<u64>,
    /// Epochs whose join failed: when to try again, and the last delay.
    retry: HashMap<u64, (Instant, Duration)>,
}

impl Upstreams {
    fn add(&mut self, id: u64, joined: Joined) {
        let Joined {
            guest,
            host,
            session,
            ..
        } = joined;
        self.retry.remove(&id);
        self.guests.insert(id, guest);
        self.guards.insert(id, session);
        self.hosts.push(
            host.map(move |message| (id, Some(message)))
                .chain(futures::stream::once(async move { (id, None) }))
                .boxed(),
        );
    }

    /// Close an upstream; its end marker still arrives and is ignored.
    fn remove(&mut self, id: u64) {
        self.guests.remove(&id);
        self.guards.remove(&id);
    }
}

impl Session {
    /// Serve until cw-egress closes, the front door breaks the protocol,
    /// cw-egress stops reading, or `stop`.
    pub(super) async fn run(
        self,
        first: (u64, Joined),
        mut requests: BoxStream<'static, Result<Vec<u8>, Status>>,
    ) {
        let (first_id, first) = first;
        let mut router = FrontDoorRouter::new(first.capabilities.clone());
        router.set_current(Some(first_id));
        let mut upstreams = Upstreams::default();
        upstreams.add(first_id, first);
        let ready = front_door::binding_ready(self.key.environment_id, self.key.generation);
        let mut readied = false;
        let ready_by = Instant::now() + STALL;
        let mut no_epoch_since = None;
        let mut refusals = Refusals::default();
        loop {
            if router.current().is_none() && upstreams.guests.is_empty() {
                no_epoch_since.get_or_insert_with(Instant::now);
            } else {
                no_epoch_since = None;
            }
            tokio::select! {
                biased;
                () = self.stop.cancelled() => return,
                () = sleep_until(no_epoch_since.map(|since| since + NO_EPOCH)) => {
                    // One more attempt, whatever the backoff: end only when
                    // the registry has no epoch for this binding, or its
                    // epoch cannot be joined.
                    upstreams.retry.clear();
                    self.follow_current(&mut router, &mut upstreams).await;
                    if router.current().is_none() {
                        return self.end(no_epoch()).await;
                    }
                }
                () = tokio::time::sleep_until(ready_by), if !readied => {
                    ready_refused("timeout");
                    return self.end(Status::invalid_argument("a front-door session starts with its binding's Ready")).await;
                }
                frame = requests.next() => {
                    let frame = match frame {
                        None => return,
                        Some(Err(status)) => return self.end(status).await,
                        Some(Ok(frame)) => frame,
                    };
                    let Some(message) = front_door::frame_message(&frame) else {
                        if readied {
                            ended("bad_length");
                        } else {
                            ready_refused("bad_length");
                        }
                        return self.end(Status::invalid_argument("front-door frame is invalid")).await;
                    };
                    if !readied {
                        if message != ready.as_slice() {
                            ready_refused("not_the_bindings_ready");
                            return self.end(Status::invalid_argument("a front-door session starts with its binding's Ready")).await;
                        }
                        readied = true;
                        router.guest(message, Instant::now());
                        continue;
                    }
                    self.follow_current_for_frame(&mut router, &mut upstreams).await;
                    match router.guest(message, Instant::now()) {
                        GuestRoute::Forward(id) => {
                            let sent = match upstreams.guests.get(&id) {
                                Some(guest) => guest.send(message.to_vec()).await.is_ok(),
                                None => false,
                            };
                            if !sent {
                                // The upstream has gone: its requests,
                                // this one too, are answered and finished.
                                let answers = router.upstream_ended(id, Instant::now());
                                upstreams.remove(id);
                                for answer in answers {
                                    if !self.send(&answer.encode_to_vec()).await {
                                        return;
                                    }
                                }
                                if upstreams.guests.is_empty() {
                                    self.follow_current(&mut router, &mut upstreams).await;
                                }
                            }
                        }
                        GuestRoute::Answer(answer, refusal) => {
                            count_refusal(&mut refusals, refusal);
                            if !self.send(&answer.encode_to_vec()).await {
                                return;
                            }
                        }
                        GuestRoute::Drop(refusal) => count_refusal(&mut refusals, refusal),
                        GuestRoute::Cancel { answer, upstream, cancel, refusal } => {
                            // The router has ended this live id: its upstream
                            // stops it, and the front door reads the answer.
                            count_refusal(&mut refusals, refusal);
                            let sent = match upstreams.guests.get(&upstream) {
                                Some(guest) => guest.send(cancel.encode_to_vec()).await.is_ok(),
                                None => false,
                            };
                            if !self.send(&answer.encode_to_vec()).await {
                                return;
                            }
                            if !sent {
                                let answers = router.upstream_ended(upstream, Instant::now());
                                upstreams.remove(upstream);
                                for answer in answers {
                                    if !self.send(&answer.encode_to_vec()).await {
                                        return;
                                    }
                                }
                                if upstreams.guests.is_empty() {
                                    self.follow_current(&mut router, &mut upstreams).await;
                                }
                            }
                        }
                        GuestRoute::Ready | GuestRoute::End => {
                            ended("malformed_envelope");
                            return self.end(Status::invalid_argument("front-door frame is invalid")).await;
                        }
                    }
                }
                Some((id, message)) = upstreams.hosts.next() => {
                    if !upstreams.guests.contains_key(&id) {
                        continue;
                    }
                    let answers = match message {
                        Some(Ok(message)) => match router.host(id, &message, Instant::now()) {
                            HostRoute::Forward => {
                                if !self.send(&message).await {
                                    return;
                                }
                                if !router.holds(id) && router.current() != Some(id) {
                                    upstreams.remove(id);
                                }
                                continue;
                            }
                            // A late frame for an id the router cancelled on
                            // this upstream, already answered.
                            HostRoute::Drop(refusal) => {
                                count_refusal(&mut refusals, refusal);
                                if !router.holds(id) && router.current() != Some(id) {
                                    upstreams.remove(id);
                                }
                                continue;
                            }
                            HostRoute::EndUpstream(answers, refusal) => {
                                count_refusal(&mut refusals, refusal);
                                answers
                            }
                        },
                        Some(Err(_)) | None => router.upstream_ended(id, Instant::now()),
                    };
                    upstreams.remove(id);
                    for answer in answers {
                        if !self.send(&answer.encode_to_vec()).await {
                            return;
                        }
                    }
                    // A quiet session's last upstream ends at every renewal:
                    // join the successor now, not at the next frame.
                    if upstreams.guests.is_empty() {
                        self.follow_current(&mut router, &mut upstreams).await;
                    }
                }
            }
        }
    }

    /// Join the binding's current epoch if it is newer than the router's,
    /// and make it current when it serves everything pinned. The older
    /// upstream keeps only the requests it holds.
    async fn follow_current(&self, router: &mut FrontDoorRouter<u64>, upstreams: &mut Upstreams) {
        let Some((id, _)) = self.front_doors.current(&self.key) else {
            return;
        };
        if router.current() == Some(id)
            || upstreams.guests.contains_key(&id)
            || upstreams.lesser.contains(&id)
            || upstreams.guests.len() >= MAX_UPSTREAMS
        {
            return;
        }
        let now = Instant::now();
        if upstreams.retry.get(&id).is_some_and(|(at, _)| now < *at) {
            return;
        }
        let joined = match join(&self.front_doors, &self.key).await {
            Ok((joined_id, joined)) if joined_id == id => joined,
            _ => {
                let delay = upstreams
                    .retry
                    .get(&id)
                    .map_or(RETRY_FIRST, |(_, delay)| (*delay * 2).min(RETRY_MAX));
                upstreams.retry.insert(id, (now + delay, delay));
                return;
            }
        };
        if !router.accepts(&joined.capabilities) {
            upstreams.lesser.insert(id);
            return;
        }
        let previous = router.current();
        upstreams.add(id, joined);
        router.set_current(Some(id));
        if let Some(previous) = previous
            && !router.holds(previous)
        {
            upstreams.remove(previous);
        }
    }

    /// Before a new frame is routed: between epochs, with nothing draining,
    /// wait for the successor instead of refusing the frame (#6099). With a
    /// predecessor still draining, the loop keeps serving it and the frame is
    /// routed at once. A stop ends the wait; the frame is then refused and
    /// the loop returns.
    async fn follow_current_for_frame(
        &self,
        router: &mut FrontDoorRouter<u64>,
        upstreams: &mut Upstreams,
    ) {
        if router.current().is_none() && upstreams.guests.is_empty() {
            let successor = Instant::now() + SUCCESSOR_EPOCH_WAIT;
            tokio::select! {
                () = self.stop.cancelled() => return,
                _ = self.front_doors.wait_for_epoch(&self.key, successor) => {}
            }
        }
        self.follow_current(router, upstreams).await;
    }

    /// One message to cw-egress, framed. False once cw-egress has gone or
    /// took nothing for [`STALL`]; the session then ends.
    async fn send(&self, message: &[u8]) -> bool {
        let Some(frame) = front_door::framed(message) else {
            return false;
        };
        matches!(
            tokio::time::timeout(STALL, self.output.send(Ok(frame))).await,
            Ok(Ok(()))
        )
    }

    async fn end(&self, status: Status) {
        // The session ends either way; the error is only its reason.
        let _ = self.output.try_send(Err(status));
    }
}

/// Never, without a deadline.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// A session whose front door did not start with its binding's Ready, by a
/// fixed class only. A front door on another bridge protocol version is
/// refused here every time, so cw-egress and orchestration roll out together.
fn ready_refused(class: &'static str) {
    tracing::warn!(
        event = "front_door_ready_refused",
        class,
        "front-door session did not start with its binding's Ready"
    );
}

/// A session ended by its front door's frame, by a fixed class only.
fn ended(class: &'static str) {
    tracing::warn!(
        event = "front_door_session_ended",
        class,
        "front-door session ended on a frame it could not read"
    );
}

/// Log a session's refusal counts, at most once a minute (`Refusals`).
fn count_refusal(refusals: &mut Refusals, refusal: Refusal) {
    for (reason, count) in refusals.count(refusal) {
        tracing::info!(
            event = "front_door_frames_refused",
            reason = ?reason,
            count,
            "front-door session refused frames"
        );
    }
}
