//! A hosted sandbox's egress loop (#4000 P4, item 2): the daemon's side of
//! its stream to cw-egress.
//!
//! Each round dials and authenticates a stream, reports the host's egress
//! trust, runs the self-check under a bound and sends its result as the first
//! guest frame, reports the daemon ready after the first pass only, then
//! carries packets between the TUN and the stream until either side fails.
//! Any failure backs off for a bounded few seconds. The TUN is drained
//! whenever no stream carries it, while dialling and checking as well as
//! backing off, so the sandbox has no egress while it is down and nothing it
//! sent then is delivered later. Only a stream that carried packets for a
//! while counts as established: the first redial after one goes at once, and
//! a stream the host drops at once backs off like any failure.
//!
//! The protocol's self-check result has no "timed out" reason, so a check that
//! does not finish within its bound sends nothing: the stream is dropped, and
//! the host, whose own wait is longer, records the sandbox as failed closed. A
//! failed check is sent, and readiness is never reported for it.
//!
//! Two round ends are not healed by redialling: a session whose trust differs
//! from the pinned one, and cw-egress refusing the daemon's session version.
//! Those are paced apart from the loop's own backoff, and slower.

use std::convert::Infallible;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use super::{
    GuestBridgeError, GuestSession, PROBE_TIMEOUT, SelfCheckProbes, bridge_guest, read_tun_packet,
    self_check,
};
use crate::hosted::HOSTED_TUN_MTU;
use crate::{EgressTrust, SelfCheck, SelfCheckFailure, SessionLimits};

/// The loop's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedEgressConfig {
    /// The TUN's MTU: no packet larger than this crosses.
    pub mtu: usize,
    /// How long the self-check may take: shorter than the host's own wait for
    /// its result, so a slow pass still reaches a host that is listening.
    pub self_check_bound: Duration,
    /// The first wait after a round that never established a stream.
    pub first_backoff: Duration,
    /// The longest wait between rounds.
    pub max_backoff: Duration,
    /// How long a stream must carry packets to count as established, so the
    /// next redial goes at once and the backoff starts over.
    pub steady_after: Duration,
    /// The first wait after a round that redialling cannot heal: a session
    /// whose trust differs from the pinned one (#5006), which only a restart
    /// of the Sandbox heals, or a session version cw-egress refuses, which
    /// only an update does. It is paced apart from, and slower than, the
    /// loop's own backoff: a node that lost a Pod's CA, or runs another
    /// version, is not met with a dial from every Sandbox every few seconds.
    pub unhealed_backoff: Duration,
    /// The longest wait between such rounds.
    pub unhealed_max_backoff: Duration,
}

impl HostedEgressConfig {
    /// A hosted sandbox's: the TUN's MTU, 8 s for the self-check against the
    /// host's 10 s wait, waits from half a second to five, and 10 s of carried
    /// packets to count as established.
    pub const HOSTED: Self = Self {
        mtu: HOSTED_TUN_MTU,
        self_check_bound: Duration::from_secs(8),
        first_backoff: Duration::from_millis(500),
        max_backoff: Duration::from_secs(5),
        steady_after: Duration::from_secs(10),
        // The values of the daemon's binding refusal pacing,
        // `BROKER_REFUSAL_RETRY_INITIAL` and `BROKER_REFUSAL_RETRY_MAX` in
        // codewire-workspace-access (#5039), which a refusal that redialling
        // cannot heal shares.
        unhealed_backoff: Duration::from_secs(30),
        unhealed_max_backoff: Duration::from_secs(60),
    };
}

// The probes run side by side, each blocked by its own timeout, so the whole
// check takes about one PROBE_TIMEOUT. The bound must leave room for that
// twice over, so it only ever fires on a hang (#4000).
const _: () = assert!(
    PROBE_TIMEOUT.as_millis() * 2 <= HostedEgressConfig::HOSTED.self_check_bound.as_millis()
);

/// Opens one authenticated stream: dial cw-egress, send the hello with a
/// fresh token, read the node's nonce, derive the stream key and run
/// [`super::authenticate_guest`].
pub trait EgressConnector {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    type Error: std::error::Error;

    fn connect(
        &self,
    ) -> impl Future<Output = Result<GuestSession<Self::Stream>, Self::Error>> + Send;

    /// The version refusal `error` is, if it is one: cw-egress answered the
    /// hello with the session versions it accepts.
    fn version_refused(_error: &Self::Error) -> Option<VersionRefused> {
        None
    }
}

/// cw-egress accepts session versions `lowest` to `highest`, and this daemon
/// speaks `spoken`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRefused {
    pub lowest: u16,
    pub highest: u16,
    pub spoken: u16,
}

/// What the loop reports, for the daemon to act on and log.
pub trait EgressEvents {
    /// The host's egress trust, from each stream's first frame.
    fn egress_trust(&mut self, trust: &EgressTrust);
    /// The first self-check passed: the daemon may serve. Called once.
    fn ready(&mut self);
    /// A round ended, and why.
    fn round_ended(&mut self, end: &RoundEnd);
}

/// Why a round ended.
#[derive(Debug)]
pub enum RoundEnd {
    /// No authenticated stream: the dial, the hello or the handshake failed,
    /// with the error and its sources.
    Connect(String),
    /// The self-check did not finish within its bound; nothing was sent.
    SelfCheckTimedOut,
    /// The self-check found the lockdown not enforcing; the result was sent.
    SelfCheckFailed(SelfCheckFailure),
    /// The self-check's result could not be sent.
    SendSelfCheck,
    /// The stream carried packets, then the bridge ended.
    Bridge(Result<(), GuestBridgeError>),
    /// The host's egress trust differs from the one pinned when the daemon
    /// first became ready, which the daemon installed and the workload now
    /// trusts. The stream is dropped before its self-check, never bridged or
    /// reported, and the loop redials (#5006).
    TrustChanged,
    /// cw-egress refused the daemon's session version before it read the
    /// token, so no stream was opened. Only an update of one of them heals
    /// it (#4000).
    VersionRefused(VersionRefused),
}

/// Run the egress loop for as long as the daemon runs. `self_check` runs the
/// probes once per stream (`guest::self_check`), and `tun` is the
/// sandbox's TUN device, opened by the daemon.
pub async fn run<C, F, Fut, E>(
    config: &HostedEgressConfig,
    connector: &C,
    self_check: F,
    tun: Arc<AsyncFd<OwnedFd>>,
    events: &mut E,
) -> Infallible
where
    C: EgressConnector,
    F: Fn() -> Fut,
    Fut: Future<Output = SelfCheck>,
    E: EgressEvents,
{
    // The trust of the session that first became ready; `Some` once ready.
    let mut pinned = None;
    let mut backoff = config.first_backoff;
    let mut unhealed_backoff = config.unhealed_backoff;
    loop {
        let (end, bridged) = round(config, connector, &self_check, &tun, events, &mut pinned).await;
        events.round_ended(&end);
        match end {
            RoundEnd::TrustChanged | RoundEnd::VersionRefused(_) => {
                drain(&tun, unhealed_backoff).await;
                unhealed_backoff = unhealed_backoff
                    .saturating_mul(2)
                    .min(config.unhealed_max_backoff);
                continue;
            }
            // Only a session cw-egress admitted, with the pinned trust,
            // reaches the bridge.
            RoundEnd::Bridge(_) => unhealed_backoff = config.unhealed_backoff,
            _ => {}
        }
        if bridged >= config.steady_after {
            backoff = config.first_backoff;
            continue;
        }
        drain(&tun, backoff).await;
        backoff = backoff.saturating_mul(2).min(config.max_backoff);
    }
}

/// [`run`] with the Pod's own probes.
pub async fn run_with_probes<C, P, E>(
    config: &HostedEgressConfig,
    connector: &C,
    probes: &P,
    tun: Arc<AsyncFd<OwnedFd>>,
    events: &mut E,
) -> Infallible
where
    C: EgressConnector,
    P: SelfCheckProbes + Sync,
    E: EgressEvents,
{
    run(config, connector, || self_check(probes), tun, events).await
}

/// One round, and how long its stream carried packets (zero when it never
/// bridged).
async fn round<C, F, Fut, E>(
    config: &HostedEgressConfig,
    connector: &C,
    self_check: &F,
    tun: &Arc<AsyncFd<OwnedFd>>,
    events: &mut E,
    pinned: &mut Option<EgressTrust>,
) -> (RoundEnd, Duration)
where
    C: EgressConnector,
    F: Fn() -> Fut,
    Fut: Future<Output = SelfCheck>,
    E: EgressEvents,
{
    let GuestSession {
        mut stream,
        mut session,
        egress_trust,
    } = match draining(tun, connector.connect()).await {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let end = match C::version_refused(&error) {
                Some(refused) => RoundEnd::VersionRefused(refused),
                None => RoundEnd::Connect(with_sources(&error)),
            };
            return (end, Duration::ZERO);
        }
    };
    // Every session's trust is reported, except one that differs from the
    // trust pinned when the daemon first became ready: the daemon installed
    // that one before it served, so a redial with another is ended before its
    // self-check and never bridged (#5006).
    if pinned
        .as_ref()
        .is_some_and(|pinned| *pinned != egress_trust)
    {
        return (RoundEnd::TrustChanged, Duration::ZERO);
    }
    events.egress_trust(&egress_trust);
    let check = tokio::time::timeout(config.self_check_bound, self_check());
    let Ok(result) = draining(tun, check).await else {
        return (RoundEnd::SelfCheckTimedOut, Duration::ZERO);
    };
    let Ok(frame) = session.encode_self_check(result) else {
        return (RoundEnd::SendSelfCheck, Duration::ZERO);
    };
    if stream.write_all(&frame).await.is_err() || stream.flush().await.is_err() {
        return (RoundEnd::SendSelfCheck, Duration::ZERO);
    }
    if let SelfCheck::Failed(reason) = result {
        return (RoundEnd::SelfCheckFailed(reason), Duration::ZERO);
    }
    if pinned.is_none() {
        *pinned = Some(egress_trust);
        events.ready();
    }
    let bridged = Instant::now();
    let end = bridge_guest(stream, session, Arc::clone(tun), config.mtu).await;
    (RoundEnd::Bridge(end), bridged.elapsed())
}

/// `error` and each of its sources, joined as `outer: inner`.
fn with_sources(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
    }
    text
}

/// Read and drop the TUN's packets for `wait`.
async fn drain(tun: &AsyncFd<OwnedFd>, wait: Duration) {
    if let Ok(never) = tokio::time::timeout(wait, drain_forever(tun)).await {
        match never {}
    }
}

/// `work`, with the TUN drained until it finishes, so nothing the workload
/// sends before a stream carries it is queued for one.
async fn draining<T>(tun: &AsyncFd<OwnedFd>, work: impl Future<Output = T>) -> T {
    tokio::select! {
        output = work => output,
        never = drain_forever(tun) => match never {},
    }
}

/// Read and drop the TUN's packets. A read error, such as a packet over the
/// bound, ends the reading but never the wait.
async fn drain_forever(tun: &AsyncFd<OwnedFd>) -> Infallible {
    let bound = SessionLimits::HOSTED.packet_bound();
    while read_tun_packet(tun, bound).await.is_ok() {}
    std::future::pending().await
}

#[cfg(target_os = "linux")]
mod connector;
#[cfg(target_os = "linux")]
pub use connector::{ConnectError, PodConnector};

#[cfg(test)]
mod tests;
