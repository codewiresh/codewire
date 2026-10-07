//! One environment's relay epochs over existing private RPCs, moved from the
//! per-environment gateway (design §4). The daemon leg keeps the existing
//! authenticated plaintext cluster trust; the broker leg reloads TLS trust and
//! presents orchestration's relay token with the daemon's workspace token.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_daemon::client::{CredentialBridgeResponseSender, SessionClient, SessionClientError};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_daemon_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_tls::ClientTlsEndpoint;
use prost::Message as _;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tonic::metadata::MetadataValue;
use tonic::{Status, Streaming};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::budget::{Charge, EnvironmentBudget, Oversized, StreamBudget};
use super::connection::{self, DaemonTarget};

const PREPARE_TIMEOUT: Duration = Duration::from_secs(10);
const BROKER_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const EPOCH_MAX_LIFETIME: Duration = Duration::from_secs(600);
/// Before the next epoch when none is admitted.
const RETRY_DELAY: Duration = Duration::from_secs(1);
/// The successor is started this long before the current epoch ends. Kubelet
/// replaces a projected token about 120 seconds (with jitter) before it
/// expires, so by now both Pods' replacement tokens normally exist.
const SUCCESSOR_LEAD: Duration = Duration::from_secs(90);
/// Between successor attempts while the current epoch is still admitted: 3
/// seconds, doubling to at most 15.
const SUCCESSOR_RETRY_FIRST: Duration = Duration::from_secs(3);
const SUCCESSOR_RETRY_MAX: Duration = Duration::from_secs(15);
/// A successor must expire at least this much later than the current epoch.
/// Otherwise kubelet has not rotated a projected token yet and the successor
/// would end with the current one.
const SUCCESSOR_MIN_EXTENSION_SECS: u64 = 60;
/// A projected token lasts 600 seconds; allow some clock skew, no more.
const EXPIRY_MAX_AHEAD_SECS: u64 = 660;
/// Decimal digits in a `u64` Unix time.
const EXPIRY_MAX_DIGITS: usize = 20;
/// Frames queued toward the broker; their bytes are bounded separately.
const FRAME_BUFFER: usize = 32;
const WORKSPACE_AUTHORIZATION: &str = codewire_daemon::client::HOSTED_WORKSPACE_AUTHORIZATION;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// What every epoch of one environment's relay presents.
#[derive(Clone)]
pub(super) struct EpochConfig {
    pub(super) environment_id: Uuid,
    pub(super) generation: u64,
    pub(super) daemon: DaemonTarget,
    pub(super) relay_token: PathBuf,
    pub(super) broker: BrokerEndpoint,
    pub(super) budget: EnvironmentBudget,
}

#[derive(Clone)]
pub(super) enum BrokerEndpoint {
    Tls(ClientTlsEndpoint),
    #[cfg(test)]
    Preconfigured(tonic::transport::Channel),
}

/// An epoch's own forwarding task failed. Every epoch severs its daemon
/// connection and seals its broker queue whatever happened, so nothing else
/// can leave an epoch's frames behind.
#[derive(Debug, thiserror::Error)]
#[error("credential relay epoch failed")]
pub(super) struct DrainFailure;

/// The broker's identity expiry for one admitted epoch, from its response
/// header. It only schedules and checks the successor; it grants nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BrokerExpiry {
    unix: u64,
    at: Instant,
}

/// Reported once the daemon has been sent this epoch's Open.
#[derive(Debug)]
struct Admitted {
    /// Absent from a malformed header: the epoch then renews after it ends.
    expiry: Option<BrokerExpiry>,
    /// The relay's own bound on the epoch.
    lifetime_ends: Instant,
}

/// What the relay asks one new epoch to do.
struct EpochStart {
    cancellation: CancellationToken,
    admitted: oneshot::Sender<Admitted>,
    /// For a successor: the current epoch's expiry, which it must extend by
    /// at least [`SUCCESSOR_MIN_EXTENSION_SECS`] before its Open is sent.
    succeeds: Option<u64>,
}

type EpochFuture<'a> = Pin<Box<dyn Future<Output = Result<(), DrainFailure>> + Send + 'a>>;

/// Relays one environment's bridge until `shutdown` completes. Readiness
/// never awaits it. New epochs reread both tokens; no request from an old
/// epoch is retained or replayed.
///
/// The relay admits the next epoch about 90 seconds before the current one's
/// identity expires; new requests move to it, and the old epoch finishes only
/// the requests already sent on it, until its own identity expires. It keeps
/// the current epoch and either its successor or its draining predecessor.
/// The successor's Open is sent only when the broker reports an expiry at
/// least 60 seconds later; otherwise the still-prepared successor is dropped,
/// the daemon is unaffected, and another is tried after 3 seconds, doubling
/// to 15, until the current epoch expires.
///
/// Every epoch presents the daemon credential of the exact bound Pod its
/// owner was started for, on its own daemon connection. A replaced Pod or
/// generation is a new binding, and the supervisor replaces this relay rather
/// than retrying a refused one.
///
/// `admissible` is whether the broker can admit this environment yet: it
/// refuses every epoch until the environment is running. A fresh epoch
/// starts only while it is true, and at once when it turns true, so no
/// attempt is spent before and none waits for a retry delay after.
pub(super) async fn run(
    config: &EpochConfig,
    admissible: watch::Receiver<bool>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), DrainFailure> {
    relay(
        config.environment_id,
        admissible,
        move |start| Box::pin(async move { run_epoch(config, start).await }),
        shutdown,
    )
    .await
}

/// An epoch started but not yet admitted.
struct Starting<'a> {
    future: EpochFuture<'a>,
    admitted: Option<oneshot::Receiver<Admitted>>,
}

/// An admitted epoch.
struct Serving<'a> {
    future: EpochFuture<'a>,
    renewal: Option<Renewal>,
}

/// When an admitted epoch with a known expiry is succeeded.
#[derive(Clone, Copy)]
struct Renewal {
    expires_at_unix: u64,
    /// The earlier of the broker's expiry and the relay's own lifetime.
    ends_at: Instant,
    successor_at: Instant,
}

impl Renewal {
    fn new(admitted: &Admitted) -> Option<Self> {
        let expiry = admitted.expiry?;
        let ends_at = expiry.at.min(admitted.lifetime_ends);
        Some(Self {
            expires_at_unix: expiry.unix,
            ends_at,
            successor_at: ends_at.checked_sub(SUCCESSOR_LEAD).unwrap_or(ends_at),
        })
    }
}

enum StartingEvent {
    Admitted(Admitted),
    /// Ended; `admitted` is set when it was admitted in the same poll.
    Finished {
        admitted: Option<Admitted>,
        result: Result<(), DrainFailure>,
    },
}

/// Owns every epoch future until it completes. A failed drain or shutdown
/// cancels and awaits all of them; dropping one would abandon its producers.
async fn relay<'a, S, D>(
    environment_id: Uuid,
    mut admissible: watch::Receiver<bool>,
    mut start: S,
    shutdown: D,
) -> Result<(), DrainFailure>
where
    S: FnMut(EpochStart) -> EpochFuture<'a>,
    D: Future<Output = ()>,
{
    let root = CancellationToken::new();
    let mut can_admit = *admissible.borrow_and_update();
    let mut first = FirstAdmission::new(can_admit);
    let mut launch = |succeeds: Option<u64>| {
        let (admitted, receiver) = oneshot::channel();
        Starting {
            future: start(EpochStart {
                cancellation: root.child_token(),
                admitted,
                succeeds,
            }),
            admitted: Some(receiver),
        }
    };
    // Normally two epochs exist: `serving` with `starting` or a `retiring`
    // predecessor, or a fresh `starting` while a predecessor finishes. A
    // successor starts only while nothing retires; `retiring` still holds
    // every replaced epoch, so none is ever dropped without being awaited.
    let mut serving: Option<Serving<'a>> = None;
    let mut retiring: Vec<EpochFuture<'a>> = Vec::new();
    let mut starting: Option<Starting<'a>> = None;
    let mut fresh_at = Instant::now();
    let mut successor_retry_at: Option<Instant> = None;
    let mut successor_refusals = 0_u32;
    tokio::pin!(shutdown);
    let result = loop {
        let next = next_start(
            serving.as_ref(),
            !retiring.is_empty(),
            starting.is_some(),
            can_admit.then_some(fresh_at),
            successor_retry_at,
        );
        tokio::select! {
            biased;
            _ = &mut shutdown => break Ok(()),
            event = starting_event(&mut starting) => {
                let Some(epoch) = starting.take() else {
                    continue;
                };
                let (admitted, finished) = match event {
                    StartingEvent::Admitted(admitted) => (Some(admitted), None),
                    StartingEvent::Finished { admitted, result } => (admitted, Some(result)),
                };
                let Some(admitted) = admitted else {
                    // Refused or failed before its Open: the daemon kept its
                    // current epoch. Try again while that epoch lasts.
                    if let Some(Err(error)) = finished {
                        break Err(error);
                    }
                    let now = Instant::now();
                    if serving.is_some() {
                        successor_retry_at = Some(now + successor_backoff(successor_refusals));
                        successor_refusals = successor_refusals.saturating_add(1);
                    } else {
                        fresh_at = now + RETRY_DELAY;
                    }
                    continue;
                };
                successor_retry_at = None;
                successor_refusals = 0;
                first.admitted(environment_id);
                let renewal = Renewal::new(&admitted);
                if let Some(previous) = serving.take() {
                    // The daemon moved new work to this epoch; the previous
                    // one finishes only what was already sent on it.
                    log_overlap(environment_id, previous.renewal, renewal);
                    retiring.push(previous.future);
                }
                match finished {
                    None => {
                        serving = Some(Serving {
                            future: epoch.future,
                            renewal,
                        });
                    }
                    Some(Err(error)) => break Err(error),
                    Some(Ok(())) => {
                        log_ended(environment_id);
                        fresh_at = Instant::now() + RETRY_DELAY;
                    }
                }
            }
            result = finished(serving.as_mut().map(|current| &mut current.future)) => {
                // An admitted successor would have moved it to `retiring`.
                serving = None;
                successor_retry_at = None;
                successor_refusals = 0;
                if let Err(error) = result {
                    break Err(error);
                }
                log_ended(environment_id);
                fresh_at = Instant::now() + RETRY_DELAY;
            }
            result = first_finished(&mut retiring) => {
                if let Err(error) = result {
                    break Err(error);
                }
            }
            now = admission_changed(&mut admissible) => {
                if now && !can_admit {
                    // The broker can admit it from now on: try at once,
                    // without waiting out a refusal's retry delay.
                    fresh_at = Instant::now();
                    first.admissible();
                }
                can_admit = now;
            }
            _ = sleep_until(next.map(|(at, _)| at)), if next.is_some() => {
                let succeeds = next.and_then(|(_, succeeds)| succeeds);
                if succeeds.is_none() {
                    first.attempt();
                }
                starting = Some(launch(succeeds));
            }
        }
    };
    // Cancel every epoch, then await all their producers together.
    root.cancel();
    let remaining = serving
        .map(|current| current.future)
        .into_iter()
        .chain(retiring)
        .chain(starting.map(|starting| starting.future))
        .collect();
    result.and(drain_all(remaining).await)
}

/// After `refusals` earlier refusals of this epoch's successor.
fn successor_backoff(refusals: u32) -> Duration {
    SUCCESSOR_RETRY_FIRST
        .checked_mul(2_u32.saturating_pow(refusals.min(8)))
        .map_or(SUCCESSOR_RETRY_MAX, |delay| delay.min(SUCCESSOR_RETRY_MAX))
}

/// The first of `futures` to finish, removed; pending while there are none.
async fn first_finished(futures: &mut Vec<EpochFuture<'_>>) -> Result<(), DrainFailure> {
    if futures.is_empty() {
        return std::future::pending().await;
    }
    std::future::poll_fn(|context| {
        for index in 0..futures.len() {
            if let Poll::Ready(result) = futures[index].as_mut().poll(context) {
                drop(futures.swap_remove(index));
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    })
    .await
}

/// Await every future concurrently; any failure fails the whole drain.
async fn drain_all(mut futures: Vec<EpochFuture<'_>>) -> Result<(), DrainFailure> {
    let mut failed = false;
    std::future::poll_fn(|context| {
        futures.retain_mut(|future| match future.as_mut().poll(context) {
            Poll::Ready(outcome) => {
                failed |= outcome.is_err();
                false
            }
            Poll::Pending => true,
        });
        if futures.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    if failed { Err(DrainFailure) } else { Ok(()) }
}

/// When the next epoch starts and, for a successor, the expiry it must
/// extend. None while an epoch is starting, while a predecessor still
/// retires, when the serving epoch reported no expiry or has ended, or, for
/// a fresh epoch, while the broker cannot admit one (`fresh_at` None).
fn next_start(
    serving: Option<&Serving<'_>>,
    retiring: bool,
    starting: bool,
    fresh_at: Option<Instant>,
    successor_retry_at: Option<Instant>,
) -> Option<(Instant, Option<u64>)> {
    if starting {
        return None;
    }
    let Some(current) = serving else {
        return fresh_at.map(|at| (at, None));
    };
    let renewal = current.renewal.filter(|_| !retiring)?;
    let at = successor_retry_at.map_or(renewal.successor_at, |retry| {
        retry.max(renewal.successor_at)
    });
    (at < renewal.ends_at).then_some((at, Some(renewal.expires_at_unix)))
}

async fn starting_event(starting: &mut Option<Starting<'_>>) -> StartingEvent {
    let Some(starting) = starting else {
        return std::future::pending().await;
    };
    std::future::poll_fn(|context| {
        if let Some(admitted) = starting.admitted.as_mut() {
            match Pin::new(admitted).poll(context) {
                Poll::Ready(Ok(admitted)) => {
                    starting.admitted = None;
                    return Poll::Ready(StartingEvent::Admitted(admitted));
                }
                // Dropped unsent: this epoch was never admitted.
                Poll::Ready(Err(_)) => starting.admitted = None,
                Poll::Pending => {}
            }
        }
        starting.future.as_mut().poll(context).map(|result| {
            // It may have been admitted and ended within this one poll.
            let admitted = starting
                .admitted
                .take()
                .and_then(|mut admitted| admitted.try_recv().ok());
            StartingEvent::Finished { admitted, result }
        })
    })
    .await
}

async fn finished(future: Option<&mut EpochFuture<'_>>) -> Result<(), DrainFailure> {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The next admissibility value. A relay whose supervisor has gone keeps the
/// last one; its shutdown follows.
async fn admission_changed(admissible: &mut watch::Receiver<bool>) -> bool {
    if admissible.changed().await.is_err() {
        return std::future::pending().await;
    }
    *admissible.borrow_and_update()
}

/// How the relay's first epoch came to be admitted, logged once: the attempts
/// it took and how long after the broker could admit it.
struct FirstAdmission {
    admissible_at: Option<Instant>,
    attempts: u32,
    logged: bool,
}

impl FirstAdmission {
    fn new(admissible: bool) -> Self {
        Self {
            admissible_at: admissible.then(Instant::now),
            attempts: 0,
            logged: false,
        }
    }

    fn admissible(&mut self) {
        self.admissible_at.get_or_insert_with(Instant::now);
    }

    fn attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    fn admitted(&mut self, environment_id: Uuid) {
        if std::mem::replace(&mut self.logged, true) {
            return;
        }
        let after_admissible_ms = self.admissible_at.map_or(0, |at| {
            u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)
        });
        tracing::info!(
            event = "credential_bridge_first_epoch_admitted",
            %environment_id,
            attempts = self.attempts,
            after_admissible_ms,
            "credential relay admitted its first epoch"
        );
    }
}

fn log_overlap(environment_id: Uuid, previous: Option<Renewal>, next: Option<Renewal>) {
    let now = Instant::now();
    let ends_in = |renewal: Option<Renewal>| {
        renewal.map_or(0, |renewal| {
            u64::try_from(renewal.ends_at.saturating_duration_since(now).as_millis())
                .unwrap_or(u64::MAX)
        })
    };
    tracing::info!(
        event = "credential_bridge_epoch_overlap",
        %environment_id,
        previous_ends_in_ms = ends_in(previous),
        next_ends_in_ms = ends_in(next),
        "credential relay admitted the next epoch; the previous epoch finishes only its pending requests"
    );
}

fn log_ended(environment_id: Uuid) {
    tracing::info!(
        event = "credential_bridge_epoch_ended",
        %environment_id,
        "credential relay epoch ended without an admitted successor"
    );
}

/// Why an epoch's relay stopped forwarding. Fixed reasons only: no frame
/// content or size is logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// A frame toward the broker is larger than a whole budget.
    Oversized,
    /// A frame made no progress for the stall timeout.
    Stalled,
}

impl Ended {
    fn log(self, environment_id: Uuid) {
        tracing::warn!(
            event = "credential_bridge_relay_bounded",
            %environment_id,
            reason = match self {
                Self::Oversized => "oversized",
                Self::Stalled => "stalled",
            },
            "credential relay ended an epoch at its byte or progress bound"
        );
    }
}

async fn run_epoch(config: &EpochConfig, start: EpochStart) -> Result<(), DrainFailure> {
    run_epoch_with_lifetime(config, start, EPOCH_MAX_LIFETIME).await
}

async fn run_epoch_with_lifetime(
    config: &EpochConfig,
    start: EpochStart,
    lifetime: Duration,
) -> Result<(), DrainFailure> {
    let severed = CancellationToken::new();
    let Ok(daemon) = connection::connect(&config.daemon, severed.clone()) else {
        Unadmitted::DaemonEndpoint.log(config.environment_id, start.succeeds);
        return Ok(());
    };
    run_epoch_on(config, &daemon, &severed, start, lifetime).await
}

/// Why an epoch ended before its broker admitted it, and at which hop: the
/// relay itself, the daemon or the broker. Closed reasons and gRPC codes
/// only: never a frame, token or status message. A status that tonic made
/// from a transport failure carries its error as a source, and is
/// "unreachable"; one the peer answered has none, and is "refused". A
/// successor's own refusal is logged where it is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unadmitted {
    DaemonEndpoint,
    DaemonUnreachable(Option<tonic::Code>),
    DaemonRefused(tonic::Code),
    DaemonReady,
    RelayToken,
    BrokerConnect,
    PrepareTimeout,
    BrokerTimeout,
    BrokerUnreachable(tonic::Code),
    BrokerRefused(tonic::Code),
    Activation,
}

/// Whether tonic made `status` from a local transport failure rather than
/// receiving it from the peer.
fn transport_failure(status: &Status) -> bool {
    std::error::Error::source(status).is_some()
}

impl Unadmitted {
    fn from_daemon(error: &SessionClientError) -> Self {
        match error {
            SessionClientError::Status(status) if transport_failure(status) => {
                Self::DaemonUnreachable(Some(status.code()))
            }
            SessionClientError::Status(status) => Self::DaemonRefused(status.code()),
            SessionClientError::InvalidCredential => Self::DaemonReady,
            _ => Self::DaemonUnreachable(None),
        }
    }

    fn from_broker(status: &Status) -> Self {
        if transport_failure(status) {
            Self::BrokerUnreachable(status.code())
        } else {
            Self::BrokerRefused(status.code())
        }
    }

    fn hop(self) -> &'static str {
        match self {
            Self::DaemonEndpoint | Self::RelayToken | Self::PrepareTimeout => "relay",
            Self::DaemonUnreachable(_)
            | Self::DaemonRefused(_)
            | Self::DaemonReady
            | Self::Activation => "daemon",
            Self::BrokerConnect
            | Self::BrokerTimeout
            | Self::BrokerUnreachable(_)
            | Self::BrokerRefused(_) => "broker",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::DaemonEndpoint => "daemon_endpoint",
            Self::DaemonUnreachable(_) => "daemon_unreachable",
            Self::DaemonRefused(_) => "daemon_refused",
            Self::DaemonReady => "daemon_ready_mismatch",
            Self::RelayToken => "relay_token",
            Self::BrokerConnect => "broker_connect",
            Self::PrepareTimeout => "prepare_timeout",
            Self::BrokerTimeout => "broker_timeout",
            Self::BrokerUnreachable(_) => "broker_unreachable",
            Self::BrokerRefused(_) => "broker_refused",
            Self::Activation => "daemon_activation",
        }
    }

    /// Logged for a fresh epoch, which the relay retries after a second. It
    /// starts only once the broker can admit the environment, so each line
    /// is a real delay before the bridge is up.
    fn log(self, environment_id: Uuid, succeeds: Option<u64>) {
        if succeeds.is_some() {
            return;
        }
        let code = match self {
            Self::DaemonUnreachable(Some(code))
            | Self::DaemonRefused(code)
            | Self::BrokerUnreachable(code)
            | Self::BrokerRefused(code) => code.description(),
            _ => "",
        };
        tracing::info!(
            event = "credential_bridge_epoch_unadmitted",
            %environment_id,
            hop = self.hop(),
            reason = self.reason(),
            code,
            "credential relay epoch ended before the broker admitted it"
        );
    }
}

/// `severed` closes this epoch's own daemon connection. A drained epoch's
/// connection closes in order once its client is dropped.
async fn run_epoch_on(
    config: &EpochConfig,
    daemon: &SessionClient,
    severed: &CancellationToken,
    start: EpochStart,
    lifetime: Duration,
) -> Result<(), DrainFailure> {
    let EpochStart {
        cancellation,
        admitted,
        succeeds,
    } = start;
    let Ok((daemon_drain, preparation)) =
        daemon.prepare_hosted_credential_bridge(config.environment_id, config.generation)
    else {
        Unadmitted::DaemonEndpoint.log(config.environment_id, succeeds);
        return Ok(());
    };
    let result = async {
        let prepare = async {
            // A refused credential is retried: the supervisor replaces this
            // relay when the binding it was started for changes.
            let (prepared, output) = preparation
                .await
                .map_err(|error| Unadmitted::from_daemon(&error))?;
            let relay = read_relay_token(&config.relay_token)
                .await
                .map_err(|_| Unadmitted::RelayToken)?;
            let metadata = credential_metadata(&relay, prepared.workspace_authorization())
                .map_err(|_| Unadmitted::RelayToken)?;
            let channel = match &config.broker {
                BrokerEndpoint::Tls(endpoint) => endpoint
                    .connect()
                    .await
                    .map_err(|_| Unadmitted::BrokerConnect)?,
                #[cfg(test)]
                BrokerEndpoint::Preconfigured(channel) => channel.clone(),
            };
            Ok::<_, Unadmitted>((prepared, output, metadata, channel))
        };
        let (prepared, output, metadata, channel) = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            result = tokio::time::timeout(PREPARE_TIMEOUT, prepare) => match result {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(unadmitted)) => {
                    unadmitted.log(config.environment_id, succeeds);
                    return Ok(());
                }
                Err(_) => {
                    Unadmitted::PrepareTimeout.log(config.environment_id, succeeds);
                    return Ok(());
                }
            },
        };
        let (sender, receiver) = mpsc::channel(FRAME_BUFFER);
        let queue = OutgoingQueue::new(receiver);
        // Forward the actual daemon Ready; never synthesize claimed Pod identity.
        sender
            .try_send(Queued {
                frame: v1::CredentialBridgeGuestMessage {
                    payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                        prepared.ready().clone(),
                    )),
                },
                charge: None,
            })
            .map_err(|_| DrainFailure)?;
        let outgoing = RelayOutput {
            queue: queue.clone(),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
        };
        let mut request = tonic::Request::new(outgoing);
        *request.metadata_mut() = metadata;
        let mut broker = CredentialBrokerServiceClient::new(channel)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        let pump_cancellation = cancellation.clone();
        let environment_id = config.environment_id;
        let stream_budget = config.budget.stream();
        let stall = config.budget.stall();
        let pump = tokio::spawn(async move {
            if let Err(ended) =
                forward_guest(output, sender, &stream_budget, stall, &pump_cancellation).await
            {
                ended.log(environment_id);
            }
            pump_cancellation.cancel();
        });
        let lifetime_ends = Instant::now() + lifetime;
        let exchange = async {
            let response =
                tokio::time::timeout(BROKER_ADMISSION_TIMEOUT, broker.credential_bridge(request))
                    .await
                    .map_err(|_| Some(Unadmitted::BrokerTimeout))?
                    .map_err(|status| Some(Unadmitted::from_broker(&status)))?;
            // Successful TLS/RPC headers certify the broker's dual TokenReview,
            // live Ready Pods, Running DB state, exact generation and real Ready.
            // They also list the optional operations this broker serves. The
            // daemon's Open carries them, so the daemon never sends one that
            // the broker would end the epoch on.
            let capabilities = broker_capabilities(response.metadata());
            let expiry = broker_expiry(response.metadata())
                .inspect_err(|rejected| {
                    // Without a usable expiry this epoch cannot be succeeded
                    // early: it renews only after it ends, with a gap.
                    tracing::warn!(
                        event = "credential_bridge_expiry_header_rejected",
                        environment_id = %config.environment_id,
                        reason = rejected.reason(),
                        "credential relay cannot renew this epoch before it ends"
                    );
                })
                .ok();
            if let Some(current) = succeeds
                && !extends(expiry, current)
            {
                // Dropping the still-prepared successor sends no Open: the
                // daemon keeps its current epoch untouched.
                tracing::info!(
                    event = "credential_bridge_successor_refused",
                    environment_id = %config.environment_id,
                    reason = if expiry.is_some() {
                        "expiry_not_extended"
                    } else {
                        "expiry_unknown"
                    },
                    "credential relay successor would not outlive the current epoch"
                );
                return Err(None);
            }
            let sender = prepared
                .activate(&capabilities)
                .await
                .map_err(|_| Some(Unadmitted::Activation))?;
            let _ = admitted.send(Admitted {
                expiry,
                lifetime_ends,
            });
            let mut responses = response.into_inner();
            loop {
                let frame = match responses.message().await {
                    Ok(Some(frame)) => frame,
                    _ => break,
                };
                // One broker frame is held at a time. A daemon that stops
                // reading ends the epoch instead of holding it indefinitely.
                match tokio::time::timeout(stall, forward_host(&sender, frame)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break,
                    Err(_) => {
                        Ended::Stalled.log(config.environment_id);
                        break;
                    }
                }
            }
            Ok::<(), Option<Unadmitted>>(())
        };
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {},
            _ = tokio::time::sleep_until(lifetime_ends) => {},
            outcome = exchange => {
                if let Err(Some(unadmitted)) = outcome {
                    unadmitted.log(config.environment_id, succeeds);
                }
            },
        }
        cancellation.cancel();
        daemon_drain.cancel();
        // The broker leg's queue is sealed here, not when tonic next polls
        // it: a broker that stopped reading cannot keep its frames' bytes.
        queue.seal();
        pump.await.map_err(|_| DrainFailure)
    }
    .await;
    cancellation.cancel();
    // Always await the daemon producer, including preparation timeout,
    // activation failure and broker rejection; do not use `?` before cleanup.
    // A daemon that stopped reading never lets it finish: its connection is
    // severed instead, which drops whatever this epoch queued toward it.
    if daemon_drain.cancel_and_drain().await.is_err() {
        severed.cancel();
        tracing::warn!(
            event = "credential_bridge_daemon_drain_severed",
            environment_id = %config.environment_id,
            "credential relay severed a daemon connection that did not drain"
        );
    }
    result
}

fn canonical_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Orchestration's projected relay token, reread for every epoch so kubelet's
/// rotation reaches the next admission.
async fn read_relay_token(path: &std::path::Path) -> Result<Zeroizing<String>, ()> {
    let file = tokio::fs::File::open(path).await.map_err(|_| ())?;
    let metadata = file.metadata().await.map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err(());
    }
    let mut token = Zeroizing::new(String::with_capacity(2048));
    file.take((MAX_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut token)
        .await
        .map_err(|_| ())?;
    if !canonical_token(token.as_bytes()) {
        return Err(());
    }
    Ok(token)
}

/// The relay's bearer and the daemon's workspace token, both sensitive.
fn credential_metadata(relay: &str, workspace: &[u8]) -> Result<tonic::metadata::MetadataMap, ()> {
    let authorization = Zeroizing::new(format!("Bearer {relay}"));
    let mut relay_value = MetadataValue::try_from(authorization.as_str()).map_err(|_| ())?;
    relay_value.set_sensitive(true);
    let mut workspace_value = MetadataValue::from_bytes(workspace);
    workspace_value.set_sensitive(true);
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", relay_value);
    metadata.insert_bin(WORKSPACE_AUTHORIZATION, workspace_value);
    Ok(metadata)
}

/// Whether a successor's reported expiry outlives the current epoch enough.
fn extends(expiry: Option<BrokerExpiry>, current: u64) -> bool {
    let Some(required) = current.checked_add(SUCCESSOR_MIN_EXTENSION_SECS) else {
        return false;
    };
    expiry.is_some_and(|expiry| expiry.unix >= required)
}

/// Why a broker's expiry header was not used. Fixed reasons only: the value
/// itself is never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpiryRejected {
    /// An older broker.
    Absent,
    /// More than one value.
    Ambiguous,
    /// Not 1-20 ASCII digits, or not a `u64`.
    Malformed,
    /// Not later than now, or more than 660 seconds ahead.
    OutOfRange,
    /// This host's clock is before the Unix epoch.
    Clock,
}

impl ExpiryRejected {
    fn reason(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Ambiguous => "ambiguous",
            Self::Malformed => "malformed",
            Self::OutOfRange => "out_of_range",
            Self::Clock => "clock",
        }
    }
}

/// The broker's reported expiry, strictly: exactly one value of at most 20
/// ASCII digits, later than now and at most 660 seconds ahead. Anything else
/// is unused, as from an older broker. This is never a JWT claim and grants
/// no authority; the broker still ends the epoch itself.
fn broker_expiry(metadata: &tonic::metadata::MetadataMap) -> Result<BrokerExpiry, ExpiryRejected> {
    let mut values = metadata
        .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER)
        .iter();
    let value = values.next().ok_or(ExpiryRejected::Absent)?;
    if values.next().is_some() {
        return Err(ExpiryRejected::Ambiguous);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExpiryRejected::Clock)?;
    let unix = parse_expiry(value.to_str().map_err(|_| ExpiryRejected::Malformed)?, now)?;
    let at = Duration::from_secs(unix)
        .checked_sub(now)
        .and_then(|remaining| Instant::now().checked_add(remaining))
        .ok_or(ExpiryRejected::OutOfRange)?;
    Ok(BrokerExpiry { unix, at })
}

fn parse_expiry(value: &str, now: Duration) -> Result<u64, ExpiryRejected> {
    if value.is_empty()
        || value.len() > EXPIRY_MAX_DIGITS
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ExpiryRejected::Malformed);
    }
    let unix = value
        .parse::<u64>()
        .map_err(|_| ExpiryRejected::Malformed)?;
    let now = now.as_secs();
    if unix > now && unix <= now.saturating_add(EXPIRY_MAX_AHEAD_SECS) {
        Ok(unix)
    } else {
        Err(ExpiryRejected::OutOfRange)
    }
}

/// Forwards the daemon's frames toward the broker until either side ends.
/// Each frame is read only after the previous one was queued, and is queued
/// only once its bytes fit the stream's and the environment's budgets: the
/// daemon's stream carries the back-pressure.
async fn forward_guest(
    mut output: Streaming<v1::CredentialBridgeGuestMessage>,
    sender: mpsc::Sender<Queued>,
    budget: &StreamBudget,
    stall: Duration,
    cancellation: &CancellationToken,
) -> Result<(), Ended> {
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            frame = output.message() => match frame { Ok(Some(frame)) => frame, _ => return Ok(()) },
        };
        if matches!(
            frame.payload,
            None | Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ) {
            return Ok(());
        }
        // Preserve an SSH request's original deadline through this bounded
        // queue. The authority and pending-response owner recheck at their own
        // boundaries; the relay adds no request or credential selector.
        let deadline = match &frame.payload {
            Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) => {
                if codewire_daemon_proto::ssh::validate_request(request).is_err() {
                    return Ok(());
                }
                let Ok(remaining) =
                    codewire_daemon_proto::ssh::remaining_deadline(request.deadline_unix_ms)
                else {
                    return Ok(());
                };
                Some(remaining)
            }
            _ => None,
        };
        let bytes = frame.encoded_len();
        // Whether the frame was queued; false once the broker leg is gone.
        let queue = async {
            let charge = budget
                .charge(bytes)
                .await
                .map_err(|Oversized| Ended::Oversized)?;
            let queued = Queued {
                frame,
                charge: Some(charge),
            };
            Ok::<_, Ended>(sender.send(queued).await.is_ok())
        };
        let queued = async {
            tokio::time::timeout(stall, queue)
                .await
                .unwrap_or(Err(Ended::Stalled))
        };
        let queued = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            _ = sleep_for(deadline), if deadline.is_some() => return Ok(()),
            result = queued => result?,
        };
        if !queued {
            return Ok(());
        }
    }
}

async fn sleep_for(duration: Option<Duration>) {
    match duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

async fn forward_host(
    sender: &CredentialBridgeResponseSender,
    frame: v1::CredentialBridgeHostMessage,
) -> Result<(), Status> {
    use v1::credential_bridge_host_message::Payload;
    let result = match frame.payload {
        Some(Payload::ResponseStart(value)) => sender.send_response_start(value).await,
        Some(Payload::ResponseBody(value)) => sender.send_response_body(value).await,
        Some(Payload::ResponseEnd(value)) => sender.send_response_end(value).await,
        Some(Payload::ResponseFailure(value)) => sender.send_response_failure(value).await,
        Some(Payload::Ssh(value)) => sender.send_ssh(value).await,
        Some(Payload::EnvironmentProjection(value)) => {
            sender.send_environment_projection(value).await
        }
        // Opaque recipient-sealed ciphertext; this relay cannot open it.
        Some(Payload::CodexLogin(value)) => sender.send_codex_login(value).await,
        Some(Payload::Open(_)) | None => {
            return Err(Status::unavailable("credential relay frame is invalid"));
        }
    };
    result.map_err(|_| Status::unavailable("credential relay stream is unavailable"))
}

/// The broker's advertised optional operations, bounded and canonical. A
/// malformed or unknown value is dropped, never forwarded; the daemon client
/// forwards only names this build knows.
fn broker_capabilities(metadata: &tonic::metadata::MetadataMap) -> Vec<String> {
    metadata
        .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| codewire_daemon_proto::valid_credential_bridge_capability(value))
        .take(codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES)
        .map(str::to_owned)
        .collect()
}

/// One frame on its way to the broker, with the bytes it holds.
struct Queued {
    frame: v1::CredentialBridgeGuestMessage,
    charge: Option<Charge>,
}

/// The broker leg's queue, shared with the request body tonic owns. Sealing
/// it drops every queued frame, returning its bytes at once, and leaves the
/// body nothing more to yield.
#[derive(Clone)]
struct OutgoingQueue(Arc<Mutex<Option<QueueState>>>);

struct QueueState {
    frames: mpsc::Receiver<Queued>,
    /// The last frame tonic took. Its bytes stay charged until tonic asks for
    /// the next one, which it does once that frame is encoded and HTTP/2 has
    /// room for more.
    held: Option<Charge>,
}

impl OutgoingQueue {
    fn new(frames: mpsc::Receiver<Queued>) -> Self {
        Self(Arc::new(Mutex::new(Some(QueueState {
            frames,
            held: None,
        }))))
    }

    fn seal(&self) {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        drop(state);
    }
}

/// Cancelling an epoch wins over queued frames.
struct RelayOutput {
    queue: OutgoingQueue,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl Stream for RelayOutput {
    type Item = v1::CredentialBridgeGuestMessage;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.cancelled.as_mut().poll(context).is_ready() {
            self.queue.seal();
            return Poll::Ready(None);
        }
        let mut guard = self.queue.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(state) = guard.as_mut() else {
            return Poll::Ready(None);
        };
        state.held = None;
        match state.frames.poll_recv(context) {
            Poll::Ready(Some(Queued { frame, charge })) => {
                state.held = charge;
                Poll::Ready(Some(frame))
            }
            Poll::Ready(None) => {
                *guard = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for RelayOutput {
    fn drop(&mut self) {
        self.queue.seal();
    }
}

#[cfg(test)]
mod tests;
