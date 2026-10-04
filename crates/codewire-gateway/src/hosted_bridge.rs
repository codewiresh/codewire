//! One owned relay over existing private RPCs, not an application endpoint.
//! The daemon leg retains the existing authenticated plaintext cluster trust;
//! the broker leg reloads TLS trust and verifies both exact projected Pods.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_daemon::client::{CredentialBridgeResponseSender, SessionClient, SessionClientError};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_gateway_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_tls::ClientTlsEndpoint;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;
use tonic::{Status, Streaming};
use uuid::Uuid;

use crate::credentials::{credential_metadata, read_gateway_token};
use crate::daemon::DaemonSessionClient;

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
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_BUFFER: usize = 32;

#[derive(Clone)]
pub(crate) struct HostedBridgeConfig {
    environment_id: Uuid,
    generation: u64,
    gateway_token: PathBuf,
    broker: BrokerEndpoint,
}

#[derive(Clone)]
enum BrokerEndpoint {
    Tls(ClientTlsEndpoint),
    #[cfg(test)]
    Preconfigured(tonic::transport::Channel),
}

impl HostedBridgeConfig {
    pub(crate) fn new(
        environment_id: Uuid,
        generation: u64,
        gateway_token: PathBuf,
        broker: ClientTlsEndpoint,
    ) -> Self {
        Self {
            environment_id,
            generation,
            gateway_token,
            broker: BrokerEndpoint::Tls(broker),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("hosted credential bridge transport did not drain")]
struct DrainFailure;

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
    /// Absent from an older broker or a malformed header: the epoch then
    /// renews as before, after it ends.
    expiry: Option<BrokerExpiry>,
    /// This gateway's own bound on the epoch.
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

/// Readiness never awaits this owner. Before initial broker admission a launch
/// may wait only within its existing finite projection deadline. New epochs
/// reread tokens; no request from an old epoch is retained or replayed.
///
/// The relay admits the next epoch about 90 seconds before the current one's
/// identity expires; new requests move to it, and the old epoch finishes only
/// the requests already sent on it, until its own identity expires. It keeps
/// the current epoch and either its successor or its draining predecessor.
/// The successor's Open is sent only when the broker reports an expiry at
/// least 60 seconds later; otherwise the still-prepared successor is dropped,
/// the daemon is unaffected, and another is tried after 3 seconds, doubling
/// to 15, until the current epoch expires. An older broker reports no expiry,
/// and its epochs renew after they end, as before.
///
/// Each epoch presents the gateway's current daemon credential, and a daemon
/// that refuses it as unauthenticated asks an issued credential to refresh,
/// so the relay follows a replaced workspace Pod (Program #2238 B2).
pub(crate) async fn run(
    config: HostedBridgeConfig,
    daemon: DaemonSessionClient,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let unauthenticated = || daemon.credential().report_unauthenticated();
    let config = &config;
    let unauthenticated = &unauthenticated;
    let daemon = &daemon;
    relay(
        move |start| {
            let session = daemon.credential_client();
            Box::pin(async move { run_epoch(config, &session, unauthenticated, start).await })
        },
        async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        },
    )
    .await
    .map_err(Into::into)
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
    /// The earlier of the broker's expiry and this gateway's lifetime.
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
async fn relay<'a, S, D>(mut start: S, shutdown: D) -> Result<(), DrainFailure>
where
    S: FnMut(EpochStart) -> EpochFuture<'a>,
    D: Future<Output = ()>,
{
    let root = CancellationToken::new();
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
            fresh_at,
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
                let renewal = Renewal::new(&admitted);
                if let Some(previous) = serving.take() {
                    // The daemon moved new work to this epoch; the previous
                    // one finishes only what was already sent on it.
                    log_overlap(previous.renewal, renewal);
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
                        log_ended();
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
                log_ended();
                fresh_at = Instant::now() + RETRY_DELAY;
            }
            result = first_finished(&mut retiring) => {
                if let Err(error) = result {
                    break Err(error);
                }
            }
            _ = sleep_until(next.map(|(at, _)| at)), if next.is_some() => {
                starting = Some(launch(next.and_then(|(_, succeeds)| succeeds)));
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
/// retires, or when the serving epoch reported no expiry or has ended.
fn next_start(
    serving: Option<&Serving<'_>>,
    retiring: bool,
    starting: bool,
    fresh_at: Instant,
    successor_retry_at: Option<Instant>,
) -> Option<(Instant, Option<u64>)> {
    if starting {
        return None;
    }
    let Some(current) = serving else {
        return Some((fresh_at, None));
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

fn log_overlap(previous: Option<Renewal>, next: Option<Renewal>) {
    let now = Instant::now();
    let ends_in = |renewal: Option<Renewal>| {
        renewal.map_or(0, |renewal| {
            u64::try_from(renewal.ends_at.saturating_duration_since(now).as_millis())
                .unwrap_or(u64::MAX)
        })
    };
    tracing::info!(
        event = "credential_bridge_epoch_overlap",
        previous_ends_in_ms = ends_in(previous),
        next_ends_in_ms = ends_in(next),
        "hosted credential bridge admitted the next epoch; the previous epoch finishes only its pending requests"
    );
}

fn log_ended() {
    tracing::info!(
        event = "credential_bridge_epoch_ended",
        "hosted credential bridge epoch ended without an admitted successor"
    );
}

async fn run_epoch(
    config: &HostedBridgeConfig,
    daemon: &SessionClient,
    unauthenticated: &(dyn Fn() + Send + Sync),
    start: EpochStart,
) -> Result<(), DrainFailure> {
    run_epoch_with_lifetime(config, daemon, unauthenticated, start, EPOCH_MAX_LIFETIME).await
}

async fn run_epoch_with_lifetime(
    config: &HostedBridgeConfig,
    daemon: &SessionClient,
    unauthenticated: &(dyn Fn() + Send + Sync),
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
        return Ok(());
    };
    let result = async {
        let prepare = async {
            let (prepared, output) = preparation.await.map_err(|error| {
                if matches!(&error, SessionClientError::Status(status)
                    if status.code() == tonic::Code::Unauthenticated)
                {
                    unauthenticated();
                }
            })?;
            let gateway = read_gateway_token(&config.gateway_token)
                .await
                .map_err(|_| ())?;
            let metadata = credential_metadata(&gateway, prepared.workspace_authorization())
                .map_err(|_| ())?;
            let channel = match &config.broker {
                BrokerEndpoint::Tls(endpoint) => endpoint.connect().await.map_err(|_| ())?,
                #[cfg(test)]
                BrokerEndpoint::Preconfigured(channel) => channel.clone(),
            };
            Ok::<_, ()>((prepared, output, metadata, channel))
        };
        let (prepared, output, metadata, channel) = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            result = tokio::time::timeout(PREPARE_TIMEOUT, prepare) => match result {
                Ok(Ok(prepared)) => prepared,
                _ => return Ok(()),
            },
        };
        let (sender, receiver) = mpsc::channel(FRAME_BUFFER);
        // Forward the actual daemon Ready; never synthesize claimed Pod identity.
        sender
            .try_send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                    prepared.ready().clone(),
                )),
            })
            .map_err(|_| DrainFailure)?;
        let (closed, closed_rx) = oneshot::channel();
        let outgoing = RelayOutput {
            frames: ReceiverStream::new(receiver),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
            closed: Some(closed),
        };
        let mut request = tonic::Request::new(outgoing);
        *request.metadata_mut() = metadata;
        let mut broker = CredentialBrokerServiceClient::new(channel)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        let pump_cancellation = cancellation.clone();
        let pump = tokio::spawn(async move {
            forward_guest(output, sender, &pump_cancellation).await;
            pump_cancellation.cancel();
        });
        let lifetime_ends = Instant::now() + lifetime;
        let exchange = async {
            let response =
                tokio::time::timeout(BROKER_ADMISSION_TIMEOUT, broker.credential_bridge(request))
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            // Successful TLS/RPC headers certify the broker's dual TokenReview,
            // live Ready Pods, Running DB state, exact generation and real Ready.
            // They also list the optional operations this broker serves. The
            // daemon's Open carries them, so the daemon never sends one that
            // an older broker would end the epoch on; an older gateway lists
            // none.
            let capabilities = broker_capabilities(response.metadata());
            let expiry = broker_expiry(response.metadata())
                .inspect_err(|rejected| {
                    // Without a usable expiry this epoch cannot be succeeded
                    // early: it renews only after it ends, with a gap.
                    tracing::warn!(
                        event = "credential_bridge_expiry_header_rejected",
                        reason = rejected.reason(),
                        "hosted credential bridge cannot renew this epoch before it ends"
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
                    reason = if expiry.is_some() {
                        "expiry_not_extended"
                    } else {
                        "expiry_unknown"
                    },
                    "hosted credential bridge successor would not outlive the current epoch"
                );
                return Err(());
            }
            let sender = prepared.activate(&capabilities).await.map_err(|_| ())?;
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
                if forward_host(&sender, frame).await.is_err() {
                    break;
                }
            }
            Ok::<(), ()>(())
        };
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {},
            _ = tokio::time::sleep_until(lifetime_ends) => {},
            _ = exchange => {},
        }
        cancellation.cancel();
        daemon_drain.cancel();
        let pump_result = pump.await.map_err(|_| DrainFailure);
        let broker_result = tokio::time::timeout(DRAIN_TIMEOUT, closed_rx)
            .await
            .map_err(|_| DrainFailure)?
            .map_err(|_| DrainFailure);
        pump_result.and(broker_result)
    }
    .await;
    cancellation.cancel();
    // Always await this second producer, including preparation timeout,
    // activation failure and broker rejection; do not use `?` before cleanup.
    let daemon_result = daemon_drain
        .cancel_and_drain()
        .await
        .map_err(|_| DrainFailure);
    result.and(daemon_result)
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
        .get_all(codewire_gateway_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER)
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

async fn forward_guest(
    mut output: Streaming<v1::CredentialBridgeGuestMessage>,
    sender: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    cancellation: &CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            frame = output.message() => match frame { Ok(Some(frame)) => frame, _ => return },
        };
        if matches!(
            frame.payload,
            None | Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ) {
            return;
        }
        if let Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) = &frame.payload {
            if codewire_gateway_proto::ssh::validate_request(request).is_err() {
                return;
            }
            let Ok(remaining) =
                codewire_gateway_proto::ssh::remaining_deadline(request.deadline_unix_ms)
            else {
                return;
            };
            // Preserve the original deadline through this bounded relay queue.
            // The authority and pending-response owner recheck at their own
            // boundaries; the gateway adds no request or credential selector.
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return,
                _ = tokio::time::sleep(remaining) => return,
                result = sender.send(frame) => if result.is_err() { return; },
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = sender.send(frame) => if result.is_err() { return; },
        }
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
            return Err(Status::unavailable(
                "hosted credential bridge frame is invalid",
            ));
        }
    };
    result.map_err(|_| Status::unavailable("hosted credential bridge stream is unavailable"))
}

/// The broker's advertised optional operations, bounded and canonical. A
/// malformed or unknown value is dropped, never forwarded; the daemon client
/// forwards only names this build knows.
fn broker_capabilities(metadata: &tonic::metadata::MetadataMap) -> Vec<String> {
    metadata
        .get_all(codewire_gateway_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| codewire_gateway_proto::valid_credential_bridge_capability(value))
        .take(codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES)
        .map(str::to_owned)
        .collect()
}

/// Cancelling an epoch wins over queued frames. Its owner waits for this exact
/// tonic producer to finish, not merely for its forwarding task to stop.
struct RelayOutput {
    frames: ReceiverStream<v1::CredentialBridgeGuestMessage>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: Option<oneshot::Sender<()>>,
}
impl RelayOutput {
    fn finish(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
impl Stream for RelayOutput {
    type Item = v1::CredentialBridgeGuestMessage;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed.is_none() {
            return Poll::Ready(None);
        }
        if self.cancelled.as_mut().poll(context).is_ready() {
            self.finish();
            return Poll::Ready(None);
        }
        let result = Pin::new(&mut self.frames).poll_next(context);
        if matches!(result, Poll::Ready(None)) {
            self.finish();
        }
        result
    }
}
impl Drop for RelayOutput {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests;
