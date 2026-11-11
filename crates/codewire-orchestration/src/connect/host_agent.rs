//! Connect-RPC adapter for the host session (#3609, slice 1).
//!
//! Mounted with no user authentication: the stream authenticates the host by
//! its key ([`crate::api::host_session`]), so the HTTP layer admits any
//! caller and this handler admits only a host that proves its key. Nothing is
//! read or written for a caller until it has sent a well-formed `open`, and
//! every wait is bounded, so an unauthenticated stream costs one lookup and
//! at most [`HANDSHAKE_SECS`] seconds. At most [`MAX_HANDSHAKES`] streams may
//! be unproven at once, across the process; more are refused at once.
//!
//! Until a valid proof, every failure looks the same: an unknown host ID and a
//! known one answered wrongly, late, out of order or not at all all end with
//! the same `unauthenticated`, so a caller learns nothing about which host IDs
//! exist.

use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::v1::{
    AttachHostRequest, AttachHostResponse, HostAgentService, HostAttached, HostChallenge,
    HostPlatform as ProtoHostPlatform, HostPong, HostRevoked, attach_host_request,
    attach_host_response,
};
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, sleep_until};

use crate::api::host_session::{
    AttachingHost, NONCE_BYTES, PING_INTERVAL_SECS, PROOF_TIMEOUT_SECS, RECHALLENGE_INTERVAL_SECS,
    attaching_host, heard_from, new_nonce, proves_key, record_hello,
};
use crate::api::hosts::{HostPlatform, OFFLINE_AFTER_SECS};

#[cfg(test)]
mod database_tests;

fn seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// How long a caller has to open and prove its key.
pub const HANDSHAKE_SECS: u64 = 10;
/// Streams that may be unproven at once in one process.
pub const MAX_HANDSHAKES: usize = 256;

/// A session's clock. Production uses [`Timing::DEFAULT`]; tests shorten it.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub handshake: Duration,
    pub ping_interval: Duration,
    pub offline_after: Duration,
    pub rechallenge: Duration,
    pub proof_timeout: Duration,
}

impl Timing {
    pub const DEFAULT: Self = Self {
        handshake: Duration::from_secs(HANDSHAKE_SECS),
        ping_interval: Duration::from_secs(PING_INTERVAL_SECS as u64),
        offline_after: Duration::from_secs(OFFLINE_AFTER_SECS.unsigned_abs() as u64),
        rechallenge: Duration::from_secs(RECHALLENGE_INTERVAL_SECS as u64),
        proof_timeout: Duration::from_secs(PROOF_TIMEOUT_SECS as u64),
    };
}

pub fn router(pool: PgPool) -> connectrpc::Router {
    router_with(pool, Timing::DEFAULT, MAX_HANDSHAKES)
}

pub fn router_with(pool: PgPool, timing: Timing, max_handshakes: usize) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(HostAgentConnectService {
        pool,
        timing,
        handshakes: Arc::new(Semaphore::new(max_handshakes)),
    }))
}

struct HostAgentConnectService {
    pool: PgPool,
    timing: Timing,
    /// One permit per stream that has not yet proven a key.
    handshakes: Arc<Semaphore>,
}

type Outbound = mpsc::Sender<Result<AttachHostResponse, ConnectError>>;

#[allow(refining_impl_trait)]
impl HostAgentService for HostAgentConnectService {
    async fn attach_host(
        &self,
        _ctx: RequestContext,
        requests: InboundStream<AttachHostRequest>,
    ) -> ServiceResult<ServiceStream<AttachHostResponse>> {
        let permit = self.handshakes.clone().try_acquire_owned().map_err(|_| {
            ConnectError::resource_exhausted("too many hosts are attaching; retry shortly")
        })?;
        // The challenge goes out on the response stream, so the session runs
        // beside it rather than before it.
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(run_session(
            self.pool.clone(),
            self.timing,
            permit,
            requests,
            tx,
        ));
        connectrpc::Response::stream_ok(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        }))
    }
}

/// Why a session ended, as the host is told.
#[derive(Debug)]
enum End {
    /// Ended by the host, or by the control plane after `revoked`.
    Closed,
    Refused(ConnectError),
}

impl From<ConnectError> for End {
    fn from(error: ConnectError) -> Self {
        Self::Refused(error)
    }
}

fn storage(error: sqlx::Error) -> End {
    tracing::error!(error = %error, "host session storage failed");
    End::Refused(ConnectError::internal("host session storage failed"))
}

fn unrecognised() -> ConnectError {
    ConnectError::unauthenticated("the host is not recognised")
}

fn out_of_order(expected: &str) -> ConnectError {
    ConnectError::invalid_argument(format!("expected {expected}"))
}

async fn run_session(
    pool: PgPool,
    timing: Timing,
    permit: OwnedSemaphorePermit,
    mut requests: InboundStream<AttachHostRequest>,
    tx: Outbound,
) {
    let end = session(&pool, timing, permit, &mut requests, &tx).await;
    if let End::Refused(error) = end {
        let _ = tx.send(Err(error)).await;
    }
}

async fn send(tx: &Outbound, output: attach_host_response::Output) -> Result<(), End> {
    tx.send(Ok(AttachHostResponse {
        output: Some(output),
        ..Default::default()
    }))
    .await
    // The response side is gone: the host disconnected.
    .map_err(|_| End::Closed)
}

/// The next message, or the end of the stream, by `deadline`.
async fn next_input(
    requests: &mut InboundStream<AttachHostRequest>,
    deadline: Instant,
    waiting_for: &str,
) -> Result<attach_host_request::Input, End> {
    let next = tokio::time::timeout_at(deadline, requests.next())
        .await
        .map_err(|_| ConnectError::deadline_exceeded(format!("no {waiting_for} in time")))?;
    match next {
        None => Err(End::Closed),
        Some(Err(error)) => Err(End::Refused(error)),
        Some(Ok(request)) => request
            .to_owned_message()
            .input
            .ok_or_else(|| End::Refused(out_of_order(waiting_for))),
    }
}

/// Sends a fresh challenge and returns its nonce.
async fn send_challenge(tx: &Outbound) -> Result<[u8; NONCE_BYTES], End> {
    let nonce = new_nonce();
    send(
        tx,
        attach_host_response::Output::Challenge(Box::new(HostChallenge {
            nonce: nonce.to_vec(),
            ..Default::default()
        })),
    )
    .await?;
    Ok(nonce)
}

/// Checks a proof against the nonce it answers.
fn check_proof(host: &AttachingHost, nonce: &[u8], signature: &[u8]) -> Result<(), End> {
    if proves_key(host, nonce, signature) {
        Ok(())
    } else {
        Err(unrecognised().into())
    }
}

/// Tells the host it was revoked, and ends the session.
async fn revoked(tx: &Outbound) -> End {
    let _ = send(
        tx,
        attach_host_response::Output::Revoked(Box::<HostRevoked>::default()),
    )
    .await;
    End::Closed
}

async fn session(
    pool: &PgPool,
    timing: Timing,
    permit: OwnedSemaphorePermit,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> End {
    match attached_session(pool, timing, permit, requests, tx).await {
        Ok(()) => End::Closed,
        Err(end) => end,
    }
}

async fn attached_session(
    pool: &PgPool,
    timing: Timing,
    handshake_permit: OwnedSemaphorePermit,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> Result<(), End> {
    let handshake = Instant::now() + timing.handshake;
    let host_id = match next_input(requests, handshake, "open").await? {
        attach_host_request::Input::Open(open) => open.host_id,
        _ => return Err(out_of_order("open").into()),
    };
    // An unknown host is challenged like a known one, and anything but a
    // valid proof within the handshake ends both the same way, so the answer
    // does not tell a caller which host IDs exist.
    let host = attaching_host(pool, &host_id).await.map_err(storage)?;
    let nonce = send_challenge(tx).await?;
    let answer = next_input(requests, handshake, "proof").await;
    let proven = match (&host, &answer) {
        (Some(host), Ok(attach_host_request::Input::Proof(proof))) => {
            proves_key(host, &nonce, &proof.signature)
        }
        _ => false,
    };
    let Some(host) = host.filter(|_| proven) else {
        return Err(unrecognised().into());
    };
    if host.revoked_at.is_some() || !heard_from(pool, &host.id).await.map_err(storage)? {
        return Err(ConnectError::permission_denied("the host is revoked").into());
    }
    send(
        tx,
        attach_host_response::Output::Attached(Box::new(HostAttached {
            ping_interval_seconds: seconds(timing.ping_interval),
            offline_after_seconds: seconds(timing.offline_after),
            rechallenge_interval_seconds: seconds(timing.rechallenge),
            proof_timeout_seconds: seconds(timing.proof_timeout),
            ..Default::default()
        })),
    )
    .await?;
    drop(handshake_permit);
    tracing::info!(host_id = %host.id, "host attached");

    // The hello comes first, within a ping interval.
    let silence = timing.offline_after;
    let hello = match next_input(requests, Instant::now() + silence, "hello").await? {
        attach_host_request::Input::Hello(hello) => hello,
        _ => return Err(out_of_order("hello").into()),
    };
    let platform = match hello.platform.as_known() {
        Some(ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM) => {
            Some(HostPlatform::LinuxX86_64Kvm)
        }
        Some(ProtoHostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ) => Some(HostPlatform::DarwinArm64Vz),
        _ => None,
    };
    if platform.is_none() || platform != host.platform {
        return Err(ConnectError::failed_precondition(
            "the host reports a different platform from the one it enrolled with",
        )
        .into());
    }
    let Ok(capability_version @ 1..) = i32::try_from(hello.capability_version) else {
        return Err(ConnectError::invalid_argument("capability_version must be at least 1").into());
    };
    if !record_hello(pool, &host.id, capability_version)
        .await
        .map_err(storage)?
    {
        return Err(revoked(tx).await);
    }

    // Then pings, and a fresh proof every rechallenge interval. Pings keep
    // coming while a challenge is open (one may already be on its way), and
    // the proof may arrive among them. A host that falls silent for the
    // offline window is ended; it reconnects.
    let mut rechallenge = Instant::now() + timing.rechallenge;
    let mut open_challenge: Option<([u8; NONCE_BYTES], Instant)> = None;
    loop {
        let silent = Instant::now() + silence;
        let due = open_challenge.map_or(rechallenge, |(_, deadline)| deadline);
        tokio::select! {
            () = sleep_until(due) => {
                if open_challenge.is_some() {
                    return Err(ConnectError::deadline_exceeded("no proof in time").into());
                }
                let nonce = send_challenge(tx).await?;
                open_challenge = Some((nonce, Instant::now() + timing.proof_timeout));
            }
            input = next_input(requests, silent, "ping") => match input? {
                attach_host_request::Input::Ping(_) => {
                    if !heard_from(pool, &host.id).await.map_err(storage)? {
                        return Err(revoked(tx).await);
                    }
                    send(tx, attach_host_response::Output::Pong(Box::<HostPong>::default()))
                        .await?;
                }
                attach_host_request::Input::Proof(proof) => {
                    let Some((nonce, _)) = open_challenge.take() else {
                        return Err(out_of_order("ping").into());
                    };
                    check_proof(&host, &nonce, &proof.signature)?;
                    if !heard_from(pool, &host.id).await.map_err(storage)? {
                        return Err(revoked(tx).await);
                    }
                    rechallenge = Instant::now() + timing.rechallenge;
                }
                _ => return Err(out_of_order("ping or proof").into()),
            },
        }
    }
}
