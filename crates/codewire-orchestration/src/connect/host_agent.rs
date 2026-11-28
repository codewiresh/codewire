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

use codewire_daemon_bridge::drain::{Restart, end_at};
use codewire_proto::codewire::v1::{
    AttachHostRequest, AttachHostResponse, HostAgentService, HostAttached, HostChallenge,
    HostPlatform as ProtoHostPlatform, HostPong, HostRevoked, HostSuperseded,
    OpenHostTunnelRequest, OpenHostTunnelResponse, attach_host_request, attach_host_response,
};
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, sleep_until};

use crate::api::host_operation_signals::{HostOperationSignal, HostOperationSignals};
use crate::api::host_session::{
    AttachingHost, NONCE_BYTES, PING_INTERVAL_SECS, PROOF_TIMEOUT_SECS, RECHALLENGE_INTERVAL_SECS,
    attaching_host, heard_from, new_nonce, proves_key, record_hello,
};
use crate::api::host_tunnels::{HostTunnels, Registration};
use crate::api::hosts::{HostPlatform, OFFLINE_AFTER_SECS};
use crate::drain::Drain;

mod access;
mod operations;
mod tunnel_stream;

use access::ACCESS_CAPABILITY;
pub use access::HostAccessSettings;
use operations::{Heard, OPERATIONS_CAPABILITY, Relay};

#[cfg(test)]
mod database_tests;

fn seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// How long a caller has to open and prove its key.
pub const HANDSHAKE_SECS: u64 = 10;
/// Streams that may be unproven at once in one process.
pub const MAX_HANDSHAKES: usize = 256;
const HOST_SESSION_RESTARTED: &str = "Codewire is restarting this server; attach the host again";

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

pub fn router(
    state: &crate::api::ApiState,
    signals: Arc<HostOperationSignals>,
) -> connectrpc::Router {
    router_with(
        state.pool.clone(),
        Timing::DEFAULT,
        MAX_HANDSHAKES,
        state.drain.clone(),
        signals,
        Arc::clone(&state.host_tunnels),
        Some(Arc::new(HostAccessSettings {
            session_secret: state.session_secret.clone(),
            coordinator_url: crate::workspace_binding::public_coordinator_url(
                &state.sandbox_cfg.api_base_url,
            ),
        })),
    )
}

pub fn router_with(
    pool: PgPool,
    timing: Timing,
    max_handshakes: usize,
    drain: Drain,
    signals: Arc<HostOperationSignals>,
    tunnels: Arc<HostTunnels>,
    access: Option<Arc<HostAccessSettings>>,
) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(HostAgentConnectService {
        pool,
        timing,
        handshakes: Arc::new(Semaphore::new(max_handshakes)),
        drain,
        signals,
        tunnels,
        access,
    }))
}

struct HostAgentConnectService {
    pool: PgPool,
    timing: Timing,
    /// One permit per stream that has not yet proven a key.
    handshakes: Arc<Semaphore>,
    /// The host re-attaches on its own, so its session ends as soon as this
    /// replica begins draining (#4426).
    drain: Drain,
    /// Operations enqueued for hosts, from this process's one listener.
    signals: Arc<HostOperationSignals>,
    /// Tunnels asked for on this replica's host sessions.
    tunnels: Arc<HostTunnels>,
    /// What a grant to a host's tailnet peer names; none, and access calls
    /// are refused as unavailable.
    access: Option<Arc<HostAccessSettings>>,
}

type Outbound = mpsc::Sender<Result<AttachHostResponse, ConnectError>>;

/// What one session runs with.
struct Session {
    pool: PgPool,
    timing: Timing,
    signals: Arc<HostOperationSignals>,
    tunnels: Arc<HostTunnels>,
    access: Option<Arc<HostAccessSettings>>,
}

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
            Session {
                pool: self.pool.clone(),
                timing: self.timing,
                signals: self.signals.clone(),
                tunnels: self.tunnels.clone(),
                access: self.access.clone(),
            },
            permit,
            requests,
            tx,
        ));
        connectrpc::Response::stream_ok(end_at(
            futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }),
            Some(self.drain.signal(Restart::Begins)),
            HOST_SESSION_RESTARTED,
        ))
    }

    async fn open_host_tunnel(
        &self,
        _ctx: RequestContext,
        requests: InboundStream<OpenHostTunnelRequest>,
    ) -> ServiceResult<ServiceStream<OpenHostTunnelResponse>> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(tunnel_stream::run(
            self.pool.clone(),
            self.tunnels.clone(),
            requests,
            tx,
        ));
        connectrpc::Response::stream_ok(end_at(
            futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }),
            Some(self.drain.signal(Restart::Begins)),
            HOST_SESSION_RESTARTED,
        ))
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
    session_context: Session,
    permit: OwnedSemaphorePermit,
    mut requests: InboundStream<AttachHostRequest>,
    tx: Outbound,
) {
    let end = session(&session_context, permit, &mut requests, &tx).await;
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
    context: &Session,
    permit: OwnedSemaphorePermit,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> End {
    match attached_session(context, permit, requests, tx).await {
        Ok(()) => End::Closed,
        Err(end) => end,
    }
}

async fn attached_session(
    context: &Session,
    handshake_permit: OwnedSemaphorePermit,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> Result<(), End> {
    // Subscribed before anything is claimed, so no enqueue between the two
    // is missed.
    let signals = context.signals.subscribe();
    let (host, session_generation) = admit(context, handshake_permit, requests, tx).await?;
    let (relay, capability_version) =
        hello(context, &host, session_generation, requests, tx).await?;
    if let Some(relay) = &relay {
        relay.send_outstanding(&context.pool, tx).await?;
    }
    // A host that runs operations is reached through this session.
    let tunnels = relay
        .as_ref()
        .map(|_| context.tunnels.register(&host.id, session_generation));
    Serving {
        context,
        host: &host,
        session_generation,
        relay: relay.as_ref(),
        // Access calls come from a host that declared capability 3 (#3609).
        access_calls: capability_version >= ACCESS_CAPABILITY,
        signals,
        tunnels,
    }
    .serve(requests, tx)
    .await
}

/// Opens the session: the host proves its key, takes the next session
/// generation, and is told it attached.
async fn admit(
    context: &Session,
    handshake_permit: OwnedSemaphorePermit,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> Result<(AttachingHost, i64), End> {
    let (pool, timing) = (&context.pool, context.timing);
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
    // Each attach takes the next generation, which supersedes every earlier
    // session of the host. A revoked host takes none.
    let session_generation = match host.revoked_at {
        Some(_) => None,
        None => crate::api::host_operations::begin_session(pool, &host.id)
            .await
            .map_err(storage)?,
    };
    let Some(session_generation) = session_generation else {
        return Err(ConnectError::permission_denied("the host is revoked").into());
    };
    if !heard_from(pool, &host.id).await.map_err(storage)? {
        return Err(ConnectError::permission_denied("the host is revoked").into());
    }
    send(
        tx,
        attach_host_response::Output::Attached(Box::new(HostAttached {
            ping_interval_seconds: seconds(timing.ping_interval),
            offline_after_seconds: seconds(timing.offline_after),
            rechallenge_interval_seconds: seconds(timing.rechallenge),
            proof_timeout_seconds: seconds(timing.proof_timeout),
            session_generation: u64::try_from(session_generation).unwrap_or_default(),
            ..Default::default()
        })),
    )
    .await?;
    drop(handshake_permit);
    tracing::info!(host_id = %host.id, session_generation, "host attached");
    Ok((host, session_generation))
}

/// The hello, which comes first, within the offline window. A host of
/// capability version 2 or later gets the session's operations.
async fn hello(
    context: &Session,
    host: &AttachingHost,
    session_generation: i64,
    requests: &mut InboundStream<AttachHostRequest>,
    tx: &Outbound,
) -> Result<(Option<Relay>, i32), End> {
    let pool = &context.pool;
    let hello = match next_input(
        requests,
        Instant::now() + context.timing.offline_after,
        "hello",
    )
    .await?
    {
        attach_host_request::Input::Hello(hello) => *hello,
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
    if capability_version < OPERATIONS_CAPABILITY {
        return Ok((None, capability_version));
    }
    Ok((
        Some(
            Relay::new(&host.id, session_generation)
                .record_inventory(pool, hello.inventory)
                .await?,
        ),
        capability_version,
    ))
}

/// The next tunnel this session is asked to open; never, for a session that
/// opens none.
async fn next_tunnel(
    tunnels: &mut Option<Registration>,
) -> Option<codewire_proto::codewire::v1::HostOpenTunnel> {
    match tunnels {
        Some(registration) => registration.requests.recv().await,
        None => std::future::pending().await,
    }
}

/// An attached session, after its hello.
struct Serving<'a> {
    context: &'a Session,
    host: &'a AttachingHost,
    session_generation: i64,
    /// Whether the host declared the access calls' capability.
    access_calls: bool,
    /// For a host that runs operations.
    relay: Option<&'a Relay>,
    signals: tokio::sync::broadcast::Receiver<HostOperationSignal>,
    /// Ends this session's tunnels when the session ends.
    tunnels: Option<Registration>,
}

impl Serving<'_> {
    /// Pings, and a fresh proof every rechallenge interval. Pings keep
    /// coming while a challenge is open (one may already be on its way), and
    /// the proof may arrive among them. A host that falls silent for the
    /// offline window is ended; it reconnects. Operations are claimed on
    /// each signal for this host and on each ping that comes while no proof
    /// is due.
    async fn serve(
        mut self,
        requests: &mut InboundStream<AttachHostRequest>,
        tx: &Outbound,
    ) -> Result<(), End> {
        let timing = self.context.timing;
        let mut rechallenge = Instant::now() + timing.rechallenge;
        let mut open_challenge: Option<([u8; NONCE_BYTES], Instant)> = None;
        loop {
            let silent = Instant::now() + timing.offline_after;
            let due = open_challenge.map_or(rechallenge, |(_, deadline)| deadline);
            tokio::select! {
                () = sleep_until(due) => {
                    if open_challenge.is_some() {
                        return Err(ConnectError::deadline_exceeded("no proof in time").into());
                    }
                    let nonce = send_challenge(tx).await?;
                    open_challenge = Some((nonce, Instant::now() + timing.proof_timeout));
                }
                signal = self.signals.recv(), if self.relay.is_some() => {
                    if self.signalled(signal) {
                        self.claim(tx).await?;
                    }
                }
                Some(request) = next_tunnel(&mut self.tunnels) => {
                    send(tx, attach_host_response::Output::OpenTunnel(Box::new(request))).await?;
                }
                input = next_input(requests, silent, "ping") => match input? {
                    attach_host_request::Input::Ping(_) => {
                        self.heard(tx).await?;
                        send(tx, attach_host_response::Output::Pong(Box::<HostPong>::default()))
                            .await?;
                        // While a proof is due, the next ping after it claims:
                        // the proof window holds no optional work (#4684).
                        if open_challenge.is_none() {
                            self.claim(tx).await?;
                        }
                    }
                    attach_host_request::Input::Proof(proof) => {
                        let Some((nonce, _)) = open_challenge.take() else {
                            return Err(out_of_order("ping").into());
                        };
                        check_proof(self.host, &nonce, &proof.signature)?;
                        self.heard(tx).await?;
                        rechallenge = Instant::now() + timing.rechallenge;
                    }
                    attach_host_request::Input::OperationResult(result) => {
                        self.operations()?.record_result(&self.context.pool, *result).await?;
                    }
                    attach_host_request::Input::EnvironmentObserved(observation) => {
                        self.operations()?.record_observed(&self.context.pool, *observation).await?;
                    }
                    // Advisory; only a result completes an operation.
                    attach_host_request::Input::OperationProgress(_) => {
                        self.operations()?;
                    }
                    attach_host_request::Input::AccessRefresh(call) => {
                        let answer = match self.access()? {
                            Some(access) => {
                                access
                                    .refresh(&self.context.pool, &self.host.id, self.session_generation, &call)
                                    .await?
                            }
                            None => access::unavailable(&call.request_id)?,
                        };
                        send(tx, answer).await?;
                    }
                    attach_host_request::Input::HostKeyRecord(call) => {
                        let answer = match self.access()? {
                            Some(access) => {
                                access
                                    .record_host_key(&self.context.pool, &self.host.id, self.session_generation, &call)
                                    .await?
                            }
                            None => access::unavailable(&call.request_id)?,
                        };
                        send(tx, answer).await?;
                    }
                    attach_host_request::Input::PeerRelayAllocate(call) => {
                        self.access()?;
                        send(tx, access::allocate_peer_relay(&call)?).await?;
                    }
                    _ => return Err(out_of_order("ping or proof").into()),
                },
            }
        }
    }

    /// This replica's access settings, for a message only a host that
    /// declared the access calls' capability sends; `None` when this replica
    /// issues no grants.
    fn access(&self) -> Result<Option<&HostAccessSettings>, End> {
        if !self.access_calls || self.relay.is_none() {
            return Err(out_of_order("ping or proof").into());
        }
        Ok(self.context.access.as_deref())
    }

    /// The relay, for a message only a host that runs operations sends.
    fn operations(&self) -> Result<&Relay, End> {
        self.relay
            .ok_or_else(|| out_of_order("ping or proof").into())
    }

    /// Whether a signal may mean an operation for this host.
    fn signalled(
        &self,
        signal: Result<HostOperationSignal, tokio::sync::broadcast::error::RecvError>,
    ) -> bool {
        match signal {
            Ok(HostOperationSignal::Host(host_id)) => *host_id == *self.host.id,
            // Missed signals, or a lagging receiver: look anyway.
            Ok(HostOperationSignal::Resync)
            | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
        }
    }

    async fn claim(&self, tx: &Outbound) -> Result<(), End> {
        match self.relay {
            Some(relay) => relay.claim_and_send(&self.context.pool, tx).await,
            None => Ok(()),
        }
    }

    /// Records that the host was heard, or ends a session that was
    /// superseded or whose host was revoked.
    async fn heard(&self, tx: &Outbound) -> Result<(), End> {
        let pool = &self.context.pool;
        let heard = match self.relay {
            Some(relay) => relay.heard_from(pool).await?,
            None if heard_from(pool, &self.host.id).await.map_err(storage)? => Heard::Current,
            None => Heard::Revoked,
        };
        match heard {
            Heard::Current => Ok(()),
            Heard::Revoked => Err(revoked(tx).await),
            Heard::Superseded => {
                // Ending anyway: a host that cannot be told still reconnects.
                let _ = send(
                    tx,
                    attach_host_response::Output::Superseded(Box::<HostSuperseded>::default()),
                )
                .await;
                tracing::info!(host_id = %self.host.id, "host session superseded");
                Err(End::Closed)
            }
        }
    }
}
