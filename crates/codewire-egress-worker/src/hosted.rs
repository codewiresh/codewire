//! The worker for one cw-egress stream (#4000): its bootstrap, the accepted
//! TCP socket it takes in place of a local VM's Unix stream, and the statuses
//! a hosted session adds.
//!
//! The supervisor starts it as it starts a local worker, from the same fixed
//! bootstrap descriptor. It writes `prepared`, takes the broker's IPC sessions
//! and writes `broker-ready`, then takes the stream. After `ready` it writes
//! the guest's self-check result: [`WORKER_SELF_CHECK_PASSED_MESSAGE`], or a
//! failure line before it ends. Nothing from the guest is forwarded before the
//! check passes. On [`WORKER_DRAIN_REQUEST`] it ends its session at the first
//! moment it holds no open flow, and writes [`WORKER_IDLE_MESSAGE`] first.

use std::io::{self, Read as _};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;

use codewire_egress_broker::ipc::{
    BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS, BrokerIpcBinding, BrokerIpcKey,
};
use codewire_egress_policy::PolicyDigest;
use codewire_network_session::{EgressTrust, MAX_EGRESS_TRUST_BYTES, SelfCheck};
use codewire_vmm_guest_probe::{NETWORK_KEY_LEN, NetworkKey};
use tokio::io::Interest;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::session::{HostedChecks, SessionAddresses, run_hosted_network_session};
use crate::worker::{
    HANDSHAKE_TIMEOUT, IpcEgressBroker, NETWORK_BOOTSTRAP_FD, NetworkWorkerError,
    WORKER_BROKER_READY_MESSAGE, WORKER_PREPARED_MESSAGE, WORKER_READY_MESSAGE,
    ambient_environment_present, confine_network_worker, inherited_std_unix_stream,
    receive_worker_broker_descriptor, receive_worker_descriptor, send_worker_descriptor,
    socket_option, transferred_stream, transferred_tokio_unix_stream, write_worker_control_message,
};

/// A hosted session is always generation 1: the Pod's UID names it.
pub const HOSTED_GENERATION: u64 = 1;
/// Written once, after `ready`, when the guest's self-check passed.
pub const WORKER_SELF_CHECK_PASSED_MESSAGE: &[u8] = b"CWNETW1 self-check passed\n";
/// The supervisor's one request: end the session once it holds no open flow.
pub const WORKER_DRAIN_REQUEST: &[u8] = b"CWNETW1 drain\n";
/// Written once, after a drain request, as the session ends with no open flow.
pub const WORKER_IDLE_MESSAGE: &[u8] = b"CWNETW1 idle\n";
/// The statuses a serving worker may still have to write: ready, the check,
/// then idle or a failure.
const STATUS_QUEUE: usize = 4;

const HOSTED_BOOTSTRAP_MAGIC: &[u8; 8] = b"CWNETH1\0";
const POD_UID: std::ops::Range<usize> = 8..24;
const NETWORK_KEY: std::ops::Range<usize> = 24..56;
const POLICY_DIGEST: std::ops::Range<usize> = 56..88;
const BROKER_KEY: std::ops::Range<usize> = 88..120;
const TRUST_LEN: std::ops::Range<usize> = 120..122;
/// The fixed part, before the trust's DER.
pub const HOSTED_BOOTSTRAP_FIXED_LEN: usize = 122;
const WORKER_STREAM_DESCRIPTOR_MARKER: u8 = b'T';

/// What the supervisor tells one hosted worker.
pub struct HostedWorkerBootstrap {
    pub pod_uid: Uuid,
    pub network_key: NetworkKey,
    pub broker_key: [u8; BROKER_IPC_KEY_LEN],
    pub policy_digest: PolicyDigest,
    pub trust: EgressTrust,
}

impl Drop for HostedWorkerBootstrap {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.broker_key);
    }
}

pub fn encode_hosted_worker_bootstrap(
    bootstrap: &HostedWorkerBootstrap,
) -> Result<Zeroizing<Vec<u8>>, NetworkWorkerError> {
    let trust: &[u8] = match &bootstrap.trust {
        EgressTrust::None => &[],
        EgressTrust::Ca(der) => der,
    };
    let trust_len = u16::try_from(trust.len()).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    if bootstrap.pod_uid.is_nil()
        || bootstrap.broker_key.iter().all(|byte| *byte == 0)
        || bootstrap
            .policy_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || matches!(bootstrap.trust, EgressTrust::Ca(_)) && trust.is_empty()
        || trust.len() > MAX_EGRESS_TRUST_BYTES
    {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; HOSTED_BOOTSTRAP_FIXED_LEN + trust.len()]);
    bytes[..8].copy_from_slice(HOSTED_BOOTSTRAP_MAGIC);
    bytes[POD_UID].copy_from_slice(bootstrap.pod_uid.as_bytes());
    bootstrap
        .network_key
        .with_bytes(|key| bytes[NETWORK_KEY].copy_from_slice(key));
    bytes[POLICY_DIGEST].copy_from_slice(bootstrap.policy_digest.as_bytes());
    bytes[BROKER_KEY].copy_from_slice(&bootstrap.broker_key);
    bytes[TRUST_LEN].copy_from_slice(&trust_len.to_le_bytes());
    bytes[HOSTED_BOOTSTRAP_FIXED_LEN..].copy_from_slice(trust);
    Ok(bytes)
}

/// The decoded bootstrap, as the worker holds it.
struct Prepared {
    network_key: NetworkKey,
    broker_binding: BrokerIpcBinding,
    broker_key: BrokerIpcKey,
    trust: EgressTrust,
}

fn decode_fixed(fixed: &[u8], expected_pod: Uuid) -> Result<(Prepared, usize), NetworkWorkerError> {
    if fixed.len() != HOSTED_BOOTSTRAP_FIXED_LEN || &fixed[..8] != HOSTED_BOOTSTRAP_MAGIC {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let pod_uid =
        Uuid::from_slice(&fixed[POD_UID]).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    if pod_uid.is_nil() || pod_uid != expected_pod {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let mut key = Zeroizing::new([0_u8; NETWORK_KEY_LEN]);
    key.copy_from_slice(&fixed[NETWORK_KEY]);
    let network_key =
        NetworkKey::from_derived_bytes(*key).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let digest: [u8; 32] = fixed[POLICY_DIGEST]
        .try_into()
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let policy_digest = PolicyDigest::from_bytes(digest);
    if policy_digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let broker_binding = BrokerIpcBinding::new(pod_uid, HOSTED_GENERATION, policy_digest)
        .map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let mut broker_key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
    broker_key.copy_from_slice(&fixed[BROKER_KEY]);
    let broker_key =
        BrokerIpcKey::from_bytes(*broker_key).map_err(|_| NetworkWorkerError::InvalidBootstrap)?;
    let trust_len = usize::from(u16::from_le_bytes(
        fixed[TRUST_LEN]
            .try_into()
            .map_err(|_| NetworkWorkerError::InvalidBootstrap)?,
    ));
    if trust_len > MAX_EGRESS_TRUST_BYTES {
        return Err(NetworkWorkerError::InvalidBootstrap);
    }
    let prepared = Prepared {
        network_key,
        broker_binding,
        broker_key,
        trust: EgressTrust::None,
    };
    Ok((prepared, trust_len))
}

fn read_bootstrap(
    bootstrap: &mut StdUnixStream,
    pod_uid: Uuid,
) -> Result<Prepared, NetworkWorkerError> {
    let mut fixed = Zeroizing::new([0_u8; HOSTED_BOOTSTRAP_FIXED_LEN]);
    bootstrap
        .read_exact(fixed.as_mut())
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let (mut prepared, trust_len) = decode_fixed(fixed.as_ref(), pod_uid)?;
    if trust_len > 0 {
        let mut der = vec![0_u8; trust_len];
        bootstrap
            .read_exact(&mut der)
            .map_err(|_| NetworkWorkerError::BootstrapIo)?;
        prepared.trust = EgressTrust::Ca(der);
    }
    Ok(prepared)
}

/// Sends the accepted guest stream, a connected TCP socket, to the worker.
pub fn send_worker_stream_descriptor(bootstrap: RawFd, stream: BorrowedFd<'_>) -> io::Result<()> {
    validate_tcp_stream(stream).map_err(io::Error::other)?;
    send_worker_descriptor(
        bootstrap,
        stream.as_raw_fd(),
        WORKER_STREAM_DESCRIPTOR_MARKER,
    )
}

fn receive_worker_stream_descriptor(bootstrap: RawFd) -> Result<OwnedFd, NetworkWorkerError> {
    let descriptor = receive_worker_descriptor(bootstrap, WORKER_STREAM_DESCRIPTOR_MARKER)
        .map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    validate_tcp_stream(descriptor.as_fd())?;
    Ok(descriptor)
}

/// A connected TCP stream: an Internet-domain stream socket with a peer.
fn validate_tcp_stream(descriptor: BorrowedFd<'_>) -> Result<(), NetworkWorkerError> {
    if socket_option(descriptor.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(NetworkWorkerError::InheritedDescriptor);
    }
    // The peer's address proves the stream is connected and in an Internet
    // domain; a Unix stream's peer is not.
    let family = rustix::net::getpeername(descriptor)
        .ok()
        .flatten()
        .map(|peer| peer.address_family());
    match family {
        Some(rustix::net::AddressFamily::INET | rustix::net::AddressFamily::INET6) => Ok(()),
        _ => Err(NetworkWorkerError::InheritedDescriptor),
    }
}

/// The entry of `cw-egress __egress-worker --pod-uid UUID`: one confined
/// worker for one admitted stream. It reports each failure on the bootstrap
/// socket before it returns.
pub async fn run_hosted_worker(pod_uid: Uuid) -> Result<(), NetworkWorkerError> {
    if pod_uid.is_nil() {
        return Err(NetworkWorkerError::InvalidIdentity);
    }
    let mut bootstrap = inherited_std_unix_stream(NETWORK_BOOTSTRAP_FD)?;
    let ready = match prepare(&mut bootstrap, pod_uid).await {
        Ok(ready) => ready,
        Err(error) => {
            // The stream to the supervisor may itself be what failed.
            let _ = write_worker_control_message(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    serve(bootstrap, ready, pod_uid).await
}

/// Everything the session needs, after confinement.
struct Ready {
    network_key: NetworkKey,
    broker: Arc<IpcEgressBroker>,
    trust: EgressTrust,
    stream: crate::worker::TransferredStream,
}

async fn prepare(
    bootstrap: &mut StdUnixStream,
    pod_uid: Uuid,
) -> Result<Ready, NetworkWorkerError> {
    bootstrap
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    bootstrap
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    if ambient_environment_present() {
        return Err(NetworkWorkerError::AmbientEnvironment);
    }
    let prepared = read_bootstrap(bootstrap, pod_uid)?;
    confine_network_worker()?;
    bootstrap
        .set_read_timeout(None)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    write_worker_control_message(bootstrap, WORKER_PREPARED_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    // One descriptor per broker IPC session, in session order (#2638).
    let streams = (0..BROKER_IPC_SESSIONS)
        .map(|_| {
            receive_worker_broker_descriptor(bootstrap.as_raw_fd())
                .and_then(transferred_tokio_unix_stream)
        })
        .collect::<Result<Vec<_>, NetworkWorkerError>>()?;
    // The hosted session's /30 (`run_hosted_network_session`).
    let broker = Arc::new(IpcEgressBroker::new(
        streams,
        prepared.broker_binding,
        prepared.broker_key,
        SessionAddresses::STANDARD,
    )?);
    broker.verify_binding().await?;
    write_worker_control_message(bootstrap, WORKER_BROKER_READY_MESSAGE)
        .map_err(|_| NetworkWorkerError::PreparedIo)?;
    let descriptor = receive_worker_stream_descriptor(bootstrap.as_raw_fd())?;
    let stream =
        transferred_stream(descriptor).map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
    Ok(Ready {
        network_key: prepared.network_key,
        broker,
        trust: prepared.trust,
        stream,
    })
}

/// Runs the session while one control task owns the bootstrap socket: it
/// writes every status in order and turns the supervisor's drain request into
/// the session's.
async fn serve(
    bootstrap: StdUnixStream,
    ready: Ready,
    pod_uid: Uuid,
) -> Result<(), NetworkWorkerError> {
    bootstrap
        .set_nonblocking(true)
        .map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let control =
        tokio::net::UnixStream::from_std(bootstrap).map_err(|_| NetworkWorkerError::BootstrapIo)?;
    let (statuses, status_queue) = mpsc::channel(STATUS_QUEUE);
    let (drain_request, drain) = oneshot::channel();
    let mut control = tokio::spawn(run_control(control, status_queue, drain_request));
    let (self_check, mut checked) = oneshot::channel();
    let ready_status = statuses.clone();
    // The broker ends when its last client closes, and the supervisor reads a
    // broker's end as the pair's: the client stays open until the last status
    // is written, so the supervisor hears the worker's last word first.
    let broker = Arc::clone(&ready.broker);
    let session = run_hosted_network_session(
        ready.stream,
        ready.network_key,
        pod_uid,
        ready.broker,
        HostedChecks {
            trust: ready.trust,
            self_check,
            drain,
        },
        move || {
            ready_status
                .try_send(WORKER_READY_MESSAGE)
                .map_err(|_| io::Error::other("the status queue is closed"))
        },
    );
    tokio::pin!(session);
    let mut check_reported = false;
    let ended = loop {
        tokio::select! {
            ended = &mut session => break ended.map_err(NetworkWorkerError::from),
            check = &mut checked, if !check_reported => {
                check_reported = true;
                // A failure ends the session, which reports it below.
                if check == Ok(SelfCheck::Passed) {
                    statuses
                        .send(WORKER_SELF_CHECK_PASSED_MESSAGE)
                        .await
                        .map_err(|_| NetworkWorkerError::StatusIo)?;
                }
            }
            stopped = &mut control => {
                // The supervisor closed the socket or broke its protocol:
                // nothing would hear the session, so it ends.
                return match stopped {
                    Ok(Err(error)) => Err(error),
                    Ok(Ok(())) | Err(_) => Err(NetworkWorkerError::StatusIo),
                };
            }
        }
    };
    let last = match &ended {
        Ok(()) => WORKER_IDLE_MESSAGE,
        Err(error) => error.startup_failure().message(),
    };
    // The control task writes what is queued, then ends with the queue.
    let _ = statuses.send(last).await;
    drop(statuses);
    let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, control).await;
    drop(broker);
    ended
}

/// Owns the bootstrap socket once the worker serves: writes each queued
/// status, and reads the supervisor's one possible request, a drain.
async fn run_control(
    control: tokio::net::UnixStream,
    mut statuses: mpsc::Receiver<&'static [u8]>,
    drain: oneshot::Sender<()>,
) -> Result<(), NetworkWorkerError> {
    let read = async {
        let mut request = [0_u8; WORKER_DRAIN_REQUEST.len()];
        read_control_exact(&control, &mut request)
            .await
            .map(|()| request)
    };
    tokio::pin!(read);
    let mut drain = Some(drain);
    loop {
        tokio::select! {
            status = statuses.recv() => {
                let Some(status) = status else { return Ok(()) };
                write_control(&control, status)
                    .await
                    .map_err(|_| NetworkWorkerError::StatusIo)?;
            }
            received = &mut read, if drain.is_some() => {
                if received.ok().as_ref().map(|request| &request[..]) != Some(WORKER_DRAIN_REQUEST) {
                    return Err(NetworkWorkerError::Protocol);
                }
                if let Some(drain) = drain.take() {
                    // The session may already have ended; nothing then waits.
                    let _ = drain.send(());
                }
            }
        }
    }
}

/// The worker's seccomp list denies `sendto` and `recvfrom`, which Tokio's
/// Unix-stream I/O may use, so the bootstrap socket is driven by readiness
/// with plain `write` and `read`, as the broker IPC client is.
async fn write_control(control: &tokio::net::UnixStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        control.writable().await?;
        match control.try_io(Interest::WRITABLE, || {
            rustix::io::write(control, bytes).map_err(io::Error::from)
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn read_control_exact(
    control: &tokio::net::UnixStream,
    mut bytes: &mut [u8],
) -> io::Result<()> {
    while !bytes.is_empty() {
        control.readable().await?;
        match control.try_io(Interest::READABLE, || {
            rustix::io::read(control, &mut *bytes).map_err(io::Error::from)
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
