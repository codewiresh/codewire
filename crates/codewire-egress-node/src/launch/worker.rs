//! One Pod's network worker, as a process.

use std::os::fd::{AsFd as _, AsRawFd as _};

use codewire_confinement::spawn::{OwnImage, duplicate_inherited_descriptor};
use codewire_egress_policy::PolicyDigest;
use codewire_egress_worker::hosted::{
    HostedWorkerBootstrap, WORKER_DRAIN_REQUEST, WORKER_IDLE_MESSAGE,
    WORKER_SELF_CHECK_PASSED_MESSAGE, encode_hosted_worker_bootstrap,
    send_worker_stream_descriptor,
};
use codewire_egress_worker::parent::{read_status_frame, transfer_descriptor};
use codewire_egress_worker::worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, NetworkWorkerStartupStatus,
    WORKER_BROKER_READY_MESSAGE, WORKER_PREPARED_MESSAGE, WORKER_READY_MESSAGE,
    WORKER_STATUS_MAX_BYTES, decode_worker_startup_status, send_worker_broker_descriptor,
};
use codewire_network_session::{EgressTrust, NetworkKey};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::Instant;
use uuid::Uuid;

use super::StartError;
use super::broker::BrokerSessions;
use super::spawner::{Process, Spawner};
use crate::children::{POD_UID_FLAG, WORKER_WORD};
use crate::supervisor::{PairStatus, SelfCheckProbe};

/// A worker whose guest session is authenticated. Dropping it kills it.
pub(super) struct Worker {
    process: Process,
    statuses: BufReader<UnixStream>,
    /// The status line being read, kept between calls so that dropping a
    /// read loses nothing.
    line: Vec<u8>,
}

/// What a worker is started with, besides its broker.
pub(super) struct WorkerSpec {
    pub(super) pod_uid: Uuid,
    pub(super) key: NetworkKey,
    pub(super) policy_digest: PolicyDigest,
    pub(super) trust: EgressTrust,
    /// The guest's stream. The worker takes it; this process keeps no copy.
    pub(super) stream: TcpStream,
}

/// Starts a worker from `image`, gives it its broker and the guest's stream,
/// and waits for it to report the guest's session authenticated.
pub(super) async fn start(
    image: &OwnImage,
    spawner: &Spawner,
    spec: WorkerSpec,
    sessions: BrokerSessions,
    deadline: Instant,
) -> Result<Worker, StartError> {
    let (parent, child_end) =
        std::os::unix::net::UnixStream::pair().map_err(|_| StartError::Spawn)?;
    parent
        .set_nonblocking(true)
        .map_err(|_| StartError::Spawn)?;
    let mut bootstrap = UnixStream::from_std(parent).map_err(|_| StartError::Spawn)?;
    let inherited =
        duplicate_inherited_descriptor(child_end.as_raw_fd()).map_err(|_| StartError::Spawn)?;
    let record = encode_hosted_worker_bootstrap(&HostedWorkerBootstrap {
        pod_uid: spec.pod_uid,
        network_key: spec.key,
        broker_key: *sessions.key,
        policy_digest: spec.policy_digest,
        trust: spec.trust,
    })
    .map_err(|_| StartError::Bootstrap)?;

    let pod = spec.pod_uid.to_string();
    let command = image
        .command(
            &["cw-egress", WORKER_WORD, POD_UID_FLAG, &pod],
            vec![(inherited.as_raw_fd(), NETWORK_BOOTSTRAP_FD)],
        )
        .map_err(|_| StartError::Spawn)?;
    let process = spawner.spawn(command).await?;
    // The child holds its own copy of its end.
    drop(inherited);
    drop(child_end);

    tokio::time::timeout_at(deadline, bootstrap.write_all(&record))
        .await
        .map_err(|_| StartError::Timeout)?
        .map_err(|_| StartError::Bootstrap)?;
    drop(record);
    expect(&mut bootstrap, WORKER_PREPARED_MESSAGE, deadline).await?;
    super::require_image(image, &process)?;

    // One message for each session, in session order.
    for endpoint in &sessions.endpoints {
        transfer_descriptor(&bootstrap, deadline, |bootstrap| {
            send_worker_broker_descriptor(bootstrap, endpoint.as_raw_fd())
        })
        .await?;
    }
    drop(sessions);
    expect(&mut bootstrap, WORKER_BROKER_READY_MESSAGE, deadline).await?;

    transfer_descriptor(&bootstrap, deadline, |bootstrap| {
        send_worker_stream_descriptor(bootstrap, spec.stream.as_fd())
    })
    .await?;
    drop(spec.stream);
    // The worker reports ready once the guest has authenticated the session.
    expect(&mut bootstrap, WORKER_READY_MESSAGE, deadline).await?;

    Ok(Worker {
        process,
        statuses: BufReader::new(bootstrap),
        line: Vec::with_capacity(WORKER_STATUS_MAX_BYTES),
    })
}

impl Worker {
    /// The worker's next status. Its end, or anything that is not a status
    /// this side knows, is the pair's end. The process's exit is never
    /// watched for itself: the socket closes after every line the worker
    /// wrote, so no status is lost to an exit that follows it. Cancel-safe.
    pub(super) async fn status(&mut self) -> PairStatus {
        loop {
            let Ok(available) = self.statuses.fill_buf().await else {
                return PairStatus::Ended;
            };
            if available.is_empty() {
                return PairStatus::Ended;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let taken = newline.map_or(available.len(), |at| at + 1);
            if self.line.len() + taken > WORKER_STATUS_MAX_BYTES {
                return PairStatus::Ended;
            }
            self.line.extend_from_slice(&available[..taken]);
            self.statuses.consume(taken);
            if newline.is_some() {
                let line = std::mem::take(&mut self.line);
                return status_of(&line);
            }
        }
    }

    /// Asks the worker to end its session at the first moment it holds no
    /// flow of the workload's. It answers with [`PairStatus::NoFlow`], once.
    pub(super) async fn request_drain(&mut self) -> Result<(), StartError> {
        self.statuses
            .get_mut()
            .write_all(WORKER_DRAIN_REQUEST)
            .await
            .map_err(|_| StartError::Bootstrap)
    }

    /// Kills the process and returns once it is reaped.
    pub(super) async fn end(self) {
        self.process.end().await;
    }
}

fn status_of(line: &[u8]) -> PairStatus {
    if line == WORKER_SELF_CHECK_PASSED_MESSAGE {
        return PairStatus::SelfCheckPassed;
    }
    if line == WORKER_IDLE_MESSAGE {
        return PairStatus::NoFlow;
    }
    match decode_worker_startup_status(line) {
        Some(NetworkWorkerStartupStatus::Failed(
            NetworkWorkerStartupFailure::SelfCheckDirectDial,
        )) => PairStatus::SelfCheckFailed(SelfCheckProbe::DirectDial),
        Some(NetworkWorkerStartupStatus::Failed(NetworkWorkerStartupFailure::SelfCheckDns)) => {
            PairStatus::SelfCheckFailed(SelfCheckProbe::Dns)
        }
        Some(NetworkWorkerStartupStatus::Failed(NetworkWorkerStartupFailure::SelfCheckRouting)) => {
            PairStatus::SelfCheckFailed(SelfCheckProbe::Routing)
        }
        _ => PairStatus::Ended,
    }
}

/// Reads the worker's next status line and requires it to be `expected`.
async fn expect(
    bootstrap: &mut UnixStream,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), StartError> {
    let status = read_status_frame(bootstrap, WORKER_STATUS_MAX_BYTES, deadline).await?;
    if status == expected {
        return Ok(());
    }
    Err(match decode_worker_startup_status(&status) {
        Some(NetworkWorkerStartupStatus::Failed(failure)) => StartError::Worker(failure),
        _ => StartError::Bootstrap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_line_is_the_self_check_or_the_pairs_end() {
        assert_eq!(
            status_of(WORKER_SELF_CHECK_PASSED_MESSAGE),
            PairStatus::SelfCheckPassed
        );
        assert_eq!(status_of(WORKER_IDLE_MESSAGE), PairStatus::NoFlow);
        assert_eq!(
            status_of(b"CWNETW1 failed-self-check-direct-dial\n"),
            PairStatus::SelfCheckFailed(SelfCheckProbe::DirectDial)
        );
        assert_eq!(
            status_of(b"CWNETW1 failed-self-check-dns\n"),
            PairStatus::SelfCheckFailed(SelfCheckProbe::Dns)
        );
        assert_eq!(
            status_of(b"CWNETW1 failed-self-check-routing\n"),
            PairStatus::SelfCheckFailed(SelfCheckProbe::Routing)
        );
        // A status that belongs to a start, a failure after the start, and
        // anything unknown all mean the pair is over.
        for line in [
            WORKER_READY_MESSAGE,
            b"CWNETW1 failed-protocol\n".as_slice(),
            b"something else\n",
        ] {
            assert_eq!(status_of(line), PairStatus::Ended);
        }
    }
}
