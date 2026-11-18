//! One Pod's egress broker, as a process.

use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream as StdUnixStream;

use codewire_confinement::spawn::{OwnImage, duplicate_inherited_descriptor};
use codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN;
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::{CompiledPolicy, PolicyDigest};
use codewire_egress_worker::broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES,
    EgressBrokerStartupStatus, decode_egress_broker_startup_status, encode_egress_broker_bootstrap,
};
use codewire_egress_worker::broker_control::{
    POLICY_ACK_TIMEOUT, encode_policy_frame, read_policy_ack,
};
use codewire_egress_worker::host_addresses::encode_frame;
use codewire_egress_worker::parent::{fresh_egress_broker_key, read_status_frame};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::StartError;
use super::spawner::{Process, Spawner};
use codewire_egress_worker::hosted::HOSTED_GENERATION;

use crate::children::{BROKER_WORD, POD_UID_FLAG};

/// A broker that is confined and enforcing its policy. Dropping it kills it.
pub(super) struct Broker {
    process: Process,
    control: UnixStream,
}

/// What the worker needs to reach a started broker: its ends of the IPC
/// sessions, the admission session first, and the key that authenticates them.
pub(super) struct BrokerSessions {
    pub(super) endpoints: Vec<StdUnixStream>,
    pub(super) key: Zeroizing<[u8; BROKER_IPC_KEY_LEN]>,
}

/// Starts a broker for `pod_uid` from `image`. It refuses `refused`, the
/// cluster's own addresses, from its first admission on.
pub(super) async fn start(
    image: &OwnImage,
    spawner: &Spawner,
    pod_uid: Uuid,
    policy: &CompiledPolicy,
    refused: &HostAddressSet,
    deadline: Instant,
) -> Result<(Broker, BrokerSessions), StartError> {
    let (mut bootstrap, inherited_bootstrap) = inherited_pair()?;
    let (mut control, inherited_control) = inherited_pair()?;
    let mut endpoints = Vec::with_capacity(EGRESS_BROKER_INHERITED_SESSIONS + 1);
    let mut inherited_sessions = Vec::with_capacity(EGRESS_BROKER_INHERITED_SESSIONS);
    for _ in 0..EGRESS_BROKER_INHERITED_SESSIONS {
        let (worker_end, broker_end) = StdUnixStream::pair().map_err(|_| StartError::Spawn)?;
        inherited_sessions.push(
            duplicate_inherited_descriptor(broker_end.as_raw_fd())
                .map_err(|_| StartError::Spawn)?,
        );
        endpoints.push(worker_end);
    }
    let mut descriptors = vec![
        (inherited_bootstrap.as_raw_fd(), EGRESS_BROKER_BOOTSTRAP_FD),
        (
            inherited_control.as_raw_fd(),
            EGRESS_BROKER_HOST_ADDRESSES_FD,
        ),
    ];
    descriptors.extend(
        inherited_sessions
            .iter()
            .zip(EGRESS_BROKER_FIRST_SESSION_FD..)
            .map(|(session, target)| (session.as_raw_fd(), target)),
    );
    let key = fresh_egress_broker_key();
    let record = encode_egress_broker_bootstrap(pod_uid, HOSTED_GENERATION, &key, policy)
        .map_err(|_| StartError::Bootstrap)?;

    let pod = pod_uid.to_string();
    let command = image
        .command(&["cw-egress", BROKER_WORD, POD_UID_FLAG, &pod], descriptors)
        .map_err(|_| StartError::Spawn)?;
    let process = spawner.spawn(command).await?;
    // The child holds its own copies of its ends.
    drop(inherited_bootstrap);
    drop(inherited_control);
    drop(inherited_sessions);

    tokio::time::timeout_at(deadline, async {
        bootstrap.write_all(&record).await?;
        control.write_all(&encode_frame(refused)).await
    })
    .await
    .map_err(|_| StartError::Timeout)?
    .map_err(|_| StartError::Bootstrap)?;
    drop(record);

    expect(&mut bootstrap, EGRESS_BROKER_PREPARED_MESSAGE, deadline).await?;
    // The child has read its bootstrap and waits here, not yet confined, so
    // its executable can still be compared with the image it must be.
    super::require_image(image, &process)?;
    tokio::time::timeout_at(deadline, bootstrap.write_all(EGRESS_BROKER_CONFINE_MESSAGE))
        .await
        .map_err(|_| StartError::Timeout)?
        .map_err(|_| StartError::Bootstrap)?;
    expect(&mut bootstrap, EGRESS_BROKER_READY_MESSAGE, deadline).await?;

    // The bootstrap stream becomes the admission session.
    endpoints.insert(0, bootstrap.into_std().map_err(|_| StartError::Bootstrap)?);
    Ok((
        Broker { process, control },
        BrokerSessions { endpoints, key },
    ))
}

impl Broker {
    /// Has the broker enforce `policy` from now on and returns the digest it
    /// acknowledged. It ends the flows the policy refuses before it answers.
    pub(super) async fn replace(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<PolicyDigest, StartError> {
        let frame = encode_policy_frame(policy).map_err(|_| StartError::Bootstrap)?;
        tokio::time::timeout(POLICY_ACK_TIMEOUT, async {
            self.control.write_all(&frame).await?;
            read_policy_ack(&mut self.control).await
        })
        .await
        .map_err(|_| StartError::Timeout)?
        .map_err(|_| StartError::Bootstrap)
    }

    /// Resolves when the broker is gone. Outside a replacement it writes
    /// nothing to its control socket, so the socket has something to read
    /// only once the broker's end is closed, which the kernel does when the
    /// process dies. A byte it was never asked for is a broker that can no
    /// longer be trusted, and counts the same. Cancel-safe.
    pub(super) async fn exited(&mut self) {
        let mut byte = [0_u8; 1];
        // End-of-file, an error and an unasked byte all mean the same here.
        let _ = self.control.read(&mut byte).await;
    }

    /// Kills the process and returns once it is reaped.
    pub(super) async fn end(self) {
        self.process.end().await;
    }
}

/// A socket pair for a child: this process's end, and the child's end
/// duplicated above the inherited-descriptor floor.
fn inherited_pair() -> Result<(UnixStream, std::os::fd::OwnedFd), StartError> {
    let (parent, child) = StdUnixStream::pair().map_err(|_| StartError::Spawn)?;
    parent
        .set_nonblocking(true)
        .map_err(|_| StartError::Spawn)?;
    let parent = UnixStream::from_std(parent).map_err(|_| StartError::Spawn)?;
    let inherited =
        duplicate_inherited_descriptor(child.as_raw_fd()).map_err(|_| StartError::Spawn)?;
    Ok((parent, inherited))
}

/// Reads the broker's next status line and requires it to be `expected`.
async fn expect(
    bootstrap: &mut UnixStream,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), StartError> {
    let status = read_status_frame(bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES, deadline).await?;
    if status == expected {
        return Ok(());
    }
    Err(match decode_egress_broker_startup_status(&status) {
        Some(EgressBrokerStartupStatus::Failed(failure)) => StartError::Broker(failure),
        _ => StartError::Bootstrap,
    })
}
