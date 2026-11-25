//! One Pod's egress broker, as a process.
//!
//! Its control socket carries the supervisor's frames down and the broker's
//! up: an acknowledgement for each policy it was sent, and its folded
//! refusals at most once a second (SPEC.md "The refusal path"). The broker
//! reports refusals only because the supervisor starts it with
//! [`REPORT_REFUSALS_FLAG`], and one task reads every frame it sends from
//! then on.

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex, PoisonError};

use codewire_confinement::spawn::{OwnImage, duplicate_inherited_descriptor};
use codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN;
use codewire_egress_broker::refusals::RefusalBatch;
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::intercept::InterceptSet;
use codewire_egress_policy::{CompiledPolicy, PolicyDigest};
use codewire_egress_worker::broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HANDOFF_FD, EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES,
    EgressBrokerStartupStatus, decode_egress_broker_startup_status, encode_egress_broker_bootstrap,
};
use codewire_egress_worker::broker_control::{
    BrokerFrame, POLICY_ACK_TIMEOUT, encode_intercept_frame, encode_policy_frame, read_broker_frame,
};
use codewire_egress_worker::host_addresses::encode_frame;
use codewire_egress_worker::parent::{fresh_egress_broker_key, read_status_frame};
use tokio::io::{AsyncRead, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::StartError;
use super::spawner::{Process, Spawner};
use codewire_egress_worker::hosted::HOSTED_GENERATION;

use crate::children::{
    BROKER_WORD, INTERCEPT_HANDOFF_FLAG, INTERCEPT_REFUSE_FLAG, POD_UID_FLAG, REPORT_REFUSALS_FLAG,
};

/// Refusal reports read and not yet taken. The broker sends at most one a
/// second and the supervisor takes each as it comes, but none during the
/// guest's ten-second self-check, so a full queue is a supervisor that
/// stopped taking them.
const REPORTS_WAITING: usize = 16;

/// A broker that is confined and enforcing its policy. Dropping it kills it.
pub(super) struct Broker {
    process: Process,
    control: OwnedWriteHalf,
    /// Where the reader sends the next acknowledgement: set only while a
    /// replacement waits for one.
    waiting: Arc<Mutex<Option<oneshot::Sender<PolicyDigest>>>>,
    /// Taken by the supervisor once.
    reports: Option<mpsc::Receiver<RefusalBatch>>,
    /// Cancelled when the reader stops: the socket closed, a frame was
    /// malformed, or an acknowledgement came that nobody asked for.
    gone: CancellationToken,
}

/// What the worker needs to reach a started broker: its ends of the IPC
/// sessions, the admission session first, and the key that authenticates them.
pub(super) struct BrokerSessions {
    pub(super) endpoints: Vec<StdUnixStream>,
    pub(super) key: Zeroizing<[u8; BROKER_IPC_KEY_LEN]>,
}

/// What a broker is started with.
pub(super) struct BrokerSpec<'a> {
    pub(super) pod_uid: Uuid,
    pub(super) policy: &'a CompiledPolicy,
    /// The cluster's own addresses, which it refuses from its first
    /// admission on.
    pub(super) refused: &'a HostAddressSet,
    pub(super) intercepts: Intercepts<'a>,
}

/// What the broker does with the dials a Pod's bindings name (#4001).
pub(super) enum Intercepts<'a> {
    Off,
    /// Hands them over on `end`, its end of the hand-off socket to the
    /// Pod's front door.
    HandOff {
        end: OwnedFd,
        hosts: &'a InterceptSet,
    },
    /// Refuses them: the Pod has no front door.
    Refuse(&'a InterceptSet),
}

/// Starts a broker for `spec.pod_uid` from `image`.
pub(super) async fn start(
    image: &OwnImage,
    spawner: &Spawner,
    spec: BrokerSpec<'_>,
    deadline: Instant,
) -> Result<(Broker, BrokerSessions), StartError> {
    let BrokerSpec {
        pod_uid,
        policy,
        refused,
        intercepts,
    } = spec;
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
    let pod = pod_uid.to_string();
    let mut arguments = vec!["cw-egress", BROKER_WORD, POD_UID_FLAG, &pod];
    let mut inherited_handoff = None;
    let hosts = match intercepts {
        Intercepts::Off => None,
        Intercepts::HandOff { end, hosts } => {
            let inherited =
                duplicate_inherited_descriptor(end.as_raw_fd()).map_err(|_| StartError::Spawn)?;
            descriptors.push((inherited.as_raw_fd(), EGRESS_BROKER_HANDOFF_FD));
            inherited_handoff = Some(inherited);
            arguments.push(INTERCEPT_HANDOFF_FLAG);
            Some(hosts)
        }
        Intercepts::Refuse(hosts) => {
            arguments.push(INTERCEPT_REFUSE_FLAG);
            Some(hosts)
        }
    };
    // Last, after any interception flag.
    arguments.push(REPORT_REFUSALS_FLAG);
    let intercepts = hosts
        .map(encode_intercept_frame)
        .transpose()
        .map_err(|_| StartError::Bootstrap)?;
    let key = fresh_egress_broker_key();
    let record = encode_egress_broker_bootstrap(pod_uid, HOSTED_GENERATION, &key, policy)
        .map_err(|_| StartError::Bootstrap)?;

    let command = image
        .command(&arguments, descriptors)
        .map_err(|_| StartError::Spawn)?;
    let process = spawner.spawn(command).await?;
    // The child holds its own copies of its ends. Once the hand-off end is
    // gone here, only the broker and the front door hold the socket.
    drop(inherited_bootstrap);
    drop(inherited_control);
    drop(inherited_sessions);
    drop(inherited_handoff);

    tokio::time::timeout_at(deadline, async {
        bootstrap.write_all(&record).await?;
        control.write_all(&encode_frame(refused)).await?;
        // A broker that intercepts reads its bindings before it is prepared.
        match &intercepts {
            Some(frame) => control.write_all(frame).await,
            None => Ok(()),
        }
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
        Broker::new(process, control),
        BrokerSessions { endpoints, key },
    ))
}

impl Broker {
    /// Starts the task that reads every frame the broker sends on `control`.
    fn new(process: Process, control: UnixStream) -> Self {
        let (reader, writer) = control.into_split();
        let waiting = Arc::new(Mutex::new(None));
        let (reports, taken) = mpsc::channel(REPORTS_WAITING);
        let gone = CancellationToken::new();
        tokio::spawn(read_from_broker(
            reader,
            Arc::clone(&waiting),
            reports,
            gone.clone(),
        ));
        Self {
            process,
            control: writer,
            waiting,
            reports: Some(taken),
            gone,
        }
    }

    /// Has the broker enforce `policy` from now on and returns the digest it
    /// acknowledged. It ends the flows the policy refuses before it answers.
    pub(super) async fn replace(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<PolicyDigest, StartError> {
        let frame = encode_policy_frame(policy).map_err(|_| StartError::Bootstrap)?;
        let (answer, acknowledged) = oneshot::channel();
        *self.waiting.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
        let replaced = match tokio::time::timeout(POLICY_ACK_TIMEOUT, async {
            self.control
                .write_all(&frame)
                .await
                .map_err(|_| StartError::Bootstrap)?;
            // Dropped unanswered when the reader stops.
            acknowledged.await.map_err(|_| StartError::Bootstrap)
        })
        .await
        {
            Ok(replaced) => replaced,
            Err(_) => Err(StartError::Timeout),
        };
        // A late acknowledgement then has no one waiting, and ends the pair.
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        replaced
    }

    /// Resolves when the broker is gone: its socket closed, which the kernel
    /// does when the process dies, or it sent something malformed or an
    /// acknowledgement nobody asked for, which is a broker that can no longer
    /// be trusted. Cancel-safe.
    pub(super) async fn exited(&mut self) {
        self.gone.cancelled().await;
    }

    /// The broker's refusal reports, as its reader reads them; `None` once
    /// taken. They end when the reader stops, which [`Broker::exited`] says.
    pub(super) fn refusals(&mut self) -> Option<mpsc::Receiver<RefusalBatch>> {
        self.reports.take()
    }

    /// Kills the process and returns once it is reaped.
    pub(super) async fn end(self) {
        self.process.end().await;
    }
}

/// Reads every frame the broker sends until its socket closes or a frame is
/// one it must not send, then cancels `gone`.
async fn read_from_broker<R: AsyncRead + Unpin>(
    mut reader: R,
    waiting: Arc<Mutex<Option<oneshot::Sender<PolicyDigest>>>>,
    reports: mpsc::Sender<RefusalBatch>,
    gone: CancellationToken,
) {
    let _gone = gone.drop_guard();
    loop {
        match read_broker_frame(&mut reader).await {
            Ok(BrokerFrame::PolicyAck(digest)) => {
                let answer = waiting
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                let Some(answer) = answer else {
                    tracing::warn!("an egress broker acknowledged a policy nobody sent");
                    return;
                };
                // The replacement gave up waiting; it ends the pair itself.
                let _ = answer.send(digest);
            }
            Ok(BrokerFrame::Refusals(batch)) => {
                if let Err(mpsc::error::TrySendError::Full(batch)) = reports.try_send(batch) {
                    tracing::warn!(
                        rows = batch.rows.len(),
                        dropped = batch.dropped,
                        "an egress broker's refusal report was dropped: the supervisor is not taking them"
                    );
                }
            }
            Err(_) => return,
        }
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
