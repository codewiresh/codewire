//! The supervisor (#4000): one confined worker and broker pair for each
//! admitted Pod.
//!
//! It keeps one table, Pod UID to the task that owns that Pod's pair. A pair
//! is owned by one task from its start to its reaping, nothing is shared
//! between Pods, and no policy, key or decision outlives its pair. The
//! supervisor opens no connection of its own: admission and reporting are
//! the other half ([`crate::admitted`]), and a pair's processes are the
//! launcher's ([`Launch`]).
//!
//! Every failure ends with no pair, and so no egress: the guest redials and
//! is admitted again.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use codewire_egress_broker::refusals::RefusalBatch;
use codewire_egress_policy::{CompiledPolicy, PolicyDigest};
use codewire_network_session::EgressTrust;
use codewire_network_session::NetworkKey;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::admitted::AdmittedStream;
use crate::interception::PairIntercepts;
use crate::leaves::LeafSigner;

mod pod;
mod refusals;
#[cfg(test)]
mod tests;

/// How long a guest has, once its session is authenticated, to report its
/// self-check. No result in that time is a failed check.
pub const SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// What a pair is started with.
pub struct PairSpec {
    pub pod_uid: Uuid,
    /// The Pod's name, as its admission gave it: its front-door session
    /// names the Pod by it and its UID.
    pub pod_name: String,
    /// The guest's stream. The worker takes it; the supervisor never reads
    /// or writes it.
    pub stream: TcpStream,
    pub key: NetworkKey,
    pub policy: CompiledPolicy,
    /// Off but for a bound Pod whose assignment intercepts: the pair then
    /// runs its front door, and its broker hands that door the dials it
    /// intercepts, or it has none and its broker refuses them (#4001).
    pub intercepts: PairIntercepts,
    /// The trust frame the worker sends the guest first.
    pub trust: EgressTrust,
}

/// One of the two ways a guest tries to get round its egress path when it
/// starts. Either one connecting means the sandbox's lockdown is not applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfCheckProbe {
    DirectDial,
    Dns,
    /// The Pod's routes do not send its traffic through its egress path.
    Routing,
}

impl SelfCheckProbe {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DirectDial => "direct_dial",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }
}

/// What a running pair tells its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairStatus {
    SelfCheckPassed,
    /// The named probe connected.
    SelfCheckFailed(SelfCheckProbe),
    /// Answering a drain request: the worker holds no flow of the workload's.
    NoFlow,
    /// A process exited or the guest's session is over.
    Ended,
}

/// Starts a Pod's worker and broker, and its front door when it has one.
pub trait Launch: Send + Sync + 'static {
    type Pair: Pair;
    type Error: std::fmt::Display + Send;

    /// Resolves once every process is confined, the front door serves its
    /// end of the broker's hand-off, the broker enforces `spec.policy` and
    /// the worker reports the guest's session authenticated. A failure, or
    /// dropping the future, leaves no process.
    fn start(&self, spec: PairSpec)
    -> impl Future<Output = Result<Self::Pair, Self::Error>> + Send;
}

/// One Pod's running worker and broker, and front door when it has one.
/// Dropping it kills them all.
pub trait Pair: Send + 'static {
    type Error: std::fmt::Display + Send;

    /// The pair's next status. Cancel-safe: a status is never lost when the
    /// future is dropped.
    fn status(&mut self) -> impl Future<Output = PairStatus> + Send;

    /// Has the broker enforce `policy` from now on, ending the flows it
    /// refuses, and returns the digest the broker acknowledged.
    fn replace(
        &mut self,
        policy: &CompiledPolicy,
    ) -> impl Future<Output = Result<PolicyDigest, Self::Error>> + Send;

    /// The broker's reports of the refusals it folded, each as it comes;
    /// `None` once taken.
    fn refusals(&mut self) -> Option<mpsc::Receiver<RefusalBatch>>;

    /// Asks the worker to say when it holds no flow of the workload's, once,
    /// as [`PairStatus::NoFlow`].
    fn request_drain(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// The front door's public key, a DER SubjectPublicKeyInfo, for its
    /// leaves; `None` for a pair without one.
    fn front_door_key(&self) -> Option<&[u8]>;

    /// Has the front door serve `leaves` from now on, all or none. A refusal
    /// keeps the leaves it had.
    fn install_leaves(
        &mut self,
        leaves: &[Vec<u8>],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Kills and reaps every process.
    fn end(self) -> impl Future<Output = ()> + Send;
}

/// What stops the supervisor.
///
/// A cw-egress that is replaced by a newer version cancels `drain` when it
/// is told to stop and `shutdown` at the drain's deadline ([`crate::drain`]).
/// It cancels `drain` before admission closes its channel: a channel that
/// closes first ends every pair at once.
#[derive(Clone, Debug, Default)]
pub struct Signals {
    /// A pair that holds no open flow is ended, so its guest moves to
    /// another cw-egress; the rest carry on until `shutdown`.
    pub drain: CancellationToken,
    /// Every pair is ended and [`supervisor`] returns.
    pub shutdown: CancellationToken,
}

/// How a drain's pairs ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// Ended at once, holding no open flow.
    pub moved_idle: u64,
    /// Still holding one when `shutdown` came.
    pub cut_at_deadline: u64,
}

struct Running {
    serial: u64,
    peer: SocketAddr,
    stop: CancellationToken,
    /// Cancelled when the Pod's task is gone, with its pair reaped.
    gone: CancellationToken,
}

/// Every Pod's task, and the table of the newest one per Pod.
struct Pods<L, S> {
    launch: Arc<L>,
    signer: Arc<S>,
    signals: Signals,
    /// Ends every pair when admission is lost outside a drain.
    stop_all: CancellationToken,
    running: HashMap<Uuid, Running>,
    tasks: JoinSet<(Uuid, u64, pod::Outcome)>,
    serial: u64,
    drained: Drained,
}

impl<L: Launch, S: LeafSigner> Pods<L, S> {
    fn new(launch: L, signer: Arc<S>, signals: Signals) -> Self {
        Self {
            launch: Arc::new(launch),
            signer,
            signals,
            stop_all: CancellationToken::new(),
            running: HashMap::new(),
            tasks: JoinSet::new(),
            serial: 0,
            drained: Drained::default(),
        }
    }

    /// Starts a task for `stream`. It waits for the Pod's older pair, if
    /// any, to be reaped before it starts its own.
    fn start(&mut self, stream: AdmittedStream) {
        self.serial += 1;
        let serial = self.serial;
        let running = Running {
            serial,
            peer: stream.peer,
            stop: self.stop_all.child_token(),
            gone: CancellationToken::new(),
        };
        let pod = pod::Pod {
            launch: Arc::clone(&self.launch),
            signer: Arc::clone(&self.signer),
            stop: running.stop.clone(),
            signals: self.signals.clone(),
        };
        let gone = running.gone.clone().drop_guard();
        let pod_uid = stream.pod_uid;
        let previous = self.running.insert(pod_uid, running).map(|previous| {
            tracing::info!(
                %pod_uid,
                pod_name = %stream.pod_name,
                replaced_peer = %previous.peer,
                peer = %stream.peer,
                "a newer egress stream replaces the Pod's pair"
            );
            previous.stop.cancel();
            previous.gone
        });
        self.tasks.spawn(async move {
            let _gone = gone;
            if let Some(previous) = previous {
                previous.cancelled().await;
            }
            (pod_uid, serial, pod.run(stream).await)
        });
    }

    fn finished(&mut self, finished: Result<(Uuid, u64, pod::Outcome), tokio::task::JoinError>) {
        match finished {
            Ok((pod_uid, serial, outcome)) => {
                if self
                    .running
                    .get(&pod_uid)
                    .is_some_and(|running| running.serial == serial)
                {
                    self.running.remove(&pod_uid);
                }
                match outcome {
                    pod::Outcome::MovedIdle => self.drained.moved_idle += 1,
                    pod::Outcome::CutAtDeadline => self.drained.cut_at_deadline += 1,
                    pod::Outcome::Other => {}
                }
            }
            // The task's pair died with it, and its entry is replaced by
            // the Pod's next stream.
            Err(error) => tracing::error!(%error, "a Pod's egress task failed"),
        }
    }
}

/// Runs a pair for every stream `admitted` yields. A newer stream for a Pod
/// replaces the older: the older pair is reaped before the newer starts.
/// `signer` signs the leaves of each pair's front door ([`crate::leaves`]).
///
/// It returns, with every pair reaped, on shutdown; when admission closes
/// its channel outside a drain; or, in a drain, once admission has closed
/// its channel and the last pair is gone.
pub async fn supervisor<L: Launch, S: LeafSigner>(
    mut admitted: mpsc::Receiver<AdmittedStream>,
    signals: Signals,
    launch: L,
    signer: Arc<S>,
) -> Drained {
    let mut pods = Pods::new(launch, signer, signals.clone());
    let mut admitting = true;
    while admitting || !pods.tasks.is_empty() {
        tokio::select! {
            // Each pair's task sees the shutdown itself, and says whether a
            // drain's deadline cut it.
            () = signals.shutdown.cancelled() => break,
            stream = admitted.recv(), if admitting => match stream {
                Some(stream) => pods.start(stream),
                None if signals.drain.is_cancelled() => admitting = false,
                None => {
                    pods.stop_all.cancel();
                    break;
                }
            },
            Some(finished) = pods.tasks.join_next() => pods.finished(finished),
        }
    }
    while let Some(finished) = pods.tasks.join_next().await {
        pods.finished(finished);
    }
    pods.drained
}
