//! A Pod's pair as two processes of cw-egress's own image (#4000).
//!
//! The broker starts first and is enforcing its policy before the worker
//! exists, so nothing can ask it anything earlier. The worker then gets the
//! broker's IPC sessions and the guest's stream, and the supervisor keeps
//! neither: after a start it holds two process handles, the broker's control
//! socket and the worker's status socket.

use std::os::linux::fs::MetadataExt as _;
use std::time::Duration;

use codewire_confinement::spawn::OwnImage;
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::{CompiledPolicy, PolicyDigest};
use codewire_egress_worker::broker::EgressBrokerStartupFailure;
use codewire_egress_worker::parent;
use codewire_egress_worker::worker::NetworkWorkerStartupFailure;
use thiserror::Error;
use tokio::time::Instant;

use crate::supervisor::{Launch, Pair, PairSpec, PairStatus};

mod broker;
mod spawner;
mod worker;

/// How long a pair has to start: two processes confining themselves and the
/// guest's handshake. A guest whose start fails redials.
pub const START_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a pair did not start, or stopped doing what it was asked.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartError {
    #[error("a child process could not be started")]
    Spawn,
    #[error("a child's bootstrap or control socket failed")]
    Bootstrap,
    #[error("a child did not answer in time")]
    Timeout,
    #[error("a child is not running cw-egress's own image")]
    Image,
    #[error("the broker refused to start: {}", .0.code())]
    Broker(EgressBrokerStartupFailure),
    #[error("the worker refused to start: {}", .0.code())]
    Worker(NetworkWorkerStartupFailure),
}

impl From<parent::StartError> for StartError {
    fn from(error: parent::StartError) -> Self {
        match error {
            parent::StartError::Timeout => Self::Timeout,
            parent::StartError::Bootstrap => Self::Bootstrap,
        }
    }
}

/// Starts each pair from one image.
#[derive(Debug)]
pub struct ProcessLaunch {
    image: OwnImage,
    spawner: spawner::Spawner,
    refused: HostAddressSet,
}

impl ProcessLaunch {
    /// `refused` are the cluster's own addresses, which no policy opens:
    /// every broker refuses them from its first admission on. Starts the one
    /// thread every child is started from.
    pub fn new(image: OwnImage, refused: HostAddressSet) -> std::io::Result<Self> {
        Ok(Self {
            image,
            spawner: spawner::Spawner::start()?,
            refused,
        })
    }
}

/// How long a worker has to say its last word once its broker is gone.
const LAST_WORD: Duration = Duration::from_secs(1);

/// One Pod's running broker and worker.
pub struct ProcessPair {
    broker: broker::Broker,
    /// The broker's end was seen. It is not the pair's end until the worker
    /// has had its last word.
    broker_gone: bool,
    worker: worker::Worker,
}

impl Launch for ProcessLaunch {
    type Pair = ProcessPair;
    type Error = StartError;

    async fn start(&self, spec: PairSpec) -> Result<ProcessPair, StartError> {
        let deadline = Instant::now() + START_TIMEOUT;
        let (broker, sessions) = broker::start(
            &self.image,
            &self.spawner,
            spec.pod_uid,
            &spec.policy,
            &self.refused,
            deadline,
        )
        .await?;
        let worker = worker::start(
            &self.image,
            &self.spawner,
            worker::WorkerSpec {
                pod_uid: spec.pod_uid,
                key: spec.key,
                policy_digest: spec.policy.digest(),
                stream: spec.stream,
            },
            sessions,
            deadline,
        )
        .await?;
        Ok(ProcessPair {
            broker,
            broker_gone: false,
            worker,
        })
    }
}

impl Pair for ProcessPair {
    type Error = StartError;

    async fn status(&mut self) -> PairStatus {
        next_status(
            self.worker.status(),
            &mut self.broker_gone,
            self.broker.exited(),
        )
        .await
    }

    async fn replace(&mut self, policy: &CompiledPolicy) -> Result<PolicyDigest, StartError> {
        self.broker.replace(policy).await
    }

    async fn request_drain(&mut self) -> Result<(), StartError> {
        self.worker.request_drain().await
    }

    async fn end(self) {
        self.worker.end().await;
        self.broker.end().await;
    }
}

/// The pair's next status from its two sources: what the worker says, and
/// the broker's end.
///
/// A worker whose session ends drops its broker first and writes its last
/// line after, so the broker's end is often seen before the line that says
/// why. That line decides whether a sandbox failed its self-check or moved
/// idle, so once the broker is gone the worker gets [`LAST_WORD`] to say it,
/// and only its silence is the pair's end.
async fn next_status(
    worker: impl Future<Output = PairStatus>,
    broker_gone: &mut bool,
    broker_exited: impl Future<Output = ()>,
) -> PairStatus {
    tokio::pin!(worker);
    if !*broker_gone {
        tokio::select! {
            biased;
            status = &mut worker => return status,
            () = broker_exited => *broker_gone = true,
        }
    }
    tokio::time::timeout(LAST_WORD, worker)
        .await
        .unwrap_or(PairStatus::Ended)
}

/// Requires `process` to be running `image`, by device and inode.
fn require_image(image: &OwnImage, process: &spawner::Process) -> Result<(), StartError> {
    same_image(image, process.id().and_then(executable_of))
}

/// The device and inode of a running process's executable.
fn executable_of(pid: u32) -> Option<(u64, u64)> {
    std::fs::metadata(format!("/proc/{pid}/exe"))
        .ok()
        .map(|executable| (executable.st_dev(), executable.st_ino()))
}

fn same_image(image: &OwnImage, executable: Option<(u64, u64)>) -> Result<(), StartError> {
    if executable.is_some() && executable == image.identity().ok() {
        Ok(())
    } else {
        Err(StartError::Image)
    }
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;

    #[test]
    fn a_child_running_another_executable_is_refused() {
        let image = OwnImage::open().unwrap();
        // A shell that waits on its input, so it is alive while it is looked at.
        let mut other = std::process::Command::new("/bin/sh")
            .args(["-c", "read line"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let running = executable_of(other.id());
        other.kill().unwrap();
        other.wait().unwrap();

        assert!(running.is_some());
        assert_eq!(same_image(&image, running), Err(StartError::Image));
        assert_eq!(same_image(&image, None), Err(StartError::Image));
        assert_eq!(same_image(&image, image.identity().ok()), Ok(()));
    }

    /// A worker that says `status` after `delay`.
    async fn says(status: PairStatus, delay: Duration) -> PairStatus {
        tokio::time::sleep(delay).await;
        status
    }

    #[tokio::test(start_paused = true)]
    async fn the_workers_last_word_is_heard_though_its_broker_went_first() {
        let mut broker_gone = false;
        let status = next_status(
            says(PairStatus::NoFlow, Duration::from_millis(100)),
            &mut broker_gone,
            std::future::ready(()),
        )
        .await;
        assert_eq!(status, PairStatus::NoFlow);
        assert!(broker_gone);
    }

    #[tokio::test(start_paused = true)]
    async fn a_worker_silent_after_its_broker_is_gone_is_the_pairs_end() {
        let mut broker_gone = false;
        let started = tokio::time::Instant::now();
        let status = next_status(
            std::future::pending(),
            &mut broker_gone,
            std::future::ready(()),
        )
        .await;
        assert_eq!(status, PairStatus::Ended);
        assert_eq!(started.elapsed(), LAST_WORD);

        // And it stays the end, without the broker being asked again.
        let again = next_status(
            std::future::pending(),
            &mut broker_gone,
            std::future::pending(),
        )
        .await;
        assert_eq!(again, PairStatus::Ended);
    }

    #[tokio::test(start_paused = true)]
    async fn while_the_broker_lives_only_the_worker_speaks() {
        let mut broker_gone = false;
        let status = next_status(
            says(PairStatus::SelfCheckPassed, Duration::from_secs(3600)),
            &mut broker_gone,
            std::future::pending(),
        )
        .await;
        assert_eq!(status, PairStatus::SelfCheckPassed);
        assert!(!broker_gone);
    }
}
