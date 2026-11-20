//! What passes between cw-egress's two halves (#4000): admission hands the
//! supervisor each admitted stream, and the supervisor tells the reporter
//! what each Pod's pair enforces.
//!
//! Admission never waits on a pair's start, and one Pod's events are ordered
//! by construction: there is one sender per admitted stream and the reporter
//! reads one Pod's events on one path.

use std::net::SocketAddr;

use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::record::EgressRecord;
use codewire_network_session::EgressTrust;
use codewire_network_session::NetworkKey;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::orchestration::{Assignment, AssignmentError};

/// One guest stream orchestration admitted, with its hello already read and
/// answered.
pub struct AdmittedStream {
    pub pod_uid: Uuid,
    pub pod_name: String,
    pub peer: SocketAddr,
    pub stream: TcpStream,
    pub key: NetworkKey,
    /// The assignment `Admit` returned.
    pub assignment: Assignment,
    /// The guest's trust frame from `Admit`: the Pod's interception CA, the
    /// same for its life, or none.
    pub trust: EgressTrust,
    /// The latest assignment from `WatchAssignment`, starting as
    /// `assignment`. One that does not parse arrives as its error; a closed
    /// channel means the Pod ended.
    pub changes: watch::Receiver<Result<Assignment, AssignmentError>>,
    pub events: PodEvents,
}

/// Why a Pod has no egress though its stream was admitted. The code is what
/// orchestration stores for operators; the guest never sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureCode {
    SelfCheckFailed,
    PolicyDigestMismatch,
}

impl FailureCode {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelfCheckFailed => "self_check_failed",
            Self::PolicyDigestMismatch => "policy_digest_mismatch",
        }
    }
}

/// What a Pod's pair enforces, in the order it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PodEvent {
    /// The broker enforces this revision and the guest's self-check passed.
    Enforced {
        revision: u32,
        digest: PolicyDigest,
    },
    FailedClosed(FailureCode),
    Records(Vec<EgressRecord>),
    /// The pair is gone; nothing follows from this stream. `moved` says this
    /// cw-egress was draining, so the guest is expected on another cw-egress:
    /// the reporter sends no `DISCONNECTED`, which could land after that
    /// one's `ENFORCED`.
    Ended {
        moved: bool,
    },
}

/// Where the supervisor reports one admitted stream's events.
#[derive(Clone, Debug)]
pub struct PodEvents(mpsc::Sender<PodEvent>);

impl PodEvents {
    pub fn new(sender: mpsc::Sender<PodEvent>) -> Self {
        Self(sender)
    }

    /// False when the reporter is gone.
    pub(crate) async fn send(&self, event: PodEvent) -> bool {
        self.0.send(event).await.is_ok()
    }
}
