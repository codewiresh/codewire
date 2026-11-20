//! One admitted stream's pair, from its start to its reaping.

use std::sync::Arc;

use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{Launch, Pair, PairSpec, PairStatus, SELF_CHECK_TIMEOUT, Signals};
use crate::admitted::{AdmittedStream, FailureCode, PodEvent, PodEvents};
use crate::interception::{Interception, InterceptionRefusal, PairIntercepts};
use crate::orchestration::{Assignment, AssignmentError};

pub(super) struct Pod<L> {
    pub(super) launch: Arc<L>,
    /// The Pod's stream was replaced, or admission is gone.
    pub(super) stop: CancellationToken,
    pub(super) signals: Signals,
}

/// How a Pod's task ended, as a drain counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    MovedIdle,
    CutAtDeadline,
    Other,
}

/// What a pair enforces for its Pod.
struct Enforcing {
    /// `None` for an unbound warm member, which runs the built-in `locked`:
    /// nothing in it reaches the outside until it is bound. The platform's
    /// own services are reached inside the cluster, never through the pair.
    environment: Option<String>,
    policy: CompiledPolicy,
    revision: u32,
    /// Started with the pair: a pair's front door, its broker's hand-off
    /// and the hosts its broker refuses exist from its start or not at all.
    intercepts: PairIntercepts,
}

impl Enforcing {
    /// What `assignment` has a pair enforce, or, for interception no broker
    /// set can refuse, why the Pod gets no pair: its agent hosts' requests
    /// carry placeholders and must never be dialled (#5159).
    fn of(assignment: Assignment, pod_uid: Uuid) -> Result<Self, InterceptionRefusal> {
        match assignment {
            Assignment::Unbound { .. } => Ok(Self {
                environment: None,
                policy: BuiltinPolicy::Locked.compile(),
                revision: 0,
                intercepts: PairIntercepts::Off,
            }),
            Assignment::Bound {
                environment_id,
                policy,
                interception,
                ..
            } => {
                match interception.as_ref() {
                    Interception::RefuseHosts { why, .. } => tracing::warn!(
                        %pod_uid,
                        reason = why.code(),
                        "a Pod's interception bindings cannot be served; its broker refuses their hosts"
                    ),
                    Interception::FailClosed(why) => tracing::warn!(
                        %pod_uid,
                        reason = why.code(),
                        "a Pod's interception bindings cannot be refused; it gets no egress pair"
                    ),
                    Interception::Off | Interception::On(_) => {}
                }
                Ok(Self {
                    environment: Some(environment_id),
                    policy: policy.policy,
                    revision: policy.revision,
                    intercepts: interception.pair()?,
                })
            }
        }
    }

    fn event(&self) -> PodEvent {
        PodEvent::Enforced {
            revision: self.revision,
            digest: self.policy.digest(),
        }
    }

    /// What moving to `next` takes. A bound Pod never goes back to unbound
    /// and never changes environment: either means its sandbox is over. A
    /// pair cannot change what it intercepts, so any change to that ends
    /// the pair, and the guest's redial starts one with the new set.
    fn change_to(&self, next: &Self) -> Change {
        match (&self.environment, &next.environment) {
            (Some(current), Some(next)) if current != next => return Change::End,
            (Some(_), None) => return Change::End,
            _ => {}
        }
        if self.intercepts != next.intercepts {
            return Change::End;
        }
        if self.policy.digest() != next.policy.digest() {
            Change::Replace
        } else if self.environment != next.environment || self.revision != next.revision {
            Change::Report
        } else {
            Change::None
        }
    }
}

enum Change {
    None,
    /// The broker already enforces the same document.
    Report,
    Replace,
    End,
}

/// Why a pair is ended.
enum End {
    /// Replaced, shut down outside a drain, or its Pod ended.
    Told,
    /// Draining, and the worker holds no open flow.
    Moved,
    /// Draining, and the shutdown came first.
    Cut,
    /// A process exited or the guest's session is over.
    Pair,
    Failed(FailureCode),
    /// The pair stopped doing what it was asked; logged where it happened.
    Lost,
    ReporterGone,
}

struct Session<'a, P> {
    pod_uid: Uuid,
    pair: &'a mut P,
    enforcing: Enforcing,
    changes: watch::Receiver<Result<Assignment, AssignmentError>>,
    events: &'a PodEvents,
    stop: &'a CancellationToken,
    signals: &'a Signals,
    draining: bool,
}

/// A shutdown during a drain is the drain's deadline.
fn shut_down(signals: &Signals) -> End {
    if signals.drain.is_cancelled() {
        End::Cut
    } else {
        End::Told
    }
}

impl<L: Launch> Pod<L> {
    pub(super) async fn run(self, admitted: AdmittedStream) -> Outcome {
        let AdmittedStream {
            pod_uid,
            pod_name,
            peer,
            stream,
            key,
            assignment,
            trust,
            changes,
            events,
        } = admitted;
        let started = match Enforcing::of(assignment, pod_uid) {
            // Logged where it was decided; no process is started.
            Err(_) => Err(End::Lost),
            Ok(enforcing) => {
                let spec = PairSpec {
                    pod_uid,
                    stream,
                    key,
                    policy: enforcing.policy.clone(),
                    intercepts: enforcing.intercepts.clone(),
                    trust,
                };
                tokio::select! {
                    () = self.stop.cancelled() => Err(End::Told),
                    () = self.signals.shutdown.cancelled() => Err(shut_down(&self.signals)),
                    started = self.launch.start(spec) => started
                        .map(|pair| (pair, enforcing))
                        .map_err(|error| {
                            tracing::warn!(%pod_uid, %pod_name, %peer, %error, "an egress pair did not start");
                            End::Lost
                        }),
                }
            }
        };
        let end = match started {
            Ok((mut pair, enforcing)) => {
                let end = Session {
                    pod_uid,
                    pair: &mut pair,
                    enforcing,
                    changes,
                    events: &events,
                    stop: &self.stop,
                    signals: &self.signals,
                    draining: false,
                }
                .run()
                .await;
                // The pair goes first, so a failed check is reported for a
                // sandbox that already has no egress.
                pair.end().await;
                end
            }
            Err(end) => end,
        };
        let draining = self.signals.drain.is_cancelled();
        report_end(end, draining, pod_uid, &pod_name, &events).await
    }
}

/// Tells the reporter how a stream ended, once its pair is gone.
async fn report_end(
    end: End,
    draining: bool,
    pod_uid: Uuid,
    pod_name: &str,
    events: &PodEvents,
) -> Outcome {
    let outcome = match end {
        End::ReporterGone => return Outcome::Other,
        End::Failed(code) => {
            tracing::warn!(%pod_uid, %pod_name, code = code.code(), "an egress pair failed closed");
            events.send(PodEvent::FailedClosed(code)).await;
            Outcome::Other
        }
        End::Moved => {
            tracing::info!(%pod_uid, %pod_name, "a draining cw-egress ended an idle Pod's pair");
            Outcome::MovedIdle
        }
        End::Cut => {
            tracing::info!(%pod_uid, %pod_name, "a draining cw-egress cut a Pod's pair at its deadline");
            Outcome::CutAtDeadline
        }
        End::Told | End::Pair | End::Lost => Outcome::Other,
    };
    // However a pair ends in a drain, its guest redials onto another
    // cw-egress. Nothing is listening when the reporter is gone.
    events.send(PodEvent::Ended { moved: draining }).await;
    outcome
}

impl<P: Pair> Session<'_, P> {
    async fn run(mut self) -> End {
        if let Err(end) = self.self_check().await {
            return end;
        }
        loop {
            let step = tokio::select! {
                () = self.stop.cancelled() => Err(End::Told),
                () = self.signals.shutdown.cancelled() => Err(shut_down(self.signals)),
                () = self.signals.drain.cancelled(), if !self.draining => self.start_draining().await,
                changed = self.changes.changed() => match changed {
                    Ok(()) => self.apply_latest().await,
                    Err(_) => Err(End::Told),
                },
                status = self.pair.status() => self.on_status(status),
            };
            if let Err(end) = step {
                return end;
            }
        }
    }

    /// Reports the first assignment enforced, only once the guest's
    /// self-check has passed, then applies whatever changed meanwhile.
    async fn self_check(&mut self) -> Result<(), End> {
        let checked = tokio::select! {
            () = self.stop.cancelled() => return Err(End::Told),
            () = self.signals.shutdown.cancelled() => return Err(shut_down(self.signals)),
            checked = tokio::time::timeout(SELF_CHECK_TIMEOUT, self.pair.status()) => checked,
        };
        let reason = match checked {
            Ok(PairStatus::SelfCheckPassed) => None,
            Ok(PairStatus::SelfCheckFailed(probe)) => Some(probe.code()),
            // A guest that cannot finish its check sends no result and drops
            // the stream, so an end here is a failed check, not a disconnect.
            Ok(PairStatus::Ended) | Err(_) => Some("no_result"),
            Ok(status @ PairStatus::NoFlow) => return self.on_status(status),
        };
        if let Some(reason) = reason {
            tracing::warn!(pod_uid = %self.pod_uid, reason, "a guest's egress self-check did not pass");
            return Err(End::Failed(FailureCode::SelfCheckFailed));
        }
        self.report().await?;
        self.apply_latest().await
    }

    // `&mut self`: a shared borrow held across the send would need the pair
    // to be `Sync`.
    async fn report(&mut self) -> Result<(), End> {
        if self.events.send(self.enforcing.event()).await {
            Ok(())
        } else {
            Err(End::ReporterGone)
        }
    }

    async fn apply_latest(&mut self) -> Result<(), End> {
        let latest = self.changes.borrow_and_update().clone();
        let next = match latest {
            // Logged where it was decided.
            Ok(assignment) => Enforcing::of(assignment, self.pod_uid).map_err(|_| End::Lost)?,
            Err(_) => return Err(End::Failed(FailureCode::PolicyDigestMismatch)),
        };
        match self.enforcing.change_to(&next) {
            Change::None => return Ok(()),
            Change::End => return Err(End::Told),
            Change::Report => {}
            Change::Replace => {
                let enforced = self
                    .pair
                    .replace(&next.policy)
                    .await
                    .map_err(|error| {
                        tracing::warn!(pod_uid = %self.pod_uid, %error, "an egress pair did not take its new policy");
                        End::Lost
                    })?;
                if enforced != next.policy.digest() {
                    tracing::warn!(pod_uid = %self.pod_uid, "an egress broker acknowledged another policy than the one it was sent");
                    return Err(End::Lost);
                }
            }
        }
        self.enforcing = next;
        self.report().await
    }

    async fn start_draining(&mut self) -> Result<(), End> {
        self.draining = true;
        self.pair.request_drain().await.map_err(|error| {
            tracing::warn!(pod_uid = %self.pod_uid, %error, "an egress pair did not take a drain request");
            End::Lost
        })
    }

    fn on_status(&self, status: PairStatus) -> Result<(), End> {
        match status {
            PairStatus::Ended => Err(End::Pair),
            PairStatus::NoFlow if self.draining => Err(End::Moved),
            PairStatus::NoFlow | PairStatus::SelfCheckPassed | PairStatus::SelfCheckFailed(_) => {
                tracing::warn!(pod_uid = %self.pod_uid, ?status, "an egress worker sent a status out of turn");
                Err(End::Lost)
            }
        }
    }
}
