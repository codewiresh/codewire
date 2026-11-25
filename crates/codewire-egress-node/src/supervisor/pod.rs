//! One admitted stream's pair, from its start to its reaping.

use std::sync::Arc;

use codewire_egress_broker::refusals::RefusalBatch;
use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy};
use codewire_egress_worker::broker_control::now_unix_ms;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::refusals::{self, SentPolicies};
use super::{Launch, Pair, PairSpec, PairStatus, SELF_CHECK_TIMEOUT, Signals};
use crate::admitted::{AdmittedStream, FailureCode, PodEvent, PodEvents};
use crate::interception::{Interception, InterceptionRefusal, PairIntercepts};
use crate::leaves::{IssuedLeaves, LeafSigner, Renewal, Settled};
use crate::orchestration::{Assignment, AssignmentError, CallError};

pub(super) struct Pod<L, S> {
    pub(super) launch: Arc<L>,
    pub(super) signer: Arc<S>,
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
    /// The policy's reference, for a bound Pod: refusals are labelled with it.
    reference: Option<String>,
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
                reference: None,
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
                    reference: Some(policy.reference),
                    policy: policy.policy,
                    revision: policy.revision,
                    intercepts: interception.pair()?,
                })
            }
        }
    }

    /// Has `sent` label refusals under this policy from now on.
    fn sent_to(&self, sent: &mut SentPolicies) {
        let label = self
            .reference
            .as_deref()
            .map(|reference| (reference, self.revision));
        sent.sent(self.policy.digest(), label);
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
        } else if self.environment != next.environment
            || self.revision != next.revision
            || self.reference != next.reference
        {
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

struct Session<'a, P, S> {
    pod_uid: Uuid,
    /// The front door's leaves, for a pair with one. They end with it.
    leaves: Option<Renewal<S>>,
    pair: &'a mut P,
    enforcing: Enforcing,
    changes: watch::Receiver<Result<Assignment, AssignmentError>>,
    events: &'a PodEvents,
    stop: &'a CancellationToken,
    signals: &'a Signals,
    draining: bool,
    /// The broker's refusal reports, and what it was sent, to label them.
    reports: Option<mpsc::Receiver<RefusalBatch>>,
    sent: SentPolicies,
    lost: Lost,
}

/// Refusals this pair's reports did not carry to orchestration, since it
/// started. Each is logged with its running total, as cw-egress counts.
#[derive(Debug, Default)]
struct Lost {
    /// Rows the broker's fold dropped to stay within its bound.
    broker_rows: u64,
    /// Refusals under a policy an unbound warm member ran.
    unbound: u64,
    /// Refusals under a digest this supervisor never sent the broker.
    unknown: u64,
}

/// A shutdown during a drain is the drain's deadline.
fn shut_down(signals: &Signals) -> End {
    if signals.drain.is_cancelled() {
        End::Cut
    } else {
        End::Told
    }
}

impl<L: Launch, S: LeafSigner> Pod<L, S> {
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
                    pod_name: pod_name.clone(),
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
                let reports = pair.refusals();
                let mut sent = SentPolicies::default();
                enforcing.sent_to(&mut sent);
                let leaves = pair.front_door_key().map(|key| {
                    Renewal::new(
                        Arc::clone(&self.signer),
                        pod_uid.to_string(),
                        pod_name.clone(),
                        key.to_vec(),
                        unix_now(),
                    )
                });
                let end = Session {
                    pod_uid,
                    leaves,
                    pair: &mut pair,
                    enforcing,
                    changes,
                    events: &events,
                    stop: &self.stop,
                    signals: &self.signals,
                    draining: false,
                    reports,
                    sent,
                    lost: Lost::default(),
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
        End::Told | End::Pair | End::Lost => {
            // Neither moved idle nor cut: a drain names how, so a Pod whose
            // open connections ended early is found by its log (#6483).
            if draining {
                let how = match end {
                    End::Told => "told",
                    End::Pair => "its pair ended",
                    _ => "lost",
                };
                tracing::info!(%pod_uid, %pod_name, how, "a draining cw-egress ended a Pod's pair before it moved");
            }
            Outcome::Other
        }
    };
    // However a pair ends in a drain, its guest redials onto another
    // cw-egress. Nothing is listening when the reporter is gone.
    events.send(PodEvent::Ended { moved: draining }).await;
    outcome
}

impl<P: Pair, S: LeafSigner> Session<'_, P, S> {
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
                batch = next_report(&mut self.reports) => self.file_refusals(batch).await,
                asked = ask(self.leaves.as_ref()) => {
                    self.install(asked).await;
                    Ok(())
                }
            };
            if let Err(end) = step {
                return end;
            }
        }
    }

    /// Installs what an ask returned and schedules the next. Its outcome is
    /// logged as a count or an error code, never a certificate.
    async fn install(&mut self, asked: Result<IssuedLeaves, CallError>) {
        let Some(leaves) = self.leaves.as_mut() else {
            return;
        };
        let pair = &mut *self.pair;
        let pod_uid = self.pod_uid;
        match leaves
            .settle(asked, async |certificates: &[Vec<u8>]| {
                pair.install_leaves(certificates).await
            })
            .await
        {
            Settled::Installed(count) => {
                tracing::info!(%pod_uid, leaves = count, "a front door's leaves are installed");
            }
            Settled::Refused(error) => {
                tracing::warn!(%pod_uid, %error, "a front door kept its leaves; asking again");
            }
            Settled::Unanswered(error) => {
                tracing::warn!(%pod_uid, %error, "a front door's leaves were not signed; asking again");
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

    /// Sends the broker's report on as records, labelled with what it was
    /// sent. What it cannot carry is counted and logged.
    async fn file_refusals(&mut self, batch: RefusalBatch) -> Result<(), End> {
        let broker_rows = batch.dropped;
        let labelled = refusals::label(batch, &self.sent, now_unix_ms());
        if broker_rows > 0 || labelled.unbound > 0 || labelled.unknown > 0 {
            let lost = &mut self.lost;
            lost.broker_rows = lost.broker_rows.saturating_add(broker_rows);
            lost.unbound = lost.unbound.saturating_add(labelled.unbound);
            lost.unknown = lost.unknown.saturating_add(labelled.unknown);
            tracing::warn!(
                pod_uid = %self.pod_uid,
                broker_rows,
                unbound = labelled.unbound,
                unknown = labelled.unknown,
                total_broker_rows = lost.broker_rows,
                total_unbound = lost.unbound,
                total_unknown = lost.unknown,
                "egress refusals not reported: rows the broker dropped, or refused under no environment's policy or one never sent"
            );
        }
        if labelled.records.is_empty() {
            return Ok(());
        }
        if self.events.send(PodEvent::Records(labelled.records)).await {
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
        next.sent_to(&mut self.sent);
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

/// The broker's next refusal report; never, once its reports have ended,
/// which the pair's status says.
async fn next_report(reports: &mut Option<mpsc::Receiver<RefusalBatch>>) -> RefusalBatch {
    match reports.as_mut() {
        Some(reports) => match reports.recv().await {
            Some(batch) => batch,
            None => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}

/// The next ask of `leaves`; never, for a pair without a front door.
async fn ask<S: LeafSigner>(leaves: Option<&Renewal<S>>) -> Result<IssuedLeaves, CallError> {
    match leaves {
        Some(leaves) => leaves.ask().await,
        None => std::future::pending().await,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
