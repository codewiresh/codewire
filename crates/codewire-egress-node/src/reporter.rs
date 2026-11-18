//! cw-egress's reporter (#4000): one ordered path per Pod for everything
//! orchestration hears about it.
//!
//! Each admitted stream gets its own [`PodEvents`] and an admission number.
//! A Pod's events from an older admission than its newest are dropped, so a
//! replaced pair's end never lands after its successor's `ENFORCED`. Every
//! call is made by the one reporting task, in order, so one Pod's reports are
//! serial, as orchestration's last-write-wins store assumes.
//!
//! Every live Pod's last state is reported again every [`REFRESH`], idle or
//! not: orchestration reads a report older than 15 minutes as not enforced
//! and sweeps an unbound Pod's row after 30, so the refresh stays well inside
//! both.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use codewire_proto::codewire::internal::v1::EgressRecord as WireRecord;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::admitted::{PodEvent, PodEvents};
use crate::orchestration::{CallError, Enforcement, Orchestration, RECORDS_PER_CALL, wire_record};

/// How often every live Pod's last state is reported again.
pub const REFRESH: Duration = Duration::from_secs(5 * 60);
/// How often a Pod's waiting records are sent.
pub const FLUSH: Duration = Duration::from_secs(5);
/// The most records one Pod keeps waiting; older ones are dropped first.
const RECORDS_WAITING: usize = 4 * RECORDS_PER_CALL;
/// One admitted stream's events in flight to the reporting task.
const EVENTS_PER_ADMISSION: usize = 64;

/// Where the reporter's calls go: orchestration, or a test's record of them.
pub trait Reports: Send + Sync + 'static {
    fn enforcement(
        &self,
        pod_uid: &str,
        pod_name: &str,
        enforcement: &Enforcement,
    ) -> impl Future<Output = Result<(), CallError>> + Send;

    fn records(
        &self,
        pod_uid: &str,
        pod_name: &str,
        records: Vec<WireRecord>,
    ) -> impl Future<Output = Result<(), CallError>> + Send;
}

impl Reports for Orchestration {
    fn enforcement(
        &self,
        pod_uid: &str,
        pod_name: &str,
        enforcement: &Enforcement,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        self.report_enforcement(pod_uid, pod_name, enforcement)
    }

    fn records(
        &self,
        pod_uid: &str,
        pod_name: &str,
        records: Vec<WireRecord>,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        self.report_records(pod_uid, pod_name, records)
    }
}

enum Message {
    Admitted {
        pod: Uuid,
        name: String,
        admission: u64,
    },
    Event {
        pod: Uuid,
        admission: u64,
        event: PodEvent,
    },
}

/// Hands out each admitted stream's [`PodEvents`].
#[derive(Clone)]
pub struct Reporter {
    messages: mpsc::UnboundedSender<Message>,
    next_admission: Arc<AtomicU64>,
}

impl Reporter {
    /// Starts the reporting task. It ends once every [`Reporter`] and every
    /// [`PodEvents`] it handed out are gone.
    pub fn start<R: Reports>(sink: Arc<R>) -> (Self, tokio::task::JoinHandle<()>) {
        let (messages, inbox) = mpsc::unbounded_channel();
        let task = tokio::spawn(report(sink, inbox));
        let reporter = Self {
            messages,
            next_admission: Arc::new(AtomicU64::new(1)),
        };
        (reporter, task)
    }

    /// The events channel for one newly admitted stream of `pod`.
    pub fn admit(&self, pod: Uuid, name: String) -> PodEvents {
        let admission = self.next_admission.fetch_add(1, Ordering::Relaxed);
        // The task is gone only once nothing reports any more.
        let _ = self.messages.send(Message::Admitted {
            pod,
            name,
            admission,
        });
        let (sender, mut events) = mpsc::channel(EVENTS_PER_ADMISSION);
        let messages = self.messages.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let message = Message::Event {
                    pod,
                    admission,
                    event,
                };
                if messages.send(message).is_err() {
                    return;
                }
            }
        });
        PodEvents::new(sender)
    }
}

struct PodState {
    name: String,
    admission: u64,
    last: Option<Enforcement>,
    records: Vec<WireRecord>,
}

async fn report<R: Reports>(sink: Arc<R>, mut inbox: mpsc::UnboundedReceiver<Message>) {
    let mut pods: HashMap<Uuid, PodState> = HashMap::new();
    let mut refresh = tokio::time::interval(REFRESH);
    let mut flush = tokio::time::interval(FLUSH);
    loop {
        tokio::select! {
            message = inbox.recv() => {
                let Some(message) = message else { break };
                handle(&*sink, &mut pods, message).await;
            }
            _ = flush.tick() => {
                for (pod, state) in &mut pods {
                    send_records(&*sink, pod, state).await;
                }
            }
            _ = refresh.tick() => {
                for (pod, state) in &pods {
                    if let Some(last) = &state.last {
                        send_enforcement(&*sink, pod, &state.name, last).await;
                    }
                }
            }
        }
    }
    for (pod, state) in &mut pods {
        send_records(&*sink, pod, state).await;
    }
}

async fn handle<R: Reports>(sink: &R, pods: &mut HashMap<Uuid, PodState>, message: Message) {
    match message {
        Message::Admitted {
            pod,
            name,
            admission,
        } => {
            let state = pods.entry(pod).or_insert_with(|| PodState {
                name: name.clone(),
                admission,
                last: None,
                records: Vec::new(),
            });
            if admission >= state.admission {
                // The newer stream reports for itself; the older pair's last
                // state is not this one's.
                state.name = name;
                state.admission = admission;
                state.last = None;
            }
        }
        Message::Event {
            pod,
            admission,
            event,
        } => {
            let Some(state) = pods.get_mut(&pod) else {
                return;
            };
            if admission < state.admission {
                // A replaced pair's event: its successor speaks for the Pod.
                return;
            }
            match event {
                PodEvent::Enforced { revision, digest } => {
                    let enforced = Enforcement::Enforced { revision, digest };
                    send_enforcement(sink, &pod, &state.name, &enforced).await;
                    state.last = Some(enforced);
                }
                PodEvent::FailedClosed(code) => {
                    let failed = Enforcement::FailedClosed {
                        detail: code.code(),
                    };
                    send_enforcement(sink, &pod, &state.name, &failed).await;
                    state.last = Some(failed);
                }
                PodEvent::Records(records) => {
                    let wire: Vec<WireRecord> = records.iter().filter_map(wire_record).collect();
                    let refused = records.len() - wire.len();
                    if refused > 0 {
                        tracing::warn!(pod = %pod, refused, "egress records orchestration would refuse were not sent");
                    }
                    state.records.extend(wire);
                    let over = state.records.len().saturating_sub(RECORDS_WAITING);
                    if over > 0 {
                        state.records.drain(..over);
                        tracing::warn!(pod = %pod, dropped = over, "egress records dropped while orchestration was not taking them");
                    }
                }
                PodEvent::Ended { moved } => {
                    let Some(mut state) = pods.remove(&pod) else {
                        return;
                    };
                    send_records(sink, &pod, &mut state).await;
                    // A failed check stays the Pod's state, and a moved Pod is
                    // another cw-egress's to report.
                    let failed = matches!(state.last, Some(Enforcement::FailedClosed { .. }));
                    if !moved && !failed {
                        send_enforcement(sink, &pod, &state.name, &Enforcement::Disconnected).await;
                    }
                }
            }
        }
    }
}

async fn send_enforcement<R: Reports>(sink: &R, pod: &Uuid, name: &str, enforcement: &Enforcement) {
    if let Err(error) = sink.enforcement(&pod.to_string(), name, enforcement).await {
        // The next change or refresh reports it again.
        tracing::warn!(pod = %pod, %error, "reporting enforcement to orchestration failed");
    }
}

async fn send_records<R: Reports>(sink: &R, pod: &Uuid, state: &mut PodState) {
    while !state.records.is_empty() {
        let batch: Vec<WireRecord> = state
            .records
            .drain(..state.records.len().min(RECORDS_PER_CALL))
            .collect();
        if let Err(error) = sink.records(&pod.to_string(), &state.name, batch).await {
            tracing::warn!(pod = %pod, %error, "reporting egress records to orchestration failed");
            return;
        }
    }
}

#[cfg(test)]
mod tests;
