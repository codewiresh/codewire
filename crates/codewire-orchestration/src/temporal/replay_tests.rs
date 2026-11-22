//! Replays of synthetic `EnvironmentWorkflow` histories shaped like one that
//! ran before runs continued as new (#5856): a create, then reconcile after
//! reconcile. The shapes and payloads follow a recorded Dev history; every
//! identifier here is synthetic.

use std::sync::{Arc, Mutex};

use futures::stream;
use temporalio_client::ClientOptions;
use temporalio_common::protos::coresdk::workflow_activation::{
    WorkflowActivation, remove_from_cache::EvictionReason, workflow_activation_job,
};
use temporalio_common::protos::coresdk::workflow_commands::workflow_command::Variant;
use temporalio_common::protos::coresdk::workflow_completion::{
    WorkflowActivationCompletion, workflow_activation_completion,
};
use temporalio_common::protos::temporal::api::common::v1::{
    ActivityType, Payload, Payloads, SearchAttributes, WorkflowType,
};
use temporalio_common::protos::temporal::api::enums::v1::EventType;
use temporalio_common::protos::temporal::api::history::v1::{
    ActivityTaskCompletedEventAttributes, ActivityTaskScheduledEventAttributes,
    ActivityTaskStartedEventAttributes, History, HistoryEvent, MarkerRecordedEventAttributes,
    UpsertWorkflowSearchAttributesEventAttributes, WorkflowExecutionSignaledEventAttributes,
    WorkflowExecutionStartedEventAttributes, WorkflowTaskCompletedEventAttributes,
    WorkflowTaskScheduledEventAttributes, WorkflowTaskStartedEventAttributes,
    history_event::Attributes,
};
use temporalio_common::protos::temporal::api::sdk::v1::WorkflowTaskCompletedMetadata;
use temporalio_common::protos::temporal::api::taskqueue::v1::TaskQueue;
use temporalio_sdk::interceptors::WorkerInterceptor;
use temporalio_sdk::{Worker, WorkerOptions};
use temporalio_sdk_core::init_replay_worker;
use temporalio_sdk_core::replay::{HistoryForReplay, ReplayWorkerInput};

use super::continuation::HISTORY_EVENTS;
use super::{CLAIM_WITH_CREATE_PATCH, EnvironmentWorkflow};

const ENVIRONMENT: &str = "00000000-0000-4000-8000-000000005856";
const QUEUE: &str = "codewire-lifecycle";

fn json(value: serde_json::Value) -> Payloads {
    Payloads {
        payloads: vec![Payload {
            metadata: [("encoding".to_owned(), b"json/plain".to_vec())].into(),
            data: serde_json::to_vec(&value).unwrap(),
            ..Default::default()
        }],
    }
}

fn queue() -> Option<TaskQueue> {
    Some(TaskQueue {
        name: QUEUE.to_owned(),
        ..Default::default()
    })
}

/// A history in the shape a run recorded before it could continue as new.
#[derive(Default)]
struct Recorded {
    events: Vec<HistoryEvent>,
    activities: u32,
}

impl Recorded {
    fn next_id(&self) -> i64 {
        self.events.len() as i64 + 1
    }

    fn push(&mut self, event_type: EventType, attributes: Attributes) -> i64 {
        let event_id = self.next_id();
        let mut event = HistoryEvent {
            event_id,
            event_type: event_type as i32,
            attributes: Some(attributes),
            event_time: Some(Default::default()),
            ..Default::default()
        };
        // Core requires a time on every task; a second per event keeps them ordered.
        if let Some(time) = event.event_time.as_mut() {
            time.seconds = 1_763_000_000 + event_id;
        }
        self.events.push(event);
        event_id
    }

    fn started(&mut self) {
        self.push(
            EventType::WorkflowExecutionStarted,
            Attributes::WorkflowExecutionStartedEventAttributes(
                WorkflowExecutionStartedEventAttributes {
                    workflow_type: Some(WorkflowType {
                        name: "EnvironmentWorkflow".to_owned(),
                    }),
                    task_queue: queue(),
                    input: Some(json(serde_json::json!({
                        "action": "", "environment_id": "", "requested_by": ""
                    }))),
                    attempt: 1,
                    workflow_id: format!("environment/{ENVIRONMENT}"),
                    ..Default::default()
                },
            ),
        );
    }

    fn signal(&mut self, action: &str) {
        self.push(
            EventType::WorkflowExecutionSignaled,
            Attributes::WorkflowExecutionSignaledEventAttributes(
                WorkflowExecutionSignaledEventAttributes {
                    signal_name: "environment.command".to_owned(),
                    input: Some(json(serde_json::json!({
                        "action": action, "environment_id": ENVIRONMENT, "requested_by": ""
                    }))),
                    ..Default::default()
                },
            ),
        );
    }

    /// A workflow task scheduled and started; `completed` also completes it.
    fn task(&mut self, completed: bool, first: bool) -> i64 {
        let scheduled = self.push(
            EventType::WorkflowTaskScheduled,
            Attributes::WorkflowTaskScheduledEventAttributes(
                WorkflowTaskScheduledEventAttributes {
                    task_queue: queue(),
                    attempt: 1,
                    ..Default::default()
                },
            ),
        );
        let started = self.push(
            EventType::WorkflowTaskStarted,
            Attributes::WorkflowTaskStartedEventAttributes(WorkflowTaskStartedEventAttributes {
                scheduled_event_id: scheduled,
                ..Default::default()
            }),
        );
        if !completed {
            return started;
        }
        self.push(
            EventType::WorkflowTaskCompleted,
            Attributes::WorkflowTaskCompletedEventAttributes(
                WorkflowTaskCompletedEventAttributes {
                    scheduled_event_id: scheduled,
                    started_event_id: started,
                    sdk_metadata: first.then(|| WorkflowTaskCompletedMetadata {
                        core_used_flags: vec![2, 3, 1],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        )
    }

    fn patch_marker(&mut self, completed: i64) {
        self.push(
            EventType::MarkerRecorded,
            Attributes::MarkerRecordedEventAttributes(MarkerRecordedEventAttributes {
                marker_name: "core_patch".to_owned(),
                details: [(
                    "patch-data".to_owned(),
                    json(serde_json::json!({"id": CLAIM_WITH_CREATE_PATCH, "deprecated": false})),
                )]
                .into(),
                workflow_task_completed_event_id: completed,
                ..Default::default()
            }),
        );
        let change_version = json(serde_json::json!([CLAIM_WITH_CREATE_PATCH]))
            .payloads
            .remove(0);
        let mut change_version = change_version;
        change_version
            .metadata
            .insert("type".to_owned(), b"KeywordList".to_vec());
        self.push(
            EventType::UpsertWorkflowSearchAttributes,
            Attributes::UpsertWorkflowSearchAttributesEventAttributes(
                UpsertWorkflowSearchAttributesEventAttributes {
                    workflow_task_completed_event_id: completed,
                    search_attributes: Some(SearchAttributes {
                        indexed_fields: [("TemporalChangeVersion".to_owned(), change_version)]
                            .into(),
                    }),
                },
            ),
        );
    }

    fn activity(&mut self, name: &str, completed: i64, result: serde_json::Value) {
        self.activities += 1;
        let scheduled = self.push(
            EventType::ActivityTaskScheduled,
            Attributes::ActivityTaskScheduledEventAttributes(
                ActivityTaskScheduledEventAttributes {
                    activity_id: self.activities.to_string(),
                    activity_type: Some(ActivityType {
                        name: name.to_owned(),
                    }),
                    task_queue: queue(),
                    workflow_task_completed_event_id: completed,
                    ..Default::default()
                },
            ),
        );
        let started = self.push(
            EventType::ActivityTaskStarted,
            Attributes::ActivityTaskStartedEventAttributes(ActivityTaskStartedEventAttributes {
                scheduled_event_id: scheduled,
                attempt: 1,
                ..Default::default()
            }),
        );
        self.push(
            EventType::ActivityTaskCompleted,
            Attributes::ActivityTaskCompletedEventAttributes(
                ActivityTaskCompletedEventAttributes {
                    result: Some(json(result)),
                    scheduled_event_id: scheduled,
                    started_event_id: started,
                    ..Default::default()
                },
            ),
        );
    }

    /// A create, then reconciles until the history has at least `events`
    /// events. `live` leaves the task after the last reconcile started, as a
    /// worker without the run cached receives it; otherwise the history ends
    /// on a completed task.
    fn reconciled(events: usize, live: bool) -> History {
        let mut recorded = Recorded::default();
        recorded.started();
        recorded.signal("create");
        let completed = recorded.task(true, true);
        recorded.patch_marker(completed);
        recorded.activity(
            "EnvironmentClaimAndCreateActivity",
            completed,
            serde_json::json!({"operation_generation": 1, "setup_completed": false}),
        );
        let completed = recorded.task(true, false);
        recorded.activity(
            "EnvironmentSetupActivity",
            completed,
            serde_json::Value::Null,
        );
        recorded.task(true, false);
        while recorded.events.len() < events {
            recorded.signal("reconcile");
            let completed = recorded.task(true, false);
            recorded.activity(
                "EnvironmentReconcileActivity",
                completed,
                serde_json::json!("Continue"),
            );
            recorded.task(true, false);
        }
        if live {
            // The last task, completed above, becomes the one just received.
            recorded.events.pop();
        }
        History {
            events: recorded.events,
        }
    }
}

/// Every command the workflow sent, and every completion core refused.
#[derive(Clone, Default)]
struct Commands(Arc<Mutex<(Vec<Variant>, Vec<String>)>>);

#[async_trait::async_trait(?Send)]
impl WorkerInterceptor for Commands {
    async fn on_workflow_activation(&self, activation: &WorkflowActivation) -> anyhow::Result<()> {
        // A replay core cannot follow arrives as an eviction, not a failure;
        // the replay worker itself evicts each run once it is done.
        let evictions = activation.jobs.iter().filter_map(|job| match &job.variant {
            Some(workflow_activation_job::Variant::RemoveFromCache(evicted))
                if evicted.reason() != EvictionReason::LangRequested =>
            {
                Some(format!("{:?}: {}", evicted.reason(), evicted.message))
            }
            _ => None,
        });
        self.0.lock().unwrap().1.extend(evictions);
        Ok(())
    }

    async fn on_workflow_activation_completion(&self, completion: &WorkflowActivationCompletion) {
        let mut seen = self.0.lock().unwrap();
        match &completion.status {
            Some(workflow_activation_completion::Status::Successful(success)) => seen
                .0
                .extend(success.commands.iter().filter_map(|c| c.variant.clone())),
            Some(workflow_activation_completion::Status::Failed(failure)) => {
                seen.1.push(format!("{failure:?}"))
            }
            None => {}
        }
    }
}

async fn replay(history: History) -> (Vec<Variant>, Vec<String>) {
    let commands = Commands::default();
    let options = WorkerOptions::new(QUEUE)
        .register_workflow::<EnvironmentWorkflow>()
        .unwrap()
        .worker_interceptor(commands.clone())
        .build();
    let core_options = options
        .to_core_options("default".to_owned(), String::new(), &Default::default())
        .unwrap();
    let histories = stream::once(async move {
        HistoryForReplay::new(history, format!("environment/{ENVIRONMENT}"))
    });
    let core = init_replay_worker(ReplayWorkerInput::new(core_options, histories)).unwrap();
    Worker::new_from_core_options(
        Arc::new(core),
        ClientOptions::new("default").build(),
        options,
    )
    .unwrap()
    .run()
    .await
    .unwrap();
    let seen = commands.0.lock().unwrap();
    (seen.0.clone(), seen.1.clone())
}

fn reconciles(commands: &[Variant]) -> usize {
    commands
        .iter()
        .filter(|command| {
            matches!(command, Variant::ScheduleActivity(a) if a.activity_type == "EnvironmentReconcileActivity")
        })
        .count()
}

fn continued(commands: &[Variant]) -> bool {
    commands
        .iter()
        .any(|command| matches!(command, Variant::ContinueAsNewWorkflowExecution(_)))
}

/// A run recorded before continue-as-new existed replays unchanged, past the
/// bound: replay never decides to continue.
#[tokio::test(flavor = "current_thread")]
async fn a_long_history_from_before_the_bound_replays_without_continuing() {
    let (commands, failures) =
        replay(Recorded::reconciled(HISTORY_EVENTS as usize * 2, false)).await;
    assert!(failures.is_empty(), "replay failed: {failures:?}");
    assert!(
        reconciles(&commands) > 300,
        "the replay ran the recorded reconciles"
    );
    assert!(!continued(&commands));
}

/// The same run, once its last reconcile has finished on the live path,
/// continues as new with no command of its own.
#[tokio::test(flavor = "current_thread")]
async fn a_long_run_continues_as_new_once_its_command_finishes() {
    let (commands, failures) =
        replay(Recorded::reconciled(HISTORY_EVENTS as usize * 2, true)).await;
    assert!(failures.is_empty(), "replay failed: {failures:?}");
    let Some(Variant::ContinueAsNewWorkflowExecution(next)) = commands.last() else {
        panic!("the run's last command continues it: {:?}", commands.last());
    };
    let input: serde_json::Value = serde_json::from_slice(&next.arguments[0].data).unwrap();
    assert_eq!(input["action"], "", "the new run starts with no command");
}

/// A continued run's first command is the claim activity, before any work:
/// the claim decides its generation, keeping the predecessor's when Temporal
/// reports it continued as new (#5950;
/// `activity_authority::tests::a_continued_run_takes_over_its_predecessors_generation_once`).
#[tokio::test(flavor = "current_thread")]
async fn a_continued_runs_first_command_is_the_claim() {
    let mut recorded = Recorded::default();
    recorded.started();
    recorded.signal("reconcile");
    recorded.task(false, false);
    let (commands, failures) = replay(History {
        events: recorded.events,
    })
    .await;
    assert!(failures.is_empty(), "replay failed: {failures:?}");
    let Some(Variant::ScheduleActivity(first)) = commands.first() else {
        panic!("the first command schedules an activity: {commands:?}");
    };
    assert_eq!(first.activity_type, "EnvironmentClaimAuthorityActivity");
}

/// A run below the bound keeps running.
#[tokio::test(flavor = "current_thread")]
async fn a_short_run_does_not_continue() {
    let (commands, failures) = replay(Recorded::reconciled(200, true)).await;
    assert!(failures.is_empty(), "replay failed: {failures:?}");
    assert!(
        reconciles(&commands) > 10,
        "the replay ran the recorded reconciles"
    );
    assert!(!continued(&commands));
}
