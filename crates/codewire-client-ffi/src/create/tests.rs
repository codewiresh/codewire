use codewire_client::environment_setup::{EnvironmentLogFeed, LogFeedConnection, LogFeedEvent};
use tokio::sync::mpsc;

use super::*;

/// Records the steps, and the daemon wait as a step named `daemon`.
#[derive(Default)]
struct Recorder {
    steps: Mutex<Vec<SetupStep>>,
}

impl SetupStepObserver for Recorder {
    fn step(&self, step: SetupStep) {
        self.steps.lock().unwrap().push(step);
    }

    fn daemon_waiting(&self) {
        self.steps.lock().unwrap().push(SetupStep {
            phase: "daemon".into(),
            status: StepStatus::Started,
            label: String::new(),
            created_at: String::new(),
        });
    }

    fn reconnecting(&self, _reason: String, _attempt: u32, _max_reconnects: u32) {}

    fn finished(&self, _outcome: SetupOutcome) {}
}

/// One connection that delivers `rows` and then stays open.
struct Rows {
    rows: Vec<EnvironmentLogRow>,
    open: Mutex<Vec<mpsc::UnboundedSender<LogFeedEvent>>>,
}

impl EnvironmentLogFeed for Rows {
    fn open(&self, _after_log_id: Option<String>) -> LogFeedConnection {
        let (sender, events) = mpsc::unbounded_channel();
        for row in &self.rows {
            sender.send(LogFeedEvent::Log(row.clone())).unwrap();
        }
        self.open.lock().unwrap().push(sender);
        LogFeedConnection::new(events, None)
    }
}

fn row(id: &str, phase: &str, status: &str, message: &str) -> EnvironmentLogRow {
    EnvironmentLogRow {
        id: id.into(),
        environment_id: "env".into(),
        phase: phase.into(),
        status: status.into(),
        message: message.into(),
        metadata: None,
        created_at: "2026-11-15T12:00:00Z".into(),
    }
}

/// Follows `rows` with a daemon that is ready at once, and a guard that
/// stops setup with `stop` after 20 ms, or never.
async fn follow(
    rows: Vec<EnvironmentLogRow>,
    stop: Option<&str>,
) -> (SetupOutcome, Vec<SetupStep>) {
    let recorder = Recorder::default();
    let guard = async {
        match stop {
            Some(message) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                message.to_owned()
            }
            None => std::future::pending().await,
        }
    };
    let ended = await_setup(
        &Rows {
            rows,
            open: Mutex::default(),
        },
        &mut StepRelay(&recorder),
        &FollowPolicy::default(),
        guard,
        || async { Ok::<_, DaemonWaitError>(()) },
    )
    .await;
    (outcome(ended), recorder.steps.into_inner().unwrap())
}

fn phases(steps: &[SetupStep]) -> Vec<&str> {
    steps.iter().map(|step| step.phase.as_str()).collect()
}

#[test]
fn each_status_keeps_its_meaning_and_an_unknown_one_is_kept() {
    let status = |status| setup_step(&row("1", "clone", status, "Cloning")).status;
    assert_eq!(status("started"), StepStatus::Started);
    assert_eq!(status("completed"), StepStatus::Completed);
    assert_eq!(status("failed"), StepStatus::Failed);
    assert_eq!(status("skipped"), StepStatus::Skipped);
    assert_eq!(
        status("paused"),
        StepStatus::Other {
            status: "paused".into()
        }
    );
}

#[test]
fn a_label_is_one_trimmed_line_of_at_most_300_characters() {
    assert_eq!(
        label("  Cloning\nrepo\tone \u{1b}[0m "),
        "Cloning repo one  [0m"
    );
    assert_eq!(label(&"é".repeat(400)).chars().count(), 300);
}

#[tokio::test]
async fn ready_follows_every_step_and_the_daemon_wait() {
    let (outcome, steps) = follow(
        vec![
            row("1", "clone", "started", "Cloning"),
            row("2", "clone", "completed", "Cloned"),
            row("3", "complete", "completed", "Ready"),
        ],
        None,
    )
    .await;
    assert_eq!(outcome, SetupOutcome::Ready);
    assert_eq!(phases(&steps), ["clone", "clone", "complete", "daemon"]);
}

#[tokio::test]
async fn a_setup_that_stops_without_a_failed_row_fails_with_the_reason() {
    let (outcome, steps) = follow(
        vec![row("1", "configure", "started", "Configuring")],
        Some("Setup failed: sync workspace env: timed out"),
    )
    .await;
    assert_eq!(
        outcome,
        SetupOutcome::Failed {
            message: "Setup failed: sync workspace env: timed out".into(),
            step: None,
        }
    );
    assert_eq!(phases(&steps), ["configure"], "no daemon wait after a stop");
}

#[test]
fn a_stop_says_why_in_one_sentence() {
    let facts = EnvironmentFacts {
        state: "stopped".into(),
        error_reason: Some("quota\nreached".into()),
        ..Default::default()
    };
    assert_eq!(
        stop_message(&facts, SetupStop::Left),
        "The environment became stopped before setup finished: quota reached"
    );
    let ended = EnvironmentFacts::default();
    assert_eq!(
        stop_message(&ended, SetupStop::PlatformEnded(PlatformEnd::NoCapacity)),
        "No capacity right now. Try again shortly."
    );
}

#[test]
fn a_target_s_debug_never_shows_its_token() {
    let target = OrgTarget {
        server_url: "https://codewire.invalid".into(),
        access_token: "synthetic-secret".into(),
        org_id: "org".into(),
    };
    assert!(!format!("{target:?}").contains("synthetic-secret"));
}

#[tokio::test]
async fn a_failed_row_ends_the_setup_at_that_step() {
    let failed = row("2", "install", "failed", "npm install exited 1");
    let (outcome, steps) = follow(
        vec![
            row("1", "install", "started", "Installing"),
            failed.clone(),
            row("3", "complete", "completed", "Ready"),
        ],
        None,
    )
    .await;
    assert_eq!(
        outcome,
        SetupOutcome::Failed {
            message: "npm install exited 1".into(),
            step: Some(setup_step(&failed)),
        }
    );
    assert_eq!(steps.len(), 2, "nothing after the failed row is shown");
}

#[test]
fn a_create_needs_an_organization_and_a_follow_an_environment() {
    let target = OrgTarget {
        server_url: "https://codewire.invalid".into(),
        access_token: "synthetic-token".into(),
        org_id: " ".into(),
    };
    assert!(matches!(
        client_for(&target),
        Err(ShellError::Invalid { message }) if message == "the organization is empty"
    ));
    let target = OrgTarget {
        org_id: "org".into(),
        ..target
    };
    assert!(matches!(
        EnvironmentSetup::follow(target, String::new(), Arc::new(Recorder::default())),
        Err(ShellError::Invalid { message }) if message == "the environment is empty"
    ));
}

#[test]
fn an_empty_name_or_preset_is_left_to_the_server() {
    assert_eq!(non_empty(Some("  ".into())), None);
    assert_eq!(non_empty(None), None);
    assert_eq!(non_empty(Some(" api ".into())), Some("api".into()));
}
