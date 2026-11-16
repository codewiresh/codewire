use std::cell::Cell;
use std::convert::Infallible;
use std::sync::Mutex;

use serde_json::json;
use tokio::sync::mpsc;

use super::*;
use crate::environment_setup::{LogFeedConnection, LogFeedEvent};

/// Records what it is shown and ends on a `failed` row.
#[derive(Default)]
struct Recorder {
    phases: Vec<String>,
    daemon: Vec<&'static str>,
}

impl SetupObserver for Recorder {
    type Failure = String;
    type Error = Infallible;

    fn row(&mut self, row: &EnvironmentLogRow, _: Instant) -> Result<Option<String>, Infallible> {
        self.phases.push(row.phase.clone());
        Ok((row.status == "failed").then(|| row.message.clone()))
    }

    fn interrupted(&mut self, _: &Interruption, _: u32, _: u32) -> Result<(), Infallible> {
        Ok(())
    }

    fn redraw(&mut self, _: Instant) -> Result<(), Infallible> {
        Ok(())
    }

    fn tick_interval(&self) -> Option<Duration> {
        None
    }
}

impl SetupWaitObserver for Recorder {
    fn daemon_waiting(&mut self, _: Instant) -> Result<(), Infallible> {
        self.daemon.push("waiting");
        Ok(())
    }

    fn daemon_ready(&mut self, _: Instant) -> Result<(), Infallible> {
        self.daemon.push("ready");
        Ok(())
    }
}

/// One connection that delivers `rows` and then stays open.
struct Rows {
    rows: Vec<EnvironmentLogRow>,
    open: Mutex<Vec<mpsc::UnboundedSender<LogFeedEvent>>>,
}

impl Rows {
    fn new(rows: Vec<EnvironmentLogRow>) -> Self {
        Self {
            rows,
            open: Mutex::default(),
        }
    }
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

/// The daemon wait, for a wait that must end before it.
fn not_asked() -> std::future::Ready<Result<(), Infallible>> {
    panic!("the daemon was asked")
}

fn row(id: &str, phase: &str, status: &str) -> EnvironmentLogRow {
    EnvironmentLogRow {
        id: id.into(),
        phase: phase.into(),
        status: status.into(),
        message: format!("{phase} {status}"),
        ..Default::default()
    }
}

fn daemon_row(id: &str, state: &str) -> EnvironmentLogRow {
    EnvironmentLogRow {
        metadata: Some(json!({ "state": state, "message": "from setup" })),
        ..row(id, "daemon_ready", "completed")
    }
}

#[tokio::test]
async fn ready_comes_only_once_the_daemon_is_ready_after_complete() {
    let feed = Rows::new(vec![
        row("1", "clone", "completed"),
        row("2", "complete", "completed"),
    ]);
    let mut recorder = Recorder::default();
    let asked = Cell::new(false);
    let ended = await_setup(
        &feed,
        &mut recorder,
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        || async {
            asked.set(true);
            Ok::<_, Infallible>(())
        },
    )
    .await
    .unwrap();

    assert_eq!(ended, SetupEnd::Ready);
    assert!(asked.get());
    assert_eq!(recorder.daemon, ["waiting", "ready"]);
}

#[tokio::test]
async fn a_daemon_that_never_becomes_ready_fails_the_wait() {
    let feed = Rows::new(vec![row("1", "complete", "completed")]);
    let mut recorder = Recorder::default();
    let ended = await_setup(
        &feed,
        &mut recorder,
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        || async { Err("unhealthy") },
    )
    .await;

    assert!(matches!(ended, Err(SetupWaitError::Daemon("unhealthy"))));
    assert_eq!(recorder.daemon, ["waiting"]);
}

#[tokio::test]
async fn the_guard_ends_a_setup_that_stops_without_a_failed_row() {
    let feed = Rows::new(vec![row("1", "configure_environment", "started")]);
    let mut recorder = Recorder::default();
    let guard = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        SetupStop::SetupError
    };
    let ended = await_setup(
        &feed,
        &mut recorder,
        &FollowPolicy::default(),
        guard,
        || async { Ok::<_, Infallible>(()) },
    )
    .await;

    assert!(matches!(
        ended,
        Err(SetupWaitError::Stopped(SetupStop::SetupError))
    ));
    assert!(recorder.daemon.is_empty(), "no daemon wait after a stop");
}

#[tokio::test]
async fn a_failed_row_ends_the_wait_without_asking_for_the_daemon() {
    let feed = Rows::new(vec![row("1", "git_clone", "failed")]);
    let mut recorder = Recorder::default();
    let ended = await_setup(
        &feed,
        &mut recorder,
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        not_asked,
    )
    .await
    .unwrap();

    assert_eq!(ended, SetupEnd::Failed::<String>("git_clone failed".into()));
}

#[tokio::test]
async fn setup_s_daemon_row_decides_when_it_says_ready_or_unusable() {
    let ready = Rows::new(vec![
        daemon_row("1", "ready"),
        row("2", "complete", "completed"),
    ]);
    let mut recorder = Recorder::default();
    let ended = await_setup(
        &ready,
        &mut recorder,
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        not_asked,
    )
    .await
    .unwrap();
    assert_eq!(ended, SetupEnd::Ready);
    assert!(recorder.daemon.is_empty());

    let unusable = Rows::new(vec![
        daemon_row("1", "upgrade_required"),
        row("2", "complete", "completed"),
    ]);
    let ended = await_setup(
        &unusable,
        &mut Recorder::default(),
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        not_asked,
    )
    .await;
    assert!(matches!(
        ended,
        Err(SetupWaitError::DaemonRow(DaemonReadyRow {
            state: DaemonState::UpgradeRequired,
            ..
        }))
    ));

    let starting = Rows::new(vec![
        daemon_row("1", "starting"),
        row("2", "complete", "completed"),
    ]);
    let mut recorder = Recorder::default();
    await_setup(
        &starting,
        &mut recorder,
        &FollowPolicy::default(),
        std::future::pending::<()>(),
        || async { Ok::<_, Infallible>(()) },
    )
    .await
    .unwrap();
    assert_eq!(recorder.daemon, ["waiting", "ready"]);
}

fn facts(state: &str, desired_state: &str) -> EnvironmentFacts {
    EnvironmentFacts {
        id: "env".into(),
        state: state.into(),
        desired_state: desired_state.into(),
        ..Default::default()
    }
}

#[test]
fn setup_stops_in_a_state_it_cannot_finish_from_or_on_a_recorded_error() {
    for state in ["creating", "starting", "running", "pending"] {
        assert_eq!(facts(state, "started").setup_stop(), None, "{state}");
    }
    for state in [
        "build_failed",
        "error",
        "failed",
        "stopping",
        "stopped",
        "destroying",
        "destroyed",
    ] {
        assert_eq!(
            facts(state, "started").setup_stop(),
            Some(SetupStop::Left),
            "{state}"
        );
    }
    let recorded = EnvironmentFacts {
        setup_error: Some("sync workspace env: timed out".into()),
        ..facts("running", "started")
    };
    assert_eq!(recorded.setup_stop(), Some(SetupStop::SetupError));
    let refused = EnvironmentFacts {
        error_code: Some("no_capacity".into()),
        ..facts("running", "started")
    };
    assert_eq!(
        refused.setup_stop(),
        Some(SetupStop::PlatformEnded(PlatformEnd::NoCapacity))
    );
}

#[test]
fn a_start_stops_only_when_a_stopped_environment_is_no_longer_wanted_started() {
    assert_eq!(facts("stopped", "started").start_stop(), None);
    assert_eq!(
        facts("stopped", "stopped").start_stop(),
        Some(SetupStop::Left)
    );
    assert_eq!(
        facts("destroyed", "started").start_stop(),
        Some(SetupStop::Left)
    );
}

#[test]
fn facts_read_the_environment_as_the_server_sent_it() {
    let environment = Environment {
        id: "env".into(),
        state: EnvironmentState::BuildFailed.into(),
        desired_state: DesiredState::Started.into(),
        isolation_tier: IsolationTier::Confidential.into(),
        error_code: "container_start_failed".into(),
        ..Default::default()
    };
    let facts = EnvironmentFacts::from_proto(&environment);
    assert_eq!(facts.state, "build_failed");
    assert_eq!(facts.desired_state, "started");
    assert!(facts.confidential);
    assert_eq!(
        facts.platform_end(),
        Some(PlatformEnd::ContainerStartFailed)
    );
    assert_eq!(facts.error_reason, None, "an empty reason is none");
}
