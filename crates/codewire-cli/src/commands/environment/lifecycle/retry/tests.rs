use std::collections::VecDeque;
use std::sync::Mutex;

use codewire_client::environment_setup::{LogFeedConnection, LogFeedEvent};
use tokio::sync::mpsc;

use super::*;
use crate::commands::progress::CapturedOutput;
use crate::config::MapEnv;
use crate::output::{Capabilities, OutputMode, TerminalFacts};
use crate::presentation::EnvironmentLog;

const RECLONE: &str = "retrying setup clones the repositories again, which deletes /workspace/app and any edits made there; confirm to retry";

fn row(id: &str, phase: &str, status: &str, message: &str) -> EnvironmentLog {
    EnvironmentLog {
        id: id.to_owned(),
        environment_id: "env-1".to_owned(),
        phase: phase.to_owned(),
        status: status.to_owned(),
        message: message.to_owned(),
        metadata: None,
        created_at: "2026-11-16T10:00:00Z".to_owned(),
    }
}

/// A feed that hands each connection its rows and keeps it open, and
/// records where each connection resumed.
#[derive(Default)]
struct Feed {
    connections: Mutex<VecDeque<Vec<EnvironmentLog>>>,
    opened: Mutex<Vec<Option<String>>>,
    held: Mutex<Vec<mpsc::UnboundedSender<LogFeedEvent>>>,
}

impl Feed {
    fn new(connections: Vec<Vec<EnvironmentLog>>) -> Self {
        Self {
            connections: Mutex::new(connections.into()),
            ..Default::default()
        }
    }
}

impl EnvironmentLogFeed for Feed {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection {
        self.opened.lock().unwrap().push(after_log_id);
        let rows = self
            .connections
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        let (sender, events) = mpsc::unbounded_channel();
        for row in rows {
            sender.send(LogFeedEvent::Log(row)).unwrap();
        }
        self.held.lock().unwrap().push(sender);
        LogFeedConnection::new(events, None)
    }
}

fn policy() -> FollowPolicy {
    FollowPolicy {
        idle_timeout: Duration::from_secs(30),
        max_reconnects: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        tick: Duration::from_millis(5),
    }
}

/// Follows `feed` from row `c0` into plain text, as redirected output shows it.
async fn follow(feed: &Feed, note_after: Duration) -> (FollowEnd, String) {
    let caps = Capabilities::detect(
        OutputMode::Text,
        &TerminalFacts::default(),
        &MapEnv::new(Vec::<(String, String)>::new()),
    );
    let out = CapturedOutput::default();
    let mut view = StartProgress::new(out.clone(), &caps, Instant::now(), "Retrying setup");
    let end = follow_retry(
        feed,
        &mut view,
        Some("c0".to_owned()),
        &policy(),
        note_after,
    )
    .await
    .unwrap();
    view.finish().unwrap();
    drop(view);
    (end, out.text())
}

#[tokio::test(start_paused = true)]
async fn a_retry_that_completes_is_followed_from_the_row_before_it() {
    let feed = Feed::new(vec![vec![
        row("r1", "install", "started", "Running install command"),
        row("r2", "install", "completed", "Install command completed"),
        row("r3", "complete", "completed", "Setup complete"),
    ]]);
    let (end, text) = follow(&feed, Duration::from_secs(60)).await;
    assert_eq!(end, FollowEnd::Complete);
    assert_eq!(*feed.opened.lock().unwrap(), [Some("c0".to_owned())]);
    assert!(!text.contains(NOT_STARTED), "{text}");
    assert_eq!(
        retry_result("app", end),
        RetryResult {
            environment: "app".to_owned(),
            status: "complete",
            step: None,
            error: None,
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_retry_that_has_not_started_says_so_once_and_keeps_following() {
    let feed = Feed::new(vec![
        Vec::new(),
        vec![
            row("r1", "install", "started", "Running install command"),
            row("r2", "install", "failed", "npm ci exploded"),
        ],
    ]);
    let (end, text) = follow(&feed, Duration::from_millis(20)).await;
    assert_eq!(text.matches(NOT_STARTED).count(), 1, "{text}");
    // The follow resumes from the same row: nothing came before the note.
    assert_eq!(
        *feed.opened.lock().unwrap(),
        [Some("c0".to_owned()), Some("c0".to_owned())]
    );
    let result = retry_result("app", end);
    assert_eq!(
        result,
        RetryResult {
            environment: "app".to_owned(),
            status: "failed",
            step: Some("Running install command".to_owned()),
            error: Some("npm ci exploded".to_owned()),
        }
    );
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::json!({
            "environment": "app",
            "status": "failed",
            "step": "Running install command",
            "error": "npm ci exploded",
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_retry_still_running_at_the_note_is_not_called_unstarted() {
    let feed = Feed::new(vec![
        vec![row("r1", "install", "started", "Running install command")],
        vec![row("r2", "complete", "completed", "Setup complete")],
    ]);
    let (end, text) = follow(&feed, Duration::from_millis(20)).await;
    assert_eq!(end, FollowEnd::Complete);
    assert!(!text.contains(NOT_STARTED), "{text}");
    assert_eq!(
        *feed.opened.lock().unwrap(),
        [Some("c0".to_owned()), Some("r1".to_owned())]
    );
}

#[test]
fn a_failed_setup_names_its_step_and_the_way_to_fix_it() {
    let failed = |step, error| {
        let error = setup_failed_error("app", step, error);
        let next = error
            .downcast_ref::<crate::error_report::NextStep>()
            .map(ToString::to_string);
        (error.root_cause().to_string(), next)
    };
    let tail = "app is still running, so fix it there and run `cw retry app` (`cw logs app --setup` has the whole log)";
    assert_eq!(
        failed(Some("Running install command"), "workspace exec exited 1"),
        (
            format!("setup failed at Running install command: workspace exec exited 1; {tail}"),
            Some("cw shell app".to_owned())
        )
    );
    assert_eq!(
        failed(Some("Gateway ready"), "").0,
        format!("setup failed at Gateway ready; {tail}")
    );
    assert_eq!(
        failed(None, "\x1b[31mboom").0,
        format!("setup failed: [31mboom; {tail}")
    );
}

#[test]
fn a_reclone_is_asked_about_at_a_terminal_and_refused_with_yes_elsewhere() {
    let Unconfirmed::Ask(deletes) = unconfirmed("app", RECLONE, true) else {
        panic!("a terminal asks");
    };
    assert_eq!(
        deletes,
        "retrying setup clones the repositories again, which deletes /workspace/app and any edits made there"
    );
    let Unconfirmed::Refuse(error) = unconfirmed("app", RECLONE, false) else {
        panic!("without a terminal it refuses");
    };
    assert_eq!(error.root_cause().to_string(), deletes);
    assert_eq!(
        error
            .downcast_ref::<crate::error_report::NextStep>()
            .map(ToString::to_string),
        Some("cw retry app --yes".to_owned())
    );
}

#[test]
fn local_is_refused_in_one_sentence() {
    assert!(!LOCAL_REFUSAL.contains('\n'));
    assert!(LOCAL_REFUSAL.contains("local VM"));
}
