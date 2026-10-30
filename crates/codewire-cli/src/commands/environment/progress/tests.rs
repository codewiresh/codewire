use std::cell::Cell;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

use serde_json::json;

use super::*;
use crate::config::MapEnv;
use crate::output::TerminalFacts;

/// Clears the current terminal line.
const CLEAR_LINE: &str = "\r\x1b[2K";
const WRAP_OFF: &str = "\x1b[?7l";
const WRAP_ON: &str = "\x1b[?7h";

const CLONE_PROGRESS_FIXTURE: &str =
    include_str!("../../../../tests/fixtures/environment-log-clone-progress-v1.json");

fn fixture_rows() -> Vec<EnvironmentLog> {
    let fixture: Value = serde_json::from_str(CLONE_PROGRESS_FIXTURE).unwrap();
    serde_json::from_value(fixture["rows"].clone()).unwrap()
}

fn row(
    id: &str,
    phase: &str,
    status: &str,
    message: &str,
    created_at: &str,
    metadata: Option<Value>,
) -> EnvironmentLog {
    EnvironmentLog {
        id: id.to_owned(),
        environment_id: "env-1".to_owned(),
        phase: phase.to_owned(),
        status: status.to_owned(),
        message: message.to_owned(),
        metadata,
        created_at: created_at.to_owned(),
    }
}

fn complete_row(id: &str) -> EnvironmentLog {
    row(
        id,
        "complete",
        "completed",
        "Setup complete",
        "2026-09-29T10:00:30Z",
        None,
    )
}

/// The permanent lines of live output: what remains on screen once every
/// status-line redraw has been overwritten.
fn permanent_lines(output: &str) -> Vec<String> {
    let mut chunks: Vec<&str> = output.split('\n').collect();
    chunks.pop();
    chunks
        .into_iter()
        .map(|chunk| chunk.rsplit(CLEAR_LINE).next().unwrap_or(chunk).to_owned())
        .collect()
}

/// A progress view writing into memory.
struct View {
    progress: StartProgress<CapturedOutput>,
    out: CapturedOutput,
}

impl Deref for View {
    type Target = StartProgress<CapturedOutput>;

    fn deref(&self) -> &Self::Target {
        &self.progress
    }
}

impl DerefMut for View {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.progress
    }
}

fn caps(facts: TerminalFacts, vars: &[(&str, &str)]) -> Capabilities {
    Capabilities::detect(OutputMode::Text, &facts, &MapEnv::new(vars.iter().copied()))
}

fn view_with(caps: &Capabilities, began: Instant) -> View {
    let out = CapturedOutput::default();
    View {
        progress: StartProgress::new(out.clone(), caps, began, "Starting"),
        out,
    }
}

/// Redirected text output: one plain line per row, no colour.
fn plain_view(began: Instant) -> View {
    view_with(&caps(TerminalFacts::default(), &[]), began)
}

/// A terminal without colour and with a static spinner glyph, so live rows
/// are exact.
fn live_view(began: Instant) -> View {
    let terminal = TerminalFacts {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        columns: Some(200),
        rows: Some(40),
    };
    view_with(
        &caps(
            terminal,
            &[("NO_COLOR", "1"), ("CODEWIRE_REDUCED_MOTION", "1")],
        ),
        began,
    )
}

fn output(view: View) -> String {
    let View { progress, out } = view;
    drop(progress);
    out.text()
}

/// Plain stored-row rendering without colour.
fn stored(logs: &[EnvironmentLog]) -> String {
    format_environment_logs_plain(logs, &caps(TerminalFacts::default(), &[]))
}

fn live_frame(text: &str) -> String {
    format!("{CLEAR_LINE}{WRAP_OFF}{text}{WRAP_ON}")
}

enum ConnectionEnd {
    Close,
    Hang,
}

struct ScriptedConnection {
    events: Vec<LogFeedEvent>,
    end: ConnectionEnd,
}

fn connection(events: Vec<LogFeedEvent>, end: ConnectionEnd) -> ScriptedConnection {
    ScriptedConnection { events, end }
}

/// A feed that replays one script per connection and records each resume
/// cursor. Connections past the script fail retryably.
#[derive(Default)]
struct ScriptedFeed {
    connections: Mutex<VecDeque<ScriptedConnection>>,
    opened: Mutex<Vec<Option<String>>>,
    held: Mutex<Vec<mpsc::UnboundedSender<LogFeedEvent>>>,
}

impl ScriptedFeed {
    fn new(connections: Vec<ScriptedConnection>) -> Self {
        Self {
            connections: Mutex::new(connections.into()),
            ..Default::default()
        }
    }

    fn opened(&self) -> Vec<Option<String>> {
        self.opened.lock().unwrap().clone()
    }
}

impl EnvironmentLogFeed for ScriptedFeed {
    fn open(&self, after_log_id: Option<String>) -> LogFeedConnection {
        self.opened.lock().unwrap().push(after_log_id);
        let script = self
            .connections
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                connection(
                    vec![failure("script exhausted", LogStreamRecovery::Retry)],
                    ConnectionEnd::Close,
                )
            });
        let (sender, events) = mpsc::unbounded_channel();
        for event in script.events {
            sender.send(event).unwrap();
        }
        if matches!(script.end, ConnectionEnd::Hang) {
            self.held.lock().unwrap().push(sender);
        }
        LogFeedConnection::new(events, None)
    }
}

fn failure(message: &str, recovery: LogStreamRecovery) -> LogFeedEvent {
    LogFeedEvent::Failed(EnvironmentLogStreamFailure {
        error: anyhow::anyhow!(message.to_owned()),
        recovery,
    })
}

fn log_event(log: EnvironmentLog) -> LogFeedEvent {
    LogFeedEvent::Log(log)
}

fn fast_policy() -> FollowPolicy {
    FollowPolicy {
        idle_timeout: Duration::from_millis(60),
        max_reconnects: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        tick: Duration::from_millis(5),
    }
}

#[test]
fn clone_progress_fixture_renders_every_stage_with_elapsed_time() {
    assert_eq!(
        stored(&fixture_rows()),
        "  ◐ Creating namespace\n\
         \x20 ✓ Creating namespace  0s\n\
         \x20 ◐ Creating sandbox\n\
         \x20 ✓ Creating sandbox  21s\n\
         \x20 ✓ Storing backend info\n\
         \x20 ◐ Checking sidecar readiness\n\
         \x20 ✓ Checking sidecar readiness  0.2s\n\
         \x20 ◐ Cloning repositories\n\
         \x20   ◐ Cloning repository 1 of 2\n\
         \x20   · Cloning repository 1 of 2: receiving objects 45%\n\
         \x20   · Cloning repository 1 of 2: resolving deltas 100%\n\
         \x20   ✓ Cloned repository 1 of 2  3s\n\
         \x20   ◐ Cloning repository 2 of 2\n\
         \x20   · Cloning repository 2 of 2: receiving objects 100%\n\
         \x20   ✓ Cloned repository 2 of 2  2s\n\
         \x20 ✓ Cloning repositories  5s\n\
         \x20 ✓ Setup complete\n"
    );
}

#[test]
fn clone_progress_fixture_updates_one_live_line_on_a_terminal() {
    let t0 = Instant::now();
    let mut view = live_view(t0);
    for (offset, log) in fixture_rows().iter().enumerate() {
        let received = t0 + Duration::from_secs(offset as u64);
        view.apply(log, received).unwrap();
    }
    view.finish().unwrap();
    let rendered = output(view);

    assert_eq!(
        permanent_lines(&rendered),
        [
            "  ✓ Creating namespace  0s",
            "  ✓ Creating sandbox  21s",
            "  ✓ Storing backend info",
            "  ✓ Checking sidecar readiness  0.2s",
            "    ✓ Cloned repository 1 of 2  3s",
            "    ✓ Cloned repository 2 of 2  2s",
            "  ✓ Cloning repositories  5s",
            "  ✓ Setup complete",
        ]
    );
    // Progress rows update the per-repository stage in place; its clock
    // runs from the local receipt of its `started` row.
    for frame in [
        "  ◐ Cloning repository 1 of 2 · receiving objects 45%  1s",
        "  ◐ Cloning repository 1 of 2 · resolving deltas 100%  2s",
        // Back to the phase-level stage between repositories.
        "  ◐ Cloning repositories  4s",
        // No stage remains open after `complete`.
        "  ◐ Starting  16s",
    ] {
        assert!(
            rendered.contains(&live_frame(frame)),
            "{frame}\n{rendered:?}"
        );
    }
    // The live row is cleared at the end.
    assert!(rendered.ends_with(CLEAR_LINE));
    assert!(!rendered.contains('◌'));
}

#[test]
fn clone_progress_metadata_is_rendered_from_whatever_fields_are_present() {
    let full =
        json!({"repo_index": 2, "repo_count": 3, "stage": "receiving_objects", "percent": 45});
    assert_eq!(
        format_clone_progress(Some(&full), true).as_deref(),
        Some("repository 2/3, receiving objects 45%")
    );
    assert_eq!(
        format_clone_progress(Some(&full), false).as_deref(),
        Some("receiving objects 45%")
    );
    assert_eq!(
        parse_clone_progress(Some(&full)),
        CloneProgress {
            repo_index: Some(2),
            repo_count: Some(3),
            stage: Some("receiving objects".to_owned()),
            percent: Some(45),
        }
    );
    let single = json!({"repo_index": 1, "repo_count": 1, "percent": 250});
    assert_eq!(
        format_clone_progress(Some(&single), true).as_deref(),
        Some("100%")
    );
    let hostile =
        json!({"stage": "resolving\u{1b}[31m_deltas\nnow", "percent": "ten", "extra": true});
    assert_eq!(
        format_clone_progress(Some(&hostile), true).as_deref(),
        Some("resolving [31m deltas now")
    );
    assert_eq!(format_clone_progress(Some(&json!({})), true), None);
    assert_eq!(format_clone_progress(None, true), None);
}

#[test]
fn connect_struct_numbers_arrive_as_doubles_and_still_parse() {
    let progress =
        json!({"repo_index": 2.0, "repo_count": 3.0, "stage": "updating_files", "percent": 99.0});
    assert_eq!(
        format_clone_progress(Some(&progress), true).as_deref(),
        Some("repository 2/3, updating files 99%")
    );
    for (value, expected) in [
        (json!(21600.0), Some(21_600)),
        (json!(7), Some(7)),
        (json!(-1.0), None),
        (json!(2.5), None),
        (json!(f64::MAX), None),
        (json!("12"), None),
    ] {
        assert_eq!(metadata_count(&value), expected, "{value}");
    }
    let t0 = Instant::now();
    let mut view = plain_view(t0);
    view.apply(
        &row(
            "a",
            "gateway_ready",
            "completed",
            "Gateway ready",
            "2026-09-29T10:00:00Z",
            Some(json!({"duration_ms": 2300.0})),
        ),
        t0,
    )
    .unwrap();
    assert_eq!(output(view), "  ✓ Gateway ready  2.3s\n");
}

#[test]
fn clone_progress_without_per_repository_rows_attaches_to_the_clone_stage() {
    let t0 = Instant::now();
    let mut view = plain_view(t0);
    let rows = [
        row(
            "a",
            "git_clone",
            "started",
            "Cloning repositories",
            "2026-09-29T10:00:00Z",
            None,
        ),
        row(
            "b",
            "git_clone",
            "progress",
            "Cloning repositories",
            "2026-09-29T10:00:01Z",
            Some(
                json!({"repo_index": 2, "repo_count": 3, "stage": "receiving_objects", "percent": 10}),
            ),
        ),
        row(
            "c",
            "git_clone",
            "progress",
            "Cloning repositories",
            "2026-09-29T10:00:02Z",
            None,
        ),
        row(
            "d",
            "git_clone",
            "completed",
            "Cloning repositories",
            "2026-09-29T10:01:07Z",
            None,
        ),
    ];
    for log in &rows {
        view.apply(log, t0).unwrap();
    }
    assert_eq!(
        output(view),
        "  ◐ Cloning repositories\n\
         \x20   · Cloning repositories: repository 2/3, receiving objects 10%\n\
         \x20   · Cloning repositories\n\
         \x20 ✓ Cloning repositories  1m 07s\n"
    );

    // On a terminal the progress row updates the open clone stage.
    let mut view = live_view(t0);
    view.apply(&rows[0], t0).unwrap();
    view.apply(&rows[1], t0 + Duration::from_secs(3)).unwrap();
    let rendered = output(view);
    assert!(
        rendered.ends_with(&format!(
            "{}{CLEAR_LINE}",
            live_frame("  ◐ Cloning repositories · repository 2/3, receiving objects 10%  3s")
        )),
        "{rendered:?}"
    );
}

#[test]
fn unknown_phases_statuses_and_control_characters_render_generically() {
    let t0 = Instant::now();
    let mut view = plain_view(t0);
    for log in [
        row(
            "a",
            "warm_pool_bind",
            "started",
            "warm_pool_bind",
            "2026-09-29T10:00:00Z",
            None,
        ),
        row(
            "b",
            "warm_pool_bind",
            "completed",
            "",
            "2026-09-29T10:00:04Z",
            None,
        ),
        row(
            "c",
            "admission",
            "queued",
            "Waiting for capacity",
            "2026-09-29T10:00:05Z",
            None,
        ),
        row(
            "d",
            "startup_script",
            "warning",
            "exit\u{1b}[2J status\r\n3",
            "2026-09-29T10:00:06Z",
            None,
        ),
    ] {
        assert_eq!(view.apply(&log, t0).unwrap(), None);
    }
    assert_eq!(
        output(view),
        "  ◐ Warm pool bind\n\
         \x20 ✓ Warm pool bind  4s\n\
         \x20 · Waiting for capacity\n\
         \x20 ! exit [2J status 3\n"
    );
}

#[test]
fn stored_logs_keep_the_established_plain_shapes() {
    let logs = [
        row(
            "log-1",
            "clone",
            "started",
            "Cloning repository",
            "2026-07-05T03:00:00Z",
            None,
        ),
        row(
            "log-2",
            "clone",
            "completed",
            "Repository cloned",
            "2026-07-05T03:00:07Z",
            None,
        ),
        row(
            "log-3",
            "install",
            "warning",
            "Package cache unavailable",
            "2026-07-05T03:00:08Z",
            None,
        ),
        row(
            "log-4",
            "install",
            "failed",
            "Install failed",
            "2026-07-05T03:00:09Z",
            None,
        ),
        // A completion earlier than its start never shows negative time.
        row(
            "log-5",
            "sync",
            "started",
            "Syncing",
            "2026-07-05T03:00:10Z",
            None,
        ),
        row(
            "log-6",
            "sync",
            "completed",
            "Synced",
            "2026-07-05T03:00:09Z",
            None,
        ),
    ];
    assert_eq!(
        stored(&logs),
        "  ◐ Cloning repository\n\
         \x20 ✓ Repository cloned  7s\n\
         \x20 ! Package cache unavailable\n\
         \x20 ✗ Install failed\n\
         \x20 ◐ Syncing\n\
         \x20 ✓ Synced  0s\n"
    );
    // A basic terminal gets ASCII marks.
    let ascii =
        format_environment_logs_plain(&logs, &caps(TerminalFacts::default(), &[("TERM", "dumb")]));
    assert!(ascii.is_ascii(), "{ascii}");
    assert!(ascii.starts_with("  | Cloning repository\n  + Repository cloned  7s\n"));
}

#[test]
fn a_failed_row_names_its_stage_and_becomes_the_command_error() {
    let t0 = Instant::now();
    let mut view = plain_view(t0);
    view.apply(
        &row(
            "a",
            "install",
            "started",
            "Running install command",
            "2026-09-29T10:00:00Z",
            None,
        ),
        t0,
    )
    .unwrap();
    let failure = view
        .apply(
            &row(
                "b",
                "install",
                "failed",
                "npm ci exploded",
                "2026-09-29T10:00:04Z",
                None,
            ),
            t0,
        )
        .unwrap()
        .expect("failed row");
    assert_eq!(
        failure,
        StageFailure {
            phase: "install".to_owned(),
            stage: "Running install command".to_owned(),
            message: "npm ci exploded".to_owned(),
        }
    );
    assert_eq!(
        output(view),
        "  ◐ Running install command\n  ✗ Running install command: npm ci exploded  4s\n"
    );
    assert_eq!(
        failure.into_error("env-1").to_string(),
        "environment env-1 failed at stage \"Running install command\": npm ci exploded (see `cw logs env-1 --setup`)"
    );

    let unlabelled = StageFailure {
        phase: "gateway_ready".to_owned(),
        stage: "Gateway ready".to_owned(),
        message: String::new(),
    };
    assert_eq!(
        unlabelled.into_error("env-2").to_string(),
        "environment env-2 failed at stage \"Gateway ready\" (see `cw logs env-2 --setup`)"
    );
}

#[test]
fn durations_and_backoff_are_bounded_and_readable() {
    assert_eq!(format_duration(Duration::from_millis(180), true), "0.2s");
    assert_eq!(format_duration(Duration::from_millis(9_940), true), "9.9s");
    assert_eq!(format_duration(Duration::from_millis(21_600), true), "21s");
    assert_eq!(format_duration(Duration::from_millis(900), false), "0s");
    assert_eq!(format_duration(Duration::from_secs(65), false), "1m 05s");
    assert_eq!(format_duration(Duration::from_secs(7_380), false), "2h 03m");

    let policy = FollowPolicy::default();
    assert_eq!(policy.backoff(1), Duration::from_secs(1));
    assert_eq!(policy.backoff(2), Duration::from_secs(2));
    assert_eq!(policy.backoff(4), Duration::from_secs(8));
    assert_eq!(policy.backoff(40), Duration::from_secs(8));
    assert_eq!(policy.idle_timeout, Duration::from_secs(45));
}

#[tokio::test]
async fn follow_resumes_after_the_last_row_when_the_stream_fails() {
    let feed = ScriptedFeed::new(vec![
        connection(
            vec![
                log_event(row(
                    "log-1",
                    "create_claim",
                    "started",
                    "Creating sandbox",
                    "2026-09-29T10:00:00Z",
                    None,
                )),
                log_event(row(
                    "log-2",
                    "create_claim",
                    "completed",
                    "Creating sandbox",
                    "2026-09-29T10:00:20Z",
                    None,
                )),
                failure("connection reset", LogStreamRecovery::Retry),
            ],
            ConnectionEnd::Close,
        ),
        connection(vec![log_event(complete_row("log-3"))], ConnectionEnd::Hang),
    ]);
    let mut view = plain_view(Instant::now());
    let mut cursor = None;
    let end = follow_start_progress(&feed, &mut view.progress, &mut cursor, &fast_policy())
        .await
        .unwrap();

    assert_eq!(end, FollowEnd::Complete);
    assert_eq!(feed.opened(), [None, Some("log-2".to_owned())]);
    assert_eq!(cursor.as_deref(), Some("log-3"));
    assert_eq!(
        output(view),
        "  ◐ Creating sandbox\n\
         \x20 ✓ Creating sandbox  20s\n\
         \x20 ! Log stream interrupted (connection reset); resuming, attempt 1 of 3\n\
         \x20 ✓ Setup complete\n"
    );
}

#[tokio::test]
async fn follow_resumes_silently_when_the_call_deadline_rotates_a_healthy_stream() {
    let feed = ScriptedFeed::new(vec![
        connection(
            vec![
                LogFeedEvent::Heartbeat,
                log_event(row(
                    "log-1",
                    "create_claim",
                    "started",
                    "Creating sandbox",
                    "2026-09-29T10:00:00Z",
                    None,
                )),
                failure("deadline exceeded", LogStreamRecovery::Resume),
            ],
            ConnectionEnd::Close,
        ),
        // A deadline with nothing delivered is not a healthy rotation.
        connection(
            vec![failure("deadline exceeded", LogStreamRecovery::Resume)],
            ConnectionEnd::Close,
        ),
        connection(vec![log_event(complete_row("log-2"))], ConnectionEnd::Close),
    ]);
    let mut view = plain_view(Instant::now());
    let end = follow_start_progress(&feed, &mut view.progress, &mut None, &fast_policy())
        .await
        .unwrap();
    assert_eq!(end, FollowEnd::Complete);
    assert_eq!(
        feed.opened(),
        [None, Some("log-1".to_owned()), Some("log-1".to_owned())]
    );
    assert_eq!(
        output(view),
        "  ◐ Creating sandbox\n\
         \x20 ! Log stream interrupted (deadline exceeded); resuming, attempt 1 of 3\n\
         \x20 ✓ Setup complete\n"
    );
}

#[tokio::test]
async fn follow_reconnects_when_heartbeats_stop_or_the_stream_closes_early() {
    let feed = ScriptedFeed::new(vec![
        connection(
            vec![log_event(row(
                "log-1",
                "ensure_namespace",
                "completed",
                "Creating namespace",
                "2026-09-29T10:00:00Z",
                None,
            ))],
            ConnectionEnd::Hang,
        ),
        connection(vec![LogFeedEvent::Heartbeat], ConnectionEnd::Close),
        connection(vec![log_event(complete_row("log-2"))], ConnectionEnd::Close),
    ]);
    let mut view = plain_view(Instant::now());
    let mut cursor = None;
    let end = follow_start_progress(&feed, &mut view.progress, &mut cursor, &fast_policy())
        .await
        .unwrap();

    assert_eq!(end, FollowEnd::Complete);
    assert_eq!(
        feed.opened(),
        [None, Some("log-1".to_owned()), Some("log-1".to_owned())]
    );
    let rendered = output(view);
    assert!(
        rendered.contains("Log stream interrupted (no heartbeat for 0s); resuming, attempt 1 of 3"),
        "{rendered}"
    );
    // The heartbeat on the second connection reset the budget.
    assert!(
        rendered.contains(
            "Log stream interrupted (the stream closed before setup finished); resuming, attempt 1 of 3"
        ),
        "{rendered}"
    );
}

#[tokio::test]
async fn heartbeats_reset_the_reconnect_budget() {
    let mut connections: Vec<_> = (0..6)
        .map(|_| connection(vec![LogFeedEvent::Heartbeat], ConnectionEnd::Close))
        .collect();
    connections.push(connection(
        vec![log_event(complete_row("log-9"))],
        ConnectionEnd::Close,
    ));
    let feed = ScriptedFeed::new(connections);
    let mut view = plain_view(Instant::now());
    let end = follow_start_progress(&feed, &mut view.progress, &mut None, &fast_policy())
        .await
        .unwrap();
    assert_eq!(end, FollowEnd::Complete);
    assert_eq!(feed.opened().len(), 7);
}

#[tokio::test]
async fn follow_gives_up_after_bounded_reconnects() {
    let feed = ScriptedFeed::new(Vec::new());
    let mut view = plain_view(Instant::now());
    let error = follow_start_progress(&feed, &mut view.progress, &mut None, &fast_policy())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "lost the environment log stream after 3 reconnect attempts: script exhausted"
    );
    assert_eq!(feed.opened().len(), 4);
}

#[tokio::test]
async fn a_non_retryable_stream_failure_ends_the_follow_at_once() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![failure(
            "session expired or invalid",
            LogStreamRecovery::Fatal,
        )],
        ConnectionEnd::Close,
    )]);
    let mut view = plain_view(Instant::now());
    let error = follow_start_progress(&feed, &mut view.progress, &mut None, &fast_policy())
        .await
        .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "follow environment logs: session expired or invalid"
    );
    assert_eq!(feed.opened().len(), 1);
}

#[tokio::test]
async fn create_waits_for_setup_complete_then_daemon_readiness() {
    let feed = ScriptedFeed::new(vec![connection(
        fixture_rows().into_iter().map(log_event).collect(),
        ConnectionEnd::Hang,
    )]);
    let mut view = plain_view(Instant::now());
    let daemon_checked = Cell::new(false);
    await_environment_setup(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-fixture",
        std::future::pending(),
        || async {
            daemon_checked.set(true);
            Ok(())
        },
    )
    .await
    .unwrap();

    assert!(daemon_checked.get());
    let rendered = output(view);
    let lines: Vec<_> = rendered.lines().collect();
    let tail = &lines[lines.len() - 3..];
    assert_eq!(tail[0], "  ✓ Setup complete");
    assert_eq!(tail[1], "  ◐ Waiting for the workspace daemon");
    assert!(
        tail[2].starts_with("  ✓ Workspace daemon ready  0."),
        "{rendered}"
    );
}

#[tokio::test]
async fn create_exits_non_zero_on_a_failed_stage_without_waiting_for_the_daemon() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![
            log_event(row(
                "log-1",
                "git_clone",
                "started",
                "Cloning repositories",
                "2026-09-29T10:00:00Z",
                None,
            )),
            log_event(row(
                "log-2",
                "git_clone",
                "failed",
                "git clone: repository not found",
                "2026-09-29T10:00:02Z",
                None,
            )),
        ],
        ConnectionEnd::Close,
    )]);
    let mut view = plain_view(Instant::now());
    let daemon_checked = Cell::new(false);
    let error = await_environment_setup(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-1",
        std::future::pending(),
        || async {
            daemon_checked.set(true);
            Ok(())
        },
    )
    .await
    .unwrap_err();

    assert!(!daemon_checked.get());
    assert_eq!(
        error.to_string(),
        "environment env-1 failed at stage \"Cloning repositories\": git clone: repository not found (see `cw logs env-1 --setup`)"
    );
    assert!(
        output(view).ends_with("  ✗ Cloning repositories: git clone: repository not found  2s\n")
    );
}

#[tokio::test]
async fn create_fails_when_setup_stops_without_a_failed_row() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![log_event(row(
            "log-1",
            "configure_environment",
            "started",
            "Configuring environment",
            "2026-09-29T10:00:00Z",
            None,
        ))],
        ConnectionEnd::Hang,
    )]);
    let policy = FollowPolicy {
        idle_timeout: Duration::from_secs(30),
        ..fast_policy()
    };
    let mut view = plain_view(Instant::now());
    let guard = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        setup_failure(&Environment {
            id: "env-1".to_owned(),
            state: "running".to_owned(),
            setup_error: Some("sync workspace env: timed out".to_owned()),
            ..Default::default()
        })
        .unwrap()
    };
    let error = await_environment_setup(
        &feed,
        &mut view.progress,
        &policy,
        "env-1",
        guard,
        || async { Ok(()) },
    )
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "stopped at stage \"Configuring environment\": environment env-1 setup failed: sync workspace env: timed out (see `cw logs env-1 --setup`)"
    );
    // The stage that was running is closed with a cross, not left open.
    let rendered = output(view);
    assert!(
        rendered.contains("  ✗ Configuring environment  0."),
        "{rendered}"
    );
}

#[tokio::test]
async fn create_reports_a_daemon_that_never_becomes_ready() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![log_event(complete_row("log-1"))],
        ConnectionEnd::Close,
    )]);
    let mut view = plain_view(Instant::now());
    let error = await_environment_setup(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-1",
        std::future::pending(),
        || async { Err(anyhow::anyhow!("environment daemon is unhealthy")) },
    )
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "stopped at stage \"Waiting for the workspace daemon\": environment daemon is unhealthy"
    );
    let rendered = output(view);
    assert!(!rendered.contains("Workspace daemon ready"));
    assert!(
        rendered.contains("  ✗ Waiting for the workspace daemon  "),
        "{rendered}"
    );
}

#[tokio::test]
async fn start_shows_rows_after_the_cursor_until_the_daemon_is_ready() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![
            log_event(row(
                "log-7",
                "lifecycle_intent",
                "completed",
                "desired state -> started",
                "2026-09-29T11:00:00Z",
                Some(json!({"kind": "desired_state", "desired_state": "started"})),
            )),
            log_event(row(
                "log-8",
                "gateway_ready",
                "completed",
                "Gateway ready",
                "2026-09-29T11:00:21Z",
                Some(json!({"duration_ms": 2_300, "pod_ip": "10.0.0.1"})),
            )),
        ],
        ConnectionEnd::Hang,
    )]);
    // The stream stays open without heartbeats; a long idle deadline keeps a
    // loaded machine from interleaving a reconnect notice before readiness.
    let policy = FollowPolicy {
        idle_timeout: Duration::from_secs(30),
        ..fast_policy()
    };
    let mut view = plain_view(Instant::now());
    await_environment_start(
        &feed,
        &mut view.progress,
        &policy,
        "env-1",
        Some("log-6".to_owned()),
        async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(())
        },
    )
    .await
    .unwrap();

    assert_eq!(feed.opened(), [Some("log-6".to_owned())]);
    let rendered = output(view);
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines[0], "  ◐ Waiting for the workspace daemon");
    assert_eq!(lines[1], "  ✓ desired state -> started");
    assert_eq!(lines[2], "  ✓ Gateway ready  2.3s");
    assert!(
        lines[3].starts_with("  ✓ Workspace daemon ready  0."),
        "{rendered}"
    );
}

#[tokio::test]
async fn start_exits_non_zero_on_a_failed_row() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![log_event(row(
            "log-8",
            "gateway_ready",
            "failed",
            "sidecar did not become ready",
            "2026-09-29T11:00:21Z",
            None,
        ))],
        ConnectionEnd::Close,
    )]);
    let mut view = plain_view(Instant::now());
    let error = await_environment_start(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-1",
        None,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "environment env-1 failed at stage \"Gateway ready\": sidecar did not become ready (see `cw logs env-1 --setup`)"
    );
}

#[tokio::test]
async fn start_still_waits_for_the_daemon_when_progress_is_unavailable() {
    let feed = ScriptedFeed::new(vec![connection(
        vec![failure(
            "session expired or invalid",
            LogStreamRecovery::Fatal,
        )],
        ConnectionEnd::Close,
    )]);
    let mut view = plain_view(Instant::now());
    await_environment_start(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-1",
        None,
        async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(())
        },
    )
    .await
    .unwrap();
    let rendered = output(view);
    assert!(
        rendered.contains(
            "  ! Start progress is unavailable: follow environment logs: session expired or invalid\n"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("  ✓ Workspace daemon ready"),
        "{rendered}"
    );
}

#[test]
fn setup_failure_reports_states_that_cannot_finish_setup() {
    let environment = |state: &str| Environment {
        id: "env-1".to_owned(),
        state: state.to_owned(),
        ..Default::default()
    };
    for state in ["pending", "creating", "starting", "running"] {
        assert!(setup_failure(&environment(state)).is_none(), "{state}");
    }
    assert_eq!(
        setup_failure(&Environment {
            error_reason: Some("claim: quota exceeded\n".to_owned()),
            ..environment("error")
        })
        .unwrap()
        .to_string(),
        "environment env-1 became error before setup completed: claim: quota exceeded"
    );
    assert_eq!(
        setup_failure(&environment("destroying"))
            .unwrap()
            .to_string(),
        "environment env-1 became destroying before setup completed"
    );
    assert!(
        setup_failure(&Environment {
            setup_error: Some("  ".to_owned()),
            ..environment("running")
        })
        .is_none()
    );
}

#[test]
fn start_cursor_is_the_newest_stored_row() {
    assert_eq!(last_log_id(&[]), None);
    assert_eq!(last_log_id(&fixture_rows()).as_deref(), Some("log-17"));
}

/// A hosted create's rows as the server writes them: the Pod start timing
/// rows arrive after `mark_running`, though their time is part of
/// `access_ready`.
fn pod_timing_rows() -> Vec<EnvironmentLog> {
    let pod = |id: &str, phase: &str, message: &str, millis: u64| {
        row(
            id,
            phase,
            "completed",
            message,
            "2026-10-27T10:00:12Z",
            Some(json!({"duration_ms": millis, "pod_uid": "pod-1"})),
        )
    };
    vec![
        row(
            "log-1",
            "access_ready",
            "started",
            "SSH access ready",
            "2026-10-27T10:00:00Z",
            None,
        ),
        row(
            "log-2",
            "access_ready",
            "completed",
            "SSH access ready",
            "2026-10-27T10:00:10Z",
            Some(json!({"duration_ms": 10_000})),
        ),
        row(
            "log-3",
            "wait_for_ready",
            "completed",
            "Waiting for sandbox ready",
            "2026-10-27T10:00:11Z",
            Some(json!({"duration_ms": 600})),
        ),
        pod("log-4", "pod_scheduled", "Workspace pod scheduled", 4_000),
        pod(
            "log-5",
            "pod_running",
            "Workspace containers started",
            5_000,
        ),
        pod(
            "log-6",
            "pod_containers_ready",
            "Workspace containers ready",
            2_000,
        ),
        row(
            "log-7",
            "mark_running",
            "completed",
            "Marking running",
            "2026-10-27T10:00:12Z",
            None,
        ),
    ]
}

#[test]
fn pod_start_timing_renders_inside_access_ready() {
    assert_eq!(
        stored(&pod_timing_rows()),
        "  ◐ SSH access ready\n\
         \x20 ✓ SSH access ready  10s\n\
         \x20 ✓ Waiting for sandbox ready  0.6s\n\
         \x20 · SSH access ready included:\n\
         \x20   ✓ Workspace pod scheduled  4.0s\n\
         \x20   ✓ Workspace containers started  5.0s\n\
         \x20   ✓ Workspace containers ready  2.0s\n\
         \x20 ✓ Marking running\n"
    );
}

#[test]
fn pod_start_timing_header_is_drawn_once_per_pod_on_a_terminal() {
    let t0 = Instant::now();
    let mut view = live_view(t0);
    let mut rows = pod_timing_rows();
    // A replaced Pod reports its own timing under a fresh header.
    rows.push(row(
        "log-8",
        "pod_scheduled",
        "completed",
        "Workspace pod scheduled",
        "2026-10-27T10:00:20Z",
        Some(json!({"duration_ms": 1_000, "pod_uid": "pod-2"})),
    ));
    for (offset, log) in rows.iter().enumerate() {
        view.apply(log, t0 + Duration::from_secs(offset as u64))
            .unwrap();
    }
    view.finish().unwrap();

    assert_eq!(
        permanent_lines(&output(view)),
        [
            "  ✓ SSH access ready  10s",
            "  ✓ Waiting for sandbox ready  0.6s",
            "  · SSH access ready included:",
            "    ✓ Workspace pod scheduled  4.0s",
            "    ✓ Workspace containers started  5.0s",
            "    ✓ Workspace containers ready  2.0s",
            "  ✓ Marking running",
            "  · SSH access ready included:",
            "    ✓ Workspace pod scheduled  1.0s",
        ]
    );
}

#[test]
fn finer_pod_stages_render_under_the_stage_they_split() {
    let pod = |id: &str, phase: &str, message: &str, millis: u64| {
        row(
            id,
            phase,
            "completed",
            message,
            "2026-10-27T10:00:12Z",
            Some(json!({"duration_ms": millis, "pod_uid": "pod-1"})),
        )
    };
    let rows = [
        pod("log-1", "pod_created", "Workspace pod created", 1_000),
        pod("log-2", "pod_scheduled", "Workspace pod scheduled", 4_000),
        pod(
            "log-3",
            "pod_volume_provisioned",
            "Workspace volume provisioned",
            3_000,
        ),
        pod("log-4", "pod_volume_bound", "Workspace volume bound", 1_000),
        pod(
            "log-5",
            "pod_running",
            "Workspace containers started",
            5_000,
        ),
        pod(
            "log-6",
            "pod_sandbox_ready",
            "Workspace sandbox started",
            3_000,
        ),
        pod(
            "log-7",
            "pod_workspace_started",
            "Workspace container started",
            1_000,
        ),
        pod(
            "log-8",
            "pod_dind_started",
            "Docker container started",
            1_000,
        ),
        pod(
            "log-9",
            "pod_containers_ready",
            "Workspace containers ready",
            3_000,
        ),
    ];
    assert_eq!(
        stored(&rows),
        "  · SSH access ready included:\n\
         \x20   ✓ Workspace pod created  1.0s\n\
         \x20   ✓ Workspace pod scheduled  4.0s\n\
         \x20     ✓ Workspace volume provisioned  3.0s\n\
         \x20     ✓ Workspace volume bound  1.0s\n\
         \x20   ✓ Workspace containers started  5.0s\n\
         \x20     ✓ Workspace sandbox started  3.0s\n\
         \x20     ✓ Workspace container started  1.0s\n\
         \x20     ✓ Docker container started  1.0s\n\
         \x20   ✓ Workspace containers ready  3.0s\n"
    );
}

#[test]
fn a_warm_members_start_is_not_counted_in_this_create() {
    let rows = [row(
        "log-1",
        "pod_scheduled",
        "completed",
        "Workspace pod scheduled",
        "2026-10-27T10:00:12Z",
        Some(json!({"duration_ms": 7_000, "pod_uid": "pod-1", "start_path": "warm"})),
    )];
    assert_eq!(
        stored(&rows),
        "  · Warm pool member, started before this create:\n\
         \x20   ✓ Workspace pod scheduled  7.0s\n"
    );
}

#[test]
fn a_pod_phase_without_a_pod_uid_is_an_ordinary_stage() {
    let rows = [row(
        "log-1",
        "pod_scheduled",
        "completed",
        "Workspace pod scheduled",
        "2026-10-27T10:00:12Z",
        Some(json!({"duration_ms": 4_000})),
    )];
    assert_eq!(stored(&rows), "  ✓ Workspace pod scheduled  4.0s\n");
}

/// The fixture's rows with setup's `daemon_ready` row (#3684) just before
/// `complete`.
fn rows_with_daemon(state: &str, message: &str) -> Vec<LogFeedEvent> {
    let mut rows = fixture_rows();
    let complete = rows
        .iter()
        .position(|row| row.phase == "complete")
        .expect("the fixture completes");
    let created_at = rows[complete].created_at.clone();
    rows.insert(
        complete,
        row(
            "daemon-ready",
            "daemon_ready",
            "completed",
            "",
            &created_at,
            Some(serde_json::json!({ "state": state, "message": message })),
        ),
    );
    rows.into_iter().map(log_event).collect()
}

async fn create_with_rows(rows: Vec<LogFeedEvent>) -> (anyhow::Result<()>, bool) {
    let feed = ScriptedFeed::new(vec![connection(rows, ConnectionEnd::Hang)]);
    let mut view = plain_view(Instant::now());
    let asked = Cell::new(false);
    let result = await_environment_setup(
        &feed,
        &mut view.progress,
        &fast_policy(),
        "env-fixture",
        std::future::pending(),
        || async {
            asked.set(true);
            Ok(())
        },
    )
    .await;
    (result, asked.get())
}

/// #3684: a `ready` daemon status from setup ends `cw create` at `complete`,
/// without asking the API again.
#[tokio::test]
async fn create_returns_at_complete_when_setup_saw_the_daemon_ready() {
    let (result, asked) = create_with_rows(rows_with_daemon("ready", "")).await;
    result.unwrap();
    assert!(!asked, "a ready row needs no API daemon check");
}

/// The row's state is judged by the API's rule, with the same messages.
#[tokio::test]
async fn a_daemon_status_from_setup_fails_create_as_the_api_answer_would() {
    for (state, message, expected) in [
        (
            "upgrade_required",
            "",
            "environment daemon requires an upgrade; run `cw daemon repair`",
        ),
        (
            "unsupported",
            "",
            "environment daemon requires an upgrade; run `cw daemon repair`",
        ),
        (
            "unhealthy",
            "docker is not running",
            "environment daemon is unhealthy (docker is not running); run `cw daemon status` or `cw daemon repair`",
        ),
    ] {
        let (result, asked) = create_with_rows(rows_with_daemon(state, message)).await;
        assert_eq!(format!("{:#}", result.unwrap_err()), expected, "{state}");
        assert!(!asked, "{state}: decided from the row");
    }
}

/// A daemon still starting when setup looked, and a server that wrote no
/// row, fall back to the API's daemon check.
#[tokio::test]
async fn create_asks_the_api_when_setup_saw_no_ready_daemon() {
    let (result, asked) = create_with_rows(rows_with_daemon("starting", "")).await;
    result.unwrap();
    assert!(asked, "a starting daemon is checked again");

    let rows = fixture_rows().into_iter().map(log_event).collect();
    let (result, asked) = create_with_rows(rows).await;
    result.unwrap();
    assert!(asked, "no row: the API is asked as before");
}
