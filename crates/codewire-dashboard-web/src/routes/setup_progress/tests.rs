use std::sync::{Arc, Mutex};

use codewire_proto::codewire::v1::{EnvironmentLog, StreamHeartbeat};

use super::*;

const ENV: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn id(n: u32) -> String {
    format!("{n:032x}")
}

fn row(n: u32, phase: &str, status: &str) -> LogRow {
    LogRow {
        id: id(n),
        phase: phase.into(),
        status: status.into(),
        message: format!("{phase} label"),
        metadata: None,
        created_at: "2026-10-06T10:00:00Z".into(),
    }
}

fn response(row: &LogRow) -> StreamLogsResponse {
    let mut log = EnvironmentLog {
        id: row.id.clone(),
        environment_id: ENV.into(),
        phase: row.phase.clone(),
        status: row.status.clone(),
        message: row.message.clone(),
        ..Default::default()
    };
    if let Some(metadata) = &row.metadata {
        log.metadata = Some(serde_json::from_value(metadata.clone()).unwrap()).into();
    }
    if let Ok(time) = DateTime::parse_from_rfc3339(&row.created_at) {
        let stamp = log.created_at.get_or_insert_default();
        stamp.seconds = time.timestamp();
        stamp.nanos = time.timestamp_subsec_nanos() as i32;
    }
    StreamLogsResponse {
        event: Some(Event::Log(Box::new(log))),
        ..Default::default()
    }
}

fn heartbeat() -> StreamLogsResponse {
    StreamLogsResponse {
        event: Some(Event::Heartbeat(Box::<StreamHeartbeat>::default())),
        ..Default::default()
    }
}

#[test]
fn stage_events_carry_only_validated_fields() {
    let mut progress = row(1, "git_clone", "progress");
    progress.metadata = Some(serde_json::json!({
        "repo_index": 2.0, "repo_count": 3, "stage": "receiving_objects", "percent": 45,
        "duration_ms": 12, "url": "https://user:synthetic-secret@git.example.test/x.git",
        "stderr": "synthetic-secret", "nested": {"secret": "synthetic-secret"},
    }));
    progress.message = "Cloning\u{7}\nrepositories".into();
    let event = stage_event(&progress).unwrap();
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "phase": "git_clone", "status": "progress", "label": "Cloning  repositories",
            "repoIndex": 2, "repoCount": 3, "stage": "receiving_objects", "percent": 45,
            "durationMs": 12, "createdAt": "2026-10-06T10:00:00Z",
        })
    );
    assert!(!json.to_string().contains("synthetic"));
}

#[test]
fn malformed_values_are_dropped_and_malformed_rows_are_skipped() {
    let mut hostile = row(1, "git_clone", "progress");
    hostile.metadata = Some(serde_json::json!({
        "repo_index": 4, "repo_count": 3, "stage": "Receiving objects: https://x", "percent": 101,
        "duration_ms": -1,
    }));
    hostile.created_at = "not a time".into();
    let json = serde_json::to_value(stage_event(&hostile).unwrap()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"phase": "git_clone", "status": "progress", "label": "git_clone label", "repoCount": 3})
    );
    for (field, value) in [
        ("id", "not-a-log-id"),
        ("phase", "Git Clone"),
        ("status", ""),
    ] {
        let mut malformed = row(2, "git_clone", "started");
        match field {
            "id" => malformed.id = value.into(),
            "phase" => malformed.phase = value.into(),
            _ => malformed.status = value.into(),
        }
        assert!(stage_event(&malformed).is_none(), "{field}");
    }
    let mut long = row(3, "git_clone", "failed");
    long.message = "x".repeat(MAX_LABEL_CHARS * 2);
    assert_eq!(
        stage_event(&long).unwrap().label.chars().count(),
        MAX_LABEL_CHARS
    );
}

#[test]
fn log_ids_accept_both_orchestration_forms_only() {
    assert!(log_id(&id(7)));
    assert!(log_id("0b1e0e2a-6c0e-4c55-9a8e-2b8b9a1f8f10"));
    for value in [
        "",
        "0B1E0E2A6C0E4C559A8E2B8B9A1F8F10",
        "0b1e0e2a6c0e4c559a8e2b8b9a1f8f1",
        "0b1e0e2a-6c0e-4c55-9a8e-2b8b9a1f8f1z",
        "../../etc",
    ] {
        assert!(!log_id(value), "{value}");
    }
}

#[test]
fn a_first_connection_shows_only_the_current_run() {
    let previous = [
        row(1, "create_claim", "started"),
        row(2, "complete", "completed"),
    ];
    let running = [
        row(3, "resume_workspace", "started"),
        row(4, "git_clone", "progress"),
    ];
    let history: Vec<_> = previous.iter().chain(&running).cloned().collect();
    assert_eq!(current_run(&history, Run::Current), &running);
    // A history that ends on a terminal row shows the run that row ended.
    let failed = [
        row(5, "health_check", "started"),
        row(6, "health_check", "failed"),
    ];
    let history: Vec<_> = previous.iter().chain(&failed).cloned().collect();
    assert_eq!(current_run(&history, Run::Current), &failed);
    assert_eq!(current_run(&previous, Run::Current), &previous);
    assert_eq!(current_run(&running, Run::Current), &running);
    assert!(current_run(&[], Run::Current).is_empty());
}

#[test]
fn resume_cursor_reads_only_one_well_formed_last_event_id() {
    let mut headers = HeaderMap::new();
    assert_eq!(resume_cursor(&headers), Ok(None));
    headers.insert("last-event-id", HeaderValue::from_static(""));
    assert_eq!(resume_cursor(&headers), Ok(None));
    headers.insert("last-event-id", HeaderValue::from_str(&id(9)).unwrap());
    assert_eq!(resume_cursor(&headers), Ok(Some(id(9))));
    headers.append("last-event-id", HeaderValue::from_str(&id(10)).unwrap());
    assert_eq!(resume_cursor(&headers), Err(()));
    let mut headers = HeaderMap::new();
    headers.insert("last-event-id", HeaderValue::from_static("1' OR '1'='1"));
    assert_eq!(resume_cursor(&headers), Err(()));
}

type Answer = Vec<Result<StreamLogsResponse, ConnectError>>;

/// Scripted orchestration: one list per `open`, recording each request.
#[derive(Clone, Default)]
struct Script {
    opens: Arc<Mutex<Vec<(String, bool)>>>,
    answers: Arc<Mutex<Vec<Answer>>>,
}

impl LogSource for Script {
    fn open(
        &self,
        after_log_id: &str,
        follow: bool,
    ) -> mpsc::Receiver<Result<StreamLogsResponse, ConnectError>> {
        self.opens
            .lock()
            .unwrap()
            .push((after_log_id.to_owned(), follow));
        let answer = self.answers.lock().unwrap().remove(0);
        let (sender, receiver) = mpsc::channel(answer.len().max(1));
        for event in answer {
            sender.try_send(event).unwrap();
        }
        receiver
    }
}

async fn relayed(script: &Script, resume: Option<String>) -> Vec<String> {
    relayed_run(script, resume, Run::Current).await
}

async fn relayed_run(script: &Script, resume: Option<String>, run: Run) -> Vec<String> {
    let (frames, mut receiver) = mpsc::channel(64);
    relay(script.clone(), resume, run, frames).await;
    let mut out = Vec::new();
    while let Ok(frame) = receiver.try_recv() {
        out.push(String::from_utf8(frame.to_vec()).unwrap());
    }
    out
}

fn ids(frames: &[String]) -> Vec<String> {
    frames
        .iter()
        .filter_map(|frame| frame.strip_prefix("id: "))
        .map(|frame| frame.split('\n').next().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn first_connection_replays_the_current_run_then_follows_to_the_end() {
    let previous_complete = row(2, "complete", "completed");
    let current = row(3, "git_clone", "started");
    let mut progress = row(4, "git_clone", "progress");
    progress.metadata = Some(
        serde_json::json!({"repo_index": 1, "repo_count": 1, "stage": "receiving_objects", "percent": 45}),
    );
    let complete = row(5, "complete", "completed");
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![
        vec![
            Ok(response(&row(1, "create_claim", "started"))),
            Ok(response(&previous_complete)),
            Ok(heartbeat()),
            Ok(response(&current)),
        ],
        vec![
            Ok(heartbeat()),
            Ok(response(&progress)),
            Ok(response(&complete)),
            Ok(response(&row(6, "late", "started"))),
        ],
    ];
    let frames = relayed(&script, None).await;
    assert_eq!(
        *script.opens.lock().unwrap(),
        vec![(String::new(), false), (id(3), true)]
    );
    assert_eq!(ids(&frames), vec![id(3), id(4), id(5)]);
    assert!(frames.contains(&": heartbeat\n\n".to_owned()));
    assert_eq!(
        frames.last().unwrap(),
        "event: end\ndata: {\"outcome\":\"complete\"}\n\n"
    );
    let progress_frame = frames
        .iter()
        .find(|frame| frame.starts_with(&format!("id: {}", id(4))))
        .unwrap();
    assert!(progress_frame.contains("\nevent: stage\ndata: {"));
    assert!(progress_frame.contains("\"percent\":45"));
}

#[tokio::test]
async fn a_resumed_connection_follows_strictly_after_its_cursor() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![Ok(response(&row(8, "git_clone", "failed")))]];
    let frames = relayed(&script, Some(id(7))).await;
    assert_eq!(*script.opens.lock().unwrap(), vec![(id(7), true)]);
    assert_eq!(ids(&frames), vec![id(8)]);
    assert_eq!(
        frames.last().unwrap(),
        "event: end\ndata: {\"outcome\":\"failed\"}\n\n"
    );
}

#[tokio::test]
async fn an_ended_run_is_shown_without_following() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![
        Ok(response(&row(1, "health_check", "started"))),
        Ok(response(&row(2, "health_check", "failed"))),
    ]];
    let frames = relayed(&script, None).await;
    assert_eq!(*script.opens.lock().unwrap(), vec![(String::new(), false)]);
    assert_eq!(ids(&frames), vec![id(1), id(2)]);
    assert!(frames.last().unwrap().starts_with("event: end\n"));
}

#[tokio::test]
async fn a_read_error_ends_the_connection_without_an_end_event() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![
        Ok(response(&row(3, "git_clone", "started"))),
        Err(ConnectError::unavailable("synthetic")),
    ]];
    let frames = relayed(&script, Some(id(2))).await;
    assert_eq!(ids(&frames), vec![id(3)]);
    assert!(!frames.iter().any(|frame| frame.starts_with("event: end")));
}

#[tokio::test]
async fn the_account_follow_limit_tells_the_page_to_stop_retrying() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![Err(ConnectError::new(
        ErrorCode::ResourceExhausted,
        "too many live log streams",
    ))]];
    let frames = relayed(&script, Some(id(3))).await;
    assert_eq!(frames, vec!["event: busy\ndata: {}\n\n".to_owned()]);
    // Any other failure just ends the connection; the browser resumes.
    *script.answers.lock().unwrap() = vec![vec![Err(ConnectError::unavailable("synthetic"))]];
    assert!(relayed(&script, Some(id(3))).await.is_empty());
}

/// A follow whose stream never ends unless its reader leaves.
#[derive(Clone)]
struct Endless {
    closed: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

impl LogSource for Endless {
    fn open(
        &self,
        _after_log_id: &str,
        _follow: bool,
    ) -> mpsc::Receiver<Result<StreamLogsResponse, ConnectError>> {
        let (sender, receiver) = mpsc::channel(1);
        let closed = self.closed.lock().unwrap().take();
        tokio::spawn(async move {
            sender.closed().await;
            if let Some(closed) = closed {
                let _ = closed.send(());
            }
        });
        receiver
    }
}

#[tokio::test]
async fn a_browser_leaving_closes_the_follow_without_waiting_for_a_heartbeat() {
    let (closed, follow_closed) = tokio::sync::oneshot::channel();
    let source = Endless {
        closed: Arc::new(Mutex::new(Some(closed))),
    };
    let (frames, receiver) = mpsc::channel(4);
    let relay = tokio::spawn(relay(source, Some(id(1)), Run::Current, frames));
    tokio::task::yield_now().await;
    drop(receiver);
    tokio::time::timeout(std::time::Duration::from_secs(5), follow_closed)
        .await
        .expect("the orchestration follow is dropped promptly")
        .unwrap();
    relay.await.unwrap();
}

#[test]
fn a_starting_page_never_sees_a_run_that_already_ended() {
    let failed = [
        row(1, "health_check", "started"),
        row(2, "health_check", "failed"),
    ];
    assert!(current_run(&failed, Run::Next { since: None }).is_empty());
    let running = [row(3, "health_check", "started")];
    assert_eq!(current_run(&running, Run::Next { since: None }), &running);
}

#[tokio::test]
async fn a_starting_page_skips_an_ended_run_and_follows_the_next() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![
        vec![
            Ok(response(&row(1, "health_check", "started"))),
            Ok(response(&row(2, "health_check", "failed"))),
        ],
        vec![
            Ok(response(&row(3, "health_check", "started"))),
            Ok(response(&row(4, "complete", "completed"))),
        ],
    ];
    let frames = relayed_run(&script, None, Run::Next { since: None }).await;
    assert_eq!(
        *script.opens.lock().unwrap(),
        vec![(String::new(), false), (id(2), true)]
    );
    assert_eq!(ids(&frames), vec![id(3), id(4)]);
    assert!(frames.last().unwrap().contains("\"outcome\":\"complete\""));
}

fn at(time: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(time)
        .unwrap()
        .with_timezone(&Utc)
}

fn row_at(n: u32, phase: &str, status: &str, time: &str) -> LogRow {
    LogRow {
        created_at: time.into(),
        ..row(n, phase, status)
    }
}

#[tokio::test]
async fn a_run_that_ended_after_the_page_rendered_is_this_starts_and_is_shown() {
    // Setup failed within a moment of running, before the page connected.
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![
        Ok(response(&row_at(
            1,
            "health_check",
            "started",
            "2026-10-06T10:00:05Z",
        ))),
        Ok(response(&row_at(
            2,
            "health_check",
            "failed",
            "2026-10-06T10:00:06Z",
        ))),
    ]];
    let since = Some(at("2026-10-06T10:00:00Z"));
    let frames = relayed_run(&script, None, Run::Next { since }).await;
    assert_eq!(*script.opens.lock().unwrap(), vec![(String::new(), false)]);
    assert_eq!(ids(&frames), vec![id(1), id(2)]);
    assert_eq!(
        frames.last().unwrap(),
        "event: end\ndata: {\"outcome\":\"failed\"}\n\n"
    );
}

#[tokio::test]
async fn a_run_that_ended_before_the_page_rendered_is_skipped_and_this_one_followed() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![
        vec![Ok(response(&row_at(
            1,
            "health_check",
            "failed",
            "2026-10-06T09:59:00Z",
        )))],
        vec![Ok(response(&row_at(
            2,
            "complete",
            "completed",
            "2026-10-06T10:01:00Z",
        )))],
    ];
    let since = Some(at("2026-10-06T10:00:00Z"));
    let frames = relayed_run(&script, None, Run::Next { since }).await;
    assert_eq!(
        *script.opens.lock().unwrap(),
        vec![(String::new(), false), (id(1), true)]
    );
    assert_eq!(ids(&frames), vec![id(2)]);
}

#[test]
fn a_retrys_page_first_gets_the_run_that_ended_before_the_retry() {
    let failed = [
        row_at(1, "health_check", "completed", "2026-10-06T09:58:00Z"),
        row_at(2, "install", "started", "2026-10-06T09:58:01Z"),
        row_at(3, "install", "failed", "2026-10-06T09:58:02Z"),
    ];
    let retry = [
        row_at(4, "install", "started", "2026-10-06T10:00:01Z"),
        row_at(5, "complete", "completed", "2026-10-06T10:00:02Z"),
    ];
    let before = Run::Before {
        since: at("2026-10-06T10:00:00Z"),
    };
    let earlier = [row_at(0, "complete", "completed", "2026-10-06T09:00:00Z")];
    let history: Vec<_> = earlier
        .iter()
        .chain(&failed)
        .chain(&retry)
        .cloned()
        .collect();
    // Whether the Retry's run is still going or has ended.
    assert_eq!(current_run(&history, before), &failed);
    assert_eq!(current_run(&history[..5], before), &failed);
    assert_eq!(current_run(&history[..4], before), &failed);
    assert!(current_run(&retry, before).is_empty());
}

#[tokio::test]
async fn a_retrys_page_gets_the_failed_run_and_its_end_and_follows_nothing() {
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![
        Ok(response(&row_at(
            1,
            "install",
            "started",
            "2026-10-06T09:58:01Z",
        ))),
        Ok(response(&row_at(
            2,
            "install",
            "failed",
            "2026-10-06T09:58:02Z",
        ))),
        Ok(response(&row_at(
            3,
            "install",
            "started",
            "2026-10-06T10:00:01Z",
        ))),
    ]];
    let before = Run::Before {
        since: at("2026-10-06T10:00:00Z"),
    };
    let frames = relayed_run(&script, None, before).await;
    assert_eq!(*script.opens.lock().unwrap(), vec![(String::new(), false)]);
    assert_eq!(ids(&frames), vec![id(1), id(2)]);
    assert_eq!(
        frames.last().unwrap(),
        "event: end\ndata: {\"outcome\":\"failed\"}\n\n"
    );
}

#[tokio::test]
async fn a_retrys_page_with_no_run_before_it_gets_an_end_and_follows_nothing() {
    // The failed run's end has left the backlog; only the retry's rows remain.
    let script = Script::default();
    *script.answers.lock().unwrap() = vec![vec![Ok(response(&row_at(
        3,
        "install",
        "started",
        "2026-10-06T10:00:01Z",
    )))]];
    let before = Run::Before {
        since: at("2026-10-06T10:00:00Z"),
    };
    let frames = relayed_run(&script, None, before).await;
    assert_eq!(*script.opens.lock().unwrap(), vec![(String::new(), false)]);
    assert_eq!(frames, vec!["event: end\ndata: {\"outcome\":\"none\"}\n\n"]);
}

#[test]
fn the_query_asks_for_the_current_run_unless_it_names_the_next() {
    let query = |run: Option<&str>, since: Option<&str>| EventsQuery {
        run: run.map(str::to_owned),
        since: since.map(str::to_owned),
    };
    assert_eq!(query(None, None).run(), Run::Current);
    assert_eq!(query(Some("other"), None).run(), Run::Current);
    assert_eq!(
        query(Some("next"), Some("2026-10-06T10:00:00.000Z")).run(),
        Run::Next {
            since: Some(at("2026-10-06T10:00:00Z"))
        }
    );
    // A malformed time is no bound: any ended run is an earlier start's.
    assert_eq!(
        query(Some("next"), Some("yesterday")).run(),
        Run::Next { since: None }
    );
    assert_eq!(
        query(Some("before"), Some("2026-10-06T10:00:00.000Z")).run(),
        Run::Before {
            since: at("2026-10-06T10:00:00Z")
        }
    );
    // Before a time it can't read, a Retry's page gets the current run.
    assert_eq!(query(Some("before"), Some("yesterday")).run(), Run::Current);
    assert_eq!(query(Some("before"), None).run(), Run::Current);
}

/// The page lists, as steps, exactly the phases orchestration's setup worker
/// writes (#3772): a new setup phase must be named on the page, or named here
/// as not a step, before it ships.
#[test]
fn the_page_lists_every_setup_phase_orchestration_writes() {
    const WORKER: &str = include_str!("../../../../codewire-orchestration/src/worker/setup.rs");
    const PAGE: &str = include_str!("../../../../../packages/codewire-design/setup-progress.js");
    // Rows the worker writes that are not steps of their own.
    const NOT_STEPS: [&str; 1] = ["daemon_ready"];

    let mut written = std::collections::BTreeSet::new();
    for call in ["emit_log(", "finish_phase("] {
        for (start, _) in WORKER.match_indices(call) {
            let args = &WORKER[start + call.len()..];
            let args = &args[..args.find(')').unwrap_or(args.len())];
            // The phase name is the first string literal after `phase,`.
            if let Some(name) = args
                .find("phase,")
                .and_then(|at| args[at..].split('"').nth(1))
            {
                written.insert(name.to_owned());
            }
        }
    }
    let body = PAGE
        .split("const SETUP_PHASES = new Map([")
        .nth(1)
        .and_then(|rest| rest.split("]);").next())
        .expect("setup-progress.js defines SETUP_PHASES");
    let listed: std::collections::BTreeSet<String> = body
        .split("[\"")
        .skip(1)
        .filter_map(|entry| entry.split('"').next().map(str::to_owned))
        .collect();
    let steps: std::collections::BTreeSet<String> = written
        .into_iter()
        .filter(|phase| !NOT_STEPS.contains(&phase.as_str()))
        .collect();
    assert!(!steps.is_empty());
    assert_eq!(listed, steps);
}
