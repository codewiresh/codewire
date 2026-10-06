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
    assert_eq!(current_run(&history), &running);
    // A history that ends on a terminal row shows the run that row ended.
    let failed = [
        row(5, "health_check", "started"),
        row(6, "health_check", "failed"),
    ];
    let history: Vec<_> = previous.iter().chain(&failed).cloned().collect();
    assert_eq!(current_run(&history), &failed);
    assert_eq!(current_run(&previous), &previous);
    assert_eq!(current_run(&running), &running);
    assert!(current_run(&[]).is_empty());
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
    let (frames, mut receiver) = mpsc::channel(64);
    relay(script.clone(), resume, frames).await;
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
    let relay = tokio::spawn(relay(source, Some(id(1)), frames));
    tokio::task::yield_now().await;
    drop(receiver);
    tokio::time::timeout(std::time::Duration::from_secs(5), follow_closed)
        .await
        .expect("the orchestration follow is dropped promptly")
        .unwrap();
    relay.await.unwrap();
}
