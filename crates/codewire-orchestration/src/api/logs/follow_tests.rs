use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;

use super::*;
use crate::api::log_notifications::EnvironmentLogNotifications;

const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// In-memory rows in commit order, counting reads per environment.
#[derive(Clone, Default)]
struct Rows {
    rows: Arc<Mutex<Vec<EnvironmentLog>>>,
    reads: Arc<Mutex<Vec<String>>>,
}

impl Rows {
    fn commit(&self, env_id: &str, id: &str, phase: &str) {
        self.rows.lock().unwrap().push(EnvironmentLog {
            id: id.into(),
            environment_id: env_id.into(),
            phase: phase.into(),
            status: "started".into(),
            message: String::new(),
            metadata: None,
            created_at: "2026-10-06T10:00:00Z".into(),
        });
    }

    fn reads(&self, env_id: &str) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|read| *read == env_id)
            .count()
    }
}

impl LogRows for Rows {
    fn after(
        &self,
        env_id: &str,
        after_id: &str,
    ) -> impl Future<Output = Result<Vec<EnvironmentLog>, sqlx::Error>> + Send {
        self.reads.lock().unwrap().push(env_id.to_owned());
        let rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.environment_id == env_id)
            .cloned()
            .collect();
        let start = if after_id.is_empty() {
            0
        } else {
            rows.iter()
                .position(|row| row.id == after_id)
                .map_or(rows.len(), |index| index + 1)
        };
        std::future::ready(Ok(rows[start..].to_vec()))
    }
}

async fn next_id(events: &mut UnboundedReceiver<AppResult<LogStreamEvent>>) -> String {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event within five seconds")
            .expect("stream open");
        match event.expect("no stream error") {
            LogStreamEvent::Log(log) => return log.id,
            LogStreamEvent::Heartbeat(_) => {}
        }
    }
}

fn follow(
    rows: &Rows,
    hub: &Arc<EnvironmentLogNotifications>,
    account: &str,
    env_id: &str,
    after: &str,
) -> UnboundedReceiver<AppResult<LogStreamEvent>> {
    let permit = hub
        .acquire_follow(account)
        .expect("under the account limit");
    start_environment_log_stream(rows.clone(), env_id.into(), after.into(), Some(permit))
}

#[tokio::test]
async fn many_followers_share_one_notification_fan_out() {
    let rows = Rows::default();
    let hub = EnvironmentLogNotifications::new(8);
    rows.commit(A, "a1", "create_claim");
    rows.commit(B, "b1", "create_claim");
    let mut on_a: Vec<_> = (0..20)
        .map(|n| follow(&rows, &hub, &format!("account-{n}"), A, ""))
        .collect();
    let mut on_b: Vec<_> = (0..5)
        .map(|n| follow(&rows, &hub, &format!("other-{n}"), B, ""))
        .collect();
    for events in &mut on_a {
        assert_eq!(next_id(events).await, "a1");
    }
    for events in &mut on_b {
        assert_eq!(next_id(events).await, "b1");
    }
    // Every follower reads its signals from the one hub; none opened its own.
    assert_eq!(hub.subscribers(), 25);
    let (reads_a, reads_b) = (rows.reads(A), rows.reads(B));

    rows.commit(A, "a2", "git_clone");
    hub.notify(A);
    for events in &mut on_a {
        assert_eq!(next_id(events).await, "a2");
    }
    assert_eq!(rows.reads(A), reads_a + 20);
    // Another environment's signal costs B's followers no read.
    assert_eq!(rows.reads(B), reads_b);
    assert!(on_b.iter_mut().all(|events| events.try_recv().is_err()));
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_that_falls_behind_rereads_instead_of_losing_rows() {
    let rows = Rows::default();
    let hub = EnvironmentLogNotifications::with_capacity(8, 4);
    rows.commit(A, "a1", "create_claim");
    let mut events = follow(&rows, &hub, "account", A, "");
    assert_eq!(next_id(&mut events).await, "a1");
    // A's own signal is lost in the overflow: only lag tells the follower.
    rows.commit(A, "a2", "git_clone");
    hub.notify(A);
    for _ in 0..16 {
        hub.notify(B);
    }
    assert_eq!(next_id(&mut events).await, "a2");
}

#[tokio::test]
async fn a_listener_resync_rereads_rows_committed_without_a_signal() {
    let rows = Rows::default();
    let hub = EnvironmentLogNotifications::new(8);
    let mut events = follow(&rows, &hub, "account", A, "");
    tokio::task::yield_now().await;
    rows.commit(A, "a1", "create_claim");
    hub.resync();
    assert_eq!(next_id(&mut events).await, "a1");
}

#[tokio::test]
async fn following_resumes_strictly_after_the_cursor_and_ends_on_a_terminal_row() {
    let rows = Rows::default();
    let hub = EnvironmentLogNotifications::new(8);
    rows.commit(A, "a1", "create_claim");
    rows.commit(A, "a2", "git_clone");
    let mut events = follow(&rows, &hub, "account", A, "a1");
    assert_eq!(next_id(&mut events).await, "a2");
    rows.commit(A, "a3", "complete");
    rows.commit(A, "a4", "after_terminal");
    hub.notify(A);
    assert_eq!(next_id(&mut events).await, "a3");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        hub.follows("account"),
        0,
        "the ended follow released its slot"
    );
}

#[tokio::test]
async fn the_account_limit_is_enforced_and_released_when_a_reader_leaves() {
    let rows = Rows::default();
    let hub = EnvironmentLogNotifications::new(2);
    let first = follow(&rows, &hub, "account", A, "");
    let _second = follow(&rows, &hub, "account", A, "");
    assert!(hub.acquire_follow("account").is_none());
    // Other accounts are unaffected.
    assert!(hub.acquire_follow("someone-else").is_some());
    drop(first);
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.follows("account") != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a closed reader releases its slot without waiting for a heartbeat");
    assert!(hub.acquire_follow("account").is_some());
}

#[test]
fn the_limit_is_refused_as_resource_exhausted() {
    let error = follow_limit_exceeded();
    assert!(matches!(
        error,
        AppError::Coded {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "log_stream_limit_exceeded",
            ..
        }
    ));
}
