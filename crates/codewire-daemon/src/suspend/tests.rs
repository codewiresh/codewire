use std::cell::Cell;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Ok,
    /// `ok`, and the VM pauses before the daemon runs again, as the Pod's
    /// runtime pauses it straight after the answer.
    OkPausedAtOnce,
    No,
    Fails,
}

/// A platform that records what the suspend asked of it.
struct FakePlatform {
    calls: Mutex<Vec<&'static str>>,
    answer: Answer,
}

impl FakePlatform {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::default(),
            answer,
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

impl SuspendPlatform for FakePlatform {
    fn hold(&self) {
        self.note("hold");
    }

    fn release(&self) {
        self.note("release");
    }

    fn ask_pause(&self) -> Pending<'_, io::Result<bool>> {
        self.note("ask");
        let answer = self.answer;
        Box::pin(async move {
            match answer {
                Answer::Ok => Ok(true),
                Answer::OkPausedAtOnce => {
                    pause_for(Duration::from_secs(60));
                    Ok(true)
                }
                Answer::No => Ok(false),
                Answer::Fails => Err(io::Error::other("the runtime is gone")),
            }
        })
    }

    fn report_wake(&self) -> Pending<'_, ()> {
        self.note("report");
        Box::pin(async {})
    }
}

thread_local! {
    /// How far the fake wall clock is ahead of the test's paused clock: a
    /// pause moves it on while the test's clock stands still.
    static WALL_AHEAD: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static ORIGIN: Cell<Option<tokio::time::Instant>> = const { Cell::new(None) };
}

fn fake_wall_clock() -> SystemTime {
    let now = tokio::time::Instant::now();
    let origin = ORIGIN.with(|origin| match origin.get() {
        Some(origin) => origin,
        None => {
            origin.set(Some(now));
            now
        }
    });
    UNIX_EPOCH + Duration::from_secs(1_764_000_000) + (now - origin) + WALL_AHEAD.with(Cell::get)
}

fn pause_for(duration: Duration) {
    WALL_AHEAD.with(|ahead| ahead.set(ahead.get() + duration));
}

/// A cgroups file placing this process at `path` in the freezer's hierarchy.
fn own_cgroups(path: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        format!("2:cpuset,cpu,memory,devices,freezer,pids:{path}\n"),
    )
    .unwrap();
    file
}

fn suspend(platform: &Arc<FakePlatform>, cgroups: &tempfile::NamedTempFile) -> Suspend {
    Suspend::new(platform.clone())
        .with_own_cgroups(cgroups.path())
        .with_wall_clock(fake_wall_clock)
}

/// Lets the suspend's task run for `duration` of the paused clock.
async fn run_for(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[tokio::test(start_paused = true)]
async fn it_holds_answers_then_asks_and_a_wall_clock_gap_releases_and_reports_the_wake() {
    let platform = FakePlatform::new(Answer::Ok);
    let cgroups = own_cgroups("/workload/workspace");
    let bridge = CredentialBridge::new(None);
    let suspend = suspend(&platform, &cgroups);

    assert!(suspend.begin(&bridge).await.unwrap());
    // Held before the answer; the pause is asked for only after it.
    assert_eq!(platform.calls(), ["hold"]);
    assert!(bridge.owner_for_test().epoch_token().is_none());
    run_for(ANSWER_LEAD + Duration::from_millis(10)).await;
    assert_eq!(platform.calls(), ["hold", "ask"]);

    // Ticks without a gap: still waiting for the pause.
    run_for(SUSPEND_TICK * 3).await;
    assert_eq!(platform.calls(), ["hold", "ask"]);
    // The VM was paused for a minute: the next tick sees the gap.
    pause_for(Duration::from_secs(60));
    run_for(SUSPEND_TICK + Duration::from_millis(10)).await;
    assert_eq!(platform.calls(), ["hold", "ask", "release", "report"]);
    assert!(bridge.owner_for_test().epoch_token().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_pause_straight_after_the_answer_is_seen_at_the_first_tick_after_the_resume() {
    let platform = FakePlatform::new(Answer::OkPausedAtOnce);
    let cgroups = own_cgroups("/workload/workspace");
    let bridge = CredentialBridge::new(None);
    let suspend = suspend(&platform, &cgroups);

    assert!(suspend.begin(&bridge).await.unwrap());
    // The waking connection waits on the release, so it comes at once, not
    // after the quiet ticks.
    run_for(ANSWER_LEAD + SUSPEND_TICK + Duration::from_millis(10)).await;
    assert_eq!(platform.calls(), ["hold", "ask", "release", "report"]);
    assert!(bridge.owner_for_test().epoch_token().is_some());
}

#[tokio::test(start_paused = true)]
async fn thirty_ticks_without_a_gap_release_and_report_the_wake_too() {
    let platform = FakePlatform::new(Answer::Ok);
    let cgroups = own_cgroups("/workload/workspace");
    let bridge = CredentialBridge::new(None);
    let suspend = suspend(&platform, &cgroups);

    assert!(suspend.begin(&bridge).await.unwrap());
    run_for(ANSWER_LEAD + SUSPEND_TICK * (QUIET_TICKS - 1)).await;
    assert_eq!(platform.calls(), ["hold", "ask"]);
    run_for(SUSPEND_TICK * 2).await;
    assert_eq!(platform.calls(), ["hold", "ask", "release", "report"]);
}

#[tokio::test(start_paused = true)]
async fn a_refused_or_failed_pause_releases_at_once_and_reports_nothing() {
    for answer in [Answer::No, Answer::Fails] {
        let platform = FakePlatform::new(answer);
        let cgroups = own_cgroups("/workload/workspace");
        let bridge = CredentialBridge::new(None);
        let suspend = suspend(&platform, &cgroups);

        assert!(suspend.begin(&bridge).await.unwrap());
        run_for(ANSWER_LEAD + Duration::from_millis(10)).await;
        assert_eq!(platform.calls(), ["hold", "ask", "release"], "{answer:?}");
        assert!(bridge.owner_for_test().epoch_token().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn a_suspend_under_way_answers_not_accepted_and_one_after_it_is_accepted() {
    let platform = FakePlatform::new(Answer::No);
    let cgroups = own_cgroups("/workload/workspace");
    let bridge = CredentialBridge::new(None);
    let suspend = suspend(&platform, &cgroups);

    assert!(suspend.begin(&bridge).await.unwrap());
    assert!(!suspend.begin(&bridge).await.unwrap());
    assert_eq!(platform.calls(), ["hold"]);
    run_for(ANSWER_LEAD + Duration::from_millis(10)).await;
    assert!(suspend.begin(&bridge).await.unwrap());
}

#[tokio::test]
async fn a_daemon_outside_the_frozen_workload_is_refused_and_holds_nothing() {
    let platform = FakePlatform::new(Answer::Ok);
    let bridge = CredentialBridge::new(None);
    for path in ["/", "/kubepods/burstable/pod", "/workloads", "/codewire"] {
        let cgroups = own_cgroups(path);
        let error = suspend(&platform, &cgroups)
            .begin(&bridge)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{path}");
    }
    let missing = Suspend::new(platform.clone())
        .with_own_cgroups(Path::new("/nonexistent/cgroup"))
        .begin(&bridge)
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::FailedPrecondition);
    assert!(platform.calls().is_empty());
    assert!(bridge.owner_for_test().epoch_token().is_some());
}

#[test]
fn only_the_freezers_hierarchy_at_or_under_workload_counts() {
    let read = |contents: &str| {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        in_frozen_workload(file.path())
    };
    assert!(read("2:cpuset,freezer:/workload/workspace\n"));
    assert!(read("2:freezer:/workload\n"));
    assert!(read(
        "1:name=systemd:/\n2:memory,freezer:/workload/docker/abc\n"
    ));
    // Another hierarchy's path, or the freezer's outside it, doesn't.
    assert!(!read("1:memory:/workload/workspace\n2:freezer:/\n"));
    assert!(!read("0::/workload/workspace\n"));
    assert!(!read("2:freezer:/workloads/x\n"));
    assert!(!read(""));
}

const TOKEN: &str = "suspend-test-daemon-token";

fn suspend_request(
    token: Option<&str>,
) -> tonic::Request<codewire_daemon_proto::daemon::v1::SuspendRequest> {
    let mut request = tonic::Request::new(codewire_daemon_proto::daemon::v1::SuspendRequest {});
    if let Some(token) = token {
        request.metadata_mut().insert(
            codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER,
            token.parse().unwrap(),
        );
    }
    request
}

fn service(root: &Path) -> crate::service::DaemonServiceImpl {
    crate::service::DaemonServiceImpl::new(crate::Config {
        listen_addr: "unused:0".into(),
        workspace_root: root.to_path_buf(),
        home_root: root.to_path_buf(),
        mount_roots: Vec::new(),
        auth_token: crate::DaemonAuthToken::new(TOKEN).unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
        session_working_dir: None,
        sandbox_server_url: None,
        interception: None,
    })
}

#[tokio::test(start_paused = true)]
async fn the_rpc_needs_the_daemon_credential_and_a_daemon_without_a_suspend_says_unimplemented() {
    use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonService as _;

    let temp = tempfile::tempdir().unwrap();
    let unimplemented = service(temp.path())
        .suspend(suspend_request(Some(TOKEN)))
        .await
        .unwrap_err();
    assert_eq!(unimplemented.code(), tonic::Code::Unimplemented);

    let platform = FakePlatform::new(Answer::No);
    let cgroups = own_cgroups("/workload/workspace");
    let daemon = service(temp.path()).with_suspend_for_test(suspend(&platform, &cgroups));
    for token in [None, Some("wrong-daemon-token")] {
        let error = daemon.suspend(suspend_request(token)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }
    assert!(platform.calls().is_empty());
    let answer = daemon
        .suspend(suspend_request(Some(TOKEN)))
        .await
        .unwrap()
        .into_inner();
    assert!(answer.accepted);
    let again = daemon
        .suspend(suspend_request(Some(TOKEN)))
        .await
        .unwrap()
        .into_inner();
    assert!(!again.accepted);
    assert_eq!(platform.calls(), ["hold"]);
}
