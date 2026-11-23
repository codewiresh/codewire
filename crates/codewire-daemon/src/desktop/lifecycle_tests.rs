//! The desktop's life against a launcher of the test's own: a shell script
//! that takes the password as the image's launcher does, with the test
//! holding the listener the VNC server would.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use codewire_daemon_proto::DaemonAuthToken;
use tokio::net::TcpListener;

use super::*;
use crate::credential_bridge::CredentialBridge;

/// Reads the password, keeps what it was given where the test can see it,
/// says it is ready and waits to be stopped, or for the test to end it.
pub(super) const LAUNCHER: &str = r#"#!/bin/sh
IFS= read -r password
printf '%s' "$password" >"$0.password"
printf 'started\n' >>"$0.starts"
echo 'codewire-desktop: display ready'
while [ ! -e "$0.end" ]; do sleep 0.05; done
"#;

struct Fixture {
    temp: tempfile::TempDir,
    engine: SessionEngine,
    desktop: Desktop,
    launcher: PathBuf,
    // Held for the test's length: the port the desktop is found listening on.
    _listener: TcpListener,
    port: u16,
}

impl Fixture {
    async fn with_launcher(script: &str) -> Self {
        Self::build(Some(script), START_TIMEOUT).await
    }

    async fn build(script: Option<&str>, start_timeout: Duration) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let launcher = temp.path().join("desktop-start");
        if let Some(script) = script {
            std::fs::write(&launcher, script).unwrap();
            std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = config(temp.path());
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        let desktop = Desktop::new(
            &config,
            engine.clone(),
            WorkloadSockets::default(),
            Layout {
                launcher: launcher.to_string_lossy().into_owned(),
                // Any file of the image: the launcher is one.
                server: launcher.to_string_lossy().into_owned(),
                port,
                start_timeout,
            },
        );
        Self {
            temp,
            engine,
            desktop,
            launcher,
            _listener: listener,
            port,
        }
    }

    fn beside_launcher(&self, suffix: &str) -> PathBuf {
        PathBuf::from(format!("{}.{suffix}", self.launcher.display()))
    }

    /// The password the launcher read on its standard input.
    fn delivered_password(&self) -> String {
        std::fs::read_to_string(self.beside_launcher("password")).unwrap()
    }

    fn launcher_starts(&self) -> usize {
        std::fs::read_to_string(self.beside_launcher("starts"))
            .map(|starts| starts.lines().count())
            .unwrap_or(0)
    }

    /// What `DISPLAY` a new durable session sees, `unset` if none; `request`
    /// is the launch's own environment.
    async fn display_seen_by_a_new_session(&self, request: &[&str]) -> String {
        let seen = self
            .temp
            .path()
            .join(format!("display-{}", uuid::Uuid::new_v4()));
        let session = self
            .engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    r#"printf '%s' "${DISPLAY-unset}" >"$1""#.into(),
                    "sh".into(),
                    seen.to_string_lossy().into_owned(),
                ],
                env: request.iter().map(|entry| (*entry).to_owned()).collect(),
                ..Default::default()
            })
            .await
            .unwrap();
        self.wait_until_ended(&session.session_id).await;
        std::fs::read_to_string(seen).unwrap()
    }

    async fn wait_until_ended(&self, session_id: &str) -> v1::SessionRecord {
        for _ in 0..200 {
            let session = self.engine.get(session_id).await.unwrap();
            if session.state != v1::SessionLifecycleState::Starting as i32
                && session.state != v1::SessionLifecycleState::Running as i32
            {
                return session;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("session {session_id} did not end");
    }

    async fn desktop_session(&self) -> v1::SessionRecord {
        self.engine
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(Desktop::owns)
            .expect("the desktop's session is listed")
    }

    async fn finish(self) {
        let _ = self.desktop.stop().await;
        self.engine.shutdown().await.unwrap();
    }
}

pub(super) fn config(home: &Path) -> Config {
    Config {
        interception: None,
        listen_addr: "unused:0".into(),
        workspace_root: home.to_path_buf(),
        home_root: home.to_path_buf(),
        mount_roots: Vec::new(),
        auth_token: DaemonAuthToken::new("desktop-test-token").unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
        session_working_dir: None,
        sandbox_server_url: None,
    }
}

fn running(desktop: &v1::Desktop) -> &v1::DesktopRunning {
    assert_eq!(
        desktop.state,
        v1::DesktopState::Running as i32,
        "{desktop:?}"
    );
    desktop
        .running
        .as_ref()
        .expect("a running desktop says where")
}

#[tokio::test]
async fn a_start_hands_the_launcher_its_password_and_answers_running_once_it_is_ready() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    assert_eq!(
        fixture.desktop.get().await.unwrap().state,
        v1::DesktopState::Stopped as i32
    );

    let started = fixture.desktop.start().await.unwrap();
    let details = running(&started);
    assert_eq!(details.display, ":1");
    assert_eq!(details.port, u32::from(fixture.port));
    assert!(details.started_at.is_some());
    assert_eq!(details.viewer_password.len(), 8);
    assert_eq!(details.viewer_password, fixture.delivered_password());

    // A read and a second start answer with the same desktop; the launcher
    // is not run again.
    let read = fixture.desktop.get().await.unwrap();
    assert_eq!(running(&read), details);
    let again = fixture.desktop.start().await.unwrap();
    assert_eq!(running(&again), details);
    assert_eq!(fixture.launcher_starts(), 1);

    // The session is an ordinary listed one, and nothing it records holds
    // the password.
    let session = fixture.desktop_session().await;
    assert_eq!(session.command, [fixture.launcher.to_string_lossy()]);
    assert!(!session.pty);
    assert_eq!(session.state, v1::SessionLifecycleState::Running as i32);
    assert!(
        !format!("{session:?}").contains(&details.viewer_password),
        "the session record holds the password"
    );
    let output = fixture
        .engine
        .read_output(v1::ReadSessionOutputRequest {
            session_id: session.session_id.clone(),
            offset: 0,
            limit: 64 * 1024,
            allow_history_gap: true,
        })
        .await
        .unwrap();
    let printed: Vec<u8> = output
        .chunks
        .into_iter()
        .flat_map(|chunk| chunk.data)
        .collect();
    assert!(
        !String::from_utf8_lossy(&printed).contains(&details.viewer_password),
        "the session's output holds the password"
    );

    // No client writes to the launcher, by one write or by an attachment's
    // input stream; the engine's own entry is where both arrive.
    let id = &session.session_id;
    for refused in [
        fixture.engine.send_input(id, b"guess\n".to_vec()).await,
        fixture.engine.input(id, b"guess\n".to_vec()).await,
        fixture
            .engine
            .stream_input(id, "attachment", 0, b"guess\n".to_vec())
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(&refused, Err(SessionError::FailedPrecondition(reason)) if reason.contains("takes no input")),
            "{refused:?}"
        );
    }
    assert_eq!(details.viewer_password, fixture.delivered_password());
    fixture.finish().await;
}

#[tokio::test]
async fn a_start_whose_caller_goes_away_still_finishes_and_is_recorded() {
    // Ready only after the caller has given up.
    let fixture = Fixture::with_launcher(&LAUNCHER.replace(
        "echo 'codewire-desktop: display ready'",
        "sleep 1; echo 'codewire-desktop: display ready'",
    ))
    .await;
    let abandoned = tokio::time::timeout(Duration::from_millis(150), fixture.desktop.start()).await;
    assert!(abandoned.is_err(), "the start answered before the launcher");

    let mut desktop = fixture.desktop.get().await.unwrap();
    for _ in 0..200 {
        if desktop.state != v1::DesktopState::Starting as i32 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        desktop = fixture.desktop.get().await.unwrap();
    }
    assert_eq!(
        running(&desktop).viewer_password,
        fixture.delivered_password()
    );
    assert_eq!(fixture.launcher_starts(), 1);

    // It was recorded, so it can be stopped and started again.
    fixture.desktop.stop().await.unwrap();
    let session = fixture.desktop_session().await;
    assert!(!is_live(&session), "{session:?}");
    fixture.finish().await;
}

#[tokio::test]
async fn new_processes_get_the_display_while_the_desktop_runs_and_not_after_it_stops() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    // Whatever this test's own environment gives a session with no desktop.
    let without = fixture.display_seen_by_a_new_session(&[]).await;

    fixture.desktop.start().await.unwrap();
    assert_eq!(fixture.display_seen_by_a_new_session(&[]).await, ":1");
    assert_eq!(
        fixture.display_seen_by_a_new_session(&["DISPLAY=:7"]).await,
        ":7",
        "a request's own display is kept"
    );

    fixture.desktop.stop().await.unwrap();
    assert_eq!(fixture.display_seen_by_a_new_session(&[]).await, without);
    fixture.finish().await;
}

#[tokio::test]
async fn a_stop_ends_the_launcher_and_the_next_start_runs_it_again_with_a_new_password() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    let first = fixture.desktop.start().await.unwrap();
    let first = running(&first).clone();
    let first_session = fixture.desktop_session().await.session_id;

    let stopped = fixture.desktop.stop().await.unwrap();
    assert_eq!(stopped.state, v1::DesktopState::Stopped as i32);
    assert!(stopped.running.is_none());
    let ended = fixture.wait_until_ended(&first_session).await;
    assert_ne!(ended.state, v1::SessionLifecycleState::Running as i32);
    assert_eq!(
        fixture.desktop.get().await.unwrap().state,
        v1::DesktopState::Stopped as i32
    );
    // Stopping a stopped desktop succeeds.
    assert_eq!(
        fixture.desktop.stop().await.unwrap().state,
        v1::DesktopState::Stopped as i32
    );

    let second = fixture.desktop.start().await.unwrap();
    let second = running(&second);
    assert_ne!(second.viewer_password, first.viewer_password);
    assert_eq!(second.viewer_password, fixture.delivered_password());
    assert_eq!(fixture.launcher_starts(), 2);
    // The name stays with one retained session, started again.
    assert_eq!(fixture.desktop_session().await.session_id, first_session);
    fixture.finish().await;
}

/// The test's listener answers on the port, as another process's would; the
/// launcher ending is what says the desktop is not there.
#[tokio::test]
async fn a_launcher_that_ends_fails_the_start_naming_the_display_and_the_port() {
    let fixture = Fixture::with_launcher("#!/bin/sh\nIFS= read -r password\nexit 1\n").await;
    let refused = fixture.desktop.start().await.unwrap_err();
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    assert!(refused.message().contains("display :1"), "{refused:?}");
    assert!(
        refused
            .message()
            .contains(&format!("port {}", fixture.port)),
        "{refused:?}"
    );
    assert_eq!(
        fixture.desktop.get().await.unwrap().state,
        v1::DesktopState::Stopped as i32
    );
    assert_eq!(
        fixture.display_seen_by_a_new_session(&["DISPLAY=:7"]).await,
        ":7"
    );
    fixture.finish().await;
}

#[test]
fn a_launch_the_environment_denied_is_aborted_and_not_named_a_display_or_port_clash() {
    let ended = |status_message: &str| v1::SessionRecord {
        state: v1::SessionLifecycleState::Failed as i32,
        status_message: status_message.into(),
        ..Default::default()
    };
    let denied = ended_start(
        &ended(crate::durable_session::LAUNCH_PROJECTION_DENIED),
        5901,
    );
    assert_eq!(denied.code(), tonic::Code::Aborted, "{denied:?}");
    assert!(!denied.message().contains("display"), "{denied:?}");
    let exited = ended_start(&ended("exited with status 1"), 5901);
    assert_eq!(exited.code(), tonic::Code::FailedPrecondition, "{exited:?}");
    assert!(exited.message().contains("display :1"), "{exited:?}");
    assert!(exited.message().contains("port 5901"), "{exited:?}");
}

#[tokio::test]
async fn a_launcher_that_never_says_ready_is_ended_when_the_start_times_out() {
    let fixture = Fixture::build(
        Some("#!/bin/sh\nIFS= read -r password\nexec sleep 300\n"),
        Duration::from_millis(400),
    )
    .await;
    let refused = fixture.desktop.start().await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded, "{refused:?}");
    let session = fixture.desktop_session().await;
    let ended = fixture.wait_until_ended(&session.session_id).await;
    assert_ne!(ended.state, v1::SessionLifecycleState::Running as i32);
    assert_eq!(
        fixture.desktop.get().await.unwrap().state,
        v1::DesktopState::Stopped as i32
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_desktop_that_ends_by_itself_reads_as_stopped_and_new_processes_lose_the_display() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    let without = fixture.display_seen_by_a_new_session(&[]).await;
    fixture.desktop.start().await.unwrap();
    let session = fixture.desktop_session().await;

    std::fs::write(fixture.beside_launcher("end"), b"").unwrap();
    fixture.wait_until_ended(&session.session_id).await;

    // Before anything reads the desktop's state: the session's end cleared it.
    assert_eq!(fixture.display_seen_by_a_new_session(&[]).await, without);
    let read = fixture.desktop.get().await.unwrap();
    assert_eq!(read.state, v1::DesktopState::Stopped as i32);
    assert!(
        read.running.is_none(),
        "a stopped desktop returns no password"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn an_image_without_a_desktop_is_unavailable_and_says_what_it_lacks() {
    let fixture = Fixture::build(None, START_TIMEOUT).await;
    let read = fixture.desktop.get().await.unwrap();
    assert_eq!(read.state, v1::DesktopState::Unavailable as i32);
    assert!(
        read.unavailable_reason
            .contains(&*fixture.launcher.to_string_lossy()),
        "{read:?}"
    );
    let refused = fixture.desktop.start().await.unwrap_err();
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    assert!(refused.message().contains("has no desktop"), "{refused:?}");
    assert_eq!(
        fixture.desktop.stop().await.unwrap().state,
        v1::DesktopState::Unavailable as i32
    );
    assert!(fixture.engine.list().await.unwrap().is_empty());
    fixture.finish().await;
}

/// Named before the name was reserved: starting the desktop must not run it.
#[tokio::test]
async fn an_earlier_session_with_the_desktops_name_is_never_started_as_the_desktop() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    let marker = fixture.temp.path().join("earlier-ran-again");
    let earlier = fixture
        .engine
        .launch(v1::LaunchSessionRequest {
            command: vec![
                "sh".into(),
                "-c".into(),
                r#"printf ran >>"$1""#.into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            name: DESKTOP_SESSION_NAME.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    fixture.wait_until_ended(&earlier.session_id).await;

    let refused = fixture.desktop.start().await.unwrap_err();
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    assert!(refused.message().contains("is in the way"), "{refused:?}");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ran");
    assert_eq!(fixture.launcher_starts(), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn a_running_session_that_only_has_the_desktops_name_can_be_stopped() {
    let fixture = Fixture::with_launcher(LAUNCHER).await;
    let earlier = fixture
        .engine
        .launch(v1::LaunchSessionRequest {
            command: vec!["sleep".into(), "300".into()],
            name: DESKTOP_SESSION_NAME.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let refused = fixture.desktop.start().await.unwrap_err();
    assert!(refused.message().contains("is in the way"), "{refused:?}");

    // The desktop holds nothing, and the session is ended all the same.
    let stopped = fixture
        .desktop
        .stop_session(&earlier.session_id)
        .await
        .unwrap();
    assert!(!is_live(&stopped), "{stopped:?}");
    let ended = fixture.wait_until_ended(&earlier.session_id).await;
    assert!(!is_live(&ended), "{ended:?}");
    assert_eq!(fixture.launcher_starts(), 0);
    fixture.finish().await;
}
