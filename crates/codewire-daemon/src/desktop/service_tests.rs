//! The desktop through the daemon's service: who may call it, and what the
//! generic session calls may do to its session.

use std::os::unix::fs::PermissionsExt as _;

use codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonService as _;
use tokio::net::TcpListener;
use tonic::{Code, Request};

use super::lifecycle_tests::{LAUNCHER, config};
use super::*;
use crate::service::DaemonServiceImpl;

const TOKEN: &str = "desktop-test-token";

fn authorized<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert(DAEMON_AUTH_TOKEN_HEADER, TOKEN.parse().unwrap());
    request
}

/// A service whose desktop is the test's launcher, with the listener the
/// VNC server would hold.
async fn service(home: &std::path::Path) -> (DaemonServiceImpl, TcpListener) {
    let launcher = home.join("desktop-start");
    std::fs::write(&launcher, LAUNCHER).unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let layout = Layout {
        launcher: launcher.to_string_lossy().into_owned(),
        server: launcher.to_string_lossy().into_owned(),
        port: listener.local_addr().unwrap().port(),
        start_timeout: START_TIMEOUT,
    };
    (
        DaemonServiceImpl::new(config(home)).with_desktop_layout(layout),
        listener,
    )
}

#[tokio::test]
async fn the_desktop_calls_need_the_daemons_token() {
    let temp = tempfile::tempdir().unwrap();
    let (service, _listener) = service(temp.path()).await;
    for refused in [
        service
            .start_desktop(Request::new(v1::StartDesktopRequest {}))
            .await
            .map(|_| ()),
        service
            .get_desktop(Request::new(v1::GetDesktopRequest {}))
            .await
            .map(|_| ()),
        service
            .stop_desktop(Request::new(v1::StopDesktopRequest {}))
            .await
            .map(|_| ()),
    ] {
        assert_eq!(refused.unwrap_err().code(), Code::Unauthenticated);
    }
    // Nothing was started for the callers that were refused.
    let read = service
        .get_desktop(authorized(v1::GetDesktopRequest {}))
        .await
        .unwrap()
        .into_inner()
        .desktop
        .unwrap();
    assert_eq!(read.state, v1::DesktopState::Stopped as i32);
    assert!(read.running.is_none());
}

#[tokio::test]
async fn the_generic_session_calls_neither_take_the_desktops_name_nor_drive_its_session() {
    let temp = tempfile::tempdir().unwrap();
    let (service, _listener) = service(temp.path()).await;

    let taken = service
        .launch_session(authorized(v1::LaunchSessionRequest {
            command: vec!["true".into()],
            name: DESKTOP_SESSION_NAME.into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(taken.code(), Code::InvalidArgument, "{taken:?}");

    service
        .start_desktop(authorized(v1::StartDesktopRequest {}))
        .await
        .unwrap();
    let sessions = service
        .list_sessions(authorized(v1::ListSessionsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .sessions;
    let session = sessions
        .iter()
        .find(|session| Desktop::owns(session))
        .unwrap();
    let session_id = session.session_id.clone();

    let input = service
        .send_session_input(authorized(v1::SendSessionInputRequest {
            session_id: session_id.clone(),
            data: b"guess\n".to_vec(),
        }))
        .await
        .unwrap_err();
    assert_eq!(input.code(), Code::FailedPrecondition, "{input:?}");
    let restart = service
        .restart_session(authorized(v1::RestartSessionRequest {
            session_id: session_id.clone(),
            expected_launch_generation: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(restart.code(), Code::FailedPrecondition, "{restart:?}");
    let still = service
        .get_desktop(authorized(v1::GetDesktopRequest {}))
        .await
        .unwrap()
        .into_inner()
        .desktop
        .unwrap();
    assert_eq!(still.state, v1::DesktopState::Running as i32);

    // Stopping the session there is stopping the desktop.
    let stopped = service
        .stop_session(authorized(v1::StopSessionRequest {
            session_id: session_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .session
        .unwrap();
    assert_ne!(stopped.state, v1::SessionLifecycleState::Running as i32);
    let after = service
        .get_desktop(authorized(v1::GetDesktopRequest {}))
        .await
        .unwrap()
        .into_inner()
        .desktop
        .unwrap();
    assert_eq!(after.state, v1::DesktopState::Stopped as i32);
    assert!(after.running.is_none());
}
