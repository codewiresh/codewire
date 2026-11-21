//! What the bridge makes of a daemon's refusal and of a vetted answer. The
//! shape an answer must have is tested with `vetted_desktop`, where it lives.

use super::*;

/// What a replaced daemon might put wherever it can write text.
const WORKLOAD_TEXT: &str = "workload-chosen-text-\u{1b}[31m-not-for-callers";

fn in_state(state: daemon::DesktopState) -> daemon::Desktop {
    daemon::Desktop {
        state: state as i32,
        unavailable_reason: WORKLOAD_TEXT.into(),
        running: None,
    }
}

fn running() -> daemon::Desktop {
    let mut details = daemon::DesktopRunning {
        display: ":1".into(),
        port: 5901,
        started_at: Some(Default::default()),
        viewer_password: "a1b2c3d4".into(),
    };
    if let Some(started_at) = details.started_at.as_mut() {
        started_at.seconds = 1_795_000_000;
        started_at.nanos = 7;
    }
    daemon::Desktop {
        state: daemon::DesktopState::Running as i32,
        unavailable_reason: String::new(),
        running: Some(details),
    }
}

#[test]
fn a_refusal_is_read_by_its_code_alone_and_no_sentence_is_the_daemons() {
    for (code, refusal) in [
        (tonic::Code::FailedPrecondition, DesktopRefusal::DidNotStart),
        (tonic::Code::Unimplemented, DesktopRefusal::DaemonTooOld),
        (
            tonic::Code::DeadlineExceeded,
            DesktopRefusal::NotReadyInTime,
        ),
        (tonic::Code::Unavailable, DesktopRefusal::TransportLost),
        (tonic::Code::Cancelled, DesktopRefusal::TransportLost),
        (tonic::Code::Internal, DesktopRefusal::Failed),
        (tonic::Code::InvalidArgument, DesktopRefusal::Failed),
        (tonic::Code::Unknown, DesktopRefusal::Failed),
    ] {
        let read = status_refusal(&tonic::Status::new(code, WORKLOAD_TEXT));
        assert_eq!(read, refusal, "{code:?}");
        assert!(!read.sentence().contains("workload-chosen"));
        assert!(!read.sentence().is_empty());
    }
}

#[test]
fn a_refused_start_is_explained_by_the_state_read_after_it() {
    assert_eq!(
        start_refusal(Ok(Some(in_state(daemon::DesktopState::Unavailable)))),
        DesktopRefusal::NoDesktopInImage
    );
    let mut misshapen = running();
    if let Some(details) = misshapen.running.as_mut() {
        details.display = WORKLOAD_TEXT.into();
    }
    for read in [
        Ok(Some(in_state(daemon::DesktopState::Stopped))),
        Ok(Some(running())),
        Ok(Some(misshapen)),
        Ok(None),
        Err(tonic::Status::unavailable(WORKLOAD_TEXT)),
    ] {
        assert_eq!(start_refusal(read), DesktopRefusal::DidNotStart);
    }
}

#[test]
fn a_vetted_answer_keeps_every_field_in_the_public_contracts_words() {
    let vetted = vetted_desktop(Some(running()), NO_DESKTOP_IN_IMAGE).expect("a real answer");
    let public = proto_desktop(vetted);
    assert_eq!(public.state, proto::EnvironmentDesktopState::Running);
    let details = public.running.as_option().expect("running details");
    assert_eq!(details.display, ":1");
    assert_eq!(details.port, 5901);
    assert_eq!(
        details.started_at.as_option(),
        Some(&Timestamp::from_unix(1_795_000_000, 7))
    );
    assert_eq!(details.viewer_password, "a1b2c3d4");
    // The public message redacts it in debug output, as the daemon's does.
    assert!(!format!("{public:?}").contains("a1b2c3d4"));

    for (state, public_state) in [
        (
            daemon::DesktopState::Unavailable,
            proto::EnvironmentDesktopState::Unavailable,
        ),
        (
            daemon::DesktopState::Stopped,
            proto::EnvironmentDesktopState::Stopped,
        ),
        (
            daemon::DesktopState::Starting,
            proto::EnvironmentDesktopState::Starting,
        ),
    ] {
        let vetted = vetted_desktop(Some(in_state(state)), NO_DESKTOP_IN_IMAGE).expect("a state");
        let public = proto_desktop(vetted);
        assert_eq!(public.state, public_state);
        assert!(public.running.as_option().is_none());
        assert!(!public.unavailable_reason.contains("workload-chosen"));
    }
    let unavailable = proto_desktop(
        vetted_desktop(
            Some(in_state(daemon::DesktopState::Unavailable)),
            NO_DESKTOP_IN_IMAGE,
        )
        .expect("unavailable"),
    );
    assert_eq!(unavailable.unavailable_reason, NO_DESKTOP_IN_IMAGE);
}
