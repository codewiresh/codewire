//! A hosted daemon's answers are the workload's own text: none of it may
//! reach a caller, and an answer is passed on only in the real daemon's shape.

use super::*;

/// What a replaced daemon might put wherever it can write text.
const WORKLOAD_TEXT: &str = "workload-chosen-text-\u{1b}[31m-not-for-callers";

fn running(display: &str, port: u32, viewer_password: &str) -> v1::Desktop {
    v1::Desktop {
        state: v1::DesktopState::Running as i32,
        unavailable_reason: String::new(),
        running: Some(v1::DesktopRunning {
            display: display.into(),
            port,
            started_at: None,
            viewer_password: viewer_password.into(),
        }),
    }
}

fn in_state(state: v1::DesktopState) -> v1::Desktop {
    v1::Desktop {
        state: state as i32,
        ..Default::default()
    }
}

#[test]
fn no_refusal_carries_the_daemons_text_and_each_code_has_its_own_sentence() {
    for code in [
        tonic::Code::FailedPrecondition,
        tonic::Code::Unimplemented,
        tonic::Code::DeadlineExceeded,
        tonic::Code::Unavailable,
        tonic::Code::Cancelled,
        tonic::Code::Internal,
        tonic::Code::InvalidArgument,
        tonic::Code::Unknown,
    ] {
        let rendered = daemon_desktop_error(&tonic::Status::new(code, WORKLOAD_TEXT));
        assert!(
            !format!("{rendered:?} {rendered}").contains("workload-chosen"),
            "{code:?}: {rendered:?}"
        );
    }
    let old = daemon_desktop_error(&tonic::Status::unimplemented(WORKLOAD_TEXT));
    assert!(
        matches!(&old, AppError::Precondition(reason) if reason.contains("cw daemon repair")),
        "{old:?}"
    );
    let slow = daemon_desktop_error(&tonic::Status::deadline_exceeded(WORKLOAD_TEXT));
    assert!(
        matches!(&slow, AppError::Upstream(reason) if reason.contains("not ready in time")),
        "{slow:?}"
    );
    let refused = daemon_desktop_error(&tonic::Status::failed_precondition(WORKLOAD_TEXT));
    assert!(
        matches!(&refused, AppError::Precondition(reason) if reason.contains("did not start")),
        "{refused:?}"
    );
}

#[test]
fn a_refused_start_is_explained_by_the_state_read_after_it() {
    let mut unavailable = in_state(v1::DesktopState::Unavailable);
    unavailable.unavailable_reason = WORKLOAD_TEXT.into();
    assert_eq!(start_refusal(Ok(Some(unavailable))), NO_DESKTOP_IN_IMAGE);
    for read in [
        Ok(Some(in_state(v1::DesktopState::Stopped))),
        Ok(None),
        Ok(Some(running(WORKLOAD_TEXT, 5901, "a1b2c3d4"))),
        Err(tonic::Status::unavailable(WORKLOAD_TEXT)),
    ] {
        assert_eq!(start_refusal(read), DID_NOT_START);
    }
}

#[test]
fn an_unavailable_desktop_says_this_modules_sentence_not_the_daemons() {
    let mut answer = in_state(v1::DesktopState::Unavailable);
    answer.unavailable_reason = WORKLOAD_TEXT.into();
    let desktop = vetted(Some(answer)).unwrap();
    assert_eq!(desktop.state, v1::DesktopState::Unavailable as i32);
    assert_eq!(desktop.unavailable_reason, NO_DESKTOP_IN_IMAGE);
    assert!(desktop.running.is_none());

    // A reason on any other state is dropped.
    for state in [v1::DesktopState::Stopped, v1::DesktopState::Starting] {
        let mut answer = in_state(state);
        answer.unavailable_reason = WORKLOAD_TEXT.into();
        let desktop = vetted(Some(answer)).unwrap();
        assert_eq!(desktop.state, state as i32);
        assert!(desktop.unavailable_reason.is_empty());
    }
}

#[test]
fn a_running_desktop_passes_only_in_the_real_daemons_shape() {
    let mut real = running(":1", 5901, "a1b2c3d4");
    real.unavailable_reason = WORKLOAD_TEXT.into();
    if let Some(details) = real.running.as_mut() {
        details.started_at = Some(Default::default());
    }
    let desktop = vetted(Some(real)).unwrap();
    assert!(desktop.unavailable_reason.is_empty());
    let details = desktop.running.expect("running details");
    assert_eq!(
        (details.display.as_str(), details.port),
        (DESKTOP_DISPLAY, 5901)
    );
    assert_eq!(details.viewer_password, "a1b2c3d4");
    assert!(details.started_at.is_some());

    for (what, answer) in [
        (
            "another display",
            Some(running(":2; rm -rf", 5901, "a1b2c3d4")),
        ),
        (
            "workload text as the display",
            Some(running(WORKLOAD_TEXT, 5901, "a1b2c3d4")),
        ),
        ("another port", Some(running(":1", 22, "a1b2c3d4"))),
        (
            "a port that is no port",
            Some(running(":1", 70_000, "a1b2c3d4")),
        ),
        ("a short password", Some(running(":1", 5901, "a1b2c3"))),
        ("a long password", Some(running(":1", 5901, "a1b2c3d4e5"))),
        (
            "a password that would break a viewer address",
            Some(running(":1", 5901, "a@b/c:d?")),
        ),
        (
            "running with no details",
            Some(in_state(v1::DesktopState::Running)),
        ),
        (
            "details on a stopped desktop",
            Some(v1::Desktop {
                state: v1::DesktopState::Stopped as i32,
                ..running(":1", 5901, "a1b2c3d4")
            }),
        ),
        (
            "details on an unavailable desktop",
            Some(v1::Desktop {
                state: v1::DesktopState::Unavailable as i32,
                ..running(":1", 5901, "a1b2c3d4")
            }),
        ),
        ("no state", Some(in_state(v1::DesktopState::Unspecified))),
        (
            "an unknown state",
            Some(v1::Desktop {
                state: 99,
                ..Default::default()
            }),
        ),
        ("no desktop", None),
    ] {
        let refused = vetted(answer).expect_err(what);
        assert!(
            matches!(&refused, AppError::Upstream(reason) if reason == INVALID_ANSWER),
            "{what}: {refused:?}"
        );
    }
}

#[test]
fn a_start_time_no_client_could_format_is_left_out() {
    for (seconds, nanos) in [
        (-1, 0),
        (LATEST_START_SECONDS + 1, 0),
        (0, -1),
        (0, 1_000_000_000),
    ] {
        let mut answer = running(":1", 5901, "a1b2c3d4");
        if let Some(details) = answer.running.as_mut() {
            let at = details.started_at.insert(Default::default());
            at.seconds = seconds;
            at.nanos = nanos;
        }
        let desktop = vetted(Some(answer)).unwrap();
        assert!(
            desktop
                .running
                .expect("running details")
                .started_at
                .is_none(),
            "{seconds}s {nanos}ns"
        );
    }
}
