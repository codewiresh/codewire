//! The desktop's viewer password: its shape, and `Debug` for the one message
//! that carries it.

use std::fmt;

use crate::daemon::v1;

/// How long a viewer password is: all that VNC's password scheme reads.
pub const DESKTOP_VIEWER_PASSWORD_LENGTH: usize = 8;

/// Whether `value` has the shape of a viewer password the daemon makes:
/// eight lowercase letters or digits. A caller that takes one from a daemon
/// it cannot trust checks this before using it in an address or a prompt.
pub fn is_desktop_viewer_password(value: &str) -> bool {
    value.len() == DESKTOP_VIEWER_PASSWORD_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

impl fmt::Debug for v1::DesktopRunning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRunning")
            .field("display", &self.display)
            .field("port", &self.port)
            .field("started_at", &self.started_at)
            .field("viewer_password", &"[REDACTED]")
            .finish()
    }
}

/// The latest second a start time may name: the last of the year 9999, which
/// every client's timestamp formatting accepts.
const LATEST_START_SECONDS: i64 = 253_402_300_799;

/// A daemon's desktop answer with nothing in it but what the real daemon
/// answers, or `None`. A Sandbox's daemon can be replaced from inside the
/// Sandbox, so whoever passes its answer on vets it first: a known state;
/// when unavailable, `no_desktop`, the caller's own sentence, in place of the
/// daemon's reason; when running, the one display and port a desktop has, a
/// password of the shape the daemon makes, and a start time a client can
/// format, or none. No part of any other answer is kept.
pub fn vetted_desktop(answer: Option<v1::Desktop>, no_desktop: &str) -> Option<v1::Desktop> {
    let desktop = answer?;
    let state = v1::DesktopState::try_from(desktop.state).ok()?;
    let (unavailable_reason, running) = match (state, desktop.running) {
        (v1::DesktopState::Unavailable, None) => (no_desktop.to_owned(), None),
        (v1::DesktopState::Stopped | v1::DesktopState::Starting, None) => (String::new(), None),
        (v1::DesktopState::Running, Some(running))
            if running.display == crate::DESKTOP_DISPLAY
                && running.port == u32::from(crate::DESKTOP_VNC_PORT)
                && is_desktop_viewer_password(&running.viewer_password) =>
        {
            let started_at = running.started_at.filter(|at| {
                (0..=LATEST_START_SECONDS).contains(&at.seconds)
                    && (0..1_000_000_000).contains(&at.nanos)
            });
            (
                String::new(),
                Some(v1::DesktopRunning {
                    started_at,
                    ..running
                }),
            )
        }
        _ => return None,
    };
    Some(v1::Desktop {
        state: state as i32,
        unavailable_reason,
        running,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "k3m9x2qa";

    /// What a replaced daemon might put wherever it can write text.
    const WORKLOAD_TEXT: &str = "workload-chosen-text-\u{1b}[31m-not-for-callers";
    const NO_DESKTOP: &str = "the caller's own sentence";

    fn answer(display: &str, port: u32, viewer_password: &str) -> v1::Desktop {
        v1::Desktop {
            state: v1::DesktopState::Running as i32,
            unavailable_reason: WORKLOAD_TEXT.into(),
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
            unavailable_reason: WORKLOAD_TEXT.into(),
            running: None,
        }
    }

    #[test]
    fn a_vetted_answer_never_carries_the_daemons_reason() {
        let unavailable =
            vetted_desktop(Some(in_state(v1::DesktopState::Unavailable)), NO_DESKTOP).unwrap();
        assert_eq!(unavailable.state, v1::DesktopState::Unavailable as i32);
        assert_eq!(unavailable.unavailable_reason, NO_DESKTOP);
        assert!(unavailable.running.is_none());
        for state in [v1::DesktopState::Stopped, v1::DesktopState::Starting] {
            let desktop = vetted_desktop(Some(in_state(state)), NO_DESKTOP).unwrap();
            assert_eq!(desktop.state, state as i32);
            assert!(desktop.unavailable_reason.is_empty());
        }
        let real = vetted_desktop(Some(answer(":1", 5901, PASSWORD)), NO_DESKTOP).unwrap();
        assert!(real.unavailable_reason.is_empty());
    }

    #[test]
    fn a_running_desktop_passes_only_in_the_real_daemons_shape() {
        let real = vetted_desktop(Some(answer(":1", 5901, PASSWORD)), NO_DESKTOP).unwrap();
        let details = real.running.expect("running details");
        assert_eq!(details.display, crate::DESKTOP_DISPLAY);
        assert_eq!(details.port, u32::from(crate::DESKTOP_VNC_PORT));
        assert_eq!(details.viewer_password, PASSWORD);

        for (what, answer) in [
            (
                "another display",
                Some(answer(":2; rm -rf", 5901, PASSWORD)),
            ),
            (
                "workload text as the display",
                Some(answer(WORKLOAD_TEXT, 5901, PASSWORD)),
            ),
            ("another port", Some(answer(":1", 22, PASSWORD))),
            (
                "a port that is no port",
                Some(answer(":1", 70_000, PASSWORD)),
            ),
            ("a short password", Some(answer(":1", 5901, "a1b2c3"))),
            ("a long password", Some(answer(":1", 5901, "a1b2c3d4e5"))),
            (
                "a password that would break a viewer address",
                Some(answer(":1", 5901, "a@b/c:d?")),
            ),
            (
                "running with no details",
                Some(in_state(v1::DesktopState::Running)),
            ),
            (
                "details on a stopped desktop",
                Some(v1::Desktop {
                    state: v1::DesktopState::Stopped as i32,
                    ..answer(":1", 5901, PASSWORD)
                }),
            ),
            (
                "details on an unavailable desktop",
                Some(v1::Desktop {
                    state: v1::DesktopState::Unavailable as i32,
                    ..answer(":1", 5901, PASSWORD)
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
            assert!(vetted_desktop(answer, NO_DESKTOP).is_none(), "{what}");
        }
    }

    #[test]
    fn a_start_time_no_client_could_format_is_left_out() {
        let mut real = answer(":1", 5901, PASSWORD);
        if let Some(details) = real.running.as_mut() {
            details.started_at = Some(Default::default());
        }
        let kept = vetted_desktop(Some(real), NO_DESKTOP).unwrap();
        assert!(kept.running.expect("running details").started_at.is_some());

        for (seconds, nanos) in [
            (-1, 0),
            (LATEST_START_SECONDS + 1, 0),
            (0, -1),
            (0, 1_000_000_000),
        ] {
            let mut answer = answer(":1", 5901, PASSWORD);
            if let Some(details) = answer.running.as_mut() {
                let at = details.started_at.insert(Default::default());
                at.seconds = seconds;
                at.nanos = nanos;
            }
            let desktop = vetted_desktop(Some(answer), NO_DESKTOP).unwrap();
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

    #[test]
    fn a_viewer_password_is_eight_lowercase_letters_or_digits_and_nothing_else() {
        assert!(is_desktop_viewer_password(PASSWORD));
        for other in [
            "",
            "k3m9x2q",
            "k3m9x2qab",
            "K3M9X2QA",
            "k3m9x2q ",
            "k3m9@2qa",
            "k3m9x2q\n",
            "pässwor",
        ] {
            assert!(!is_desktop_viewer_password(other), "{other:?}");
        }
    }

    fn running() -> v1::DesktopRunning {
        v1::DesktopRunning {
            display: ":1".into(),
            port: 5901,
            started_at: None,
            viewer_password: PASSWORD.into(),
        }
    }

    /// The password is in no `Debug` output, of the message or of anything
    /// that holds it, so a logged request or response never shows it.
    #[test]
    fn the_viewer_password_is_never_in_debug_output() {
        let desktop = v1::Desktop {
            state: v1::DesktopState::Running as i32,
            unavailable_reason: String::new(),
            running: Some(running()),
        };
        let responses = [
            format!("{:?}", running()),
            format!("{:#?}", running()),
            format!("{desktop:?}"),
            format!(
                "{:?}",
                v1::StartDesktopResponse {
                    desktop: Some(desktop.clone())
                }
            ),
            format!(
                "{:?}",
                v1::GetDesktopResponse {
                    desktop: Some(desktop.clone())
                }
            ),
            format!(
                "{:?}",
                v1::StopDesktopResponse {
                    desktop: Some(desktop)
                }
            ),
        ];
        for output in responses {
            assert!(!output.contains(PASSWORD), "{output}");
            assert!(output.contains("[REDACTED]"), "{output}");
            assert!(output.contains("5901"), "{output}");
        }
    }
}
