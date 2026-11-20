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

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "k3m9x2qa";

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
