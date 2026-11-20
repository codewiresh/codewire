//! `Debug` for the one desktop message that carries the viewer password.

use std::fmt;

use crate::daemon::v1;

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
