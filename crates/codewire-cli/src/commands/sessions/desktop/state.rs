//! A desktop answer, parsed once into what `cw desktop` acts on.
//!
//! The answer is the control plane's or the local supervisor's, and both vet
//! what the environment's daemon said. `cw` checks it again all the same
//! before any of it reaches a terminal, an address or a script
//! (`docs/dev/SANDBOX-DESKTOP.md`, "The viewer password").

use std::fmt;

use chrono::{DateTime, Utc};
use codewire_daemon_proto::{DESKTOP_DISPLAY, DESKTOP_VNC_PORT, is_desktop_viewer_password};
use codewire_proto::codewire::v1::{EnvironmentDesktop, EnvironmentDesktopState};

/// A viewer password in the one shape the daemon makes: eight lowercase
/// letters or digits.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ViewerPassword(String);

impl ViewerPassword {
    pub(super) fn parse(value: &str) -> Option<Self> {
        is_desktop_viewer_password(value).then(|| Self(value.to_owned()))
    }

    pub(super) fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ViewerPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ViewerPassword(redacted)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Running {
    pub(super) started_at: Option<DateTime<Utc>>,
    pub(super) password: ViewerPassword,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Desktop {
    /// The environment's image has no desktop.
    Unavailable,
    Stopped,
    Starting,
    Running(Running),
}

/// An answer that is not in the shape the service gives.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("the desktop's answer was not understood; update cw, and report it if it repeats")]
pub(super) struct InvalidAnswer;

impl Desktop {
    pub(super) fn parse(answer: EnvironmentDesktop) -> Result<Self, InvalidAnswer> {
        let running = answer.running.into_option();
        match (answer.state.as_known(), running) {
            (Some(EnvironmentDesktopState::Unavailable), None) => Ok(Self::Unavailable),
            (Some(EnvironmentDesktopState::Stopped), None) => Ok(Self::Stopped),
            (Some(EnvironmentDesktopState::Starting), None) => Ok(Self::Starting),
            (Some(EnvironmentDesktopState::Running), Some(running))
                if running.display == DESKTOP_DISPLAY
                    && running.port == i32::from(DESKTOP_VNC_PORT) =>
            {
                let password =
                    ViewerPassword::parse(&running.viewer_password).ok_or(InvalidAnswer)?;
                let started_at = match running.started_at.into_option() {
                    Some(at) => Some(
                        u32::try_from(at.nanos)
                            .ok()
                            .and_then(|nanos| DateTime::from_timestamp(at.seconds, nanos))
                            .ok_or(InvalidAnswer)?,
                    ),
                    None => None,
                };
                Ok(Self::Running(Running {
                    started_at,
                    password,
                }))
            }
            _ => Err(InvalidAnswer),
        }
    }

    /// Whether this is the desktop `earlier` was: a stop and a new start
    /// change the password.
    pub(super) fn is_still(&self, earlier: &Running) -> bool {
        matches!(self, Self::Running(running) if running.password == earlier.password)
    }
}
