//! How a child process ended.

use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

/// How a process ended: with an exit code, or by a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessEnd {
    Code(i32),
    Signal(i32),
    /// The platform gave neither.
    Unknown,
}

impl ProcessEnd {
    /// The exit code; `None` when a signal ended the process.
    pub fn code(self) -> Option<i32> {
        match self {
            Self::Code(code) => Some(code),
            Self::Signal(_) | Self::Unknown => None,
        }
    }

    /// The signal that ended the process; `None` when it exited with a code.
    pub fn signal(self) -> Option<i32> {
        match self {
            Self::Signal(signal) => Some(signal),
            Self::Code(_) | Self::Unknown => None,
        }
    }

    /// The exit code as text, or `signal` when there is none.
    pub fn code_or_signal(self) -> String {
        self.code()
            .map_or_else(|| "signal".to_owned(), |code| code.to_string())
    }
}

impl From<ExitStatus> for ProcessEnd {
    fn from(status: ExitStatus) -> Self {
        match (status.code(), status.signal()) {
            (Some(code), _) => Self::Code(code),
            (None, Some(signal)) => Self::Signal(signal),
            (None, None) => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_is_kept_beside_an_exit_code() {
        // Wait statuses: an exit code in the high byte, a signal in the low.
        assert_eq!(
            ProcessEnd::from(ExitStatus::from_raw(72 << 8)),
            ProcessEnd::Code(72)
        );
        assert_eq!(
            ProcessEnd::from(ExitStatus::from_raw(9)),
            ProcessEnd::Signal(9)
        );
        assert_eq!(ProcessEnd::Code(72).code(), Some(72));
        assert_eq!(ProcessEnd::Signal(9).code(), None);
        assert_eq!(ProcessEnd::Code(72).code_or_signal(), "72");
        assert_eq!(ProcessEnd::Signal(9).code_or_signal(), "signal");
    }
}
