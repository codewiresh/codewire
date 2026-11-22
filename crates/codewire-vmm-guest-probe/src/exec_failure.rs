//! A workspace command that could not be executed, said and ended as a shell
//! ends one: a missing program exits 127, one that cannot run exits 126. A
//! local `cw exec` then answers as a cloud one, whose command a shell runs
//! (docs/dev/CLI-PARITY.md, N1).

use std::ffi::OsStr;
use std::fmt;
use std::io;

/// `execvp` of the workspace command failed.
#[derive(Debug)]
pub struct ExecFailed {
    program: String,
    error: io::Error,
}

impl ExecFailed {
    /// The failure `execvp` of `program` just reported in `errno`.
    pub fn last_os_error(program: &OsStr) -> Self {
        Self::new(program, io::Error::last_os_error())
    }

    fn new(program: &OsStr, error: io::Error) -> Self {
        Self {
            program: program.to_string_lossy().into_owned(),
            error,
        }
    }

    /// The exit status a shell gives the same failure.
    pub fn exit_code(&self) -> i32 {
        match self.error.kind() {
            io::ErrorKind::NotFound => 127,
            _ => 126,
        }
    }
}

impl fmt::Display for ExecFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let program = &self.program;
        match self.error.kind() {
            io::ErrorKind::NotFound => write!(f, "{program}: command not found"),
            io::ErrorKind::PermissionDenied => write!(f, "{program}: permission denied"),
            _ => write!(f, "{program}: cannot execute: {}", self.error),
        }
    }
}

impl std::error::Error for ExecFailed {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_exec_ends_as_a_shell_ends_it() {
        let said = |error: io::Error| {
            let failed = ExecFailed::new(OsStr::new("definitely-not-a-command"), error);
            (failed.to_string(), failed.exit_code())
        };
        assert_eq!(
            said(io::Error::from_raw_os_error(libc::ENOENT)),
            (
                "definitely-not-a-command: command not found".to_owned(),
                127
            )
        );
        assert_eq!(
            said(io::Error::from_raw_os_error(libc::EACCES)),
            (
                "definitely-not-a-command: permission denied".to_owned(),
                126
            )
        );
        let (message, code) = said(io::Error::from_raw_os_error(libc::ENOEXEC));
        assert!(
            message.starts_with("definitely-not-a-command: cannot execute: "),
            "{message}"
        );
        assert_eq!(code, 126);
    }
}
