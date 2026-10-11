//! The git that local workspace preparation runs: the system git on Linux,
//! the admitted runtime's pinned git on macOS.

use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct HostGit {
    pub(crate) program: PathBuf,
    /// Set after the caller clears the environment.
    pub(crate) environment: Vec<(&'static str, OsString)>,
    /// The runtime's helper directory (`GIT_EXEC_PATH`); the system git
    /// finds its own.
    pub(crate) exec_path: Option<PathBuf>,
}
