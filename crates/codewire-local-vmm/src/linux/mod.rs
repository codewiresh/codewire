pub(crate) mod confinement;
pub mod path;
pub mod preflight;
pub mod process;
pub(crate) mod supervisor_peer;

pub use preflight::{PreflightError, PreflightReport, preflight};
pub use process::{LiveProcess, ProcessIdentity, RecoveryError};

/// The system git; Linux hosts provide it.
pub(crate) fn git() -> Option<crate::host_git::HostGit> {
    Some(crate::host_git::HostGit {
        program: "/usr/bin/git".into(),
        environment: Vec::new(),
        exec_path: None,
    })
}
