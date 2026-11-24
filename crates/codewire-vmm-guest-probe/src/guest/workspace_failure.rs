//! The fixed failure frames trusted container PID 1 publishes on its
//! readiness descriptor, one per workspace start stage that can fail.

use super::*;

pub(super) const WORKSPACE_FAILURE_FRAMES: &[(&[u8], &str)] = &[
    (
        b"CWFAIL1 workspace-identity-failed\n",
        "workspace-identity-failed",
    ),
    (
        b"CWFAIL1 workspace-confinement-failed\n",
        "workspace-confinement-failed",
    ),
    (
        b"CWFAIL1 workspace-plan-invalid\n",
        "workspace-plan-invalid",
    ),
    (
        b"CWFAIL1 workspace-signal-failed\n",
        "workspace-signal-failed",
    ),
    (
        b"CWFAIL1 workspace-install-failed\n",
        "workspace-install-failed",
    ),
    (
        b"CWFAIL1 workspace-workload-failed\n",
        "workspace-workload-failed",
    ),
    (
        b"CWFAIL1 workspace-startup-failed\n",
        "workspace-startup-failed",
    ),
    (
        b"CWFAIL1 workspace-credential-forwarder-failed\n",
        "workspace-credential-forwarder-failed",
    ),
    (
        b"CWFAIL1 workspace-launch-refused\n",
        "workspace-launch-refused",
    ),
];

/// Publish `stage`'s failure frame and return `error`. A launch the daemon
/// refused before it ran is published as `workspace-launch-refused` whichever
/// launch it was, so the runner can tell it from a command that failed (#6281).
pub(super) fn fail_workspace_init<T>(stage: &'static str, error: anyhow::Error) -> Result<T> {
    let stage = if error.downcast_ref::<bootstrap::LaunchRefused>().is_some() {
        "workspace-launch-refused"
    } else {
        stage
    };
    let _ = publish_workspace_failure(stage);
    Err(error)
}

fn publish_workspace_failure(stage: &'static str) -> Result<()> {
    let frame = WORKSPACE_FAILURE_FRAMES
        .iter()
        .find_map(|(frame, admitted)| (*admitted == stage).then_some(*frame))
        .ok_or_else(|| anyhow::anyhow!("workspace failure stage is invalid"))?;
    ensure!(
        unsafe { libc::fcntl(WORKSPACE_READY_FD, libc::F_GETFD) } != -1,
        "workspace readiness descriptor is absent"
    );
    let mut stream = unsafe { UnixStream::from_raw_fd(WORKSPACE_READY_FD) };
    stream
        .write_all(frame)
        .context("publish trusted workspace failure")?;
    stream.flush().context("flush trusted workspace failure")
}
