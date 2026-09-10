//! Fixed guest lifecycle control, independent of workload launch projection.
//!
//! The RPC owner authenticates the generation daemon capability before calling
//! this module. No request may select an executable, argument, or environment.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tonic::Status;

use crate::execution::ProcessExecution;
use crate::{Config, CredentialBridgeTransport};

static GUEST_POWEROFF_HELPER_PERMIT: Semaphore = Semaphore::const_new(1);
const POWEROFF_HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const POWEROFF_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) async fn poweroff_guest(config: &Config) -> Result<(), Status> {
    poweroff_with_command(
        config,
        &GUEST_POWEROFF_HELPER_PERMIT,
        poweroff_command,
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
}

fn validate_guest(config: &Config) -> Result<(), Status> {
    let ProcessExecution::Runc(runc) = &config.process_execution else {
        return Err(unsupported());
    };
    let Some(identity) = &config.credential_bridge else {
        return Err(unsupported());
    };
    // These are the existing sealed guest bootstrap identities. Do not use a
    // configurable Runc helper as a general host-side command runner.
    if identity.transport != CredentialBridgeTransport::Local
        || identity.environment_id.is_nil()
        || identity.environment_generation == 0
        || identity.environment_generation > i64::MAX as u64
        || runc.helper_path != Path::new("/init")
        || runc.container_id != "codewire-workspace"
        || runc.process_wrapper != ["/run/codewire-runtime/init", "workspace-exec"]
        || identity.ingress_uid != runc.uid
        || identity.ingress_gid != runc.gid
    {
        return Err(unsupported());
    }
    Ok(())
}

fn unsupported() -> Status {
    Status::failed_precondition("guest poweroff requires the trusted local guest runtime")
}

fn poweroff_command() -> Command {
    let mut command = Command::new("/init");
    command.arg("poweroff");
    command
}

// Private command injection exists solely for synthetic tests. Production has
// exactly one caller and always supplies the fixed builder above.
async fn poweroff_with_command(
    config: &Config,
    permits: &'static Semaphore,
    build_command: impl FnOnce() -> Command + Send + 'static,
    timeout: Duration,
) -> Result<(), Status> {
    validate_guest(config)?;
    let permit = permits
        .try_acquire()
        .map_err(|_| Status::resource_exhausted("guest poweroff helper is unavailable or busy"))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Status::internal("guest poweroff deadline is invalid"))?;
    // Dropping the RPC's JoinHandle does not abort this blocking owner. It
    // retains both the permit and exact child through kill/reap; the runtime
    // drains blocking workers during shutdown. Scheduling consumes the same
    // original deadline instead of granting a fresh budget to a queued worker.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if Instant::now() >= deadline {
            return Err(Status::deadline_exceeded("guest poweroff helper timed out"));
        }
        let mut command = build_command();
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|_| Status::unavailable("guest poweroff helper could not start"))?;
        let mut owner = PoweroffChild {
            child: Some(child),
            permits,
        };
        loop {
            match owner
                .child
                .as_mut()
                .expect("owned poweroff child")
                .try_wait()
            {
                Ok(Some(status)) => {
                    owner.child = None;
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(Status::internal("guest poweroff helper failed"))
                    };
                }
                Ok(None) => {}
                Err(_) => {
                    owner.terminate()?;
                    return Err(Status::internal("guest poweroff helper wait failed"));
                }
            }
            if Instant::now() >= deadline {
                owner.terminate()?;
                return Err(Status::deadline_exceeded("guest poweroff helper timed out"));
            }
            std::thread::sleep(
                POWEROFF_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })
    .await
    .map_err(|_| {
        permits.close();
        Status::internal("guest poweroff worker failed")
    })?
}

struct PoweroffChild {
    child: Option<Child>,
    permits: &'static Semaphore,
}

impl PoweroffChild {
    fn terminate(&mut self) -> Result<(), Status> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        // Even a failed kill must not abandon the exact child. Retain the
        // worker until wait completes; close admission if cleanup is unproven.
        let killed = child.kill();
        if killed.is_err() {
            self.permits.close();
        }
        let reaped = child.wait();
        if reaped.is_ok() {
            self.child = None;
        } else {
            self.permits.close();
        }
        if killed.is_err() || reaped.is_err() {
            return Err(Status::internal("guest poweroff helper cleanup failed"));
        }
        Ok(())
    }
}

impl Drop for PoweroffChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            // Includes an unexpected unwind: do not reopen admission while a
            // helper's outcome is unknown, and retain ownership while reaping.
            self.permits.close();
            let _ = self.terminate();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
