//! A cw update never disturbs local VMs (#2826). After one, the previous cw's
//! supervisor may still serve this state root; every command keeps using it
//! while its protocol is in the supported range
//! ([`MINIMUM_SUPERVISOR_PROTOCOL_VERSION`] to this cw's). Only a command that
//! boots or reconfigures a VM needs this cw's supervisor (`connect_for_boot`):
//!
//! - while the older supervisor may still run a VM, the command is refused
//!   with one line naming its VMs; this cw takes over once they stop;
//! - once it runs none, it is retired and this cw's starts: through
//!   RetireSupervisor from protocol 12, or, for exactly v0.3.388's protocol 10
//!   on the root's own socket and v0.3.389's 11 on the socket directory, with
//!   SIGTERM once its identity checks out again and a last list still shows
//!   no VM. A supervisor's exit force-stops its VMs on macOS, so one that may
//!   run a VM is never signalled.
//!
//! The new supervisor retires the older one's idle runners
//! (`reconcile_runner`). Two commands never race a takeover: it runs under
//! `takeover.lock` in the state root.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};

use crate::control::v1;
use crate::host::path::PrivateRoot;
use crate::supervisor::{NativeSupervisorClient, SupervisorError};
use crate::supervisor_config::{
    MINIMUM_SUPERVISOR_PROTOCOL_VERSION, NATIVE_SUPERVISOR_PROTOCOL_VERSION, NativeRuntimeConfig,
    SupervisorFeature,
};

const TAKEOVER_LOCK: &str = "takeover.lock";
/// How long a command waits for another command's takeover of the same root.
const LOCK_WAIT: Duration = Duration::from_secs(120);
const LIST_DEADLINE: Duration = Duration::from_secs(30);
const RETIRE_DEADLINE: Duration = Duration::from_secs(60);
const EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Supervisors with no RetireSupervisor, each only on its own socket: a
/// takeover ends them with SIGTERM once no VM runs. Nothing else is ever
/// signalled.
const SIGNALLED_ROOT_SOCKET_PROTOCOLS: [u32; 1] = [10];
const SIGNALLED_SOCKET_DIRECTORY_PROTOCOLS: [u32; 1] = [11];

#[derive(Debug, thiserror::Error)]
pub enum TakeoverError {
    #[error(
        "your local VMs {0} still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw env --local stop NAME`)"
    )]
    Busy(String),
    #[error(
        "this cw could not take over your local VMs from the cw you updated from (process {pid}, {executable}): {reason}. Retry, or stop its VMs and end process {pid}"
    )]
    Failed {
        reason: String,
        pid: u32,
        executable: PathBuf,
    },
    #[error("another cw is taking over your local VMs; retry when it has finished")]
    Locked,
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
}

impl From<crate::host::path::PathError> for TakeoverError {
    fn from(error: crate::host::path::PathError) -> Self {
        Self::Supervisor(error.into())
    }
}

/// Whether the previous supervisor may still have a VM for an environment:
/// running or starting, an error its runner still owns (the runner reports
/// one with an error code and keeps the VM), or, on macOS, where a
/// supervisor's exit stops its VMs, ownership unknown.
pub(crate) fn vm_may_run(environment: &v1::Environment) -> bool {
    environment.state == v1::EnvironmentState::Running as i32
        || environment.state == v1::EnvironmentState::Starting as i32
        || environment.state == v1::EnvironmentState::Error as i32
            && !environment.error_code.is_empty()
        || cfg!(target_os = "macos") && environment.state == v1::EnvironmentState::Orphaned as i32
}

/// Whether a supervisor of `protocol` on the root's own socket (`legacy`) or
/// the socket directory may be ended with SIGTERM once it runs no VM.
fn may_signal(protocol: u32, legacy: bool) -> bool {
    if legacy {
        SIGNALLED_ROOT_SOCKET_PROTOCOLS.contains(&protocol)
    } else {
        SIGNALLED_SOCKET_DIRECTORY_PROTOCOLS.contains(&protocol)
    }
}

/// This cw's supervisor, for a command that boots or reconfigures a VM.
/// Another version's supervisor of the same protocol keeps serving (#2549);
/// an older protocol's is taken over once it runs no VM, and the command is
/// refused while it may.
pub async fn connect_for_boot(
    config: &NativeRuntimeConfig,
) -> Result<NativeSupervisorClient, TakeoverError> {
    let client = NativeSupervisorClient::connect_or_start(config).await?;
    if client.protocol() == NATIVE_SUPERVISOR_PROTOCOL_VERSION {
        return Ok(client);
    }
    let root = PrivateRoot::open(&config.root)?;
    let _lock = TakeoverLock::acquire(&root, LOCK_WAIT).await?;
    // Another command may have taken over while this one waited.
    let mut client = NativeSupervisorClient::connect_or_start(config).await?;
    if client.protocol() == NATIVE_SUPERVISOR_PROTOCOL_VERSION {
        return Ok(client);
    }
    let legacy = client.supervisor_peer_pin().socket() == config.legacy_supervisor_socket();
    retire_idle(&mut client, legacy).await?;
    Ok(NativeSupervisorClient::connect_or_start(config).await?)
}

/// Refuse a change of the installed runtime (`cw setup --local`) while an
/// older supervisor may run a VM: it would start its next VM from the new
/// files. Starts nothing.
pub async fn refuse_while_older_serves(config: &NativeRuntimeConfig) -> Result<(), TakeoverError> {
    for socket in [
        config.supervisor_socket(),
        config.legacy_supervisor_socket(),
    ] {
        if std::os::unix::net::UnixStream::connect(&socket).is_err() {
            continue;
        }
        let mut client = NativeSupervisorClient::connect_configured_at(&socket, config)
            .await
            .map_err(SupervisorError::from)?;
        if client.protocol() == NATIVE_SUPERVISOR_PROTOCOL_VERSION {
            return Ok(());
        }
        let running = running_vms(&mut client)
            .await
            .map_err(|reason| failed(&client, reason))?;
        if !running.is_empty() {
            return Err(TakeoverError::Busy(running.join(", ")));
        }
        return Ok(());
    }
    Ok(())
}

async fn running_vms(client: &mut NativeSupervisorClient) -> Result<Vec<String>, String> {
    let environments = tokio::time::timeout(LIST_DEADLINE, client.list())
        .await
        .map_err(|_| {
            format!(
                "listing its VMs did not answer within {} s",
                LIST_DEADLINE.as_secs()
            )
        })?
        .map_err(|status| format!("listing its VMs failed: {}", status.message()))?;
    Ok(environments
        .into_iter()
        .filter(vm_may_run)
        .map(|environment| environment.name)
        .collect())
}

fn failed(client: &NativeSupervisorClient, reason: String) -> TakeoverError {
    let pin = client.supervisor_peer_pin();
    let (pid, executable) = pin
        .peer_process()
        .map_or((0, PathBuf::new()), |(pid, executable)| {
            (pid, executable.to_owned())
        });
    TakeoverError::Failed {
        reason,
        pid,
        executable,
    }
}

/// Retire an older supervisor that runs no VM. Nothing is signalled unless
/// its protocol is listed for its socket, its identity checks out again and
/// a list immediately before still shows no VM.
async fn retire_idle(
    client: &mut NativeSupervisorClient,
    legacy: bool,
) -> Result<(), TakeoverError> {
    debug_assert!(client.protocol() >= MINIMUM_SUPERVISOR_PROTOCOL_VERSION);
    let running = running_vms(client)
        .await
        .map_err(|reason| failed(client, reason))?;
    if !running.is_empty() {
        return Err(TakeoverError::Busy(running.join(", ")));
    }
    let pin = client.supervisor_peer_pin();
    let (exit, signalled) = if client.supports(SupervisorFeature::Retire) {
        let exit = pin.watch_exit().map_err(|error| {
            failed(client, format!("it could not be confirmed again ({error})"))
        })?;
        match tokio::time::timeout(
            RETIRE_DEADLINE,
            client.retire(NATIVE_SUPERVISOR_PROTOCOL_VERSION),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(status)) if status.code() == tonic::Code::FailedPrecondition => {
                // A VM started meanwhile: it keeps serving.
                let running = running_vms(client)
                    .await
                    .map_err(|reason| failed(client, reason))?;
                return Err(TakeoverError::Busy(running.join(", ")));
            }
            Ok(Err(status)) => {
                return Err(failed(
                    client,
                    format!("it refused to hand over ({})", status.message()),
                ));
            }
            Err(_) => {
                return Err(failed(
                    client,
                    format!("it did not answer within {} s", RETIRE_DEADLINE.as_secs()),
                ));
            }
        }
        (exit, false)
    } else if may_signal(client.protocol(), legacy) {
        // The last list, immediately before the signal.
        let running = running_vms(client)
            .await
            .map_err(|reason| failed(client, reason))?;
        if !running.is_empty() {
            return Err(TakeoverError::Busy(running.join(", ")));
        }
        let exit = pin.terminate().map_err(|error| {
            failed(
                client,
                format!("it could not be confirmed again before ending it ({error})"),
            )
        })?;
        (exit, true)
    } else {
        return Err(failed(
            client,
            format!(
                "its local VM supervisor protocol {} has no safe takeover",
                client.protocol()
            ),
        ));
    };
    let deadline = tokio::time::Instant::now() + EXIT_DEADLINE;
    loop {
        match exit.exited() {
            Ok(true) => break,
            Ok(false) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            _ => {
                return Err(failed(
                    client,
                    format!("it did not exit within {} s", EXIT_DEADLINE.as_secs()),
                ));
            }
        }
    }
    if signalled {
        // A SIGTERM skips the supervisor's own socket cleanup.
        let _ = pin.remove_stale_socket();
    }
    Ok(())
}

/// One takeover of a state root at a time.
struct TakeoverLock {
    _held: std::fs::File,
}

impl TakeoverLock {
    async fn acquire(root: &PrivateRoot, wait: Duration) -> Result<Self, TakeoverError> {
        let file = root
            .create_regular(Path::new(TAKEOVER_LOCK), 0o600, false)?
            .into_file();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Self { _held: file }),
                Err(error)
                    if (error == rustix::io::Errno::WOULDBLOCK
                        || error == rustix::io::Errno::INTR)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(rustix::io::Errno::WOULDBLOCK) => return Err(TakeoverError::Locked),
                Err(error) => {
                    return Err(TakeoverError::Supervisor(SupervisorError::Io {
                        path: root.path().join(TAKEOVER_LOCK),
                        source: error.into(),
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(state: v1::EnvironmentState, error_code: &str) -> v1::Environment {
        v1::Environment {
            name: "dev".to_owned(),
            state: state as i32,
            error_code: error_code.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn a_vm_may_run_unless_stopped_or_failed_without_its_runner() {
        use v1::EnvironmentState::{Error, Orphaned, Running, Starting, Stopped};
        for (listed, may_run) in [
            (environment(Stopped, ""), false),
            (environment(Error, ""), false),
            (environment(Error, "network_worker_exit"), true),
            (environment(Running, ""), true),
            (environment(Starting, ""), true),
            (environment(Orphaned, ""), cfg!(target_os = "macos")),
        ] {
            assert_eq!(vm_may_run(&listed), may_run, "{listed:?}");
        }
    }

    #[test]
    fn only_v0_3_388_and_v0_3_389_supervisors_are_signalled_each_on_its_socket() {
        assert!(may_signal(10, true));
        assert!(!may_signal(10, false));
        assert!(may_signal(11, false));
        assert!(!may_signal(11, true));
        for protocol in [0, 8, 9, 12, NATIVE_SUPERVISOR_PROTOCOL_VERSION, u32::MAX] {
            assert!(!may_signal(protocol, true), "{protocol}");
            assert!(!may_signal(protocol, false), "{protocol}");
        }
        // Every signalled protocol is one the range admits, and older than
        // the first with RetireSupervisor.
        for protocol in SIGNALLED_ROOT_SOCKET_PROTOCOLS
            .into_iter()
            .chain(SIGNALLED_SOCKET_DIRECTORY_PROTOCOLS)
        {
            assert!(protocol >= MINIMUM_SUPERVISOR_PROTOCOL_VERSION);
            assert!(protocol < SupervisorFeature::Retire.since());
        }
    }
}
