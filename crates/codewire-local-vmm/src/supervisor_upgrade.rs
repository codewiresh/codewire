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

/// Whether a boot command may replace a credential authority older than this
/// cw: only once no VM `client`'s supervisor lists may run. Each running VM's
/// broker belongs to the authority that started it, so while one may run, the
/// older authority keeps serving.
pub async fn may_replace_older_authority(
    client: &mut NativeSupervisorClient,
) -> Result<bool, TakeoverError> {
    let environments = tokio::time::timeout(LIST_DEADLINE, client.list())
        .await
        .map_err(|_| failed(client, "listing its VMs did not answer in time".to_owned()))?
        .map_err(|status| {
            failed(
                client,
                format!("listing its VMs failed: {}", status.message()),
            )
        })?;
    Ok(authority_replaceable(&environments))
}

fn authority_replaceable(environments: &[v1::Environment]) -> bool {
    !environments.iter().any(vm_may_run)
}

/// A previous cw's supervisor still serving this root: an older protocol, or
/// this protocol from another cw executable (#2549 keeps that one serving).
/// `cw env --local upgrade` moves its VMs to this cw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousCw {
    socket: PathBuf,
    pid: u32,
    /// Running or starting: stopped, then started on this cw.
    pub restart: Vec<String>,
    /// An error whose runner still owns its VM: stopped, and left stopped.
    pub stop_only: Vec<String>,
    /// May still run a VM that no stop reaches (a macOS orphan); nothing
    /// moves while one does.
    pub blocked: Vec<String>,
}

impl PreviousCw {
    /// Every VM it stops, in order.
    pub fn stopping(&self) -> impl Iterator<Item = &str> {
        self.restart
            .iter()
            .chain(&self.stop_only)
            .map(String::as_str)
    }
}

/// The supervisor serving this root, when it belongs to a previous cw. Starts
/// nothing. A supervisor no takeover can retire is refused here, before any
/// VM stops.
pub async fn previous_cw(
    config: &NativeRuntimeConfig,
) -> Result<Option<PreviousCw>, TakeoverError> {
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
        let pin = client.supervisor_peer_pin();
        let Some((pid, executable)) = pin.peer_process() else {
            return Ok(None);
        };
        if client.protocol() == NATIVE_SUPERVISOR_PROTOCOL_VERSION
            && executable == config.executable
        {
            return Ok(None);
        }
        let legacy = socket == config.legacy_supervisor_socket();
        if !client.supports(SupervisorFeature::Retire) && !may_signal(client.protocol(), legacy) {
            return Err(failed(
                &client,
                format!(
                    "its local VM supervisor protocol {} has no safe takeover",
                    client.protocol()
                ),
            ));
        }
        let environments = list(&mut client).await?;
        return Ok(Some(sort_previous(socket, pid, &environments)));
    }
    Ok(None)
}

fn sort_previous(socket: PathBuf, pid: u32, environments: &[v1::Environment]) -> PreviousCw {
    let mut previous = PreviousCw {
        socket,
        pid,
        restart: Vec::new(),
        stop_only: Vec::new(),
        blocked: Vec::new(),
    };
    for environment in environments
        .iter()
        .filter(|environment| vm_may_run(environment))
    {
        let name = environment.name.clone();
        if environment.state == v1::EnvironmentState::Running as i32
            || environment.state == v1::EnvironmentState::Starting as i32
        {
            previous.restart.push(name);
        } else if environment.state == v1::EnvironmentState::Error as i32 {
            previous.stop_only.push(name);
        } else {
            previous.blocked.push(name);
        }
    }
    previous
}

/// Why moving a previous cw's VMs to this cw stopped.
#[derive(Debug, thiserror::Error)]
pub enum MoveError {
    #[error(
        "your local VMs changed since they were listed; nothing was stopped. Run `cw env --local upgrade` again"
    )]
    Changed,
    #[error("{stage}{}", restored_note(.restored, .not_restored))]
    Stopped {
        stage: String,
        restored: Vec<String>,
        not_restored: Vec<String>,
    },
    #[error(transparent)]
    Takeover(#[from] TakeoverError),
}

fn restored_note(restored: &[String], not_restored: &[String]) -> String {
    let mut note = String::new();
    if !restored.is_empty() {
        note.push_str(&format!(
            "; {} run again on the previous cw",
            restored.join(", ")
        ));
    }
    if !not_restored.is_empty() {
        note.push_str(&format!(
            "; {} stayed stopped (`cw env --local start NAME` once this is fixed)",
            not_restored.join(", ")
        ));
    }
    note
}

/// Stop `previous`'s VMs through its own supervisor, the ordinary stop, then
/// retire it, all under the takeover lock and only while it still serves
/// exactly those VMs. A failure before it retires starts the VMs this stopped
/// again through that supervisor, on the runtime they ran; nothing is left
/// half moved. `stopped` hears each VM once it stopped.
pub async fn stop_and_retire(
    config: &NativeRuntimeConfig,
    previous: &PreviousCw,
    mut stopped: impl FnMut(&str),
) -> Result<(), MoveError> {
    let root = PrivateRoot::open(&config.root).map_err(TakeoverError::from)?;
    let _lock = TakeoverLock::acquire(&root, LOCK_WAIT).await?;
    let mut client = NativeSupervisorClient::connect_configured_at(&previous.socket, config)
        .await
        .map_err(|error| TakeoverError::Supervisor(error.into()))?;
    let pin = client.supervisor_peer_pin();
    let pid = pin.peer_process().map(|(pid, _)| pid);
    if pid != Some(previous.pid)
        || sort_previous(
            previous.socket.clone(),
            previous.pid,
            &list(&mut client).await?,
        ) != *previous
    {
        return Err(MoveError::Changed);
    }
    let mut done = Vec::new();
    for name in previous.stopping() {
        if let Err(status) = client.stop(name).await {
            let stage = format!("stopping local VM {name} failed: {}", status.message());
            return Err(restore(&mut client, previous, &done, stage).await);
        }
        stopped(name);
        done.push(name.to_owned());
    }
    let legacy = previous.socket == config.legacy_supervisor_socket();
    if let Err(error) = retire_idle(&mut client, legacy).await {
        let stage = format!("the previous cw's supervisor did not hand over: {error}");
        return Err(restore(&mut client, previous, &done, stage).await);
    }
    Ok(())
}

/// Start again, through the previous supervisor, the VMs this stopped that
/// were running.
async fn restore(
    client: &mut NativeSupervisorClient,
    previous: &PreviousCw,
    done: &[String],
    stage: String,
) -> MoveError {
    let mut restored = Vec::new();
    let mut not_restored = Vec::new();
    for name in done.iter().filter(|name| previous.restart.contains(name)) {
        match client.start(name).await {
            Ok(_) => restored.push(name.clone()),
            Err(_) => not_restored.push(name.clone()),
        }
    }
    MoveError::Stopped {
        stage,
        restored,
        not_restored,
    }
}

async fn list(client: &mut NativeSupervisorClient) -> Result<Vec<v1::Environment>, TakeoverError> {
    tokio::time::timeout(LIST_DEADLINE, client.list())
        .await
        .map_err(|_| {
            failed(
                client,
                format!(
                    "listing its VMs did not answer within {} s",
                    LIST_DEADLINE.as_secs()
                ),
            )
        })?
        .map_err(|status| {
            failed(
                client,
                format!("listing its VMs failed: {}", status.message()),
            )
        })
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

    fn named(name: &str, state: v1::EnvironmentState, error_code: &str) -> v1::Environment {
        v1::Environment {
            name: name.to_owned(),
            ..environment(state, error_code)
        }
    }

    #[test]
    fn a_previous_cws_vms_restart_stay_stopped_or_block_the_move() {
        use v1::EnvironmentState::{Error, Orphaned, Running, Starting, Stopped};
        let previous = sort_previous(
            PathBuf::from("/run/cw/supervisor.sock"),
            7,
            &[
                named("a", Running, ""),
                named("b", Starting, ""),
                named("c", Error, "network_worker_exit"),
                named("d", Error, ""),
                named("e", Stopped, ""),
                named("f", Orphaned, ""),
            ],
        );
        assert_eq!(previous.restart, ["a", "b"]);
        assert_eq!(previous.stop_only, ["c"]);
        let orphans: &[&str] = if cfg!(target_os = "macos") {
            &["f"]
        } else {
            &[]
        };
        assert_eq!(previous.blocked, orphans);
        assert_eq!(previous.stopping().collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    #[test]
    fn a_failed_move_says_which_vms_run_again_and_which_stayed_stopped() {
        let failed = MoveError::Stopped {
            stage: "stopping local VM b failed: busy".to_owned(),
            restored: vec!["a".to_owned()],
            not_restored: vec!["c".to_owned()],
        };
        assert_eq!(
            failed.to_string(),
            "stopping local VM b failed: busy; a run again on the previous cw; c stayed stopped (`cw env --local start NAME` once this is fixed)"
        );
        let nothing_to_restore = MoveError::Stopped {
            stage: "stopping local VM a failed: busy".to_owned(),
            restored: Vec::new(),
            not_restored: Vec::new(),
        };
        assert_eq!(
            nothing_to_restore.to_string(),
            "stopping local VM a failed: busy"
        );
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
    fn an_older_authority_is_replaced_only_while_no_vm_may_run() {
        use v1::EnvironmentState::{Error, Running, Stopped};
        assert!(authority_replaceable(&[]));
        assert!(authority_replaceable(&[
            environment(Stopped, ""),
            environment(Error, ""),
        ]));
        assert!(!authority_replaceable(&[
            environment(Stopped, ""),
            environment(Running, ""),
        ]));
        assert!(!authority_replaceable(&[environment(
            Error,
            "network_worker_exit"
        )]));
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
