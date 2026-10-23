//! Progress for a local environment's `cw create`, `cw start`, `cw restart`,
//! `cw stop` and `cw rm`.
//!
//! The local supervisor publishes every lifecycle stage, and inside VM start
//! every runner and guest-boot stage, on its operation stream. This maps them
//! onto the shared [`StatusLine`]: one live row with the rotating spinner on a
//! terminal, one plain line per stage when redirected, nothing for machine
//! output. Bookkeeping stages (journal writes) stay quiet; only work a person
//! waits on is shown. A failure ends the open stage with a cross that names
//! it. When the command asks for it, the first Ctrl-C ends the wait (never
//! the operation): the live row is cleared and the command reports what
//! continues.

use std::io::Stderr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_local_vmm::control::v1;

use crate::commands::lifecycle_output::InterruptNotice;
use crate::output::{Capabilities, StatusLine};

/// The CLI-side stage before the supervisor has an operation: it inspects the
/// workspace source and fetches repositories inside the create request.
const SOURCES: (&str, &str) = ("cli:sources", "Preparing sources");

/// Redraws at least this often while waiting, so elapsed time keeps counting.
const MAX_TICK: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct NativeProgress {
    line: Arc<Mutex<StatusLine<Stderr>>>,
    current: Arc<Mutex<Option<(&'static str, &'static str)>>>,
    /// The supervisor reported the operation, so it runs whatever the CLI
    /// does next.
    confirmed: Arc<AtomicBool>,
    interrupt: Option<InterruptNotice>,
}

impl NativeProgress {
    pub(crate) fn new(caps: &Capabilities) -> Self {
        Self {
            line: Arc::new(Mutex::new(StatusLine::new(std::io::stderr(), caps))),
            current: Arc::new(Mutex::new(None)),
            confirmed: Arc::new(AtomicBool::new(false)),
            interrupt: None,
        }
    }

    /// Lets the first Ctrl-C end the wait with `notice`, outside machine
    /// output. Without it Ctrl-C keeps its default behaviour.
    pub(crate) fn interruptible(mut self, caps: &Capabilities, notice: InterruptNotice) -> Self {
        if !caps.is_machine() {
            self.interrupt = Some(notice);
        }
        self
    }

    /// Opens the CLI's own pre-operation stage.
    pub(crate) fn begin_sources(&self) {
        self.enter(SOURCES.0, SOURCES.1, None);
    }

    /// Opens one stage of the CLI's own, for an operation whose supervisor
    /// stages are not observed, such as stop or remove.
    pub(crate) fn begin(&self, key: &'static str, label: &'static str) {
        self.enter(key, label, None);
    }

    /// Feeds one operation update from the supervisor.
    pub(crate) fn observe(&self, operation: &v1::Operation) {
        self.confirmed.store(true, Ordering::Relaxed);
        match stage_of(operation) {
            Some((key, label)) => self.enter(key, label, guest_detail(operation)),
            None => {
                // The sources stage ends with the supervisor's first update.
                if self.current_key() == Some(SOURCES.0) {
                    self.close_current();
                }
            }
        }
    }

    /// Closes the last open stage once the operation has succeeded.
    pub(crate) fn complete(&self) {
        self.close_current();
        let _ = self.line.lock().map(|mut line| line.clear());
    }

    /// Ends the open stage with a failure line and returns its label, or
    /// `None` when no stage was open. A failure whose `error_code` names a
    /// check with its own stage ([`failed_check_stage`]) fails that stage
    /// instead of the one that was showing.
    pub(crate) fn fail_with_code(&self, error_code: Option<&str>) -> Option<&'static str> {
        if let Some((key, label)) = error_code.and_then(failed_check_stage)
            && let (Ok(mut current), Ok(mut line)) = (self.current.lock(), self.line.lock())
            && current.is_some()
        {
            let _ = line.begin(label);
            *current = Some((key, label));
        }
        self.fail()
    }

    /// Ends the open stage with a failure line and returns its label, or
    /// `None` when no stage was open.
    pub(crate) fn fail(&self) -> Option<&'static str> {
        let (Ok(mut current), Ok(mut line)) = (self.current.lock(), self.line.lock()) else {
            return None;
        };
        let stage = current.take().map(|(_, label)| label);
        match stage {
            Some(label) => {
                let _ = line.fail(label);
            }
            None => {
                let _ = line.clear();
            }
        }
        stage
    }

    /// Advances the live row while `work` runs, at the spinner's pace, so the
    /// spinner turns and elapsed time keeps counting between supervisor
    /// updates. An interruptible wait ends at the first Ctrl-C: the live row
    /// is cleared, `work` is dropped and the error says what continues.
    pub(crate) async fn tick_while<T>(&self, work: impl Future<Output = T>) -> anyhow::Result<T> {
        tokio::pin!(work);
        let mut listening = self.interrupt.is_some();
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            let interval = self
                .line
                .lock()
                .ok()
                .and_then(|line| line.tick_interval())
                .map_or(MAX_TICK, |interval| interval.min(MAX_TICK));
            tokio::select! {
                result = &mut work => return Ok(result),
                signal = &mut ctrl_c, if listening => match (signal, &self.interrupt) {
                    (Ok(()), Some(notice)) => {
                        self.clear();
                        return Err(notice.error(self.confirmed.load(Ordering::Relaxed)));
                    }
                    // No usable handler: keep Ctrl-C's default behaviour.
                    _ => listening = false,
                },
                () = tokio::time::sleep(interval) => {
                    let _ = self.line.lock().map(|mut line| line.tick());
                }
            }
        }
    }

    /// Removes the live row and forgets the open stage, without a line.
    fn clear(&self) {
        if let Ok(mut current) = self.current.lock() {
            current.take();
        }
        let _ = self.line.lock().map(|mut line| line.clear());
    }

    fn current_key(&self) -> Option<&'static str> {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.map(|(key, _)| key))
    }

    fn enter(&self, key: &'static str, label: &'static str, detail: Option<&'static str>) {
        let (Ok(mut current), Ok(mut line)) = (self.current.lock(), self.line.lock()) else {
            return;
        };
        if current.map(|(open, _)| open) != Some(key) {
            if let Some((_, open_label)) = current.take() {
                let _ = line.done(open_label);
            }
            let _ = line.begin(label);
            *current = Some((key, label));
        }
        let _ = line.detail(detail);
    }

    fn close_current(&self) {
        let (Ok(mut current), Ok(mut line)) = (self.current.lock(), self.line.lock()) else {
            return;
        };
        if let Some((_, label)) = current.take() {
            let _ = line.done(label);
        }
    }
}

/// The stage a person is waiting on, or `None` for bookkeeping.
fn stage_of(operation: &v1::Operation) -> Option<(&'static str, &'static str)> {
    use v1::OperationStage as Stage;
    use v1::RunnerStage as Runner;
    Some(match Stage::try_from(operation.stage).ok()? {
        // Recording a new environment admits the runtime artifacts and the
        // in-guest cw runtime first, which takes seconds on a first create.
        Stage::RecordEnvironment => ("runtime", "Checking the VM runtime"),
        Stage::BindEnvironmentAccess
        | Stage::RequireEnvironmentAccess
        | Stage::ApplySourceAccessBinding => ("access", "Checking credential access"),
        Stage::ProvisionWorkspace => ("disk", "Preparing the workspace disk"),
        Stage::StageWorkspaceGeneration => ("image", "Pulling the image"),
        Stage::EnsureRunner => ("runner", "Starting the VM runner"),
        Stage::StartVm | Stage::RestartVm => match Runner::try_from(operation.runner_stage) {
            Ok(Runner::WaitingGuest | Runner::GuestInit | Runner::DaemonReady) => {
                ("boot", "Booting the workspace")
            }
            // Preparing the disks happens between two VMM updates; one row.
            _ => ("vm", "Starting the VM"),
        },
        Stage::GrowDisk => ("grow", "Growing the disk"),
        Stage::StopVm => ("stop", "Stopping the VM"),
        _ => return None,
    })
}

/// The stage a failure belongs to when its error code names the check that
/// refused it. Every start, and a replayed create, first checks each direct
/// mount's host folder (#3209); that runs before any stage the supervisor
/// publishes, so without this its refusal would name the stage showing.
fn failed_check_stage(error_code: &str) -> Option<(&'static str, &'static str)> {
    error_code
        .ends_with("direct_share_changed")
        .then_some(("mounts", "Checking mounted folders"))
}

/// What the guest is doing while it boots, for the live line.
fn guest_detail(operation: &v1::Operation) -> Option<&'static str> {
    use v1::GuestBootStage as Guest;
    match v1::RunnerStage::try_from(operation.runner_stage) {
        Ok(v1::RunnerStage::DaemonReady) => return Some("daemon ready"),
        Ok(v1::RunnerStage::PreparingVm) => return Some("preparing the VM disks"),
        _ => {}
    }
    Some(match Guest::try_from(operation.guest_stage).ok()? {
        Guest::StateMounted | Guest::CgroupsReady | Guest::DisksAdmitted => "mounting disks",
        Guest::RootMounted | Guest::RootLayersReady | Guest::RootGenerationReady => {
            "unpacking the image"
        }
        Guest::SetupHeaderReady | Guest::SetupContentReady => "running setup",
        Guest::WorkspacePlanReady | Guest::OwnershipReady | Guest::PersistentLayoutReady => {
            "preparing the workspace"
        }
        Guest::ContainerControlReady | Guest::RuncLaunching | Guest::RuncRunning => {
            "starting the workspace"
        }
        Guest::WorkspaceRunning | Guest::DaemonStarted => "starting the daemon",
        Guest::Unspecified | Guest::SetupFailed | Guest::WorkspaceFailed => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(stage: v1::OperationStage, runner: v1::RunnerStage) -> v1::Operation {
        v1::Operation {
            stage: stage as i32,
            runner_stage: runner as i32,
            ..Default::default()
        }
    }

    #[test]
    fn create_stages_map_to_what_a_person_waits_on() {
        use v1::OperationStage as Stage;
        use v1::RunnerStage as Runner;
        for (stage, runner, expected) in [
            (
                Stage::RecordEnvironment,
                Runner::Unspecified,
                Some("runtime"),
            ),
            (Stage::ProvisionWorkspace, Runner::Unspecified, Some("disk")),
            (
                Stage::StageWorkspaceGeneration,
                Runner::Unspecified,
                Some("image"),
            ),
            (Stage::RecordStarting, Runner::Unspecified, None),
            (Stage::EnsureRunner, Runner::Unspecified, Some("runner")),
            (Stage::StartVm, Runner::PreparingVm, Some("vm")),
            (Stage::StartVm, Runner::StartingVmm, Some("vm")),
            (Stage::StartVm, Runner::GuestInit, Some("boot")),
            (Stage::StartVm, Runner::DaemonReady, Some("boot")),
            (Stage::RecordRunning, Runner::DaemonReady, None),
        ] {
            assert_eq!(
                stage_of(&operation(stage, runner)).map(|(key, _)| key),
                expected,
                "{stage:?} {runner:?}"
            );
        }
    }

    #[test]
    fn starting_the_vm_stays_one_stage_while_its_disks_are_prepared() {
        use v1::OperationStage as Stage;
        use v1::RunnerStage as Runner;
        // The runner reports StartingVmm, then PreparingVm, then StartingVmm
        // again; a person waits on one thing, so one row and one line.
        let keys: Vec<_> = [
            Runner::Ready,
            Runner::StartingVmm,
            Runner::PreparingVm,
            Runner::StartingVmm,
        ]
        .into_iter()
        .map(|runner| stage_of(&operation(Stage::StartVm, runner)))
        .collect();
        assert!(
            keys.iter()
                .all(|stage| *stage == Some(("vm", "Starting the VM"))),
            "{keys:?}"
        );
        assert_eq!(
            guest_detail(&operation(Stage::StartVm, Runner::PreparingVm)),
            Some("preparing the VM disks")
        );
        assert_eq!(
            stage_of(&operation(Stage::RestartVm, Runner::PreparingVm)),
            Some(("vm", "Starting the VM"))
        );
    }

    #[test]
    fn guest_boot_detail_names_the_current_step() {
        let mut boot = operation(v1::OperationStage::StartVm, v1::RunnerStage::GuestInit);
        boot.guest_stage = v1::GuestBootStage::RootLayersReady as i32;
        assert_eq!(guest_detail(&boot), Some("unpacking the image"));
        boot.guest_stage = v1::GuestBootStage::SetupContentReady as i32;
        assert_eq!(guest_detail(&boot), Some("running setup"));
        boot.runner_stage = v1::RunnerStage::DaemonReady as i32;
        assert_eq!(guest_detail(&boot), Some("daemon ready"));
    }

    /// #3209: a refused mounted folder names its own check, not the stage
    /// that was showing when the supervisor refused it; other failures keep
    /// the open stage, and no open stage stays none.
    #[test]
    fn a_refused_mounted_folder_fails_its_own_stage() {
        let caps = crate::output::Capabilities::from_process(crate::output::OutputMode::Machine);
        let access = operation(
            v1::OperationStage::RequireEnvironmentAccess,
            v1::RunnerStage::Unspecified,
        );
        for (code, expected) in [
            (
                Some("start_direct_share_changed"),
                Some("Checking mounted folders"),
            ),
            (
                Some("create_direct_share_changed"),
                Some("Checking mounted folders"),
            ),
            (Some("start_failed"), Some("Checking credential access")),
            (None, Some("Checking credential access")),
        ] {
            let progress = NativeProgress::new(&caps);
            progress.observe(&access);
            assert_eq!(progress.fail_with_code(code), expected, "{code:?}");
        }
        assert_eq!(
            NativeProgress::new(&caps).fail_with_code(Some("start_direct_share_changed")),
            None
        );
    }
}
